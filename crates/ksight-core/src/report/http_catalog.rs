//! HTTP catalog helpers shared by session reports and dump-package.
//!
//! Heap/private plaintext stores are parsed into [`HttpCallActivity`] rows,
//! then ranked/collapsed before graph attachment.

use ksight_model::SensorKind;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

use super::{HandshakeNameActivity, HttpCallActivity};

fn http_call_key(row: &HttpCallActivity) -> String {
    let host = row.host.as_deref().unwrap_or("-");
    let origin = if row.origin.is_empty() {
        "inspect"
    } else {
        row.origin.as_str()
    };
    format!(
        "http_call:{origin}:{}:{}:{}{}",
        row.process_id, row.method, host, row.path
    )
}

fn http_call_label(row: &HttpCallActivity) -> String {
    let tracker = if row.third_party { " tracker" } else { "" };
    if row.kind == "http1_response" || row.kind == "http2_response" {
        let status = row
            .status
            .map_or_else(|| "?".to_owned(), |value| value.to_string());
        let content = row.content_type.as_deref().unwrap_or("");
        return format!("HTTP {status} {content}{tracker} ×{}", row.count);
    }
    let host = row.host.as_deref().unwrap_or("-");
    format!("{} {host}{}{tracker} ×{}", row.method, row.path, row.count)
}

pub(crate) fn attach_http_call_graph(
    graph: &mut crate::SessionGraph,
    session_id: Uuid,
    calls: &[HttpCallActivity],
) {
    for row in calls.iter().take(64) {
        let from = graph.ensure_process(session_id, &row.source, row.process_id);
        let to = http_call_key(row);
        if !graph.entities.iter().any(|entity| entity.key == to) {
            graph.entities.push(crate::GraphEntity {
                kind: crate::GraphEntityKind::SocketFlow,
                session_id,
                key: to.clone(),
                label: http_call_label(row),
                sensors: vec![SensorKind::Integrity],
                artifact: None,
                process_instance_id: None,
            });
        }
        let strength = if row.origin == "heap" {
            crate::EdgeStrength::Correlated
        } else {
            crate::EdgeStrength::Confirmed
        };
        graph.edges.push(crate::GraphEdge {
            from,
            to: to.clone(),
            relation: "http_call".to_owned(),
            strength,
            sensor: Some(SensorKind::Integrity),
        });
        if let Some(name) = row.host.as_deref() {
            let host_key = format!("host:{name}");
            if !graph.entities.iter().any(|entity| entity.key == host_key) {
                graph.entities.push(crate::GraphEntity {
                    kind: crate::GraphEntityKind::HostName,
                    session_id,
                    key: host_key.clone(),
                    label: name.to_owned(),
                    sensors: vec![SensorKind::Integrity],
                    artifact: None,
                    process_instance_id: None,
                });
            }
            graph.edges.push(crate::GraphEdge {
                from: host_key,
                to,
                relation: "http_host".to_owned(),
                strength: crate::EdgeStrength::Correlated,
                sensor: Some(SensorKind::Integrity),
            });
        }
    }
}

pub(crate) fn pair_http_replies(
    graph: &mut crate::SessionGraph,
    _session_id: Uuid,
    calls: &[HttpCallActivity],
) {
    let requests: Vec<&HttpCallActivity> = calls
        .iter()
        .filter(|row| {
            matches!(row.kind.as_str(), "http1_request" | "http2_request") && row.host.is_some()
        })
        .take(64)
        .collect();
    let responses: Vec<&HttpCallActivity> = calls
        .iter()
        .filter(|row| {
            matches!(row.kind.as_str(), "http1_response" | "http2_response") && row.host.is_some()
        })
        .take(64)
        .collect();
    let mut paired = 0_usize;
    for request in requests {
        for response in &responses {
            if paired >= 32 {
                return;
            }
            if request.process_id != response.process_id {
                continue;
            }
            if request.host != response.host {
                continue;
            }
            graph.edges.push(crate::GraphEdge {
                from: http_call_key(request),
                to: http_call_key(response),
                relation: "http_reply".to_owned(),
                strength: crate::EdgeStrength::Correlated,
                sensor: Some(SensorKind::Integrity),
            });
            paired = paired.saturating_add(1);
        }
    }
}

/// Parse dump/forensics `plaintext/` windows into heap `http_calls`.
#[must_use]
pub fn http_calls_from_plaintext_dir(dir: &std::path::Path, source: &str) -> Vec<HttpCallActivity> {
    http_calls_from_store(dir, source, "heap", 8 * 1024, false)
}

/// Parse already-copied CE/DE prefs/databases/files for `http(s)://` interface rows.
#[must_use]
pub fn http_calls_from_private_dir(dir: &std::path::Path, source: &str) -> Vec<HttpCallActivity> {
    http_calls_from_store(dir, source, "private", 512 * 1024, true)
}

fn http_calls_from_store(
    dir: &std::path::Path,
    source: &str,
    origin: &str,
    max_bytes: usize,
    recursive: bool,
) -> Vec<HttpCallActivity> {
    let mut files = Vec::new();
    let mut remaining = 256_usize;
    collect_store_files(dir, recursive, &mut files, &mut remaining);
    let mut calls = BTreeMap::<(String, String, String, String), HttpCallActivity>::new();
    for path in files {
        let Ok(mut bytes) = std::fs::read(&path) else {
            continue;
        };
        if bytes.len() > max_bytes {
            bytes.truncate(max_bytes);
        }
        if bytes.is_empty() {
            continue;
        }
        let process_id = pid_from_plaintext_name(&path);
        for parsed in crate::parse_http_plain_all_bytes(&bytes, "text") {
            if parsed.kind == "http2_preface" {
                continue;
            }
            let host = parsed.host.clone().unwrap_or_default();
            let is_response = parsed.status.is_some() && parsed.kind.contains("response");
            if host.is_empty() && !is_response {
                continue;
            }
            if !host.is_empty()
                && crate::format_inspect_url(parsed.scheme, &host, &parsed.path).is_none()
            {
                continue;
            }
            let key = (
                parsed.kind.to_owned(),
                parsed.method.clone(),
                host.clone(),
                parsed.path.clone(),
            );
            let activity = calls.entry(key).or_insert_with(|| HttpCallActivity {
                source: source.to_owned(),
                process_id,
                direction: origin.to_owned(),
                kind: parsed.kind.to_owned(),
                method: parsed.method.clone(),
                host: (!host.is_empty()).then_some(host.clone()),
                path: parsed.path.clone(),
                status: parsed.status,
                query_keys: parsed.query_keys.clone(),
                header_names: parsed.header_names.clone(),
                redacted_headers: parsed.redacted_headers.clone(),
                body_keys: parsed.body_keys.clone(),
                redacted_body_keys: parsed.redacted_body_keys.clone(),
                content_type: parsed.content_type.clone(),
                third_party: parsed.third_party,
                count: 0,
                origin: origin.to_owned(),
            });
            activity.count = activity.count.saturating_add(1);
            activity.third_party |= parsed.third_party;
        }
    }
    let mut out = calls.into_values().collect::<Vec<_>>();
    sort_http_catalog(&mut out);
    out
}

/// First-party inspect/private/heap paths outrank tracker/CDN so the 256-row cap keeps APIs.
pub fn sort_http_catalog(calls: &mut Vec<HttpCallActivity>) {
    calls.retain(keep_catalog_row);
    drop_truncated_catalog_hosts(calls);
    drop_truncated_catalog_paths(calls);
    collapse_catalog_families(calls);
    for row in calls.iter_mut() {
        if let Some(host) = row.host.as_deref() {
            row.third_party |= crate::is_third_party_host(host);
        }
    }
    calls.sort_by(|left, right| {
        catalog_weight(right)
            .cmp(&catalog_weight(left))
            .then_with(|| right.count.cmp(&left.count))
            .then_with(|| left.origin.cmp(&right.origin))
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.method.cmp(&right.method))
    });
    calls.truncate(256);
}

pub(crate) fn stamp_empty_hosts_from_sni(
    calls: &mut [HttpCallActivity],
    handshakes: &[HandshakeNameActivity],
) {
    let mut by_pid: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
    for handshake in handshakes {
        if let Some(sni) = handshake.sni.as_deref().filter(|value| !value.is_empty()) {
            by_pid
                .entry(handshake.process_id)
                .or_default()
                .insert(sni.to_ascii_lowercase());
        }
        if let Some(host) = handshake
            .http_host
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            by_pid
                .entry(handshake.process_id)
                .or_default()
                .insert(host.to_ascii_lowercase());
        }
    }
    for call in calls {
        if call.host.as_deref().is_some_and(|host| !host.is_empty()) {
            continue;
        }
        let Some(names) = by_pid.get(&call.process_id) else {
            continue;
        };
        if names.len() != 1 {
            continue;
        }
        let Some(host) = names.iter().next().cloned() else {
            continue;
        };
        if crate::format_inspect_url(Some("https"), &host, &call.path).is_some() {
            call.host = Some(host);
        }
    }
}

fn keep_catalog_row(row: &HttpCallActivity) -> bool {
    if row
        .host
        .as_deref()
        .is_some_and(|host| crate::format_inspect_url(Some("https"), host, &row.path).is_some())
    {
        return true;
    }
    row.status.is_some() && row.kind.contains("response")
}

fn drop_truncated_catalog_hosts(calls: &mut Vec<HttpCallActivity>) {
    let hosts: Vec<String> = calls.iter().filter_map(|row| row.host.clone()).collect();
    calls.retain(|row| {
        let Some(host) = row.host.as_deref() else {
            return row.status.is_some() && row.kind.contains("response");
        };
        !hosts
            .iter()
            .any(|other| crate::http_plain::is_truncated_host(host, other))
    });
}

/// Keep a few representatives per host+path-prefix so CMS variants cannot fill the 256 cap.
fn collapse_catalog_families(calls: &mut Vec<HttpCallActivity>) {
    const PER_FAMILY: usize = 3;
    let mut families: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, row) in calls.iter().enumerate() {
        families
            .entry(catalog_family_key(row))
            .or_default()
            .push(index);
    }
    let mut keep = vec![false; calls.len()];
    for indexes in families.values() {
        let mut ranked = indexes.clone();
        ranked.sort_by(|&left, &right| {
            catalog_weight(&calls[right])
                .cmp(&catalog_weight(&calls[left]))
                .then_with(|| calls[right].count.cmp(&calls[left].count))
                .then_with(|| calls[right].path.len().cmp(&calls[left].path.len()))
        });
        for index in ranked.into_iter().take(PER_FAMILY) {
            keep[index] = true;
        }
    }
    let mut cursor = 0_usize;
    calls.retain(|_| {
        let kept = keep[cursor];
        cursor = cursor.saturating_add(1);
        kept
    });
}

fn catalog_family_key(row: &HttpCallActivity) -> String {
    let host = row.host.as_deref().unwrap_or("");
    let prefix: Vec<&str> = row
        .path
        .split('/')
        .filter(|part| !part.is_empty())
        .take(4)
        .collect();
    format!("{host}|{}", prefix.join("/"))
}

fn drop_truncated_catalog_paths(calls: &mut Vec<HttpCallActivity>) {
    let keys: Vec<(String, String)> = calls
        .iter()
        .map(|row| (row.host.clone().unwrap_or_default(), row.path.clone()))
        .collect();
    calls.retain(|row| {
        let host = row.host.clone().unwrap_or_default();
        let path = &row.path;
        if path.is_empty() {
            return true;
        }
        !keys.iter().any(|(other_host, other_path)| {
            other_host == &host
                && other_path.len() > path.len()
                && other_path.starts_with(path)
                && other_path
                    .as_bytes()
                    .get(path.len())
                    .is_some_and(|byte| *byte == b'/' || byte.is_ascii_alphanumeric())
        })
    });
}

fn catalog_weight(row: &HttpCallActivity) -> u8 {
    let Some(host) = row.host.as_deref().filter(|value| !value.is_empty()) else {
        return 0;
    };
    if row.third_party {
        return 1;
    }
    let host_l = host.to_ascii_lowercase();
    let path = row.path.to_ascii_lowercase();
    let static_like = host_l.contains("cdn")
        || host_l.contains("static")
        || host_l.starts_with("image")
        || path.contains("/static/")
        || path.contains("/assets/")
        || path.contains("/img/")
        || path.contains("/huamei_")
        || path.contains("/www/js/")
        || path.contains("/file/download/")
        || path.starts_with("/cd/")
        || path.contains("/content/dam/");
    let ext = std::path::Path::new(&path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    let static_like =
        static_like || ext.eq_ignore_ascii_case("js") || ext.eq_ignore_ascii_case("css");
    let api_like = path.contains("/api")
        || path.contains("/mbfront")
        || path.contains("/login")
        || path.contains("/ebs")
        || path.contains("/phone")
        || path.contains("/wap")
        || path.contains("/interface/")
        || row.kind.contains("request");
    let has_path = !path.is_empty();
    let mut weight: u8 = match row.origin.as_str() {
        "inspect" if api_like || (has_path && !static_like) => 6,
        "private" | "heap" if api_like => 5,
        "inspect" => 4,
        "private" | "heap" if has_path && !static_like => 4,
        "private" | "heap" if has_path => 3,
        _ => 2,
    };
    if source_matches_host(&row.source, host) && !static_like {
        weight = weight.saturating_add(2);
    }
    weight
}

fn source_matches_host(source: &str, host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    source
        .to_ascii_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .flat_map(|token| {
            let mut tokens = Vec::new();
            if token.len() >= 4 {
                tokens.push(token.to_owned());
            }
            for suffix in ["gphone", "phone", "mobile", "android"] {
                if let Some(stem) = token.strip_suffix(suffix) {
                    if stem.len() >= 4 {
                        tokens.push(stem.to_owned());
                    }
                }
            }
            tokens
        })
        .filter(|token| {
            !matches!(
                token.as_str(),
                "android"
                    | "phone"
                    | "mobile"
                    | "plat"
                    | "apps"
                    | "gphone"
                    | "main"
                    | "studio"
                    | "winner"
            )
        })
        .any(|token| host.contains(&token))
}

fn collect_store_files(
    dir: &std::path::Path,
    recursive: bool,
    out: &mut Vec<std::path::PathBuf>,
    remaining: &mut usize,
) {
    if *remaining == 0 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if *remaining == 0 {
            return;
        }
        let path = entry.path();
        if path.is_dir() {
            if recursive {
                collect_store_files(&path, true, out, remaining);
            }
            continue;
        }
        if path
            .components()
            .any(|part| skip_store_dir_name(&part.as_os_str().to_string_lossy()))
        {
            continue;
        }
        if !keep_store_file(&path) {
            continue;
        }
        out.push(path);
        *remaining = remaining.saturating_sub(1);
    }
}

fn skip_store_dir_name(name: &str) -> bool {
    matches!(
        name,
        "fresco_disk_cache"
            | "image_manager_disk_cache"
            | "Crash Reports"
            | "HTTP Cache"
            | "Code Cache"
            | "Cache_Data"
            | "oat_primary"
            | "shaders_cache"
            | "com.android.opengl.shaders_cache.multifile"
    )
}

fn keep_store_file(path: &std::path::Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.ends_with("-wal") || name.ends_with("-shm") || name.ends_with("-journal") {
        return false;
    }
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "xml" | "json" | "txt" | "html" | "db" | "sqlite" | "sqlite3" | ""
    ) || name.starts_with("mem-")
        || name == "cookies"
        || name.contains("webview")
}

fn pid_from_plaintext_name(path: &std::path::Path) -> u32 {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("mem-"))
        .and_then(|name| name.split('-').next())
        .and_then(|pid| pid.parse().ok())
        .unwrap_or(0)
}
