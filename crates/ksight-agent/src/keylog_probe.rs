//! Keylog probe: uprobe at per-ELF offsets to recover TLS traffic secrets.
//!
//! Stripped TLS stacks (Alibaba tnet/slightssl, vendor cronet forks) never set
//! BoringSSL's keylog callback, so the line-formatter never runs. The internal
//! `ssl_log_secret(ssl, label, secret, len)` call sites still exist and the
//! keylog label strings survive in `.rodata`; offline xref analysis pins the
//! call-site offset per build. At that address x1 is the label pointer, x2 the
//! secret pointer, x3 the secret length, so the generic register uprobe already
//! snapshots the label and userspace reads the secret bytes.
//!
//! Offset table: `/data/local/tmp/ksight/keylog_offsets.json`
//! `[{"build_id": "...", "offset": 123456, "client_random_offset": 512,
//!    "note": "xqc ssl_log_secret call site"}]`
//! `client_random_offset` (optional) reads 32 bytes at `ssl + offset` to emit
//! a standard Wireshark keylog line; without it the line stays in debug form.
#![cfg(any(target_os = "android", target_os = "linux"))]

use std::path::{Path, PathBuf};

use ksight_hwbp::UprobeSession;

const KEYLOG_TABLE_PATH: &str = "/data/local/tmp/ksight/keylog_offsets.json";
/// One `ssl_log_secret` argument set.
const SECRET_MAX_BYTES: usize = 128;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct KeylogEntry {
    /// GNU build-id of the target library. Empty when the ELF ships none
    /// (vendor forks often strip it); `lib_name` (+ size) is matched instead.
    #[serde(default)]
    build_id: String,
    offset: u64,
    /// Basename fallback for ELFs without a build-id.
    #[serde(default)]
    lib_name: Option<String>,
    /// File size of the library, disambiguating same-name builds.
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    client_random_offset: Option<u64>,
    #[serde(default)]
    note: String,
}

/// One attached probe for a matched library build.
struct KeylogHandle {
    session: UprobeSession,
    client_random_offset: Option<u64>,
    library: String,
}

/// Live keylog probes for one capture session.
pub struct KeylogProbe {
    handles: Vec<KeylogHandle>,
    matched_builds: Vec<String>,
    pending: Vec<KeylogEntry>,
}

impl KeylogProbe {
    /// True while table entries remain that no mapped build satisfied yet.
    #[must_use]
    pub fn needs_retry(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Re-attempt pending entries; target libraries are often dlopened lazily
    /// well after process start.
    pub fn retry_attach(&mut self, uprobe_object: &Path, pids: &[u32]) -> Vec<String> {
        let mut status = Vec::new();
        let pending = std::mem::take(&mut self.pending);
        for entry in pending {
            let mut placed = false;
            for pid in pids.iter().copied().take(8) {
                let Some(library) = mapped_library_matching(pid, &entry) else {
                    continue;
                };
                match UprobeSession::start_program(
                    uprobe_object,
                    "ksight_uprobe_regs",
                    Path::new(&library),
                    entry.offset,
                    None,
                    false,
                ) {
                    Ok(mut session) => {
                        let tgids: Vec<u32> = pids.to_vec();
                        let _ = session.apply_tgid_filter(Some(&tgids));
                        status.push(format!(
                            "keylog probe attached build={} offset={:#x} lib={library}",
                            entry.build_id, entry.offset
                        ));
                        self.matched_builds.push(entry.build_id.clone());
                        self.handles.push(KeylogHandle {
                            session,
                            client_random_offset: entry.client_random_offset,
                            library,
                        });
                        placed = true;
                        break;
                    }
                    Err(error) => {
                        status.push(format!(
                            "keylog probe: attach failed build={} lib={library}: {error:#}",
                            entry.build_id
                        ));
                        placed = true;
                        break;
                    }
                }
            }
            if !placed {
                self.pending.push(entry);
            }
        }
        if !self.pending.is_empty() {
            status.push(format!(
                "keylog probe: {} entries still pending",
                self.pending.len()
            ));
        }
        status
    }
}

impl KeylogProbe {
    /// Attach probes for every table entry whose build-id is mapped by `pids`.
    ///
    /// Table sources, in order: the device overlay (`keylog_offsets.json`),
    /// then the unified stack-rules table embedded in the agent.
    ///
    /// Returns the probe plus status lines for the capture log.
    pub fn attach_for_pids(uprobe_object: &Path, pids: &[u32]) -> (Self, Vec<String>) {
        let mut status = Vec::new();
        status.extend(ensure_device_stack_tables());
        let table_result = load_table(Path::new(KEYLOG_TABLE_PATH));
        let mut entries = match &table_result {
            Ok(entries) if !entries.is_empty() => entries.clone(),
            Ok(_) => Vec::new(),
            Err(error) => {
                status.push(format!(
                    "keylog probe: device table unreadable ({error}); trying stack-rules"
                ));
                Vec::new()
            }
        };
        let rules = rules_table_entries();
        if entries.is_empty() {
            entries = rules;
            if entries.is_empty() {
                status.push("keylog probe: no table entries".to_owned());
                return (
                    Self {
                        handles: Vec::new(),
                        matched_builds: Vec::new(),
                        pending: Vec::new(),
                    },
                    status,
                );
            }
            status.push(format!(
                "keylog probe: using stack-rules table ({} entries)",
                entries.len()
            ));
        } else {
            let before = entries.len();
            merge_keylog_entries(&mut entries, rules);
            if entries.len() > before {
                status.push(format!(
                    "keylog probe: merged {} stack-rules entries into device overlay",
                    entries.len() - before
                ));
            }
        }
        let mut handles = Vec::new();
        let mut matched_builds = Vec::new();
        let mut pending = Vec::new();
        for entry in &entries {
            let mut placed = false;
            for pid in pids.iter().copied().take(8) {
                let Some(library) = mapped_library_matching(pid, entry) else {
                    continue;
                };
                eprintln!("keylog scan: matched lib={library}");
                eprintln!("keylog scan: attaching...");
                let Ok(mut session) = UprobeSession::start_program(
                    uprobe_object,
                    "ksight_uprobe_regs",
                    Path::new(&library),
                    entry.offset,
                    None,
                    false,
                ) else {
                    status.push(format!(
                        "keylog probe: attach failed build={} offset={:#x} lib={library}",
                        entry.build_id, entry.offset
                    ));
                    continue;
                };
                let tgids: Vec<u32> = pids.to_vec();
                if let Err(error) = session.apply_tgid_filter(Some(&tgids)) {
                    status.push(format!("keylog probe: tgid filter failed: {error:#}"));
                }
                status.push(format!(
                    "keylog probe attached build={} offset={:#x} lib={library} random_offset={:?}",
                    entry.build_id, entry.offset, entry.client_random_offset
                ));
                matched_builds.push(entry.build_id.clone());
                handles.push(KeylogHandle {
                    session,
                    client_random_offset: entry.client_random_offset,
                    library,
                });
                placed = true;
                break;
            }
            if !placed {
                pending.push(entry.clone());
            }
        }
        if !pending.is_empty() {
            status.push(format!(
                "keylog probe: {}/{} entries pending (target libs not mapped yet; retried)",
                pending.len(),
                entries.len()
            ));
        }
        (
            Self {
                handles,
                matched_builds,
                pending,
            },
            status,
        )
    }

    /// Drain probe hits and render keylog lines.
    pub fn poll(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        for handle in &mut self.handles {
            let Ok(hits) = handle.session.poll_hits() else {
                continue;
            };
            for hit in hits {
                if let Some(line) = render_line(&hit, handle) {
                    lines.push(line);
                }
            }
        }
        lines
    }

    /// Builds that this probe is armed for, for the session report.
    pub fn matched_builds(&self) -> &[String] {
        &self.matched_builds
    }
}

fn render_line(hit: &ksight_hwbp::RegisterContext, handle: &KeylogHandle) -> Option<String> {
    let label_end = hit
        .aux
        .iter()
        .take(
            usize::try_from(hit.aux_bytes)
                .unwrap_or(0)
                .min(hit.aux.len()),
        )
        .position(|byte| *byte == 0)
        .unwrap_or(hit.aux.len());
    let label = String::from_utf8_lossy(&hit.aux[..label_end])
        .trim()
        .to_owned();
    if label.is_empty() {
        return None;
    }
    let secret_ptr = hit.regs.get(2).copied().unwrap_or(0);
    let secret_len = usize::try_from(hit.regs.get(3).copied().unwrap_or(0)).unwrap_or(0);
    if secret_ptr < 0x1000 || secret_len == 0 || secret_len > SECRET_MAX_BYTES {
        return None;
    }
    let secret = crate::inspect_runtime::read_remote_bytes(hit.pid, secret_ptr, secret_len)?;
    let secret_hex: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
    let ssl_ptr = hit.regs.first().copied().unwrap_or(0);
    if let Some(offset) = handle.client_random_offset {
        if let Some(random) =
            crate::inspect_runtime::read_remote_bytes(hit.pid, ssl_ptr.saturating_add(offset), 32)
        {
            if random.len() == 32 {
                let random_hex: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
                return Some(format!("{label} {random_hex} {secret_hex}"));
            }
        }
    }
    Some(format!(
        "# {label} secret={secret_hex} ssl={ssl_ptr:#x} pid={} (no client_random_offset)",
        hit.pid
    ))
}

fn load_table(path: &Path) -> Result<Vec<KeylogEntry>, String> {
    let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    serde_json::from_str(&text).map_err(|error| error.to_string())
}

/// Entries from the unified stack-rules table, converted to probe entries.
#[must_use]
pub fn rules_table_entries() -> Vec<KeylogEntry> {
    ksight_core::keylog_entries()
        .into_iter()
        .map(|rule| KeylogEntry {
            build_id: rule.build_id.unwrap_or_default(),
            offset: rule.offset.expect("filtered"),
            lib_name: rule.lib_name,
            size: rule.size,
            client_random_offset: rule.client_random_offset,
            note: rule.note,
        })
        .collect()
}

/// Write `tls_stacks.json` and `keylog_offsets.json` when missing or stale.
/// Stale = schema/agent/content-hash mismatch against the embedded table.
/// Local stacks (`source=local`) are merged after the embedded rows.
pub fn ensure_device_stack_tables() -> Vec<String> {
    let mut status = Vec::new();
    let dir = Path::new("/data/local/tmp/ksight");
    if let Err(error) = std::fs::create_dir_all(dir) {
        status.push(format!("keylog probe: mkdir {dir:?} failed: {error}"));
        return status;
    }
    let stacks = dir.join("tls_stacks.json");
    let embedded = ksight_core::EMBEDDED_STACK_RULES;
    let agent = env!("CARGO_PKG_VERSION");
    let need_write = match std::fs::read_to_string(&stacks) {
        Ok(text) => device_stack_table_stale(&text, embedded, agent),
        Err(_) => true,
    };
    if need_write {
        let payload = merge_local_stack_table(&stacks, embedded, agent);
        let tmp = dir.join("tls_stacks.json.tmp");
        match std::fs::write(&tmp, &payload) {
            Ok(()) => match std::fs::rename(&tmp, &stacks) {
                Ok(()) => status.push(format!(
                    "keylog probe: atomically wrote tls_stacks.json schema={} agent={}",
                    ksight_core::load_stack_rules().schema_version,
                    agent
                )),
                Err(error) => status.push(format!(
                    "keylog probe: rename tls_stacks.json failed: {error}"
                )),
            },
            Err(error) => status.push(format!(
                "keylog probe: write tls_stacks.json.tmp failed: {error}"
            )),
        }
    }
    let keylog = Path::new(KEYLOG_TABLE_PATH);
    let entries = rules_table_entries();
    let encoded = serde_json::to_string_pretty(&entries).ok();
    let keylog_stale = match (std::fs::read_to_string(keylog), encoded.as_ref()) {
        (Ok(existing), Some(fresh)) => existing != *fresh,
        _ => true,
    };
    if keylog_stale {
        if let Some(json) = encoded {
            let tmp = dir.join("keylog_offsets.json.tmp");
            match std::fs::write(&tmp, json) {
                Ok(()) => match std::fs::rename(&tmp, keylog) {
                    Ok(()) => status.push(format!(
                        "keylog probe: atomically wrote keylog_offsets.json ({} entries)",
                        entries.len()
                    )),
                    Err(error) => status.push(format!(
                        "keylog probe: rename keylog_offsets.json failed: {error}"
                    )),
                },
                Err(error) => status.push(format!(
                    "keylog probe: write keylog_offsets.json.tmp failed: {error}"
                )),
            }
        }
    }
    status
}

fn device_stack_table_stale(existing: &str, embedded: &str, agent: &str) -> bool {
    let Ok(on_device) = serde_json::from_str::<serde_json::Value>(existing) else {
        return true;
    };
    let Ok(want) = serde_json::from_str::<serde_json::Value>(embedded) else {
        return false;
    };
    let schema = on_device
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let want_schema = want
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if schema != want_schema {
        return true;
    }
    let device_agent = on_device
        .get("agent_version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    device_agent != agent
}

fn merge_local_stack_table(path: &Path, embedded: &str, agent: &str) -> String {
    let mut root: serde_json::Value =
        serde_json::from_str(embedded).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(obj) = root.as_object_mut() {
        obj.insert(
            "agent_version".to_owned(),
            serde_json::Value::String(agent.to_owned()),
        );
    }
    if let Ok(existing) = std::fs::read_to_string(path) {
        if let Ok(local) = serde_json::from_str::<serde_json::Value>(&existing) {
            let local_stacks = local
                .get("stacks")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            if let Some(stacks) = root.get_mut("stacks").and_then(|v| v.as_array_mut()) {
                let embedded_ids: std::collections::BTreeSet<String> = stacks
                    .iter()
                    .filter_map(|row| row.get("id").and_then(serde_json::Value::as_str))
                    .map(ToOwned::to_owned)
                    .collect();
                for row in local_stacks {
                    let source = row
                        .get("source")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    let id = row
                        .get("id")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    if source == "local" && !id.is_empty() && !embedded_ids.contains(id) {
                        stacks.push(row);
                    } else if !id.is_empty() && embedded_ids.contains(id) && source == "local" {
                        eprintln!("stack rule conflict id={id} source=local discarded in favor of embedded");
                    }
                }
            }
        }
    }
    serde_json::to_string_pretty(&root).unwrap_or_else(|_| embedded.to_owned())
}

fn merge_keylog_entries(entries: &mut Vec<KeylogEntry>, extra: Vec<KeylogEntry>) {
    for candidate in extra {
        let exists = entries.iter().any(|entry| {
            entry.offset == candidate.offset
                && entry.build_id == candidate.build_id
                && entry.lib_name == candidate.lib_name
                && entry.size == candidate.size
        });
        if !exists {
            entries.push(candidate);
        }
    }
}

/// First mapped file matching the entry: build-id when given, otherwise the
/// library basename plus optional file size (vendor ELFs often strip notes).
fn mapped_library_matching(pid: u32, entry: &KeylogEntry) -> Option<String> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    let mut checked: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for line in maps.lines() {
        let Some(path) = line.split_whitespace().last() else {
            continue;
        };
        if !path.starts_with('/') || path.contains(" (deleted)") {
            continue;
        }
        if !checked.insert(path.to_owned()) {
            continue;
        }
        if !crate::elf::plausible_elf_file(path) {
            continue;
        }
        let basename = Path::new(path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if let Some(wanted) = entry.lib_name.as_deref() {
            if basename != wanted {
                continue;
            }
            if let Some(size) = entry.size {
                match std::fs::metadata(path) {
                    Ok(meta) if meta.len() == size => {}
                    _ => continue,
                }
            }
            return Some(path.to_owned());
        }
        let elf = std::panic::catch_unwind(|| crate::elf::inspect_elf(path).ok());
        if let Ok(Some(elf)) = elf {
            if !entry.build_id.is_empty() && elf.build_id.as_deref() == Some(&entry.build_id) {
                return Some(path.to_owned());
            }
        }
    }
    None
}

/// Default table path for status output.
pub fn table_path() -> PathBuf {
    PathBuf::from(KEYLOG_TABLE_PATH)
}
