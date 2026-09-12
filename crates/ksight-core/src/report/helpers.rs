//! Handshake stamp merge, loopback collapse, and report labeling helpers.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    LoopbackScanActivity, MutableHandshake, MutableNetworkPeerActivity, NetworkPeerActivity,
};

pub(super) fn merge_handshake(dst: &mut MutableHandshake, src: &MutableHandshake) {
    if dst.kind.is_empty() {
        dst.kind.clone_from(&src.kind);
    } else if !src.kind.is_empty() && !dst.kind.split(',').any(|part| part == src.kind) {
        dst.kind = format!("{},{}", dst.kind, src.kind);
    }
    if dst.sni.is_none() {
        dst.sni.clone_from(&src.sni);
    }
    if dst.alpn.is_none() {
        dst.alpn.clone_from(&src.alpn);
    }
    if dst.http_host.is_none() {
        dst.http_host.clone_from(&src.http_host);
    }
    if dst.http_method.is_none() {
        dst.http_method.clone_from(&src.http_method);
    }
}

pub(super) fn apply_handshake(activity: &mut MutableNetworkPeerActivity, stamp: &MutableHandshake) {
    if activity.sni.is_none() {
        activity.sni.clone_from(&stamp.sni);
    }
    if activity.alpn.is_none() {
        activity.alpn.clone_from(&stamp.alpn);
    }
    if activity.http_host.is_none() {
        activity.http_host.clone_from(&stamp.http_host);
    }
    if activity.http_method.is_none() {
        activity.http_method.clone_from(&stamp.http_method);
    }
    if activity.handshake_kind.is_none() {
        if !stamp.kind.is_empty() {
            activity.handshake_kind = Some(stamp.kind.clone());
        }
    } else if let Some(existing) = activity.handshake_kind.as_mut() {
        if !stamp.kind.is_empty() && !existing.split(',').any(|part| part == stamp.kind) {
            existing.push(',');
            existing.push_str(&stamp.kind);
        }
    }
}

#[allow(clippy::type_complexity)]
pub(super) fn collapse_loopback_scans(
    peers: &mut Vec<NetworkPeerActivity>,
) -> Vec<LoopbackScanActivity> {
    let mut unique: BTreeMap<(u32, String), BTreeSet<u16>> = BTreeMap::new();
    for peer in peers.iter() {
        if let Some(port) = peer.port {
            if peer.peer == "127.0.0.1" || peer.peer == "::1" {
                unique
                    .entry((peer.source_process_id, peer.peer.clone()))
                    .or_default()
                    .insert(port);
            }
        }
    }
    let collapse: BTreeSet<(u32, String)> = unique
        .into_iter()
        .filter(|(_, ports)| ports.len() >= 16)
        .map(|(key, _)| key)
        .collect();
    let mut grouped: BTreeMap<(u32, String, String), (u16, u16, u64, u64)> = BTreeMap::new();
    peers.retain(|peer| {
        let key = (peer.source_process_id, peer.peer.clone());
        if !collapse.contains(&key) {
            return true;
        }
        let Some(port) = peer.port else {
            return true;
        };
        let slot = grouped
            .entry((
                peer.source_process_id,
                peer.source.clone(),
                peer.peer.clone(),
            ))
            .or_insert((port, port, 0, 0));
        slot.0 = slot.0.min(port);
        slot.1 = slot.1.max(port);
        slot.2 = slot.2.saturating_add(1);
        slot.3 = slot.3.saturating_add(peer.attempts);
        false
    });
    let mut scans = grouped
        .into_iter()
        .map(
            |((process_id, source, address), (port_min, port_max, unique_ports, attempts))| {
                LoopbackScanActivity {
                    source,
                    process_id,
                    address,
                    port_min,
                    port_max,
                    unique_ports,
                    attempts,
                }
            },
        )
        .collect::<Vec<_>>();
    scans.sort_by_key(|scan| std::cmp::Reverse(scan.attempts));
    scans
}

pub(super) fn mode_name(mode: ksight_model::CaptureMode) -> &'static str {
    match mode {
        ksight_model::CaptureMode::Observe => "observe",
        ksight_model::CaptureMode::Inspect => "inspect",
        ksight_model::CaptureMode::Debug => "debug",
    }
}

pub(super) fn path_category(path: &str) -> &'static str {
    let lower = path.to_ascii_lowercase();
    let extension = std::path::Path::new(path)
        .extension()
        .and_then(std::ffi::OsStr::to_str);
    if extension.is_some_and(|value| {
        value.eq_ignore_ascii_case("dex")
            || value.eq_ignore_ascii_case("odex")
            || value.eq_ignore_ascii_case("vdex")
    }) {
        "dex"
    } else if extension
        .is_some_and(|value| value.eq_ignore_ascii_case("apk") || value.eq_ignore_ascii_case("jar"))
    {
        "android_package"
    } else if extension.is_some_and(|value| value.eq_ignore_ascii_case("so"))
        || lower.contains("/lib/")
    {
        "native_elf_candidate"
    } else if lower.starts_with("/proc/") {
        "proc"
    } else if lower.starts_with("/sys/") {
        "sys"
    } else if lower.starts_with("/data/") {
        "app_or_system_data"
    } else {
        "other"
    }
}

pub(super) fn plaintext_graph_relation(adapter: &str, direction: &str) -> &'static str {
    if adapter.starts_with("jni_") {
        match direction {
            "java_to_native" => "jni_from_java",
            "native_to_java" => "jni_to_java",
            _ => "jni_plain",
        }
    } else if direction == "recv" {
        "tls_recv"
    } else {
        "tls_send"
    }
}

pub(super) fn report_limitations() -> Vec<String> {
    vec![
        "Binder driver submission-to-delivery latency is correlated by transaction ID. Two-way RPCs pair reply submit to the request debug_id (binder_reply / replies_to, confirmed). A 128-byte parcel prefix is copied at kprobe binder_transaction (every online CPU) for 32-bit and 64-bit clients (native UAPI after compat conversion) and parsed as writeInterfaceToken String16. Inspect transact joins that request by tid+code as correlated joined_transact and copies reply latency when the kernel pair exists. Inspect pairs writeInterfaceToken and bounded exported Parcel writers on the same TID on ELF64; this GKI rejects AArch32 uprobes. AIDL method names come from on-device AOSP Stub tables (aosp_stub) or that process's loaded DEX TRANSACTION_* (process_dex). Parcel C++ object fields and writeFloat/writeDouble (no FPSIMD in uprobe pt_regs) are not read.".to_owned(),
        "DEX, ELF, connlog, and packed-cache path candidates may include a SHA-256 when a regular file <= 1 MiB is opened; capture also copies those forensic files under the spool forensics directory because apps often delete packed DEX after load.".to_owned(),
        "Connect/accept and FD baseline/dup/close evidence reconstruct descriptor lifetimes. Optional network-io counts byte-returning socket calls and reports sendmmsg/recvmmsg results as message counts. UDP/53 datagrams parse QNAME/A/AAAA and stamp later connect() as correlated resolved_name (same-process first, then any resolver that answered the IP). getaddrinfo uprobes and non-53 resolvers remain uncovered. TLS/QUIC plaintext is Inspect-only. Consecutive SSL_read/SSL_write text previews for one process are stitched up to 16 KiB. gzip/zlib magic in those buffers is inflated before HTTP/JSON/`http(s)://` URL parse. HTTP/1 request-line, Host, query keys, JSON/form keys, embedded URLs, and HTTP/2 HEADERS HPACK (`:method`/`:path`/`:authority`) go into http_calls; Cookie/Authorization/token values are redacted. HTTP responses have no URL path. Heap windows that start at HTTP/1.1, GET/POST, `https://`, `\"url\"`, `/api/`, `/login`, `/mbfront`, or `:path`/`:authority` are 8192-byte cuts (NUL or CRLF), not a full memory image. CE/DE shared_prefs/SQLite copies contribute origin=private URL rows. Same-process same-host request/response pairs are correlated http_reply. HPACK is report-side analysis of already-copied Inspect/dump buffers, not MITM. QUIC v1 Initial datagrams are decrypted in user space (RFC 9001, no hook) and the ClientHello SNI/ALPN land in handshake names; QUIC/HTTP/3 application bodies, Cronet without SSL_write, Flutter Dart TLS, WebView/Chromium, and custom TLS without that export are not decoded.".to_owned(),
        "The L0 graph is queryable (`ksightctl device graph`). Process instances use `procinst:{boot_id:pid:start_time_ns}` when start time is known; otherwise `process:pkg:pid`. Confirmed edges are Binder, Binder `replies_to`/`binder_reply` (request debug_id), socket, Binder FD `transfers_fd`, loopback scans, sched wakeup identity, and mmap/remap `maps` edges. Dump VMA `overlaps_mmap` is correlated even on an exact address match. Inspect `inspect_hit` and TLS `tls_send`/`tls_recv` are selected-process facts, not Observe. JNIEnv UTF-8/`byte[]` Inspect previews graph as `jni_from_java`/`jni_to_java` (confirmed selected-process, not Observe). Inspect HTTP `http_call` edges are parsed from those TLS or JNI previews (HTTP/1, HTTP/2 HPACK, JSON, or embedded URLs); dump heap `http_call` edges are correlated. Same-host `http_reply` is correlated, not a stream id. Binder userspace hits record handle/code and join L0 `binder:req` by tid+code as correlated `joined_transact`. The interface token and bounded scalars come from exported Parcel writers on the same TID. AIDL names come from on-device AOSP Stub tables or session process DEX; they are not hardcoded GMS/app names. Parcel C++ fields are not read. RegisterNatives copies JNINativeMethod name/signature/fnPtr from the JNINativeInterface slot; jclass fields and Java/native stacks remain unresolved. Cronet/QUIC and custom TLS remain unresolved. Time proximity is never a confirmed edge.".to_owned(),
        "dup/close file-descriptor events are off unless --files-fd is set. WebView/Chromium dup storms previously overflowed the file ring and dropped millions of records.".to_owned(),
        "Sampling, truncation, source loss, compatibility failures, or target early exit can make application behavior incomplete.".to_owned(),
    ]
}
