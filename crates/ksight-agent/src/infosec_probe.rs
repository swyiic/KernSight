//! Empirical probe for vendor TLS JNI boundaries (InfosecTcp GMSSL stack).
//!
//! Vendor GM TLS JNI traffic rides `libInfosecMSSL.so`'s exported
//! `Java_InfosecTcp_writeSSLDataNative` / `readSSLDataNative`. The JNI argument
//! layout is not documented, so this probe dumps registers x0-x7 plus bounded
//! memory at each plausible pointer argument for offline layout analysis.
//! Once the layout is pinned, the decoded path graduates to a real adapter.
#![cfg(any(target_os = "android", target_os = "linux"))]

use std::path::Path;

use ksight_hwbp::UprobeSession;

/// Fallback boundary symbols; the unified rules table takes precedence.
const FALLBACK_SYMBOLS: [&str; 4] = [
    "Java_InfosecTcp_writeSSLDataNative",
    "Java_InfosecTcp_readSSLDataNative",
    "Java_InfosecTcp_writeSSLData",
    "Java_InfosecTcp_readSSLData",
];

/// One attached vendor boundary probe.
struct InfosecHandle {
    session: UprobeSession,
    /// Optional uretprobe session when capture_phase needs return pairing
    /// and paired start_entry_return was unavailable.
    ret_session: Option<UprobeSession>,
    /// True when entry+return share one BPF load (`snapshot_at_return`).
    paired_entry_return: bool,
    symbol: String,
    library: String,
    offset: u64,
    direction: &'static str,
    buffer_arg: Option<u8>,
    length_arg: Option<u8>,
    output_length_arg: Option<u8>,
    connection_arg: Option<u8>,
    stream_arg: Option<u8>,
    capture_phase: Option<ksight_core::CapturePhase>,
    return_semantics: Option<String>,
    is_header: Option<bool>,
    is_body: Option<bool>,
    confidence: Option<String>,
    max_bytes: usize,
    learned_args: Option<(u8, u8)>,
    /// Consistent inferences in this session for this symbol+build-id only.
    learned_hits: u8,
    last_inferred: Option<(u8, u8)>,
    build_id: Option<String>,
    /// Entry frames waiting for return when capture_phase requires pairing.
    pending: std::collections::HashMap<(u32, u32), PendingBoundary>,
}

struct PendingBoundary {
    buffer: u64,
    requested: u64,
    connection_id: Option<u64>,
    stream_id: Option<u64>,
}

/// A decoded plaintext hit from a rule whose ABI layout is pinned.
pub struct BoundaryCapture {
    pub pid: u32,
    pub tid: u32,
    pub adapter: String,
    pub direction: &'static str,
    pub library: String,
    pub offset: u64,
    pub connection_id: Option<u64>,
    pub stream_id: Option<u64>,
    pub requested: u64,
    pub bytes: Vec<u8>,
    pub is_header: Option<bool>,
    pub is_body: Option<bool>,
    pub confidence: Option<String>,
}

/// Live vendor-boundary probes for one capture session.
pub struct InfosecProbe {
    handles: Vec<InfosecHandle>,
}

fn automatic_boundary_allowed(layout: &str, allow_empirical: bool) -> bool {
    allow_empirical || layout.eq_ignore_ascii_case("pinned")
}

impl InfosecProbe {
    /// Attach to every target symbol exported by the process's mapped ELFs.
    ///
    /// Returns the probe plus status lines for the capture log.
    pub fn attach_for_pids(
        uprobe_object: &Path,
        pids: &[u32],
        allow_empirical: bool,
    ) -> (Self, Vec<String>) {
        let mut status = Vec::new();
        let mut handles = Vec::new();
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut deferred_empirical = std::collections::BTreeSet::new();
        for pid in pids.iter().copied().take(8) {
            let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
                continue;
            };
            for line in maps.lines() {
                let Some(path) = line.split_whitespace().last() else {
                    continue;
                };
                if !path.starts_with('/') || path.contains(" (deleted)") {
                    continue;
                }
                if !crate::elf::plausible_elf_file(path) {
                    continue;
                }
                if !seen.insert(path.to_owned()) {
                    continue;
                }
                let Ok(elf) = crate::elf::inspect_elf(path) else {
                    continue;
                };
                let targets: Vec<String> = {
                    let from_rules = ksight_core::boundary_symbols();
                    if from_rules.is_empty() {
                        FALLBACK_SYMBOLS.iter().map(|s| s.to_string()).collect()
                    } else {
                        from_rules
                    }
                };
                for symbol in &targets {
                    let needle: &str = symbol.as_str();
                    let Some((name, offset)) = crate::elf::matching_symbols_exact(&elf, &[needle])
                        .into_iter()
                        .next()
                    else {
                        continue;
                    };
                    let Some((stack, boundary, direction)) =
                        ksight_core::boundary_rule_for_symbol(name)
                    else {
                        continue;
                    };
                    if !automatic_boundary_allowed(&boundary.layout, allow_empirical) {
                        deferred_empirical.insert(format!("{}:{name}", stack.id));
                        continue;
                    }
                    if handles.iter().any(|handle: &InfosecHandle| {
                        handle.symbol == name && handle.library == path
                    }) {
                        continue;
                    }
                    // Prefer per-function BoundaryFunction row when present.
                    let function = ksight_core::boundary_functions()
                        .into_iter()
                        .find(|(_, function)| function.symbol == name)
                        .map(|(_, function)| function);
                    let buffer_arg = function
                        .as_ref()
                        .and_then(|f| f.buffer_arg)
                        .or(boundary.buffer_arg);
                    let length_arg = function
                        .as_ref()
                        .and_then(|f| f.length_arg)
                        .or(boundary.length_arg);
                    let connection_arg = function
                        .as_ref()
                        .and_then(|f| f.connection_arg)
                        .or(boundary.connection_arg);
                    let max_bytes = function
                        .as_ref()
                        .and_then(|f| f.max_bytes)
                        .or(boundary.max_bytes)
                        .unwrap_or(16 * 1024);
                    let capture_phase = function.as_ref().and_then(|f| f.capture_phase);
                    let needs_return = matches!(
                        capture_phase,
                        Some(ksight_core::CapturePhase::Return)
                            | Some(ksight_core::CapturePhase::EntryAndReturn)
                    ) || function
                        .as_ref()
                        .and_then(|f| f.return_semantics.as_deref())
                        .is_some_and(|s| {
                            let s = s.to_ascii_lowercase();
                            s.contains("return") || s.contains("out_len")
                        });
                    let started = if needs_return {
                        match UprobeSession::start_entry_return(
                            uprobe_object,
                            Path::new(path),
                            offset,
                            None,
                            false,
                        ) {
                            Ok(mut session) => {
                                let _ = session.apply_tgid_filter(Some(pids));
                                Some((session, None, true))
                            }
                            Err(_) => match UprobeSession::start_program(
                                uprobe_object,
                                "ksight_uprobe_regs",
                                Path::new(path),
                                offset,
                                None,
                                false,
                            ) {
                                Ok(mut session) => {
                                    let _ = session.apply_tgid_filter(Some(pids));
                                    let ret_session = UprobeSession::start_program(
                                        uprobe_object,
                                        "ksight_uretprobe_regs",
                                        Path::new(path),
                                        offset,
                                        None,
                                        false,
                                    )
                                    .ok()
                                    .map(|mut ret| {
                                        let _ = ret.apply_tgid_filter(Some(pids));
                                        ret
                                    });
                                    Some((session, ret_session, false))
                                }
                                Err(error) => {
                                    status.push(format!(
                                        "infosec probe attach failed {name}: {error:#}"
                                    ));
                                    None
                                }
                            },
                        }
                    } else {
                        match UprobeSession::start_program(
                            uprobe_object,
                            "ksight_uprobe_regs",
                            Path::new(path),
                            offset,
                            None,
                            false,
                        ) {
                            Ok(mut session) => {
                                let _ = session.apply_tgid_filter(Some(pids));
                                Some((session, None, false))
                            }
                            Err(error) => {
                                status.push(format!(
                                    "infosec probe attach failed {name}: {error:#}"
                                ));
                                None
                            }
                        }
                    };
                    let Some((session, ret_session, paired_entry_return)) = started else {
                        continue;
                    };
                    let pair_note = if paired_entry_return {
                        " paired_entry_return=true"
                    } else if ret_session.is_some() {
                        " uretprobe=separate"
                    } else {
                        ""
                    };
                    status.push(format!(
                        "infosec probe attached {name} offset={offset:#x} lib={path}{pair_note}"
                    ));
                    handles.push(InfosecHandle {
                        session,
                        ret_session,
                        paired_entry_return,
                        symbol: name.to_owned(),
                        library: path.to_owned(),
                        offset,
                        direction,
                        buffer_arg,
                        length_arg,
                        output_length_arg: function.as_ref().and_then(|f| f.output_length_arg),
                        connection_arg,
                        stream_arg: function.as_ref().and_then(|f| f.stream_arg),
                        capture_phase,
                        return_semantics: function.as_ref().and_then(|f| f.return_semantics.clone()),
                        is_header: function.as_ref().and_then(|f| f.is_header),
                        is_body: function.as_ref().and_then(|f| f.is_body),
                        confidence: function.as_ref().and_then(|f| f.confidence.clone()),
                        max_bytes: usize::try_from(max_bytes)
                            .unwrap_or(16 * 1024)
                            .clamp(1, 64 * 1024),
                        learned_args: None,
                        learned_hits: 0,
                        last_inferred: None,
                        build_id: None,
                        pending: std::collections::HashMap::new(),
                    });
                    status.push(format!(
                        "vendor boundary stack={} symbol={} layout={} buffer_arg={:?} length_arg={:?} phase={:?} header={:?} body={:?}",
                        stack.id, name, boundary.layout, buffer_arg, length_arg, capture_phase,
                        function.as_ref().and_then(|f| f.is_header),
                        function.as_ref().and_then(|f| f.is_body)
                    ));
                }
            }
        }
        if handles.is_empty() {
            status.push("infosec probe: no vendor TLS boundary symbols found".to_owned());
        }
        if !deferred_empirical.is_empty() {
            status.push(format!(
                "auto-discovery deferred {} empirical vendor boundary candidate(s); only pinned ABI rules attach automatically",
                deferred_empirical.len()
            ));
        }
        (Self { handles }, status)
    }

    /// True while at least one boundary probe is armed.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        !self.handles.is_empty()
    }

    /// Drain hits; returns hex-dump lines for layout analysis.
    pub fn poll(&mut self, pids: &[u32]) -> Vec<String> {
        let mut lines = Vec::new();
        for handle in &mut self.handles {
            if handle.buffer_arg.is_some() && handle.length_arg.is_some() {
                continue;
            }
            let Ok(hits) = handle.session.poll_hits() else {
                continue;
            };
            for hit in hits.iter().take(64) {
                let mut regs = [0u64; 8];
                for (index, reg) in regs.iter_mut().enumerate() {
                    *reg = hit.regs[index];
                }
                let mut line = format!(
                    "infosec {} pid={} tid={} x0={:x} x1={:x} x2={:x} x3={:x} x4={:x} x5={:x}",
                    handle.symbol,
                    hit.pid,
                    hit.tid,
                    regs[0],
                    regs[1],
                    regs[2],
                    regs[3],
                    regs[4],
                    regs[5]
                );
                // Dump bounded memory at each pointer-shaped argument.
                for (index, value) in regs.iter().enumerate().skip(2) {
                    if *value > 0x1000 && *value < 0x0000_8000_0000_0000 {
                        if let Some(bytes) =
                            crate::inspect_runtime::read_remote_bytes(hit.pid, *value, 48)
                        {
                            if !bytes.iter().all(|byte| *byte == 0) {
                                let hex: String =
                                    bytes.iter().map(|byte| format!("{byte:02x}")).collect();
                                line.push_str(&format!(" x{index}mem={hex}"));
                            }
                        }
                    }
                }
                let _ = pids;
                lines.push(line);
            }
        }
        lines
    }

    /// Drain boundary hits into structured plaintext. A pinned rule wins. For
    /// empirical rules, a bounded ARM64 pointer/length pair is learned from a
    /// recognizable HTTP, JSON, form, or image prefix and then reused for the
    /// remainder of this selected-package session.
    pub fn poll_captures(&mut self) -> Vec<BoundaryCapture> {
        let mut captures = Vec::new();
        for handle in &mut self.handles {
            // Entry hits (and return hits when paired_entry_return).
            let Ok(mut hits) = handle.session.poll_hits() else {
                continue;
            };
            hits.sort_by_key(|hit| hit.time_ns);
            let (entry_hits, ret_hits_paired): (Vec<_>, Vec<_>) = if handle.paired_entry_return {
                let mut entry = Vec::new();
                let mut ret = Vec::new();
                for hit in hits.into_iter().take(256) {
                    if hit.snapshot_at_return {
                        ret.push(hit);
                    } else {
                        entry.push(hit);
                    }
                }
                (entry, ret)
            } else {
                (hits.into_iter().take(256).collect(), Vec::new())
            };
            for hit in entry_hits {
                let args = handle
                    .buffer_arg
                    .zip(handle.length_arg)
                    .or(handle.learned_args)
                    .or_else(|| infer_boundary_args(hit.pid, &hit.regs, handle.max_bytes));
                let Some((buffer_arg, length_arg)) = args else {
                    continue;
                };
                let Some(&buffer) = hit.regs.get(usize::from(buffer_arg)) else {
                    continue;
                };
                let requested = hit.regs.get(usize::from(length_arg)).copied().unwrap_or(0);
                if buffer < 0x1000 || requested == 0 {
                    continue;
                }
                if handle.buffer_arg.is_none() && handle.learned_args.is_none() {
                    let inferred = (buffer_arg, length_arg);
                    if handle.last_inferred == Some(inferred) {
                        handle.learned_hits = handle.learned_hits.saturating_add(1);
                    } else {
                        handle.last_inferred = Some(inferred);
                        handle.learned_hits = 1;
                    }
                    if handle.learned_hits >= 3 {
                        handle.learned_args = Some(inferred);
                        eprintln!(
                            "vendor boundary learned symbol={} build_id={} buffer=x{} length=x{} hits={}",
                            handle.symbol,
                            handle.build_id.as_deref().unwrap_or("-"),
                            buffer_arg,
                            length_arg,
                            handle.learned_hits
                        );
                    }
                }
                let connection_id = handle
                    .connection_arg
                    .and_then(|index| hit.regs.get(usize::from(index)).copied())
                    .filter(|value| *value >= 0x1000);
                let stream_id = handle
                    .stream_arg
                    .and_then(|index| hit.regs.get(usize::from(index)).copied())
                    .filter(|value| *value >= 0x1000);
                let needs_return = handle.ret_session.is_some()
                    || matches!(
                        handle.capture_phase,
                        Some(ksight_core::CapturePhase::Return)
                            | Some(ksight_core::CapturePhase::EntryAndReturn)
                    );
                if needs_return {
                    if handle.pending.len() < 256 {
                        handle.pending.insert(
                            (hit.pid, hit.tid),
                            PendingBoundary {
                                buffer,
                                requested,
                                connection_id,
                                stream_id,
                            },
                        );
                    }
                    continue;
                }
                let want = usize::try_from(requested)
                    .unwrap_or(usize::MAX)
                    .min(handle.max_bytes);
                let Some(bytes) = crate::inspect_runtime::read_remote_bytes(hit.pid, buffer, want)
                else {
                    continue;
                };
                if bytes.is_empty() {
                    continue;
                }
                captures.push(BoundaryCapture {
                    pid: hit.pid,
                    tid: hit.tid,
                    adapter: format!("vendor_boundary:{}", handle.symbol),
                    direction: handle.direction,
                    library: handle.library.clone(),
                    offset: handle.offset,
                    connection_id,
                    stream_id,
                    requested,
                    bytes,
                    is_header: handle.is_header,
                    is_body: handle.is_body,
                    confidence: handle.confidence.clone(),
                });
            }

            // Return hits: paired session first, else separate uretprobe.
            let ret_hits = if handle.paired_entry_return {
                ret_hits_paired
            } else {
                let Some(ret_session) = handle.ret_session.as_mut() else {
                    continue;
                };
                let Ok(hits) = ret_session.poll_hits() else {
                    continue;
                };
                hits.into_iter().take(256).collect()
            };
            for hit in ret_hits {
                let Some(pending) = handle.pending.remove(&(hit.pid, hit.tid)) else {
                    continue;
                };
                let mut requested = pending.requested;
                if let Some(out_arg) = handle.output_length_arg {
                    if let Some(&out_len) = hit.regs.get(usize::from(out_arg)) {
                        if out_len > 0 && out_len <= requested {
                            requested = out_len;
                        }
                    }
                } else if handle
                    .return_semantics
                    .as_deref()
                    .is_some_and(|s| s.to_ascii_lowercase().contains("return"))
                {
                    let signed = hit.regs[0] as i64;
                    if signed > 0 {
                        requested = signed as u64;
                    }
                }
                if pending.buffer < 0x1000 || requested == 0 {
                    continue;
                }
                let want = usize::try_from(requested)
                    .unwrap_or(usize::MAX)
                    .min(handle.max_bytes);
                let Some(bytes) =
                    crate::inspect_runtime::read_remote_bytes(hit.pid, pending.buffer, want)
                else {
                    continue;
                };
                if bytes.is_empty() {
                    continue;
                }
                captures.push(BoundaryCapture {
                    pid: hit.pid,
                    tid: hit.tid,
                    adapter: format!("vendor_boundary:{}", handle.symbol),
                    direction: handle.direction,
                    library: handle.library.clone(),
                    offset: handle.offset,
                    connection_id: pending.connection_id,
                    stream_id: pending.stream_id,
                    requested,
                    bytes,
                    is_header: handle.is_header,
                    is_body: handle.is_body,
                    confidence: handle.confidence.clone(),
                });
            }
        }
        captures
    }
}

fn infer_boundary_args(pid: u32, regs: &[u64; 31], max_bytes: usize) -> Option<(u8, u8)> {
    const PAIRS: [(u8, u8); 7] = [(2, 3), (1, 2), (3, 4), (0, 1), (4, 5), (5, 6), (6, 7)];
    let mut best: Option<(u32, u8, u8)> = None;
    for (buffer_arg, length_arg) in PAIRS {
        let buffer = regs[usize::from(buffer_arg)] & 0x00ff_ffff_ffff_ffff;
        let length = regs[usize::from(length_arg)];
        if buffer < 0x1_0000 || length == 0 || length > max_bytes as u64 {
            continue;
        }
        let sample_len = usize::try_from(length).unwrap_or(max_bytes).min(512);
        let Some(sample) = crate::inspect_runtime::read_remote_bytes(pid, buffer, sample_len)
        else {
            continue;
        };
        let score = boundary_sample_score(&sample);
        if score > 0 && best.is_none_or(|(current, _, _)| score > current) {
            best = Some((score, buffer_arg, length_arg));
        }
    }
    best.map(|(_, buffer, length)| (buffer, length))
}

fn boundary_sample_score(bytes: &[u8]) -> u32 {
    if bytes.is_empty() || bytes.iter().all(|byte| *byte == 0) {
        return 0;
    }
    let http = [
        b"GET ".as_slice(),
        b"POST ".as_slice(),
        b"PUT ".as_slice(),
        b"PATCH ".as_slice(),
        b"DELETE ".as_slice(),
        b"HTTP/1.".as_slice(),
    ]
    .iter()
    .any(|needle| bytes.starts_with(needle));
    if http {
        return 100;
    }
    if bytes.starts_with(b"{")
        || bytes.starts_with(b"[")
        || bytes.starts_with(b"\xff\xd8\xff")
        || bytes.starts_with(b"\x89PNG")
    {
        return 80;
    }
    if bytes
        .windows(19)
        .any(|window| window == b"multipart/form-data")
        || bytes.windows(8).any(|window| window == b"https://")
        || bytes.windows(5).any(|window| window == b"code=")
    {
        return 60;
    }
    let printable = bytes
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || matches!(byte, b' ' | b'\r' | b'\n' | b'\t'))
        .count();
    (printable.saturating_mul(100) / bytes.len() >= 85)
        .then_some(20)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{automatic_boundary_allowed, boundary_sample_score};

    #[test]
    fn automatic_mode_only_arms_pinned_boundaries() {
        assert!(automatic_boundary_allowed("pinned", false));
        assert!(!automatic_boundary_allowed("empirical", false));
        assert!(automatic_boundary_allowed("empirical", true));
    }

    #[test]
    fn boundary_learning_prefers_protocol_and_upload_prefixes() {
        assert_eq!(boundary_sample_score(b"POST /v1/ping HTTP/1.1\r\n"), 100);
        assert!(boundary_sample_score(b"{\"status\":\"ok\"}") >= 80);
        assert!(boundary_sample_score(b"\xff\xd8\xff\xe0image") >= 80);
        assert_eq!(boundary_sample_score(&[0; 64]), 0);
    }
}
