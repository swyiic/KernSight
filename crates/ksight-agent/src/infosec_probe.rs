//! Empirical probe for vendor TLS JNI boundaries (InfosecTcp GMSSL stack).
//!
//! pazq's login/captcha traffic rides `libInfosecMSSL.so`'s exported
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
    symbol: String,
    library: String,
    offset: u64,
    direction: &'static str,
    buffer_arg: Option<u8>,
    length_arg: Option<u8>,
    connection_arg: Option<u8>,
    max_bytes: usize,
    learned_args: Option<(u8, u8)>,
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
    pub requested: u64,
    pub bytes: Vec<u8>,
}

/// Live vendor-boundary probes for one capture session.
pub struct InfosecProbe {
    handles: Vec<InfosecHandle>,
}

impl InfosecProbe {
    /// Attach to every target symbol exported by the process's mapped ELFs.
    ///
    /// Returns the probe plus status lines for the capture log.
    pub fn attach_for_pids(uprobe_object: &Path, pids: &[u32]) -> (Self, Vec<String>) {
        let mut status = Vec::new();
        let mut handles = Vec::new();
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
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
                    if handles.iter().any(|handle: &InfosecHandle| {
                        handle.symbol == name && handle.library == path
                    }) {
                        continue;
                    }
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
                            status.push(format!(
                                "infosec probe attached {name} offset={offset:#x} lib={path}"
                            ));
                            handles.push(InfosecHandle {
                                session,
                                symbol: name.to_owned(),
                                library: path.to_owned(),
                                offset,
                                direction,
                                buffer_arg: boundary.buffer_arg,
                                length_arg: boundary.length_arg,
                                connection_arg: boundary.connection_arg,
                                max_bytes: usize::try_from(boundary.max_bytes.unwrap_or(16 * 1024))
                                    .unwrap_or(16 * 1024)
                                    .clamp(1, 64 * 1024),
                                learned_args: None,
                            });
                            status.push(format!(
                                "vendor boundary stack={} symbol={} layout={} buffer_arg={:?} length_arg={:?}",
                                stack.id, name, boundary.layout, boundary.buffer_arg, boundary.length_arg
                            ));
                        }
                        Err(error) => {
                            status.push(format!("infosec probe attach failed {name}: {error:#}"));
                        }
                    }
                }
            }
        }
        if handles.is_empty() {
            status.push("infosec probe: no vendor TLS boundary symbols found".to_owned());
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
            let Ok(hits) = handle.session.poll_hits() else {
                continue;
            };
            for hit in hits.into_iter().take(256) {
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
                if handle.buffer_arg.is_none() && handle.learned_args.is_none() {
                    handle.learned_args = Some((buffer_arg, length_arg));
                    eprintln!(
                        "vendor boundary learned symbol={} buffer=x{} length=x{} sample={}B",
                        handle.symbol,
                        buffer_arg,
                        length_arg,
                        bytes.len()
                    );
                }
                let connection_id = handle
                    .connection_arg
                    .and_then(|index| hit.regs.get(usize::from(index)).copied())
                    .filter(|value| *value >= 0x1000);
                captures.push(BoundaryCapture {
                    pid: hit.pid,
                    tid: hit.tid,
                    adapter: format!("vendor_boundary:{}", handle.symbol),
                    direction: handle.direction,
                    library: handle.library.clone(),
                    offset: handle.offset,
                    connection_id,
                    requested,
                    bytes,
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
    use super::boundary_sample_score;

    #[test]
    fn boundary_learning_prefers_protocol_and_upload_prefixes() {
        assert_eq!(boundary_sample_score(b"POST /captcha HTTP/1.1\r\n"), 100);
        assert!(boundary_sample_score(b"{\"verifyCode\":\"1234\"}") >= 80);
        assert!(boundary_sample_score(b"\xff\xd8\xff\xe0image") >= 80);
        assert_eq!(boundary_sample_score(&[0; 64]), 0);
    }
}
