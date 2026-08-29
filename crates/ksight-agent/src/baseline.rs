//! Session-start procfs FD/VMA baseline capture.
//!
//! Fills the L0 "pre-session origins" and "pre-session VMAs" gaps: at session
//! start we snapshot the scoped process descriptors and mappings so that
//! in-session events have an explicit pre-existing context. Socket descriptors
//! found by the FD baseline are also returned so the network sensor can seed
//! its `socket_fds` map and identify `read`/`write` on pre-session sockets.

use ksight_model::{
    BaselineFd, BaselineFdKind, BaselineVma, CaptureMode, Confidence, DataQuality, Event,
    EventHeader, EventPayload, ProcessIdentity, ProcessKey, SensorKind, SessionFdBaseline,
    SessionVmaBaseline, CURRENT_SCHEMA,
};
use nix::time::{clock_gettime, ClockId};
use uuid::Uuid;

use crate::scope::CaptureScope;

/// Maximum descriptor entries retained across all FD baseline chunks for one process.
pub const MAX_BASELINE_FDS: usize = 8192;
/// Maximum VMA entries retained across all VMA baseline chunks for one process.
pub const MAX_BASELINE_VMAS: usize = 8192;
/// Maximum processes scanned for a UID-scoped baseline.
pub const MAX_BASELINE_PROCESSES: usize = 1024;
/// Descriptor or VMA entries in one baseline event.
pub const BASELINE_CHUNK: usize = 256;

type BaselineFdEntry = (i32, BaselineFdKind, String);

/// Collect baseline events and the socket descriptors found by the FD scan.
///
/// Whole-device sessions (no pid and no uid) are skipped: a baseline without a
/// concrete scope would be unbounded. Returns the socket `(pid, fd)` pairs so
/// the caller can seed the network sensor before the event loop starts.
#[allow(clippy::too_many_lines)]
pub fn collect(
    scope: &CaptureScope,
    boot_id: Uuid,
    session_id: Uuid,
    include_fds: bool,
    include_vmas: bool,
) -> (Vec<Event>, Vec<(u32, i32)>) {
    let mut events = Vec::new();
    let mut sockets = Vec::new();
    if !include_fds && !include_vmas {
        return (events, sockets);
    }
    if scope.target_tgid.is_none() && scope.target_uid.is_none() && scope.target_package.is_none() {
        return (events, sockets);
    }
    let mut fd_sequence = 0_u64;
    let mut vma_sequence = 0_u64;
    let (pids, process_list_truncated) = baseline_pids(scope);

    for pid in pids {
        let comm = read_trimmed(format!("/proc/{pid}/comm"));
        let (uid, gid) = read_credentials(&format!("/proc/{pid}/status"));
        let identity = ProcessIdentity {
            key: ProcessKey {
                boot_id,
                pid,
                start_time_ns: read_start_time_ns(pid).unwrap_or(0),
            },
            tid: pid,
            tgid: pid,
            uid: uid.unwrap_or(0),
            gid: gid.unwrap_or(0),
            comm,
            command_line: None,
            selinux_context: None,
            packages: Vec::new(),
        };

        if include_fds {
            if let Some((entries, entries_truncated)) = collect_fds(pid) {
                let mut fds = Vec::with_capacity(entries.len());
                for (fd, kind, target) in entries {
                    if matches!(kind, BaselineFdKind::Socket) {
                        sockets.push((pid, fd));
                    }
                    fds.push(BaselineFd { fd, kind, target });
                }
                let chunk_count = chunk_count(fds.len());
                for (chunk_index, chunk) in fds.chunks(BASELINE_CHUNK).enumerate() {
                    fd_sequence = fd_sequence.saturating_add(1);
                    events.push(Event {
                        header: EventHeader {
                            schema: CURRENT_SCHEMA,
                            session_id,
                            source_sequence: fd_sequence,
                            monotonic_ns: now_ns(),
                            cpu: None,
                            process: identity.clone(),
                            sensor: SensorKind::File,
                            mode: CaptureMode::Observe,
                            quality: DataQuality {
                                confidence: Confidence::Partial,
                                truncated: process_list_truncated
                                    || (entries_truncated
                                        && chunk_index + 1 == chunk_count as usize),
                                lost_before: 0,
                                sample_one_in: 1,
                                source: "procfs/fd_baseline".to_owned(),
                            },
                        },
                        payload: EventPayload::SessionFdBaseline(SessionFdBaseline {
                            process_id: pid,
                            fds: chunk.to_vec(),
                            chunk_index: u32::try_from(chunk_index).unwrap_or(u32::MAX),
                            chunk_count,
                        }),
                    });
                }
            }
        }

        if include_vmas {
            if let Some((vmas, vmas_truncated)) = collect_vmas(pid) {
                let chunk_count = chunk_count(vmas.len());
                for (chunk_index, chunk) in vmas.chunks(BASELINE_CHUNK).enumerate() {
                    vma_sequence = vma_sequence.saturating_add(1);
                    events.push(Event {
                        header: EventHeader {
                            schema: CURRENT_SCHEMA,
                            session_id,
                            source_sequence: vma_sequence,
                            monotonic_ns: now_ns(),
                            cpu: None,
                            process: identity.clone(),
                            sensor: SensorKind::Memory,
                            mode: CaptureMode::Observe,
                            quality: DataQuality {
                                confidence: Confidence::Partial,
                                truncated: process_list_truncated
                                    || (vmas_truncated && chunk_index + 1 == chunk_count as usize),
                                lost_before: 0,
                                sample_one_in: 1,
                                source: "procfs/vma_baseline".to_owned(),
                            },
                        },
                        payload: EventPayload::SessionVmaBaseline(SessionVmaBaseline {
                            process_id: pid,
                            vmas: chunk.to_vec(),
                            chunk_index: u32::try_from(chunk_index).unwrap_or(u32::MAX),
                            chunk_count,
                        }),
                    });
                }
            }
        }
    }

    (events, sockets)
}

/// Resolve the candidate baseline processes for a concrete scope.
fn baseline_pids(scope: &CaptureScope) -> (Vec<u32>, bool) {
    if let Some(pid) = scope.target_tgid {
        return (vec![pid], false);
    }
    let uid = scope.target_uid;
    let mut pids = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return (pids, false);
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if uid
            .is_none_or(|target| read_credentials(&format!("/proc/{pid}/status")).0 == Some(target))
        {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    let truncated = pids.len() > MAX_BASELINE_PROCESSES;
    pids.truncate(MAX_BASELINE_PROCESSES);
    (pids, truncated)
}

/// Read `/proc/<pid>/fd/*` up to [`MAX_BASELINE_FDS`] entries.
fn collect_fds(pid: u32) -> Option<(Vec<BaselineFdEntry>, bool)> {
    let root = format!("/proc/{pid}/fd");
    let entries = std::fs::read_dir(&root).ok()?;
    let mut fds = Vec::new();
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(fd) = name.parse::<i32>() else {
            continue;
        };
        let target = std::fs::read_link(entry.path())
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();
        let kind = classify_fd(&target);
        fds.push((fd, kind, target));
    }
    fds.sort_by_key(|(fd, _, _)| *fd);
    let truncated = fds.len() > MAX_BASELINE_FDS;
    fds.truncate(MAX_BASELINE_FDS);
    Some((fds, truncated))
}

fn classify_fd(target: &str) -> BaselineFdKind {
    if target.starts_with("socket:") {
        BaselineFdKind::Socket
    } else if target.starts_with("pipe:") {
        BaselineFdKind::Pipe
    } else if target.is_empty() || target.starts_with("anon_inode:") {
        BaselineFdKind::Other
    } else {
        BaselineFdKind::File
    }
}

/// Read `/proc/<pid>/maps` up to [`MAX_BASELINE_VMAS`] entries.
fn collect_vmas(pid: u32) -> Option<(Vec<BaselineVma>, bool)> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    Some(parse_vmas(&text))
}

fn parse_vmas(text: &str) -> (Vec<BaselineVma>, bool) {
    let mut vmas = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(range) = fields.next() else { continue };
        let Some(perms) = fields.next() else { continue };
        fields.next(); // offset
        fields.next(); // dev
        fields.next(); // inode

        // A procfs maps pathname may itself contain spaces (for example
        // `[page size compat]`). Preserve the complete remainder instead of
        // silently turning it into a misleading path candidate such as
        // `[page`.
        let path = {
            let remainder = fields.collect::<Vec<_>>().join(" ");
            (!remainder.is_empty()).then_some(remainder)
        };
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            continue;
        };
        vmas.push(BaselineVma {
            start,
            end,
            protection: decode_protection(perms),
            path,
        });
    }
    let truncated = vmas.len() > MAX_BASELINE_VMAS;
    vmas.truncate(MAX_BASELINE_VMAS);
    (vmas, truncated)
}

fn chunk_count(len: usize) -> u32 {
    if len == 0 {
        return 0;
    }
    u32::try_from(len.div_ceil(BASELINE_CHUNK)).unwrap_or(u32::MAX)
}

/// Decode the `r/w/x/p` maps permission column into `PROT_*` bits.
fn decode_protection(perms: &str) -> u32 {
    let mut protection = 0;
    for (index, flag) in perms.bytes().enumerate().take(3) {
        let active = flag != b'-';
        match index {
            0 if active => protection |= 1, // PROT_READ
            1 if active => protection |= 2, // PROT_WRITE
            2 if active => protection |= 4, // PROT_EXEC
            _ => {}
        }
    }
    protection
}

fn read_trimmed(path: String) -> String {
    std::fs::read_to_string(path)
        .map(|value| value.trim().to_owned())
        .unwrap_or_default()
}

fn read_credentials(status_path: &str) -> (Option<u32>, Option<u32>) {
    let Ok(status) = std::fs::read_to_string(status_path) else {
        return (None, None);
    };
    let uid = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok());
    let gid = status
        .lines()
        .find(|line| line.starts_with("Gid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok());
    (uid, gid)
}

fn read_start_time_ns(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    let ticks = fields.nth(19)?.parse::<u64>().ok()?;
    let ticks_per_second = nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK)
        .ok()
        .flatten()
        .and_then(|value| u64::try_from(value).ok())?;
    ticks
        .checked_mul(1_000_000_000)
        .map(|nanoseconds| nanoseconds / ticks_per_second)
}

fn now_ns() -> u64 {
    clock_gettime(ClockId::CLOCK_MONOTONIC)
        .ok()
        .and_then(|time| {
            let seconds = u64::try_from(time.tv_sec()).ok()?;
            let nanoseconds = u64::try_from(time.tv_nsec()).ok()?;
            seconds
                .checked_mul(1_000_000_000)
                .and_then(|value| value.checked_add(nanoseconds))
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fd_classification_recognizes_sockets() {
        assert_eq!(classify_fd("socket:[12345]"), BaselineFdKind::Socket);
        assert_eq!(classify_fd("pipe:[54321]"), BaselineFdKind::Pipe);
        assert_eq!(
            classify_fd("/data/app/com.example/x.apk"),
            BaselineFdKind::File
        );
        assert_eq!(classify_fd("anon_inode:[eventfd]"), BaselineFdKind::Other);
        assert_eq!(classify_fd(""), BaselineFdKind::Other);
    }

    #[test]
    fn protection_decode_covers_read_write_exec() {
        assert_eq!(decode_protection("r--p"), 1);
        assert_eq!(decode_protection("rw-p"), 3);
        assert_eq!(decode_protection("r-xp"), 5);
        assert_eq!(decode_protection("rwxp"), 7);
        assert_eq!(decode_protection("---p"), 0);
    }

    #[test]
    fn maps_parser_preserves_paths_with_spaces() {
        let (vmas, truncated) = parse_vmas("1000-2000 r--p 00000000 00:00 0 [page size compat]\n");
        assert!(!truncated);
        assert_eq!(vmas.len(), 1);
        assert_eq!(vmas[0].path.as_deref(), Some("[page size compat]"));
    }
}
