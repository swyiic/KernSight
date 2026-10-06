//! Bounded L2 forensic memory snapshots. Explicit, selected-process, paused, hashed.

use std::{
    fs::File,
    io::{SeekFrom, Write as _},
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::dexdump::{
    blob_map_class, can_join_harvest, extend_span, parse_maps, pids_for_package, MapRow,
    StoppedProcess,
};

/// Schema identifier for `snapshot-report.json`.
pub const SNAPSHOT_SCHEMA: &str = "mobilee.kernsight-memory-snapshot/v1";
const MIN_RANGE: u64 = 256 * 1024;
const MAX_RANGE: u64 = 64 * 1024 * 1024;
const MAX_RANGES: usize = 24;
const DEFAULT_MAX_BYTES: u64 = 32 * 1024 * 1024;

/// Operator request for one forensic snapshot.
#[derive(Debug, Clone)]
pub struct SnapshotRequest {
    /// Destination directory that receives the report and range files.
    pub dest: PathBuf,
    /// Optional package used to resolve PIDs.
    pub package: Option<String>,
    /// Explicit PID; when set with a package it must belong to that package.
    pub pid: Option<u32>,
    /// Inclusive copy start. Requires [`Self::end`].
    pub start: Option<u64>,
    /// Exclusive copy end. Requires [`Self::start`].
    pub end: Option<u64>,
    /// Hard cap on copied bytes. Zero uses 32 MiB.
    pub max_bytes: u64,
    /// When false, copy without `SIGSTOP` and mark the report torn.
    pub pause: bool,
}

/// One copied mapping or stitched span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRange {
    /// Inclusive virtual address.
    pub start: u64,
    /// Exclusive virtual address.
    pub end: u64,
    /// `/proc/<pid>/maps` pathname or anonymous label.
    pub path: String,
    /// Mapping permissions of the first contributing VMA.
    pub perms: String,
    /// Bytes actually written.
    pub bytes: u64,
    /// SHA-256 of the written bytes.
    pub sha256: String,
    /// Path relative to the snapshot root.
    pub relative_path: String,
    /// True when adjacent same-path VMAs were joined.
    #[serde(default)]
    pub stitched: bool,
    /// True when the range was shortened by the byte budget or a short read.
    #[serde(default)]
    pub truncated: bool,
}

/// A selected range could not be copied completely. No secret bytes in this record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotFailure {
    /// Requested inclusive address.
    pub start: u64,
    /// Requested exclusive address.
    pub end: u64,
    /// Only this prefix was retained.
    pub copied_bytes: u64,
    /// `read_failed`, `short_read`, `budget_exhausted`, or `range_cap`.
    pub reason: String,
}

/// A mapping or requested interval that was not copied. No page bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSkipped {
    /// Inclusive virtual address.
    pub start: u64,
    /// Exclusive virtual address.
    pub end: u64,
    /// `outside_explicit`, `not_readable`, `not_selected`, `not_harvestable`, `below_min_range`, or `over_range_cap`.
    pub reason: String,
}

/// Provenance for one paused `/proc/<pid>/mem` copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "These independently selected flags are part of the existing CLI and evidence schema."
)]
pub struct SnapshotReport {
    /// Schema identifier.
    pub schema_version: String,
    /// Agent version that produced the snapshot.
    pub agent_version: String,
    /// Target process.
    pub pid: u32,
    /// Package used to select the process, when any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    /// True when `SIGSTOP` was applied.
    pub paused: bool,
    /// True when the copy raced without a pause.
    pub torn: bool,
    /// Wall milliseconds of the copy window.
    pub elapsed_ms: u64,
    /// Configured byte budget.
    pub max_bytes: u64,
    /// Sum of written range files.
    pub copied_bytes: u64,
    /// True when later ranges were skipped because the budget was exhausted.
    pub truncated: bool,
    /// Copied ranges, in copy order.
    pub ranges: Vec<SnapshotRange>,
    /// Selected spans not copied completely, including zero-byte failures.
    #[serde(default)]
    pub failures: Vec<SnapshotFailure>,
    /// Honest limits.
    pub warnings: Vec<String>,
    /// Sum of mapped VMA lengths. This is not copied memory and not RSS.
    #[serde(default)]
    pub mapped_bytes: u64,
    /// Bytes in the ranges selected before the copy budget.
    #[serde(default)]
    pub selected_bytes: u64,
    /// True only when this call sent SIGSTOP. An already-stopped process stays stopped.
    #[serde(default)]
    pub stopped_by_tool: bool,
    /// `/proc/<pid>/stat` starttime. Distinguishes a recycled PID. Zero means unread.
    #[serde(default)]
    pub process_start_ticks: u64,
    /// `/proc/<pid>/task` entries seen before the copy.
    #[serde(default)]
    pub threads_seen: u32,
    /// SHA-256 of `/proc/<pid>/maps` read before the copy.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub maps_sha256: String,
    /// SHA-256 of `/proc/<pid>/maps` read after the copy, before SIGCONT.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub maps_after_sha256: String,
    /// True when the before and after maps text are identical and non-empty.
    #[serde(default)]
    pub maps_consistent: bool,
    /// Mappings and requested intervals that were not copied.
    #[serde(default)]
    pub unselected: Vec<SnapshotSkipped>,
    /// High-visibility notice. Never an Observe event.
    pub visibility: String,
}

/// Copy selected live mappings of one process into `dest`.
///
/// # Errors
///
/// Returns when no live PID exists, dest cannot be created, or `/proc/<pid>/mem`
/// cannot be read.
#[allow(
    clippy::too_many_lines,
    reason = "Keep the admission or lifecycle transaction together for review."
)]
pub fn snapshot(request: SnapshotRequest) -> Result<SnapshotReport> {
    if request.start.is_some() != request.end.is_some() {
        bail!("--start and --end must be provided together");
    }
    if let (Some(start), Some(end)) = (request.start, request.end) {
        if end <= start {
            bail!("snapshot range end must be greater than start");
        }
    }
    let pid = resolve_pid(&request)?;
    let max_bytes = if request.max_bytes == 0 {
        DEFAULT_MAX_BYTES
    } else {
        request.max_bytes
    };
    std::fs::create_dir_all(&request.dest)
        .with_context(|| format!("create {}", request.dest.display()))?;
    let ranges_dir = request.dest.join("ranges");
    std::fs::create_dir_all(&ranges_dir)?;
    let pause = if request.pause {
        StoppedProcess::enter(pid)
    } else {
        StoppedProcess::inert()
    };
    if request.pause && !pause.active {
        bail!("target stop could not be confirmed; no snapshot copied");
    }
    let maps_text = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .with_context(|| format!("read /proc/{pid}/maps"))?;
    ksight_core::output_budget::write(request.dest.join(format!("maps-{pid}.txt")), &maps_text)
        .context("write snapshot maps evidence")?;
    let maps = parse_maps(&maps_text);
    let explicit = request.start.zip(request.end);
    let planned = plan_ranges(&maps, explicit, max_bytes);
    let (unselected, unselected_omitted) = unselected_ranges(&maps, explicit, &planned);
    let paused = request.pause && pause.active;
    let stopped_by_tool = pause.stopped_by_tool();
    let process_start_ticks = read_process_start_ticks(pid);
    let threads_seen = task_count(pid);
    let mapped_bytes = maps
        .iter()
        .map(|row| row.end.saturating_sub(row.start))
        .fold(0_u64, u64::saturating_add);
    let selected_bytes = planned
        .iter()
        .map(|span| span.end.saturating_sub(span.start))
        .fold(0_u64, u64::saturating_add);
    let started = Instant::now();
    let (ranges, copied_bytes, truncated, failures) = if planned.is_empty() {
        (Vec::new(), 0, false, Vec::new())
    } else {
        copy_planned(&request.dest, pid, &planned, max_bytes)?
    };
    let maps_after = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap_or_default();
    let maps_consistent = maps_match(&maps_text, &maps_after);
    drop(pause);
    let mut warnings = vec![
        "memory snapshot is L2 forensic evidence, not an Observe event".to_owned(),
        "SIGSTOP pauses the target; torn=true means pages may have changed during the copy"
            .to_owned(),
        "stitched ranges are adjacent same-path maps, not proof of a single mmap".to_owned(),
        "byte budget may truncate later ranges; sha256 covers only the retained bytes".to_owned(),
        "copied_bytes is the retained prefix, not mapped_bytes and not process RSS".to_owned(),
        "stopped_by_tool is false when the process was already stopped; that process is not continued"
            .to_owned(),
        "process_start_ticks is /proc stat starttime; 0 means it was not read".to_owned(),
        "maps_consistent compares /proc/pid/maps text before and after the copy".to_owned(),
        "unselected lists intervals that were not copied".to_owned(),
    ];
    if planned.is_empty() {
        warnings.push("no mapping met the copy rule; copied_bytes is 0".to_owned());
    }
    if process_start_ticks == 0 {
        warnings
            .push("process starttime was not readable; PID reuse is not distinguished".to_owned());
    }
    if !maps_consistent {
        warnings.push("maps text changed or could not be reread; the copy may be torn".to_owned());
    }
    if unselected_omitted > 0 {
        warnings.push(format!(
            "unselected list omitted {unselected_omitted} further intervals"
        ));
    }
    let report = SnapshotReport {
        schema_version: SNAPSHOT_SCHEMA.to_owned(),
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        pid,
        package: request.package,
        paused,
        torn: !paused,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        max_bytes,
        copied_bytes,
        truncated,
        ranges,
        failures,
        warnings,
        visibility: "L2 forensic SIGSTOP + /proc/pid/mem copy".to_owned(),
        mapped_bytes,
        selected_bytes,
        stopped_by_tool,
        process_start_ticks,
        threads_seen,
        maps_sha256: hex_sha256(maps_text.as_bytes()),
        maps_after_sha256: if maps_after.is_empty() {
            String::new()
        } else {
            hex_sha256(maps_after.as_bytes())
        },
        maps_consistent,
        unselected,
    };
    ksight_core::output_budget::write(
        request.dest.join("snapshot-report.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}

fn copy_planned(
    dest: &Path,
    pid: u32,
    planned: &[PlannedSpan],
    max_bytes: u64,
) -> Result<(Vec<SnapshotRange>, u64, bool, Vec<SnapshotFailure>)> {
    let mut mem =
        File::open(format!("/proc/{pid}/mem")).with_context(|| format!("open /proc/{pid}/mem"))?;
    let mut copied_bytes = 0_u64;
    let mut truncated = false;
    let mut ranges = Vec::new();
    let mut failures = Vec::new();
    for (index, span) in planned.iter().enumerate() {
        if copied_bytes >= max_bytes {
            truncated = true;
            failures.push(SnapshotFailure {
                start: span.start,
                end: span.end,
                copied_bytes: 0,
                reason: "budget_exhausted".to_owned(),
            });
            continue;
        }
        let available = span.end.saturating_sub(span.start);
        let remaining = max_bytes.saturating_sub(copied_bytes);
        let want = available.min(remaining).min(MAX_RANGE);
        if want < 4 {
            truncated = true;
            for rest in planned.iter().skip(index) {
                failures.push(SnapshotFailure {
                    start: rest.start,
                    end: rest.end,
                    copied_bytes: 0,
                    reason: "budget_exhausted".to_owned(),
                });
            }
            break;
        }
        let (bytes, reason) = copy_span(&mut mem, span.start, want);
        if let Some(name) = reason {
            truncated = true;
            failures.push(SnapshotFailure {
                start: span.start,
                end: span.end,
                copied_bytes: bytes.len() as u64,
                reason: name.to_owned(),
            });
        }
        if bytes.is_empty() {
            continue;
        }
        let relative = format!("ranges/{pid}-{start:x}.bin", start = span.start);
        let path = dest.join(&relative);
        ksight_core::output_budget::BudgetFile::create(&path)
            .and_then(|mut file| file.write_all(&bytes))
            .with_context(|| format!("write {}", path.display()))?;
        let wrote = u64::try_from(bytes.len()).unwrap_or(0);
        copied_bytes = copied_bytes.saturating_add(wrote);
        ranges.push(SnapshotRange {
            start: span.start,
            end: span.start.saturating_add(wrote),
            path: span.path.clone(),
            perms: span.perms.clone(),
            bytes: wrote,
            sha256: hex_sha256(&bytes),
            relative_path: relative,
            stitched: span.stitched,
            truncated: wrote < available,
        });
        if wrote < available {
            truncated = true;
            if reason.is_none() {
                failures.push(SnapshotFailure {
                    start: span.start,
                    end: span.end,
                    copied_bytes: wrote,
                    reason: limit_reason(available, remaining)
                        .unwrap_or("range_cap")
                        .to_owned(),
                });
            }
        }
    }
    Ok((ranges, copied_bytes, truncated, failures))
}

fn copy_span(
    reader: &mut (impl std::io::Read + std::io::Seek),
    start: u64,
    want: u64,
) -> (Vec<u8>, Option<&'static str>) {
    if reader.seek(SeekFrom::Start(start)).is_err() {
        return (Vec::new(), Some("read_failed"));
    }
    let mut bytes = Vec::new();
    let mut block = [0_u8; 4096];
    while (bytes.len() as u64) < want {
        let n = usize::try_from((want - bytes.len() as u64).min(block.len() as u64))
            .unwrap_or(block.len());
        match reader.read(&mut block[..n]) {
            Ok(0) => return (bytes, Some("short_read")),
            Ok(n) => bytes.extend_from_slice(&block[..n]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return (bytes, Some("read_failed")),
        }
    }
    (bytes, None)
}

fn resolve_pid(request: &SnapshotRequest) -> Result<u32> {
    if let Some(package) = request.package.as_deref() {
        if package.is_empty()
            || !package
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'))
        {
            bail!("Android package name contains unsupported characters");
        }
        let pids = pids_for_package(package);
        if pids.is_empty() {
            bail!("package {package} has no live process");
        }
        if let Some(pid) = request.pid {
            if !pids.contains(&pid) {
                bail!("pid {pid} is not a live process of {package}");
            }
            return Ok(pid);
        }
        return Ok(pids[0]);
    }
    request
        .pid
        .ok_or_else(|| anyhow::anyhow!("snapshot requires --package or --pid"))
}

#[derive(Debug, Clone)]
struct PlannedSpan {
    start: u64,
    end: u64,
    path: String,
    perms: String,
    stitched: bool,
    class: u8,
}

fn plan_ranges(maps: &[MapRow], explicit: Option<(u64, u64)>, max_bytes: u64) -> Vec<PlannedSpan> {
    if let Some((start, end)) = explicit {
        return explicit_span(maps, start, end).into_iter().collect();
    }
    let mut spans = Vec::new();
    let mut index = 0_usize;
    while index < maps.len() {
        if !can_join_harvest(&maps[index]) {
            index = index.saturating_add(1);
            continue;
        }
        let start = maps[index].start;
        let span_end = extend_span(maps, index, true, MAX_RANGE);
        let len = span_end.saturating_sub(start);
        let mut count = 0_u32;
        let mut next = index;
        while next < maps.len() && maps[next].start < span_end && maps[next].end <= span_end {
            count = count.saturating_add(1);
            next = next.saturating_add(1);
        }
        if len >= MIN_RANGE {
            spans.push(PlannedSpan {
                start,
                end: span_end,
                path: maps[index].path.clone(),
                perms: maps[index].perms.clone(),
                stitched: count > 1,
                class: blob_map_class(&maps[index].path),
            });
        }
        index = next.max(index.saturating_add(1));
    }
    spans.sort_by(|left, right| {
        left.class.cmp(&right.class).then_with(|| {
            right
                .end
                .saturating_sub(right.start)
                .cmp(&(left.end.saturating_sub(left.start)))
        })
    });
    let mut kept = Vec::new();
    let _ = max_bytes;
    for span in spans {
        if kept.len() >= MAX_RANGES {
            break;
        }
        kept.push(span);
    }
    kept
}

fn explicit_span(maps: &[MapRow], start: u64, end: u64) -> Option<PlannedSpan> {
    let index = maps
        .iter()
        .position(|row| start >= row.start && start < row.end)?;
    if !maps[index].perms.contains('r') {
        return None;
    }
    let span_end = extend_span(maps, index, false, MAX_RANGE).min(end);
    if span_end <= start {
        return None;
    }
    Some(PlannedSpan {
        start,
        end: span_end,
        path: maps[index].path.clone(),
        perms: maps[index].perms.clone(),
        stitched: span_end > maps[index].end,
        class: blob_map_class(&maps[index].path),
    })
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn maps_match(before: &str, after: &str) -> bool {
    !before.is_empty() && before == after
}

fn read_process_start_ticks(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| parse_process_start_ticks(&stat))
        .unwrap_or(0)
}

fn parse_process_start_ticks(stat: &str) -> Option<u64> {
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

fn task_count(pid: u32) -> u32 {
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return 0;
    };
    u32::try_from(tasks.flatten().count()).unwrap_or(u32::MAX)
}

/// Why a span shorter than `available` was cut. `remaining` is the unused byte budget.
fn limit_reason(available: u64, remaining: u64) -> Option<&'static str> {
    let want = available.min(remaining).min(MAX_RANGE);
    if want >= available {
        None
    } else if remaining < available {
        Some("budget_exhausted")
    } else {
        Some("range_cap")
    }
}

const MAX_UNSELECTED: usize = 256;

fn unselected_ranges(
    maps: &[MapRow],
    explicit: Option<(u64, u64)>,
    planned: &[PlannedSpan],
) -> (Vec<SnapshotSkipped>, usize) {
    let mut skipped = Vec::new();
    if let Some((req_start, req_end)) = explicit {
        if let Some(span) = planned.first() {
            if req_start < span.start {
                skipped.push(skip(req_start, span.start, "not_readable"));
            }
            if span.end < req_end {
                skipped.push(skip(span.end, req_end, "not_readable"));
            }
        } else if req_end > req_start {
            skipped.push(skip(req_start, req_end, "not_selected"));
        }
        for row in maps {
            if row.end <= req_start || row.start >= req_end {
                skipped.push(skip(row.start, row.end, "outside_explicit"));
                continue;
            }
            if row.start < req_start {
                skipped.push(skip(row.start, req_start, "outside_explicit"));
            }
            if row.end > req_end {
                skipped.push(skip(req_end, row.end, "outside_explicit"));
            }
        }
        return cap_unselected(skipped);
    }
    let mut index = 0_usize;
    while index < maps.len() {
        if planned
            .iter()
            .any(|span| maps[index].start >= span.start && maps[index].end <= span.end)
        {
            index = index.saturating_add(1);
            continue;
        }
        if !can_join_harvest(&maps[index]) {
            skipped.push(skip(maps[index].start, maps[index].end, "not_harvestable"));
            index = index.saturating_add(1);
            continue;
        }
        let start = maps[index].start;
        let span_end = extend_span(maps, index, true, MAX_RANGE);
        let mut next = index;
        while next < maps.len() && maps[next].start < span_end && maps[next].end <= span_end {
            next = next.saturating_add(1);
        }
        let reason = if span_end.saturating_sub(start) < MIN_RANGE {
            "below_min_range"
        } else {
            "over_range_cap"
        };
        skipped.push(skip(start, span_end, reason));
        index = next.max(index.saturating_add(1));
    }
    cap_unselected(skipped)
}

fn skip(start: u64, end: u64, reason: &str) -> SnapshotSkipped {
    SnapshotSkipped {
        start,
        end,
        reason: reason.to_owned(),
    }
}

fn cap_unselected(mut skipped: Vec<SnapshotSkipped>) -> (Vec<SnapshotSkipped>, usize) {
    if skipped.len() <= MAX_UNSELECTED {
        return (skipped, 0);
    }
    let omitted = skipped.len() - MAX_UNSELECTED;
    skipped.truncate(MAX_UNSELECTED);
    (skipped, omitted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(start: u64, end: u64, perms: &str, path: &str) -> MapRow {
        MapRow {
            start,
            end,
            perms: perms.to_owned(),
            path: path.to_owned(),
            inode: 0,
        }
    }

    #[test]
    fn plans_stitched_scudo_ahead_of_small_anon() {
        let maps = vec![
            row(0x1000, 0x2000, "rw-p", "[stack]"),
            row(0x2000, 0x3000, "rw-p", "[anon:scudo:secondary]"),
            row(
                0x3000,
                0x3000 + 6 * 1024 * 1024,
                "rw-p",
                "[anon:scudo:secondary]",
            ),
            row(
                0x1000_0000,
                0x1000_0000 + 512 * 1024,
                "rw-p",
                String::new().as_str(),
            ),
        ];
        let planned = plan_ranges(&maps, None, 32 * 1024 * 1024);
        assert!(!planned.is_empty());
        assert_eq!(planned[0].start, 0x2000);
        assert!(planned[0].stitched);
        assert_eq!(
            planned[0].end.saturating_sub(planned[0].start),
            4 * 1024 + 6 * 1024 * 1024
        );
    }

    #[test]
    fn explicit_range_clamps_to_readable_map() {
        let maps = vec![row(0x1000, 0x5000, "r--p", "[anon:scudo:secondary]")];
        let planned = plan_ranges(&maps, Some((0x1200, 0x8000)), 1024 * 1024);
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].start, 0x1200);
        assert_eq!(planned[0].end, 0x5000);
    }

    #[test]
    fn budget_keeps_highest_ranked_span() {
        let maps = vec![
            row(
                0x1000,
                0x1000 + 8 * 1024 * 1024,
                "rw-p",
                "[anon:scudo:secondary]",
            ),
            row(0x2000_0000, 0x2000_0000 + 8 * 1024 * 1024, "rw-p", ""),
        ];
        let planned = plan_ranges(&maps, None, 8 * 1024 * 1024);
        assert_eq!(
            planned.len(),
            2,
            "all selected spans must remain visible to copy/report"
        );
        assert!(planned[0].path.contains("scudo:secondary"));
    }

    #[test]
    fn snapshot_retains_short_read_prefix_and_reports_missing_suffix() {
        let mut reader = std::io::Cursor::new(b"abcdefgh".to_vec());
        let (bytes, failure) = copy_span(&mut reader, 0, 20);
        assert_eq!(bytes, b"abcdefgh");
        assert_eq!(failure, Some("short_read"));
    }

    #[test]
    fn starttime_uses_the_field_after_the_last_comm_paren() {
        let stat = "9 (a) b) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 99";
        assert_eq!(parse_process_start_ticks(stat), Some(424_242));
    }

    #[test]
    fn maps_match_rejects_an_empty_reread() {
        assert!(maps_match("a-b r--p 0", "a-b r--p 0"));
        assert!(!maps_match("a-b r--p 0", "a-c r--p 0"));
        assert!(!maps_match("a-b r--p 0", ""));
    }

    #[test]
    fn budget_cut_is_not_a_range_cap() {
        assert_eq!(limit_reason(40960, 4096), Some("budget_exhausted"));
        assert_eq!(
            limit_reason(80 * 1024 * 1024, 100 * 1024 * 1024),
            Some("range_cap")
        );
        assert_eq!(limit_reason(4096, 32 * 1024 * 1024), None);
    }

    #[test]
    fn small_maps_stay_unselected_without_lowering_the_minimum() {
        let maps = vec![
            row(0x1000, 0x2000, "r--p", "/system/bin/app_process64"),
            row(0x2000, 0x3000, "rw-p", ""),
        ];
        let planned = plan_ranges(&maps, None, 32 * 1024 * 1024);
        assert!(planned.is_empty());
        let (skipped, omitted) = unselected_ranges(&maps, None, &planned);
        assert_eq!(omitted, 0);
        assert!(skipped.iter().any(|row| row.reason == "not_harvestable"));
        assert!(skipped
            .iter()
            .any(|row| row.reason == "below_min_range" && row.end - row.start == 0x1000));
    }

    #[test]
    fn explicit_window_lists_the_other_mappings() {
        let maps = vec![
            row(0x1000, 0x2000, "r--p", "[vdso]"),
            row(0x22_1000, 0x22_b000, "rw-p", ""),
            row(0x22_b000, 0x22_c000, "---p", ""),
        ];
        let planned = plan_ranges(&maps, Some((0x22_1000, 0x22_c000)), 1024 * 1024);
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].end, 0x22_b000);
        let (skipped, _) = unselected_ranges(&maps, Some((0x22_1000, 0x22_c000)), &planned);
        assert!(skipped.iter().any(|row| {
            row.start == 0x22_b000 && row.end == 0x22_c000 && row.reason == "not_readable"
        }));
        assert!(skipped
            .iter()
            .any(|row| row.start == 0x1000 && row.reason == "outside_explicit"));
        assert!(!skipped
            .iter()
            .any(|row| row.start == 0x22_1000 && row.end == 0x22_b000));
    }

    #[test]
    fn the_twenty_fifth_span_is_over_the_range_cap() {
        let maps = (0..25)
            .map(|index| {
                let start = 0x1000_0000 + u64::try_from(index).unwrap() * 0x10_0000;
                row(start, start + 256 * 1024, "rw-p", "")
            })
            .collect::<Vec<_>>();
        let planned = plan_ranges(&maps, None, 32 * 1024 * 1024);
        assert_eq!(planned.len(), 24);
        let (skipped, _) = unselected_ranges(&maps, None, &planned);
        assert_eq!(
            skipped
                .iter()
                .filter(|row| row.reason == "over_range_cap")
                .count(),
            1
        );
    }
}
