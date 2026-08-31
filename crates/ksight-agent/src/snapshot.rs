//! Bounded L2 forensic memory snapshots. Explicit, selected-process, paused, hashed.

use std::{
    fs::File,
    io::Write as _,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::dexdump::{
    blob_map_class, can_join_harvest, extend_span, parse_maps, pids_for_package, read_region,
    MapRow, StoppedProcess,
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

/// Provenance for one paused `/proc/<pid>/mem` copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Honest limits.
    pub warnings: Vec<String>,
    /// High-visibility notice. Never an Observe event.
    pub visibility: String,
}

/// Copy selected live mappings of one process into `dest`.
///
/// # Errors
///
/// Returns when no live PID exists, dest cannot be created, or `/proc/<pid>/mem`
/// cannot be read.
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
    let maps_text = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .with_context(|| format!("read /proc/{pid}/maps"))?;
    let _ = std::fs::write(request.dest.join(format!("maps-{pid}.txt")), &maps_text);
    let maps = parse_maps(&maps_text);
    let planned = plan_ranges(&maps, request.start.zip(request.end), max_bytes);
    if planned.is_empty() {
        bail!("no snapshot ranges selected for pid {pid}");
    }
    let pause = if request.pause {
        StoppedProcess::enter(pid)
    } else {
        StoppedProcess::inert()
    };
    let paused = request.pause && pause.active;
    let started = Instant::now();
    let (ranges, copied_bytes, truncated) = copy_planned(&request.dest, pid, &planned, max_bytes)?;
    drop(pause);
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
        warnings: vec![
            "memory snapshot is L2 forensic evidence, not an Observe event".to_owned(),
            "SIGSTOP pauses the target; torn=true means pages may have changed during the copy"
                .to_owned(),
            "stitched ranges are adjacent same-path maps, not proof of a single mmap".to_owned(),
            "byte budget may truncate later ranges; sha256 covers only the retained bytes"
                .to_owned(),
        ],
        visibility: "L2 forensic SIGSTOP + /proc/pid/mem copy".to_owned(),
    };
    std::fs::write(
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
) -> Result<(Vec<SnapshotRange>, u64, bool)> {
    let mut mem =
        File::open(format!("/proc/{pid}/mem")).with_context(|| format!("open /proc/{pid}/mem"))?;
    let mut copied_bytes = 0_u64;
    let mut truncated = false;
    let mut ranges = Vec::new();
    for span in planned {
        if copied_bytes >= max_bytes {
            truncated = true;
            break;
        }
        let available = span.end.saturating_sub(span.start);
        let want = available
            .min(max_bytes.saturating_sub(copied_bytes))
            .min(MAX_RANGE);
        if want < 4 {
            truncated = true;
            break;
        }
        let Some(bytes) = read_region(&mut mem, span.start, want) else {
            continue;
        };
        let relative = format!("ranges/{pid}-{start:x}.bin", start = span.start);
        let path = dest.join(&relative);
        File::create(&path)
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
            break;
        }
    }
    Ok((ranges, copied_bytes, truncated))
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
    let mut budget = max_bytes;
    for span in spans {
        if kept.len() >= MAX_RANGES || budget < 4 {
            break;
        }
        let len = span.end.saturating_sub(span.start).min(MAX_RANGE);
        kept.push(span);
        budget = budget.saturating_sub(len);
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
        assert_eq!(planned.len(), 1);
        assert!(planned[0].path.contains("scudo:secondary"));
    }
}
