#![cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
//! Backend capability, physical task qualification and anchored live code copies.
//! No qualification is minted from a numeric PID, proc ticks or a missing record.
use anyhow::{bail, Context as _, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io;
use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[allow(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "Registered Android file names are intentionally case-sensitive."
)]
fn prioritize_install_rows(rows: &mut [crate::dexdump::MapRow], apks: &[std::path::PathBuf]) {
    rows.sort_by_key(|r| {
        if apks
            .iter()
            .filter_map(|p| p.parent())
            .any(|dir| Path::new(&r.path).starts_with(dir))
        {
            if android_suffix(&r.path, ".dex") || android_suffix(&r.path, ".vdex") {
                0
            } else if android_suffix(&r.path, ".so") {
                1
            } else {
                2
            }
        } else {
            3
        }
    });
}
fn stat_start_ticks(stat: &str) -> Option<u64> {
    let rest = stat.rsplit_once(')')?.1;
    rest.split_whitespace().nth(19)?.parse().ok()
}

fn app_code_mapped_bytes(pid: u32) -> u64 {
    let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return 0;
    };
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let range = parts.next()?;
            let perms = parts.next()?;
            let path = parts.last()?;
            if path.starts_with("/system/")
                || path.starts_with("/apex/")
                || path.starts_with("/vendor/")
                || path.starts_with('[')
            {
                return None;
            }
            let code = perms.contains('x')
                || android_suffix(path, ".dex")
                || android_suffix(path, ".vdex")
                || android_suffix(path, ".apk")
                || android_suffix(path, ".so");
            if !code {
                return None;
            }
            let (start, end) = range.split_once('-')?;
            let start = u64::from_str_radix(start, 16).ok()?;
            let end = u64::from_str_radix(end, 16).ok()?;
            Some(end.saturating_sub(start))
        })
        .sum()
}

fn android_suffix(path: &str, suffix: &str) -> bool {
    path.len() >= suffix.len() && path.as_bytes().ends_with(suffix.as_bytes())
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn eligible_mapping(r: &crate::dexdump::MapRow) -> bool {
    r.perms.contains('r')
        && (r.perms.contains('x')
            || [".dex", ".vdex", ".apk", ".oat", ".art", ".so"]
                .iter()
                .any(|s| r.path.contains(s)))
}

const UNGUARDED_RANGE_LIMIT: u64 = 128 * 1024 * 1024;
// A wider copy can create a multi-MiB bound note plus a catalog. Reserve this
// before selecting payload, rather than relying on the 256KiB note fallback.
const RANGE_METADATA_RESERVE: u64 = 16 * 1024 * 1024;

fn selected_range_bytes(requested: u64, parent_remaining: Option<u64>) -> u64 {
    // Registered invocations already have finite byte and time contracts.
    // Mapping type cannot silently truncate an APK/JIT/ELF payload.
    parent_remaining.map_or(requested.min(UNGUARDED_RANGE_LIMIT), |remaining| {
        requested.min(remaining.saturating_sub(RANGE_METADATA_RESERVE))
    })
}

enum BoundRangeStep {
    Stop {
        saw_budget_reserve: bool,
    },
    Copied {
        record: serde_json::Value,
        partial: bool,
        saw_budget_reserve: bool,
        saw_range_cap: bool,
        vdex: bool,
        dex: bool,
        native: bool,
    },
}

fn publish_bound_pending(
    pending: &Path,
    out: &Path,
    expected: &SourceIdentity,
    row: &crate::dexdump::MapRow,
    admitted: bool,
) -> (PathBuf, Option<String>) {
    if !admitted {
        return (pending.to_path_buf(), None);
    }
    let published = out.join(format!(
        "bound-{}-{:x}-{}.code",
        expected.pid,
        row.start,
        uuid::Uuid::new_v4()
    ));
    // Reserve a fresh destination before replacing only our own empty placeholder.
    let publish = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&published)
        .and_then(|owned| {
            drop(owned);
            std::fs::rename(pending, &published)
        });
    match publish {
        Ok(()) => (published, None),
        Err(error) => (pending.to_path_buf(), Some(error.to_string())),
    }
}

#[derive(Clone, Copy)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "These stop flags are independent and are not a state machine."
)]
struct BoundCopyStops {
    stopped_early: bool,
    budget_stop: bool,
    saw_range_cap: bool,
    saw_budget_reserve: bool,
}

fn bound_copy_gap_state(stops: BoundCopyStops) -> (&'static str, &'static str) {
    let unattempted = if stops.stopped_early && stops.budget_stop {
        "not_attempted_parent_deadline_or_output_exhausted"
    } else if stops.stopped_early && stops.saw_budget_reserve {
        "not_attempted_runtime_metadata_reserve"
    } else if stops.stopped_early {
        "not_attempted_local_copy_window"
    } else {
        "none"
    };
    let truncation = if stops.saw_range_cap {
        "per_range_cap"
    } else if stops.saw_budget_reserve {
        "runtime_payload_budget_metadata_reserve"
    } else {
        "none"
    };
    (unattempted, truncation)
}

fn budget_io(error: &std::io::Error) -> bool {
    let text = error.to_string();
    text.contains("output_budget_exhausted") || text.contains("time_budget_exhausted")
}
fn candidate_object(
    rank: usize,
    row: &crate::dexdump::MapRow,
    parent_remaining: Option<u64>,
) -> serde_json::Value {
    let category = if row.path.contains("jit") {
        "jit_named"
    } else if [".dex", ".vdex", ".apk", ".oat", ".art"]
        .iter()
        .any(|suffix| row.path.contains(suffix))
    {
        "dex_container_named"
    } else if row.path.contains(".so") {
        "elf_named"
    } else {
        "other_executable"
    };
    let path: String = row.path.chars().take(256).collect();
    serde_json::json!({
        "rank": rank,
        "start": row.start,
        "end": row.end,
        "path": path,
        "path_truncated": row.path.chars().count() > 256,
        "category": category,
        "ownership": "unknown",
        "requested_mapping_bytes": row.end.saturating_sub(row.start),
        "selection_limit_bytes": selected_range_bytes(row.end.saturating_sub(row.start), parent_remaining),
        "selection_reason": "eligible_install_priority_until_parent_budget",
        "state": "planned_not_read",
        "actual_bytes": null
    })
}

fn candidate_ledger(
    rows: &[crate::dexdump::MapRow],
    parent_remaining: Option<u64>,
) -> serde_json::Value {
    let candidates: Vec<_> = rows
        .iter()
        .filter(|row| eligible_mapping(row))
        .enumerate()
        .map(|(rank, row)| candidate_object(rank, row, parent_remaining))
        .collect();
    serde_json::json!({
        "schema": "kernsight.code-candidates/v1",
        "order": "original_maps_order_unchanged",
        "mapping_observation_scope": "initial_bound_maps_snapshot; later mappings not observed",
        "eligible_count": candidates.len(),
        "listed_count": candidates.len(),
        "omitted_count": 0,
        "omitted_reason": null,
        "budget": "same_parent_output_budget; ledger_written_before_payload; no_extra_memory_reads",
        "candidates": candidates
    })
}

fn write_candidate_ledger(dir: &Path, stem: &str, mut note: serde_json::Value) -> Result<()> {
    let candidates = note["candidates"].as_array().cloned().unwrap_or_default();
    let eligible = candidates.len();
    note["eligible_count"] = serde_json::json!(eligible);
    let mut start = 0_usize;
    let mut shard = 0_u32;
    while start < eligible || (eligible == 0 && shard == 0) {
        let mut end = (start + 1).min(eligible.max(1));
        if eligible == 0 {
            end = 0;
        }
        let mut chosen = end;
        while end <= eligible {
            let mut part = note.clone();
            part["candidates"] = serde_json::json!(candidates[start..end]);
            part["shard_index"] = serde_json::json!(shard);
            part["shard_count_known_after_write"] = serde_json::json!(true);
            part["listed_count"] = serde_json::json!(end.saturating_sub(start));
            part["omitted_count"] = serde_json::json!(eligible.saturating_sub(end));
            part["omitted_reason"] = if end < eligible {
                serde_json::json!("continued_in_next_candidate_shard")
            } else {
                serde_json::Value::Null
            };
            let size = serde_json::to_vec(&part)?.len();
            if size > 200 * 1024 && end > start + 1 {
                break;
            }
            chosen = end;
            if size > 200 * 1024 || end == eligible {
                break;
            }
            end += 1;
        }
        let mut part = note.clone();
        let listed = if eligible == 0 {
            &candidates[..]
        } else {
            &candidates[start..chosen]
        };
        part["candidates"] = serde_json::json!(listed);
        part["shard_index"] = serde_json::json!(shard);
        part["listed_count"] = serde_json::json!(listed.len());
        part["omitted_count"] = serde_json::json!(eligible.saturating_sub(chosen));
        part["omitted_reason"] = if chosen < eligible {
            serde_json::json!("continued_in_next_candidate_shard")
        } else {
            serde_json::Value::Null
        };
        let bytes = serde_json::to_vec(&part)?;
        if bytes.len() > 256 * 1024 {
            bail!("candidate metadata size bound");
        }
        ksight_core::output_budget::write(dir.join(format!("{stem}-{shard:02}.json")), &bytes)?;
        if eligible == 0 || chosen >= eligible {
            break;
        }
        start = chosen;
        shard = shard.saturating_add(1);
        if shard > 64 {
            bail!("candidate shard bound");
        }
    }
    Ok(())
}

const NOTE_LIMIT: usize = 2 * 1024 * 1024;
const NOTES_TOTAL_LIMIT: usize = 8 * 1024 * 1024;
const NOTE_COUNT_LIMIT: usize = 16;
const HEADER_GROWTH_RESERVE: usize = 1024;

struct LimitedJson {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for LimitedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|next| *next <= self.limit)
            .ok_or_else(|| io::Error::other("bound note exceeds size limit"))?;
        if next > self.bytes.capacity() {
            let capacity = self
                .limit
                .min(self.bytes.capacity().saturating_mul(2).max(65536).max(next));
            self.bytes.reserve_exact(capacity - self.bytes.len());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode_note(note: &Value) -> Result<Vec<u8>> {
    let mut sink = LimitedJson {
        bytes: Vec::new(),
        limit: NOTE_LIMIT,
    };
    serde_json::to_writer(&mut sink, note).context("bounded compact bound note")?;
    Ok(sink.bytes)
}
struct JsonCount {
    count: usize,
    limit: usize,
}
impl Write for JsonCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.count = self
            .count
            .checked_add(bytes.len())
            .filter(|next| *next <= self.limit)
            .ok_or_else(|| io::Error::other("bound record exceeds size limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn compact_record_bytes(record: &Value) -> Result<usize> {
    let mut count = JsonCount {
        count: 0,
        limit: NOTE_LIMIT,
    };
    serde_json::to_writer(&mut count, record).context("bounded compact record size")?;
    Ok(count.count)
}
fn admit_note_size(total: &mut usize, size: usize) -> Result<()> {
    if size > NOTE_LIMIT {
        bail!("bound note exceeds single-note limit");
    }
    let next = total
        .checked_add(size)
        .filter(|next| *next <= NOTES_TOTAL_LIMIT)
        .context("bound notes exceed aggregate limit")?;
    *total = next;
    Ok(())
}

// Each compact shard remains readable by the existing v1 coverage verifier.
// Encoding is bounded; publication still obeys the original output guard.
fn compact_bound_notes(mut template: Value) -> Result<Vec<Vec<u8>>> {
    let Value::Array(records) = template["records"].take() else {
        bail!("missing bound records");
    };
    let attempted = records.len();
    if attempted > 65536 {
        bail!("bound record count limit");
    }
    let excluded = records
        .iter()
        .enumerate()
        .filter(|(_, record)| record["excluded_local_window"] == true)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if excluded.len() > 1
        || excluded
            .first()
            .is_some_and(|index| *index + 1 != attempted)
    {
        bail!("excluded local window must be the last global record only");
    }
    template["records"] = json!([]);
    template["candidate_result"]["attempted"] = json!(0);
    template["candidate_result"]["total_attempted"] = json!(attempted);
    template["shard_index"] = json!(0);
    template["shard_count"] = json!(NOTE_COUNT_LIMIT);
    let overhead = encode_note(&template)?
        .len()
        .checked_add(HEADER_GROWTH_RESERVE)
        .filter(|size| *size < NOTE_LIMIT)
        .context("bound header exceeds note limit")?;
    let capacity = NOTE_LIMIT - overhead;
    let mut groups = Vec::<Vec<Value>>::new();
    let mut current = Vec::new();
    let mut used = 0usize;
    for record in records {
        let size = compact_record_bytes(&record)?;
        if size > capacity {
            bail!("single bound record cannot fit within note limit");
        }
        let need = size + usize::from(!current.is_empty());
        if need > capacity.saturating_sub(used) {
            groups.push(std::mem::take(&mut current));
            used = 0;
        }
        if groups.len() >= NOTE_COUNT_LIMIT {
            bail!("bound note shard count limit");
        }
        used += size + usize::from(!current.is_empty());
        current.push(record);
    }
    if !current.is_empty() || groups.is_empty() {
        groups.push(current);
    }
    if groups.len() > NOTE_COUNT_LIMIT {
        bail!("bound note shard count limit");
    }
    let count = groups.len();
    let mut bodies = Vec::with_capacity(count);
    let mut total = 0usize;
    for (index, records) in groups.into_iter().enumerate() {
        let mut note = template.clone();
        note["shard_index"] = json!(index);
        note["shard_count"] = json!(count);
        note["candidate_result"]["attempted"] = json!(records.len());
        if index + 1 != count {
            // This note's rows are complete; global remainder is described only
            // by the final note. Explicit shard metadata keeps the scope clear.
            note["candidate_result"]["unattempted_state"] = json!("none");
            note["candidate_result"]["stop_scope"] = json!("none_or_parent_budget");
        }
        note["records"] = Value::Array(records);
        let body = encode_note(&note)?;
        admit_note_size(&mut total, body.len())?;
        bodies.push(body);
    }
    Ok(bodies)
}

fn track_record_metadata(out: &Path, record: &Value, used: &mut usize) -> Result<()> {
    let next = compact_record_bytes(record)
        .and_then(|size| {
            used.checked_add(size + 1)
                .filter(|next| *next <= NOTES_TOTAL_LIMIT - 65536)
                .context("bound record metadata size limit")
        })
        .inspect_err(|_| {
            ksight_core::output_budget::record_failure(out, "bound_note_metadata_exhausted");
        })?;
    *used = next;
    Ok(())
}

fn write_bound_notes(out: &Path, pid: u32, note: Value) -> Result<()> {
    let bodies = compact_bound_notes(note)?;
    let mut count = bodies.len();
    let mut total = bodies.iter().map(Vec::len).sum::<usize>();
    for entry in std::fs::read_dir(out)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("bound-source-") && name.ends_with(".json") {
            let bytes = usize::try_from(entry.metadata()?.len())?;
            if bytes > NOTE_LIMIT {
                bail!("existing bound note size limit");
            }
            count += 1;
            total = total
                .checked_add(bytes)
                .context("bound note inventory overflow")?;
        }
    }
    if count > NOTE_COUNT_LIMIT || total > NOTES_TOTAL_LIMIT {
        bail!("bound note inventory limit");
    }
    let id = uuid::Uuid::new_v4();
    for (index, body) in bodies.iter().enumerate() {
        ksight_core::output_budget::write(
            out.join(format!("bound-source-{pid}-{id}-{index:02}.json")),
            body,
        )?;
    }
    Ok(())
}

/// Controller comparison only. A physical issuer must independently qualify this identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceIdentity {
    /// Package retained by this evidence operation.
    pub package: String,
    /// Pid retained by this evidence operation.
    pub pid: u32,
    /// Uid retained by this evidence operation.
    pub uid: u32,
    /// Birth ns retained by this evidence operation.
    pub birth_ns: u64,
    /// Exec id retained by this evidence operation.
    pub exec_id: u64,
    /// Boot id retained by this evidence operation.
    pub boot_id: String,
}
impl SourceIdentity {
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    /// Validate retained by this evidence operation.
    pub fn validate(&self) -> Result<()> {
        if self.package.is_empty() || self.pid == 0 || self.birth_ns == 0 || self.boot_id.is_empty()
        {
            bail!("source identity missing; never infer legacy completeness");
        }
        Ok(())
    }
}
#[cfg(any(target_os = "linux", target_os = "android", test))]
fn require_same_source(actual: &SourceIdentity, expected: &SourceIdentity) -> Result<()> {
    if actual != expected {
        bail!("source generation changed; no numeric retry");
    }
    Ok(())
}

/// Capability checks only the available physical backend, not a not-yet-started App.
///
/// # Errors
/// Returns the validation or required operation error; no successful result is fabricated.
pub fn capability() -> Result<()> {
    ksight_core::capture_scope::require_code_collection_backend().map_err(anyhow::Error::msg)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        Backend::open().map(|_| ())
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        bail!("qualified backend not-supported on this host")
    }
}
/// Read result records requested/actual ranges and independent read/write failures.
#[derive(Debug, Serialize)]
pub struct RangeResult {
    /// Requested start retained by this evidence operation.
    pub requested_start: u64,
    /// Requested length retained by this evidence operation.
    pub requested_length: u64,
    /// Actual start retained by this evidence operation.
    pub actual_start: u64,
    /// Actual length retained by this evidence operation.
    pub actual_length: u64,
    /// Read status retained by this evidence operation.
    pub read_status: String,
    /// Read error retained by this evidence operation.
    pub read_error: Option<String>,
    /// Write status retained by this evidence operation.
    pub write_status: String,
    /// Write error retained by this evidence operation.
    pub write_error: Option<String>,
    /// Admission retained by this evidence operation.
    pub admission: String,
    /// Digest of actual read bytes; independent of destination commit status.
    pub sha256: Option<String>,
    /// Paused retained by this evidence operation.
    pub paused: bool,
    /// Torn retained by this evidence operation.
    pub torn: bool,
}
/// The same streaming function serves production and host short-read/identity/IO counterexamples.
pub(crate) fn copy_range(
    source: &mut (impl Read + Seek),
    target: &mut impl Write,
    start: u64,
    requested: u64,
    mut current: impl FnMut() -> Result<()>,
) -> RangeResult {
    let mut r = RangeResult {
        requested_start: start,
        requested_length: requested,
        actual_start: start,
        actual_length: 0,
        read_status: "complete".into(),
        read_error: None,
        write_status: "complete".into(),
        write_error: None,
        admission: "pending".into(),
        sha256: None,
        paused: false,
        torn: true,
    };
    let mut hash = Sha256::new();
    if let Err(e) = current() {
        r.read_status = "not_attempted".into();
        r.admission = "rejected_identity".into();
        r.read_error = Some(e.to_string());
        return r;
    }
    if let Err(e) = source.seek(SeekFrom::Start(start)) {
        r.read_status = "read_failed".into();
        r.read_error = Some(e.to_string());
        return r;
    }
    let mut block = vec![0_u8; 65_536];
    while r.actual_length < requested {
        if let Err(e) = current() {
            r.read_status = "interrupted".into();
            r.admission = "rejected_identity_or_deadline".into();
            r.read_error = Some(e.to_string());
            break;
        }
        let count = usize::try_from((requested - r.actual_length).min(block.len() as u64))
            .unwrap_or(block.len());
        let n = match source.read(&mut block[..count]) {
            Ok(0) => {
                r.read_status = "short_read".into();
                break;
            }
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                r.read_status = "read_failed".into();
                r.read_error = Some(e.to_string());
                break;
            }
        };
        // Actual read count is not a claim that the destination committed it.
        r.actual_length += n as u64;
        hash.update(&block[..n]);
        if let Err(e) = target.write_all(&block[..n]) {
            if r.actual_length < requested {
                r.read_status = "interrupted".into();
            }
            r.write_status = "write_failed".into();
            r.write_error = Some(e.to_string());
            break;
        }
    }
    if r.admission == "pending" {
        match current() {
            Ok(()) => r.admission = "qualified_live_copy".into(),
            Err(e) => {
                r.admission = "rejected_identity_or_deadline".into();
                r.read_error = Some(e.to_string());
            }
        }
    }
    r.sha256 = Some(format!("{:x}", hash.finalize()));
    r
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod physical {
    use super::{
        android_suffix, app_code_mapped_bytes, bail, bound_copy_gap_state, budget_io,
        candidate_ledger, copy_range, eligible_mapping, hex_bytes, prioritize_install_rows,
        publish_bound_pending, selected_range_bytes, stat_start_ticks, write_candidate_ledger,
        BoundCopyStops, BoundRangeStep, Digest, Path, Read, Result, Sha256, SourceIdentity,
    };
    use anyhow::Context as _;
    use ksight_hwbp::{
        metadata_scope::{PolicyWitness, QualificationPolicy, QualifiedInstance},
        MetadataObserver,
    };
    use rustix::{
        fs::{openat, Mode, OFlags},
        process::{pidfd_open, Pid, PidfdFlags},
    };
    use std::time::Instant;
    use std::{fs::File, os::fd::AsFd, path::PathBuf};
    /// Real BTF and actual verifier acceptance. Retained hashes detect drift at every issuance.
    pub struct Backend {
        /// `metadata`.
        pub metadata: PathBuf,
        /// `uprobe`.
        pub uprobe: PathBuf,
        object_hash: [u8; 32],
        btf_hash: [u8; 32],
        /// `boot_id`.
        pub boot_id: String,
    }
    impl Backend {
        ///
        /// # Errors
        ///
        /// Returns the existing failure for this operation. No success value is invented.
        pub fn open() -> Result<Self> {
            let (metadata, uprobe) = crate::embedded::qualified_objects()?;
            let object = std::fs::read(&metadata)?;
            if object.len() > 262_144 {
                bail!("metadata object bound");
            }
            let mut btf = Vec::new();
            File::open("/sys/kernel/btf/vmlinux")?
                .take(8 * 1024 * 1024 + 1)
                .read_to_end(&mut btf)?;
            if btf.len() > 8 * 1024 * 1024 {
                bail!("kernel BTF bound");
            }
            let object_hash = Sha256::digest(&object).into();
            let btf_hash = Sha256::digest(&btf).into();
            // Actual BPF loading/CO-RE/verifier checks, no hook/target grant/payload read.
            drop(MetadataObserver::load(&metadata, object_hash, btf_hash)?);
            ksight_hwbp::UprobeSession::verify_instance_backend(&uprobe)?;
            drop(pidfd_open(
                Pid::from_raw(i32::try_from(std::process::id()).context("self PID")?)
                    .context("self PID")?,
                PidfdFlags::empty(),
            )?);
            Ok(Self {
                metadata,
                uprobe,
                object_hash,
                btf_hash,
                boot_id: crate::retention::boot_id().context("kernel boot identity unavailable")?,
            })
        }
        ///
        /// # Errors
        ///
        /// Returns the existing failure for this operation. No success value is invented.
        pub fn uid(&self, package: &str) -> Result<u32> {
            let resolver = crate::identity::AndroidIdentityResolver::from_system()?;
            let uid = resolver
                .exclusive_package_uid(package)
                .context("not-supported: shared/ambiguous/missing package UID enrollment")?;
            Ok(uid)
        }
        ///
        /// # Errors
        ///
        /// Returns the existing failure for this operation. No success value is invented.
        pub fn qualify(&self, package: &str, pid: u32, with_memory: bool) -> Result<Target> {
            if crate::retention::boot_id().as_deref() != Some(self.boot_id.as_str()) {
                bail!("boot identity changed");
            }
            let uid = self
                .uid(package)
                .context("resolve exclusive package UID for qualification")?;
            let pidfd = pidfd_open(
                Pid::from_raw(i32::try_from(pid).context("target PID")?).context("target PID")?,
                PidfdFlags::empty(),
            )
            .with_context(|| format!("open qualification pidfd for pid={pid}"))?;
            // Proc directory retained through qualification; mem belongs to this original task/mm, not a later numeric PID.
            let dir = File::open(format!("/proc/{pid}")).with_context(|| {
                format!("open anchored qualification proc directory for pid={pid}")
            })?;
            let mut maps = None;
            let mut mem = None;
            let qualified = MetadataObserver::load(&self.metadata, self.object_hash, self.btf_hash)
                .context("load physical metadata observer for qualification")?
                .qualify(
                    &QualificationPolicy {
                        package: package.into(),
                        tgid: pid,
                        uid,
                    },
                    pidfd,
                    |_, identity| {
                        let name = read_at(&dir, "cmdline", 65536)
                            .context("read anchored qualification cmdline")?;
                        if name.split(|b| *b == 0).next() != Some(package.as_bytes()) {
                            bail!(
                                "not-supported: only explicitly enrolled main process is qualified"
                            );
                        }
                        let status = String::from_utf8(
                            read_at(&dir, "status", 65536)
                                .context("read anchored qualification status")?,
                        )?;
                        let observed = status
                            .lines()
                            .find(|l| l.starts_with("Uid:"))
                            .and_then(|l| l.split_whitespace().nth(1))
                            .and_then(|s| s.parse::<u32>().ok())
                            .context("anchored UID missing")?;
                        if observed != uid || identity.uid != uid || identity.tgid != pid {
                            bail!("anchored package witness mismatch");
                        }
                        if with_memory {
                            maps = Some(open_file(&dir, "maps")?);
                            mem = Some(open_file(&dir, "mem")?);
                        }
                        Ok(PolicyWitness {
                            package: package.into(),
                            tgid: pid,
                            uid,
                        })
                    },
                )
                .context("qualify physical metadata and anchored package witness")?;
            let raw = qualified.identity();
            Ok(Target {
                identity: SourceIdentity {
                    package: package.into(),
                    pid,
                    uid,
                    birth_ns: raw.birth_ns,
                    exec_id: raw.exec_id,
                    boot_id: self.boot_id.clone(),
                },
                qualified,
                dir,
                maps,
                mem,
            })
        }
        ///
        /// # Errors
        ///
        /// Returns when the package process list cannot be read.
        ///
        /// # Panics
        ///
        /// Panics if a debug assertion in this function fails.
        pub fn main_pid(&self, package: &str) -> Result<Option<u32>> {
            let mut candidates: Vec<_> = crate::dexdump::pids_for_package(package)
                .into_iter()
                .filter(|pid| {
                    std::fs::read(format!("/proc/{pid}/cmdline"))
                        .is_ok_and(|b| b.split(|v| *v == 0).next() == Some(package.as_bytes()))
                })
                .collect();
            if candidates.len() <= 1 {
                return Ok(candidates.first().copied());
            }
            // Several processes share the exact package cmdline. Do not merge
            // them and do not fail the capture. Keep the one that has mapped
            // the most app code; break ties toward the newer start time.
            candidates.sort_by_key(|pid| {
                (
                    app_code_mapped_bytes(*pid),
                    stat_start_ticks(
                        &std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default(),
                    )
                    .unwrap_or(0),
                    *pid,
                )
            });
            let chosen = *candidates.last().unwrap();
            eprintln!(
                "multiple exact package processes; selected pid={chosen} by app-code mapping; not merged; unselected={:?}",
                &candidates[..candidates.len() - 1]
            );
            Ok(Some(chosen))
        }
        ///
        /// # Errors
        ///
        /// Returns the existing failure for this operation. No success value is invented.
        pub fn record_candidates(&self, expected: &SourceIdentity, out: &Path) -> Result<()> {
            expected.validate()?;
            let mut target = self.qualify(&expected.package, expected.pid, true)?;
            super::require_same_source(&target.identity, expected)
                .context("candidate source generation changed")?;
            let mut text = String::new();
            target
                .maps
                .as_mut()
                .context("bound candidate maps missing")?
                .take(2 * 1024 * 1024 + 1)
                .read_to_string(&mut text)?;
            if text.len() > 2 * 1024 * 1024 {
                bail!("candidate maps bound");
            }
            let mut rows = crate::dexdump::parse_maps(&text);
            prioritize_install_rows(&mut rows, &crate::dump::apk_paths(&expected.package));
            let mut note = candidate_ledger(&rows, ksight_core::output_budget::remaining(out));
            note["order"] =
                serde_json::json!("app_install_dex_then_elf_then_other_original_maps_order");
            note["source"] = serde_json::to_value(expected)?;
            note["phase"] =
                serde_json::json!("before_static_extraction; runtime_reads_not_started");
            std::fs::create_dir_all(out)?;
            write_candidate_ledger(
                out,
                &format!(
                    "bound-candidates-before-static-{}-{}",
                    expected.pid,
                    uuid::Uuid::new_v4()
                ),
                note,
            )?;
            Ok(())
        }
        ///
        /// # Errors
        ///
        /// Returns the existing failure for this operation. No success value is invented.
        fn copy_one_bound_range(
            &self,
            target: &mut Target,
            expected: &SourceIdentity,
            out: &Path,
            deadline: Instant,
            row: &crate::dexdump::MapRow,
        ) -> Result<BoundRangeStep> {
            let current = self.qualify(&expected.package, expected.pid, false)?;
            super::require_same_source(&current.identity, expected)
                .context("source generation changed before next range")?;
            let binding = current.qualified.into_bound()?;
            let requested = row.end.saturating_sub(row.start);
            let remaining = ksight_core::output_budget::remaining(out);
            let want = selected_range_bytes(requested, remaining);
            let saw_budget_reserve = remaining.is_some() && want < requested;
            let saw_range_cap = remaining.is_none() && want < requested;
            if want == 0 {
                return Ok(BoundRangeStep::Stop { saw_budget_reserve });
            }
            let pending = out.join(format!(
                "bound-{}-{:x}-{}.pending",
                expected.pid,
                row.start,
                uuid::Uuid::new_v4()
            ));
            let mut output = match ksight_core::output_budget::BudgetFile::create(&pending) {
                Ok(file) => file,
                Err(error) if budget_io(&error) => {
                    return Ok(BoundRangeStep::Stop { saw_budget_reserve });
                }
                Err(error) => return Err(error.into()),
            };
            let mut receipt = copy_range(
                target.mem.as_mut().context("bound mem handle missing")?,
                &mut output,
                row.start,
                want,
                || {
                    if ksight_core::output_budget::should_stop(out) {
                        bail!("parent_deadline_or_output_exhausted");
                    }
                    if Instant::now() >= deadline {
                        bail!("local_copy_window_exhausted");
                    }
                    binding.check_current()
                },
            );
            if receipt.admission == "qualified_live_copy" {
                match self.qualify(&expected.package, expected.pid, false) {
                    Ok(current) if current.identity == *expected => {}
                    _ => {
                        receipt.admission = "rejected_generation_after_read".into();
                    }
                }
            }
            // The partial file stays unadmitted. A separate positive end check
            // only establishes that this gap was local time, never code coverage.
            let local_window = receipt.read_error.as_deref() == Some("local_copy_window_exhausted");
            let post_copy_source_verified = local_window
                && !ksight_core::output_budget::should_stop(out)
                && binding.check_current().is_ok()
                && self
                    .qualify(&expected.package, expected.pid, false)
                    .is_ok_and(|current| current.identity == *expected)
                && !ksight_core::output_budget::should_stop(out);
            let stable_mapping = same_bound_mapping(target, row);
            let post_copy_source_verified = post_copy_source_verified
                && stable_mapping
                && !ksight_core::output_budget::should_stop(out)
                && binding.check_current().is_ok()
                && !ksight_core::output_budget::should_stop(out);
            if !stable_mapping {
                receipt.admission = "rejected_mapping_changed_or_unknown".into();
            }
            if output.sync_all().is_err() {
                receipt.write_status = "write_failed".into();
                receipt.write_error = Some("sync failed".into());
            }
            let admitted = receipt.admission == "qualified_live_copy"
                && receipt.read_status == "complete"
                && receipt.write_status == "complete";
            let (final_path, publish_error) =
                publish_bound_pending(&pending, out, expected, row, admitted);
            if let Some(error) = publish_error {
                receipt.write_status = "write_failed".into();
                receipt.write_error = Some(error);
                receipt.admission = "rejected_publish_failure".into();
            }
            let admitted_now = admitted && receipt.write_status == "complete";
            let excluded_local_window = local_window
                && post_copy_source_verified
                && stable_mapping
                && receipt.write_status == "complete"
                && receipt.write_error.is_none()
                && !ksight_core::output_budget::should_stop(out);
            let record = serde_json::json!({"source":expected,"excluded_local_window":excluded_local_window,"post_copy_source_verified":post_copy_source_verified,"mapping_revalidated":stable_mapping,"mapping":{"start":row.start,"end":row.end,"path":row.path,"inode":row.inode,"perms":row.perms},"requested_mapping_bytes":requested,"selection_limit_bytes":want,"selection_limit_reason":if saw_budget_reserve {"runtime_payload_budget_metadata_reserve"} else if saw_range_cap {"per_range_cap"} else {"full_mapping_selected"},"read":receipt,"raw_evidence":final_path.file_name().and_then(|n|n.to_str()),"derived":[],"selection_policy":"app_install_dex_then_elf_then_other_original_maps_order","scope":"anchored original task/mm; named code or executable mappings","admitted":admitted_now});
            Ok(BoundRangeStep::Copied {
                record,
                partial: !admitted_now || want < requested,
                saw_budget_reserve,
                saw_range_cap,
                vdex: admitted_now && android_suffix(&row.path, ".vdex"),
                dex: admitted_now
                    && (android_suffix(&row.path, ".dex") || android_suffix(&row.path, ".cdex")),
                native: admitted_now && android_suffix(&row.path, ".so"),
            })
        }

        /// Copy qualified code ranges from the anchored task.
        ///
        /// # Errors
        ///
        /// Returns when qualification, the maps handle, or the copy note cannot be written.
        pub fn copy_code(
            &self,
            expected: &SourceIdentity,
            out: &Path,
            deadline: Instant,
        ) -> Result<crate::dexdump::LiveDump> {
            expected.validate()?;
            let mut target = self.qualify(&expected.package, expected.pid, true)?;
            super::require_same_source(&target.identity, expected)
                .context("source generation changed before live-copy; no numeric retry")?;

            let mut text = String::new();
            target
                .maps
                .as_mut()
                .context("bound maps handle missing")?
                .take(2 * 1024 * 1024 + 1)
                .read_to_string(&mut text)?;
            if text.len() > 2 * 1024 * 1024 {
                bail!("bound maps bound");
            }
            std::fs::create_dir_all(out)?;
            let mut stats = crate::dexdump::LiveDump::default();
            let mut rows = crate::dexdump::parse_maps(&text);
            prioritize_install_rows(&mut rows, &crate::dump::apk_paths(&expected.package));
            let mut candidates =
                candidate_ledger(&rows, ksight_core::output_budget::remaining(out));
            candidates["order"] =
                serde_json::json!("app_install_dex_then_elf_then_other_original_maps_order");
            let candidate_name =
                format!("bound-candidates-{}-{}", expected.pid, uuid::Uuid::new_v4());
            write_candidate_ledger(out, &candidate_name, candidates)?;
            let mut records = Vec::new();
            let mut record_bytes = 0usize;
            let mut partial = false;
            let mut stopped_early = false;
            let mut saw_range_cap = false;
            let mut saw_budget_reserve = false;
            for row in rows.into_iter().filter(eligible_mapping) {
                if Instant::now() >= deadline || ksight_core::output_budget::should_stop(out) {
                    partial = true;
                    stopped_early = true;
                    break;
                }
                match self.copy_one_bound_range(&mut target, expected, out, deadline, &row)? {
                    BoundRangeStep::Stop {
                        saw_budget_reserve: reserve,
                    } => {
                        partial = true;
                        stopped_early = true;
                        saw_budget_reserve |= reserve;
                        break;
                    }
                    BoundRangeStep::Copied {
                        record,
                        partial: row_partial,
                        saw_budget_reserve: reserve,
                        saw_range_cap: capped,
                        vdex,
                        dex,
                        native,
                    } => {
                        partial |= row_partial;
                        saw_budget_reserve |= reserve;
                        saw_range_cap |= capped;
                        if vdex {
                            stats.vdex_images = stats.vdex_images.saturating_add(1);
                        } else if dex {
                            stats.memory_images = stats.memory_images.saturating_add(1);
                        } else if native {
                            stats.native_libs = stats.native_libs.saturating_add(1);
                        }
                        super::track_record_metadata(out, &record, &mut record_bytes)?;
                        records.push(record);
                    }
                }
            }
            let (unattempted_state, truncation) = bound_copy_gap_state(BoundCopyStops {
                stopped_early,
                budget_stop: ksight_core::output_budget::should_stop(out),
                saw_range_cap,
                saw_budget_reserve,
            });
            let note = serde_json::json!({"schema":"kernsight.bound-code-copy/v1","source":expected,"candidate_manifest":candidate_name,"candidate_result":{"attempted":records.len(),"unattempted_state":unattempted_state,"truncation":truncation,"stop_scope":if stopped_early && saw_budget_reserve {"runtime_metadata_reserve"} else if stopped_early && !ksight_core::output_budget::should_stop(out) {"local_copy_window"} else {"none_or_parent_budget"},"actual_ranges":"records.read","budget_stop":ksight_core::output_budget::should_stop(out)},"records":records,"partial":partial,"paused":false,"torn":true,"torn_reason":"process_not_paused","unsupported":"unregistered anonymous heap/FD/private scans; main-process enrollment only","object_sha256":format!("{:x}",Sha256::digest(std::fs::read(&self.metadata)?)),"btf_sha256":hex_bytes(&self.btf_hash)});
            if let Err(error) = super::write_bound_notes(out, expected.pid, note) {
                ksight_core::output_budget::record_failure(out, "bound_note_metadata_uncommitted");
                return Err(error).context("bound notes not committed; raw payload retained");
            }
            if partial {
                ksight_core::output_budget::record_failure(out, "bound_code_copy_partial");
            }
            let _ = target.dir.as_fd(); // Retain original directory to the end of this producer scope.
            Ok(stats)
        }
    }
    fn same_bound_mapping(target: &Target, row: &crate::dexdump::MapRow) -> bool {
        read_at(&target.dir, "maps", 2 * 1024 * 1024)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .is_some_and(|text| {
                crate::dexdump::parse_maps(&text).iter().any(|now| {
                    now.start == row.start
                        && now.end == row.end
                        && now.path == row.path
                        && now.inode == row.inode
                        && now.perms == row.perms
                })
            })
    }
    /// `Target`.
    pub struct Target {
        /// `identity`.
        pub identity: SourceIdentity,
        /// `qualified`.
        pub qualified: QualifiedInstance,
        dir: File,
        maps: Option<File>,
        mem: Option<File>,
    }
    impl Target {
        pub(crate) fn identity(&self) -> &SourceIdentity {
            &self.identity
        }
        /// Maps text from the directory handle opened at qualification.
        ///
        /// # Errors
        ///
        /// Returns when that handle is missing or the text exceeds the bound.
        /// This does not open `/proc/<pid>/maps` by a numeric pid.
        pub(crate) fn maps_text(&mut self) -> Result<String> {
            use std::io::{Read, Seek, SeekFrom};
            let maps = self.maps.as_mut().context("bound maps handle missing")?;
            maps.seek(SeekFrom::Start(0))?;
            let mut text = String::new();
            maps.take(2 * 1024 * 1024 + 1).read_to_string(&mut text)?;
            if text.len() > 2 * 1024 * 1024 {
                bail!("bound maps bound");
            }
            Ok(text)
        }
        /// Memory handle opened beside qualification. Absent means no read.
        pub(crate) fn anchored_mem(&mut self) -> Option<&mut File> {
            self.mem.as_mut()
        }
    }
    fn open_file(dir: &File, name: &str) -> Result<File> {
        Ok(openat(dir, name, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?.into())
    }
    fn read_at(dir: &File, name: &str, max: usize) -> Result<Vec<u8>> {
        let mut b = Vec::new();
        open_file(dir, name)?
            .take(max as u64 + 1)
            .read_to_end(&mut b)?;
        if b.len() > max {
            bail!("anchored proc field bound");
        }
        Ok(b)
    }
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use physical::{Backend, Target};

#[cfg(test)]
mod range_receipt_regressions {
    use super::copy_range;
    use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

    #[test]
    fn short_read_keeps_actual_bytes_distinct_from_requested_bytes() {
        let mut source = Cursor::new(vec![1, 2, 3]);
        let mut sink = Vec::new();
        let receipt = copy_range(&mut source, &mut sink, 0, 8, || Ok(()));
        assert_eq!(receipt.requested_length, 8);
        assert_eq!(receipt.actual_length, 3);
        assert_eq!(receipt.read_status, "short_read");
        assert_eq!(receipt.write_status, "complete");
        assert_eq!(receipt.admission, "qualified_live_copy");
        assert_eq!(sink, [1, 2, 3]);
        assert!(receipt.torn);
        assert!(!receipt.paused);
    }

    struct ReadFailure {
        source: Cursor<Vec<u8>>,
        reads: usize,
    }
    impl Read for ReadFailure {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            if self.reads == 1 {
                self.source.read(&mut bytes[..3])
            } else {
                Err(io::Error::other("injected read failure"))
            }
        }
    }
    impl Seek for ReadFailure {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.source.seek(position)
        }
    }
    #[test]
    fn read_failure_retains_only_prefix_and_never_claims_complete() {
        let mut source = ReadFailure {
            source: Cursor::new(vec![1; 8]),
            reads: 0,
        };
        let mut sink = Vec::new();
        let receipt = copy_range(&mut source, &mut sink, 0, 8, || Ok(()));
        assert_eq!(receipt.actual_length, 3);
        assert_eq!(sink.len(), 3);
        assert_eq!(receipt.read_status, "read_failed");
        assert_eq!(receipt.read_error.as_deref(), Some("injected read failure"));
        assert_eq!(receipt.write_status, "complete");
    }

    struct WriteFailure;
    impl Write for WriteFailure {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("injected write failure"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn read_success_does_not_hide_destination_failure() {
        let mut source = Cursor::new(vec![1; 8]);
        let receipt = copy_range(&mut source, &mut WriteFailure, 0, 8, || Ok(()));
        assert_eq!(receipt.actual_length, 8);
        assert_eq!(receipt.read_status, "complete");
        assert_eq!(receipt.write_status, "write_failed");
        assert_eq!(
            receipt.write_error.as_deref(),
            Some("injected write failure")
        );
    }
}

#[cfg(test)]
mod preceding_source_identity_tests {
    use super::*;
    use std::io::Cursor;
    #[test]
    fn next_copy_rejects_pid_reuse_exec_change_or_exit_before_reading() {
        let expected = SourceIdentity {
            package: "com.example.fixture".into(),
            pid: 42,
            uid: 10001,
            birth_ns: 123,
            exec_id: 4,
            boot_id: "fixture-boot".into(),
        };
        let mut reused = expected.clone();
        reused.birth_ns += 1;
        let mut exec = expected.clone();
        exec.exec_id += 1;
        for observed in [Some(reused), Some(exec), None] {
            let mut source = Cursor::new(b"original task bytes".to_vec());
            let mut sink = Vec::new();
            let receipt = copy_range(&mut source, &mut sink, 0, 19, || {
                let actual = observed
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("qualified task exited"))?;
                require_same_source(actual, &expected)
            });
            assert_eq!(receipt.actual_length, 0);
            assert_eq!(receipt.admission, "rejected_identity");
            assert_eq!(sink, [] as [u8; 0]);
            assert_eq!(source.position(), 0);
        }
        let mut source = Cursor::new(b"original task bytes".to_vec());
        let mut sink = Vec::new();
        let receipt = copy_range(&mut source, &mut sink, 0, 19, || {
            require_same_source(&expected, &expected)
        });
        assert_eq!(receipt.admission, "qualified_live_copy");
        assert_eq!(sink, b"original task bytes");
    }
}

#[cfg(test)]
mod expanded_mapping_tests {
    use super::*;
    use std::io;

    struct VirtualMap {
        length: u64,
        at: u64,
        sparse_tail: bool,
        max_read: usize,
    }
    impl Read for VirtualMap {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.max_read = self.max_read.max(bytes.len());
            let n = usize::try_from((self.length - self.at).min(bytes.len() as u64)).unwrap();
            bytes[..n].fill(0);
            if self.sparse_tail && n != 0 && self.at + n as u64 == self.length {
                bytes[n - 1] = 7;
            }
            self.at += n as u64;
            Ok(n)
        }
    }
    impl Seek for VirtualMap {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            if let SeekFrom::Start(at) = pos {
                self.at = at;
                Ok(at)
            } else {
                Err(io::Error::other("start seek only"))
            }
        }
    }
    #[derive(Default)]
    struct CountingSink {
        bytes: u64,
        max_write: usize,
        nonzero: usize,
        last: u8,
    }
    impl Write for CountingSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes += bytes.len() as u64;
            self.max_write = self.max_write.max(bytes.len());
            self.nonzero += bytes.iter().filter(|b| **b != 0).count();
            if let Some(last) = bytes.last() {
                self.last = *last;
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn registered_mapping_selection_removes_type_caps_but_reserves_finite_metadata() {
        for requested in [
            16 * 1024 * 1024 + 1,
            64 * 1024 * 1024 + 1,
            128 * 1024 * 1024 + 1,
            121_491_456,
        ] {
            assert_eq!(
                selected_range_bytes(requested, Some(requested + RANGE_METADATA_RESERVE)),
                requested
            );
        }
        assert_eq!(selected_range_bytes(100, Some(RANGE_METADATA_RESERVE)), 0);
        assert_eq!(
            selected_range_bytes(100, Some(RANGE_METADATA_RESERVE - 1)),
            0
        );
        assert_eq!(
            selected_range_bytes(100, Some(RANGE_METADATA_RESERVE + 1)),
            1
        );
        assert_eq!(selected_range_bytes(u64::MAX, None), UNGUARDED_RANGE_LIMIT);
        let text = "1000-2000 r-xp 00000000 00:00 0 /data/app/base.apk\n3000-5000 r-xp 00000000 00:00 0 /memfd:jit-cache";
        let rows = crate::dexdump::parse_maps(text);
        let ledger = candidate_ledger(&rows, Some(RANGE_METADATA_RESERVE));
        assert_eq!(ledger["eligible_count"], 2);
        for candidate in ledger["candidates"].as_array().unwrap() {
            assert_eq!(candidate["selection_limit_bytes"], 0);
            assert_eq!(candidate["state"], "planned_not_read");
            assert!(candidate["actual_bytes"].is_null());
        }
        let (gap, truncation) = bound_copy_gap_state(BoundCopyStops {
            stopped_early: true,
            budget_stop: false,
            saw_range_cap: false,
            saw_budget_reserve: true,
        });
        assert_eq!(gap, "not_attempted_runtime_metadata_reserve");
        assert_eq!(truncation, "runtime_payload_budget_metadata_reserve");
    }

    #[test]
    fn large_sparse_tails_and_all_zero_bytes_are_retained_with_fixed_chunks() {
        for (length, sparse_tail) in [
            (16 * 1024 * 1024 + 1, true),
            (64 * 1024 * 1024 + 1, true),
            (128 * 1024 * 1024 + 1, true),
            (65539, false),
        ] {
            let mut source = VirtualMap {
                length,
                at: 0,
                sparse_tail,
                max_read: 0,
            };
            let mut sink = CountingSink::default();
            let receipt = copy_range(&mut source, &mut sink, 0, length, || Ok(()));
            assert_eq!(receipt.requested_length, length);
            assert_eq!(receipt.actual_length, length);
            assert_eq!(receipt.read_status, "complete");
            assert_eq!(receipt.write_status, "complete");
            assert_eq!(receipt.admission, "qualified_live_copy");
            assert_eq!(sink.bytes, length);
            assert_eq!(sink.nonzero, usize::from(sparse_tail));
            assert_eq!(sink.last, if sparse_tail { 7 } else { 0 });
            assert!(source.max_read <= 65536 && sink.max_write <= 65536);
        }
    }

    #[test]
    fn original_parent_stop_between_chunks_retains_prefix_and_stops_further_reads() {
        let root = std::env::temp_dir().join(format!("copy-parent-stop-{}", uuid::Uuid::new_v4()));
        let _guard =
            ksight_core::output_budget::Guard::install(vec![root.clone()], 1024 * 1024, 60000)
                .unwrap();
        let mut source = VirtualMap {
            length: 200_000,
            at: 0,
            sparse_tail: true,
            max_read: 0,
        };
        let mut sink = CountingSink::default();
        let mut checks = 0;
        let receipt = copy_range(&mut source, &mut sink, 0, 200_000, || {
            checks += 1;
            if checks == 3 {
                ksight_core::output_budget::interrupt(&root, "cancel_requested");
            }
            if ksight_core::output_budget::should_stop(&root) {
                bail!("parent_deadline_or_output_exhausted");
            }
            Ok(())
        });
        assert_eq!(source.at, 65536);
        assert_eq!(sink.bytes, 65536);
        assert_eq!(receipt.read_status, "interrupted");
        assert_eq!(receipt.admission, "rejected_identity_or_deadline");
        assert_eq!(checks, 3);
    }
}
#[cfg(test)]
mod bounded_note_tests {
    use super::*;
    fn check_note(
        note: &Value,
        package: &str,
        expected: &[crate::qualified_code::SourceIdentity],
    ) -> Result<(usize, usize, u64)> {
        let rows = note["records"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("missing ranges"))?;
        let source: crate::qualified_code::SourceIdentity =
            serde_json::from_value(note["source"].clone())?;
        source.validate()?;
        if !expected.contains(&source)
            || source.package != package
            || note["schema"] != "kernsight.bound-code-copy/v1"
            || note["paused"] != false
            || note["candidate_result"]["budget_stop"] != false
            || rows.is_empty()
            || rows.len() > 65536
            || note["candidate_result"]["attempted"].as_u64() != Some(rows.len() as u64)
        {
            bail!("unknown bound coverage");
        }
        let gap = &note["candidate_result"]["unattempted_state"];
        if gap != "none"
            && !(matches!(
                gap.as_str(),
                Some("not_attempted_parent_deadline" | "not_attempted_local_copy_window")
            ) && note["candidate_result"]["stop_scope"] == "local_copy_window")
        {
            bail!("parent or unknown stop");
        }
        let mut admitted = 0;
        let mut excluded = 0;
        let mut excluded_bytes = 0;
        for (index, row) in rows.iter().enumerate() {
            let read = &row["read"];
            let selected = row["selection_limit_bytes"].as_u64().unwrap_or(0);
            if row["source"] != note["source"]
                || selected == 0
                || read["requested_length"].as_u64() != Some(selected)
                || read["write_status"] != "complete"
                || !read["write_error"].is_null()
                || !matches!(
                    row["selection_limit_reason"].as_str(),
                    Some(
                        "full_mapping_selected"
                            | "per_range_cap"
                            | "runtime_payload_budget_metadata_reserve"
                    )
                )
            {
                bail!("unverified source/range or write failure");
            }
            if row["admitted"] == true
                && read["admission"] == "qualified_live_copy"
                && read["read_status"] == "complete"
                && read["read_error"].is_null()
                && read["actual_length"].as_u64() == Some(selected)
            {
                admitted += 1;
            } else if index + 1 == rows.len()
                && excluded == 0
                && row["admitted"] == false
                && row["excluded_local_window"] == true
                && row["post_copy_source_verified"] == true
                && row["mapping_revalidated"] == true
                && read["read_error"] == "local_copy_window_exhausted"
                && ((read["admission"] == "rejected_identity_or_deadline"
                    && matches!(read["read_status"].as_str(), Some("interrupted" | "complete")))
                // copy_range's initial current() check uses these generic states
                // even for a local-window stop before the first read. The exact
                // reason and positive post-copy checks above still gate exclusion.
                || (read["admission"] == "rejected_identity"
                    && read["read_status"] == "not_attempted"
                    && read["actual_length"].as_u64() == Some(0)
                    && read.get("sha256").is_some_and(Value::is_null)))
                && read["actual_length"]
                    .as_u64()
                    .is_some_and(|n| n <= selected)
                && row["raw_evidence"]
                    .as_str()
                    .is_some_and(|name| name.ends_with(".pending") && !name.contains('/'))
                && note["candidate_result"]["stop_scope"] == "local_copy_window"
            {
                excluded = 1;
                excluded_bytes = read["actual_length"].as_u64().unwrap_or(0);
            } else {
                bail!("unverified range or IO/identity failure");
            }
        }
        Ok((admitted, excluded, excluded_bytes))
    }

    fn source() -> Value {
        json!({"package":"test.app","pid":1,"uid":10001,"birth_ns":1,"exec_id":1,"boot_id":"test-boot"})
    }
    fn complete(padding: usize) -> Value {
        json!({"source":source(),"admitted":true,"selection_limit_bytes":1,
            "selection_limit_reason":"full_mapping_selected","padding":"x".repeat(padding),
            "read":{"admission":"qualified_live_copy","read_status":"complete",
            "write_status":"complete","read_error":null,"write_error":null,"actual_length":1,"requested_length":1}})
    }
    fn note(records: Vec<Value>) -> Value {
        json!({"schema":"kernsight.bound-code-copy/v1","source":source(),"paused":false,
            "candidate_manifest":"bound-candidates-review","candidate_result":{"budget_stop":false,
            "attempted":records.len(),"unattempted_state":"none","stop_scope":"none_or_parent_budget"},"records":Value::Array(records)})
    }
    fn validated_counts(bodies: &[Vec<u8>]) -> (usize, usize) {
        let expected = vec![serde_json::from_value(source()).unwrap()];
        let mut admitted = 0;
        let mut excluded = 0;
        for body in bodies {
            assert!(body.len() <= NOTE_LIMIT);
            let parsed: Value = serde_json::from_slice(body).unwrap();
            let counts = check_note(&parsed, "test.app", &expected).unwrap();
            admitted += counts.0;
            excluded += counts.1;
        }
        assert!(bodies.len() <= NOTE_COUNT_LIMIT);
        assert!(bodies.iter().map(Vec::len).sum::<usize>() <= NOTES_TOTAL_LIMIT);
        (admitted, excluded)
    }
    #[test]
    fn compact_1390_rows_remain_inside_the_current_validator_limits() {
        let bodies = compact_bound_notes(note(vec![complete(700); 1390])).unwrap();
        assert_eq!(validated_counts(&bodies), (1390, 0));
        assert_eq!(bodies.len(), 1);
    }
    #[test]
    fn bounded_shards_keep_all_actual_ranges_and_match_attempted() {
        let bodies = compact_bound_notes(note(vec![complete(800_000); 3])).unwrap();
        assert_eq!(bodies.len(), 2);
        assert_eq!(validated_counts(&bodies), (3, 0));
    }
    #[test]
    fn only_the_last_global_local_window_is_excluded() {
        let mut last = complete(800_000);
        last["admitted"] = json!(false);
        last["excluded_local_window"] = json!(true);
        last["post_copy_source_verified"] = json!(true);
        last["mapping_revalidated"] = json!(true);
        last["raw_evidence"] = json!("bound-review.pending");
        last["read"] = json!({"admission":"rejected_identity","read_status":"not_attempted",
            "write_status":"complete","read_error":"local_copy_window_exhausted",
            "write_error":null,"actual_length":0,"requested_length":1,"sha256":null});
        let mut n = note(vec![complete(800_000), complete(800_000), last.clone()]);
        n["candidate_result"]["unattempted_state"] = json!("not_attempted_local_copy_window");
        n["candidate_result"]["stop_scope"] = json!("local_copy_window");
        let bodies = compact_bound_notes(n).unwrap();
        assert_eq!(validated_counts(&bodies), (2, 1));
        assert!(compact_bound_notes(note(vec![last, complete(0)])).is_err());
    }
    #[test]
    fn exact_note_and_total_size_boundaries_fail_closed_at_plus_one() {
        let mut count = JsonCount {
            count: 0,
            limit: NOTE_LIMIT,
        };
        let chunk = vec![0u8; 65536];
        for _ in 0..NOTE_LIMIT / 65536 {
            count.write_all(&chunk).unwrap();
        }
        assert_eq!(count.count, NOTE_LIMIT);
        assert!(count.write_all(&[0]).is_err());
        let mut total = NOTES_TOTAL_LIMIT - NOTE_LIMIT;
        admit_note_size(&mut total, NOTE_LIMIT).unwrap();
        assert_eq!(total, NOTES_TOTAL_LIMIT);
        assert!(admit_note_size(&mut total, 1).is_err());
        assert!(admit_note_size(&mut 0, NOTE_LIMIT + 1).is_err());
    }
    #[test]
    fn excessive_single_record_and_aggregate_are_never_silently_omitted() {
        assert!(compact_bound_notes(note(vec![complete(NOTE_LIMIT)])).is_err());
        assert!(compact_bound_notes(note(vec![complete(800_000); 12])).is_err());
    }
    #[test]
    fn runtime_metadata_reserve_gap_is_not_disguised_as_local_time() {
        let mut n = note(vec![complete(0)]);
        n["candidate_result"]["unattempted_state"] =
            json!("not_attempted_runtime_metadata_reserve");
        n["candidate_result"]["stop_scope"] = json!("runtime_metadata_reserve");
        let bodies = compact_bound_notes(n).unwrap();
        let parsed: Value = serde_json::from_slice(&bodies[0]).unwrap();
        let expected = vec![serde_json::from_value(source()).unwrap()];
        assert!(check_note(&parsed, "test.app", &expected).is_err());
        assert_eq!(
            parsed["candidate_result"]["unattempted_state"],
            "not_attempted_runtime_metadata_reserve"
        );
    }
}

#[cfg(test)]
mod bound_note_production_proof_tests {
    use super::*;
    #[test]
    fn production_shards_keep_real_1390_receipts_compatible_with_existing_proof() {
        let root = std::env::temp_dir().join(format!("bound-note-proof-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("runtime")).unwrap();
        let guard =
            ksight_core::output_budget::Guard::install(vec![root.clone()], 16 * 1024 * 1024, 60000)
                .unwrap();
        let source = SourceIdentity {
            package: "test.app".into(),
            pid: 1,
            uid: 10001,
            birth_ns: 1,
            exec_id: 1,
            boot_id: "test-boot".into(),
        };
        let records = (0..1390).map(|_| json!({"source":source,"admitted":true,"selection_limit_bytes":1,"selection_limit_reason":"full_mapping_selected","padding":"x".repeat(1300),"read":{"admission":"qualified_live_copy","read_status":"complete","write_status":"complete","read_error":null,"write_error":null,"actual_length":1,"requested_length":1}})).collect::<Vec<_>>();
        let note = json!({"schema":"kernsight.bound-code-copy/v1","source":source,"paused":false,"candidate_result":{"budget_stop":false,"attempted":1390,"unattempted_state":"none","stop_scope":"none_or_parent_budget"},"records":records});
        write_bound_notes(&root.join("runtime"), source.pid, note).unwrap();
        ksight_core::output_budget::write(root.join("dump-report.json"), serde_json::to_vec(&json!({"schema_version":crate::dump::PACKAGE_DUMP_SCHEMA,"package":"test.app","dump_id":uuid::Uuid::new_v4(),"agent_version":"test","artifacts":[{}],"mapped_code":[],"warnings":[]})).unwrap()).unwrap();
        ksight_core::output_budget::record_failure(&root, "bound_code_copy_partial");
        let proof =
            crate::dump_coverage::proof(&root, "test.app", std::slice::from_ref(&source)).unwrap();
        assert_eq!(proof["admitted_ranges"], 1390);
        assert_eq!(proof["bound_notes"], 2);
        assert_eq!(proof["payload_coverage_complete"], false);
        drop(guard);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod metadata_omission_authority_tests {
    use super::*;
    #[test]
    fn oversized_record_is_explicit_noncoverage_failure_not_a_trusted_prior_note() {
        let root = std::env::temp_dir().join(format!("metadata-stop-{}", uuid::Uuid::new_v4()));
        let guard =
            ksight_core::output_budget::Guard::install(vec![root.clone()], 16 * 1024 * 1024, 60000)
                .unwrap();
        ksight_core::output_budget::record_failure(&root, "bound_code_copy_partial");
        assert!(ksight_core::output_budget::bound_terminal_coverage(&root).is_some());
        let mut used = 0;
        assert!(track_record_metadata(
            &root,
            &json!({"padding":"x".repeat(NOTE_LIMIT)}),
            &mut used
        )
        .is_err());
        assert_eq!(used, 0);
        assert!(guard
            .receipt()
            .failure_reasons
            .contains(&"bound_note_metadata_exhausted".into()));
        assert!(ksight_core::output_budget::bound_terminal_coverage(&root).is_none());
    }
}
