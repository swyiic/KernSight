#![cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
//! Backend capability, physical task qualification and anchored live code copies.
//! No qualification is minted from a numeric PID, proc ticks or a missing record.
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
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
            if r.path.ends_with(".dex") || r.path.ends_with(".vdex") {
                0
            } else if r.path.ends_with(".so") {
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
                || path.ends_with(".dex")
                || path.ends_with(".vdex")
                || path.ends_with(".apk")
                || path.ends_with(".so");
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

fn eligible_mapping(r: &crate::dexdump::MapRow) -> bool {
    r.perms.contains('r')
        && (r.perms.contains('x')
            || [".dex", ".vdex", ".apk", ".oat", ".art", ".so"]
                .iter()
                .any(|s| r.path.contains(s)))
}

fn code_range_cap(path: &str) -> u64 {
    let path = path.trim_end().strip_suffix(" (deleted)").unwrap_or(path);
    // DEX images and named ELF libraries share the 128MiB image limit.
    // JIT memfd and APK mappings stay at 16MiB so they cannot consume the runtime payload.
    if path.ends_with(".vdex")
        || path.ends_with(".dex")
        || path.ends_with(".cdex")
        || path.ends_with(".so")
    {
        128 * 1024 * 1024
    } else {
        16 * 1024 * 1024
    }
}

fn bound_copy_gap_state(
    stopped_early: bool,
    budget_stop: bool,
    saw_range_cap: bool,
    saw_budget_reserve: bool,
) -> (&'static str, &'static str) {
    let unattempted = if stopped_early && budget_stop {
        "not_attempted_parent_deadline_or_output_exhausted"
    } else if stopped_early {
        "not_attempted_parent_deadline"
    } else {
        "none"
    };
    let truncation = if saw_range_cap {
        "per_range_cap"
    } else if saw_budget_reserve {
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
fn candidate_object(rank: usize, row: &crate::dexdump::MapRow) -> serde_json::Value {
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
        "selection_limit_bytes": row.end.saturating_sub(row.start).min(code_range_cap(&row.path)),
        "selection_reason": "eligible_install_priority_until_parent_budget",
        "state": "planned_not_read",
        "actual_bytes": null
    })
}

fn candidate_ledger(rows: &[crate::dexdump::MapRow]) -> serde_json::Value {
    let candidates: Vec<_> = rows
        .iter()
        .filter(|row| eligible_mapping(row))
        .enumerate()
        .map(|(rank, row)| candidate_object(rank, row))
        .collect();
    serde_json::json!({
        "schema": "kernsight.code-candidates/v1",
        "order": "original_maps_order_unchanged",
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
    use super::*;
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
    use std::{fs::File, os::fd::AsFd, path::PathBuf, time::Duration};
    /// Real BTF and actual verifier acceptance. Retained hashes detect drift at every issuance.
    pub struct Backend {
        pub metadata: PathBuf,
        pub uprobe: PathBuf,
        object_hash: [u8; 32],
        btf_hash: [u8; 32],
        pub boot_id: String,
    }
    impl Backend {
        pub fn open() -> Result<Self> {
            let (metadata, uprobe) = crate::embedded::qualified_objects()?;
            let object = std::fs::read(&metadata)?;
            if object.len() > 262144 {
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
                Pid::from_raw(std::process::id() as i32).context("self PID")?,
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
        pub fn uid(&self, package: &str) -> Result<u32> {
            let resolver = crate::identity::AndroidIdentityResolver::from_system()?;
            let uid = resolver
                .exclusive_package_uid(package)
                .context("not-supported: shared/ambiguous/missing package UID enrollment")?;
            Ok(uid)
        }
        pub fn qualify(&self, package: &str, pid: u32, with_memory: bool) -> Result<Target> {
            if crate::retention::boot_id().as_deref() != Some(self.boot_id.as_str()) {
                bail!("boot identity changed");
            }
            let uid = self.uid(package)?;
            let pidfd = pidfd_open(
                Pid::from_raw(pid as i32).context("target PID")?,
                PidfdFlags::empty(),
            )?;
            // Proc directory retained through qualification; mem belongs to this original task/mm, not a later numeric PID.
            let dir = File::open(format!("/proc/{pid}"))?;
            let mut maps = None;
            let mut mem = None;
            let qualified =
                MetadataObserver::load(&self.metadata, self.object_hash, self.btf_hash)?.qualify(
                    &QualificationPolicy {
                        package: package.into(),
                        tgid: pid,
                        uid,
                    },
                    pidfd,
                    |_, identity| {
                        let name = read_at(&dir, "cmdline", 65536)?;
                        if name.split(|b| *b == 0).next() != Some(package.as_bytes()) {
                            bail!(
                                "not-supported: only explicitly enrolled main process is qualified"
                            );
                        }
                        let status = String::from_utf8(read_at(&dir, "status", 65536)?)?;
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
                )?;
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
        pub fn record_candidates(&self, expected: &SourceIdentity, out: &Path) -> Result<()> {
            expected.validate()?;
            let mut target = self.qualify(&expected.package, expected.pid, true)?;
            if target.identity != *expected {
                bail!("candidate source generation changed");
            }
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
            let mut note = candidate_ledger(&rows);
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
        pub fn copy_code(
            &self,
            expected: &SourceIdentity,
            out: &Path,
            deadline: Instant,
        ) -> Result<crate::dexdump::LiveDump> {
            expected.validate()?;
            let mut target = self.qualify(&expected.package, expected.pid, true)?;
            if target.identity != *expected {
                bail!("source generation changed before live-copy; no numeric retry");
            }

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
            let mut candidates = candidate_ledger(&rows);
            candidates["order"] =
                serde_json::json!("app_install_dex_then_elf_then_other_original_maps_order");
            let candidate_name =
                format!("bound-candidates-{}-{}", expected.pid, uuid::Uuid::new_v4());
            write_candidate_ledger(out, &candidate_name, candidates)?;
            let mut records = Vec::new();
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
                let current = self.qualify(&expected.package, expected.pid, false)?;
                if current.identity != *expected {
                    bail!("source generation changed before next range");
                }
                let binding = current.qualified.into_bound()?;
                let requested = row.end.saturating_sub(row.start);
                let range_cap = code_range_cap(&row.path);
                let want = requested.min(range_cap).min(
                    ksight_core::output_budget::remaining(out)
                        .map_or(u64::MAX, |n| n.saturating_sub(256 * 1024)),
                );
                if want < requested.min(range_cap) {
                    saw_budget_reserve = true;
                } else if want < requested {
                    saw_range_cap = true;
                }
                if want == 0 {
                    partial = true;
                    break;
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
                        partial = true;
                        break;
                    }
                    Err(error) => return Err(error.into()),
                };
                let mut receipt = copy_range(
                    target.mem.as_mut().context("bound mem handle missing")?,
                    &mut output,
                    row.start,
                    want,
                    || {
                        if Instant::now() >= deadline
                            || ksight_core::output_budget::should_stop(out)
                        {
                            bail!("parent_deadline_or_output_exhausted");
                        }
                        binding.check_current()
                    },
                );
                // Fresh raw metadata comparison after copying. Unknown/different exec never becomes qualified data.
                if receipt.admission == "qualified_live_copy" {
                    match self.qualify(&expected.package, expected.pid, false) {
                        Ok(current) if current.identity == *expected => {}
                        _ => {
                            receipt.admission = "rejected_generation_after_read".into();
                            partial = true;
                        }
                    }
                }
                let stable_mapping = read_at(&target.dir, "maps", 2 * 1024 * 1024)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .is_some_and(|text| {
                        crate::dexdump::parse_maps(&text).iter().any(|now| {
                            now.start == row.start
                                && now.end == row.end
                                && now.path == row.path
                                && now.inode == row.inode
                                && now.perms == row.perms
                        })
                    });
                if !stable_mapping {
                    receipt.admission = "rejected_mapping_changed_or_unknown".into();
                    partial = true;
                }
                if output.sync_all().is_err() {
                    receipt.write_status = "write_failed".into();
                    receipt.write_error = Some("sync failed".into());
                }
                let admitted = receipt.admission == "qualified_live_copy"
                    && receipt.read_status == "complete"
                    && receipt.write_status == "complete";
                let final_path = if admitted {
                    let p = out.join(format!(
                        "bound-{}-{:x}-{}.code",
                        expected.pid,
                        row.start,
                        uuid::Uuid::new_v4()
                    ));
                    // Reserve a fresh destination before replacing only our own empty placeholder.
                    // Rename retains the raw bytes without doubling inventory/budget via a hard-link alias.
                    let publish = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&p)
                        .and_then(|owned| {
                            drop(owned);
                            std::fs::rename(&pending, &p)
                        });
                    match publish {
                        Ok(()) => p,
                        Err(error) => {
                            receipt.write_status = "write_failed".into();
                            receipt.write_error = Some(error.to_string());
                            receipt.admission = "rejected_publish_failure".into();
                            partial = true;
                            pending.clone()
                        }
                    }
                } else {
                    partial = true;
                    pending.clone()
                };
                if want < requested {
                    partial = true;
                }
                if admitted && receipt.write_status == "complete" {
                    if row.path.ends_with(".vdex") {
                        stats.vdex_images = stats.vdex_images.saturating_add(1);
                    } else if row.path.ends_with(".dex") || row.path.ends_with(".cdex") {
                        stats.memory_images = stats.memory_images.saturating_add(1);
                    } else if row.path.ends_with(".so") {
                        stats.native_libs = stats.native_libs.saturating_add(1);
                    }
                }
                records.push(serde_json::json!({"source":expected,"mapping":{"start":row.start,"end":row.end,"path":row.path,"inode":row.inode,"perms":row.perms},"requested_mapping_bytes":requested,"selection_limit_bytes":want,"selection_limit_reason":if want<requested.min(range_cap){"runtime_payload_budget_metadata_reserve"}else if want<requested{"per_range_cap"}else{"full_mapping_selected"},"read":receipt,"raw_evidence":final_path.file_name().and_then(|n|n.to_str()),"derived":[],"selection_policy":"app_install_dex_then_elf_then_other_original_maps_order","scope":"anchored original task/mm; named code or executable mappings","admitted":admitted && receipt.write_status=="complete"}));
                // These are qualified raw code ranges, not reconstructed complete DEX/SO images.
            }
            let (unattempted_state, truncation) = bound_copy_gap_state(
                stopped_early,
                ksight_core::output_budget::should_stop(out),
                saw_range_cap,
                saw_budget_reserve,
            );
            let note = serde_json::json!({"schema":"kernsight.bound-code-copy/v1","source":expected,"candidate_manifest":candidate_name,"candidate_result":{"attempted":records.len(),"unattempted_state":unattempted_state,"truncation":truncation,"actual_ranges":"records.read","budget_stop":ksight_core::output_budget::should_stop(out)},"records":records,"partial":partial,"paused":false,"torn":true,"torn_reason":"process_not_paused","unsupported":"unregistered anonymous heap/FD/private scans; main-process enrollment only","object_sha256":format!("{:x}",Sha256::digest(std::fs::read(&self.metadata)?)),"btf_sha256":self.btf_hash.iter().map(|b|format!("{b:02x}")).collect::<String>()});
            let note_body = serde_json::to_vec_pretty(&note)?;
            let note_path = out.join(format!(
                "bound-source-{}-{}.json",
                expected.pid,
                uuid::Uuid::new_v4()
            ));
            if ksight_core::output_budget::write(&note_path, &note_body).is_err() {
                partial = true;
                // Already-read range metadata only. No further process memory is read.
                if note_body.len() <= 256 * 1024 {
                    let _ = std::fs::write(&note_path, &note_body);
                }
            }
            if partial {
                ksight_core::output_budget::record_failure(out, "bound_code_copy_partial");
            }
            let _ = target.dir.as_fd(); // Retain original directory to the end of this producer scope.
            Ok(stats)
        }
    }
    pub struct Target {
        pub identity: SourceIdentity,
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
mod tests {
    #[test]
    fn elf_range_cap_matches_dex_image_limit_and_jit_stays_small() {
        assert_eq!(
            code_range_cap("/data/app/p/lib/arm64/libapp.so"),
            128 * 1024 * 1024
        );
        assert_eq!(
            code_range_cap("/data/app/p/lib/arm64/libapp.so (deleted)"),
            128 * 1024 * 1024
        );
        assert_eq!(
            code_range_cap("/data/app/p/oat/arm64/base.vdex"),
            128 * 1024 * 1024
        );
        assert_eq!(
            code_range_cap("/memfd:jit-cache (deleted)"),
            16 * 1024 * 1024
        );
        assert_eq!(code_range_cap("/data/app/p/base.apk"), 16 * 1024 * 1024);
    }

    #[test]
    fn full_so_copy_is_not_labeled_unattempted_when_only_torn() {
        assert_eq!(
            bound_copy_gap_state(false, false, false, false),
            ("none", "none")
        );
        assert_eq!(
            bound_copy_gap_state(false, false, true, false),
            ("none", "per_range_cap")
        );
        assert_eq!(
            bound_copy_gap_state(true, true, false, true),
            (
                "not_attempted_parent_deadline_or_output_exhausted",
                "runtime_payload_budget_metadata_reserve"
            )
        );
    }

    use super::*;
    #[test]
    fn static_install_rows_follow_registered_code_priority() {
        let mut rows=crate::dexdump::parse_maps("1000-2000 r--p 0 00:00 1 /data/app/id/base.apk\n2000-3000 r-xp 0 00:00 2 /data/app/id/lib/a.so\n3000-4000 rw-p 0 00:00 3 /data/app/id/oat/base.vdex\n");
        prioritize_install_rows(&mut rows, &["/data/app/id/base.apk".into()]);
        assert_eq!(
            rows.iter().map(|r| r.start).collect::<Vec<_>>(),
            vec![0x3000, 0x2000, 0x1000]
        );
    }
    #[test]
    fn app_file_priority_preserves_ties_and_does_not_promote_private_or_prefix_collision() {
        let mut rows=crate::dexdump::parse_maps("1000-2000 r-xs 00000000 00:00 1 /memfd:jit-cache\n2000-3000 r-xp 00000000 00:00 2 /data/app/id/lib/libone.so\n3000-4000 r-xp 00000000 00:00 3 /data/app/id2/lib/libother.so\n4000-5000 r-xp 00000000 00:00 4 /data/app/id/lib/libtwo.so\n5000-6000 r-xp 00000000 00:00 5 /data/user/0/pkg/cache/base.art\n");
        prioritize_install_rows(&mut rows, &["/data/app/id/base.apk".into()]);
        assert_eq!(
            rows.iter().map(|r| r.start).collect::<Vec<_>>(),
            vec![0x2000, 0x4000, 0x1000, 0x3000, 0x5000]
        );
    }
    #[test]
    fn candidate_plan_preserves_order_bounds_and_unknown_actual() {
        let rows = crate::dexdump::parse_maps("1000-2000 r-xs 00000000 00:00 1 /memfd:jit-cache\n2000-3000 r-xp 00000000 00:00 2 /data/app/test/libapp.so\n3000-4000 rw-p 00000000 00:00 0 [heap]\n");
        let note = candidate_ledger(&rows);
        assert_eq!(note["eligible_count"], 2);
        assert_eq!(note["candidates"][0]["category"], "jit_named");
        assert_eq!(note["candidates"][1]["category"], "elf_named");
        assert!(note["candidates"][1]["actual_bytes"].is_null());
        assert_eq!(note["candidates"][1]["ownership"], "unknown");
        let many = (0..140)
            .map(|_| crate::dexdump::MapRow {
                start: 0,
                end: 1,
                perms: "r-xp".into(),
                path: "x".repeat(400),
                inode: 0,
            })
            .collect::<Vec<_>>();
        let capped = candidate_ledger(&many);
        assert_eq!(capped["listed_count"], 140);
        assert_eq!(capped["omitted_count"], 0);
        assert!(capped["omitted_reason"].is_null());
        assert_eq!(capped["candidates"][0]["path_truncated"], true);
        assert_eq!(
            capped["candidates"][0]["selection_reason"],
            "eligible_install_priority_until_parent_budget"
        );
    }

    #[test]
    fn stat_start_ticks_reads_field_22_after_comm() {
        let stat = "12 (my proc) R 1 12 12 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 999 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
        assert_eq!(stat_start_ticks(stat), Some(999));
        assert_eq!(stat_start_ticks("no-paren"), None);
    }

    use std::io::Cursor;
    #[test]
    #[allow(
        clippy::items_after_statements,
        reason = "Local fixture or owned callback keeps its explicit scope and fallible signature."
    )]
    fn production_bound_range_short_failure_and_generation_rejection_remain_distinct() {
        let r = copy_range(&mut Cursor::new(b"abc"), &mut Vec::new(), 0, 6, || Ok(()));
        assert_eq!(r.read_status, "short_read");
        assert_eq!(r.actual_length, 3);
        assert!(r.torn);
        assert!(!r.paused);
        struct Broken;
        impl Read for Broken {
            #[allow(
                clippy::items_after_statements,
                reason = "Local fixture or owned callback keeps its explicit scope and fallible signature."
            )]
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::PermissionDenied.into())
            }
        }
        impl Seek for Broken {
            fn seek(&mut self, _: SeekFrom) -> std::io::Result<u64> {
                Ok(0)
            }
        }
        let r = copy_range(&mut Broken, &mut Vec::new(), 0, 6, || Ok(()));
        assert_eq!(r.read_status, "read_failed");
        assert_eq!(r.actual_length, 0);
        let r = copy_range(&mut Cursor::new(b"abc"), &mut Vec::new(), 0, 3, || {
            bail!("generation changed")
        });
        assert_eq!(r.admission, "rejected_identity");
        assert_eq!(r.actual_length, 0);
    }
    #[test]
    fn production_bound_range_checks_current_qualification_between_chunks_and_at_return() {
        let bytes = vec![7; 131_072];
        let mut checks = 0;
        let mut out = Vec::new();
        let r = copy_range(
            &mut Cursor::new(&bytes),
            &mut out,
            0,
            bytes.len() as u64,
            || {
                checks += 1;
                if checks == 3 {
                    bail!("task exited");
                }
                Ok(())
            },
        );
        assert_eq!(r.actual_length, 65536);
        assert_eq!(r.admission, "rejected_identity_or_deadline");
        assert_eq!(out.len(), 65536);
        let r = copy_range(&mut Cursor::new(b"same"), &mut Vec::new(), 0, 4, || Ok(()));
        assert_eq!(r.admission, "qualified_live_copy");
        assert_eq!(r.sha256, Some(format!("{:x}", Sha256::digest(b"same"))));
    }
    #[test]
    fn production_budget_exhaustion_retains_prefix_and_marks_unfinished_read_interrupted() {
        let root = std::env::temp_dir().join(format!("range-budget-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("raw.pending");
        let guard =
            ksight_core::output_budget::Guard::install(vec![root.clone()], 65536, 1000).unwrap();
        let mut out = ksight_core::output_budget::BudgetFile::create(&path).unwrap();
        let r = copy_range(
            &mut Cursor::new(vec![7; 196_608]),
            &mut out,
            0,
            196_608,
            || Ok(()),
        );
        out.sync_all().unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 65536);
        assert_eq!(r.actual_length, 131_072); // read bytes are independent of committed bytes
        assert_eq!(r.read_status, "interrupted");
        assert_eq!(r.write_status, "write_failed");
        assert!(r
            .write_error
            .as_deref()
            .unwrap()
            .contains("output_budget_exhausted"));
        assert_eq!(guard.receipt().admitted_write_bytes, 65536);
        assert!(guard.receipt().partial);
    }
    #[test]
    fn production_bound_range_write_failure_and_missing_old_identity_never_count_as_complete() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::StorageFull.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let r = copy_range(&mut Cursor::new(b"abc"), &mut Broken, 0, 3, || Ok(()));
        assert_eq!(r.write_status, "write_failed");
        assert_eq!(r.actual_length, 3);
        assert!(SourceIdentity {
            package: "fixture".into(),
            pid: 1,
            uid: 1,
            birth_ns: 0,
            exec_id: 0,
            boot_id: String::new()
        }
        .validate()
        .is_err());
        assert!(capability().is_err()); // Host is not an ARM Android backend; no fake success.
    }
}
