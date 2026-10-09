//! Opt-in output-write budget. Scope is this invocation's registered roots, not system disk.
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Write},
    path::{Component, Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
#[derive(Clone, Debug, Serialize)]
/// Receipt retained by this evidence operation.
pub struct Receipt {
    /// Bounded aggregate write charges by evidence kind; no paths or payloads.
    pub admitted_by_kind: BTreeMap<&'static str, u64>,
    /// Charge calls by kind include replacements and admitted writes that later fail.
    pub admission_calls_by_kind: BTreeMap<&'static str, u64>,
    /// Schema retained by this evidence operation.
    pub schema: &'static str,
    /// Limit bytes retained by this evidence operation.
    pub limit_bytes: u64,
    /// Admitted write bytes retained by this evidence operation.
    pub admitted_write_bytes: u64,
    /// Rejected writes retained by this evidence operation.
    pub rejected_writes: u64,
    /// Partial retained by this evidence operation.
    pub partial: bool,
    /// Reason retained by this evidence operation.
    pub reason: Option<String>,
    /// Bounded distinct causes; coverage gaps and later hard stops are retained separately.
    pub failure_reasons: Vec<String>,
}
struct State {
    non_coverage_failure: bool,
    roots: Vec<PathBuf>,
    deadline: Instant,
    receipt: Receipt,
}
fn note_failure(state: &mut State, reason: &str) {
    state.non_coverage_failure |= reason != "bound_code_copy_partial";
    state.receipt.partial = true;
    if state.receipt.reason.is_none() {
        state.receipt.reason = Some(reason.into());
    }
    let reason: String = reason.chars().take(256).collect();
    if !state.receipt.failure_reasons.contains(&reason) {
        if state.receipt.failure_reasons.len() < 16 {
            state.receipt.failure_reasons.push(reason);
        } else {
            state.receipt.failure_reasons[15] = "additional_failure_reasons_omitted".into();
        }
    }
}

static STATES: OnceLock<Mutex<BTreeMap<u64, State>>> = OnceLock::new();
static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
fn states() -> &'static Mutex<BTreeMap<u64, State>> {
    STATES.get_or_init(|| Mutex::new(BTreeMap::new()))
}
struct StaticState {
    root: PathBuf,
    limit: u64,
    spent: u64,
    reserved_report: Option<PathBuf>,
    allow_bound_coverage: bool,
}
static STATIC_SCOPES: OnceLock<Mutex<BTreeMap<u64, StaticState>>> = OnceLock::new();
fn static_scopes() -> &'static Mutex<BTreeMap<u64, StaticState>> {
    STATIC_SCOPES.get_or_init(|| Mutex::new(BTreeMap::new()))
}
/// Additional static-output admission limit; the invocation guard remains authoritative.
pub struct StaticScope(u64);
impl StaticScope {
    /// Bound catalog sidecars while reserving capacity for the exact final report path.
    /// The report still passes the original invocation quota and deadline checks.
    /// # Errors
    /// Returns an invalid or overlapping scope error.
    pub fn install_catalog(root: PathBuf, reserve: u64) -> io::Result<Self> {
        let report = root.join("dump-report.json");
        let scope = Self::install(root, 64 * 1024 * 1024, reserve)?;
        static_scopes()
            .lock()
            .map_err(|_| io::Error::other("static scope lock"))?
            .get_mut(&scope.0)
            .ok_or_else(|| io::Error::other("missing catalog scope"))?
            .reserved_report = Some(report);
        Ok(scope)
    }
    /// Permit independent installed-file extraction after a coverage-only live copy gap.
    /// This never authorizes another runtime memory read, nor resets the parent receipt.
    /// # Errors
    /// Returns an invalid scope or lock error.
    pub fn install_after_bound_copy(root: PathBuf, cap: u64, reserve: u64) -> io::Result<Self> {
        let scope = Self::install(root, cap, reserve)?;
        static_scopes()
            .lock()
            .map_err(|_| io::Error::other("static scope lock"))?
            .get_mut(&scope.0)
            .ok_or_else(|| io::Error::other("missing static scope"))?
            .allow_bound_coverage = true;
        Ok(scope)
    }

    /// Reserve report space from the parent's remaining allowance and bound static output.
    /// # Errors
    /// Returns an invalid or overlapping scope error.
    pub fn install(root: PathBuf, cap: u64, reserve: u64) -> io::Result<Self> {
        if !root.is_absolute() || root.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(io::Error::other("invalid static scope"));
        }
        let available = remaining(&root).unwrap_or(cap).saturating_sub(reserve);
        let mut scopes = static_scopes()
            .lock()
            .map_err(|_| io::Error::other("static scope lock"))?;
        if scopes
            .values()
            .any(|s| root.starts_with(&s.root) || s.root.starts_with(&root))
        {
            return Err(io::Error::other("overlapping static scope"));
        }
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        scopes.insert(
            id,
            StaticState {
                root,
                limit: cap.min(available),
                spent: 0,
                reserved_report: None,
                allow_bound_coverage: false,
            },
        );
        Ok(Self(id))
    }
}
impl Drop for StaticScope {
    fn drop(&mut self) {
        if let Ok(mut scopes) = static_scopes().lock() {
            scopes.remove(&self.0);
        }
    }
}
/// Guard retained by this evidence operation.
pub struct Guard(u64);
impl Guard {
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    /// Install retained by this evidence operation.
    pub fn install(roots: Vec<PathBuf>, bytes: u64, max_ms: u64) -> io::Result<Self> {
        if roots.is_empty()
            || max_ms == 0
            || max_ms > 3_600_000
            || bytes > 16 * 1024 * 1024 * 1024
            || roots.iter().any(|p| {
                !p.is_absolute() || p.components().any(|c| matches!(c, Component::ParentDir))
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid output budget scope",
            ));
        }
        let mut all = states()
            .lock()
            .map_err(|_| io::Error::other("budget lock"))?;
        if all.values().any(|s| {
            roots.iter().any(|r| {
                s.roots
                    .iter()
                    .any(|old| r.starts_with(old) || old.starts_with(r))
            })
        }) {
            return Err(io::Error::other("overlapping budget scope"));
        }
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        all.insert(
            id,
            State {
                non_coverage_failure: false,
                roots,
                deadline: Instant::now() + Duration::from_millis(max_ms),
                receipt: Receipt {
                    admitted_by_kind: BTreeMap::new(),
                    admission_calls_by_kind: BTreeMap::new(),
                    schema: "kernsight.output-budget/v1",
                    limit_bytes: bytes,
                    admitted_write_bytes: 0,
                    rejected_writes: 0,
                    partial: false,
                    reason: None,
                    failure_reasons: Vec::new(),
                },
            },
        );
        Ok(Self(id))
    }
    ///
    /// # Panics
    /// Panics if an internal invariant checked by `expect` or `unwrap` is violated.
    /// Receipt retained by this evidence operation.
    #[must_use]
    pub fn receipt(&self) -> Receipt {
        states()
            .lock()
            .unwrap()
            .get(&self.0)
            .unwrap()
            .receipt
            .clone()
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        if let Ok(mut s) = states().lock() {
            s.remove(&self.0);
        }
    }
}
fn write_kind(path: &Path) -> &'static str {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if name.starts_with(".pending-") {
        "spool_batch"
    } else if name.starts_with(".manifest-") {
        "spool_manifest"
    } else if name.starts_with("raw-bytes.json") || name == "raw-ledger.json" {
        "raw_evidence"
    } else if name.starts_with("bound-")
        || path.components().any(|p| {
            matches!(
                p.as_os_str().to_str(),
                Some("code-objects" | "code-evidence")
            )
        })
    {
        "code_evidence"
    } else {
        "other"
    }
}
///
/// # Errors
/// Returns the validation or required operation error; no successful result is fabricated.
/// Charge retained by this evidence operation.
pub fn charge(path: &Path, n: u64) -> io::Result<()> {
    // Admission checks the child first, without spending or exhausting the parent.
    let mut scopes = static_scopes()
        .lock()
        .map_err(|_| io::Error::other("static scope lock"))?;
    for scope in scopes
        .values()
        .filter(|s| path.starts_with(&s.root) && s.reserved_report.as_deref() != Some(path))
    {
        if n > scope.limit.saturating_sub(scope.spent) {
            return Err(io::Error::other("static_output_budget_exhausted"));
        }
    }
    let mut all = states()
        .lock()
        .map_err(|_| io::Error::other("budget lock"))?;
    for s in all
        .values_mut()
        .filter(|s| s.roots.iter().any(|r| path.starts_with(r)))
    {
        let unsafe_path = path.components().any(|c| matches!(c, Component::ParentDir))
            || path
                .ancestors()
                .filter(|p| s.roots.iter().any(|r| p.starts_with(r)))
                .any(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()));
        let reason = if unsafe_path {
            Some("output_path_escape")
        } else if Instant::now() >= s.deadline {
            Some("time_budget_exhausted")
        } else if n > s
            .receipt
            .limit_bytes
            .saturating_sub(s.receipt.admitted_write_bytes)
        {
            Some("output_budget_exhausted")
        } else {
            None
        };
        let reason = reason.map(str::to_owned);
        if let Some(reason) = reason {
            note_failure(s, &reason);
            s.receipt.rejected_writes = s.receipt.rejected_writes.saturating_add(1);
            return Err(io::Error::other(reason));
        }
        s.receipt.admitted_write_bytes += n;
        let kind = write_kind(path);
        *s.receipt.admitted_by_kind.entry(kind).or_default() += n;
        *s.receipt.admission_calls_by_kind.entry(kind).or_default() += 1;
    }
    for scope in scopes
        .values_mut()
        .filter(|s| path.starts_with(&s.root) && s.reserved_report.as_deref() != Some(path))
    {
        scope.spent = scope.spent.saturating_add(n);
    }
    Ok(())
}
/// Remaining admitted-write allowance for the registered output scope, not disk free space.
#[must_use]
pub fn remaining(path: &Path) -> Option<u64> {
    states()
        .lock()
        .ok()?
        .values()
        .find(|s| s.roots.iter().any(|r| path.starts_with(r)))
        .map(|s| {
            s.receipt
                .limit_bytes
                .saturating_sub(s.receipt.admitted_write_bytes)
        })
}

/// First recorded stop reason for this registered output scope.
#[must_use]
pub fn stop_reason(path: &Path) -> Option<String> {
    states()
        .lock()
        .ok()?
        .values()
        .find(|s| s.roots.iter().any(|r| path.starts_with(r)))?
        .receipt
        .reason
        .clone()
}

/// Cooperatively stop this registered output scope without signalling any process.
pub fn interrupt(path: &Path, reason: &str) {
    if let Ok(mut all) = states().lock() {
        for s in all
            .values_mut()
            .filter(|s| s.roots.iter().any(|r| path.starts_with(r)))
        {
            s.deadline = Instant::now();
            note_failure(s, reason);
        }
    }
}
/// Record failure retained by this evidence operation.
pub fn record_failure(path: &Path, reason: &str) {
    if let Ok(mut all) = states().lock() {
        for s in all
            .values_mut()
            .filter(|s| s.roots.iter().any(|r| path.starts_with(r)))
        {
            note_failure(s, reason);
        }
    }
}
///
/// # Errors
/// Returns the validation or required operation error; no successful result is fabricated.
/// Write retained by this evidence operation.
pub fn write(path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) -> io::Result<()> {
    let path = path.as_ref();
    let b = bytes.as_ref();
    charge(path, b.len() as u64)?;
    let result = std::fs::write(path, b);
    if result.is_err() {
        record_failure(path, "output_io_failed");
    }
    result
}
/// Budget File retained by this evidence operation.
pub struct BudgetFile {
    file: File,
    path: PathBuf,
}
impl BudgetFile {
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    /// Create retained by this evidence operation.
    pub fn create(path: impl AsRef<Path>) -> io::Result<Self> {
        let p = path.as_ref();
        charge(p, 0)?;
        Ok(Self {
            file: File::create(p).inspect_err(|_| record_failure(p, "output_open_failed"))?,
            path: p.to_owned(),
        })
    }
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    /// Sync all retained by this evidence operation.
    pub fn sync_all(&self) -> io::Result<()> {
        self.file.sync_all()
    }
}
impl Write for BudgetFile {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        charge(&self.path, b.len() as u64)?;
        let result = self.file.write(b);
        if result.is_err() {
            record_failure(&self.path, "output_io_failed");
        }
        result
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
///
/// # Errors
/// Returns the validation or required operation error; no successful result is fabricated.
/// Copy retained by this evidence operation.
pub fn copy(src: impl AsRef<Path>, dest: impl AsRef<Path>) -> io::Result<u64> {
    if !states()
        .lock()
        .map_err(|_| io::Error::other("budget lock"))?
        .values()
        .any(|s| s.roots.iter().any(|r| dest.as_ref().starts_with(r)))
    {
        return std::fs::copy(src, dest);
    }
    let mut src = File::open(src)?;
    let mut dest = BudgetFile::create(dest)?;
    io::copy(&mut src, &mut dest)
}
///
/// # Errors
/// Returns the validation or required operation error; no successful result is fabricated.
/// Write open retained by this evidence operation.
pub fn write_open(path: &Path, options: &OpenOptions, bytes: &[u8]) -> io::Result<()> {
    charge(path, bytes.len() as u64)?;
    let mut f = options.open(path)?;
    f.write_all(bytes)
}
impl std::io::Seek for BudgetFile {
    fn seek(&mut self, p: std::io::SeekFrom) -> io::Result<u64> {
        std::io::Seek::seek(&mut self.file, p)
    }
}

/// Clip all scanner rounds to the same invocation deadline.
#[must_use]
pub fn deadline(path: &Path, desired: Instant) -> Instant {
    if let Ok(all) = states().lock() {
        all.values()
            .filter(|s| s.roots.iter().any(|r| path.starts_with(r)))
            .fold(desired, |d, s| d.min(s.deadline))
    } else {
        Instant::now()
    }
}

/// Stop admission and the capture loop on exhaustion or a failed output.
#[must_use]
pub fn should_stop(path: &Path) -> bool {
    // Explicit static scope only; runtime roots retain the stop-on-partial rule.
    let static_only = static_scopes().lock().is_ok_and(|scopes| {
        scopes.values().any(|s| {
            s.allow_bound_coverage
                && path.starts_with(&s.root)
                && !path.starts_with(s.root.join("runtime"))
        })
    });
    if let Ok(mut all) = states().lock() {
        for s in all
            .values_mut()
            .filter(|s| s.roots.iter().any(|r| path.starts_with(r)))
        {
            let exhausted = Instant::now() >= s.deadline
                || s.receipt.admitted_write_bytes >= s.receipt.limit_bytes;
            if exhausted {
                note_failure(
                    s,
                    if Instant::now() >= s.deadline {
                        "time_budget_exhausted"
                    } else {
                        "output_budget_exhausted"
                    },
                );
            }
            let coverage_only = !s.non_coverage_failure
                && s.receipt.reason.as_deref() == Some("bound_code_copy_partial");
            if s.receipt.partial && !(static_only && coverage_only && !exhausted) {
                return true;
            }
        }
    }
    false
}

/// True only for a bound-copy coverage gap with no other recorded failure.
#[must_use]
pub fn bound_coverage_only(path: &Path) -> bool {
    states().lock().is_ok_and(|all| {
        all.values().any(|s| {
            s.roots.iter().any(|r| path.starts_with(r))
                && !s.non_coverage_failure
                && Instant::now() < s.deadline
                && s.receipt.admitted_write_bytes < s.receipt.limit_bytes
                && s.receipt.reason.as_deref() == Some("bound_code_copy_partial")
                && s.receipt.rejected_writes == 0
        })
    })
}

#[cfg(test)]
mod static_tests {
    use super::*;
    #[test]
    fn independent_static_scope_keeps_coverage_partial_and_original_hard_limits() {
        let root = std::env::temp_dir().join(format!("ksight-static-gap-{}", uuid::Uuid::new_v4()));
        let parent = Guard::install(vec![root.clone()], 100, 30000).unwrap();
        charge(&root.join("runtime"), 20).unwrap();
        record_failure(&root, "bound_code_copy_partial");
        assert!(should_stop(&root));
        let child = StaticScope::install_after_bound_copy(root.clone(), 60, 30).unwrap();
        assert!(!should_stop(&root));
        assert!(should_stop(&root.join("runtime"))); // No renewed memory reads.
        charge(&root.join("apk-reference.json"), 50).unwrap();
        assert!(charge(&root.join("apk-reference.json"), 1).is_err());
        assert!(!should_stop(&root)); // Child allowance is independent of parent exhaustion.
        assert!(parent.receipt().partial);
        assert_eq!(
            parent.receipt().reason.as_deref(),
            Some("bound_code_copy_partial")
        );
        assert_eq!(parent.receipt().admitted_write_bytes, 70);
        interrupt(&root, "cancelled");
        assert!(should_stop(&root));
        assert!(parent
            .receipt()
            .failure_reasons
            .contains(&"cancelled".into()));
        assert!(parent
            .receipt()
            .failure_reasons
            .contains(&"bound_code_copy_partial".into()));
        assert!(charge(&root.join("apk-reference.json"), 0).is_err());
        drop(child);
    }
    #[test]
    fn static_exception_stops_when_the_original_write_allowance_is_spent() {
        let root =
            std::env::temp_dir().join(format!("ksight-static-full-{}", uuid::Uuid::new_v4()));
        let parent = Guard::install(vec![root.clone()], 100, 30000).unwrap();
        charge(&root.join("runtime"), 20).unwrap();
        record_failure(&root, "bound_code_copy_partial");
        let child = StaticScope::install_after_bound_copy(root.clone(), 100, 0).unwrap();
        charge(&root.join("static"), 80).unwrap();
        assert!(should_stop(&root));
        assert!(!bound_coverage_only(&root));
        assert!(charge(&root.join("static"), 1).is_err());
        assert!(parent
            .receipt()
            .failure_reasons
            .contains(&"output_budget_exhausted".into()));
        assert!(parent
            .receipt()
            .failure_reasons
            .contains(&"bound_code_copy_partial".into()));
        drop(child);
    }
    #[test]
    fn static_scope_cannot_bypass_unsafe_source_or_expired_parent() {
        for unsafe_stop in [false, true] {
            let root =
                std::env::temp_dir().join(format!("ksight-static-unsafe-{}", uuid::Uuid::new_v4()));
            let parent = Guard::install(vec![root.clone()], 100, 30000).unwrap();
            record_failure(&root, "bound_code_copy_partial");
            let child = StaticScope::install_after_bound_copy(root.clone(), 60, 30).unwrap();
            if unsafe_stop {
                record_failure(&root, "source_identity_invalidated");
            } else {
                states()
                    .lock()
                    .unwrap()
                    .get_mut(&parent.0)
                    .unwrap()
                    .deadline = Instant::now();
            }
            assert!(should_stop(&root));
            assert!(!bound_coverage_only(&root));
            drop(child);
        }
    }
    #[test]
    fn static_rejection_preserves_parent_report_allowance() {
        let root = std::env::temp_dir().join(format!("ksight-static-{}", uuid::Uuid::new_v4()));
        let parent = Guard::install(vec![root.clone()], 100, 30000).unwrap();
        charge(&root.join("runtime"), 20).unwrap();
        let child = StaticScope::install(root.clone(), 60, 30).unwrap();
        charge(&root.join("lib"), 50).unwrap();
        assert!(charge(&root.join("lib"), 1).is_err());
        assert_eq!(parent.receipt().admitted_write_bytes, 70);
        assert!(!parent.receipt().partial);
        drop(child);
        charge(&root.join("dump-report.json"), 30).unwrap();
        assert_eq!(parent.receipt().admitted_write_bytes, 100);
    }
}
