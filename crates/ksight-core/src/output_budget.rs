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
}
struct State {
    roots: Vec<PathBuf>,
    deadline: Instant,
    receipt: Receipt,
}
static STATES: OnceLock<Mutex<BTreeMap<u64, State>>> = OnceLock::new();
static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
fn states() -> &'static Mutex<BTreeMap<u64, State>> {
    STATES.get_or_init(|| Mutex::new(BTreeMap::new()))
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
                },
            },
        );
        Ok(Self(id))
    }
    ///
    /// # Panics
    /// Panics if an internal invariant checked by `expect` or `unwrap` is violated.
    /// Receipt retained by this evidence operation.
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
            Some(
                s.receipt
                    .reason
                    .as_deref()
                    .unwrap_or("time_budget_exhausted"),
            )
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
            s.receipt.partial = true;
            s.receipt.reason = Some(reason.clone());
            s.receipt.rejected_writes = s.receipt.rejected_writes.saturating_add(1);
            return Err(io::Error::other(reason));
        }
        s.receipt.admitted_write_bytes += n;
        let kind = write_kind(path);
        *s.receipt.admitted_by_kind.entry(kind).or_default() += n;
        *s.receipt.admission_calls_by_kind.entry(kind).or_default() += 1;
    }
    Ok(())
}
/// Remaining admitted-write allowance for the registered output scope, not disk free space.
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
            s.receipt.partial = true;
            if s.receipt.reason.is_none() {
                s.receipt.reason = Some(reason.to_owned());
            }
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
            s.receipt.partial = true;
            if s.receipt.reason.is_none() {
                s.receipt.reason = Some(reason.into());
            }
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
pub fn should_stop(path: &Path) -> bool {
    if let Ok(mut all) = states().lock() {
        for s in all
            .values_mut()
            .filter(|s| s.roots.iter().any(|r| path.starts_with(r)))
        {
            if (Instant::now() >= s.deadline
                || s.receipt.admitted_write_bytes >= s.receipt.limit_bytes)
                && !s.receipt.partial
            {
                s.receipt.partial = true;
                s.receipt.reason = Some(
                    if Instant::now() >= s.deadline {
                        "time_budget_exhausted"
                    } else {
                        "output_budget_exhausted"
                    }
                    .into(),
                );
            }
            if s.receipt.partial {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aggregate_charge_classes_reconcile_replacements_without_payload_paths() {
        let root = std::env::temp_dir().join(format!("budget-kinds-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let g = Guard::install(vec![root.clone()], 20, 1000).unwrap();
        charge(&root.join(".pending-private-name.tmp"), 7).unwrap();
        charge(&root.join(".manifest-first.tmp"), 4).unwrap();
        charge(&root.join(".manifest-second.tmp"), 4).unwrap();
        charge(&root.join("raw-ledger.json"), 3).unwrap();
        assert!(charge(&root.join(".pending-rejected.tmp"), 3).is_err());
        let r = g.receipt();
        assert_eq!(r.admitted_write_bytes, 18);
        assert_eq!(r.admitted_by_kind.values().sum::<u64>(), 18);
        assert_eq!(r.admitted_by_kind["spool_manifest"], 8);
        assert_eq!(r.admission_calls_by_kind["spool_manifest"], 2);
        assert_eq!(r.rejected_writes, 1);
        assert!(r.partial);
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("private-name"));
    }
    #[test]
    fn zero_budget_terminal_and_shared_threads() {
        let root = std::env::temp_dir().join(format!("budget-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let g = Guard::install(vec![root.clone()], 3, 1000).unwrap();
        write(root.join("apk"), b"abc").unwrap();
        assert!(write(root.join("phase"), b"x").is_err());
        assert!(std::thread::spawn({
            let root = root.clone();
            move || write(root.join("tail"), b"x")
        })
        .join()
        .unwrap()
        .is_err());
        assert_eq!(g.receipt().admitted_write_bytes, 3);
        assert!(g.receipt().partial);
        std::fs::write(
            root.join("terminal.json"),
            serde_json::to_vec(&g.receipt()).unwrap(),
        )
        .unwrap();
        assert!(root.join("terminal.json").exists());
        drop(g);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn independent_roots_and_untouched_legacy() {
        let a = std::env::temp_dir().join(format!("a-{}", uuid::Uuid::new_v4()));
        let b = std::env::temp_dir().join(format!("b-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&a).unwrap();
        std::fs::create_dir(&b).unwrap();
        let ga = Guard::install(vec![a.clone()], 0, 1000).unwrap();
        let gb = Guard::install(vec![b.clone()], 3, 1000).unwrap();
        assert!(write(a.join("no"), b"x").is_err());
        write(b.join("yes"), b"xxx").unwrap();
        assert_eq!(ga.receipt().admitted_write_bytes, 0);
        assert_eq!(gb.receipt().admitted_write_bytes, 3);
        drop((ga, gb));
        std::fs::remove_dir_all(a).unwrap();
        std::fs::remove_dir_all(b).unwrap();
    }
}
