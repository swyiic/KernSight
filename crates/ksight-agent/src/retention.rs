//! Global spool retention, interrupted-session repair, and last-exit records.

use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use ksight_protocol::{DurableSessionState, LastExit};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::spool::{inspect_root, mark_session_state, SpoolError};

const COLLECTOR_LEASE_FILE: &str = ".collector-lease.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CollectorLeaseDocument {
    pid: u32,
    process_start_ticks: u64,
    boot_id: String,
    token: Uuid,
}

/// Exclusive ownership of one spool root.
///
/// Foreground and detached collectors share this lease, preventing a second
/// capture from repairing or pruning a session that is still being written.
#[derive(Debug)]
pub struct SpoolLease {
    path: PathBuf,
    token: Uuid,
}

impl SpoolLease {
    /// Acquire a root-wide collector lease, recovering it only when the exact
    /// PID/start-time/boot tuple is no longer alive.
    ///
    /// # Errors
    ///
    /// Returns when another live collector owns the root or lease I/O fails.
    pub fn acquire(root: impl AsRef<Path>) -> Result<Self, RetentionError> {
        let root = root.as_ref();
        fs::create_dir_all(root)?;
        let path = root.join(COLLECTOR_LEASE_FILE);
        for _ in 0..2 {
            let token = Uuid::new_v4();
            let document = CollectorLeaseDocument {
                pid: std::process::id(),
                process_start_ticks: process_start_ticks(std::process::id()).unwrap_or(0),
                boot_id: boot_id().unwrap_or_default(),
                token,
            };
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    file.write_all(&serde_json::to_vec(&document)?)?;
                    file.sync_all()?;
                    return Ok(Self { path, token });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let active = fs::read(&path)
                        .ok()
                        .and_then(|bytes| {
                            serde_json::from_slice::<CollectorLeaseDocument>(&bytes).ok()
                        })
                        .is_some_and(|owner| lease_owner_alive(&owner));
                    if active {
                        return Err(RetentionError::ActiveCollector(path));
                    }
                    match fs::remove_file(&path) {
                        Ok(()) => {}
                        Err(remove) if remove.kind() == std::io::ErrorKind::NotFound => {}
                        Err(remove) => return Err(remove.into()),
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(RetentionError::ActiveCollector(path))
    }
}

impl Drop for SpoolLease {
    fn drop(&mut self) {
        let owned = fs::read(&self.path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<CollectorLeaseDocument>(&bytes).ok())
            .is_some_and(|document| document.token == self.token);
        if owned {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Root-wide durable storage policy.
#[derive(Debug, Clone)]
pub struct SpoolRetention {
    /// Directory containing UUID session folders.
    pub root: PathBuf,
    /// Maximum complete-batch bytes across all sessions; zero disables the global bound.
    pub max_total_bytes: u64,
    /// Complete sessions to keep after pruning, newest first.
    pub keep_completed: u32,
}

/// Why a collector process stopped writing.
#[derive(Debug, Clone)]
pub struct ExitRecord {
    /// Active session at exit.
    pub session_id: Option<Uuid>,
    /// Stable classification written to `last_exit.json`.
    pub reason: String,
    /// Operator-facing diagnostic.
    pub detail: Option<String>,
    /// True when a completion event was sealed.
    pub clean: bool,
}

impl SpoolRetention {
    /// Mark `running` sessions without a live collector as interrupted.
    ///
    /// # Errors
    ///
    /// Returns an error when a recognized session cannot be updated.
    pub fn repair_interrupted(&self) -> Result<u32, RetentionError> {
        if !self.root.exists() {
            return Ok(0);
        }
        let mut repaired = 0_u32;
        for summary in inspect_root(&self.root)? {
            if summary.state != DurableSessionState::Running {
                continue;
            }
            mark_session_state(
                self.root.join(summary.session_id.to_string()),
                DurableSessionState::Interrupted,
                None,
            )?;
            repaired = repaired.saturating_add(1);
        }
        Ok(repaired)
    }

    /// Bytes currently occupied by complete batches under the root.
    ///
    /// # Errors
    ///
    /// Returns an error when inventory cannot be read.
    pub fn used_bytes(&self) -> Result<u64, RetentionError> {
        inspect_root(&self.root)?
            .iter()
            .try_fold(0_u64, |total, summary| {
                total
                    .checked_add(summary.used_bytes)
                    .ok_or(RetentionError::Overflow)
            })
    }

    /// Delete oldest sealed sessions until the global bound and keep-count are satisfied.
    ///
    /// Running sessions are never deleted. Returns bytes freed.
    ///
    /// # Errors
    ///
    /// Returns an error when inventory or deletion fails.
    pub fn prune(&self) -> Result<u64, RetentionError> {
        let mut sessions = inspect_root(&self.root)?;
        sessions.sort_by_key(|summary| summary.started_unix_ms.unwrap_or(0));
        let mut used = sessions.iter().try_fold(0_u64, |total, summary| {
            total
                .checked_add(summary.used_bytes)
                .ok_or(RetentionError::Overflow)
        })?;
        let mut freed = 0_u64;
        let keep = usize::try_from(self.keep_completed).unwrap_or(usize::MAX);
        loop {
            let sealed: Vec<_> = sessions
                .iter()
                .filter(|summary| summary.state != DurableSessionState::Running)
                .cloned()
                .collect();
            if sealed_is_within_policy(&sealed, used, self.max_total_bytes, keep) {
                break;
            }
            let Some(victim) = sealed_oldest(&sessions) else {
                break;
            };
            let directory = self.root.join(victim.session_id.to_string());
            let size = victim.used_bytes;
            match fs::remove_dir_all(&directory) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            sessions.retain(|summary| summary.session_id != victim.session_id);
            used = used.saturating_sub(size);
            freed = freed.saturating_add(size);
        }
        Ok(freed)
    }

    /// Whether a new session may be opened without exceeding the global bound.
    ///
    /// # Errors
    ///
    /// Returns an error when inventory cannot be read.
    pub fn can_open_session(&self) -> Result<bool, RetentionError> {
        if self.max_total_bytes == 0 {
            return Ok(true);
        }
        Ok(self.used_bytes()? < self.max_total_bytes)
    }

    /// Persist `last_exit.json` under the spool root.
    ///
    /// # Errors
    ///
    /// Returns an error when the document cannot be written.
    pub fn write_last_exit(&self, record: &ExitRecord) -> Result<(), RetentionError> {
        fs::create_dir_all(&self.root)?;
        let document = LastExit {
            written_unix_ms: unix_ms(),
            pid: std::process::id(),
            session_id: record.session_id,
            reason: record.reason.clone(),
            detail: record.detail.clone(),
            clean: record.clean,
        };
        let path = self.root.join("last_exit.json");
        let temporary = self.root.join(format!(".last_exit-{}.tmp", Uuid::new_v4()));
        fs::write(&temporary, serde_json::to_vec_pretty(&document)?)?;
        fs::rename(&temporary, path)?;
        Ok(())
    }

    /// Load the latest last-exit document, if present.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed document.
    pub fn read_last_exit(&self) -> Result<Option<LastExit>, RetentionError> {
        let path = self.root.join("last_exit.json");
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

fn sealed_is_within_policy(
    sealed: &[ksight_protocol::DurableSessionSummary],
    used: u64,
    max_total_bytes: u64,
    keep: usize,
) -> bool {
    let over_keep = sealed.len() > keep;
    let over_bytes = max_total_bytes != 0 && used > max_total_bytes;
    !over_keep && !over_bytes
}

fn sealed_oldest(
    sessions: &[ksight_protocol::DurableSessionSummary],
) -> Option<ksight_protocol::DurableSessionSummary> {
    sessions
        .iter()
        .filter(|summary| summary.state != DurableSessionState::Running)
        .min_by_key(|summary| summary.started_unix_ms.unwrap_or(0))
        .cloned()
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Retention failure.
#[derive(Debug, Error)]
pub enum RetentionError {
    /// Underlying spool I/O or validation failed.
    #[error(transparent)]
    Spool(#[from] SpoolError),
    /// Filesystem operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// JSON encoding failed.
    #[error(transparent)]
    Encode(#[from] serde_json::Error),
    /// Byte accounting overflowed.
    #[error("spool byte accounting overflow")]
    Overflow,
    /// Another exact collector process owns the spool root.
    #[error("another collector owns spool root lease {0}")]
    ActiveCollector(PathBuf),
}

fn lease_owner_alive(owner: &CollectorLeaseDocument) -> bool {
    match (boot_id(), process_start_ticks(owner.pid)) {
        (Some(current_boot), Some(current_start)) => {
            current_boot == owner.boot_id && current_start == owner.process_start_ticks
        }
        // Host-side tests and non-procfs development platforms cannot provide
        // the Android identity tuple. Fall back to a non-signalling liveness
        // check only when both recorded identity fields were unavailable.
        _ if owner.boot_id.is_empty() && owner.process_start_ticks == 0 => {
            process_is_alive(owner.pid)
        }
        _ => false,
    }
}

fn process_is_alive(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    match nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None) {
        Ok(()) | Err(nix::errno::Errno::EPERM) => true,
        Err(_) => false,
    }
}

fn boot_id() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|value| value.trim().to_owned())
}

fn process_start_ticks(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spool_lease_is_exclusive_and_released() {
        let root = std::env::temp_dir().join(format!("ksight-spool-lease-{}", Uuid::new_v4()));
        let lease = SpoolLease::acquire(&root).expect("first lease");
        assert!(matches!(
            SpoolLease::acquire(&root),
            Err(RetentionError::ActiveCollector(_))
        ));
        drop(lease);
        SpoolLease::acquire(&root).expect("released lease");
        let _ = fs::remove_dir_all(root);
    }
}
