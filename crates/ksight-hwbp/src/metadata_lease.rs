#![cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
//! Keep the physical task mark through sampler grant insertion. No map pin or
//! map sharing with Aya is required: the metadata map remains separately owned.
use crate::metadata_scope::Token;
use anyhow::Result;
use std::os::fd::OwnedFd;

#[cfg(any(target_os = "linux", target_os = "android"))]
#[repr(C)]
struct TaskLookup {
    map_fd: u32,
    pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}
#[cfg(any(target_os = "linux", target_os = "android"))]
const _: () = assert!(std::mem::size_of::<TaskLookup>() == 32);
#[derive(Debug)]
pub(crate) struct MetadataLease {
    map: OwnedFd,
    token: Token,
    deadline: std::time::Instant,
}
impl MetadataLease {
    pub(crate) fn new(map: OwnedFd, token: Token) -> Self {
        Self {
            map,
            token,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(5),
        }
    }
    pub(crate) fn with_deadline(mut self, deadline: std::time::Instant) -> Self {
        self.deadline = deadline;
        self
    }
    pub(crate) fn admission_valid(&self) -> bool {
        std::time::Instant::now() < self.deadline && self.token.nonce != 0 && self.token.round == 2
    }
    pub(crate) fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            map: self.map.try_clone()?,
            token: self.token,
            deadline: self.deadline,
        })
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) fn check(&self, pidfd: std::os::fd::BorrowedFd<'_>) -> Result<()> {
        use anyhow::bail;
        if !self.admission_valid() {
            bail!("metadata lease expired before sampler binding");
        }
        self.task_mark_matches(pidfd)
    }

    /// Compare the kernel task mark on this pidfd. The sampler admission
    /// deadline does not apply: a long read still has to see exec, exit, and
    /// retarget. Lookup does not mint a replacement grant.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) fn task_mark_matches(&self, pidfd: std::os::fd::BorrowedFd<'_>) -> Result<()> {
        use anyhow::{bail, Context};
        use std::os::fd::AsRawFd;
        let key = pidfd.as_raw_fd();
        let mut token = Token { nonce: 0, round: 0 };
        let attr = TaskLookup {
            map_fd: u32::try_from(self.map.as_raw_fd()).context("metadata map descriptor")?,
            pad: 0,
            key: (&raw const key) as u64,
            value: (&raw mut token) as u64,
            flags: 0,
        };
        // SAFETY: initialized published UAPI prefix and live borrowed key/map;
        // sixteen writable token bytes. Lookup cannot mint a replacement grant.
        let rc =
            unsafe { libc::syscall(libc::SYS_bpf, 1, &attr, std::mem::size_of::<TaskLookup>()) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .context("qualification task mark absent/retargeted");
        }
        if token != self.token || token.nonce == 0 || token.round != 2 {
            bail!("qualification task mark changed");
        }
        if !crate::task_storage::alive(pidfd)? {
            bail!("qualified task exited before sampler binding");
        }
        Ok(())
    }
}
/// Used by the production sampler with its deny gate already set. A pidfd
/// retarget between precheck and insertion fails postcheck; caller revokes the
/// whole uncommitted sampler before any hook can read application memory.
pub(crate) fn guarded_bind(
    mut check: impl FnMut() -> Result<()>,
    insert: impl FnOnce() -> Result<()>,
) -> Result<()> {
    check()?;
    insert()?;
    check()?;
    Ok(())
}
