//! Exact kernel instance gate contract. No tick-to-nanosecond conversion exists.
#[cfg(any(test, target_os = "android", target_os = "linux"))]
use anyhow::Context as _;
#[cfg(any(test, target_os = "android", target_os = "linux"))]
use anyhow::{bail, Result};
#[cfg(any(test, target_os = "android", target_os = "linux"))]
use std::os::fd::AsFd;

/// Trusted metadata from the SAME verified kernel/boot as the session.
/// `tgid` and real `uid` use the kernel's initial namespaces. `birth_ns` is
/// group-leader `start_boottime`, NOT proc stat ticks or a wall-clock estimate.
/// This type does not establish package authorization; the caller must qualify
/// the exact kernel observation against a stable process handle before use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstanceIdentity {
    pub tgid: u32,
    pub uid: u32,
    pub birth_ns: u64,
    pub exec_id: u64,
}

/// Candidate authorization input: an owned, caller-qualified group-leader pidfd
/// plus trusted raw metadata from that SAME task/kernel. Construction alone
/// proves neither package policy nor metadata provenance. The map syscall
/// validates the fd as a pidfd; no numeric PID or proc-tick fallback exists.
#[derive(Debug)]
pub struct BoundInstance {
    pub identity: InstanceIdentity,
    pub pidfd: std::os::fd::OwnedFd,
    pub(crate) metadata_lease: Option<crate::metadata_lease::MetadataLease>,
}
impl BoundInstance {
    /// Legacy low-level candidate input. This constructor does not establish
    /// kernel task-object provenance or permit strict capture.
    pub fn trusted_candidate(identity: InstanceIdentity, pidfd: std::os::fd::OwnedFd) -> Self {
        Self {
            identity,
            pidfd,
            metadata_lease: None,
        }
    }

    pub fn has_metadata_lease(&self) -> bool {
        self.metadata_lease.is_some()
    }
    /// Check current retained task and physical metadata admission before a read or scope update.
    ///
    /// # Errors
    ///
    /// Returns when the metadata lease is missing, the task mark changed, or the pidfd is no longer alive.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn check_current(&self) -> anyhow::Result<()> {
        self.metadata_lease
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("physical metadata lease missing"))?
            .check(self.pidfd.as_fd())?;
        if !crate::task_storage::alive(self.pidfd.as_fd())? {
            anyhow::bail!("qualified task exited");
        }
        Ok(())
    }
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    pub fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            identity: self.identity,
            pidfd: self.pidfd.try_clone()?,
            metadata_lease: self
                .metadata_lease
                .as_ref()
                .map(super::metadata_lease::MetadataLease::try_clone)
                .transpose()?,
        })
    }
}

#[cfg(any(test, target_os = "linux", target_os = "android"))]
pub(crate) fn require_metadata_leases(targets: &[BoundInstance]) -> Result<()> {
    if targets.iter().any(|t| {
        !t.metadata_lease
            .as_ref()
            .is_some_and(super::metadata_lease::MetadataLease::admission_valid)
    }) {
        bail!("raw pidfd/identity lacks physical metadata lease; sampler refused");
    }
    Ok(())
}

pub const INSTANCE_ABI_V1: u32 = 0x4b53_4931;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstanceStamp {
    pub identity: InstanceIdentity,
    pub epoch: u32,
    pub thread_birth_ns: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ScopeKey {
    pub tgid: u32,
    pub epoch: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AllowValue {
    pub uid: u32,
    pub epoch: u32,
    pub birth_ns: u64,
    pub exec_id: u64,
}
const _: () = assert!(std::mem::size_of::<ScopeKey>() == 8);
const _: () = assert!(std::mem::size_of::<AllowValue>() == 24);

#[cfg(any(test, target_os = "android", target_os = "linux"))]
#[derive(Debug, Default)]
pub(crate) struct ScopeState {
    pub epoch: u32,
    pub keys: Vec<ScopeKey>,
    identities: Vec<InstanceIdentity>,
    pub bindings: Vec<BoundInstance>,
}
#[cfg(any(test, target_os = "android", target_os = "linux"))]
impl ScopeState {
    pub fn accepts(&self, stamp: &InstanceStamp) -> bool {
        self.epoch != 0
            && stamp.epoch == self.epoch
            && stamp.thread_birth_ns != 0
            && self.identities.contains(&stamp.identity)
    }
}

#[cfg(any(test, target_os = "android", target_os = "linux"))]
pub(crate) trait InstanceMaps {
    fn gate(&mut self, mode: u32) -> Result<()>;
    fn epoch(&mut self, epoch: u32) -> Result<()>;
    fn remove(&mut self, key: ScopeKey) -> Result<()>;
    fn insert(&mut self, key: ScopeKey, value: AllowValue) -> Result<()>;
    fn unbind(&mut self, pidfd: std::os::fd::BorrowedFd<'_>) -> Result<()>;
    fn bind(&mut self, target: &BoundInstance, value: AllowValue) -> Result<()>;
}

/// Install before attachment, or detach owned links on ANY error. No rollback,
/// retry on the same object, numeric downgrade, epoch reuse or epoch wrap.
/// A failed first gate write cannot promise instantaneous kernel revocation.
#[cfg(any(test, target_os = "android", target_os = "linux"))]
pub(crate) fn configure(
    maps: &mut impl InstanceMaps,
    previous: &ScopeState,
    targets: &[BoundInstance],
) -> Result<ScopeState> {
    let identities: Vec<_> = targets.iter().map(|t| t.identity).collect();
    if identities.len() > 128 || identities.iter().any(|i| i.tgid == 0 || i.birth_ns == 0) {
        bail!("instance scope requires exact nonzero TGID/birth and at most 128 entries");
    }
    let mut sorted = identities.clone();
    sorted.sort_unstable_by_key(|i| i.tgid);
    if sorted.windows(2).any(|w| w[0].tgid == w[1].tgid) {
        bail!("ambiguous duplicate TGID instance");
    }
    let epoch = previous
        .epoch
        .checked_add(1)
        .context("instance epoch exhausted")?;
    let keys: Vec<_> = sorted
        .iter()
        .map(|i| ScopeKey {
            tgid: i.tgid,
            epoch,
        })
        .collect();
    // Duplicate before any write; never store a borrowed raw fd number. Closing
    // the caller's fd cannot retarget a future transaction through fd reuse.
    let bindings: Vec<_> = targets
        .iter()
        .map(BoundInstance::try_clone)
        .collect::<std::io::Result<_>>()?;
    maps.gate(2)?;
    // Epoch is never restored. An overlapping invocation cannot pass both
    // checks after a complete deny->allow ABA update to the next generation.
    maps.epoch(epoch)?;
    for &old in &previous.keys {
        maps.remove(old)?;
    }
    for old in &previous.bindings {
        maps.unbind(old.pidfd.as_fd())?;
    }
    for (&key, identity) in keys.iter().zip(&sorted) {
        maps.insert(
            key,
            AllowValue {
                uid: identity.uid,
                epoch,
                birth_ns: identity.birth_ns,
                exec_id: identity.exec_id,
            },
        )?;
    }
    for target in &bindings {
        maps.bind(
            target,
            AllowValue {
                uid: target.identity.uid,
                epoch,
                birth_ns: target.identity.birth_ns,
                exec_id: target.identity.exec_id,
            },
        )?;
    }
    maps.gate(3)?;
    Ok(ScopeState {
        epoch,
        keys,
        identities: sorted,
        bindings,
    })
}

