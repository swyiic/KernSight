#![cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
//! Sealed raw identity and two-observation qualification. This is a candidate
//! interface, not a kernel validation certificate or Android package attestation.
use crate::instance_scope::{BoundInstance, InstanceIdentity};
use anyhow::{bail, Result};
use std::{
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    time::{Duration, Instant},
};
pub(crate) const METADATA_ABI: u32 = 0x4b53_4d31;
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Token {
    pub nonce: u64,
    pub round: u64,
}
/// Can only be constructed by the metadata reader after its task-object nonce
/// and exact wire record match. Raw tuples supplied by a caller cannot mint it.
#[derive(Debug, Clone, Copy)]
pub struct ObservedIdentity {
    pub(crate) identity: InstanceIdentity,
    pub(crate) token: Token,
}
impl ObservedIdentity {
    pub fn identity(&self) -> InstanceIdentity {
        self.identity
    }
}
pub(crate) fn decode(bytes: &[u8], token: Token) -> Result<ObservedIdentity> {
    if bytes.len() != 48 || token.nonce == 0 || token.round == 0 {
        bail!("metadata framing/token");
    }
    let u32_at = |o| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
    let u64_at = |o| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
    if u32_at(0) != METADATA_ABI
        || u32_at(4) != 48
        || u64_at(8) != token.nonce
        || u64_at(16) != token.round
    {
        bail!("foreign/stale metadata observation");
    }
    let identity = InstanceIdentity {
        tgid: u32_at(24),
        uid: u32_at(28),
        birth_ns: u64_at(32),
        exec_id: u64_at(40),
    };
    if identity.tgid == 0 || identity.birth_ns == 0 || identity.exec_id == u64::MAX {
        bail!("invalid raw metadata");
    }
    Ok(ObservedIdentity { identity, token })
}
/// Caller-owned package enrollment decision. Its source must already be
/// qualified; matching a mutable cmdline alone is not Android attestation.
#[derive(Debug)]
pub struct QualificationPolicy {
    pub package: String,
    pub tgid: u32,
    pub uid: u32,
}
/// Policy reader's result, read BETWEEN raw observations using the SAME retained
/// handle. The issuer checks this tuple, never turns proc ticks into raw birth.
#[derive(Debug)]
pub struct PolicyWitness {
    pub package: String,
    pub tgid: u32,
    pub uid: u32,
}
#[derive(Debug)]
pub struct QualifiedInstance {
    package: String,
    bound: BoundInstance,
    deadline: Instant,
}
impl QualifiedInstance {
    pub fn package(&self) -> &str {
        &self.package
    }
    pub fn identity(&self) -> InstanceIdentity {
        self.bound.identity
    }
    pub(crate) fn attach_lease(mut self, map: OwnedFd, token: Token) -> Self {
        self.bound.metadata_lease = Some(
            crate::metadata_lease::MetadataLease::new(map, token).with_deadline(self.deadline),
        );
        self
    }
    /// Clone the same physical qualification lease; never renew its deadline.
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    pub fn try_clone(&self) -> std::io::Result<Self> {
        Ok(Self {
            package: self.package.clone(),
            bound: self.bound.try_clone()?,
            deadline: self.deadline,
        })
    }
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    pub fn into_bound(self) -> Result<BoundInstance> {
        if Instant::now() >= self.deadline {
            bail!("qualification expired before backend setup");
        }
        if self.bound.metadata_lease.is_none() {
            bail!("physical qualification lease missing");
        }
        Ok(self.bound)
    }
}
pub(crate) trait Reader {
    fn alive(&mut self, fd: BorrowedFd<'_>) -> Result<bool>;
    fn observe(&mut self, fd: BorrowedFd<'_>) -> Result<ObservedIdentity>;
}
/// No retry or lock/freeze of the target. Exec/exit/UID/birth changes, missing
/// observations and errors refuse issuance. Once setup starts, the existing
/// kernel task-storage/raw-exec gate rechecks EVERY hit before user reads.
pub(crate) fn qualify(
    reader: &mut impl Reader,
    policy: &QualificationPolicy,
    pidfd: OwnedFd,
    mut witness: impl FnMut(BorrowedFd<'_>, InstanceIdentity) -> Result<PolicyWitness>,
) -> Result<QualifiedInstance> {
    if policy.package.is_empty() || policy.tgid == 0 {
        bail!("explicit qualification policy required");
    }
    let started = Instant::now();
    if !reader.alive(pidfd.as_fd())? {
        bail!("task exited before qualification");
    }
    let before = reader.observe(pidfd.as_fd())?;
    if before.identity.tgid != policy.tgid || before.identity.uid != policy.uid {
        bail!("kernel identity does not match enrolled policy");
    }
    let result = witness(pidfd.as_fd(), before.identity)?;
    if result.package != policy.package || result.tgid != policy.tgid || result.uid != policy.uid {
        bail!("package policy witness mismatch");
    }
    let after = reader.observe(pidfd.as_fd())?;
    if before.identity != after.identity
        || before.token.nonce != after.token.nonce
        || before.token.round >= after.token.round
    {
        bail!("identity changed during policy read");
    }
    if !reader.alive(pidfd.as_fd())? {
        bail!("task exited during qualification");
    }
    // Admission deadline; it cannot interrupt a synchronous kernel read. A
    // separate bounded helper is required for a hard wall-time test window.
    if started.elapsed() > Duration::from_secs(1) {
        bail!("qualification deadline exceeded");
    }
    Ok(QualifiedInstance {
        package: policy.package.clone(),
        bound: BoundInstance::trusted_candidate(after.identity, pidfd),
        deadline: Instant::now() + Duration::from_secs(5),
    })
}
