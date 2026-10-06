//! Production iterator lifecycle shared by the raw syscall driver and tests.
//! Keep one task-storage grant across both observations. An EXIST update on the
//! second observation cannot authorize a replacement task after pidfd retarget.
use crate::metadata_scope::{
    self, ObservedIdentity, PolicyWitness, QualificationPolicy, QualifiedInstance, Reader, Token,
};
use anyhow::{bail, Result};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

pub(crate) trait Driver {
    type Handle: AsFd;
    fn grant(&mut self, pidfd: BorrowedFd<'_>, token: Token, existing: bool) -> Result<()>;
    fn remove(&mut self, pidfd: BorrowedFd<'_>) -> Result<()>;
    fn link(&mut self, info: [u32; 3]) -> Result<Self::Handle>;
    fn iterator(&mut self, link: BorrowedFd<'_>) -> Result<Self::Handle>;
    fn read(&mut self, iterator: Self::Handle) -> Result<Vec<u8>>;
    fn alive(&mut self, pidfd: BorrowedFd<'_>) -> Result<bool>;
}
fn task_filter(fd: i32) -> Result<[u32; 3]> {
    // pid_fd == 0 means ALL tasks in Linux UAPI. Never use that fallback.
    if fd <= 0 {
        bail!("positive retained pidfd required; all-task iteration forbidden");
    }
    Ok([0, 0, u32::try_from(fd)?])
}
struct Issuer<'a, D> {
    driver: &'a mut D,
    nonce: u64,
    round: u64,
    granted: bool,
}
impl<D: Driver> Reader for Issuer<'_, D> {
    fn alive(&mut self, pidfd: BorrowedFd<'_>) -> Result<bool> {
        self.driver.alive(pidfd)
    }
    fn observe(&mut self, pidfd: BorrowedFd<'_>) -> Result<ObservedIdentity> {
        let info = task_filter(pidfd.as_raw_fd())?;
        self.round = self
            .round
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("metadata round exhausted"))?;
        let token = Token {
            nonce: self.nonce,
            round: self.round,
        };
        self.driver.grant(pidfd, token, self.granted)?;
        self.granted = true;
        let link = self.driver.link(info)?;
        let iter = self.driver.iterator(link.as_fd())?;
        let bytes = self.driver.read(iter)?;
        let observed = metadata_scope::decode(&bytes, token)?;
        if !self.driver.alive(pidfd)? {
            bail!("task exited while reading iterator");
        }
        Ok(observed)
    }
}
/// One-use session. The driver owner drops its unpinned map/program/BTF FDs
/// on error; on success its map transfers into the sealed qualification lease.
pub(crate) fn issue(
    driver: &mut impl Driver,
    nonce: u64,
    policy: &QualificationPolicy,
    pidfd: OwnedFd,
    witness: impl FnMut(
        BorrowedFd<'_>,
        crate::instance_scope::InstanceIdentity,
    ) -> Result<PolicyWitness>,
) -> Result<QualifiedInstance> {
    if nonce == 0 {
        bail!("metadata nonce required");
    }
    // Keep a duplicate ONLY for cleanup; both observations and policy reader
    // receive the same original owned handle. Duplication preserves its object.
    task_filter(pidfd.as_raw_fd())?;
    let cleanup_fd = pidfd.try_clone()?;
    let mut issuer = Issuer {
        driver,
        nonce,
        round: 0,
        granted: false,
    };
    let result = metadata_scope::qualify(&mut issuer, policy, pidfd, witness);
    let cleanup = if issuer.granted && result.is_err() {
        issuer.driver.remove(cleanup_fd.as_fd())
    } else {
        Ok(())
    };
    match (result, cleanup) {
        (Ok(v), Ok(())) => Ok(v),
        (Err(e), Err(cleanup)) => {
            Err(e.context(format!("metadata cleanup also failed: {cleanup:#}")))
        }
        (Err(e), Ok(())) | (Ok(_), Err(e)) => Err(e),
    }
}
