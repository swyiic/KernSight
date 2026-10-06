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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instance_scope::InstanceIdentity;
    use std::collections::VecDeque;
    fn fd() -> OwnedFd {
        std::fs::File::open("/dev/null").unwrap().into()
    }
    fn policy() -> QualificationPolicy {
        QualificationPolicy {
            package: "fixture.package".into(),
            tgid: 7,
            uid: 10001,
        }
    }
    struct Mock {
        calls: Vec<&'static str>,
        fail: Option<&'static str>,
        round: u64,
        records: VecDeque<Vec<u8>>,
        live: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    impl Mock {
        fn step(&mut self, name: &'static str) -> Result<()> {
            self.calls.push(name);
            if self.fail == Some(name) {
                bail!("injected {name}");
            }
            Ok(())
        }
    }
    fn wire(round: u64) -> Vec<u8> {
        let mut b = Vec::new();
        for v in [metadata_scope::METADATA_ABI, 48] {
            b.extend(v.to_le_bytes());
        }
        for v in [19u64, round] {
            b.extend(v.to_le_bytes());
        }
        for v in [7u32, 10001] {
            b.extend(v.to_le_bytes());
        }
        for v in [12_345_678_901u64, 2] {
            b.extend(v.to_le_bytes());
        }
        b
    }
    fn mock() -> Mock {
        Mock {
            calls: Vec::new(),
            fail: None,
            round: 0,
            records: VecDeque::from([wire(1), wire(2)]),
            live: std::sync::Arc::default(),
        }
    }
    struct Tracked {
        fd: OwnedFd,
        live: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }
    impl AsFd for Tracked {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.fd.as_fd()
        }
    }
    impl Drop for Tracked {
        fn drop(&mut self) {
            self.live.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    impl Mock {
        fn handle(&mut self) -> Tracked {
            self.live.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Tracked {
                fd: fd(),
                live: self.live.clone(),
            }
        }
    }
    impl Driver for Mock {
        type Handle = Tracked;
        fn grant(&mut self, p: BorrowedFd<'_>, t: Token, existing: bool) -> Result<()> {
            assert!(p.as_raw_fd() > 0);
            assert_eq!(t.nonce, 19);
            assert_eq!(t.round, self.round + 1);
            assert_eq!(existing, self.round != 0);
            self.step(if existing { "EXIST" } else { "NOEXIST" })?;
            self.round = t.round;
            Ok(())
        }
        fn remove(&mut self, _: BorrowedFd<'_>) -> Result<()> {
            self.step("remove")
        }
        fn link(&mut self, info: [u32; 3]) -> Result<Self::Handle> {
            assert_eq!(info[0..2], [0, 0]);
            assert!(info[2] > 0);
            self.step("link")?;
            Ok(self.handle())
        }
        fn iterator(&mut self, _: BorrowedFd<'_>) -> Result<Self::Handle> {
            self.step("iterator")?;
            Ok(self.handle())
        }
        fn read(&mut self, _: Self::Handle) -> Result<Vec<u8>> {
            self.step("read")?;
            Ok(self.records.pop_front().unwrap_or_default())
        }
        fn alive(&mut self, _: BorrowedFd<'_>) -> Result<bool> {
            self.step("alive")?;
            Ok(true)
        }
    }
    #[allow(
        clippy::unnecessary_wraps,
        reason = "Local fixture or owned callback keeps its explicit scope and fallible signature."
    )]
    fn witness(_: BorrowedFd<'_>, i: InstanceIdentity) -> Result<PolicyWitness> {
        Ok(PolicyWitness {
            package: "fixture.package".into(),
            tgid: i.tgid,
            uid: i.uid,
        })
    }
    #[test]
    fn production_io_keeps_single_object_grant_across_policy_read() {
        let mut m = mock();
        let p = fd();
        let number = p.as_raw_fd();
        let q = issue(&mut m, 19, &policy(), p, |handle, i| {
            assert_eq!(handle.as_raw_fd(), number);
            witness(handle, i)
        })
        .unwrap();
        assert_eq!(q.identity().birth_ns, 12_345_678_901);
        assert_eq!(
            m.calls,
            [
                "alive", "NOEXIST", "link", "iterator", "read", "alive", "EXIST", "link",
                "iterator", "read", "alive", "alive"
            ]
        );
        assert_eq!(m.live.load(std::sync::atomic::Ordering::SeqCst), 0);
        let q = q.attach_lease(
            fd(),
            Token {
                nonce: 19,
                round: 2,
            },
        );
        assert_eq!(q.into_bound().unwrap().pidfd.as_raw_fd(), number);
    }
    #[test]
    fn production_io_refuses_retarget_and_cleans_each_failure_without_retry() {
        for name in [
            "alive", "NOEXIST", "EXIST", "link", "iterator", "read", "remove",
        ] {
            let mut m = mock();
            m.fail = Some(name);
            assert!(
                (if name == "remove" {
                    issue(&mut m, 19, &policy(), fd(), |_, _| {
                        anyhow::bail!("policy error")
                    })
                } else {
                    issue(&mut m, 19, &policy(), fd(), witness)
                })
                .is_err(),
                "{name}"
            );
            assert!(m.calls.iter().filter(|&&v| v == name).count() <= 1);
            assert_eq!(m.live.load(std::sync::atomic::Ordering::SeqCst), 0);
            if !["alive", "NOEXIST"].contains(&name) {
                assert_eq!(m.calls.last(), Some(&"remove"));
            }
        }
    }
    #[test]
    fn production_io_rejects_missing_duplicate_truncated_stale_observations() {
        for case in 0..4 {
            let mut m = mock();
            m.records[1] = match case {
                0 => Vec::new(),
                1 => [wire(2), wire(2)].concat(),
                2 => wire(2)[..47].to_vec(),
                _ => wire(1),
            };
            assert!(issue(&mut m, 19, &policy(), fd(), witness).is_err());
            assert_eq!(m.calls.last(), Some(&"remove"));
        }
    }
    #[test]
    fn zero_pidfd_never_expands_iterator_to_all_tasks() {
        assert!(task_filter(0).is_err());
        assert!(task_filter(-1).is_err());
        assert_eq!(task_filter(12).unwrap(), [0, 0, 12]);
    }
}
