#![cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
//! Keep the physical task mark through sampler grant insertion. No map pin or
//! map sharing with Aya is required: the metadata map remains separately owned.
use crate::instance_scope::InstanceIdentity;
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
    /// Kept after qualification so a later read can snapshot `self_exec_id`.
    /// Dropping it leaves the task-storage token unchanged across exec.
    program: OwnedFd,
    btf: OwnedFd,
    token: Token,
    identity: InstanceIdentity,
    deadline: std::time::Instant,
}
impl MetadataLease {
    pub(crate) fn new(
        map: OwnedFd,
        program: OwnedFd,
        btf: OwnedFd,
        token: Token,
        identity: InstanceIdentity,
    ) -> Self {
        Self {
            map,
            program,
            btf,
            token,
            identity,
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
            program: self.program.try_clone()?,
            btf: self.btf.try_clone()?,
            token: self.token,
            identity: self.identity,
            deadline: self.deadline,
        })
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) fn check(&self, pidfd: std::os::fd::BorrowedFd<'_>) -> Result<()> {
        validate_use(LeaseUse::Admission, self.admission_valid(), || {
            self.observe_task_mark(pidfd)
        })
    }

    /// Compare the kernel task mark on this pidfd. The sampler admission
    /// deadline does not apply: a long read still has to see exec, exit, and
    /// retarget. Lookup does not mint a replacement grant.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) fn task_mark_matches(&self, pidfd: std::os::fd::BorrowedFd<'_>) -> Result<()> {
        validate_use(LeaseUse::Live, self.admission_valid(), || {
            self.observe_task_mark(pidfd)
        })
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn observe_task_mark(&self, pidfd: std::os::fd::BorrowedFd<'_>) -> Result<()> {
        use anyhow::{bail, Context};
        use std::os::fd::{AsFd, AsRawFd};
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
        // The stored grant is not rewritten on exec. Read the iterator again and
        // compare the live identity. An empty emission is a failed observation.
        let live = crate::metadata_observer::read_granted_record(self.program.as_fd(), pidfd)
            .context("live metadata observation failed")?;
        crate::metadata_scope::accept_live_identity(
            &self.identity,
            self.token.nonce,
            self.token.round,
            &live,
        )?;
        if !crate::task_storage::alive(pidfd)? {
            bail!("qualified task exited during live metadata check");
        }
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum LeaseUse {
    Admission,
    Live,
}

// Shared decision boundary for admission versus an already-bound live source.
// Live use still executes the full token/identity/pidfd check; it never issues
// a grant, extends a deadline, or permits a new sampler binding.
fn validate_use(
    purpose: LeaseUse,
    admission_valid: bool,
    observe: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if matches!(purpose, LeaseUse::Admission) && !admission_valid {
        anyhow::bail!("metadata lease expired before sampler binding");
    }
    observe()
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

#[cfg(test)]
mod retained_lease_regressions {
    use super::{InstanceIdentity, MetadataLease, Token};
    use std::{
        fs::File,
        os::fd::AsFd,
        time::{Duration, Instant},
    };

    #[test]
    fn clone_keeps_all_owned_resources_without_renewing_admission() {
        let deadline = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("past instant");
        let lease = MetadataLease::new(
            File::open("/dev/null").expect("map stand-in").into(),
            File::open("/dev/null").expect("program stand-in").into(),
            File::open("/dev/null").expect("BTF stand-in").into(),
            Token {
                nonce: 19,
                round: 2,
            },
            InstanceIdentity {
                tgid: 7,
                uid: 10_001,
                birth_ns: 123,
                exec_id: 2,
            },
        )
        .with_deadline(deadline);
        let clone = lease.try_clone().expect("clone");
        drop(lease);
        // Duplication here exercises ownership only, not a BPF task-storage claim.
        assert!(clone.map.as_fd().try_clone_to_owned().is_ok());
        assert!(clone.program.as_fd().try_clone_to_owned().is_ok());
        assert!(clone.btf.as_fd().try_clone_to_owned().is_ok());
        assert_eq!(clone.deadline, deadline);
        assert!(!clone.admission_valid());
    }
}

#[cfg(test)]
mod live_use_regressions {
    use super::{validate_use, LeaseUse};
    use crate::{
        instance_scope::InstanceIdentity,
        metadata_scope::{accept_live_identity, live_metadata_record},
    };
    use std::cell::Cell;

    fn identity() -> InstanceIdentity {
        InstanceIdentity {
            tgid: 7,
            uid: 10_001,
            birth_ns: 123,
            exec_id: 4,
        }
    }

    #[test]
    fn expired_admission_still_blocks_new_bind_but_not_live_identity_observation() {
        let source = identity();
        let record = live_metadata_record(&source, 19, 2);
        let calls = Cell::new(0);
        let check = || {
            calls.set(calls.get() + 1);
            accept_live_identity(&source, 19, 2, &record)
        };
        let error = validate_use(LeaseUse::Admission, false, check).expect_err("expired admission");
        assert!(error.to_string().contains("expired before sampler binding"));
        assert_eq!(calls.get(), 0);
        validate_use(LeaseUse::Live, false, check).expect("same live task after admission window");
        assert_eq!(calls.get(), 1);
        // Live observation did not renew the admission window.
        assert!(validate_use(LeaseUse::Admission, false, check).is_err());
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn live_checks_after_admission_expiry_still_reject_exec_token_and_empty_records() {
        let source = identity();
        let mut replaced = source;
        replaced.exec_id += 1;
        for record in [
            live_metadata_record(&replaced, 19, 2).to_vec(),
            live_metadata_record(&source, 20, 2).to_vec(),
            Vec::new(),
        ] {
            assert!(validate_use(LeaseUse::Live, false, || accept_live_identity(
                &source, 19, 2, &record
            ))
            .is_err());
        }
    }

    #[test]
    fn live_exit_and_observer_errors_are_preserved_in_both_time_states() {
        for still_admissible in [false, true] {
            for reason in ["qualified task exited", "metadata iterator denied"] {
                let error = validate_use(LeaseUse::Live, still_admissible, || {
                    anyhow::bail!("{reason}")
                })
                .expect_err("live observation failure");
                assert_eq!(error.to_string(), reason);
            }
        }
    }
}
