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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn target(identity: InstanceIdentity) -> BoundInstance {
        // Offline stand-in only; production kernel rejects non-pidfd handles.
        BoundInstance {
            identity,
            pidfd: std::fs::File::open("/dev/null").unwrap().into(),
            metadata_lease: None,
        }
    }
    #[test]
    fn sampler_admission_refuses_unsealed_raw_identity_before_external_actions() {
        assert!(require_metadata_leases(&[target(identity(123))]).is_err());
        assert!(require_metadata_leases(&[]).is_ok());
        let mut t = target(identity(123));
        t.metadata_lease = Some(crate::metadata_lease::MetadataLease::new(
            std::fs::File::open("/dev/null").unwrap().into(),
            crate::metadata_scope::Token {
                nonce: 19,
                round: 2,
            },
        ));
        assert!(require_metadata_leases(&[t]).is_ok());
    }
    fn identity(birth_ns: u64) -> InstanceIdentity {
        InstanceIdentity {
            tgid: 7,
            uid: 10001,
            birth_ns,
            exec_id: 2,
        }
    }
    #[derive(Default)]
    struct Maps {
        mode: u32,
        epoch: u32,
        rows: BTreeMap<ScopeKey, AllowValue>,
        calls: Vec<String>,
        fail_at: Option<usize>,
    }
    impl Maps {
        fn write(&mut self, name: String) -> Result<()> {
            self.calls.push(name);
            if self.fail_at == Some(self.calls.len()) {
                bail!("injected map failure");
            }
            Ok(())
        }
        fn admits(&self, identity: InstanceIdentity) -> bool {
            self.mode == 3
                && self.rows.get(&ScopeKey {
                    tgid: identity.tgid,
                    epoch: self.epoch,
                }) == Some(&AllowValue {
                    uid: identity.uid,
                    epoch: self.epoch,
                    birth_ns: identity.birth_ns,
                    exec_id: identity.exec_id,
                })
        }
    }
    impl InstanceMaps for Maps {
        fn unbind(&mut self, _pidfd: std::os::fd::BorrowedFd<'_>) -> Result<()> {
            assert_eq!(self.mode, 2);
            self.write("unbind".into())
        }
        fn bind(&mut self, _target: &BoundInstance, _value: AllowValue) -> Result<()> {
            assert_eq!(self.mode, 2);
            self.write("bind".into())
        }
        fn gate(&mut self, mode: u32) -> Result<()> {
            self.write(format!("gate:{mode}"))?;
            self.mode = mode;
            Ok(())
        }
        fn epoch(&mut self, epoch: u32) -> Result<()> {
            assert_eq!(self.mode, 2);
            self.write(format!("epoch:{epoch}"))?;
            self.epoch = epoch;
            Ok(())
        }
        fn remove(&mut self, key: ScopeKey) -> Result<()> {
            assert_eq!(self.mode, 2);
            self.write(format!("remove:{}:{}", key.tgid, key.epoch))?;
            self.rows.remove(&key);
            Ok(())
        }
        fn insert(&mut self, key: ScopeKey, value: AllowValue) -> Result<()> {
            assert_eq!(self.mode, 2);
            self.write(format!("insert:{}:{}", key.tgid, key.epoch))?;
            assert!(
                self.rows.insert(key, value).is_none(),
                "epoch row must be immutable"
            );
            Ok(())
        }
    }
    #[test]
    fn instance_commit_exact_tuple_and_current_epoch_only() {
        let mut maps = Maps::default();
        let state = configure(&mut maps, &ScopeState::default(), &[target(identity(123))]).unwrap();
        assert_eq!(
            maps.calls,
            ["gate:2", "epoch:1", "insert:7:1", "bind", "gate:3"]
        );
        assert!(maps.admits(identity(123)));
        assert!(state.accepts(&InstanceStamp {
            identity: identity(123),
            epoch: 1,
            thread_birth_ns: 200
        }));
        for other in [
            identity(124),
            InstanceIdentity {
                uid: 9,
                ..identity(123)
            },
            InstanceIdentity {
                exec_id: 3,
                ..identity(123)
            },
        ] {
            assert!(!maps.admits(other));
            assert!(!state.accepts(&InstanceStamp {
                identity: other,
                epoch: 1,
                thread_birth_ns: 200
            }));
        }
        let next = configure(&mut maps, &state, &[target(identity(124))]).unwrap();
        assert_eq!(next.epoch, 2);
        assert!(!next.accepts(&InstanceStamp {
            identity: identity(124),
            epoch: 1,
            thread_birth_ns: 200
        }));
        assert!(!maps.admits(identity(123)));
        assert!(maps.admits(identity(124)));
        assert_eq!(maps.rows.len(), 1);
    }
    #[test]
    fn instance_each_partial_update_fails_without_committing_state() {
        for failure in 1..=7 {
            let mut maps = Maps::default();
            let previous =
                configure(&mut maps, &ScopeState::default(), &[target(identity(123))]).unwrap();
            maps.calls.clear();
            maps.fail_at = Some(failure);
            assert!(configure(&mut maps, &previous, &[target(identity(124))]).is_err());
            assert_eq!(previous.epoch, 1); // Caller must detach/discard; cannot retag old cache.
            assert_eq!(maps.calls.len(), failure);
            assert!(!maps.admits(identity(124)));
            if failure == 1 {
                assert!(maps.admits(identity(123))); // Failed write is not a kernel barrier.
            } else {
                assert_eq!(maps.mode, 2);
                assert!(!maps.admits(identity(123)));
            }
            assert!(!maps.calls.iter().any(|s| s == "gate:0" || s == "gate:1"));
        }
    }
    #[test]
    fn instance_invalid_identity_capacity_and_wrap_write_nothing() {
        let too_many: Vec<_> = (1..=129)
            .map(|tgid| InstanceIdentity {
                tgid,
                ..identity(123)
            })
            .collect();
        for bad in [
            vec![identity(0)],
            vec![InstanceIdentity {
                tgid: 0,
                ..identity(123)
            }],
            vec![identity(123), identity(124)],
            too_many,
        ] {
            let mut maps = Maps::default();
            assert!(configure(
                &mut maps,
                &ScopeState::default(),
                &bad.into_iter().map(target).collect::<Vec<_>>()
            )
            .is_err());
            assert!(maps.calls.is_empty());
        }
        let mut maps = Maps::default();
        let exhausted = ScopeState {
            epoch: u32::MAX,
            ..ScopeState::default()
        };
        assert!(configure(&mut maps, &exhausted, &[target(identity(123))]).is_err());
        assert!(maps.calls.is_empty());
    }
    #[test]
    fn instance_committed_handles_are_owned_after_caller_closes_and_reuses_fds() {
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::os::fd::AsRawFd;
        let path = std::env::temp_dir().join(format!("ksight-owned-scope-{}", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.write_all(b"owned-fixture").unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        let targets = [BoundInstance {
            identity: identity(123),
            pidfd: file.into(),
            metadata_lease: None,
        }];
        let original_fd = targets[0].pidfd.as_raw_fd();
        let mut maps = Maps::default();
        let state = configure(&mut maps, &ScopeState::default(), &targets).unwrap();
        assert_ne!(state.bindings[0].pidfd.as_raw_fd(), original_fd);
        drop(targets);
        let unrelated = std::fs::File::open("/dev/null").unwrap();
        let mut retained = std::fs::File::from(state.bindings[0].pidfd.try_clone().unwrap());
        let mut text = String::new();
        retained.read_to_string(&mut text).unwrap();
        assert_eq!(text, "owned-fixture");
        drop(unrelated);
        drop(retained);
        drop(state);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn instance_empty_scope_clears_rows_and_denies_all() {
        let mut maps = Maps::default();
        let previous =
            configure(&mut maps, &ScopeState::default(), &[target(identity(123))]).unwrap();
        let state = configure(&mut maps, &previous, &[]).unwrap();
        assert_eq!(state.epoch, 2);
        assert!(maps.rows.is_empty());
        assert!(!maps.admits(identity(123)));
        assert!(!state.accepts(&InstanceStamp {
            identity: identity(123),
            epoch: 2,
            thread_birth_ns: 200
        }));
    }
}
