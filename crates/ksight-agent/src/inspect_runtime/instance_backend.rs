//! Candidate backend plumbing. This module does not issue authorization or
//! enable strict mirror. Callers must qualify raw metadata and package policy.
use anyhow::{bail, Result};
use ksight_hwbp::{instance_scope::BoundInstance, RegisterContext};

pub(super) fn select(
    targets: &[BoundInstance],
    tgids: Option<&[u32]>,
) -> Result<Vec<BoundInstance>> {
    let Some(tgids) = tgids else {
        bail!("bound backend requires explicit scoped allowlist");
    };
    // Unknown numeric discoveries cannot turn into new kernel authorization.
    targets
        .iter()
        .filter(|t| tgids.contains(&t.identity.tgid))
        .map(|t| t.try_clone().map_err(Into::into))
        .collect()
}
#[allow(
    clippy::items_after_statements,
    reason = "Local fixture or owned callback keeps its explicit scope and fallible signature."
)]
pub(super) fn accepts(
    hit: &RegisterContext,
    targets: &[BoundInstance],
    epoch: Option<u32>,
) -> bool {
    match (hit.instance.as_ref(), epoch) {
        (Some(stamp), Some(epoch)) => {
            epoch != 0
                && stamp.epoch == epoch
                && stamp.thread_birth_ns != 0
                && hit.pid == stamp.identity.tgid
                && targets.iter().any(|t| t.identity == stamp.identity)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ksight_hwbp::instance_scope::{InstanceIdentity, InstanceStamp};
    use std::os::fd::AsRawFd;
    fn target() -> BoundInstance {
        BoundInstance::trusted_candidate(
            InstanceIdentity {
                tgid: 7,
                uid: 10001,
                birth_ns: 123,
                exec_id: 2,
            },
            std::fs::File::open("/dev/null").unwrap().into(),
        )
    }
    #[test]
    fn bound_selection_never_grants_discovered_numeric_pid_or_unscoped_mode() {
        let targets = [target()];
        assert!(select(&targets, None).is_err());
        assert!(select(&targets, Some(&[])).unwrap().is_empty());
        assert!(select(&targets, Some(&[8])).unwrap().is_empty());
        let next = select(&targets, Some(&[7, 8])).unwrap();
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].identity, targets[0].identity);
        assert_ne!(next[0].pidfd.as_raw_fd(), targets[0].pidfd.as_raw_fd());
    }
    #[test]
    fn production_scope_revocation_closes_candidate_handles_and_preserves_deny_backend() {
        use super::super::*;
        let policy = InspectPolicy {
            package: Some("fixture.package".into()),
            whole_device: false,
            ..InspectPolicy::default()
        };
        let mut runtime = InspectRuntime::prepare_all(
            &policy,
            &[InspectAdapterKind::TlsSslRead],
            std::path::Path::new("missing-candidate-object"),
        );
        // Internal offline stand-in, never accepted by public candidate startup.
        runtime.bound_instance_targets = Some(vec![target()]);
        runtime.scoped_tgids = vec![7];
        runtime.process_starts.insert(7, 123);
        clear_scope_state(&mut runtime, Some(7));
        assert!(runtime.bound_instance_targets.as_ref().unwrap().is_empty());
        assert!(runtime.scoped_tgids.is_empty());
        assert!(runtime.process_starts.is_empty());
    }
    #[test]
    fn qualified_candidate_requires_package_and_empty_scope_stays_denied() {
        use super::super::*;
        let mut policy = InspectPolicy {
            package: None,
            ..InspectPolicy::default()
        };
        let prepare = |p: &InspectPolicy| {
            InspectRuntime::prepare_qualified_candidate(
                p,
                &[InspectAdapterKind::TlsSslRead],
                std::path::Path::new("not-loaded"),
                vec![],
            )
        };
        assert!(prepare(&policy).is_err());
        policy.package = Some("fixture.package".into());
        policy.whole_device = true;
        assert!(prepare(&policy).is_err());
        policy.whole_device = false;
        assert!(InspectRuntime::prepare_bound_candidate(
            &policy,
            &[InspectAdapterKind::TlsSslRead],
            std::path::Path::new("not-loaded"),
            vec![target()]
        )
        .is_err());
        let runtime = prepare(&policy).unwrap();
        assert!(runtime.bound_instance_targets.as_ref().unwrap().is_empty());
        assert!(ksight_core::capture_scope::require_strict_mirror_backend().is_err());
    }
    #[test]
    fn consumer_rejects_old_generation_raw_records_and_changed_identity() {
        let targets = [target()];
        let mut hit = RegisterContext {
            pid: 7,
            ..Default::default()
        };
        assert!(!accepts(&hit, &targets, Some(1)));
        hit.instance = Some(InstanceStamp {
            identity: targets[0].identity,
            epoch: 1,
            thread_birth_ns: 200,
        });
        assert!(accepts(&hit, &targets, Some(1)));
        assert!(!accepts(&hit, &targets, None));
        assert!(!accepts(&hit, &targets, Some(2)));
        assert!(!accepts(&hit, &[], Some(1)));
        hit.instance.as_mut().unwrap().identity.exec_id += 1;
        assert!(!accepts(&hit, &targets, Some(1)));
    }
}
