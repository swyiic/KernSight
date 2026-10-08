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

/// Validate every returned identity, even when no further payload may be decoded.
pub(super) fn check_budgeted_hit(
    hit: &RegisterContext,
    targets: &[BoundInstance],
    epoch: Option<u32>,
    exhausted: bool,
    live_check: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    if !exhausted {
        live_check()?;
    }
    if !accepts(hit, targets, epoch) {
        return Err("bound_consumer_generation_or_identity_mismatch".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    use ksight_hwbp::instance_scope::{InstanceIdentity, InstanceStamp};
    fn fixture() -> (RegisterContext, Vec<BoundInstance>) {
        let identity = InstanceIdentity {
            tgid: 10,
            uid: 20,
            birth_ns: 30,
            exec_id: 40,
        };
        let target = BoundInstance::trusted_candidate(
            identity,
            std::fs::File::open("/dev/null").unwrap().into(),
        );
        let hit = RegisterContext {
            pid: 10,
            instance: Some(InstanceStamp {
                identity,
                epoch: 2,
                thread_birth_ns: 50,
            }),
            ..RegisterContext::default()
        };
        (hit, vec![target])
    }
    #[test]
    fn exhausted_records_skip_live_work_but_not_exact_identity() {
        let (mut hit, targets) = fixture();
        assert!(check_budgeted_hit(&hit, &targets, Some(2), true, || panic!(
            "unreachable payload work"
        ))
        .is_ok());
        hit.instance.as_mut().unwrap().epoch = 3;
        assert!(check_budgeted_hit(&hit, &targets, Some(2), true, || panic!(
            "unreachable payload work"
        ))
        .is_err());
        hit.instance = None;
        assert!(check_budgeted_hit(&hit, &targets, Some(2), true, || panic!(
            "unreachable payload work"
        ))
        .is_err());
    }
    #[test]
    fn payload_eligible_records_keep_original_live_failure() {
        let (hit, targets) = fixture();
        assert_eq!(
            check_budgeted_hit(&hit, &targets, Some(2), false, || Err(
                "source exited".to_owned()
            )),
            Err("source exited".to_owned())
        );
    }
}
