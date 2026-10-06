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

