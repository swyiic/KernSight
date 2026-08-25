//! Agent policy-store tests.

use ksight_agent::policy::{PolicyInstallError, PolicyStore};
use ksight_model::CaptureMode;
use ksight_protocol::UpdatePolicy;

#[test]
fn policy_generation_must_increase() {
    let mut store = PolicyStore::default();
    let policy = UpdatePolicy {
        generation: 7,
        mode: CaptureMode::Observe,
        sensors: Vec::new(),
    };
    store.replace(policy.clone()).expect("first policy");
    assert_eq!(
        store.replace(policy),
        Err(PolicyInstallError::StaleGeneration)
    );
}
