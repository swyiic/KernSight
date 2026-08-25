//! Ordering and capture-policy invariants.

use ksight_core::{validate_policy, PolicyError, SequenceError, SequenceTracker};
use ksight_model::{CaptureMode, SensorKind};
use ksight_protocol::{SensorPolicy, UpdatePolicy};

#[test]
fn sequence_gaps_are_evidence() {
    let mut tracker = SequenceTracker::default();
    assert_eq!(tracker.observe(SensorKind::Process, 10), Ok(None));
    let gap = tracker
        .observe(SensorKind::Process, 13)
        .expect("ordered")
        .expect("gap");
    assert_eq!(gap.first_missing, 11);
    assert_eq!(gap.last_missing, 12);
    assert!(matches!(
        tracker.observe(SensorKind::Process, 12),
        Err(SequenceError::NonMonotonic { .. })
    ));
}

#[test]
fn policies_reject_unbounded_payloads() {
    let policy = UpdatePolicy {
        generation: 1,
        mode: CaptureMode::Inspect,
        sensors: vec![SensorPolicy {
            sensor: SensorKind::Network,
            enabled: true,
            sample_one_in: 1,
            max_payload_bytes: 65_537,
        }],
    };
    assert!(matches!(
        validate_policy(&policy),
        Err(PolicyError::PayloadTooLarge { .. })
    ));
}
