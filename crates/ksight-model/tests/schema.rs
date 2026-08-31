//! Initial normalized schema invariants.

use ksight_model::{CaptureMode, SensorKind, CURRENT_SCHEMA};

#[test]
fn initial_schema_is_explicit() {
    assert_eq!(CURRENT_SCHEMA.major, 1);
    assert_eq!(CURRENT_SCHEMA.minor, 28);
    assert_eq!(CaptureMode::Observe, CaptureMode::Observe);
    assert_eq!(SensorKind::Process, SensorKind::Process);
}
