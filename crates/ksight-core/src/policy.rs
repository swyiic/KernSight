use std::collections::BTreeSet;

use ksight_model::SensorKind;
use ksight_protocol::UpdatePolicy;
use thiserror::Error;

const MAX_PAYLOAD_BYTES: u32 = 64 * 1024;

/// Invalid capture policy.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    /// Sampling denominator must never be zero.
    #[error("sensor {sensor:?} has a zero sampling denominator")]
    ZeroSampling {
        /// Invalid sensor.
        sensor: SensorKind,
    },
    /// Payload capture must remain bounded.
    #[error("sensor {sensor:?} requests {requested} bytes, above the {maximum} byte limit")]
    PayloadTooLarge {
        /// Invalid sensor.
        sensor: SensorKind,
        /// Requested bytes.
        requested: u32,
        /// Maximum bytes.
        maximum: u32,
    },
    /// One policy generation may define each sensor once.
    #[error("sensor {sensor:?} appears more than once")]
    DuplicateSensor {
        /// Duplicated sensor.
        sensor: SensorKind,
    },
}

/// Validate safety invariants before a policy reaches any capture adapter.
///
/// # Errors
///
/// Returns the first violated sampling, payload-bound, or uniqueness invariant.
pub fn validate_policy(policy: &UpdatePolicy) -> Result<(), PolicyError> {
    let mut seen = BTreeSet::new();
    for sensor in &policy.sensors {
        if !seen.insert(sensor.sensor) {
            return Err(PolicyError::DuplicateSensor {
                sensor: sensor.sensor,
            });
        }
        if sensor.sample_one_in == 0 {
            return Err(PolicyError::ZeroSampling {
                sensor: sensor.sensor,
            });
        }
        if sensor.max_payload_bytes > MAX_PAYLOAD_BYTES {
            return Err(PolicyError::PayloadTooLarge {
                sensor: sensor.sensor,
                requested: sensor.max_payload_bytes,
                maximum: MAX_PAYLOAD_BYTES,
            });
        }
    }
    Ok(())
}
