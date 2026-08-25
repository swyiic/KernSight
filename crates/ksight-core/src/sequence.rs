use std::collections::BTreeMap;

use ksight_model::SensorKind;
use thiserror::Error;

/// Missing source-local event range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequenceGap {
    /// Producing sensor.
    pub sensor: SensorKind,
    /// First missing sequence.
    pub first_missing: u64,
    /// Last missing sequence, inclusive.
    pub last_missing: u64,
}

/// Invalid source ordering.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SequenceError {
    /// Duplicate or out-of-order sequence.
    #[error("sensor {sensor:?} sequence moved from {last} to {observed}")]
    NonMonotonic {
        /// Producing sensor.
        sensor: SensorKind,
        /// Last accepted sequence.
        last: u64,
        /// Rejected sequence.
        observed: u64,
    },
}

/// Tracks source-local ordering and turns missing ranges into explicit evidence.
#[derive(Debug, Default)]
pub struct SequenceTracker {
    last: BTreeMap<SensorKind, u64>,
}

impl SequenceTracker {
    /// Observe a sequence and return a gap when records were skipped.
    ///
    /// # Errors
    ///
    /// Returns [`SequenceError::NonMonotonic`] for a duplicate or out-of-order sequence.
    pub fn observe(
        &mut self,
        sensor: SensorKind,
        sequence: u64,
    ) -> Result<Option<SequenceGap>, SequenceError> {
        let Some(previous) = self.last.get(&sensor).copied() else {
            self.last.insert(sensor, sequence);
            return Ok(None);
        };

        if sequence <= previous {
            return Err(SequenceError::NonMonotonic {
                sensor,
                last: previous,
                observed: sequence,
            });
        }

        self.last.insert(sensor, sequence);
        let first_missing = previous.saturating_add(1);
        if sequence == first_missing {
            return Ok(None);
        }

        Ok(Some(SequenceGap {
            sensor,
            first_missing,
            last_missing: sequence - 1,
        }))
    }
}
