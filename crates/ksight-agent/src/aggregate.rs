use std::collections::BTreeMap;

use ksight_model::SensorKind;

/// Low-cost per-sensor counters maintained outside BPF.
#[derive(Debug, Default)]
pub struct SensorCounters {
    counts: BTreeMap<SensorKind, u64>,
}

impl SensorCounters {
    /// Record one normalized event.
    pub fn record(&mut self, sensor: SensorKind) {
        *self.counts.entry(sensor).or_default() += 1;
    }

    /// Return the current count for a sensor.
    pub fn count(&self, sensor: SensorKind) -> u64 {
        self.counts.get(&sensor).copied().unwrap_or_default()
    }
}
