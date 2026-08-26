//! Linux and Android eBPF loading and ring-buffer collection.

use std::path::Path;

use anyhow::{Context, Result};
use aya::{
    maps::{Array, MapData, RingBuf},
    programs::TracePoint,
    Ebpf,
};

use crate::collector::{Collector, RawRecord};

/// Attached M1 process lifecycle sensor.
pub struct ProcessSensor {
    bpf: Ebpf,
    events: RingBuf<MapData>,
    dropped: Array<MapData, u64>,
}

impl std::fmt::Debug for ProcessSensor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProcessSensor")
            .field("program_count", &self.bpf.programs().count())
            .field("dropped_records", &self.dropped_records())
            .finish_non_exhaustive()
    }
}

impl ProcessSensor {
    /// Load the process BPF object and attach all three stable scheduler tracepoints.
    ///
    /// # Errors
    ///
    /// Returns an error when the object, maps, verifier, or an attachment is unavailable.
    pub fn load_and_attach(object: &Path) -> Result<Self> {
        let mut bpf = Ebpf::load_file(object)
            .with_context(|| format!("load BPF object {}", object.display()))?;

        for (program_name, tracepoint_name) in [
            ("ksight_process_fork", "sched_process_fork"),
            ("ksight_process_exec", "sched_process_exec"),
            ("ksight_process_exit", "sched_process_exit"),
        ] {
            let program: &mut TracePoint = bpf
                .program_mut(program_name)
                .with_context(|| format!("BPF program {program_name} is missing"))?
                .try_into()
                .with_context(|| format!("BPF program {program_name} is not a tracepoint"))?;
            program
                .load()
                .with_context(|| format!("load BPF program {program_name}"))?;
            program
                .attach("sched", tracepoint_name)
                .with_context(|| format!("attach sched/{tracepoint_name}"))?;
        }

        let events = RingBuf::try_from(
            bpf.take_map("process_events")
                .context("BPF map process_events is missing")?,
        )
        .context("open process_events ring buffer")?;
        let dropped = Array::try_from(
            bpf.take_map("dropped_events")
                .context("BPF map dropped_events is missing")?,
        )
        .context("open dropped_events counter")?;

        Ok(Self {
            bpf,
            events,
            dropped,
        })
    }
}

impl Collector for ProcessSensor {
    type Error = ksight_abi::DecodeError;

    fn next_record(&mut self) -> Result<Option<RawRecord>, Self::Error> {
        self.events
            .next()
            .map(|item| RawRecord::from_bytes(&item))
            .transpose()
    }

    fn dropped_records(&self) -> u64 {
        self.dropped.get(&0, 0).unwrap_or(0)
    }
}
