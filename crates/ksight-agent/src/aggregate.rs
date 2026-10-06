use std::collections::{BTreeMap, BTreeSet};

use ksight_model::{Event, EventPayload, ProcessLifecycleKind, SensorKind};

/// Low-cost per-sensor counters maintained outside BPF.
#[derive(Debug, Default)]
pub struct SensorCounters {
    counts: BTreeMap<SensorKind, u64>,
}

/// Correlates records from independent sensor ring buffers to one process instance.
#[derive(Debug, Default)]
pub struct ProcessInstanceTracker {
    start_times: BTreeMap<u32, u64>,
    active: BTreeSet<(u32, u64)>,
    /// 已识别的 Zygote 进程：pid → comm（zygote64 / zygote）。
    zygotes: BTreeMap<u32, String>,
}

impl ProcessInstanceTracker {
    /// Fill missing start times, learn new leaders, and mark exited instances inactive.
    pub fn correlate(&mut self, event: &mut Event) {
        let process = &mut event.header.process;
        let process_id = process.tgid;
        self.track_zygote(process_id, process.command_line.as_deref());
        if process.key.start_time_ns == 0 {
            process.key.start_time_ns = self
                .start_times
                .get(&process_id)
                .copied()
                .unwrap_or_default();
        }

        let leader = process.tid == process.tgid;
        let exiting = matches!(
            event.payload,
            EventPayload::ProcessLifecycle(ref lifecycle)
                if lifecycle.kind == ProcessLifecycleKind::Exit
        );
        if leader && !exiting && process.key.start_time_ns != 0 {
            self.start_times
                .insert(process_id, process.key.start_time_ns);
            self.active.insert((process_id, process.key.start_time_ns));
        }
        if leader && exiting {
            let observed_start = process.key.start_time_ns;
            self.active.remove(&(process_id, observed_start));
        }
        self.annotate_zygote_lineage(event);
    }

    /// Record a process as a Zygote when its command line matches the known names.
    ///
    /// The Zygote task name is `main`; its identity lives in `argv[0]`, which
    /// the identity resolver exposes as `command_line`.
    fn track_zygote(&mut self, process_id: u32, command_line: Option<&str>) {
        let Some(command) = command_line else {
            return;
        };
        let command = command.split(':').next().unwrap_or(command);
        if (command == "zygote" || command == "zygote64") && !self.zygotes.contains_key(&process_id)
        {
            self.zygotes.insert(process_id, command.to_owned());
        }
    }

    /// Scan `/proc` once at capture start to pre-seed Zygote process identities.
    ///
    /// Zygote is long-lived and may not emit a lifecycle event during a short
    /// capture, so its identity must be discovered proactively.
    pub fn discover_zygotes(&mut self) {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return;
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            let Ok(cmdline) = std::fs::read_to_string(format!("/proc/{pid}/cmdline")) else {
                continue;
            };
            let command = cmdline.split('\0').next().unwrap_or("").trim();
            let command = command.split(':').next().unwrap_or(command);
            if command == "zygote" || command == "zygote64" {
                self.zygotes.insert(pid, command.to_owned());
            }
        }
    }

    /// Annotate a fork with its Zygote lineage when the parent is a known Zygote.
    fn annotate_zygote_lineage(&mut self, event: &mut Event) {
        let EventPayload::ProcessLifecycle(lifecycle) = &mut event.payload else {
            return;
        };
        if lifecycle.kind != ProcessLifecycleKind::Fork {
            return;
        }
        let Some(parent) = lifecycle.parent_pid else {
            return;
        };
        lifecycle.zygote_source = self.zygotes.get(&parent).cloned();
    }

    /// Number of process leaders currently known to the capture session.
    #[must_use]
    pub fn len(&self) -> usize {
        self.active.len()
    }

    /// Whether no process leaders are currently known.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }
}

impl SensorCounters {
    /// Record one normalized event.
    pub fn record(&mut self, sensor: SensorKind) {
        *self.counts.entry(sensor).or_default() += 1;
    }

    /// Return the current count for a sensor.
    #[must_use]
    pub fn count(&self, sensor: SensorKind) -> u64 {
        self.counts.get(&sensor).copied().unwrap_or_default()
    }
}
