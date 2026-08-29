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
    pub fn len(&self) -> usize {
        self.active.len()
    }

    /// Whether no process leaders are currently known.
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
    pub fn count(&self, sensor: SensorKind) -> u64 {
        self.counts.get(&sensor).copied().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use ksight_model::{
        CaptureMode, Confidence, DataQuality, EventHeader, ProcessIdentity, ProcessKey,
        ProcessLifecycle, SchemaVersion,
    };
    use uuid::Uuid;

    use super::*;

    #[test]
    fn correlates_late_file_events_after_exact_exit() {
        let mut tracker = ProcessInstanceTracker::default();
        let mut fork = event(42, 42, 100, ProcessLifecycleKind::Fork, SensorKind::Process);
        tracker.correlate(&mut fork);

        let mut file = event(42, 42, 0, ProcessLifecycleKind::Exec, SensorKind::File);
        tracker.correlate(&mut file);
        assert_eq!(file.header.process.key.start_time_ns, 100);

        let mut exit = event(42, 42, 100, ProcessLifecycleKind::Exit, SensorKind::Process);
        tracker.correlate(&mut exit);
        assert!(tracker.is_empty());

        let mut after_exit = event(42, 42, 0, ProcessLifecycleKind::Exec, SensorKind::File);
        tracker.correlate(&mut after_exit);
        assert_eq!(after_exit.header.process.key.start_time_ns, 100);
    }

    fn event(
        pid: u32,
        tid: u32,
        start_time_ns: u64,
        kind: ProcessLifecycleKind,
        sensor: SensorKind,
    ) -> Event {
        Event {
            header: EventHeader {
                schema: SchemaVersion { major: 1, minor: 8 },
                session_id: Uuid::nil(),
                source_sequence: 1,
                monotonic_ns: 1,
                cpu: Some(0),
                process: ProcessIdentity {
                    key: ProcessKey {
                        boot_id: Uuid::nil(),
                        pid,
                        start_time_ns,
                    },
                    tid,
                    tgid: pid,
                    uid: 0,
                    gid: 0,
                    comm: "test".to_owned(),
                    command_line: None,
                    selinux_context: None,
                    packages: Vec::new(),
                },
                sensor,
                mode: CaptureMode::Observe,
                quality: DataQuality {
                    confidence: Confidence::Partial,
                    truncated: false,
                    lost_before: 0,
                    sample_one_in: 1,
                    source: "test".to_owned(),
                },
            },
            payload: EventPayload::ProcessLifecycle(ProcessLifecycle {
                kind,
                parent_pid: None,
                filename: None,
                exit_code: None,
                zygote_source: None,
            }),
        }
    }
}
