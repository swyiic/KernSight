//! Linux and Android eBPF loading and ring-buffer collection.

use std::{
    os::fd::{AsFd as _, AsRawFd as _},
    path::Path,
};

use anyhow::{Context, Result};
use aya::{
    maps::{Array, HashMap, MapData, RingBuf},
    programs::{KProbe, TracePoint},
    Ebpf,
};

use crate::collector::{Collector, RawRecord};

/// Optional kernel-side scope shared by enabled sensors.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct CaptureFilter {
    /// Emit only this thread-group ID.
    pub target_tgid: Option<u32>,
    /// Emit only this effective Linux UID.
    pub target_uid: Option<u32>,
    /// Include memory operations that do not request executable permission.
    pub memory_all: bool,
    /// Include high-frequency socket send/receive byte-count metadata.
    pub network_io: bool,
    /// Include dup/close/fcntl descriptor events (WebView storms this).
    pub file_descriptors: bool,
    /// Emit one out of this many eligible sensor records.
    pub sample_one_in: u32,
}

#[derive(Debug, Clone, Copy)]
struct TracepointSpec {
    program: &'static str,
    category: &'static str,
    name: &'static str,
}

/// One attached eBPF object with a normalized record stream.
pub struct EbpfSensor {
    label: &'static str,
    bpf: Ebpf,
    events: RingBuf<MapData>,
    dropped: Array<MapData, u64>,
    /// Known socket descriptors keyed by `(tgid << 32) | fd` (network sensor only).
    socket_fds: Option<HashMap<MapData, u64, u8>>,
    /// Per-CPU kprobe perf events; must outlive the program.
    _probe_session: Option<ksight_hwbp::KprobeSession>,
}

impl std::fmt::Debug for EbpfSensor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EbpfSensor")
            .field("label", &self.label)
            .field("program_count", &self.bpf.programs().count())
            .field("dropped_records", &self.dropped_records())
            .finish_non_exhaustive()
    }
}

impl Collector for EbpfSensor {
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

    fn seed_socket_fds(&mut self, entries: &[(u32, i32)]) {
        self.seed_socket_fds_from_baseline(entries);
    }
}

/// Load and attach the process lifecycle sensor.
///
/// # Errors
///
/// Returns an error when the object, maps, verifier, or an attachment is unavailable.
pub fn load_process_sensor(object: &Path, filter: CaptureFilter) -> Result<EbpfSensor> {
    load_sensor(
        object,
        filter,
        "process",
        "process_events",
        &[
            TracepointSpec {
                program: "ksight_process_fork",
                category: "sched",
                name: "sched_process_fork",
            },
            TracepointSpec {
                program: "ksight_process_exec",
                category: "sched",
                name: "sched_process_exec",
            },
            TracepointSpec {
                program: "ksight_process_exit",
                category: "sched",
                name: "sched_process_exit",
            },
            TracepointSpec {
                program: "ksight_process_rename",
                category: "task",
                name: "task_rename",
            },
            TracepointSpec {
                program: "ksight_process_credentials",
                category: "raw_syscalls",
                name: "sys_exit",
            },
        ],
        false,
    )
}

/// Load and attach the file-open sensor.
///
/// # Errors
///
/// Returns an error when the object, maps, verifier, or an attachment is unavailable.
pub fn load_file_sensor(object: &Path, filter: CaptureFilter) -> Result<EbpfSensor> {
    load_raw_syscall_sensor(
        object,
        filter,
        "file",
        "file_events",
        "ksight_file_open_enter",
        "ksight_file_open_exit",
    )
}

/// Load and attach the socket-connect sensor.
///
/// # Errors
///
/// Returns an error when the object, maps, verifier, or an attachment is unavailable.
pub fn load_network_sensor(object: &Path, filter: CaptureFilter) -> Result<EbpfSensor> {
    let lifecycle = [
        TracepointSpec {
            program: "ksight_network_connect_enter",
            category: "raw_syscalls",
            name: "sys_enter",
        },
        TracepointSpec {
            program: "ksight_network_connect_exit",
            category: "raw_syscalls",
            name: "sys_exit",
        },
        TracepointSpec {
            program: "ksight_network_accept_enter",
            category: "raw_syscalls",
            name: "sys_enter",
        },
        TracepointSpec {
            program: "ksight_network_accept_exit",
            category: "raw_syscalls",
            name: "sys_exit",
        },
        TracepointSpec {
            program: "ksight_dns_enter",
            category: "raw_syscalls",
            name: "sys_enter",
        },
        TracepointSpec {
            program: "ksight_dns_exit",
            category: "raw_syscalls",
            name: "sys_exit",
        },
        TracepointSpec {
            program: "ksight_handshake_enter",
            category: "raw_syscalls",
            name: "sys_enter",
        },
        TracepointSpec {
            program: "ksight_handshake_exit",
            category: "raw_syscalls",
            name: "sys_exit",
        },
    ];
    let with_io = [
        lifecycle[0],
        lifecycle[1],
        lifecycle[2],
        lifecycle[3],
        lifecycle[4],
        lifecycle[5],
        lifecycle[6],
        lifecycle[7],
        TracepointSpec {
            program: "ksight_network_io_enter",
            category: "raw_syscalls",
            name: "sys_enter",
        },
        TracepointSpec {
            program: "ksight_network_io_exit",
            category: "raw_syscalls",
            name: "sys_exit",
        },
    ];
    let programs = if filter.network_io {
        &with_io[..]
    } else {
        &lifecycle[..]
    };
    load_sensor(object, filter, "network", "network_events", programs, true)
}

/// Load and attach the memory-region sensor.
///
/// # Errors
///
/// Returns an error when the object, maps, verifier, or an attachment is unavailable.
pub fn load_memory_sensor(object: &Path, filter: CaptureFilter) -> Result<EbpfSensor> {
    load_raw_syscall_sensor(
        object,
        filter,
        "memory",
        "memory_events",
        "ksight_memory_enter",
        "ksight_memory_exit",
    )
}

/// Load and attach the scheduler wakeup sensor.
///
/// # Errors
///
/// Returns an error when the object, maps, verifier, or an attachment is unavailable.
pub fn load_sched_sensor(object: &Path, filter: CaptureFilter) -> Result<EbpfSensor> {
    crate::tracepoint::validate_format(
        "sched",
        "sched_wakeup",
        crate::tracepoint::SCHED_WAKEUP_FIELDS,
    )?;
    load_sensor(
        object,
        filter,
        "sched",
        "sched_events",
        &[TracepointSpec {
            program: "ksight_sched_wakeup_prog",
            category: "sched",
            name: "sched_wakeup",
        }],
        false,
    )
}

/// Load and attach the Binder transaction sensor.
///
/// # Errors
///
/// Returns an error when the object, maps, verifier, or an attachment is unavailable.
pub fn load_binder_sensor(object: &Path, filter: CaptureFilter) -> Result<EbpfSensor> {
    let mut sensor = load_sensor(
        object,
        filter,
        "binder",
        "binder_events",
        &[
            TracepointSpec {
                program: "ksight_binder_transaction",
                category: "binder",
                name: "binder_transaction",
            },
            TracepointSpec {
                program: "ksight_binder_transaction_received",
                category: "binder",
                name: "binder_transaction_received",
            },
            TracepointSpec {
                program: "ksight_binder_buffer_allocated",
                category: "binder",
                name: "binder_transaction_alloc_buf",
            },
            TracepointSpec {
                program: "ksight_binder_fd_sent",
                category: "binder",
                name: "binder_transaction_fd_send",
            },
            TracepointSpec {
                program: "ksight_binder_fd_received",
                category: "binder",
                name: "binder_transaction_fd_recv",
            },
        ],
        false,
    )?;
    if let Err(error) = attach_binder_parcel_kprobe(&mut sensor) {
        eprintln!(
            "binder parcel kprobe unavailable (32-bit clients will have no interface token): {error:#}"
        );
    }
    Ok(sensor)
}

fn attach_binder_parcel_kprobe(sensor: &mut EbpfSensor) -> Result<()> {
    let program: &mut KProbe = sensor
        .bpf
        .program_mut("ksight_binder_parcel_enter")
        .context("BPF program ksight_binder_parcel_enter is missing")?
        .try_into()
        .context("BPF program ksight_binder_parcel_enter is not a kprobe")?;
    program
        .load()
        .context("load BPF program ksight_binder_parcel_enter")?;
    let prog_fd = program
        .fd()
        .context("binder parcel kprobe fd")?
        .as_fd()
        .as_raw_fd();
    let session = ksight_hwbp::attach_kprobe_all_cpus(prog_fd, "binder_transaction")?;
    eprintln!(
        "binder parcel kprobe attached on {} CPUs (32-bit and 64-bit clients)",
        session.cpu_count()
    );
    sensor._probe_session = Some(session);
    Ok(())
}

fn load_raw_syscall_sensor(
    object: &Path,
    filter: CaptureFilter,
    label: &'static str,
    event_map: &'static str,
    enter_program: &'static str,
    exit_program: &'static str,
) -> Result<EbpfSensor> {
    load_sensor(
        object,
        filter,
        label,
        event_map,
        &[
            TracepointSpec {
                program: enter_program,
                category: "raw_syscalls",
                name: "sys_enter",
            },
            TracepointSpec {
                program: exit_program,
                category: "raw_syscalls",
                name: "sys_exit",
            },
        ],
        false,
    )
}

fn load_sensor(
    object: &Path,
    filter: CaptureFilter,
    label: &'static str,
    event_map: &'static str,
    tracepoints: &[TracepointSpec],
    retain_socket_fds: bool,
) -> Result<EbpfSensor> {
    let mut bpf =
        Ebpf::load_file(object).with_context(|| format!("load BPF object {}", object.display()))?;
    configure_control(&mut bpf, label, filter)?;
    for spec in tracepoints {
        let program: &mut TracePoint = bpf
            .program_mut(spec.program)
            .with_context(|| format!("BPF program {} is missing", spec.program))?
            .try_into()
            .with_context(|| format!("BPF program {} is not a tracepoint", spec.program))?;
        program
            .load()
            .with_context(|| format!("load BPF program {}", spec.program))?;
        program
            .attach(spec.category, spec.name)
            .with_context(|| format!("attach {}/{}", spec.category, spec.name))?;
    }

    let events = RingBuf::try_from(
        bpf.take_map(event_map)
            .with_context(|| format!("BPF map {event_map} is missing"))?,
    )
    .with_context(|| format!("open {event_map} ring buffer"))?;
    let dropped = Array::try_from(
        bpf.take_map("dropped_events")
            .context("BPF map dropped_events is missing")?,
    )
    .context("open dropped_events counter")?;
    let socket_fds = if retain_socket_fds {
        Some(
            HashMap::try_from(
                bpf.take_map("socket_fds")
                    .context("BPF map socket_fds is missing")?,
            )
            .context("open socket_fds map")?,
        )
    } else {
        None
    };

    Ok(EbpfSensor {
        label,
        bpf,
        events,
        dropped,
        socket_fds,
        _probe_session: None,
    })
}

impl EbpfSensor {
    /// Record pre-session socket descriptors in the `socket_fds` map.
    fn seed_socket_fds_from_baseline(&mut self, entries: &[(u32, i32)]) {
        let Some(map) = self.socket_fds.as_mut() else {
            return;
        };
        for (tgid, fd) in entries {
            let key = ((*tgid as u64) << 32) | (*fd as u32 as u64);
            let _ = map.insert(key, 1, 0);
        }
    }
}

fn configure_control(bpf: &mut Ebpf, sensor: &str, filter: CaptureFilter) -> Result<()> {
    let mut control = Array::<_, u32>::try_from(
        bpf.map_mut("control")
            .context("BPF map control is missing")?,
    )
    .with_context(|| format!("open {sensor} sensor control map"))?;
    for (index, value) in [
        (0, std::process::id()),
        (1, filter.target_tgid.unwrap_or(u32::MAX)),
        (2, filter.target_uid.unwrap_or(u32::MAX)),
        (3, u32::from(filter.memory_all)),
        (6, u32::from(filter.network_io)),
        (4, filter.sample_one_in.max(1)),
        (5, 0),
        (7, u32::from(filter.file_descriptors)),
    ] {
        control
            .set(index, value, 0)
            .with_context(|| format!("configure {sensor} sensor control index {index}"))?;
    }
    Ok(())
}
