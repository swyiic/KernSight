//! `ksightctl` command-line client entry point.

mod device;
mod display;

use anyhow::{bail, Result};
use clap::{Args as ClapArgs, Parser, Subcommand};
use ksight_model::CURRENT_SCHEMA;
use ksight_protocol::CURRENT_PROTOCOL;
use uuid::Uuid;

use crate::{
    device::{
        cleanup_package, daemon_start, daemon_status, daemon_stop, deploy_agent,
        protocol_acknowledge, protocol_graph, protocol_replay, protocol_report, protocol_sessions,
        pull_forensics, pull_package, pull_snapshot, read_last_session, recatalog_package,
        run_device, run_device_tee, run_hide_debug_capture, validate_package, DEVICE_AGENT,
        DEVICE_BINDER_OBJECT, DEVICE_FILE_OBJECT, DEVICE_MEMORY_OBJECT, DEVICE_NETWORK_OBJECT,
        DEVICE_PROCESS_OBJECT, DEVICE_SCHED_OBJECT, DEVICE_SPOOL_ROOT, DEVICE_UPROBE_OBJECT,
    },
    display::{print_capabilities, print_keypoints},
};

#[derive(Debug, Parser)]
#[command(name = "ksightctl", version, about = "KernSight command-line client")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print component boundaries before a device transport exists.
    Architecture,
    /// Print compatibility versions.
    Versions,
    /// Show what this build can collect, what remains partial, and collection visibility.
    Capabilities {
        /// Emit the capability matrix as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show reviewed L1 semantic probe candidates without enabling them.
    Keypoints {
        /// Emit the keypoint registry as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Operate the authorized `KernSight` agent over ADB.
    Device {
        /// Select a device by ADB serial when more than one is connected.
        #[arg(long)]
        serial: Option<String>,
        #[command(subcommand)]
        command: Box<DeviceCommand>,
    },
}

#[derive(Debug, Subcommand)]
enum DeviceCommand {
    /// Print the device's read-only kernel capability report.
    Probe,
    /// Manage the detached whole-device collector.
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
    /// List durable sessions waiting for client acknowledgement.
    Sessions,
    /// Replay one durable session as protocol JSON Lines without deleting it.
    Replay {
        /// Capture session UUID.
        session: Uuid,
        /// Replay only batches strictly after this sequence.
        #[arg(long)]
        after: Option<u64>,
    },
    /// Aggregate one durable session into an operator-readable report without deleting it.
    Report {
        /// Capture session UUID.
        session: Uuid,
        /// Replay only batches strictly after this sequence.
        #[arg(long)]
        after: Option<u64>,
        /// Maximum rows printed in each high-volume section.
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// Emit the complete report as JSON for `MobileE` or another client.
        #[arg(long)]
        json: bool,
    },
    /// Confirm a contiguous durable batch range and release its device storage.
    Acknowledge {
        /// Capture session UUID.
        session: Uuid,
        /// Highest contiguous batch sequence safely received and validated.
        #[arg(long)]
        through: u64,
    },
    /// Query the L0 correlation graph for one durable session.
    Graph {
        /// Capture session UUID.
        session: Uuid,
        /// Replay only batches strictly after this sequence.
        #[arg(long)]
        after: Option<u64>,
        /// Substring matched against entity keys, labels, and edge endpoints.
        #[arg(long)]
        entity: Option<String>,
        /// Exact relation name such as binder, connects, wakes, maps, or `overlaps_mmap`.
        #[arg(long)]
        relation: Option<String>,
        /// Required edge strength: confirmed, correlated, or inferred.
        #[arg(long)]
        strength: Option<String>,
        /// Maximum entities and edges to return.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Emit the queried graph as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Stream normalized whole-device runtime events.
    Capture(CaptureOptions),
    /// Build the device agent and push it to the phone. `cargo run` only rebuilds this CLI.
    Deploy,
    /// Pull hashed forensic snapshots (DEX, connlogs) copied during capture.
    PullForensics {
        /// Capture session UUID.
        session: Uuid,
        /// Host directory that receives the files.
        #[arg(long, default_value = ".")]
        dest: std::path::PathBuf,
    },
    /// Copy one installed package's APK, native libraries, repaired DEX, and live images.
    PullPackage {
        /// Exact Android package name, for example `com.sgcc.wsgw.cn`.
        #[arg(long)]
        package: String,
        /// Host directory that receives `dest/<package>/`.
        #[arg(long, default_value = "packages")]
        dest: std::path::PathBuf,
        /// Cold-start the app on device and harvest live DEX/SO (needed for packed APKs).
        #[arg(long)]
        launch: bool,
        /// Skip install APK/lib/oat. The pulled folder is this package's collected evidence.
        #[arg(long, alias = "evidence-only")]
        runtime_only: bool,
        /// Hide USB debugging and developer options after ART attach, then launch. Apps that check `adb_enabled` need this. Does not hide root.
        #[arg(long)]
        hide_debug: bool,
        /// If Magisk is present, add the package to `DenyList` for the dump window. Does not hide root or an unlocked bootloader.
        #[arg(long)]
        denylist: bool,
        /// Hide-debug watchdog seconds. Default 120 with `--launch`, otherwise 60.
        #[arg(long)]
        hide_debug_secs: Option<u64>,
    },
    /// Rebuild dump-report.json artifacts and correlated VMA/maps edges without a live dump.
    RecatalogPackage {
        /// Exact Android package name already dumped under `/data/local/tmp/ksight/packages`.
        #[arg(long)]
        package: String,
    },
    /// Delete one package's protected and published device-side dump copies.
    CleanupPackage {
        /// Exact Android package name.
        #[arg(long)]
        package: String,
    },
    /// Bounded live `/proc/<pid>/mem` copy. L2 forensic; pauses the target.
    Snapshot {
        /// Exact Android package name. Resolves a live PID when `--pid` is omitted.
        #[arg(long)]
        package: Option<String>,
        /// Target process ID.
        #[arg(long)]
        pid: Option<u32>,
        /// Host directory that receives `dest/<name>/`.
        #[arg(long, default_value = "snapshots")]
        dest: std::path::PathBuf,
        /// Inclusive hex or decimal virtual address. Requires `--end`.
        #[arg(long)]
        start: Option<String>,
        /// Exclusive hex or decimal virtual address. Requires `--start`.
        #[arg(long)]
        end: Option<String>,
        /// Maximum copied MiB.
        #[arg(long, default_value_t = 32)]
        max_mib: u64,
        /// Copy without `SIGSTOP`.
        #[arg(long)]
        no_pause: bool,
    },
}

#[derive(Debug, Subcommand)]
enum DaemonCommand {
    /// Validate configuration and start the collector independently of the ADB shell.
    Start,
    /// Show machine-readable lifecycle state and process identity.
    Status,
    /// Request graceful shutdown and wait for the final batch flush.
    Stop,
}

#[derive(Debug, ClapArgs)]
#[allow(clippy::struct_excessive_bools)] // Independent command-line switches are intentionally boolean.
struct CaptureOptions {
    /// Stop after this many live kernel events; baseline records do not consume the limit.
    #[arg(long, default_value_t = 0)]
    count: u64,
    /// Stop after this many seconds; zero means no time limit.
    #[arg(long, default_value_t = 0)]
    duration_seconds: u64,
    /// Emit one normalized JSON event per line.
    #[arg(long)]
    json: bool,
    /// Suppress individual events and print only capture/spool summaries.
    #[arg(long)]
    quiet: bool,
    /// Include individual thread lifecycle and rename events.
    #[arg(long)]
    include_threads: bool,
    /// Enable the experimental file-open sensor.
    #[arg(long)]
    files: bool,
    /// Also capture dup/close/fcntl. Default off; WebView/Chromium will overflow the ring.
    #[arg(long)]
    files_fd: bool,
    /// Enable the experimental socket-connect sensor.
    #[arg(long)]
    network: bool,
    /// Include socket send/receive byte counts without payload bytes.
    #[arg(long)]
    network_io: bool,
    /// Enable the experimental memory-region sensor.
    #[arg(long)]
    memory: bool,
    /// Mapping-sized mmap/mprotect/munmap (256 KiB+) plus executable transitions. Large anonymous heaps are always kept; page-permission storms are not.
    #[arg(long)]
    memory_all: bool,
    /// Enable all default-volume sensors; excludes network-io and memory-all.
    #[arg(long)]
    all: bool,
    /// Enable the experimental Binder transaction sensor.
    #[arg(long)]
    binder: bool,
    /// Enable scheduler wakeup capture (requires --pid, --uid, or --package).
    #[arg(long)]
    sched: bool,
    /// Capture only this process/thread-group ID.
    #[arg(long)]
    pid: Option<u32>,
    /// Capture only this effective Linux UID.
    #[arg(long)]
    uid: Option<u32>,
    /// Capture only this exact Android package, including its colon processes.
    #[arg(long)]
    package: Option<String>,
    /// Persist bounded event batches on the device for later replay.
    #[arg(long)]
    spool: bool,
    /// Maximum retained complete batch data in MiB.
    #[arg(long, default_value_t = 64)]
    spool_max_mib: u64,
    /// Maximum events in each persisted protocol batch.
    #[arg(long, default_value_t = 64)]
    batch_events: usize,
    /// Emit one out of this many eligible optional-sensor events.
    #[arg(long, default_value_t = 1)]
    sample_one_in: u32,
    /// Enable the linker SO-load Inspect adapter. Default off; pair with `--package` or `--pid`.
    #[arg(long)]
    inspect_linker: bool,
    /// Enable bounded `SSL_write` plaintext for one app. May be combined with `--inspect-adapter binder_userspace`.
    #[arg(long)]
    inspect_tls: bool,
    /// Inspect every app mapping the adapter ELF. Noisy; prefer `--package`.
    #[arg(long)]
    inspect_all_apps: bool,
    /// Maximum `SSL_write` bytes copied per hit (hard cap 4096).
    #[arg(long, default_value_t = 256)]
    inspect_max_bytes: u32,
    /// Maximum Inspect hits; 0 uses the adapter default.
    #[arg(long, default_value_t = 0)]
    inspect_max_hits: u32,
    /// Named Inspect adapter. Combine with `--inspect-tls` for Binder plus TLS in one session.
    #[arg(long)]
    inspect_adapter: Option<String>,
    /// Optional GNU build-id that must match before Inspect attach.
    #[arg(long)]
    inspect_build_id: Option<String>,
    /// Optional ELF path for Inspect attach.
    #[arg(long)]
    inspect_elf: Option<String>,
    /// Optional file offset for Inspect attach.
    #[arg(long)]
    inspect_offset: Option<u64>,
    /// Maximum wall time for an attached Inspect adapter; 0 follows the capture duration.
    #[arg(long, default_value_t = 0)]
    inspect_max_secs: u32,
    /// After a spooled capture, pull forensic snapshots here (DEX, connlogs).
    #[arg(long, default_value = "forensics")]
    forensics_dir: std::path::PathBuf,
    /// Do not pull forensic snapshots after capture.
    #[arg(long)]
    no_pull_forensics: bool,
    /// Detach capture, hide USB debugging and developer options for the duration, restore them, then pull forensics. Does not hide root or an unlocked bootloader.
    #[arg(long)]
    hide_debug: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Architecture => {
            println!("ksightctl -> versioned protocol -> ksightd -> sensor adapters -> eBPF");
            println!("MobileE is a peer client and is not a dependency of KernSight.");
        }
        Command::Versions => {
            println!(
                "wire={}.{} schema={}.{} raw_abi=1",
                CURRENT_PROTOCOL.major,
                CURRENT_PROTOCOL.minor,
                CURRENT_SCHEMA.major,
                CURRENT_SCHEMA.minor
            );
        }
        Command::Capabilities { json } => print_capabilities(json)?,
        Command::Keypoints { json } => print_keypoints(json)?,
        Command::Device { serial, command } => run_device_command(serial.as_deref(), *command)?,
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_device_command(serial: Option<&str>, command: DeviceCommand) -> Result<()> {
    match command {
        DeviceCommand::Probe => run_device(serial, &format!("{DEVICE_AGENT} probe --json"))?,
        DeviceCommand::Deploy => deploy_agent(serial)?,
        DeviceCommand::PullForensics { session, dest } => pull_forensics(serial, session, &dest)?,
        DeviceCommand::PullPackage {
            package,
            dest,
            launch,
            runtime_only,
            hide_debug,
            denylist,
            hide_debug_secs,
        } => pull_package(
            serial,
            &package,
            &dest,
            launch,
            runtime_only,
            hide_debug,
            denylist,
            hide_debug_secs,
        )?,
        DeviceCommand::RecatalogPackage { package } => recatalog_package(serial, &package)?,
        DeviceCommand::CleanupPackage { package } => cleanup_package(serial, &package)?,
        DeviceCommand::Snapshot {
            package,
            pid,
            dest,
            start,
            end,
            max_mib,
            no_pause,
        } => pull_snapshot(
            serial,
            package.as_deref(),
            pid,
            &dest,
            start.as_deref(),
            end.as_deref(),
            max_mib,
            no_pause,
        )?,
        DeviceCommand::Daemon { command } => match command {
            DaemonCommand::Start => daemon_start(serial)?,
            DaemonCommand::Status => daemon_status(serial)?,
            DaemonCommand::Stop => daemon_stop(serial)?,
        },
        DeviceCommand::Sessions => protocol_sessions(serial)?,
        DeviceCommand::Replay { session, after } => protocol_replay(serial, session, after)?,
        DeviceCommand::Report {
            session,
            after,
            top,
            json,
        } => {
            if top == 0 || top > 100 {
                bail!("report row limit must be between 1 and 100");
            }
            protocol_report(serial, session, after, top, json)?;
        }
        DeviceCommand::Acknowledge { session, through } => {
            protocol_acknowledge(serial, session, through)?;
        }
        DeviceCommand::Graph {
            session,
            after,
            entity,
            relation,
            strength,
            limit,
            json,
        } => {
            if limit == 0 || limit > 1000 {
                bail!("graph limit must be between 1 and 1000");
            }
            let strength = strength
                .as_deref()
                .map(|value| {
                    ksight_core::EdgeStrength::parse_name(value).ok_or_else(|| {
                        anyhow::anyhow!(
                            "strength must be confirmed, correlated, or inferred; got {value}"
                        )
                    })
                })
                .transpose()?;
            protocol_graph(
                serial,
                session,
                after,
                &ksight_core::GraphQuery {
                    entity,
                    relation,
                    strength,
                    limit,
                },
                json,
            )?;
        }
        DeviceCommand::Capture(options) => run_capture(serial, &options)?,
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_capture(serial: Option<&str>, options: &CaptureOptions) -> Result<()> {
    let json_flag = if options.json { " --json" } else { "" };
    let quiet_flag = if options.quiet { " --quiet" } else { "" };
    let threads_flag = if options.include_threads {
        " --include-threads"
    } else {
        ""
    };
    let files_flag = if options.files { " --files" } else { "" };
    let files_fd_flag = if options.files_fd { " --files-fd" } else { "" };
    let network_flag = if options.network { " --network" } else { "" };
    let network_io_flag = if options.network_io {
        " --network-io"
    } else {
        ""
    };
    let memory_flag = if options.memory { " --memory" } else { "" };
    let memory_all_flag = if options.memory_all {
        " --memory-all"
    } else {
        ""
    };
    let all_flag = if options.all { " --all" } else { "" };
    let binder_flag = if options.binder { " --binder" } else { "" };
    let sched_flag = if options.sched { " --sched" } else { "" };
    let pid_flag = options
        .pid
        .map_or_else(String::new, |value| format!(" --pid {value}"));
    let uid_flag = options
        .uid
        .map_or_else(String::new, |value| format!(" --uid {value}"));
    let package_flag = if let Some(value) = options.package.as_deref() {
        validate_package(value)?;
        format!(" --package {value}")
    } else {
        String::new()
    };
    if options.batch_events == 0 || options.batch_events > 1024 {
        bail!("batch event count must be between 1 and 1024");
    }
    if options.sample_one_in == 0 {
        bail!("sampling rate must be greater than zero");
    }
    let sampling_flag = format!(" --sample-one-in {}", options.sample_one_in);
    let spool_flag = if options.spool {
        format!(
            " --spool-dir {DEVICE_SPOOL_ROOT} --spool-max-mib {} --batch-events {}",
            options.spool_max_mib, options.batch_events
        )
    } else {
        String::new()
    };
    if options.inspect_linker
        && (options.inspect_tls
            || options
                .inspect_adapter
                .as_deref()
                .is_some_and(|name| name != "linker_so_load"))
    {
        bail!("--inspect-linker cannot be combined with --inspect-tls or a non-linker --inspect-adapter");
    }
    if options.inspect_all_apps
        && !(options.inspect_linker || options.inspect_tls || options.inspect_adapter.is_some())
    {
        bail!("--inspect-all-apps requires --inspect-tls, --inspect-linker, or --inspect-adapter");
    }
    if (options.inspect_linker || options.inspect_tls || options.inspect_adapter.is_some())
        && !options.inspect_all_apps
        && options.pid.is_none()
        && options.uid.is_none()
        && options.package.is_none()
    {
        bail!("inspect requires --package, --pid, or --uid; --inspect-all-apps is only for a whole-device test");
    }
    let inspect_linker_flag = if options.inspect_linker {
        " --inspect-linker"
    } else {
        ""
    };
    let inspect_tls_flag = if options.inspect_tls {
        " --inspect-tls"
    } else {
        ""
    };
    let inspect_all_apps_flag = if options.inspect_all_apps {
        " --inspect-all-apps"
    } else {
        ""
    };
    let inspect_max_bytes_flag = format!(" --inspect-max-bytes {}", options.inspect_max_bytes);
    let inspect_max_hits_flag = format!(" --inspect-max-hits {}", options.inspect_max_hits);
    let inspect_adapter_flag = options
        .inspect_adapter
        .as_deref()
        .map_or_else(String::new, |value| format!(" --inspect-adapter {value}"));
    let inspect_build_id_flag = options
        .inspect_build_id
        .as_deref()
        .map_or_else(String::new, |value| format!(" --inspect-build-id {value}"));
    let inspect_elf_flag = options
        .inspect_elf
        .as_deref()
        .map_or_else(String::new, |value| format!(" --inspect-elf {value}"));
    let inspect_offset_flag = options
        .inspect_offset
        .map_or_else(String::new, |value| format!(" --inspect-offset {value}"));
    let inspect_max_flag = format!(" --inspect-max-secs {}", options.inspect_max_secs);
    let command = format!(
        "{DEVICE_AGENT} capture --object {DEVICE_PROCESS_OBJECT} --file-object {DEVICE_FILE_OBJECT} --network-object {DEVICE_NETWORK_OBJECT} --memory-object {DEVICE_MEMORY_OBJECT} --binder-object {DEVICE_BINDER_OBJECT} --sched-object {DEVICE_SCHED_OBJECT} --uprobe-object {DEVICE_UPROBE_OBJECT} --count {} --duration-seconds {}{json_flag}{quiet_flag}{threads_flag}{files_flag}{files_fd_flag}{network_flag}{network_io_flag}{memory_flag}{memory_all_flag}{binder_flag}{sched_flag}{all_flag}{pid_flag}{uid_flag}{package_flag}{spool_flag}{sampling_flag}{inspect_linker_flag}{inspect_tls_flag}{inspect_all_apps_flag}{inspect_adapter_flag}{inspect_build_id_flag}{inspect_elf_flag}{inspect_offset_flag}{inspect_max_flag}{inspect_max_bytes_flag}{inspect_max_hits_flag}",
        options.count, options.duration_seconds
    );
    eprintln!(
        "ksightctl {} sends this capture to {DEVICE_AGENT} on the phone; hide-debug={} spool={} package={}. cargo run only rebuilds the host CLI; deploy with `cargo run -q -p ksight-cli -- device{} deploy`.",
        env!("CARGO_PKG_VERSION"),
        if options.hide_debug { "on" } else { "off" },
        if options.spool { "on" } else { "off" },
        options.package.as_deref().unwrap_or("-"),
        serial.map_or_else(String::new, |value| format!(" --serial {value}"))
    );
    if options.files && !options.files_fd {
        eprintln!("file sensor: openat only (dup/close off). Do not add --files-fd unless chasing FD leaks.");
    }
    if options.hide_debug {
        if !options.spool {
            bail!("--hide-debug requires --spool so the session can be pulled after ADB returns");
        }
        run_hide_debug_capture(serial, options.duration_seconds, &command)?;
    } else {
        let _ = run_device_tee(serial, &command)?;
    }
    if options.spool && !options.no_pull_forensics {
        match read_last_session(serial) {
            Ok(session) => {
                eprintln!("pulling forensics for {session}");
                if let Err(error) = pull_forensics(serial, session, &options.forensics_dir) {
                    eprintln!("forensics pull skipped: {error}");
                }
            }
            Err(error) => eprintln!("forensics pull skipped: {error}"),
        }
    }
    Ok(())
}
