//! `ksightd` device-service entry point.

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use ksight_agent::{
    capture::{
        CaptureRequest, MemorySelection, NetworkSelection, OutputOptions, SamplingOptions,
        SensorSelection, StorageOptions,
    },
    CapabilityProbe, HostCapabilityProbe,
};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "ksightd", version, about = "KernSight device agent")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Perform a read-only capability probe.
    Probe {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run the quiet long-lived collector in the foreground.
    Run {
        /// Versioned service JSON configuration.
        #[arg(long, default_value = "/data/local/tmp/ksight/ksightd.json")]
        config: PathBuf,
        /// Validate configuration without starting capture.
        #[arg(long)]
        dry_run: bool,
    },
    /// Inspect the detached collector lifecycle state.
    Status {
        /// Versioned service JSON configuration.
        #[arg(long, default_value = "/data/local/tmp/ksight/ksightd.json")]
        config: PathBuf,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Request a graceful detached-collector shutdown.
    Stop {
        /// Versioned service JSON configuration.
        #[arg(long, default_value = "/data/local/tmp/ksight/ksightd.json")]
        config: PathBuf,
    },
    /// Attach selected sensors and stream normalized whole-device runtime events.
    Capture(Box<CaptureArgs>),
    /// Inspect, replay, or acknowledge durable capture batches.
    Spool {
        /// Durable spool root.
        #[arg(long, default_value = "/data/local/tmp/ksight/spool")]
        root: PathBuf,
        #[command(subcommand)]
        command: SpoolCommand,
    },
    /// Serve the framed durable-session protocol over stdin/stdout.
    Serve {
        /// Durable spool root.
        #[arg(long, default_value = "/data/local/tmp/ksight/spool")]
        spool_root: PathBuf,
    },
    /// Copy one installed package's APK, native libraries, and live DEX/SO images.
    DumpPackage {
        /// Exact Android package name.
        #[arg(long)]
        package: String,
        /// Device directory that receives the copied artifacts.
        #[arg(long)]
        dest: PathBuf,
        /// Force-stop, launch the package, then dump live process images.
        #[arg(long)]
        launch: bool,
        /// Skip install APK/lib/oat; dest is the pullable evidence folder for this package.
        #[arg(long, alias = "evidence-only")]
        runtime_only: bool,
        /// Yield after ART attach so a hide-debug wrapper can clear USB debugging before launch.
        #[arg(long)]
        hide_debug: bool,
        /// If Magisk is present, add the package to `DenyList` for this dump window. Not a root-hide claim.
        #[arg(long)]
        denylist: bool,
        /// Print the full dump-report JSON (default is a short summary).
        #[arg(long)]
        json: bool,
    },
    /// Rebuild dump-report artifacts and correlated VMA/maps graph without a live dump.
    RecatalogPackage {
        /// Device directory that already holds a package dump.
        #[arg(long)]
        dest: PathBuf,
        /// Print the full dump-report JSON (default is a short summary).
        #[arg(long)]
        json: bool,
    },
    /// Copy bounded live mappings of one process. L2 forensic; pauses the target.
    Snapshot {
        /// Exact Android package name. Resolves its live PID when `--pid` is omitted.
        #[arg(long)]
        package: Option<String>,
        /// Target process ID.
        #[arg(long)]
        pid: Option<u32>,
        /// Device directory that receives `snapshot-report.json` and range files.
        #[arg(long)]
        dest: PathBuf,
        /// Inclusive hex or decimal virtual address. Requires `--end`.
        #[arg(long)]
        start: Option<String>,
        /// Exclusive hex or decimal virtual address. Requires `--start`.
        #[arg(long)]
        end: Option<String>,
        /// Maximum copied MiB (hard cap per snapshot).
        #[arg(long, default_value_t = 32)]
        max_mib: u64,
        /// Copy without `SIGSTOP`. Pages may tear; report marks `torn=true`.
        #[arg(long)]
        no_pause: bool,
    },
    /// Enforce bounded retention under an approved package-dump root.
    PrunePackages {
        /// `/data/local/tmp/ksight/packages` or the published `Download/dexDump` root.
        #[arg(long)]
        root: PathBuf,
        /// Maximum total retained MiB; zero disables the byte bound.
        #[arg(long)]
        max_total_mib: u64,
        /// Maximum package directories retained, newest first.
        #[arg(long, default_value_t = 8)]
        keep: usize,
    },
}

#[derive(Debug, Subcommand)]
enum SpoolCommand {
    /// List durable capture sessions and their unacknowledged ranges.
    List,
    /// Emit unacknowledged batches as protocol JSON Lines without deleting them.
    Replay {
        /// Capture session to replay.
        session: Uuid,
    },
    /// Delete only the contiguous batch range confirmed by the client.
    Acknowledge {
        /// Capture session owning the confirmed batches.
        session: Uuid,
        /// Highest contiguous batch sequence safely received by the client.
        #[arg(long)]
        through: u64,
    },
}

#[derive(Debug, clap::Args)]
// Independent CLI switches are clearer than a positional or combinatorial sensor enum.
#[allow(clippy::struct_excessive_bools)]
struct CaptureArgs {
    /// Compiled process lifecycle BPF object.
    #[arg(long, default_value = "/data/local/tmp/ksight/process_lifecycle.bpf.o")]
    object: PathBuf,
    /// Compiled file-open BPF object.
    #[arg(long, default_value = "/data/local/tmp/ksight/file_open.bpf.o")]
    file_object: PathBuf,
    /// Compiled socket-connect BPF object.
    #[arg(long, default_value = "/data/local/tmp/ksight/network_connect.bpf.o")]
    network_object: PathBuf,
    /// Compiled memory-region BPF object.
    #[arg(long, default_value = "/data/local/tmp/ksight/memory_regions.bpf.o")]
    memory_object: PathBuf,
    /// Compiled Binder transaction BPF object.
    #[arg(
        long,
        default_value = "/data/local/tmp/ksight/binder_transaction.bpf.o"
    )]
    binder_object: PathBuf,
    /// Compiled scheduler wakeup BPF object.
    #[arg(long, default_value = "/data/local/tmp/ksight/sched_wakeup.bpf.o")]
    sched_object: PathBuf,
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
    /// Enable scheduler wakeup capture (requires --pid/--uid/--package).
    #[arg(long)]
    sched: bool,
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
    /// Capture only this process/thread-group ID.
    #[arg(long)]
    pid: Option<u32>,
    /// Capture only this effective Linux UID.
    #[arg(long)]
    uid: Option<u32>,
    /// Capture only this exact Android package, including its colon processes.
    #[arg(long)]
    package: Option<String>,
    /// Persist immutable event batches beneath this directory.
    #[arg(long)]
    spool_dir: Option<PathBuf>,
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
    /// Enable bounded `SSL_write` plaintext for one app. Pair with `--package` during a short test.
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
    /// Named Inspect adapter. May be combined with `--inspect-tls` (for example `binder_userspace`).
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
    /// Compiled uprobe object used by Inspect adapters.
    #[arg(long, default_value = "/data/local/tmp/ksight/uprobe_regs.bpf.o")]
    uprobe_object: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    if matches!(
        &args.command,
        Command::Run { .. }
            | Command::Status { .. }
            | Command::Stop { .. }
            | Command::Capture(_)
            | Command::DumpPackage { .. }
    ) {
        ksight_agent::embedded::prepare_default_layout()?;
    }
    match args.command {
        Command::Probe { json } => probe(json),
        Command::Run { config, dry_run } => run_service(&config, dry_run),
        Command::Status { config, json } => show_service_status(&config, json),
        Command::Stop { config } => stop_service(&config),
        Command::Capture(args) => run_capture(*args),
        Command::Spool { root, command } => manage_spool(&root, &command),
        Command::Serve { spool_root } => serve_stdio(spool_root),
        Command::DumpPackage {
            package,
            dest,
            launch,
            runtime_only,
            hide_debug,
            denylist,
            json,
        } => dump_package(
            &package,
            &dest,
            launch,
            runtime_only,
            hide_debug,
            denylist,
            json,
        ),
        Command::RecatalogPackage { dest, json } => recatalog_package(&dest, json),
        Command::Snapshot {
            package,
            pid,
            dest,
            start,
            end,
            max_mib,
            no_pause,
        } => run_snapshot(
            package,
            pid,
            &dest,
            start.as_deref(),
            end.as_deref(),
            max_mib,
            no_pause,
        ),
        Command::PrunePackages {
            root,
            max_total_mib,
            keep,
        } => {
            let max = max_total_mib
                .checked_mul(1024 * 1024)
                .ok_or_else(|| anyhow::anyhow!("package retention byte bound overflows"))?;
            let report = ksight_agent::dump::prune_package_dumps(&root, max, keep)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
    }
}

#[allow(clippy::fn_params_excessive_bools)]
fn dump_package(
    package: &str,
    dest: &std::path::Path,
    launch: bool,
    runtime_only: bool,
    hide_debug: bool,
    denylist: bool,
    json: bool,
) -> Result<()> {
    let report = ksight_agent::dump::dump_package_with(
        package,
        dest,
        &ksight_agent::dump::DumpOptions {
            launch,
            runtime_only,
            hide_debug,
            denylist,
        },
    )?;
    print_dump_report(dest, &report, json)
}

fn recatalog_package(dest: &std::path::Path, json: bool) -> Result<()> {
    let report = ksight_agent::dump::recatalog_package(dest)?;
    print_dump_report(dest, &report, json)
}

fn parse_addr(value: &str) -> Result<u64> {
    let text = value.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
            .map_err(|error| anyhow::anyhow!("invalid address {value}: {error}"))
    } else {
        text.parse::<u64>()
            .map_err(|error| anyhow::anyhow!("invalid address {value}: {error}"))
    }
}

fn run_snapshot(
    package: Option<String>,
    pid: Option<u32>,
    dest: &std::path::Path,
    start: Option<&str>,
    end: Option<&str>,
    max_mib: u64,
    no_pause: bool,
) -> Result<()> {
    let max_bytes = max_mib
        .checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow::anyhow!("snapshot byte bound overflows"))?;
    let report = ksight_agent::snapshot::snapshot(ksight_agent::snapshot::SnapshotRequest {
        dest: dest.to_path_buf(),
        package,
        pid,
        start: start.map(parse_addr).transpose()?,
        end: end.map(parse_addr).transpose()?,
        max_bytes,
        pause: !no_pause,
    })?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "pid": report.pid,
            "package": report.package,
            "paused": report.paused,
            "torn": report.torn,
            "elapsed_ms": report.elapsed_ms,
            "copied_bytes": report.copied_bytes,
            "ranges": report.ranges.len(),
            "truncated": report.truncated,
            "snapshot_report": dest.join("snapshot-report.json").to_string_lossy(),
        }))?
    );
    Ok(())
}

fn print_dump_report(
    dest: &std::path::Path,
    report: &ksight_agent::dump::PackageDumpReport,
    json: bool,
) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "package": report.package,
            "dump_id": report.dump_id,
            "launched": report.launched,
            "pids": report.pids,
            "readable_dex": report.readable_dex,
            "runtime_blob_dex": report.runtime_blob_dex,
            "apk_dex": report.apk_dex,
            "private_files": report.private_files,
            "runtime_libs": report.runtime_libs,
            "artifacts": report.artifacts.len(),
            "snapshots": report.snapshots.len(),
            "stitched_spans": report.stitched_spans,
            "mapped_code": report.mapped_code.len(),
            "code_loaders": report.code_loaders.len(),
            "art_open_joined": report
                .code_loaders
                .iter()
                .filter(|loader| loader.origin == "art_open" && loader.joined_sha256.is_some())
                .count(),
            "graph_edges": report.graph.edges.len(),
            "usb_debugging": report.observation_env.usb_debugging,
            "hide_debug": report.observation_env.hide_debug_requested,
            "denylist": report.observation_env.denylist_applied,
            "dump_report": dest.join("dump-report.json").to_string_lossy(),
        }))?
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_capture(args: CaptureArgs) -> Result<()> {
    if args.sample_one_in == 0 {
        bail!("sampling rate must be greater than zero");
    }
    let inspect_adapter_set = args.inspect_adapter.is_some();
    let mut inspect_adapters = Vec::new();
    if args.inspect_tls {
        inspect_adapters.push(ksight_agent::inspect_runtime::InspectAdapterKind::TlsSslWrite);
    }
    if args.inspect_linker {
        inspect_adapters.push(ksight_agent::inspect_runtime::InspectAdapterKind::LinkerSoLoad);
    }
    if let Some(name) = args.inspect_adapter.as_deref() {
        let parsed = name
            .parse::<ksight_agent::inspect_runtime::InspectAdapterKind>()
            .map_err(anyhow::Error::msg)?;
        if !inspect_adapters.contains(&parsed) {
            inspect_adapters.push(parsed);
        }
    }
    if args.inspect_linker
        && inspect_adapters.iter().any(|adapter| {
            *adapter != ksight_agent::inspect_runtime::InspectAdapterKind::LinkerSoLoad
        })
    {
        bail!("--inspect-linker cannot be combined with --inspect-tls or a non-linker --inspect-adapter");
    }
    if inspect_adapters.is_empty() {
        inspect_adapters.push(ksight_agent::inspect_runtime::InspectAdapterKind::LinkerSoLoad);
    }
    let inspect_enabled = args.inspect_linker || args.inspect_tls || inspect_adapter_set;
    if args.inspect_all_apps && !inspect_enabled {
        bail!("--inspect-all-apps requires --inspect-tls, --inspect-linker, or --inspect-adapter");
    }
    if inspect_enabled
        && !args.inspect_all_apps
        && args.pid.is_none()
        && args.uid.is_none()
        && args.package.is_none()
    {
        bail!("inspect requires --package, --pid, or --uid; --inspect-all-apps is only for a whole-device test");
    }
    let inspect = ksight_core::InspectPolicy {
        enabled: inspect_enabled,
        pid: args.pid,
        uid: args.uid,
        package: args.package.clone(),
        elf_path: args.inspect_elf,
        build_id: args.inspect_build_id,
        offset: args.inspect_offset,
        max_hits: args.inspect_max_hits,
        max_duration_secs: args.inspect_max_secs,
        whole_device: args.inspect_all_apps,
        max_payload_bytes: args.inspect_max_bytes.clamp(1, 4096),
        ..ksight_core::InspectPolicy::default()
    };
    ksight_agent::capture::run(CaptureRequest {
        collector_mode: ksight_model::CollectorMode::ForegroundAdb,
        status: None,
        process_object: args.object,
        file_object: args.file_object,
        network_object: args.network_object,
        memory_object: args.memory_object,
        binder_object: args.binder_object,
        sched_object: args.sched_object,
        sensors: SensorSelection {
            files: args.files || args.all,
            file_descriptors: args.files_fd,
            network: if args.network_io {
                NetworkSelection::Io
            } else if args.network || args.all {
                NetworkSelection::Lifecycle
            } else {
                NetworkSelection::Disabled
            },
            memory: if args.memory_all {
                MemorySelection::All
            } else if args.memory || args.all {
                MemorySelection::Executable
            } else {
                MemorySelection::Disabled
            },
            binder: args.binder || args.all,
            sched: args.sched,
        },
        output: OutputOptions {
            json: args.json,
            include_threads: args.include_threads,
            quiet: args.quiet,
        },
        storage: StorageOptions {
            spool_root: args.spool_dir,
            max_spool_bytes: args
                .spool_max_mib
                .checked_mul(1024 * 1024)
                .ok_or_else(|| anyhow::anyhow!("spool capacity overflows u64 bytes"))?,
            events_per_batch: args.batch_events,
            ..StorageOptions::default()
        },
        sampling: SamplingOptions {
            process: 1,
            file: args.sample_one_in,
            network: args.sample_one_in,
            memory: args.sample_one_in,
            binder: args.sample_one_in,
            sched: args.sample_one_in,
        },
        count: args.count,
        duration_seconds: args.duration_seconds,
        pid: args.pid,
        uid: args.uid,
        package: args.package,
        inspect,
        inspect_adapters,
        uprobe_object: args.uprobe_object,
    })
}

fn run_service(path: &std::path::Path, dry_run: bool) -> Result<()> {
    let config = ksight_agent::service::ServiceConfig::load(path)?;
    config.validate_runtime_paths()?;
    if dry_run {
        println!(
            "service configuration valid: schema={} spool={} batch_events={}",
            config.schema_version,
            config.storage.spool_root.display(),
            config.storage.events_per_batch
        );
        return Ok(());
    }
    let _lease = ksight_agent::service::ServiceLease::acquire(&config.lock_file)?;
    let status =
        ksight_agent::service::ServiceStatusGuard::publish(&config.status_file, path, &config)?;
    let mut request = config.capture_request()?;
    request.status = Some(status.handle());
    let result = ksight_agent::capture::run(request);
    if let Err(error) = &result {
        let retention = ksight_agent::retention::SpoolRetention {
            root: config.storage.spool_root.clone(),
            max_total_bytes: config
                .storage
                .max_total_spool_mib
                .saturating_mul(1024 * 1024),
            keep_completed: config.storage.keep_completed_sessions,
        };
        let _ = retention.write_last_exit(&ksight_agent::retention::ExitRecord {
            session_id: None,
            reason: "error".to_owned(),
            detail: Some(error.to_string()),
            clean: false,
        });
    }
    result
}

fn show_service_status(path: &std::path::Path, json: bool) -> Result<()> {
    let status = ksight_agent::service::inspect_service(path)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!(
            "state={:?} pid={} started_monotonic_ns={} executable={}",
            status.state,
            status
                .pid
                .map_or_else(|| "-".to_owned(), |pid| pid.to_string()),
            status
                .started_monotonic_ns
                .map_or_else(|| "-".to_owned(), |value| value.to_string()),
            status
                .executable
                .as_deref()
                .map_or_else(|| "-".to_owned(), |value| value.display().to_string())
        );
    }
    Ok(())
}

fn stop_service(path: &std::path::Path) -> Result<()> {
    let status = ksight_agent::service::stop_service(path)?;
    println!(
        "graceful stop requested: pid={}",
        status
            .pid
            .map_or_else(|| "-".to_owned(), |pid| pid.to_string())
    );
    Ok(())
}

fn serve_stdio(spool_root: PathBuf) -> Result<()> {
    use ksight_agent::{
        control::ControlSession,
        transport::{SplitFramedTransport, Transport as _},
    };
    use ksight_protocol::Capability;

    let input = std::io::stdin();
    let output = std::io::stdout();
    let mut transport = SplitFramedTransport::new(input.lock(), output.lock());
    let mut session = ControlSession::new(
        spool_root,
        env!("CARGO_PKG_VERSION"),
        vec![
            Capability {
                name: "framed_json".to_owned(),
                version: 1,
            },
            Capability {
                name: "durable_spool".to_owned(),
                version: 2,
            },
            Capability {
                name: "get_status".to_owned(),
                version: 1,
            },
        ],
    );
    while let Some(message) = transport.receive()? {
        for response in session.handle(message)? {
            transport.send(&response)?;
        }
    }
    Ok(())
}

fn manage_spool(root: &std::path::Path, command: &SpoolCommand) -> Result<()> {
    use ksight_agent::spool::{inspect_root, DirectorySpool, Spool as _};
    use ksight_protocol::Message;

    match command {
        SpoolCommand::List => {
            println!("{}", serde_json::to_string_pretty(&inspect_root(root)?)?);
        }
        SpoolCommand::Replay { session } => {
            ksight_agent::spool::visit_batches(
                root.join(session.to_string()),
                *session,
                None,
                |batch| {
                    println!(
                        "{}",
                        serde_json::to_string(&Message::EventBatch(batch))
                            .map_err(ksight_agent::spool::SpoolError::from)?
                    );
                    Ok(())
                },
            )?;
        }
        SpoolCommand::Acknowledge { session, through } => {
            let mut spool =
                DirectorySpool::open_existing(root.join(session.to_string()), u64::MAX)?;
            spool.acknowledge_through(*through)?;
            println!(
                "acknowledged session={session} through={through} remaining_bytes={}",
                spool.used_bytes()
            );
        }
    }
    Ok(())
}

fn probe(json: bool) -> Result<()> {
    let report = HostCapabilityProbe.probe();
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    println!("target: {}/{}", report.target_os, report.architecture);
    println!("android: {}", report.android);
    println!(
        "kernel: {}",
        report.kernel_release.as_deref().unwrap_or("unknown")
    );
    println!("root: {}", report.running_as_root);
    println!("btf: {}", report.btf_readable);
    println!("bpffs: {}", report.bpffs_mounted);
    println!("tracefs: {}", report.tracefs_mounted);
    for tracepoint in report.tracepoints {
        println!(
            "tracepoint {}: present={} format={} attachable={}",
            tracepoint.name,
            tracepoint.available,
            tracepoint
                .format_compatible
                .map_or("not-checked".to_owned(), |value| value.to_string()),
            tracepoint
                .attachable
                .map_or("not-tested".to_owned(), |value| value.to_string())
        );
    }
    for note in report.notes {
        println!("note: {note}");
    }
    Ok(())
}
