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
    /// Explicit isolated runtime directory; legacy CLI defaults are unchanged.
    #[arg(long, global = true)]
    runtime_root: Option<PathBuf>,
    #[arg(long, global = true, requires = "runtime_root")]
    expected_agent_path: Option<PathBuf>,
    #[arg(long, global = true, requires = "runtime_root")]
    expected_agent_sha256: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Audit configured library rules without loading probes or inspecting Apps.
    RulesAudit {
        /// JSON rules file; otherwise inspect the device table, or embedded defaults if absent.
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Emit machine-readable diagnostics (never implies runtime verification).
        #[arg(long)]
        json: bool,
    },
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
    /// Cooperative control of one exact parent-owned attempt. Never signals a target.
    CaptureControl {
        #[arg(long)]
        parent_session: Uuid,
        #[arg(long)]
        stage_id: Uuid,
        #[arg(long)]
        attempt_id: Uuid,
        #[arg(long)]
        stage_attempt: u32,
        #[arg(long)]
        stage_key: String,
        #[arg(long,value_parser=["status","stop"])]
        action: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Read-only status of verified code-only collection scope.
    CodeCapabilities,
    /// Read-only full-path inventory beneath a selected capture root.
    EvidenceInventory {
        #[arg(long)]
        root: PathBuf,
    },
    /// Copy one installed package's APK, native libraries, and live DEX/SO images.
    DumpPackage {
        #[arg(long)]
        expected_code_sources: Option<String>,
        #[arg(long)]
        code_only: bool,
        /// Payload output-write allowance; terminal metadata reserves 64KiB separately.
        #[arg(long)]
        output_budget_bytes: Option<u64>,
        #[arg(long)]
        output_budget_ms: Option<u64>,
        #[arg(long)]
        collect_keys: bool,
        #[arg(long)]
        collect_private: bool,
        #[arg(long)]
        collect_memory_windows: bool,
        #[arg(long)]
        parent_session: Option<uuid::Uuid>,
        #[arg(long)]
        stage_id: Option<uuid::Uuid>,
        #[arg(long)]
        attempt_id: Option<uuid::Uuid>,
        #[arg(long)]
        stage_attempt: Option<u32>,
        #[arg(long)]
        stage_key: Option<String>,

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
    /// Mark stale running sessions as interrupted after their collector has exited.
    Repair,
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
    #[arg(long)]
    launch_after_attach: bool,
    #[arg(long)]
    code_only: bool,
    #[arg(long)]
    output_budget_bytes: Option<u64>,
    #[arg(long)]
    output_budget_ms: Option<u64>,
    #[arg(long)]
    collect_keys: bool,
    #[arg(long)]
    collect_memory_windows: bool,
    #[arg(long)]
    stage_links: Option<String>,
    #[arg(long)]
    parent_session: Option<uuid::Uuid>,
    #[arg(long)]
    stage_id: Option<uuid::Uuid>,
    #[arg(long)]
    attempt_id: Option<uuid::Uuid>,
    #[arg(long)]
    stage_attempt: Option<u32>,
    #[arg(long)]
    stage_key: Option<String>,

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
    /// Opt-in sequential Inspect windows; L0 sensors persist. Legacy flags remain exclusive.
    #[arg(long, value_name = "l0:SECONDS,l1:SECONDS,linker:SECONDS", conflicts_with_all = ["inspect_linker", "inspect_tls", "inspect_jni", "inspect_adapter", "inspect_all_apps", "mirror_http", "mitm_burp", "inspect_max_secs", "inspect_elf", "inspect_offset", "inspect_build_id"])]
    inspect_stages: Option<String>,
    /// Enable bounded `SSL_write` plaintext for one app. Pair with `--package` during a short test.
    #[arg(long)]
    inspect_tls: bool,
    /// Enable `JNIEnv` UTF-8/`byte[]` Inspect via exported `GetFunctionTable`. May combine with `--inspect-tls` and `binder_userspace`.
    #[arg(long)]
    inspect_jni: bool,
    /// Inspect every app mapping the adapter ELF. Noisy; prefer `--package`.
    #[arg(long)]
    inspect_all_apps: bool,
    /// Maximum plaintext bytes reconstructed per hit (hard cap 256 KiB).
    #[arg(long, default_value_t = 65536)]
    inspect_max_bytes: u32,
    /// Maximum Inspect hits; 0 uses the adapter default.
    #[arg(long, default_value_t = 0)]
    inspect_max_hits: u32,
    /// Named Inspect adapter (`binder_userspace`, `jni_plaintext`, ...). May be combined with `--inspect-tls`.
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
    /// Burp HTTP proxy `host:port`. Copies TLS HTTP/WS to that listener; app TLS is unchanged.
    #[arg(long, alias = "mirror-burp", value_name = "HOST:PORT")]
    mirror_http: Option<String>,
    /// Require the minimal mirror contract; old agents reject this marker.
    #[arg(long, requires = "mirror_http")]
    minimal_mirror: bool,
    /// Transparent UID REDIRECT of 80/443 to Burp (CONNECT uses SNI). Pinning still applies.
    #[arg(long)]
    mitm_burp: bool,
}

fn capability_failure(error: &anyhow::Error) -> serde_json::Value {
    serde_json::json!({
        "error_chain": error.chain().map(ToString::to_string).collect::<Vec<_>>(),
        "errno": error.chain().find_map(|e| e.downcast_ref::<std::io::Error>().and_then(std::io::Error::raw_os_error)),
    })
}

fn runtime_agent_hash() -> Option<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(std::env::current_exe().ok()?).ok()?;
    Some(format!("{:x}", Sha256::digest(bytes)))
}
/// Route the actual parsed production paths, never rewrite payload text.
fn route_command_paths(command: &mut Command) -> Result<()> {
    route_command_paths_at(command, &ksight_agent::runtime_paths::root())
}
fn route_command_paths_at(command: &mut Command, root: &std::path::Path) -> Result<()> {
    let route = |path: &std::path::Path| ksight_agent::runtime_paths::route_at(path, root);
    match command {
        Command::Capture(c) => {
            for p in [
                &mut c.object,
                &mut c.file_object,
                &mut c.network_object,
                &mut c.memory_object,
                &mut c.binder_object,
                &mut c.sched_object,
                &mut c.uprobe_object,
            ] {
                *p = route(p)?;
            }
            if let Some(p) = &mut c.spool_dir {
                *p = route(p)?;
            }
        }
        Command::DumpPackage { dest, .. } | Command::RecatalogPackage { dest, .. } => {
            *dest = route(dest)?;
        }
        Command::Spool { root, .. } | Command::EvidenceInventory { root, .. } => {
            *root = route(root)?;
        }
        Command::Serve { spool_root, .. } => {
            *spool_root = route(spool_root)?;
        }
        Command::CaptureControl { .. } | Command::CodeCapabilities | Command::Probe { .. } => {}
        _ => bail!(
            "runtime-root supports capture/dump/control/spool/inventory capability commands only"
        ),
    }
    Ok(())
}

fn validate_isolated_command(command: &Command) -> Result<()> {
    match command {
        Command::Capture(c) if c.parent_session.is_none() || c.collect_keys || c.collect_memory_windows => bail!("isolated capture requires parent scope; auxiliary scans not-supported"),
        Command::DumpPackage{parent_session,collect_keys,collect_private,collect_memory_windows,hide_debug,denylist,launch,..} if parent_session.is_none() || *collect_keys || *collect_private || *collect_memory_windows || *hide_debug || *denylist || *launch => bail!("isolated dump requires existing parent instance; auxiliary scans/launch not-supported"),
        _=>Ok(()),
    }
}
#[allow(
    clippy::too_many_lines,
    reason = "Keep the admission or lifecycle transaction together for review."
)]
fn main() -> Result<()> {
    let mut args = Args::parse();
    if let Some(root) = args.runtime_root.as_ref() {
        if let Some(path) = &args.expected_agent_path {
            ksight_agent::runtime_paths::validate_shape(path)?;
            ksight_agent::runtime_paths::no_symlinks(path)?;
            if std::env::current_exe()? != *path {
                bail!("candidate executable identity path differs");
            }
        }
        if let Some(expected) = &args.expected_agent_sha256 {
            if expected.len() != 64
                || !expected
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                || runtime_agent_hash().as_ref() != Some(expected)
            {
                bail!("candidate complete SHA256 differs");
            }
        }
        ksight_agent::runtime_paths::configure(root)?;
        validate_isolated_command(&args.command)?;
        route_command_paths(&mut args.command)?;
    }

    if let Command::DumpPackage {
        parent_session,
        stage_id,
        attempt_id,
        stage_attempt,
        stage_key,
        code_only,
        ..
    } = &args.command
    {
        if *code_only {
            ksight_core::capture_scope::require_code_collection_backend()
                .map_err(anyhow::Error::msg)?;
        }
        let relation = ksight_agent::capture_relation::CaptureRelation::parse(
            *parent_session,
            *stage_id,
            *attempt_id,
            *stage_attempt,
            stage_key.clone(),
        )?;
        if relation.as_ref().is_some_and(|r| r.stage_key != "dump") {
            bail!("dump-package requires dump stage key");
        }
    }
    if matches!(
        &args.command,
        Command::Run { .. }
            | Command::Status { .. }
            | Command::Stop { .. }
            | Command::DumpPackage { .. }
    ) {
        ksight_agent::embedded::prepare_default_layout()?;
    }
    match args.command {
        Command::CaptureControl {
            parent_session,
            stage_id,
            attempt_id,
            stage_attempt,
            stage_key,
            action,
            reason,
        } => {
            let relation = ksight_agent::capture_relation::CaptureRelation::parse(
                Some(parent_session),
                Some(stage_id),
                Some(attempt_id),
                Some(stage_attempt),
                Some(stage_key),
            )?
            .unwrap();
            let base = ksight_agent::runtime_paths::captures();
            let root = ksight_agent::capture_lifecycle::control_root(&base, &relation);
            if !root.canonicalize()?.starts_with(base.canonicalize()?) {
                bail!("lifecycle root escapes captures");
            }
            let status = if action == "stop" {
                ksight_agent::capture_lifecycle::request_stop(
                    &root,
                    &relation,
                    reason
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("stop requires reason"))?,
                )?
            } else {
                ksight_agent::capture_lifecycle::inspect(&root, &relation)?
            };
            println!("{}", serde_json::to_string(&status)?);
            Ok(())
        }
        Command::CodeCapabilities => {
            let status = ksight_agent::qualified_code::capability();
            println!(
                "{}",
                serde_json::json!({"schema":"kernsight.code-capabilities/v1","supported":status.is_ok(),"reason":status.as_ref().err().map(|e|format!("{e:#}")),"failure":status.as_ref().err().map(capability_failure),"instance_state":"not-yet-qualified","code_scope":"main process; registered named/executable mappings only; unregistered anonymous/FD scans not-supported","agent_version":env!("CARGO_PKG_VERSION"),"lifecycle_schema":"kernsight.capture-lifecycle/v1","code_copy_pause":"forbidden","runtime_paths_schema":"kernsight.runtime-paths/v1","runtime_root":ksight_agent::runtime_paths::root(),"agent_sha256":runtime_agent_hash(),"agent_path":std::env::current_exe().ok(),"parent_lifecycle_supported":cfg!(any(target_os="linux",target_os="android")) && std::fs::read_to_string("/proc/sys/kernel/random/boot_id").is_ok() && std::fs::read_to_string("/proc/self/stat").is_ok()})
            );
            Ok(())
        }
        Command::EvidenceInventory { root } => {
            if root
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
                || !root
                    .canonicalize()?
                    .starts_with(&ksight_agent::runtime_paths::captures().canonicalize()?)
            {
                bail!("inventory requires selected capture root");
            }
            println!(
                "{}",
                serde_json::to_string(&ksight_agent::evidence_inventory::inventory(&root)?)?
            );
            Ok(())
        }
        Command::RulesAudit { rules, json } => rules_audit(rules.as_deref(), json),
        Command::Probe { json } => probe(json),
        Command::Run { config, dry_run } => run_service(&config, dry_run),
        Command::Status { config, json } => show_service_status(&config, json),
        Command::Stop { config } => stop_service(&config),
        Command::Capture(args) => run_capture(*args),
        Command::Spool { root, command } => manage_spool(&root, &command),
        Command::Serve { spool_root } => serve_stdio(spool_root),
        Command::DumpPackage {
            expected_code_sources,
            code_only,
            output_budget_bytes,
            output_budget_ms,
            collect_keys,
            collect_private,
            collect_memory_windows,
            parent_session,
            stage_id,
            attempt_id,
            stage_attempt,
            stage_key,
            package,
            dest,
            launch,
            runtime_only,
            hide_debug,
            denylist,
            json,
        } => {
            let relation = ksight_agent::capture_relation::CaptureRelation::parse(
                parent_session,
                stage_id,
                attempt_id,
                stage_attempt,
                stage_key,
            )?;
            if let Some(r) = relation.as_ref() {
                if r.stage_key != "dump" {
                    bail!("dump-package requires dump stage key");
                }
                r.retain(&dest, None, Some(&package))?;
            }
            dump_package(
                &package,
                &dest,
                launch,
                runtime_only,
                hide_debug,
                denylist,
                json,
                code_only,
                collect_keys,
                collect_private,
                collect_memory_windows,
                output_budget_bytes,
                output_budget_ms,
                relation.as_ref(),
                expected_code_sources.as_deref(),
            )
        }
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

fn rules_audit(path: Option<&std::path::Path>, json: bool) -> Result<()> {
    use std::io::Read as _;
    let selected =
        path.unwrap_or_else(|| std::path::Path::new(ksight_core::STACK_RULES_DEVICE_PATH));
    let (text, source) = match std::fs::File::open(selected) {
        Ok(file) => {
            let mut text = String::new();
            file.take(ksight_core::STACK_AUDIT_MAX_BYTES as u64 + 1)
                .read_to_string(&mut text)?;
            (text, selected.display().to_string())
        }
        Err(error) if path.is_none() && error.kind() == std::io::ErrorKind::NotFound => (
            ksight_core::EMBEDDED_STACK_RULES.to_owned(),
            "embedded".to_owned(),
        ),
        Err(error) => bail!("cannot read rules {}: {error}", selected.display()),
    };
    let report =
        ksight_core::audit_stack_rules_json(&text).map_err(|error| anyhow::anyhow!(error))?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"source": source, "report": report}))?
        );
    } else {
        println!(
            "source={source} rules={} valid={} runtime_verification=not_assessed",
            report.rule_count, report.valid
        );
        for error in &report.errors {
            println!("ERROR: {error}");
        }
        for row in &report.rules {
            println!("{}: identity={} plaintext_configured={} keylog_configured={} runtime_verification={}",
                row.id, row.identity_basis, row.plaintext_configured, row.keylog_configured, row.runtime_verification);
            for diagnostic in &row.diagnostics {
                println!("  {diagnostic}");
            }
        }
        for limitation in &report.limitations {
            println!("NOTE: {limitation}");
        }
    }
    if !report.valid {
        bail!("library rule validation failed; no capture started");
    }
    Ok(())
}

#[allow(clippy::fn_params_excessive_bools)]
#[allow(
    clippy::too_many_arguments,
    reason = "Keep the admission or lifecycle transaction together for review."
)]
fn dump_package(
    package: &str,
    dest: &std::path::Path,
    launch: bool,
    runtime_only: bool,
    hide_debug: bool,
    denylist: bool,
    json: bool,
    code_only: bool,
    collect_keys: bool,
    collect_private: bool,
    collect_memory_windows: bool,
    output_budget_bytes: Option<u64>,
    output_budget_ms: Option<u64>,
    relation: Option<&ksight_agent::capture_relation::CaptureRelation>,
    expected_code_sources: Option<&str>,
) -> Result<()> {
    if relation.is_some() && launch {
        bail!("not-supported: parent dump requires the existing capture instance; launch via parent capture first; standalone --launch is unchanged");
    }
    let guard = budget_guard(vec![dest.to_owned()], output_budget_bytes, output_budget_ms)?;
    if relation.is_some()
        && (collect_keys || collect_private || collect_memory_windows || hide_debug || denylist)
    {
        bail!("parent lifecycle cannot attest optional auxiliary cleanup");
    }
    let lifecycle = {
        relation
            .map(|r| {
                ksight_agent::capture_lifecycle::Lease::begin(
                    &ksight_agent::capture_lifecycle::control_root(
                        &ksight_agent::runtime_paths::captures(),
                        r,
                    ),
                    r,
                    vec![dest.to_owned()],
                    output_budget_ms
                        .ok_or_else(|| anyhow::anyhow!("parent lifecycle requires deadline"))?,
                    true,
                )
            })
            .transpose()?
    };
    let result = (|| {
        let report = ksight_agent::dump::dump_package_with(
            package,
            dest,
            &ksight_agent::dump::DumpOptions {
                launch,
                runtime_only,
                hide_debug,
                denylist,
                code_only,
                collect_keys,
                collect_private,
                collect_memory_windows,
                parent_owned: relation.is_some(),
                expected_code_sources: expected_code_sources
                    .map(serde_json::from_str::<Vec<ksight_agent::qualified_code::SourceIdentity>>)
                    .transpose()?,
            },
        )?;
        print_dump_report(dest, &report, json)
    })();
    if let Some(g) = guard.as_ref() {
        let receipt = g.receipt();
        let body = serde_json::to_vec(&receipt)?;
        std::fs::create_dir_all(dest)?;
        std::fs::write(dest.join("budget-receipt.json"), &body)?;
        if !dest.join("dump-report.json").exists() && (receipt.partial || result.is_err()) {
            std::fs::write(
                dest.join("dump-report.json"),
                serde_json::to_vec(
                    &serde_json::json!({"schema_version":"mobilee.kernsight-package-dump/v2","package":package,"dump_id":uuid::Uuid::new_v4(),"collection_status":"partial","budget":receipt,"artifacts":[],"warnings":["budget/IO terminated collection; retained raw paths are preserved; coverage unknown"]}),
                )?,
            )?;
        }
        eprintln!("{}", String::from_utf8_lossy(&body));
    }
    if let Some(l) = lifecycle {
        eprintln!(
            "{}",
            serde_json::to_string(
                &l.finish(result.is_ok() && !guard.as_ref().is_some_and(|g| g.receipt().partial))?
            )?
        );
    }
    result
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

fn validate_mirror_profile(
    all: bool,
    network_io: bool,
    memory_all: bool,
    binder: bool,
    sched: bool,
    inspect_jni: bool,
    inspect_linker: bool,
    inspect_all_apps: bool,
    inspect_adapter: bool,
) -> Result<()> {
    if all
        || network_io
        || memory_all
        || binder
        || sched
        || inspect_jni
        || inspect_linker
        || inspect_all_apps
        || inspect_adapter
    {
        bail!("--mirror-http uses the minimal profile (--package + --network + --inspect-tls); retry without --all/--network-io/--memory-all/--binder/--sched/--inspect-jni/--inspect-linker/--inspect-all-apps/--inspect-adapter");
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_capture(args: CaptureArgs) -> Result<()> {
    let limits = (args.output_budget_bytes, args.output_budget_ms);
    let launch_after_attach = args.launch_after_attach;
    let mut request = plan_capture(args)?;
    request.validate_live_backend()?;
    let roots: Vec<PathBuf> = request.storage.spool_root.clone().into_iter().collect();
    let guard = budget_guard(roots.clone(), limits.0, limits.1)?;
    if request.storage.capture_relation.is_some()
        && (request.collect_keys || request.collect_memory_windows)
    {
        bail!("parent lifecycle cannot attest optional auxiliary cleanup");
    }
    let lifecycle = {
        request
            .storage
            .capture_relation
            .as_ref()
            .map(|r| {
                ksight_agent::capture_lifecycle::Lease::begin(
                    &ksight_agent::capture_lifecycle::control_root(
                        &ksight_agent::runtime_paths::captures(),
                        r,
                    ),
                    r,
                    roots,
                    limits
                        .1
                        .ok_or_else(|| anyhow::anyhow!("parent lifecycle requires deadline"))?,
                    true,
                )
            })
            .transpose()?
    };
    if launch_after_attach {
        let lease = lifecycle
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("launch requires parent lifecycle"))?;
        let startup = lease.startup(
            request
                .package
                .clone()
                .ok_or_else(|| anyhow::anyhow!("launch requires package"))?,
        );
        // All target operations happen after immutable lease acquisition.
        request.startup = Some(startup);
    }
    let result = ksight_agent::capture::run(request);
    if let Some(g) = guard.as_ref() {
        eprintln!("{}", serde_json::to_string(&g.receipt())?);
    }
    if let Some(l) = lifecycle {
        eprintln!(
            "{}",
            serde_json::to_string(
                &l.finish(result.is_ok() && !guard.as_ref().is_some_and(|g| g.receipt().partial))?
            )?
        );
    }
    result
}

fn budget_guard(
    roots: Vec<PathBuf>,
    bytes: Option<u64>,
    ms: Option<u64>,
) -> Result<Option<ksight_core::output_budget::Guard>> {
    match (bytes, ms) {
        (None, None) => Ok(None),
        (Some(n), Some(t)) => Ok(Some(ksight_core::output_budget::Guard::install(
            roots, n, t,
        )?)),
        _ => bail!("output budget requires bytes and milliseconds together"),
    }
}

/// Pure production planning: no layout, process, device or network operations.
#[allow(
    clippy::too_many_lines,
    reason = "Keep the admission or lifecycle transaction together for review."
)]
fn plan_capture(mut args: CaptureArgs) -> Result<CaptureRequest> {
    let relation = ksight_agent::capture_relation::CaptureRelation::parse(
        args.parent_session,
        args.stage_id,
        args.attempt_id,
        args.stage_attempt,
        args.stage_key.take(),
    )?;
    if args.launch_after_attach && (relation.is_none() || args.package.is_none()) {
        bail!("launch requires package and parent attempt lifecycle");
    }
    let relation = relation
        .map(|r| r.with_stage_links(args.stage_links.as_deref()))
        .transpose()?;
    if args.stage_links.is_some() && (relation.is_none() || args.inspect_stages.is_none()) {
        bail!("stage links require validated ancestry and inspect stages");
    }
    if let Some(r) = relation.as_ref() {
        if r.stage_key == "dump" || args.spool_dir.is_none() || args.package.is_none() {
            bail!("capture ancestry requires capture stage, package and durable spool");
        }
    }
    if args.mitm_burp {
        ksight_core::capture_scope::require_injection_restore_backend()
            .map_err(anyhow::Error::msg)?;
    }
    if args.sample_one_in == 0 {
        bail!("sampling rate must be greater than zero");
    }
    let stages = args
        .inspect_stages
        .as_deref()
        .map(ksight_agent::capture_stages::parse_stages)
        .transpose()
        .map_err(anyhow::Error::msg)?
        .unwrap_or_default();
    if !stages.is_empty() {
        if args.package.is_none() && args.pid.is_none() {
            bail!("--inspect-stages requires --package or --pid; UID alone cannot attest the main process instance");
        }
        if args.count != 0 {
            bail!("--inspect-stages does not accept --count; use explicit phase durations");
        }
        let total: u64 = stages.iter().map(|s| s.seconds).sum();
        if args.duration_seconds != 0 && args.duration_seconds != total {
            bail!("--duration-seconds must be omitted/0 or equal the stage total {total}");
        }
        args.duration_seconds = total;
    }
    let inspect_adapter_set = args.inspect_adapter.is_some();
    let mut inspect_adapters = Vec::new();
    if let Some(endpoint) = args.mirror_http.as_deref() {
        if let Err(error) = ksight_core::parse_mirror_endpoint(endpoint) {
            bail!("{error}");
        }
        validate_mirror_profile(
            args.all,
            args.network_io,
            args.memory_all,
            args.binder,
            args.sched,
            args.inspect_jni,
            args.inspect_linker,
            args.inspect_all_apps,
            args.inspect_adapter.is_some(),
        )?;
        args.inspect_tls = true;
        args.network = true;
        if args.inspect_max_hits == 0 {
            args.inspect_max_hits = 1_000_000;
        }
        args.inspect_max_secs = 0;
        if !args.inspect_jni {
            eprintln!(
                "mirror auto-discovery: package-scoped TLS exporters, embedded stack rules, lazy library rescans, and pinned vendor boundaries; experimental ART/JNI probes remain off"
            );
        }
    }
    if args.mitm_burp {
        if args.mirror_http.is_none() || args.package.is_none() {
            bail!("--mitm-burp requires --mirror-http HOST:PORT and --package");
        }
        eprintln!(
            "mitm-burp: UID REDIRECT every TCP port; non-DNS UDP rejected (QUIC cannot skip); Intercept off; Proxy HTTP history; Burp upstream 127.0.0.1:18888; pinning still applies on bank apps"
        );
    }
    if args.inspect_tls {
        inspect_adapters.push(ksight_agent::inspect_runtime::InspectAdapterKind::TlsSslWrite);
    }
    if args.inspect_jni {
        inspect_adapters.push(ksight_agent::inspect_runtime::InspectAdapterKind::JniPlaintext);
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
        bail!("--inspect-linker cannot be combined with --inspect-tls, --inspect-jni, or a non-linker --inspect-adapter");
    }
    if inspect_adapters.is_empty() {
        inspect_adapters.push(ksight_agent::inspect_runtime::InspectAdapterKind::LinkerSoLoad);
    }
    let inspect_enabled = args.inspect_linker
        || args.inspect_tls
        || args.inspect_jni
        || inspect_adapter_set
        || !stages.is_empty();
    if args.inspect_all_apps && !inspect_enabled {
        bail!("--inspect-all-apps requires --inspect-tls, --inspect-jni, --inspect-linker, or --inspect-adapter");
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
        max_duration_secs: if args.inspect_max_secs == 0 && args.duration_seconds != 0 {
            u32::try_from(args.duration_seconds).unwrap_or(u32::MAX)
        } else {
            args.inspect_max_secs
        },
        whole_device: args.inspect_all_apps,
        max_payload_bytes: args.inspect_max_bytes.clamp(1, 256 * 1024),
        ..ksight_core::InspectPolicy::default()
    };
    if let Some(r) = relation.as_ref().filter(|r| !r.stage_links.is_empty()) {
        let planned = stages
            .iter()
            .map(|s| s.name.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let linked = r
            .stage_links
            .iter()
            .filter_map(|s| s["stageKey"].as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if planned != linked || stages.first().is_none_or(|s| s.name != r.stage_key) {
            bail!("stage links must exactly match planned phases and primary relation");
        }
    }
    let request = CaptureRequest {
        code_only: args.code_only,
        startup: None,
        collect_keys: args.collect_keys,
        collect_memory_windows: args.collect_memory_windows,
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
            capture_relation: relation,
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
        inspect_stages: stages,
        uprobe_object: args.uprobe_object,
        mirror_http: args.mirror_http,
        mitm_burp: args.mitm_burp,
    };
    request.auxiliary_plan()?;
    Ok(request)
}

fn run_service(path: &std::path::Path, dry_run: bool) -> Result<()> {
    let config = ksight_agent::service::ServiceConfig::load(path)?;
    config.validate_runtime_paths()?;
    if dry_run {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            for line in ksight_agent::keylog_probe::ensure_device_stack_tables() {
                eprintln!("{line}");
            }
        }
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
        SpoolCommand::Repair => {
            let _lease = ksight_agent::retention::SpoolLease::acquire(root)?;
            let repaired = ksight_agent::retention::SpoolRetention {
                root: root.to_path_buf(),
                max_total_bytes: 0,
                keep_completed: u32::MAX,
            }
            .repair_interrupted()?;
            println!("repaired_interrupted_sessions={repaired}");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_failure_keeps_syscall_errno_and_parameter_context() {
        let error = anyhow::Error::new(std::io::Error::from_raw_os_error(22))
            .context("metadata TASK_STORAGE create command=0 type=29 flags=1 btf_key_type_id=2 btf_value_type_id=39");
        let note = capability_failure(&error);
        assert_eq!(note["errno"], 22);
        assert_eq!(note["error_chain"].as_array().unwrap().len(), 2);
        assert!(note["error_chain"][0]
            .as_str()
            .unwrap()
            .contains("btf_value_type_id=39"));
        assert!(format!("{error:#}").contains("22"));
        assert!(capability_failure(&anyhow::anyhow!("offline refusal"))["errno"].is_null());
    }

    #[test]
    #[allow(
        clippy::similar_names,
        reason = "Local fixture or owned callback keeps its explicit scope and fallible signature."
    )]
    fn production_cli_stage_links_match_actual_plan_and_primary() {
        let parent = uuid::Uuid::new_v4();
        let stage = uuid::Uuid::new_v4();
        let attempt = uuid::Uuid::new_v4();
        let links = serde_json::json!([{"parentId":parent,"stageId":stage,"attemptId":attempt,"attempt":1,"stageKey":"l0"},{"parentId":parent,"stageId":uuid::Uuid::new_v4(),"attemptId":uuid::Uuid::new_v4(),"attempt":1,"stageKey":"l1"},{"parentId":parent,"stageId":uuid::Uuid::new_v4(),"attemptId":uuid::Uuid::new_v4(),"attempt":1,"stageKey":"linker"}]);
        let parent = parent.to_string();
        let stage = stage.to_string();
        let attempt = attempt.to_string();
        let links = links.to_string();
        let arguments = [
            "ksightd",
            "capture",
            "--package",
            "org.example.fixture",
            "--spool-dir",
            "/tmp/not-created-stage-fixture",
            "--duration-seconds",
            "6",
            "--inspect-stages",
            "l0:2,l1:2,linker:2",
            "--parent-session",
            &parent,
            "--stage-id",
            &stage,
            "--attempt-id",
            &attempt,
            "--stage-attempt",
            "1",
            "--stage-key",
            "l0",
            "--stage-links",
            &links,
        ];
        let Command::Capture(args) = Args::try_parse_from(arguments).unwrap().command else {
            panic!()
        };
        let request = plan_capture(*args).unwrap();
        assert_eq!(
            request.storage.capture_relation.unwrap().stage_links.len(),
            3
        );
        let mut arguments = arguments;
        arguments[9] = "l0:1,l1:5";
        let Command::Capture(args) = Args::try_parse_from(arguments).unwrap().command else {
            panic!()
        };
        assert!(plan_capture(*args).is_err());
    }
    #[test]
    fn production_cli_ancestry_requires_complete_valid_parameters() {
        let parent = uuid::Uuid::new_v4().to_string();
        let stage = uuid::Uuid::new_v4().to_string();
        let attempt = uuid::Uuid::new_v4().to_string();
        let cli = Args::try_parse_from([
            "ksightd",
            "capture",
            "--package",
            "org.example.fixture",
            "--spool-dir",
            "/tmp/fixture-only",
            "--parent-session",
            &parent,
            "--stage-id",
            &stage,
            "--attempt-id",
            &attempt,
            "--stage-attempt",
            "1",
            "--stage-key",
            "l0",
        ])
        .unwrap();
        let Command::Capture(args) = cli.command else {
            panic!()
        };
        let request = plan_capture(*args).unwrap();
        let relation = request.storage.capture_relation.unwrap();
        assert_eq!(relation.parent_id.to_string(), parent);
        assert_eq!(relation.stage_key, "l0");
        let cli =
            Args::try_parse_from(["ksightd", "capture", "--parent-session", &parent]).unwrap();
        let Command::Capture(args) = cli.command else {
            panic!()
        };
        assert!(plan_capture(*args).is_err());
        let old = Args::try_parse_from(["ksightd", "capture"]).unwrap();
        let Command::Capture(args) = old.command else {
            panic!()
        };
        assert!(plan_capture(*args)
            .unwrap()
            .storage
            .capture_relation
            .is_none());
    }
    #[test]
    fn rules_audit_is_a_separate_read_only_command() {
        let args = Args::try_parse_from([
            "ksightd",
            "rules-audit",
            "--rules",
            "fixture.json",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            args.command,
            Command::RulesAudit {
                rules: Some(_),
                json: true
            }
        ));
    }

    #[test]
    fn mirror_http_accepts_legacy_device_flag() {
        let args = Args::try_parse_from([
            "ksightd",
            "capture",
            "--package",
            "com.example.app",
            "--mirror-http",
            "127.0.0.1:8080",
            "--mitm-burp",
        ])
        .unwrap();
        let Command::Capture(capture) = args.command else {
            panic!("expected capture command");
        };
        assert_eq!(capture.mirror_http.as_deref(), Some("127.0.0.1:8080"));
        assert!(capture.mitm_burp);

        let legacy = Args::try_parse_from([
            "ksightd",
            "capture",
            "--package",
            "com.example.app",
            "--mirror-burp",
            "127.0.0.1:8080",
        ])
        .unwrap();
        let Command::Capture(capture) = legacy.command else {
            panic!("expected capture command");
        };
        assert_eq!(capture.mirror_http.as_deref(), Some("127.0.0.1:8080"));
    }

    #[test]
    fn mirror_profile_rejects_high_volume_sensors() {
        for combo in [
            (true, false, false, false, false, false, false, false, false),
            (false, true, false, false, false, false, false, false, false),
            (false, false, true, false, false, false, false, false, false),
            (false, false, false, true, false, false, false, false, false),
            (false, false, false, false, true, false, false, false, false),
            (false, false, false, false, false, true, false, false, false),
            (false, false, false, false, false, false, true, false, false),
            (false, false, false, false, false, false, false, true, false),
            (false, false, false, false, false, false, false, false, true),
        ] {
            assert!(validate_mirror_profile(
                combo.0, combo.1, combo.2, combo.3, combo.4, combo.5, combo.6, combo.7, combo.8
            )
            .is_err());
        }
        assert!(validate_mirror_profile(
            false, false, false, false, false, false, false, false, false
        )
        .is_ok());
    }
    #[allow(
        clippy::similar_names,
        reason = "Local fixture or owned callback keeps its explicit scope and fallible signature."
    )]
    fn minimal_request(extra: &[&str]) -> Result<CaptureRequest> {
        let mut arguments = vec![
            "ksightd",
            "capture",
            "--package",
            "com.example.app",
            "--mirror-http",
            "127.0.0.1:8080",
            "--minimal-mirror",
        ];
        arguments.extend_from_slice(extra);
        let args = Args::try_parse_from(arguments)?;
        let Command::Capture(args) = args.command else {
            panic!("capture");
        };
        plan_capture(*args)
    }

    #[test]
    fn production_minimal_mirror_plan_never_calls_auxiliary_backend() {
        use ksight_agent::capture::{AuxiliaryAction, AuxiliaryStage};
        let request = minimal_request(&["--spool-dir", "/unused-test-spool"]).unwrap();
        let plan = request.auxiliary_plan().unwrap();
        for action in [
            AuxiliaryAction::Pcap,
            AuxiliaryAction::Keylog,
            AuxiliaryAction::Infosec,
            AuxiliaryAction::CryptoWatch,
            AuxiliaryAction::MemoryDump,
        ] {
            assert!(!plan.enabled(action));
        }
        for success in [true, false] {
            for stage in [
                AuxiliaryStage::Start,
                AuxiliaryStage::Poll,
                AuxiliaryStage::Finish,
            ] {
                plan.dispatch(stage, success, |_| -> Result<(), ()> {
                    panic!("production plan leaked auxiliary operation")
                })
                .unwrap();
            }
        }
        assert_eq!(
            request.capture_layout_assets().unwrap(),
            [
                "process_lifecycle.bpf.o",
                "network_connect.bpf.o",
                "uprobe_regs.bpf.o"
            ]
        );
    }

    #[test]
    fn production_minimal_mirror_rejects_expanded_scope_before_any_io() {
        for flag in [
            "--files",
            "--files-fd",
            "--memory",
            "--all",
            "--network-io",
            "--memory-all",
            "--binder",
            "--sched",
            "--inspect-jni",
            "--inspect-linker",
            "--inspect-all-apps",
            "--mitm-burp",
        ] {
            assert!(minimal_request(&[flag]).is_err(), "{flag}");
        }
        let args = Args::try_parse_from([
            "ksightd",
            "capture",
            "--pid",
            "123",
            "--mirror-http",
            "127.0.0.1:8080",
        ])
        .unwrap();
        let Command::Capture(args) = args.command else {
            panic!("capture")
        };
        assert!(plan_capture(*args).is_err());
        assert!(Args::try_parse_from(["ksightd", "capture", "--minimal-mirror"]).is_err());
    }

    #[test]
    fn production_minimal_mirror_custom_paths_do_not_materialize_default_assets() {
        let request = minimal_request(&[
            "--object",
            "/custom/process.o",
            "--network-object",
            "/custom/network.o",
            "--uprobe-object",
            "/custom/uprobe.o",
        ])
        .unwrap();
        assert!(request.capture_layout_assets().unwrap().is_empty());
        let mut request = minimal_request(&[]).unwrap();
        request.inspect.package = Some("com.other.app".to_owned());
        assert!(request.auxiliary_plan().is_err());
        request.inspect.package = request.package.clone();
        request.inspect.whole_device = true;
        assert!(request.auxiliary_plan().is_err());
    }
    #[test]
    #[allow(
        clippy::similar_names,
        reason = "Local fixture or owned callback keeps its explicit scope and fallible signature."
    )]
    fn production_host_marker_round_trip_keeps_auxiliary_backends_disabled() {
        use ksight_agent::capture::AuxiliaryStage;
        let flags = std::env::var_os("KSIGHT_TEST_HOST_MIRROR_FLAG_INPUT").map_or_else(
            || " --mirror-http 127.0.0.1:8080 --minimal-mirror".to_owned(),
            |path| std::fs::read_to_string(path).expect("host production formatter fixture"),
        );
        let mut arguments = vec!["ksightd", "capture", "--package", "com.example.app"];
        arguments.extend(flags.split_whitespace());
        let parsed = Args::try_parse_from(arguments).unwrap();
        let Command::Capture(args) = parsed.command else {
            panic!("capture");
        };
        assert!(args.minimal_mirror);
        let request = plan_capture(*args).unwrap();
        let plan = request.auxiliary_plan().unwrap();
        for successful in [false, true] {
            for stage in [
                AuxiliaryStage::Start,
                AuxiliaryStage::Poll,
                AuxiliaryStage::Finish,
            ] {
                plan.dispatch(stage, successful, |_| -> Result<(), ()> {
                    panic!("host marker permitted auxiliary capture")
                })
                .unwrap();
            }
        }
    }
    #[test]
    fn production_live_mirror_refuses_before_spool_or_custom_layout() {
        let parent = std::env::temp_dir().join(format!("ksight-refuse-{}", uuid::Uuid::new_v4()));
        let path = parent.join("spool");
        let object = parent.join("process.o");
        let arguments = [
            "ksightd",
            "capture",
            "--package",
            "com.example.app",
            "--mirror-http",
            "127.0.0.1:8080",
            "--minimal-mirror",
            "--spool-dir",
            path.to_str().unwrap(),
            "--object",
            object.to_str().unwrap(),
        ];
        let parsed = Args::try_parse_from(arguments).unwrap();
        let Command::Capture(args) = parsed.command else {
            panic!("capture")
        };
        let error = run_capture(*args).unwrap_err().to_string();
        assert!(error.contains("process-instance binding"), "{error}");
        assert!(!parent.exists());
        let request = minimal_request(&[]).unwrap();
        let error = ksight_agent::capture::run(request).unwrap_err().to_string();
        assert!(error.contains("process-instance binding"), "{error}");
    }
    #[test]
    fn injection_refuses_before_raw_capture_layout_or_spool() {
        let parent =
            std::env::temp_dir().join(format!("ksight-injection-refuse-{}", uuid::Uuid::new_v4()));
        let mut request = minimal_request(&[]).unwrap();
        request.mirror_http = None;
        request.mitm_burp = true;
        request.storage.spool_root = Some(parent.join("spool"));
        request.process_object = parent.join("process.o");
        let error = request
            .validate_live_backend()
            .expect_err("unsafe optional injection accepted")
            .to_string();
        assert!(error.contains("TLS injection disabled"), "{error}");
        let error = ksight_agent::capture::run(request).unwrap_err().to_string();
        assert!(error.contains("TLS injection disabled"), "{error}");
        assert!(!parent.exists(), "refusal must precede layout/spool writes");
    }

    #[test]
    fn mitm_cli_refuses_before_injection_or_network_policy_actions() {
        let parsed = Args::try_parse_from([
            "ksightd",
            "capture",
            "--package",
            "com.example.app",
            "--mitm-burp",
            "--mirror-http",
            "127.0.0.1:8080",
        ])
        .unwrap();
        let Command::Capture(args) = parsed.command else {
            panic!("capture");
        };
        let error = run_capture(*args).unwrap_err().to_string();
        assert!(error.contains("TLS injection disabled"), "{error}");
    }
    #[test]
    fn staged_cli_plans_one_exact_duration_without_changing_l0_scope() {
        let args = Args::try_parse_from([
            "ksightd",
            "capture",
            "--package",
            "com.example.fixture",
            "--spool-dir",
            "/unused/offline",
            "--memory",
            "--inspect-stages",
            "l0:15,l1:90,linker:15",
        ])
        .unwrap();
        let Command::Capture(args) = args.command else {
            panic!()
        };
        let req = plan_capture(*args).unwrap();
        assert_eq!(req.duration_seconds, 120);
        assert_eq!(req.inspect_stages.len(), 3);
        assert_eq!(req.sensors.memory, MemorySelection::Executable);
        assert_eq!(req.sensors.network, NetworkSelection::Disabled);
        assert_eq!(req.package.as_deref(), Some("com.example.fixture"));
    }
    #[test]
    fn staged_cli_rejects_legacy_mode_collisions_before_runtime() {
        for flag in [
            "--inspect-tls",
            "--inspect-jni",
            "--inspect-linker",
            "--inspect-all-apps",
            "--mitm-burp",
        ] {
            assert!(
                Args::try_parse_from(["ksightd", "capture", "--inspect-stages", "l1:1", flag])
                    .is_err(),
                "{flag}"
            );
        }
        for (flag, value) in [
            ("--inspect-adapter", "binder_userspace"),
            ("--mirror-burp", "127.0.0.1:8080"),
            ("--inspect-max-secs", "1"),
        ] {
            assert!(
                Args::try_parse_from([
                    "ksightd",
                    "capture",
                    "--inspect-stages",
                    "l1:1",
                    flag,
                    value
                ])
                .is_err(),
                "{flag}"
            );
        }
    }
    #[test]
    fn staged_cli_refuses_missing_scope_spool_or_mismatched_duration() {
        for tail in [
            vec![],
            vec!["--uid", "10000", "--spool-dir", "/unused/offline"],
            vec!["--package", "com.example.fixture"],
            vec![
                "--package",
                "com.example.fixture",
                "--spool-dir",
                "/unused/offline",
                "--duration-seconds",
                "9",
            ],
            vec![
                "--package",
                "com.example.fixture",
                "--spool-dir",
                "/unused/offline",
                "--count",
                "1",
            ],
        ] {
            let mut arguments = vec!["ksightd", "capture", "--inspect-stages", "l1:1"];
            arguments.extend(tail);
            let Command::Capture(args) = Args::try_parse_from(arguments).unwrap().command else {
                panic!()
            };
            assert!(plan_capture(*args).is_err());
        }
    }
    #[test]
    fn legacy_combination_and_exclusive_linker_behavior_remain() {
        let Command::Capture(args) = Args::try_parse_from([
            "ksightd",
            "capture",
            "--package",
            "com.example.fixture",
            "--inspect-tls",
            "--inspect-jni",
            "--inspect-adapter",
            "binder_userspace",
        ])
        .unwrap()
        .command
        else {
            panic!()
        };
        let req = plan_capture(*args).unwrap();
        assert!(req.inspect_stages.is_empty());
        assert_eq!(req.inspect_adapters.len(), 3);
        let Command::Capture(args) = Args::try_parse_from([
            "ksightd",
            "capture",
            "--package",
            "com.example.fixture",
            "--inspect-tls",
            "--inspect-linker",
        ])
        .unwrap()
        .command
        else {
            panic!()
        };
        assert!(plan_capture(*args).is_err());
        let Command::Capture(args) = Args::try_parse_from(["ksightd", "capture", "--memory"])
            .unwrap()
            .command
        else {
            panic!()
        };
        let req = plan_capture(*args).unwrap();
        assert!(!req.inspect.enabled);
        assert!(req.inspect_stages.is_empty());
    }
}

#[cfg(test)]
mod budget_scope_tests {
    use super::*;
    #[test]
    fn startup_plan_rejects_unleased_or_legacy_launch_before_live_io() {
        for flags in [
            vec!["--launch-after-attach"],
            vec!["--launch-after-attach", "--code-only"],
        ] {
            let mut args = vec!["ksightd", "capture", "--package", "org.example.fixture"];
            args.extend(flags);
            let Command::Capture(a) = Args::try_parse_from(args).unwrap().command else {
                panic!("capture")
            };
            assert!(plan_capture(*a)
                .err()
                .unwrap()
                .to_string()
                .contains("parent attempt lifecycle"));
        }
    }
    #[test]
    fn corrected_ordinary_parent_launch_plans_without_code_only_gate() {
        let parent = Uuid::new_v4().to_string();
        let stage = Uuid::new_v4().to_string();
        let attempt = Uuid::new_v4().to_string();
        let spool = format!("/data/local/tmp/ksight/captures/{parent}/{stage}/{attempt}/spool");
        let a = Args::try_parse_from([
            "ksightd",
            "capture",
            "--package",
            "org.example.fixture",
            "--launch-after-attach",
            "--parent-session",
            &parent,
            "--stage-id",
            &stage,
            "--attempt-id",
            &attempt,
            "--stage-attempt",
            "1",
            "--stage-key",
            "l0",
            "--spool-dir",
            &spool,
            "--output-budget-bytes",
            "1048576",
            "--output-budget-ms",
            "1000",
        ])
        .unwrap();
        let Command::Capture(a) = a.command else {
            panic!("capture")
        };
        let request = plan_capture(*a).unwrap();
        assert!(!request.code_only);
        assert!(request.storage.capture_relation.is_some());
        request.validate_live_backend().unwrap();
    }
    #[test]
    fn code_only_plan_keeps_code_but_refuses_before_any_live_output() {
        let root = std::env::temp_dir().join(format!("scope-blocked-{}", Uuid::new_v4()));
        let text = root.to_str().unwrap();
        let a = Args::try_parse_from([
            "ksightd",
            "capture",
            "--package",
            "org.example.fixture",
            "--code-only",
            "--spool-dir",
            text,
            "--output-budget-bytes",
            "0",
            "--output-budget-ms",
            "1000",
        ])
        .unwrap();
        let Command::Capture(args) = a.command else {
            panic!("capture")
        };
        let r = plan_capture(*args).unwrap();
        assert!(r.code_only);
        let p = r.auxiliary_plan().unwrap();
        assert!(!p.enabled(ksight_agent::capture::AuxiliaryAction::CryptoWatch));
        let plain = plan_capture(
            match Args::try_parse_from(["ksightd", "capture", "--package", "org.example.fixture"])
                .unwrap()
                .command
            {
                Command::Capture(a) => *a,
                _ => panic!("capture"),
            },
        )
        .unwrap();
        assert!(!plain.collect_keys);
        assert!(!plain
            .auxiliary_plan()
            .unwrap()
            .enabled(ksight_agent::capture::AuxiliaryAction::CryptoWatch));
        assert!(p.enabled(ksight_agent::capture::AuxiliaryAction::MemoryDump));
        assert!(r
            .validate_live_backend()
            .unwrap_err()
            .to_string()
            .contains("process-instance"));
        assert!(!root.exists());
    }
}

#[cfg(test)]
mod isolated_path_tests {
    use super::*;
    #[test]
    fn production_cli_routes_assets_spool_and_dump_before_io() {
        let root = std::path::Path::new("/data/local/tmp/ksight-candidate-fixture");
        let mut args = Args::try_parse_from([
            "ksightd",
            "--runtime-root",
            "/data/local/tmp/ksight-candidate-fixture",
            "capture",
            "--spool-dir",
            "/data/local/tmp/ksight/spool",
        ])
        .unwrap();
        route_command_paths_at(&mut args.command, root).unwrap();
        let Command::Capture(c) = args.command else {
            panic!()
        };
        assert_eq!(c.object, root.join("process_lifecycle.bpf.o"));
        assert_eq!(c.uprobe_object, root.join("uprobe_regs.bpf.o"));
        assert_eq!(c.spool_dir, Some(root.join("spool")));
        let mut args = Args::try_parse_from([
            "ksightd",
            "dump-package",
            "--package",
            "fixture",
            "--dest",
            "/data/local/tmp/ksight/captures/p/s/a/dump",
        ])
        .unwrap();
        route_command_paths_at(&mut args.command, root).unwrap();
        let Command::DumpPackage { dest, .. } = args.command else {
            panic!()
        };
        assert_eq!(dest, root.join("captures/p/s/a/dump"));
        let mut args =
            Args::try_parse_from(["ksightd", "capture", "--object", "/sdcard/other.bpf.o"])
                .unwrap();
        assert!(route_command_paths_at(&mut args.command, root).is_err());
    }
}
