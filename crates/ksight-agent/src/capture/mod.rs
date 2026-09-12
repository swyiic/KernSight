//! Foreground multi-sensor capture orchestration.

use std::path::PathBuf;

#[cfg(any(target_os = "android", target_os = "linux"))]
use anyhow::Context;
use anyhow::{bail, Result};

/// Optional sensor selection for one capture session.
#[derive(Debug, Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct SensorSelection {
    /// Observe completed file opens.
    pub files: bool,
    /// Observe dup/close/fcntl descriptor events. Default off; Chromium storms this.
    pub file_descriptors: bool,
    /// Network-event capture level.
    pub network: NetworkSelection,
    /// Memory-region capture level.
    pub memory: MemorySelection,
    /// Observe Binder transaction metadata.
    pub binder: bool,
    /// Observe scheduler wakeup relationships (requires a scoped target).
    pub sched: bool,
}

/// Network-event verbosity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NetworkSelection {
    /// Do not attach the network sensor.
    #[default]
    Disabled,
    /// Observe connect and accept lifecycle metadata.
    Lifecycle,
    /// Also count explicit socket send/receive syscall results without payload bytes.
    Io,
}

/// Memory-event verbosity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MemorySelection {
    /// Do not attach the memory sensor.
    #[default]
    Disabled,
    /// Observe operations that request executable permission.
    Executable,
    /// Observe every mmap and mprotect operation.
    All,
}

/// Event rendering controls.
#[derive(Debug, Clone, Copy, Default)]
pub struct OutputOptions {
    /// Emit JSON Lines instead of human-readable text.
    pub json: bool,
    /// Keep process-thread lifecycle records.
    pub include_threads: bool,
    /// Suppress per-event rendering while retaining capture and durable storage.
    pub quiet: bool,
}

/// Optional durable event batching controls.
#[derive(Debug, Clone)]
pub struct StorageOptions {
    /// Root under which a session-specific spool directory is created.
    pub spool_root: Option<PathBuf>,
    /// Maximum complete batch bytes retained for the session.
    pub max_spool_bytes: u64,
    /// Maximum normalized events in one immutable protocol batch.
    pub events_per_batch: usize,
    /// Compress each batch independently.
    pub compress_batches: bool,
    /// Bytes reserved so a completion event can be sealed.
    pub completion_reserve_bytes: u64,
    /// Rotate the session after this many seconds; zero disables time rotation.
    pub max_session_age_secs: u64,
    /// Global complete-batch bound across the spool root; zero disables it.
    pub max_total_spool_bytes: u64,
    /// Sealed sessions to retain after pruning.
    pub keep_completed_sessions: u32,
}

impl Default for StorageOptions {
    fn default() -> Self {
        Self {
            spool_root: None,
            max_spool_bytes: 64 * 1024 * 1024,
            events_per_batch: 64,
            compress_batches: true,
            completion_reserve_bytes: crate::spool::DEFAULT_COMPLETION_RESERVE_BYTES,
            max_session_age_secs: 3600,
            max_total_spool_bytes: 512 * 1024 * 1024,
            keep_completed_sessions: 4,
        }
    }
}

/// Explicit per-sensor kernel sampling rates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamplingOptions {
    /// Process lifecycle sampling rate.
    pub process: u32,
    /// File-open sampling rate.
    pub file: u32,
    /// Socket-connect sampling rate.
    pub network: u32,
    /// Memory-region sampling rate.
    pub memory: u32,
    /// Binder transaction sampling rate.
    pub binder: u32,
    /// Scheduler wakeup sampling rate.
    pub sched: u32,
}

impl SamplingOptions {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn for_sensor(self, sensor: ksight_model::SensorKind) -> u32 {
        use ksight_model::SensorKind;

        match sensor {
            SensorKind::Process => self.process,
            SensorKind::File => self.file,
            SensorKind::Network => self.network,
            SensorKind::Memory => self.memory,
            SensorKind::Binder => self.binder,
            SensorKind::Sched => self.sched,
            SensorKind::Integrity | SensorKind::Syscall => 1,
        }
        .max(1)
    }
}

impl Default for SamplingOptions {
    fn default() -> Self {
        Self {
            process: 1,
            file: 1,
            network: 1,
            memory: 1,
            binder: 1,
            sched: 1,
        }
    }
}

/// Complete validated-by-construction capture request from the CLI boundary.
#[derive(Debug)]
pub struct CaptureRequest {
    /// Whether the session is foreground-controlled or device-daemon owned.
    pub collector_mode: ksight_model::CollectorMode,
    /// Optional daemon status writer; foreground captures leave this unset.
    pub status: Option<crate::service::ServiceStatusHandle>,
    /// Process lifecycle BPF object.
    pub process_object: PathBuf,
    /// File-open BPF object.
    pub file_object: PathBuf,
    /// Socket-connect BPF object.
    pub network_object: PathBuf,
    /// Memory-region BPF object.
    pub memory_object: PathBuf,
    /// Binder transaction BPF object.
    pub binder_object: PathBuf,
    /// Scheduler wakeup BPF object.
    pub sched_object: PathBuf,
    /// Enabled optional sensors.
    pub sensors: SensorSelection,
    /// Output controls.
    pub output: OutputOptions,
    /// Optional bounded durable storage.
    pub storage: StorageOptions,
    /// Per-sensor sampling recorded in event quality metadata.
    pub sampling: SamplingOptions,
    /// Event limit, or zero for unlimited.
    pub count: u64,
    /// Duration limit, or zero for unlimited.
    pub duration_seconds: u64,
    /// Optional target TGID.
    pub pid: Option<u32>,
    /// Optional target Linux UID.
    pub uid: Option<u32>,
    /// Optional exact Android package.
    pub package: Option<String>,
    /// Explicit Inspect policy. Default is disabled.
    pub inspect: ksight_core::InspectPolicy,
    /// Inspect adapters selected by the operator. TLS and Binder may be combined.
    pub inspect_adapters: Vec<crate::inspect_runtime::InspectAdapterKind>,
    /// Compiled uprobe object used by Inspect adapters.
    pub uprobe_object: PathBuf,
    /// Optional Burp HTTP proxy `host:port`. Device feeds reconstructed HTTP/WS there.
    pub mirror_burp: Option<String>,
    /// Transparent per-UID REDIRECT of 80/443 through a CONNECT forwarder to Burp.
    pub mitm_burp: bool,
}

/// Run a foreground capture session.
///
/// # Errors
///
/// Returns an error for invalid scope, unavailable identity data, BPF load failure, or output I/O.
#[cfg(any(target_os = "android", target_os = "linux"))]
pub fn run(request: CaptureRequest) -> Result<()> {
    use crate::normalize::EventNormalizer;

    if std::env::consts::ARCH != "aarch64" {
        bail!(
            "the current raw-syscall adapters support only aarch64; refusing architecture {}",
            std::env::consts::ARCH
        );
    }
    if request.sensors.sched
        && request.pid.is_none()
        && request.uid.is_none()
        && request.package.is_none()
    {
        bail!("scheduler capture requires --pid, --uid, or --package");
    }

    if request.sensors.network == NetworkSelection::Io
        && request.pid.is_none()
        && request.uid.is_none()
        && request.package.is_none()
        && request.sampling.network == 1
    {
        eprintln!(
            "warning: unscoped network-io at 1/1 can be high volume; use --pid, --uid, --package, or --sample-one-in"
        );
    }

    // A spool is a single-writer evidence store. Hold the lease for the
    // complete capture so interrupted-session repair can never rewrite a live
    // peer collector's manifest.
    let _spool_lease = request
        .storage
        .spool_root
        .as_ref()
        .map(crate::retention::SpoolLease::acquire)
        .transpose()?;
    let environment = crate::environment::collect(request.collector_mode);
    let (identity_resolver, mut kernel_filter, scope) =
        resolve_scope(request.pid, request.uid, request.package.as_deref())?;
    kernel_filter.memory_all = request.sensors.memory == MemorySelection::All;
    kernel_filter.network_io = request.sensors.network == NetworkSelection::Io;
    kernel_filter.file_descriptors = request.sensors.file_descriptors;
    let sensors = load_sensors(&request, kernel_filter)?;
    let normalizer = EventNormalizer::from_system()?;
    let include_fd_baseline = request.sensors.files
        || request.sensors.network != NetworkSelection::Disabled
        || request.sensors.binder;
    let include_vma_baseline = request.sensors.memory != MemorySelection::Disabled;
    let (baseline_events, baseline_sockets) = crate::baseline::collect(
        &scope,
        normalizer.boot_id(),
        normalizer.session_id(),
        include_fd_baseline,
        include_vma_baseline,
    );
    if let Some(root) = request.storage.spool_root.as_ref() {
        let retention = crate::retention::SpoolRetention {
            root: root.clone(),
            max_total_bytes: request.storage.max_total_spool_bytes,
            keep_completed: request.storage.keep_completed_sessions,
        };
        retention.repair_interrupted()?;
        retention.prune()?;
    }
    let spool = request
        .storage
        .spool_root
        .as_ref()
        .map(|root| {
            crate::spool::SessionSpoolWriter::open_with(
                root,
                normalizer.session_id(),
                request.storage.max_spool_bytes,
                request.storage.events_per_batch,
                crate::spool::SpoolOptions {
                    compress: request.storage.compress_batches,
                    completion_reserve_bytes: request.storage.completion_reserve_bytes,
                },
            )
        })
        .transpose()?;
    stream_events(
        sensors,
        identity_resolver,
        normalizer,
        scope,
        spool,
        &request,
        environment,
        baseline_events,
        baseline_sockets,
    )
}

/// Return a platform error when live eBPF capture is unavailable.
///
/// # Errors
///
/// Always returns an error on unsupported host platforms.
#[cfg(not(any(target_os = "android", target_os = "linux")))]
pub fn run(_request: CaptureRequest) -> Result<()> {
    bail!("live eBPF capture is available only in Linux or Android builds")
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn resolve_scope(
    pid: Option<u32>,
    uid: Option<u32>,
    package: Option<&str>,
) -> Result<(
    crate::identity::AndroidIdentityResolver,
    crate::ebpf::CaptureFilter,
    crate::scope::CaptureScope,
)> {
    use crate::{identity::valid_package_name, scope::CaptureScope};

    if package.is_some_and(|name| !valid_package_name(name)) {
        bail!("package name contains unsupported characters");
    }
    let identity_resolver = match crate::identity::AndroidIdentityResolver::from_system() {
        Ok(resolver) => resolver,
        Err(error) if package.is_some() => {
            return Err(error).context("package capture requires readable packages.list")
        }
        Err(error) => {
            eprintln!("identity enrichment unavailable: {error}");
            crate::identity::AndroidIdentityResolver::default()
        }
    };
    let package_uid = package
        .map(|name| {
            identity_resolver
                .uid_for_package(name)
                .with_context(|| format!("package {name} is not installed"))
        })
        .transpose()?;
    if let (Some(requested_uid), Some(resolved_uid)) = (uid, package_uid) {
        if requested_uid != resolved_uid {
            bail!("requested UID {requested_uid} conflicts with package UID {resolved_uid}");
        }
    }
    let target_uid = uid.or(package_uid);
    Ok((
        identity_resolver,
        crate::ebpf::CaptureFilter {
            target_tgid: pid,
            target_uid,
            memory_all: false,
            network_io: false,
            file_descriptors: false,
            sample_one_in: 1,
        },
        CaptureScope {
            target_tgid: pid,
            target_uid,
            target_package: package.map(str::to_owned),
        },
    ))
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn load_sensors(
    request: &CaptureRequest,
    filter: crate::ebpf::CaptureFilter,
) -> Result<Vec<ActiveSensor>> {
    use crate::ebpf::{
        load_binder_sensor, load_file_sensor, load_memory_sensor, load_network_sensor,
        load_process_sensor, load_sched_sensor,
    };

    let mut sensors = vec![ActiveSensor::new(
        "process",
        load_process_sensor(
            &request.process_object,
            with_sampling(filter, request.sampling.process),
        )?,
    )];
    if request.sensors.files || request.sensors.file_descriptors {
        sensors.push(ActiveSensor::new(
            "file",
            load_file_sensor(
                &request.file_object,
                with_sampling(filter, request.sampling.file),
            )?,
        ));
    }
    if request.sensors.network != NetworkSelection::Disabled {
        sensors.push(ActiveSensor::new(
            "network",
            load_network_sensor(
                &request.network_object,
                with_sampling(filter, request.sampling.network),
            )?,
        ));
    }
    if request.sensors.memory != MemorySelection::Disabled {
        sensors.push(ActiveSensor::new(
            "memory",
            load_memory_sensor(
                &request.memory_object,
                with_sampling(filter, request.sampling.memory),
            )?,
        ));
    }
    if request.sensors.binder {
        sensors.push(ActiveSensor::new(
            "binder",
            load_binder_sensor(
                &request.binder_object,
                with_sampling(filter, request.sampling.binder),
            )?,
        ));
    }
    if request.sensors.sched {
        sensors.push(ActiveSensor::new(
            "sched",
            load_sched_sensor(
                &request.sched_object,
                with_sampling(filter, request.sampling.sched),
            )?,
        ));
    }
    Ok(sensors)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn with_sampling(
    mut filter: crate::ebpf::CaptureFilter,
    sample_one_in: u32,
) -> crate::ebpf::CaptureFilter {
    filter.sample_one_in = sample_one_in.max(1);
    filter
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn spawn_pcap_watchdog(
    interface: &str,
    destination: &std::path::Path,
    filter: &str,
) -> std::io::Result<std::process::Child> {
    // The shell watches ksightd's PID and owns tcpdump. If ksightd is killed
    // before Rust cleanup runs, the watchdog still terminates and reaps the
    // packet-capture child instead of leaving it reparented to PID 1.
    const SCRIPT: &str = r#"
parent=$1
interface=$2
destination=$3
filter=$4
tcpdump -i "$interface" -s 0 -U -w "$destination" "$filter" >/dev/null 2>&1 &
worker=$!
cleanup() {
  trap - EXIT INT TERM HUP
  kill "$worker" 2>/dev/null || true
  wait "$worker" 2>/dev/null || true
}
trap 'cleanup; exit 0' EXIT INT TERM HUP
while kill -0 "$parent" 2>/dev/null; do sleep 1; done
cleanup
"#;
    std::process::Command::new("sh")
        .args([
            "-c",
            SCRIPT,
            "ksight-pcap-watchdog",
            &std::process::id().to_string(),
            interface,
            destination.to_string_lossy().as_ref(),
            filter,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn stop_pcap_watchdog(child: &mut std::process::Child) {
    let Ok(pid) = i32::try_from(child.id()) else {
        let _ = child.kill();
        let _ = child.wait();
        return;
    };
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGTERM,
    );
    for _ in 0..40 {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[allow(clippy::too_many_lines)]
fn stream_events(
    mut sensors: Vec<ActiveSensor>,
    identity_resolver: crate::identity::AndroidIdentityResolver,
    normalizer: crate::normalize::EventNormalizer,
    scope: crate::scope::CaptureScope,
    spool: Option<crate::spool::SessionSpoolWriter>,
    request: &CaptureRequest,
    environment: ksight_model::SessionEnvironment,
    baseline_events: Vec<ksight_model::Event>,
    baseline_sockets: Vec<(u32, i32)>,
) -> Result<()> {
    use std::{
        io::Write as _,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };

    let started = Instant::now();
    let deadline =
        (request.duration_seconds != 0).then(|| Duration::from_secs(request.duration_seconds));
    let running = Arc::new(AtomicBool::new(true));
    let signal_state = Arc::clone(&running);
    ctrlc::set_handler(move || signal_state.store(false, Ordering::SeqCst))?;
    let mut pipeline = EventPipeline::new(
        normalizer,
        identity_resolver,
        scope.clone(),
        request.output,
        spool,
        request.sampling,
        request.collector_mode,
        request.storage.clone(),
        environment.clone(),
    );
    let mut last_environment = environment.clone();
    pipeline.emit_session_payload(ksight_model::EventPayload::SessionEnvironment(environment))?;
    if let Some(root) = request.storage.spool_root.as_ref() {
        let _ = std::fs::create_dir_all(root);
        let _ = std::fs::write(
            root.join("last_session"),
            pipeline.normalizer.session_id().to_string(),
        );
    }
    let mut tls_inject: Option<crate::tls_inject::TlsInject> = None;
    if request.mitm_burp {
        match crate::tls_inject::TlsInject::start(request.package.as_deref()) {
            Ok(inject) => {
                eprintln!("tls-inject on with --mitm-burp only");
                tls_inject = Some(inject);
            }
            Err(error) => eprintln!("tls-inject skipped: {error}"),
        }
    } else if request.mirror_burp.is_some() {
        eprintln!("tls-inject off (no ptrace); inspect-tls uprobe only; app TLS unchanged");
    }
    let _mitm = if request.mitm_burp {
        match (request.package.as_deref(), request.mirror_burp.as_deref()) {
            (Some(package), Some(endpoint)) => {
                match (
                    crate::mitm_redirect::uid_for_package(package),
                    ksight_core::parse_mirror_endpoint(endpoint),
                ) {
                    (Some(uid), Ok(addr)) => {
                        match crate::mitm_redirect::MitmRedirect::install(uid, addr) {
                            Ok(mitm) => {
                                eprintln!(
                                "mitm-burp uid={uid} package={package} -> {endpoint}; Burp Network→Connections→Upstream proxy = 127.0.0.1:18888 (adb forward); Proxy HTTP history, not Logger"
                            );
                                Some(mitm)
                            }
                            Err(error) => {
                                eprintln!("mitm-burp skipped: {error}");
                                None
                            }
                        }
                    }
                    _ => {
                        eprintln!("mitm-burp skipped: need package uid and Burp host:port");
                        None
                    }
                }
            }
            _ => {
                eprintln!("mitm-burp requires --package and --mirror-burp host:port");
                None
            }
        }
    } else {
        None
    };
    pipeline.burp_mirror = match request.mirror_burp.as_deref() {
        Some(endpoint) => match crate::burp_mirror::BurpMirror::start_for_session(
            endpoint,
            Some(&pipeline.normalizer.session_id().to_string()),
        ) {
            Ok(mirror) => {
                eprintln!(
                    "burp-mirror {endpoint} playback=:{} (original HTTP request+response; Intercept off)",
                    ksight_core::BURP_PLAYBACK_PORT
                );
                Some(mirror)
            }
            Err(error) => {
                eprintln!("burp-mirror disabled: {error}");
                None
            }
        },
        None => None,
    };
    eprintln!(
        "ksightd {} session={} files={} files-fd={} network={:?} binder={} inspect={} package={} mirror={}",
        env!("CARGO_PKG_VERSION"),
        pipeline.normalizer.session_id(),
        request.sensors.files,
        request.sensors.file_descriptors,
        request.sensors.network,
        request.sensors.binder,
        request.inspect.enabled,
        request.package.as_deref().unwrap_or("-"),
        request.mirror_burp.as_deref().unwrap_or("-")
    );
    if request.sensors.files && !request.sensors.file_descriptors {
        eprintln!("file sensor: openat only; dup/close is off unless --files-fd");
    }

    let mut inspect_policy = request.inspect.clone();
    if inspect_policy.enabled {
        if inspect_policy.pid.is_none() {
            inspect_policy.pid = request.pid;
        }
        if inspect_policy.uid.is_none() {
            inspect_policy.uid = request.uid.or(scope.target_uid);
        }
        if inspect_policy.package.is_none() {
            inspect_policy.package.clone_from(&request.package);
        }
    }
    let mut inspect = crate::inspect_runtime::InspectRuntime::prepare_all(
        &inspect_policy,
        &request.inspect_adapters,
        &request.uprobe_object,
    );
    if request.inspect.enabled {
        for observation in inspect.initial_observations() {
            pipeline.emit_inspect(observation)?;
        }
    }

    publish_service_health(request, &pipeline, &sensors)?;
    let mut next_heartbeat = Instant::now() + Duration::from_secs(1);
    let mut next_crypto = Instant::now() + Duration::from_secs(3);
    // Publish the first payload-free coverage snapshot quickly enough for the
    // desktop UI to distinguish startup from a missing boundary.
    let mut next_inspect_stats = Instant::now() + Duration::from_secs(3);
    let environment_check_interval = match request.collector_mode {
        ksight_model::CollectorMode::ForegroundAdb => Duration::from_secs(1),
        ksight_model::CollectorMode::DetachedDaemon => Duration::from_secs(30),
    };
    let mut next_environment_check = Instant::now() + environment_check_interval;

    for sensor in &mut sensors {
        sensor.seed_socket_fds(&baseline_sockets);
    }
    for event in baseline_events {
        pipeline.emit_event(event)?;
    }

    // Passive on-wire capture for the mirror workflow: the pcap plus a keylog
    // file (when a keylog probe is configured) decrypt offline to the full
    // traffic picture that symbol probes cannot reach on stripped stacks.
    let mut pcap_child: Option<std::process::Child> = None;
    let pcap_dest = request.storage.spool_root.as_ref().map(|root| {
        let dir = root
            .join("forensics")
            .join(pipeline.normalizer.session_id().to_string());
        let _ = std::fs::create_dir_all(&dir);
        dir.join("traffic.pcap")
    });
    let mut keylog_probe: Option<crate::keylog_probe::KeylogProbe> = None;
    let mut keylog_attached = false;
    let mut next_keylog_try = Instant::now();
    let mut infosec_probe: Option<crate::infosec_probe::InfosecProbe> = None;
    let mut next_infosec_try = Instant::now();
    let mut next_stack_inventory = Instant::now();
    let keylog_file = pcap_dest
        .as_ref()
        .map(|pcap| pcap.with_file_name("sslkeylog.txt"));

    if request.mirror_burp.is_some() {
        if let Some(dest) = pcap_dest.as_ref() {
            let filter = "tcp port 443 or udp port 443";
            for iface in ["any", "wlan0", "rmnet_data0"] {
                match spawn_pcap_watchdog(iface, dest, filter) {
                    Ok(child) => {
                        eprintln!("pcap capture started iface={iface} dest={}", dest.display());
                        pcap_child = Some(child);
                        break;
                    }
                    Err(error) => {
                        eprintln!("pcap spawn iface={iface} failed: {error}");
                    }
                }
            }
        }
    }

    while running.load(Ordering::SeqCst)
        && (request.count == 0 || pipeline.stats.live_emitted < request.count)
        && deadline.is_none_or(|duration| started.elapsed() < duration)
    {
        if Instant::now() >= next_environment_check {
            let current = crate::environment::collect(request.collector_mode);
            if !same_environment_state(&last_environment, &current) {
                pipeline.environment.clone_from(&current);
                pipeline.emit_session_payload(ksight_model::EventPayload::SessionEnvironment(
                    current.clone(),
                ))?;
                last_environment = current;
            }
            next_environment_check = Instant::now() + environment_check_interval;
        }
        let mut consumed_any = false;
        for sensor in &mut sensors {
            if request.count != 0 && pipeline.stats.live_emitted >= request.count {
                break;
            }
            match sensor.next_record() {
                Ok(Some(record)) => {
                    consumed_any = true;
                    pipeline.emit(record)?;
                }
                Ok(None) => {}
                Err(error) => {
                    pipeline.stats.invalid_records += 1;
                    eprintln!(
                        "discard invalid {} ring-buffer record: {error}",
                        sensor.name
                    );
                }
            }
        }
        if request.inspect.enabled {
            for observation in inspect.attach_when_safe() {
                pipeline.emit_inspect(observation)?;
            }
            if let (Some(inject), Some(package)) = (tls_inject.as_mut(), request.package.as_deref())
            {
                if let Some(pid) = crate::tls_inject::TlsInject::main_pid(package) {
                    inject.inject(pid);
                    let items = inject.poll();
                    if !items.is_empty() {
                        eprintln!(
                            "tls-inject plaintext {} chunks first={}B",
                            items.len(),
                            items[0].bytes.len()
                        );
                    }
                    if let Some(mirror) = pipeline.burp_mirror.as_mut() {
                        for item in items {
                            let adapter = if item.direction == "send" {
                                "tls_ssl_write"
                            } else {
                                "tls_ssl_read"
                            };
                            mirror.observe_bytes(pid, 0, adapter, item.direction, &item.bytes);
                        }
                    }
                }
            }
            for output in inspect.poll() {
                if let Some(mirror) = pipeline.burp_mirror.as_mut() {
                    if let crate::inspect_runtime::InspectOutput::Plaintext {
                        pid,
                        tid,
                        connection_id,
                        fragment,
                        raw,
                    } = &output
                    {
                        mirror.observe_bytes_for_connection(
                            *pid,
                            *tid,
                            *connection_id,
                            &fragment.adapter,
                            &fragment.direction,
                            raw,
                        );
                    }
                }
                pipeline.emit_inspect_output(output)?;
            }
            if let Some(observation) = inspect.expire_if_needed() {
                pipeline.emit_inspect(observation)?;
            }
            if request.mirror_burp.is_some() && Instant::now() >= next_keylog_try {
                if !keylog_attached {
                    eprintln!(
                        "keylog attempt: mirror={} pids={:?} table={}",
                        request.mirror_burp.is_some(),
                        request
                            .package
                            .as_deref()
                            .map(crate::dexdump::pids_for_package)
                            .unwrap_or_default(),
                        crate::keylog_probe::table_path().display()
                    );
                }
                let pids = request
                    .package
                    .as_deref()
                    .map(crate::dexdump::pids_for_package)
                    .unwrap_or_default();
                if !pids.is_empty() {
                    let (probe, status) = if keylog_attached {
                        (
                            None,
                            keylog_probe.as_mut().map_or_else(Vec::new, |probe| {
                                probe.retry_attach(&request.uprobe_object, &pids)
                            }),
                        )
                    } else {
                        let (probe, status) = crate::keylog_probe::KeylogProbe::attach_for_pids(
                            &request.uprobe_object,
                            &pids,
                        );
                        keylog_attached = true;
                        (Some(probe), status)
                    };
                    for line in &status {
                        eprintln!("{line}");
                    }
                    if let Some(probe) = probe {
                        keylog_probe = Some(probe);
                    }
                }
                next_keylog_try = Instant::now() + Duration::from_secs(5);
                if !infosec_probe.as_ref().is_some_and(|probe| probe.is_armed())
                    && Instant::now() >= next_infosec_try
                {
                    let pids = request
                        .package
                        .as_deref()
                        .map(crate::dexdump::pids_for_package)
                        .unwrap_or_default();
                    if !pids.is_empty() {
                        let (probe, status) = crate::infosec_probe::InfosecProbe::attach_for_pids(
                            &request.uprobe_object,
                            &pids,
                            request
                                .inspect_adapters
                                .iter()
                                .any(|adapter| adapter.is_jni()),
                        );
                        for line in &status {
                            eprintln!("{line}");
                        }
                        infosec_probe = Some(probe);
                        next_infosec_try = Instant::now() + Duration::from_secs(15);
                    }
                }
            }
            if let Some(probe) = keylog_probe.as_mut() {
                let lines = probe.poll();
                if !lines.is_empty() {
                    if let Some(dest) = keylog_file.as_ref() {
                        if let Ok(mut file) = std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(dest)
                        {
                            use std::io::Write as _;
                            for line in &lines {
                                let _ = writeln!(file, "{line}");
                            }
                        }
                    }
                    eprintln!("keylog lines captured: {}", lines.len());
                    if let Some(mirror) = pipeline.burp_mirror.as_mut() {
                        mirror.ingest_keylog_lines(&lines);
                    }
                }
            }
            if let Some(probe) = infosec_probe.as_mut() {
                for capture in probe.poll_captures() {
                    let output = crate::inspect_runtime::external_plaintext(capture);
                    if let Some(mirror) = pipeline.burp_mirror.as_mut() {
                        if let crate::inspect_runtime::InspectOutput::Plaintext {
                            pid,
                            tid,
                            connection_id,
                            fragment,
                            raw,
                        } = &output
                        {
                            mirror.observe_bytes_for_connection(
                                *pid,
                                *tid,
                                *connection_id,
                                &fragment.adapter,
                                &fragment.direction,
                                raw,
                            );
                        }
                    }
                    pipeline.emit_inspect_output(output)?;
                }
                for line in probe.poll(
                    request
                        .package
                        .as_deref()
                        .map(crate::dexdump::pids_for_package)
                        .unwrap_or_default()
                        .as_slice(),
                ) {
                    eprintln!("{line}");
                }
            }
        }
        if request.mirror_burp.is_some() && Instant::now() >= next_stack_inventory {
            if let (Some(package), Some(mirror)) =
                (request.package.as_deref(), pipeline.burp_mirror.as_mut())
            {
                mirror.set_stack_coverage(mapped_stack_coverage(package));
            }
            next_stack_inventory = Instant::now() + Duration::from_secs(15);
        }
        if Instant::now() >= next_inspect_stats {
            let (raw, decoded, lost) = inspect.drain_totals();
            let (ssl_re, ssl_rr, ssl_rok, ssl_rf, ssl_rw) = inspect.ssl_read_funnel();
            let (ssl_gt0, ssl_dgt0, ssl_wo, ssl_wc, ssl_oko, ssl_okc, ssl_gto, ssl_gtc) =
                inspect.ssl_read_funnel_ex();
            let mirror_diagnostics = pipeline
                .burp_mirror
                .as_ref()
                .map(crate::burp_mirror::BurpMirror::diagnostic_detail);
            let mirror_metrics = pipeline
                .burp_mirror
                .as_ref()
                .map(crate::burp_mirror::BurpMirror::diagnostic_metrics)
                .unwrap_or_default();
            eprintln!(
                "inspect layers: raw_uprobe={raw} decoded={decoded} perf_lost={lost} ssl_read_entry={ssl_re} ssl_read_ret={ssl_rr} ssl_read_ok={ssl_rok} ssl_read_fail={ssl_rf} ssl_read_want={ssl_rw} ssl_read_ret_gt0={ssl_gt0} ssl_read_drop_gt0={ssl_dgt0} ssl_read_want_openssl={ssl_wo} ssl_read_want_conscrypt={ssl_wc} ssl_read_ok_openssl={ssl_oko} ssl_read_ok_conscrypt={ssl_okc} ssl_read_gt0_openssl={ssl_gto} ssl_read_gt0_conscrypt={ssl_gtc} {}",
                mirror_diagnostics.as_deref().unwrap_or("mirror=disabled")
            );
            if let Some(detail) = mirror_diagnostics {
                pipeline.emit_inspect(ksight_model::InspectObservation {
                    adapter: "burp_mirror_diagnostics".to_owned(),
                    attached: true,
                    hit: true,
                    detail,
                    metrics: mirror_metrics,
                    detectability_notice:
                        "diagnostic counters only; no additional probe was attached".to_owned(),
                    ..ksight_model::InspectObservation::default()
                })?;
            }
            next_inspect_stats = Instant::now() + Duration::from_secs(10);
        }
        if Instant::now() >= next_crypto {
            if let Some(package) = request.package.as_deref() {
                if let Some(pid) = crate::tls_inject::TlsInject::main_pid(package) {
                    let result = crate::crypto_watch::scan_pid_ex(
                        pid,
                        package,
                        crate::crypto_watch::Paths::device(),
                    );
                    if result.added > 0 {
                        eprintln!(
                            "crypto-watch pid={pid} new={} log=/data/local/tmp/ksight/crypto-watch.log events=crypto-watch-events.jsonl",
                            result.added
                        );
                        let mut metrics = std::collections::BTreeMap::new();
                        metrics.insert("hits".to_owned(), result.added as u64);
                        for (family, count) in &result.family_hits {
                            metrics.insert((*family).to_owned(), *count as u64);
                        }
                        pipeline.emit_inspect(ksight_model::InspectObservation {
                            adapter: "crypto_watch".to_owned(),
                            attached: true,
                            hit: true,
                            detail: crate::crypto_watch::observation_detail(&result),
                            metrics,
                            detectability_notice:
                                "heap needle scan; durable events retain sha256 fingerprints + redacted previews only — never raw secrets to Burp"
                                    .to_owned(),
                            ..ksight_model::InspectObservation::default()
                        })?;
                    }
                }
            }
            next_crypto = Instant::now() + Duration::from_secs(5);
        }
        if !consumed_any {
            std::thread::sleep(Duration::from_millis(10));
        }
        if Instant::now() >= next_heartbeat {
            publish_service_health(request, &pipeline, &sensors)?;
            next_heartbeat = Instant::now() + Duration::from_secs(1);
            if pipeline.normalizer.boot_id_changed().unwrap_or(false) {
                if !pipeline.rotate(
                    ksight_model::CaptureStopReason::BootChanged,
                    &sensors,
                    request,
                )? {
                    break;
                }
            }
        }
        if pipeline.should_rotate() {
            let reason = ksight_model::CaptureStopReason::SessionRotated;
            if !pipeline.rotate(reason, &sensors, request)? {
                running.store(false, Ordering::SeqCst);
                break;
            }
        }
    }

    if request.duration_seconds != 0 {
        eprintln!(
            "duration {}s elapsed, sealing capture",
            request.duration_seconds
        );
    }
    if request.inspect.enabled {
        // Seal mirror before the final line so session-end unpaired/H2 soft
        // flushes count in mirror_deliveries (Drop alone runs too late).
        if let Some(mirror) = pipeline.burp_mirror.as_mut() {
            mirror.seal();
        }
        let (raw, decoded, lost) = inspect.drain_totals();
        let (ssl_re, ssl_rr, ssl_rok, ssl_rf, ssl_rw) = inspect.ssl_read_funnel();
        let (ssl_gt0, ssl_dgt0, ssl_wo, ssl_wc, ssl_oko, ssl_okc, ssl_gto, ssl_gtc) =
            inspect.ssl_read_funnel_ex();
        eprintln!(
            "inspect final: raw_uprobe={raw} decoded={decoded} perf_lost={lost} ssl_read_entry={ssl_re} ssl_read_ret={ssl_rr} ssl_read_ok={ssl_rok} ssl_read_fail={ssl_rf} ssl_read_want={ssl_rw} ssl_read_ret_gt0={ssl_gt0} ssl_read_drop_gt0={ssl_dgt0} ssl_read_want_openssl={ssl_wo} ssl_read_want_conscrypt={ssl_wc} ssl_read_ok_openssl={ssl_oko} ssl_read_ok_conscrypt={ssl_okc} ssl_read_gt0_openssl={ssl_gto} ssl_read_gt0_conscrypt={ssl_gtc} mirror_deliveries={}",
            pipeline
                .burp_mirror
                .as_ref()
                .map_or(0, |mirror| mirror.delivery_count())
        );
    }
    if let Some(mut child) = pcap_child.take() {
        stop_pcap_watchdog(&mut child);
        if let Some(dest) = pcap_dest.as_ref() {
            if let Ok(meta) = std::fs::metadata(dest) {
                eprintln!("pcap captured {} bytes at {}", meta.len(), dest.display());
            }
        }
    }
    if let Some(root) = request.storage.spool_root.as_ref() {
        let dest = root
            .join("forensics")
            .join(pipeline.normalizer.session_id().to_string());
        let pids = request
            .package
            .as_deref()
            .map(crate::dexdump::pids_for_package)
            .unwrap_or_default();
        let dump_deadline = Instant::now() + Duration::from_secs(8);
        for pid in pids.into_iter().take(8) {
            if Instant::now() >= dump_deadline {
                eprintln!("in-memory DEX dump budget exceeded, continuing shutdown");
                break;
            }
            let dumped = crate::dexdump::dump_live_process(pid, &dest, dump_deadline);
            let total = dumped
                .memory_images
                .saturating_add(dumped.vdex_images)
                .saturating_add(dumped.fd_images)
                .saturating_add(dumped.native_libs);
            if total > 0 {
                eprintln!(
                    "dumped pid {pid}: memory_dex={} vdex={} fd={} so={}",
                    dumped.memory_images, dumped.vdex_images, dumped.fd_images, dumped.native_libs
                );
            }
        }
    }

    let stop_reason = if pipeline.storage_limit_reached {
        ksight_model::CaptureStopReason::StorageLimitReached
    } else if !running.load(Ordering::SeqCst) {
        if request.collector_mode == ksight_model::CollectorMode::DetachedDaemon {
            ksight_model::CaptureStopReason::ServiceStop
        } else {
            ksight_model::CaptureStopReason::Signal
        }
    } else if request.count != 0 && pipeline.stats.live_emitted >= request.count {
        ksight_model::CaptureStopReason::EventLimitReached
    } else {
        ksight_model::CaptureStopReason::DurationElapsed
    };
    let dropped_by_sensor = sensors
        .iter()
        .map(|sensor| (sensor.kind(), sensor.dropped_records()))
        .collect::<std::collections::BTreeMap<_, _>>();
    pipeline.emit_session_payload(ksight_model::EventPayload::SessionCompletion(
        ksight_model::SessionCompletion {
            stop_reason,
            capture_complete: true,
            raw_records: pipeline.stats.raw_records,
            live_events: pipeline.stats.live_emitted,
            invalid_records: pipeline.stats.invalid_records,
            filtered_scope: pipeline.stats.filtered_scope,
            filtered_threads: pipeline.stats.filtered_threads,
            filtered_collector: pipeline.stats.filtered_collector,
            dropped_by_sensor: dropped_by_sensor.clone(),
        },
    ))?;
    pipeline.seal(stop_reason)?;
    write_last_exit(request, pipeline.normalizer.session_id(), stop_reason, true);
    publish_service_health(request, &pipeline, &sensors)?;
    let dropped = sensors
        .iter()
        .map(|sensor| format!("{}:{}", sensor.name, sensor.dropped_records()))
        .collect::<Vec<_>>()
        .join(",");
    std::io::stdout().flush()?;
    let summary = format!(
        "capture complete: raw={} live_emitted={} total_emitted={} filtered_threads={} filtered_scope={} filtered_collector={} invalid={} active_instances={} dropped=[{}] elapsed_ms={}",
        pipeline.stats.raw_records,
        pipeline.stats.live_emitted,
        pipeline.stats.emitted,
        pipeline.stats.filtered_threads,
        pipeline.stats.filtered_scope,
        pipeline.stats.filtered_collector,
        pipeline.stats.invalid_records,
        pipeline.process_instances.len(),
        dropped,
        started.elapsed().as_millis()
    );
    print_summary(request.output.json, &summary);
    if let Some(spool) = pipeline.spool.as_ref() {
        let summary = format!(
            "spool complete: directory={} batches={} bytes={}",
            spool.directory().display(),
            spool.persisted_batches(),
            spool.used_bytes()
        );
        print_summary(request.output.json, &summary);
    }
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn publish_service_health(
    request: &CaptureRequest,
    pipeline: &EventPipeline,
    sensors: &[ActiveSensor],
) -> Result<()> {
    let Some(status) = request.status.as_ref() else {
        return Ok(());
    };
    let dropped_by_sensor = sensors
        .iter()
        .map(|sensor| (sensor.name.to_owned(), sensor.dropped_records()))
        .collect();
    status.update(crate::service::ServiceHealth {
        session_id: Some(pipeline.normalizer.session_id()),
        attached_sensors: sensors
            .iter()
            .map(|sensor| sensor.name.to_owned())
            .collect(),
        raw_records: pipeline.stats.raw_records,
        live_events: pipeline.stats.live_emitted,
        invalid_records: pipeline.stats.invalid_records,
        filtered_scope: pipeline.stats.filtered_scope,
        filtered_threads: pipeline.stats.filtered_threads,
        filtered_collector: pipeline.stats.filtered_collector,
        dropped_by_sensor,
        spool_used_bytes: pipeline
            .spool
            .as_ref()
            .map_or(0, |spool| spool.used_bytes()),
        spool_limit_bytes: request.storage.max_spool_bytes,
        last_event_monotonic_ns: pipeline.last_event_monotonic_ns,
        heartbeat_monotonic_ns: monotonic_now_ns(),
        scope_pid: request.pid,
        scope_uid: request.uid,
        scope_package: request.package.clone(),
    })?;
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn print_summary(json_output: bool, summary: &str) {
    if json_output {
        eprintln!("{summary}");
    } else {
        println!("{summary}");
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
struct ActiveSensor {
    name: &'static str,
    collector: Box<dyn crate::collector::Collector<Error = ksight_abi::DecodeError>>,
}

#[cfg(any(target_os = "android", target_os = "linux"))]
impl ActiveSensor {
    fn new(
        name: &'static str,
        collector: impl crate::collector::Collector<Error = ksight_abi::DecodeError> + 'static,
    ) -> Self {
        Self {
            name,
            collector: Box::new(collector),
        }
    }

    fn next_record(
        &mut self,
    ) -> Result<Option<crate::collector::RawRecord>, ksight_abi::DecodeError> {
        self.collector.next_record()
    }

    fn dropped_records(&self) -> u64 {
        self.collector.dropped_records()
    }

    fn kind(&self) -> ksight_model::SensorKind {
        match self.name {
            "process" => ksight_model::SensorKind::Process,
            "file" => ksight_model::SensorKind::File,
            "network" => ksight_model::SensorKind::Network,
            "memory" => ksight_model::SensorKind::Memory,
            "binder" => ksight_model::SensorKind::Binder,
            "sched" => ksight_model::SensorKind::Sched,
            _ => ksight_model::SensorKind::Integrity,
        }
    }

    fn seed_socket_fds(&mut self, entries: &[(u32, i32)]) {
        self.collector.seed_socket_fds(entries);
    }
}

#[cfg(any(test, target_os = "android", target_os = "linux"))]
#[derive(Debug, Clone, Default)]
struct PendingParcel {
    interface_token: Option<String>,
    binder_method: Option<String>,
    binder_method_source: Option<String>,
    parcel_prefix_hex: Option<String>,
}

#[cfg(any(test, target_os = "android", target_os = "linux"))]
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
fn insert_capped<K: Eq + std::hash::Hash, V>(
    map: &mut std::collections::HashMap<K, V>,
    key: K,
    value: V,
) {
    if map.len() >= 4096 && !map.contains_key(&key) {
        return;
    }
    map.insert(key, value);
}

#[cfg(any(test, target_os = "android", target_os = "linux"))]
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
fn push_capped_deque<K: Eq + std::hash::Hash, V>(
    map: &mut std::collections::HashMap<K, std::collections::VecDeque<V>>,
    key: K,
    value: V,
    cap: usize,
) {
    if map.len() >= 4096 && !map.contains_key(&key) {
        return;
    }
    let queue = map.entry(key).or_default();
    if queue.len() >= cap {
        queue.pop_front();
    }
    queue.push_back(value);
}

#[cfg(any(test, target_os = "android", target_os = "linux"))]
fn apply_pending_parcel(transaction: &mut ksight_model::BinderTransaction, parcel: PendingParcel) {
    if transaction.interface_token.is_none() {
        transaction.interface_token = parcel.interface_token;
    }
    if transaction.binder_method.is_none() {
        transaction.binder_method = parcel.binder_method;
    }
    if transaction.binder_method_source.is_none() {
        transaction.binder_method_source = parcel.binder_method_source;
    }
    if transaction.parcel_prefix_hex.is_none() {
        transaction.parcel_prefix_hex = parcel.parcel_prefix_hex;
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[derive(Debug, Default)]
struct CaptureStats {
    raw_records: u64,
    live_emitted: u64,
    emitted: u64,
    filtered_threads: u64,
    filtered_scope: u64,
    filtered_collector: u64,
    invalid_records: u64,
}

#[cfg(any(target_os = "android", target_os = "linux"))]
struct EventPipeline {
    normalizer: crate::normalize::EventNormalizer,
    identity_resolver: crate::identity::AndroidIdentityResolver,
    process_instances: crate::aggregate::ProcessInstanceTracker,
    scope: crate::scope::CaptureScope,
    output: OutputOptions,
    spool: Option<crate::spool::SessionSpoolWriter>,
    sampling: SamplingOptions,
    collector_mode: ksight_model::CollectorMode,
    storage: StorageOptions,
    environment: ksight_model::SessionEnvironment,
    storage_limit_reached: bool,
    binder_transactions_in_scope: std::collections::HashSet<i32>,
    /// Kernel parcel prefix waiting to join the matching submit `debug_id`.
    pending_parcels: std::collections::HashMap<i32, PendingParcel>,
    /// Fallback join when the kprobe event has `transaction_id=0`.
    pending_parcels_by_tid_code:
        std::collections::HashMap<(u32, u32), std::collections::VecDeque<PendingParcel>>,
    /// Last-resort FIFO when the same thread pipelines identical codes.
    pending_parcels_by_tid:
        std::collections::HashMap<u32, std::collections::VecDeque<PendingParcel>>,
    /// 已提交且等待回复的请求事务：transaction_id -> 提交时刻（monotonic_ns）。
    binder_request_timestamps: std::collections::HashMap<i32, u64>,
    /// 跨进程文件描述符血缘追踪。
    fd_lineage: crate::fd_lineage::FdLineageTracker,
    dns_lineage: crate::dns_lineage::DnsLineageTracker,
    session_sequence: u64,
    collector_pid: u32,
    last_event_monotonic_ns: Option<u64>,
    stats: CaptureStats,
    burp_mirror: Option<crate::burp_mirror::BurpMirror>,
}

#[cfg(any(test, target_os = "android", target_os = "linux"))]
fn binder_event_matches_scope(
    process_matches_scope: bool,
    payload: &ksight_model::EventPayload,
    transactions_in_scope: &mut std::collections::HashSet<i32>,
) -> bool {
    use ksight_model::{BinderTransactionStage, EventPayload};

    let EventPayload::BinderTransaction(transaction) = payload else {
        return false;
    };
    if process_matches_scope && transaction.stage == BinderTransactionStage::Submitted {
        transactions_in_scope.insert(transaction.transaction_id);
    }
    let matches =
        process_matches_scope || transactions_in_scope.contains(&transaction.transaction_id);
    if matches && transaction.stage == BinderTransactionStage::Received {
        transactions_in_scope.remove(&transaction.transaction_id);
    }
    matches
}

#[cfg(any(target_os = "android", target_os = "linux"))]
impl EventPipeline {
    #[allow(clippy::too_many_arguments)]
    fn new(
        normalizer: crate::normalize::EventNormalizer,
        identity_resolver: crate::identity::AndroidIdentityResolver,
        scope: crate::scope::CaptureScope,
        output: OutputOptions,
        spool: Option<crate::spool::SessionSpoolWriter>,
        sampling: SamplingOptions,
        collector_mode: ksight_model::CollectorMode,
        storage: StorageOptions,
        environment: ksight_model::SessionEnvironment,
    ) -> Self {
        let mut process_instances = crate::aggregate::ProcessInstanceTracker::default();
        process_instances.discover_zygotes();
        Self {
            normalizer,
            identity_resolver,
            process_instances,
            scope,
            output,
            spool,
            sampling,
            collector_mode,
            storage,
            environment,
            storage_limit_reached: false,
            binder_transactions_in_scope: std::collections::HashSet::new(),
            pending_parcels: std::collections::HashMap::new(),
            pending_parcels_by_tid_code: std::collections::HashMap::new(),
            pending_parcels_by_tid: std::collections::HashMap::new(),
            binder_request_timestamps: std::collections::HashMap::new(),
            fd_lineage: crate::fd_lineage::FdLineageTracker::default(),
            dns_lineage: crate::dns_lineage::DnsLineageTracker::default(),
            session_sequence: 0,
            collector_pid: std::process::id(),
            last_event_monotonic_ns: None,
            stats: CaptureStats::default(),
            burp_mirror: None,
        }
    }

    fn emit(&mut self, record: crate::collector::RawRecord) -> Result<()> {
        use crate::normalize::Normalizer as _;

        self.stats.raw_records += 1;
        let mut event = match self.normalizer.normalize(record) {
            Ok(event) => event,
            Err(error) => {
                self.stats.invalid_records += 1;
                eprintln!("discard invalid raw record: {error}");
                return Ok(());
            }
        };
        if self.absorb_or_apply_parcel(&mut event) {
            return Ok(());
        }
        let emitted_before = self.stats.emitted;
        self.finalize_event(&mut event)?;
        self.stats.live_emitted = self
            .stats
            .live_emitted
            .saturating_add(self.stats.emitted.saturating_sub(emitted_before));
        Ok(())
    }

    /// Emit a pre-built event (for example a session-start baseline).
    fn emit_event(&mut self, mut event: ksight_model::Event) -> Result<()> {
        self.finalize_event(&mut event)
    }

    fn emit_session_payload(&mut self, payload: ksight_model::EventPayload) -> Result<()> {
        self.session_sequence = self.session_sequence.saturating_add(1);
        let event = ksight_model::Event {
            header: session_event_header(
                &self.normalizer,
                self.session_sequence,
                ksight_model::CaptureMode::Observe,
            ),
            payload,
        };
        self.publish_event(&event)
    }

    /// Active capture package for inspect/crypto-watch correlation (no offsets).
    fn package_name(&self) -> Option<&str> {
        self.scope
            .target_package
            .as_deref()
            .filter(|p| !p.is_empty())
    }

    fn emit_inspect(&mut self, observation: ksight_model::InspectObservation) -> Result<()> {
        self.emit_inspect_payload(
            None,
            None,
            ksight_model::EventPayload::InspectObservation(observation),
        )
    }

    fn emit_inspect_output(&mut self, output: crate::inspect_runtime::InspectOutput) -> Result<()> {
        match output {
            crate::inspect_runtime::InspectOutput::Observation {
                pid,
                tid,
                observation,
            } => self.emit_inspect_payload(
                Some(pid).filter(|pid| *pid > 0),
                Some(tid).filter(|tid| *tid > 0),
                ksight_model::EventPayload::InspectObservation(observation),
            ),
            crate::inspect_runtime::InspectOutput::Plaintext {
                pid,
                tid,
                connection_id: _,
                fragment,
                raw: _,
            } => {
                // Opt-in corridor: feed pre-encrypt markers into versioned rules.
                // Keep --inspect-jni opt-in (packer grace). Do NOT auto-enable with --mirror-burp.
                // Never push crypto-watch raw windows to Burp — fingerprints / path_hint only.
                // Live guards: skip empty preview and content_class=="tls_record".
                if !fragment.preview.is_empty() && fragment.content_class != "tls_record" {
                    if let Some(package) = self.package_name() {
                        if let Some(hit) = crate::crypto_watch::ingest_inspect_plaintext(
                            package,
                            fragment.adapter.as_str(),
                            fragment.preview.as_str(),
                            Some(fragment.sha256.as_str()).filter(|s| !s.is_empty()),
                            &crate::crypto_watch::Paths::device(),
                        ) {
                            let mut metrics = std::collections::BTreeMap::new();
                            metrics.insert("ingest".to_owned(), 1);
                            metrics.insert(hit.family.to_owned(), 1);
                            let _ = self.emit_inspect(ksight_model::InspectObservation {
                                adapter: format!("crypto_watch:{}", hit.source),
                                attached: true,
                                hit: true,
                                path_hint: Some(hit.path_hint.clone()),
                                detail: hit.detail.clone(),
                                metrics,
                                detectability_notice:
                                    "inspect plaintext classified into crypto-watch-rules.json; redacted preview + sha256 only — never raw secrets to Burp"
                                        .to_owned(),
                                ..ksight_model::InspectObservation::default()
                            });
                        }
                    }
                }
                self.emit_inspect_payload(
                    Some(pid),
                    Some(tid),
                    ksight_model::EventPayload::InspectPlaintext(fragment),
                )
            }
        }
    }

    fn emit_inspect_payload(
        &mut self,
        pid: Option<u32>,
        tid: Option<u32>,
        payload: ksight_model::EventPayload,
    ) -> Result<()> {
        self.session_sequence = self.session_sequence.saturating_add(1);
        let mut header = session_event_header(
            &self.normalizer,
            self.session_sequence,
            ksight_model::CaptureMode::Inspect,
        );
        if let Some(pid) = pid.filter(|pid| *pid > 0) {
            header.process = crate::inspect_runtime::process_identity(
                pid,
                tid.unwrap_or(pid),
                self.normalizer.boot_id(),
            );
            self.identity_resolver.enrich(&mut header.process);
        }
        self.publish_event(&ksight_model::Event { header, payload })
    }

    fn finalize_event(&mut self, event: &mut ksight_model::Event) -> Result<()> {
        use ksight_model::{EventPayload, SensorKind};

        self.identity_resolver.enrich(&mut event.header.process);
        if event.header.process.tgid == self.collector_pid {
            self.stats.filtered_collector = self.stats.filtered_collector.saturating_add(1);
            return Ok(());
        }
        self.process_instances.correlate(event);
        self.correlate_binder_request_reply(event);
        event.header.quality.sample_one_in = self.sampling.for_sensor(event.header.sensor);
        let process_matches_scope = self.scope.matches(&event.header.process);
        let binder_matches_scope = binder_event_matches_scope(
            process_matches_scope,
            &event.payload,
            &mut self.binder_transactions_in_scope,
        );
        if !process_matches_scope && !binder_matches_scope {
            self.stats.filtered_scope += 1;
            return Ok(());
        }
        if let EventPayload::FileOpen(open) = &mut event.payload {
            crate::file::resolve_open_path(event.header.process.key.pid, open);
            if let Some(root) = self.storage.spool_root.as_ref() {
                let dest = root
                    .join("forensics")
                    .join(self.normalizer.session_id().to_string());
                crate::file::snapshot_forensic(event.header.process.key.pid, open, &dest);
            }
        }
        if let EventPayload::MemoryRegionChange(change) = &mut event.payload {
            crate::memory::resolve_backing_path(event.header.process.key.pid, change);
        }
        self.fd_lineage.correlate(event);
        self.dns_lineage.correlate(event);
        if let Some(mirror) = self.burp_mirror.as_mut() {
            match &event.payload {
                EventPayload::SocketConnect(_) => mirror.observe_network_connect(),
                EventPayload::NetworkHandshake(_) => mirror.observe_network_handshake(),
                _ => {}
            }
        }
        let pid = event.header.process.key.pid;
        let tid = event.header.process.tid;
        if let (Some(mirror), EventPayload::SocketConnect(connect)) =
            (self.burp_mirror.as_mut(), &event.payload)
        {
            if let Some(name) = connect
                .resolved_name
                .as_deref()
                .map(str::trim)
                .filter(|name| !name.is_empty())
            {
                mirror.observe_peer_on_thread(pid, tid, name.to_owned());
            }
        }
        if let (Some(mirror), EventPayload::NetworkHandshake(handshake)) =
            (self.burp_mirror.as_mut(), &event.payload)
        {
            if let Some(host) = handshake_mirror_host(handshake) {
                mirror.observe_peer_on_thread(pid, tid, host);
            }
            if let Some(prefix) = handshake.request_prefix.as_deref() {
                mirror.observe_bytes(pid, tid, "handshake_http", "send", prefix.as_bytes());
            }
        }
        if !self.output.include_threads
            && event.header.sensor == SensorKind::Process
            && event.header.process.tid != event.header.process.tgid
        {
            self.stats.filtered_threads += 1;
            return Ok(());
        }
        self.publish_event(event)
    }

    fn publish_event(&mut self, event: &ksight_model::Event) -> Result<()> {
        self.last_event_monotonic_ns = Some(event.header.monotonic_ns);
        if let Some(spool) = self.spool.as_mut() {
            spool.push(event)?;
        }
        if !self.output.quiet {
            if self.output.json {
                println!("{}", serde_json::to_string(event)?);
            } else {
                print_event(event);
            }
        }
        self.stats.emitted += 1;
        Ok(())
    }

    fn absorb_or_apply_parcel(&mut self, event: &mut ksight_model::Event) -> bool {
        use ksight_model::{BinderTransactionStage, EventPayload};

        let EventPayload::BinderTransaction(transaction) = &mut event.payload else {
            return false;
        };
        match transaction.stage {
            BinderTransactionStage::ParcelPrefix => {
                let parcel = PendingParcel {
                    interface_token: transaction.interface_token.clone(),
                    binder_method: transaction.binder_method.clone(),
                    binder_method_source: transaction.binder_method_source.clone(),
                    parcel_prefix_hex: transaction.parcel_prefix_hex.clone(),
                };
                if transaction.transaction_id != 0 {
                    insert_capped(
                        &mut self.pending_parcels,
                        transaction.transaction_id,
                        parcel.clone(),
                    );
                }
                push_capped_deque(
                    &mut self.pending_parcels_by_tid_code,
                    (event.header.process.tid, transaction.code),
                    parcel.clone(),
                    8,
                );
                push_capped_deque(
                    &mut self.pending_parcels_by_tid,
                    event.header.process.tid,
                    parcel,
                    16,
                );
                true
            }
            BinderTransactionStage::Submitted => {
                let parcel = self
                    .pending_parcels
                    .remove(&transaction.transaction_id)
                    .or_else(|| {
                        self.pending_parcels_by_tid_code
                            .get_mut(&(event.header.process.tid, transaction.code))
                            .and_then(std::collections::VecDeque::pop_front)
                    })
                    .or_else(|| {
                        self.pending_parcels_by_tid
                            .get_mut(&event.header.process.tid)
                            .and_then(std::collections::VecDeque::pop_front)
                    });
                if let Some(parcel) = parcel {
                    apply_pending_parcel(transaction, parcel);
                }
                false
            }
            _ => false,
        }
    }

    /// Correlate a Binder request transaction with its reply to expose latency.
    fn correlate_binder_request_reply(&mut self, event: &mut ksight_model::Event) {
        use ksight_model::{BinderTransactionStage, EventPayload};

        let EventPayload::BinderTransaction(transaction) = &mut event.payload else {
            return;
        };
        if transaction.stage != BinderTransactionStage::Submitted {
            return;
        }
        if transaction.reply {
            if let Some(request_id) = transaction.reply_to_request_id {
                transaction.reply_latency_ns = self
                    .binder_request_timestamps
                    .remove(&request_id)
                    .map(|submitted_ns| event.header.monotonic_ns.saturating_sub(submitted_ns));
            }
        } else if (transaction.flags & 0x1) == 0
            && !transaction
                .decoded_flags
                .contains(&ksight_model::BinderTransactionFlag::OneWay)
        {
            self.binder_request_timestamps
                .insert(transaction.transaction_id, event.header.monotonic_ns);
        }
    }

    fn should_rotate(&self) -> bool {
        self.collector_mode == ksight_model::CollectorMode::DetachedDaemon
            && self
                .spool
                .as_ref()
                .is_some_and(|spool| spool.should_rotate(self.storage.max_session_age_secs))
    }

    fn rotate(
        &mut self,
        reason: ksight_model::CaptureStopReason,
        sensors: &[ActiveSensor],
        request: &CaptureRequest,
    ) -> Result<bool> {
        let dropped_by_sensor = sensors
            .iter()
            .map(|sensor| (sensor.kind(), sensor.dropped_records()))
            .collect::<std::collections::BTreeMap<_, _>>();
        self.emit_session_payload(ksight_model::EventPayload::SessionCompletion(
            ksight_model::SessionCompletion {
                stop_reason: reason,
                capture_complete: true,
                raw_records: self.stats.raw_records,
                live_events: self.stats.live_emitted,
                invalid_records: self.stats.invalid_records,
                filtered_scope: self.stats.filtered_scope,
                filtered_threads: self.stats.filtered_threads,
                filtered_collector: self.stats.filtered_collector,
                dropped_by_sensor,
            },
        ))?;
        self.seal(reason)?;
        let Some(root) = self.storage.spool_root.clone() else {
            return Ok(false);
        };
        let retention = crate::retention::SpoolRetention {
            root: root.clone(),
            max_total_bytes: self.storage.max_total_spool_bytes,
            keep_completed: self.storage.keep_completed_sessions,
        };
        let _ = retention.prune();
        if !retention.can_open_session().unwrap_or(false) {
            self.storage_limit_reached = true;
            write_last_exit(request, self.normalizer.session_id(), reason, true);
            return Ok(false);
        }
        let session_id = self.normalizer.rotate_session();
        self.session_sequence = 0;
        self.spool = Some(crate::spool::SessionSpoolWriter::open_with(
            root,
            session_id,
            self.storage.max_spool_bytes,
            self.storage.events_per_batch,
            crate::spool::SpoolOptions {
                compress: self.storage.compress_batches,
                completion_reserve_bytes: self.storage.completion_reserve_bytes,
            },
        )?);
        self.emit_session_payload(ksight_model::EventPayload::SessionEnvironment(
            self.environment.clone(),
        ))?;
        Ok(true)
    }

    fn seal(&mut self, reason: ksight_model::CaptureStopReason) -> Result<()> {
        if let Some(spool) = self.spool.as_mut() {
            let state = match reason {
                ksight_model::CaptureStopReason::SessionRotated => {
                    ksight_protocol::DurableSessionState::Rotated
                }
                ksight_model::CaptureStopReason::StorageLimitReached => {
                    ksight_protocol::DurableSessionState::StorageLimited
                }
                _ => ksight_protocol::DurableSessionState::Completed,
            };
            spool.seal(state, Some(reason))?;
        }
        Ok(())
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn write_last_exit(
    request: &CaptureRequest,
    session_id: uuid::Uuid,
    reason: ksight_model::CaptureStopReason,
    clean: bool,
) {
    let Some(root) = request.storage.spool_root.clone() else {
        return;
    };
    let retention = crate::retention::SpoolRetention {
        root,
        max_total_bytes: request.storage.max_total_spool_bytes,
        keep_completed: request.storage.keep_completed_sessions,
    };
    let _ = retention.write_last_exit(&crate::retention::ExitRecord {
        session_id: Some(session_id),
        reason: format!("{reason:?}"),
        detail: None,
        clean,
    });
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn session_event_header(
    normalizer: &crate::normalize::EventNormalizer,
    source_sequence: u64,
    mode: ksight_model::CaptureMode,
) -> ksight_model::EventHeader {
    let pid = std::process::id();
    let (uid, gid) = current_credentials();
    ksight_model::EventHeader {
        schema: ksight_model::CURRENT_SCHEMA,
        session_id: normalizer.session_id(),
        source_sequence,
        monotonic_ns: monotonic_now_ns(),
        cpu: None,
        process: ksight_model::ProcessIdentity {
            key: ksight_model::ProcessKey {
                boot_id: normalizer.boot_id(),
                pid,
                start_time_ns: 0,
            },
            tid: pid,
            tgid: pid,
            uid,
            gid,
            comm: "ksightd".to_owned(),
            command_line: None,
            selinux_context: None,
            packages: Vec::new(),
        },
        sensor: ksight_model::SensorKind::Integrity,
        mode,
        quality: ksight_model::DataQuality {
            confidence: ksight_model::Confidence::Confirmed,
            truncated: false,
            lost_before: 0,
            sample_one_in: 1,
            source: "ksight/session".to_owned(),
        },
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn same_environment_state(
    left: &ksight_model::SessionEnvironment,
    right: &ksight_model::SessionEnvironment,
) -> bool {
    left.collector_mode == right.collector_mode
        && left.developer_options == right.developer_options
        && left.usb_debugging == right.usb_debugging
        && left.wireless_debugging == right.wireless_debugging
        && left.root_authorized == right.root_authorized
        && left.selinux_enforcing == right.selinux_enforcing
        && left.verified_boot_state == right.verified_boot_state
        && left.bootloader_locked == right.bootloader_locked
        && left.target_behavior_may_be_altered == right.target_behavior_may_be_altered
        && left.warnings == right.warnings
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn monotonic_now_ns() -> u64 {
    nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
        .ok()
        .and_then(|time| {
            let seconds = u64::try_from(time.tv_sec()).ok()?;
            let nanoseconds = u64::try_from(time.tv_nsec()).ok()?;
            seconds
                .checked_mul(1_000_000_000)
                .and_then(|value| value.checked_add(nanoseconds))
        })
        .unwrap_or(0)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn current_credentials() -> (u32, u32) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let parse = |prefix: &str| {
        status
            .lines()
            .find(|line| line.starts_with(prefix))
            .and_then(|line| line.split_whitespace().nth(2))
            .and_then(|value| value.parse().ok())
            .unwrap_or(0)
    };
    (parse("Uid:"), parse("Gid:"))
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn handshake_mirror_host(handshake: &ksight_model::NetworkHandshake) -> Option<String> {
    if let Some(host) = handshake
        .http_host
        .as_deref()
        .map(str::trim)
        .filter(|host| !host.is_empty())
    {
        return Some(host.to_owned());
    }
    if let Some(sni) = handshake
        .sni
        .as_deref()
        .map(str::trim)
        .filter(|sni| !sni.is_empty())
    {
        return Some(sni.to_owned());
    }
    let address = handshake
        .peer_address
        .as_deref()
        .filter(|addr| !addr.is_empty())?;
    if handshake.peer_port > 0 {
        Some(format!("{address}:{}", handshake.peer_port))
    } else {
        Some(address.to_owned())
    }
}

/// Classify mapped network/crypto stacks using path, file-size and the embedded
/// rule table. Build-id-only rules remain candidates here; actual attachment
/// still requires the stricter probe-side validation.
#[cfg(any(target_os = "android", target_os = "linux"))]
fn mapped_stack_coverage(package: &str) -> crate::burp_mirror::StackCoverageSnapshot {
    let mut paths = std::collections::BTreeSet::new();
    for pid in crate::dexdump::pids_for_package(package)
        .into_iter()
        .take(8)
    {
        let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
            continue;
        };
        for line in maps.lines() {
            let Some(path) = line.split_whitespace().last() else {
                continue;
            };
            if path.starts_with('/') && !path.contains(" (deleted)") {
                paths.insert(path.to_owned());
            }
        }
    }

    let mut matched = std::collections::BTreeMap::new();
    for path in paths {
        let size = std::fs::metadata(&path).ok().map(|meta| meta.len());
        for stack in &ksight_core::load_stack_rules().stacks {
            let mut path_rule = stack.match_rules.clone();
            path_rule.build_id = None;
            if path_rule.matches(&path, size, None) {
                matched.entry(stack.id.clone()).or_insert(stack);
            }
        }
    }

    let mut snapshot = crate::burp_mirror::StackCoverageSnapshot {
        candidates: u64::try_from(matched.len()).unwrap_or(u64::MAX),
        ..crate::burp_mirror::StackCoverageSnapshot::default()
    };
    for stack in matched.values() {
        let export_candidate = stack.coverage.plaintext_copy
            && (!stack.symbols.write.is_empty() || !stack.symbols.read.is_empty());
        let pinned_boundary = stack
            .boundary
            .as_ref()
            .is_some_and(|boundary| boundary.layout.eq_ignore_ascii_case("pinned"));
        let empirical_boundary = stack
            .boundary
            .as_ref()
            .is_some_and(|boundary| !boundary.layout.eq_ignore_ascii_case("pinned"));
        let keylog_candidate = stack.coverage.keylog == Some(true)
            && stack
                .keylog
                .as_ref()
                .is_some_and(|rule| rule.offset.is_some());
        snapshot.export_candidates = snapshot
            .export_candidates
            .saturating_add(u64::from(export_candidate));
        snapshot.pinned_boundaries = snapshot
            .pinned_boundaries
            .saturating_add(u64::from(pinned_boundary));
        snapshot.empirical_boundaries = snapshot
            .empirical_boundaries
            .saturating_add(u64::from(empirical_boundary));
        snapshot.keylog_candidates = snapshot
            .keylog_candidates
            .saturating_add(u64::from(keylog_candidate));
        if !export_candidate && !pinned_boundary && !keylog_candidate {
            snapshot.uncovered = snapshot.uncovered.saturating_add(1);
        }
    }
    snapshot
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn print_event(event: &ksight_model::Event) {
    let process = &event.header.process;
    let package = process
        .packages
        .first()
        .filter(|candidate| candidate.confidence_percent >= 90)
        .map_or_else(String::new, |candidate| {
            format!(" package={}", candidate.package_name)
        });
    let command_line = process
        .command_line
        .as_deref()
        .map_or_else(String::new, |command| format!(" cmd={command}"));
    let (kind, detail) = format_payload(&event.payload);
    let sampling = (event.header.quality.sample_one_in > 1)
        .then(|| format!(" sample=1/{}", event.header.quality.sample_one_in))
        .unwrap_or_default();
    println!(
        "seq={} cpu={} uid={} pid={} tid={} comm={} kind={}{}{}{}{}",
        event.header.source_sequence,
        event.header.cpu.unwrap_or_default(),
        process.uid,
        process.key.pid,
        process.tid,
        process.comm,
        kind,
        sampling,
        package,
        command_line,
        detail
    );
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn format_payload(payload: &ksight_model::EventPayload) -> (String, String) {
    use ksight_model::EventPayload;

    match payload {
        EventPayload::ProcessLifecycle(lifecycle) => (
            format!("{:?}", lifecycle.kind),
            lifecycle
                .filename
                .as_deref()
                .map_or_else(String::new, |filename| format!(" file={filename}")),
        ),
        EventPayload::ProcessIdentityChange(change) => (
            format!("{:?}", change.kind),
            change
                .previous_comm
                .as_deref()
                .map_or_else(String::new, |comm| format!(" previous_comm={comm}")),
        ),
        EventPayload::FileOpen(open) => (
            "FileOpen".to_owned(),
            format!(
                " path={} result={} flags={:#x} mode={:#o}",
                open.resolved_path.as_deref().unwrap_or(&open.path),
                open.result,
                open.flags,
                open.mode
            ),
        ),
        EventPayload::FileDescriptorChange(change) => (
            format!("Fd{:?}", change.operation),
            format!(
                " fd={} last={} requested={} resulting={} result={} command={} flags={:#x}",
                change.file_descriptor,
                change
                    .last_file_descriptor
                    .map_or_else(|| "-".to_owned(), |fd| fd.to_string()),
                change
                    .requested_file_descriptor
                    .map_or_else(|| "-".to_owned(), |fd| fd.to_string()),
                change
                    .resulting_file_descriptor
                    .map_or_else(|| "-".to_owned(), |fd| fd.to_string()),
                change.result,
                change.command,
                change.flags
            ),
        ),
        EventPayload::SocketConnect(connect) => (
            "SocketConnect".to_owned(),
            format!(
                " fd={} result={} family={} addr_len={}/{} peer={} port={} name={}",
                connect.file_descriptor,
                connect.result,
                connect.address_family,
                connect.captured_address_length,
                connect.submitted_address_length,
                connect.peer_address.as_deref().unwrap_or("unknown"),
                connect
                    .peer_port
                    .map_or_else(|| "-".to_owned(), |port| port.to_string()),
                connect.resolved_name.as_deref().unwrap_or("-")
            ),
        ),
        EventPayload::DnsDatagram(datagram) => (
            "DnsDatagram".to_owned(),
            format!(
                " fd={} result={} dir={} port={} peer={} qname={} addrs={} trunc={}",
                datagram.file_descriptor,
                datagram.result,
                datagram.direction,
                datagram.peer_port,
                datagram.peer_address.as_deref().unwrap_or("-"),
                datagram.qname.as_deref().unwrap_or("-"),
                datagram.addresses.join(","),
                datagram.truncated
            ),
        ),
        EventPayload::NetworkHandshake(handshake) => (
            "NetworkHandshake".to_owned(),
            format!(
                " fd={} result={} kind={} port={} peer={} sni={} alpn={} ech={} http={} host={} quic={} trunc={}",
                handshake.file_descriptor,
                handshake.result,
                handshake.kind,
                handshake.peer_port,
                handshake.peer_address.as_deref().unwrap_or("-"),
                handshake.sni.as_deref().unwrap_or("-"),
                handshake.alpn.as_deref().unwrap_or("-"),
                handshake.ech,
                handshake.http_method.as_deref().unwrap_or("-"),
                handshake.http_host.as_deref().unwrap_or("-"),
                handshake
                    .quic_packet
                    .as_deref()
                    .or(handshake.quic_version.as_deref())
                    .unwrap_or("-"),
                handshake.truncated
            ),
        ),
        EventPayload::SocketAccept(accept) => (
            "SocketAccept".to_owned(),
            format!(
                " listen_fd={} accepted_fd={} result={} family={} addr_len={}/{} peer={} port={}",
                accept.listening_file_descriptor,
                accept
                    .accepted_file_descriptor
                    .map_or_else(|| "-".to_owned(), |fd| fd.to_string()),
                accept.result,
                accept.address_family,
                accept.captured_address_length,
                accept.returned_address_length,
                accept.peer_address.as_deref().unwrap_or("unknown"),
                accept
                    .peer_port
                    .map_or_else(|| "-".to_owned(), |port| port.to_string())
            ),
        ),
        EventPayload::SocketIo(io) => (
            format!("Socket{:?}", io.operation),
            format!(
                " fd={} result={} requested={} syscall={}",
                io.file_descriptor,
                io.result,
                io.requested_bytes.map_or_else(
                    || "-".to_owned(),
                    |requested| requested.to_string()
                ),
                io.syscall
            ),
        ),
        EventPayload::MemoryRegionChange(change) => (
            format!("Memory{:?}", change.operation),
            format!(
                " address={:#x} length={} result={} prot={:#x} flags={} backing={}",
                change.address,
                change.length,
                change.result,
                change.protection,
                change
                    .mapping_flags
                    .map_or_else(|| "-".to_owned(), |flags| format!("{flags:#x}")),
                change.backing_path.as_deref().unwrap_or("-")
            ),
        ),
        EventPayload::BinderTransaction(transaction) => (
            format!("Binder{:?}", transaction.stage),
            format!(
                " tx={} target={}:{} node={} reply={} code={:#x} flags={:#x} bytes={}/{}/{} fd={} object_offset={} origin={} src={}:{} token={} method={} prefix={}",
                transaction.transaction_id,
                transaction
                    .target_process_id
                    .map_or_else(|| "-".to_owned(), |pid| pid.to_string()),
                transaction
                    .target_thread_id
                    .map_or_else(|| "-".to_owned(), |tid| tid.to_string()),
                transaction
                    .target_node
                    .map_or_else(|| "-".to_owned(), |node| node.to_string()),
                transaction.reply,
                transaction.code,
                transaction.flags,
                transaction
                    .data_size
                    .map_or_else(|| "-".to_owned(), |size| size.to_string()),
                transaction
                    .offsets_size
                    .map_or_else(|| "-".to_owned(), |size| size.to_string()),
                transaction
                    .extra_buffers_size
                    .map_or_else(|| "-".to_owned(), |size| size.to_string()),
                transaction
                    .file_descriptor
                    .map_or_else(|| "-".to_owned(), |fd| fd.to_string()),
                transaction
                    .object_offset
                    .map_or_else(|| "-".to_owned(), |offset| offset.to_string()),
                transaction.transferred_fd_origin.as_deref().unwrap_or("-"),
                transaction
                    .transferred_fd_source_pid
                    .map_or_else(|| "-".to_owned(), |pid| pid.to_string()),
                transaction
                    .transferred_fd_source_fd
                    .map_or_else(|| "-".to_owned(), |fd| fd.to_string()),
                transaction
                    .interface_token
                    .as_deref()
                    .unwrap_or("-"),
                transaction.binder_method.as_deref().unwrap_or("-"),
                transaction.parcel_prefix_hex.as_deref().unwrap_or("-")
            ),
        ),
        EventPayload::SessionFdBaseline(baseline) => (
            "FdBaseline".to_owned(),
            format!(" pid={} fds={}", baseline.process_id, baseline.fds.len()),
        ),
        EventPayload::SessionVmaBaseline(baseline) => (
            "VmaBaseline".to_owned(),
            format!(" pid={} vmas={}", baseline.process_id, baseline.vmas.len()),
        ),
        EventPayload::SchedWakeup(wakeup) => (
            "SchedWakeup".to_owned(),
            format!(
                " wakee_tid={} prio={} target_cpu={}",
                wakeup.wakee_tid, wakeup.wakee_prio, wakeup.target_cpu
            ),
        ),
        EventPayload::SessionEnvironment(environment) => (
            "SessionEnvironment".to_owned(),
            format!(
                " collector={:?} developer={:?} usb_debug={:?} wireless_debug={:?} root={} altered={}",
                environment.collector_mode,
                environment.developer_options,
                environment.usb_debugging,
                environment.wireless_debugging,
                environment.root_authorized,
                environment.target_behavior_may_be_altered
            ),
        ),
        EventPayload::SessionCompletion(completion) => (
            "SessionCompletion".to_owned(),
            format!(
                " stop={:?} complete={} raw={} live={} invalid={}",
                completion.stop_reason,
                completion.capture_complete,
                completion.raw_records,
                completion.live_events,
                completion.invalid_records
            ),
        ),
        EventPayload::InspectObservation(observation) => (
            "Inspect".to_owned(),
            format!(
                " adapter={} attached={} hit={} library={} build_id={} offset={} path={} detail={}",
                observation.adapter,
                observation.attached,
                observation.hit,
                observation.library,
                observation.build_id.as_deref().unwrap_or("-"),
                observation
                    .offset
                    .map_or_else(|| "-".to_owned(), |offset| format!("{offset:#x}")),
                observation.path_hint.as_deref().unwrap_or("-"),
                observation.detail
            ),
        ),
        EventPayload::InspectPlaintext(fragment) => (
            "Plaintext".to_owned(),
            format!(
                " adapter={} dir={} requested={} captured={} truncated={} class={} sha256={} preview={}",
                fragment.adapter,
                fragment.direction,
                fragment.requested_bytes,
                fragment.captured_bytes,
                fragment.truncated,
                fragment.content_class,
                fragment.sha256,
                fragment.preview.replace('\n', "\\n")
            ),
        ),
        EventPayload::Opaque { type_id, .. } => (format!("Opaque({type_id})"), String::new()),
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
