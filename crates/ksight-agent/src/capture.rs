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
    /// Inspect adapter selected by the operator.
    pub inspect_adapter: crate::inspect_runtime::InspectAdapterKind,
    /// Compiled uprobe object used by Inspect adapters.
    pub uprobe_object: PathBuf,
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
    eprintln!(
        "ksightd {} session={} files={} files-fd={} network={:?} binder={} inspect={} package={}",
        env!("CARGO_PKG_VERSION"),
        pipeline.normalizer.session_id(),
        request.sensors.files,
        request.sensors.file_descriptors,
        request.sensors.network,
        request.sensors.binder,
        request.inspect.enabled,
        request.package.as_deref().unwrap_or("-")
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
    let mut inspect = crate::inspect_runtime::InspectRuntime::prepare(
        &inspect_policy,
        request.inspect_adapter,
        &request.uprobe_object,
    );
    if request.inspect.enabled {
        for observation in inspect.initial_observations() {
            pipeline.emit_inspect(observation)?;
        }
        for observation in inspect.attach() {
            pipeline.emit_inspect(observation)?;
        }
    }

    publish_service_health(request, &pipeline, &sensors)?;
    let mut next_heartbeat = Instant::now() + Duration::from_secs(1);
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
            for output in inspect.poll() {
                pipeline.emit_inspect_output(output)?;
            }
            if let Some(observation) = inspect.expire_if_needed() {
                pipeline.emit_inspect(observation)?;
            }
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
    /// 已提交且等待回复的请求事务：transaction_id -> 提交时刻（monotonic_ns）。
    binder_request_timestamps: std::collections::HashMap<i32, u64>,
    /// 跨进程文件描述符血缘追踪。
    fd_lineage: crate::fd_lineage::FdLineageTracker,
    session_sequence: u64,
    collector_pid: u32,
    last_event_monotonic_ns: Option<u64>,
    stats: CaptureStats,
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
            binder_request_timestamps: std::collections::HashMap::new(),
            fd_lineage: crate::fd_lineage::FdLineageTracker::default(),
            session_sequence: 0,
            collector_pid: std::process::id(),
            last_event_monotonic_ns: None,
            stats: CaptureStats::default(),
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

    fn emit_inspect(&mut self, observation: ksight_model::InspectObservation) -> Result<()> {
        self.emit_inspect_payload(
            None,
            None,
            ksight_model::EventPayload::InspectObservation(observation),
        )
    }

    fn emit_inspect_output(&mut self, output: crate::inspect_runtime::InspectOutput) -> Result<()> {
        match output {
            crate::inspect_runtime::InspectOutput::Observation(observation) => {
                self.emit_inspect(observation)
            }
            crate::inspect_runtime::InspectOutput::Plaintext { pid, tid, fragment } => self
                .emit_inspect_payload(
                    Some(pid),
                    Some(tid),
                    ksight_model::EventPayload::InspectPlaintext(fragment),
                ),
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
        } else {
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
                " fd={} result={} family={} addr_len={}/{} peer={} port={}",
                connect.file_descriptor,
                connect.result,
                connect.address_family,
                connect.captured_address_length,
                connect.submitted_address_length,
                connect.peer_address.as_deref().unwrap_or("unknown"),
                connect
                    .peer_port
                    .map_or_else(|| "-".to_owned(), |port| port.to_string())
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
                " tx={} target={}:{} node={} reply={} code={:#x} flags={:#x} bytes={}/{}/{} fd={} object_offset={}",
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
                    .map_or_else(|| "-".to_owned(), |offset| offset.to_string())
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
mod tests {
    use std::collections::HashSet;

    use ksight_model::{
        BinderTransaction, BinderTransactionDirection, BinderTransactionStage, EventPayload,
    };

    use super::binder_event_matches_scope;

    #[test]
    fn binder_follow_on_stages_keep_the_originating_process_scope() {
        let mut tracked = HashSet::new();
        assert!(binder_event_matches_scope(
            true,
            &binder(BinderTransactionStage::Submitted, 42),
            &mut tracked,
        ));
        assert!(binder_event_matches_scope(
            false,
            &binder(BinderTransactionStage::BufferAllocated, 42),
            &mut tracked,
        ));
        assert!(binder_event_matches_scope(
            false,
            &binder(BinderTransactionStage::Received, 42),
            &mut tracked,
        ));
        assert!(tracked.is_empty());
        assert!(!binder_event_matches_scope(
            false,
            &binder(BinderTransactionStage::Received, 43),
            &mut tracked,
        ));
    }

    fn binder(stage: BinderTransactionStage, transaction_id: i32) -> EventPayload {
        EventPayload::BinderTransaction(BinderTransaction {
            stage,
            transaction_id,
            target_node: None,
            target_process_id: None,
            target_thread_id: None,
            target_kind: None,
            reply: false,
            direction: BinderTransactionDirection::Request,
            reply_to_request_id: None,
            reply_latency_ns: None,
            code: 0,
            code_kind: None,
            flags: 0,
            decoded_flags: Vec::new(),
            data_size: None,
            offsets_size: None,
            extra_buffers_size: None,
            file_descriptor: None,
            object_offset: None,
            transferred_fd_origin: None,
        })
    }
}
