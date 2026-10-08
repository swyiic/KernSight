//! Foreground multi-sensor capture orchestration.

mod auxiliary;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub(crate) mod qualification;
pub use auxiliary::{AuxiliaryAction, AuxiliaryCapturePlan, AuxiliaryStage};

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
    /// Optional validated automatic-capture ancestry.
    pub capture_relation: Option<crate::capture_relation::CaptureRelation>,
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
            capture_relation: None,
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
#[allow(
    clippy::struct_excessive_bools,
    reason = "These independently selected flags are part of the existing CLI and evidence schema."
)]
pub struct CaptureRequest {
    /// Explicit code scope; legacy requests retain their old selection.
    pub code_only: bool,
    /// Optional attempt-owned launch, performed only after probes attach.
    pub startup: Option<crate::capture_lifecycle::Startup>,
    /// Collect keys retained by this evidence operation.
    pub collect_keys: bool,
    /// Collect memory windows retained by this evidence operation.
    pub collect_memory_windows: bool,
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
    /// Explicit sequential phase plan; empty preserves legacy single-mode capture.
    pub inspect_stages: Vec<crate::capture_stages::InspectStage>,
    /// Compiled uprobe object used by Inspect adapters.
    pub uprobe_object: PathBuf,
    /// Optional Burp HTTP proxy `host:port`. Device feeds reconstructed HTTP/WS there.
    pub mirror_http: Option<String>,
    /// Reserved per-UID MITM path; currently refused before injection/routing
    /// actions because complete target-state restoration is unproved.
    pub mitm_burp: bool,
}

impl CaptureRequest {
    /// Validate the minimal mirror boundary without any I/O, before layout/load.
    ///
    /// # Errors
    /// Rejects unscoped or expanded mirror capture requests.
    /// Validate live sampling capability before any external or filesystem action.
    ///
    /// # Errors
    /// Strict mirror is unavailable on the current numeric-TGID-only backend.
    pub fn validate_live_backend(&self) -> Result<()> {
        if self.code_only {
            crate::qualified_code::capability()?;
        }
        if self.mitm_burp {
            ksight_core::capture_scope::require_injection_restore_backend()
                .map_err(anyhow::Error::msg)?;
        }
        if self.mirror_http.is_some() {
            ksight_core::capture_scope::require_strict_mirror_backend()
                .map_err(anyhow::Error::msg)?;
        }
        self.auxiliary_plan()?;
        Ok(())
    }

    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    /// Auxiliary plan retained by this evidence operation.
    pub fn auxiliary_plan(&self) -> Result<AuxiliaryCapturePlan> {
        if !self.inspect_stages.is_empty() {
            let text = self
                .inspect_stages
                .iter()
                .map(|s| format!("{}:{}", s.name, s.seconds))
                .collect::<Vec<_>>()
                .join(",");
            crate::capture_stages::parse_stages(&text).map_err(anyhow::Error::msg)?;
            if !self.inspect.enabled
                || self.inspect.elf_path.is_some()
                || self.inspect.offset.is_some()
                || self.inspect.build_id.is_some()
                || self.mirror_http.is_some()
                || self.mitm_burp
                || self.inspect.whole_device
                || self.count != 0
                || (self.pid.is_none() && self.package.is_none())
                || self.storage.spool_root.is_none()
                || self.duration_seconds
                    != self.inspect_stages.iter().map(|s| s.seconds).sum::<u64>()
            {
                bail!("staged capture requires package/PID, spool, exact total duration, no count/mirror/MITM/whole-device mode");
            }
        }

        if self.mirror_http.is_some() {
            let package = self
                .package
                .as_deref()
                .filter(|p| !p.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("minimal mirror requires --package"))?;
            if self.mitm_burp
                || self.sensors.files
                || self.sensors.file_descriptors
                || self.sensors.memory != MemorySelection::Disabled
                || self.sensors.binder
                || self.sensors.sched
                || self.sensors.network != NetworkSelection::Lifecycle
                || !self.inspect.enabled
                || self.inspect.whole_device
                || self
                    .inspect
                    .package
                    .as_deref()
                    .is_some_and(|p| p != package)
                || self.inspect.pid.is_some_and(|pid| Some(pid) != self.pid)
                || self.inspect.uid.is_some_and(|uid| Some(uid) != self.uid)
                || self.inspect_adapters.is_empty()
                || self.inspect_adapters.iter().any(|a| {
                    !matches!(
                        a,
                        crate::inspect_runtime::InspectAdapterKind::TlsSslWrite
                            | crate::inspect_runtime::InspectAdapterKind::TlsSslRead
                    )
                })
            {
                bail!("minimal mirror permits only package-scoped TLS/QUIC and network lifecycle; auxiliary sensors and MITM are forbidden");
            }
        }
        let plan = AuxiliaryCapturePlan::scoped(
            self.mirror_http.is_some(),
            self.code_only,
            self.collect_keys,
        );
        Ok(if self.storage.capture_relation.is_some() {
            plan.without_automatic_dump()
        } else {
            plan
        })
    }

    /// Minimal mirror installs only selected default objects; custom paths stay untouched.
    /// None preserves the legacy non-mirror distribution layout.
    pub fn capture_layout_assets(&self) -> Option<Vec<&'static str>> {
        self.mirror_http.as_ref()?;
        let mut names = Vec::new();
        for (path, name) in [
            (&self.process_object, "process_lifecycle.bpf.o"),
            (&self.network_object, "network_connect.bpf.o"),
            (&self.uprobe_object, "uprobe_regs.bpf.o"),
        ] {
            if *path == crate::runtime_paths::root().join(name) {
                names.push(name);
            }
        }
        Some(names)
    }
}

#[cfg(any(test, target_os = "android", target_os = "linux"))]
fn inherit_inspect_scope(
    policy: &mut ksight_core::InspectPolicy,
    pid: Option<u32>,
    uid: Option<u32>,
    package: Option<&str>,
    qualified: bool,
) {
    if policy.enabled || qualified {
        if policy.pid.is_none() {
            policy.pid = pid;
        }
        if policy.uid.is_none() {
            policy.uid = uid;
        }
        if policy.package.is_none() {
            policy.package = package.map(str::to_owned);
        }
    }
}

/// Run a foreground capture session.
///
/// # Errors
///
/// Returns an error for invalid scope, unavailable identity data, BPF load failure, or output I/O.
#[cfg(any(target_os = "android", target_os = "linux"))]
#[allow(
    clippy::needless_pass_by_value,
    reason = "The platform entry point preserves the owned capture request API."
)]
#[allow(
    clippy::too_many_lines,
    reason = "Keep this admission or delivery transaction together for review."
)]
pub fn run(request: CaptureRequest) -> Result<()> {
    use crate::normalize::EventNormalizer;

    request.validate_live_backend()?;
    request.auxiliary_plan()?;

    if std::env::consts::ARCH != "aarch64" {
        bail!(
            "the current raw-syscall adapters support only aarch64; refusing architecture {}",
            std::env::consts::ARCH
        );
    }
    // Backend verification precedes target actions. Instance qualification waits until the new App exists.
    let qualified_backend = if request.code_only || request.storage.capture_relation.is_some() {
        let backend = crate::qualified_code::Backend::open()?;
        let package = request
            .package
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("qualified production capture requires package"))?;
        let uid = backend.uid(package)?;
        if crate::dexdump::live_uid_for_package(package).is_some_and(|live| live != uid) {
            bail!("not-supported: virtual/container UID enrollment");
        }
        Some(backend)
    } else {
        None
    };
    if let Some(startup) = &request.startup {
        if let Err(error) = startup.force_stop() {
            let _ = startup.retain_timing();
            return Err(error);
        }
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
    if let (Some(relation), Some(root)) = (
        &request.storage.capture_relation,
        &request.storage.spool_root,
    ) {
        relation.retain(
            &root.join(normalizer.session_id().to_string()),
            Some(normalizer.session_id()),
            request.package.as_deref(),
        )?;
    }
    stream_events(
        sensors,
        identity_resolver,
        normalizer,
        &scope,
        spool,
        &request,
        environment,
        baseline_events,
        &baseline_sockets,
        qualified_backend.as_ref(),
    )
}

/// Return a platform error when live eBPF capture is unavailable.
///
/// # Errors
///
/// Always returns an error on unsupported host platforms.
#[cfg(not(any(target_os = "android", target_os = "linux")))]
#[allow(
    clippy::needless_pass_by_value,
    reason = "The platform entry point preserves the owned capture request API."
)]
pub fn run(request: CaptureRequest) -> Result<()> {
    request.validate_live_backend()?;
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
    let live_uid = package.and_then(crate::dexdump::live_uid_for_package);
    if let (Some(listed), Some(live)) = (package_uid, live_uid) {
        if listed != live {
            eprintln!(
                "package uid {listed} differs from live process uid {live}; scoping capture to the live process"
            );
        }
    }
    if let (Some(requested_uid), Some(resolved_uid)) = (uid, package_uid) {
        if requested_uid != resolved_uid {
            bail!("requested UID {requested_uid} conflicts with package UID {resolved_uid}");
        }
    }
    let target_uid = uid.or(live_uid).or(package_uid);
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
#[allow(
    clippy::too_many_arguments,
    reason = "Keep this admission or delivery transaction together for review."
)]
fn stream_events(
    mut sensors: Vec<ActiveSensor>,
    identity_resolver: crate::identity::AndroidIdentityResolver,
    normalizer: crate::normalize::EventNormalizer,
    scope: &crate::scope::CaptureScope,
    spool: Option<crate::spool::SessionSpoolWriter>,
    request: &CaptureRequest,
    environment: ksight_model::SessionEnvironment,
    baseline_events: Vec<ksight_model::Event>,
    baseline_sockets: &[(u32, i32)],
    qualified_backend: Option<&crate::qualified_code::Backend>,
) -> Result<()> {
    use std::{
        io::Write as _,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };

    let _phase = crate::capture_timing::enter(crate::capture_timing::Phase::Observe);
    let started = Instant::now();
    let deadline =
        (request.duration_seconds != 0).then(|| Duration::from_secs(request.duration_seconds));
    let running = Arc::new(AtomicBool::new(true));
    let signal_state = Arc::clone(&running);
    ctrlc::set_handler(move || signal_state.store(false, Ordering::SeqCst))?;
    let auxiliary = request.auxiliary_plan()?;
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
    let mut tls_inject: Option<crate::tls_inject::TlsInject> = None;
    if request.mitm_burp {
        match crate::tls_inject::TlsInject::start(request.package.as_deref()) {
            Ok(inject) => {
                eprintln!("tls-inject on with --mitm-burp only");
                tls_inject = Some(inject);
            }
            Err(error) => eprintln!("tls-inject skipped: {error}"),
        }
    } else if request.mirror_http.is_some() {
        eprintln!("tls-inject off (no ptrace); inspect-tls uprobe only; app TLS unchanged");
    }
    let _mitm = if request.mitm_burp {
        if let (Some(package), Some(endpoint)) =
            (request.package.as_deref(), request.mirror_http.as_deref())
        {
            if let (Some(uid), Ok(addr)) = (
                crate::mitm_redirect::uid_for_package(package),
                ksight_core::parse_mirror_endpoint(endpoint),
            ) {
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
            } else {
                eprintln!("mitm-burp skipped: need package uid and Burp host:port");
                None
            }
        } else {
            eprintln!("mitm-burp requires --package and --mirror-http host:port");
            None
        }
    } else {
        None
    };
    pipeline.burp_mirror = match request.mirror_http.as_deref() {
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
        request.mirror_http.as_deref().unwrap_or("-")
    );
    if request.sensors.files && !request.sensors.file_descriptors {
        eprintln!("file sensor: openat only; dup/close is off unless --files-fd");
    }

    let mut inspect_policy = request.inspect.clone();
    inherit_inspect_scope(
        &mut inspect_policy,
        request.pid,
        request.uid.or(scope.target_uid),
        request.package.as_deref(),
        qualified_backend.is_some(),
    );
    let mut stage_cursor = (!request.inspect_stages.is_empty())
        .then(|| crate::capture_stages::StageCursor::new(&request.inspect_stages));
    let mut stage_open = stage_cursor.is_some();
    let mut target_instance = None;
    let mut next_instance_check = Instant::now();
    let active_adapters = if let Some(cursor) = &stage_cursor {
        let stage = &request.inspect_stages[cursor.index];
        inspect_policy.enabled = stage.name != "l0";
        inspect_policy.max_duration_secs = u32::try_from(stage.seconds).unwrap_or(300);
        stage.adapters()
    } else {
        request.inspect_adapters.clone()
    };
    let prepare_phase = crate::capture_timing::enter(crate::capture_timing::Phase::InspectPrepare);
    let mut inspect = if let Some(backend) = &qualified_backend {
        crate::inspect_runtime::InspectRuntime::prepare_qualified_candidate(
            &inspect_policy,
            &active_adapters,
            &backend.uprobe,
            vec![],
        )?
    } else {
        crate::inspect_runtime::InspectRuntime::prepare_all(
            &inspect_policy,
            &active_adapters,
            &request.uprobe_object,
        )
    };
    drop(prepare_phase);
    let mut qualified_source: Option<crate::qualified_code::SourceIdentity> = None;
    let mut next_qualification = Instant::now();
    if request.inspect.enabled {
        for observation in inspect.initial_observations() {
            pipeline.emit_inspect(observation)?;
        }
    }

    if let Some(cursor) = &stage_cursor {
        emit_capture_stage(
            &mut pipeline,
            cursor.index,
            &request.inspect_stages[cursor.index],
            "started",
            Some(&inspect),
            target_instance,
        )?;
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
        sensor.seed_socket_fds(baseline_sockets);
    }
    for event in baseline_events {
        pipeline.emit_event(event)?;
    }

    let launch_task = request
        .startup
        .as_ref()
        .map(super::capture_lifecycle::Startup::start)
        .transpose()?;

    let mut next_startup_observation = Instant::now();
    let mut next_stack_inventory = Instant::now();
    let mut unprocessed_inspect_outputs = 0usize;
    // Loop errors must not skip final counters, raw checkpoints or own child cleanup.
    let capture_loop_result = (|| -> Result<()> {
        while running.load(Ordering::SeqCst)
            && (request.count == 0 || pipeline.stats.live_emitted < request.count)
            && deadline.is_none_or(|duration| started.elapsed() < duration)
        {
            if request
                .storage
                .spool_root
                .as_ref()
                .is_some_and(|root| ksight_core::output_budget::should_stop(root))
            {
                bail!("phase lease exhausted before next capture poll; original evidence retained");
            }
            if let Some(backend) = &qualified_backend {
                if Instant::now() >= next_qualification {
                    let package = request.package.as_deref().unwrap();
                    if let Some(existing) = qualified_source.clone() {
                        let refreshed = qualification::refresh(
                            &existing,
                            || {
                                let target = backend.qualify(package, existing.pid, false)?;
                                Ok((target.identity, target.qualified))
                            },
                            |target| inspect.refresh_qualified(vec![target]),
                        );
                        if let Err(failure) = refreshed {
                            eprintln!(
                                "{}",
                                serde_json::json!({
                                    "schema": "kernsight.qualified-source-failure/v1",
                                    "failure": failure,
                                })
                            );
                            if let Some(relation) = &request.storage.capture_relation {
                                let root = crate::capture_lifecycle::control_root(
                                    &crate::runtime_paths::captures(),
                                    relation,
                                );
                                if let Err(error) =
                                    crate::capture_lifecycle::retain_qualification_failure(
                                        &root, relation, &failure,
                                    )
                                {
                                    // Diagnostic storage must not hide the original refusal.
                                    eprintln!(
                                        "qualification failure receipt not retained: {error:#}"
                                    );
                                }
                            }
                            return Err(failure.into());
                        }
                        next_qualification = Instant::now() + Duration::from_secs(2);
                    } else if let Some(pid) = backend.main_pid(package)? {
                        let target = backend.qualify(package, pid, false)?;
                        qualified_source = Some(target.identity.clone());
                        inspect.refresh_qualified(vec![target.qualified])?;
                        next_qualification = Instant::now() + Duration::from_secs(2);
                    } else {
                        next_qualification = Instant::now() + Duration::from_millis(100);
                    }
                }
            }
            if let Some(task) = &launch_task {
                task.check()?;
            }
            if Instant::now() >= next_startup_observation {
                if let Some(startup) = &request.startup {
                    startup.observe_target();
                }
                next_startup_observation = Instant::now() + Duration::from_millis(100);
            }
            if request
                .storage
                .spool_root
                .as_ref()
                .is_some_and(|root| ksight_core::output_budget::should_stop(root))
            {
                pipeline.storage_limit_reached = true;
                break;
            }
            if let Some(cursor) = stage_cursor.as_mut() {
                let elapsed = started.elapsed().as_secs();
                if Instant::now() >= next_instance_check || cursor.due(elapsed) {
                    let current = observe_stage_target(request, target_instance);
                    if let Some(expected) = target_instance {
                        crate::capture_stages::confirm_instance(expected, current)
                            .map_err(anyhow::Error::msg)?;
                    } else {
                        target_instance = current;
                    }
                    next_instance_check = Instant::now() + Duration::from_secs(1);
                }
                if cursor.due(elapsed) {
                    if target_instance.is_none() {
                        bail!("staged target instance was never verified; stopping before the next phase");
                    }
                    finish_capture_stage(
                        &mut pipeline,
                        cursor.index,
                        &request.inspect_stages[cursor.index],
                        "window_elapsed",
                        &mut inspect,
                        target_instance,
                    )?;
                    stage_open = false;
                    if !cursor.advance(elapsed).map_err(anyhow::Error::msg)? {
                        running.store(false, Ordering::SeqCst);
                        break;
                    }
                    let stage = &request.inspect_stages[cursor.index];
                    inspect_policy.enabled = stage.name != "l0";
                    inspect_policy.max_duration_secs = u32::try_from(stage.seconds).unwrap_or(300);
                    // Old owned uprobe sessions were dropped before new resources are prepared.
                    inspect = if let Some(backend) = &qualified_backend {
                        let source = qualified_source.as_ref().ok_or_else(|| {
                            anyhow::anyhow!("stage transition has no physical source")
                        })?;
                        let current = backend.qualify(&source.package, source.pid, false)?;
                        if current.identity != *source {
                            bail!("physical generation changed at stage transition");
                        }
                        crate::inspect_runtime::InspectRuntime::prepare_qualified_candidate(
                            &inspect_policy,
                            &stage.adapters(),
                            &backend.uprobe,
                            vec![current.qualified],
                        )?
                    } else {
                        crate::inspect_runtime::InspectRuntime::prepare_all(
                            &inspect_policy,
                            &stage.adapters(),
                            &request.uprobe_object,
                        )
                    };
                    stage_open = true;
                    emit_capture_stage(
                        &mut pipeline,
                        cursor.index,
                        stage,
                        "started",
                        Some(&inspect),
                        target_instance,
                    )?;
                    for observation in inspect.initial_observations() {
                        pipeline.emit_inspect(observation)?;
                    }
                }
            }
            if Instant::now() >= next_environment_check {
                let current = crate::environment::collect(request.collector_mode);
                if !same_environment_state(&last_environment, &current) {
                    pipeline.environment.clone_from(&current);
                    pipeline.emit_session_payload(
                        ksight_model::EventPayload::SessionEnvironment(current.clone()),
                    )?;
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
            if inspect_policy.enabled {
                for observation in inspect.attach_when_safe() {
                    if observation.attached {
                        if let Some(startup) = &request.startup {
                            startup.record_attach(&observation.adapter);
                        }
                    }
                    pipeline.emit_inspect(observation)?;
                }
                if let (Some(inject), Some(package)) =
                    (tls_inject.as_mut(), request.package.as_deref())
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
                let outputs = {
                    let _phase = crate::capture_timing::enter(crate::capture_timing::Phase::Poll);
                    inspect.poll()
                };
                let output_count = outputs.len();
                let _output_phase =
                    crate::capture_timing::enter(crate::capture_timing::Phase::PollOutput);
                for (output_index, output) in outputs.into_iter().enumerate() {
                    if let Some(mirror) = pipeline.burp_mirror.as_mut() {
                        route_inspect_to_mirror(mirror, &output);
                    }
                    if let Err(error) = pipeline.emit_inspect_output(output) {
                        unprocessed_inspect_outputs = output_count - output_index - 1;
                        return Err(error);
                    }
                }
                if let Some(observation) = inspect.expire_if_needed() {
                    pipeline.emit_inspect(observation)?;
                }
            }
            if request.mirror_http.is_some() && Instant::now() >= next_stack_inventory {
                if let (Some(package), Some(mirror)) =
                    (request.package.as_deref(), pipeline.burp_mirror.as_mut())
                {
                    mirror.set_stack_coverage(mapped_stack_coverage(package));
                }
                next_stack_inventory = Instant::now() + Duration::from_secs(15);
            }
            if Instant::now() >= next_inspect_stats {
                let (raw, decoded, lost) = inspect.drain_totals();
                let [perf_min_size, perf_max_size, perf_padding_removed] =
                    inspect.perf_record_framing_totals();
                eprintln!("inspect perf framing: min_size={perf_min_size} max_size={perf_max_size} padding_removed={perf_padding_removed}");
                let [bad_size, bad_abi, malformed, scope_epoch, scope_identity, accepted] =
                    inspect.record_admission_totals();
                eprintln!("inspect record admission: bad_size={bad_size} bad_abi={bad_abi} malformed={malformed} scope_epoch={scope_epoch} scope_identity={scope_identity} accepted={accepted}");
                let (read_entry, read_return, read_success, read_failure, read_wanted) =
                    inspect.ssl_read_funnel();
                let (
                    positive_return,
                    dropped_positive,
                    want_openssl,
                    want_conscrypt,
                    ok_openssl,
                    ok_conscrypt,
                    positive_openssl,
                    positive_conscrypt,
                ) = inspect.ssl_read_funnel_ex();
                let (conn_streams, conn_returns, conn_shared) = inspect.connkey_stats();
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
                "inspect layers: raw_uprobe={raw} decoded={decoded} perf_lost={lost} ssl_read_entry={read_entry} ssl_read_ret={read_return} ssl_read_ok={read_success} ssl_read_fail={read_failure} ssl_read_want={read_wanted} ssl_read_ret_gt0={positive_return} ssl_read_drop_gt0={dropped_positive} ssl_read_want_openssl={want_openssl} ssl_read_want_conscrypt={want_conscrypt} ssl_read_ok_openssl={ok_openssl} ssl_read_ok_conscrypt={ok_conscrypt} ssl_read_gt0_openssl={positive_openssl} ssl_read_gt0_conscrypt={positive_conscrypt} quic_connkey_streams={conn_streams} quic_connkey_returns={conn_returns} quic_connkey_shared={conn_shared} {}",
                mirror_diagnostics.as_deref().unwrap_or("mirror=disabled")
            );
                if pipeline.burp_mirror.is_some() {
                    let get = |name: &str| mirror_metrics.get(name).copied().unwrap_or(0);
                    eprintln!(
                    "mirror rates: coverage candidates={} export={} pinned={} empirical={} keylog={} uncovered={} | retention raw={} decoded={} perf_lost={} drop_gt0={} | delivery delivered={} reconstructed={} ok_paired={} no_status={} no_host={} unpaired_req={} unpaired_resp={} orphan_overflow={} incomplete={} http3_dirs={} http3_yielded={}",
                    get("stack_candidates"),
                    get("stack_export_candidates"),
                    get("stack_pinned_boundaries"),
                    get("stack_empirical_boundaries"),
                    get("stack_keylog_candidates"),
                    get("stack_uncovered"),
                    raw,
                    decoded,
                    lost,
                    dropped_positive,
                    get("delivered"),
                    get("reconstructed_messages"),
                    get("paired_responses"),
                    get("unknown_status_responses"),
                    get("hostless_requests"),
                    get("unpaired_requests"),
                    get("unpaired_responses"),
                    get("orphan_overflow_preserved"),
                    get("incomplete_messages"),
                    get("http3_directions"),
                    get("http3_yielded"),
                );
                }
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
            auxiliary.dispatch(AuxiliaryStage::Poll, true, |action| -> Result<()> {
                debug_assert_eq!(action, AuxiliaryAction::CryptoWatch);
        if Instant::now() >= next_crypto {
            if let Some(package) = request.package.as_deref() {
                if let Some(pid) = crate::tls_inject::TlsInject::main_pid(package) {
                    let result = crate::crypto_watch::scan_pid_ex(
                        pid,
                        package,
                        &crate::crypto_watch::Paths::device(),
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
                Ok(())
            })?;
            if !consumed_any {
                std::thread::sleep(Duration::from_millis(10));
            }
            if let Some(spool) = pipeline.spool.as_mut() {
                flush_capture_idle(spool)?;
            }
            if Instant::now() >= next_heartbeat {
                publish_service_health(request, &pipeline, &sensors)?;
                next_heartbeat = Instant::now() + Duration::from_secs(1);
                if pipeline.normalizer.boot_id_changed().unwrap_or(false) {
                    if stage_cursor.is_some() {
                        bail!("boot changed during staged capture");
                    }
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
                if stage_cursor.is_some() {
                    bail!("staged session reached rotation boundary; refusing to silently start another session");
                }
                let reason = ksight_model::CaptureStopReason::SessionRotated;
                if !pipeline.rotate(reason, &sensors, request)? {
                    running.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }

        Ok(())
    })();
    let (poll_budget_yields, unread_perf_possible) = inspect.poll_budget_status();
    let scope_failures = inspect.scope_failure_count();
    let perf_read_failures = inspect.perf_read_failure_count();
    let coverage_gap = unread_perf_possible || scope_failures != 0 || perf_read_failures != 0;
    let pending_perf_tail = capture_loop_result.is_ok() && coverage_gap;
    let capture_loop_result = if pending_perf_tail {
        Err(anyhow::anyhow!("capture coverage partial: perf_poll_backlog_or_scope_gap_at_observation_end; raw coverage incomplete"))
    } else {
        capture_loop_result
    };
    eprintln!(
        "{}",
        serde_json::json!({
            "schema":"kernsight.perf-poll-budget/v1", "bounded_slice_yields":poll_budget_yields,
            "unread_tail_possible":unread_perf_possible, "unread_tail_count":null, "scope_failures":scope_failures,
            "perf_read_failures":perf_read_failures, "coverage_partial":coverage_gap
        })
    );
    let mut stage_evidence_error = None;
    if let Some(cursor) = &stage_cursor {
        if !cursor.finished {
            let last_elapsed = capture_loop_result.is_ok()
                && running.load(Ordering::SeqCst)
                && cursor.index + 1 == request.inspect_stages.len()
                && cursor.due(started.elapsed().as_secs())
                && target_instance.is_some()
                && observe_stage_target(request, target_instance) == target_instance;
            if !last_elapsed {
                stage_evidence_error = Some(anyhow::anyhow!(
                    "staged capture did not finish all windows; remaining phases not started"
                ));
            }
            let state = if last_elapsed {
                "window_elapsed"
            } else if capture_loop_result.is_err() {
                "failed"
            } else {
                "aborted"
            };
            if stage_open {
                if let Err(error) = finish_capture_stage(
                    &mut pipeline,
                    cursor.index,
                    &request.inspect_stages[cursor.index],
                    state,
                    &mut inspect,
                    target_instance,
                ) {
                    eprintln!("staged final evidence failed: {error}");
                    stage_evidence_error = Some(error);
                }
            }
            for index in cursor.index + 1..request.inspect_stages.len() {
                if let Err(error) = emit_capture_stage(
                    &mut pipeline,
                    index,
                    &request.inspect_stages[index],
                    "not_started",
                    None,
                    target_instance,
                ) {
                    eprintln!("staged pending evidence failed: {error}");
                    stage_evidence_error = Some(error);
                    break;
                }
            }
        }
    }
    if let (Some(r), Some(source)) = (&request.storage.capture_relation, &qualified_source) {
        crate::capture_lifecycle::retain_qualification(
            &crate::capture_lifecycle::control_root(&crate::runtime_paths::captures(), r),
            r,
            std::slice::from_ref(source),
        )?;
    }
    let capture_loop_result = if qualified_backend.is_some() && qualified_source.is_none() {
        capture_loop_result.and(Err(anyhow::anyhow!(
            "qualified target never appeared; no payload admitted"
        )))
    } else {
        capture_loop_result
    };
    let launcher_result = launch_task.map_or(Ok(()), super::capture_lifecycle::LaunchTask::finish);
    let capture_loop_result = capture_loop_result.and(launcher_result);
    let capture_loop_result =
        capture_loop_result.and_then(|()| stage_evidence_error.map_or(Ok(()), Err));
    if capture_loop_result.is_err() {
        eprintln!("capture loop stopped with error; unprocessed_inspect_outputs={unprocessed_inspect_outputs}; finalizing retained evidence");
    }

    if capture_loop_result.is_ok() && request.duration_seconds != 0 {
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
        let [perf_min_size, perf_max_size, perf_padding_removed] =
            inspect.perf_record_framing_totals();
        eprintln!("inspect perf framing: min_size={perf_min_size} max_size={perf_max_size} padding_removed={perf_padding_removed}");
        let [bad_size, bad_abi, malformed, scope_epoch, scope_identity, accepted] =
            inspect.record_admission_totals();
        eprintln!("inspect record admission: bad_size={bad_size} bad_abi={bad_abi} malformed={malformed} scope_epoch={scope_epoch} scope_identity={scope_identity} accepted={accepted}");
        let (read_entry, read_return, read_success, read_failure, read_wanted) =
            inspect.ssl_read_funnel();
        let (
            positive_return,
            dropped_positive,
            want_openssl,
            want_conscrypt,
            ok_openssl,
            ok_conscrypt,
            positive_openssl,
            positive_conscrypt,
        ) = inspect.ssl_read_funnel_ex();
        let (conn_streams, conn_returns, conn_shared) = inspect.connkey_stats();
        eprintln!(
            "inspect final: raw_uprobe={raw} decoded={decoded} perf_lost={lost} ssl_read_entry={read_entry} ssl_read_ret={read_return} ssl_read_ok={read_success} ssl_read_fail={read_failure} ssl_read_want={read_wanted} ssl_read_ret_gt0={positive_return} ssl_read_drop_gt0={dropped_positive} ssl_read_want_openssl={want_openssl} ssl_read_want_conscrypt={want_conscrypt} ssl_read_ok_openssl={ok_openssl} ssl_read_ok_conscrypt={ok_conscrypt} ssl_read_gt0_openssl={positive_openssl} ssl_read_gt0_conscrypt={positive_conscrypt} quic_connkey_streams={conn_streams} quic_connkey_returns={conn_returns} quic_connkey_shared={conn_shared} mirror_deliveries={}",
            pipeline
                .burp_mirror
                .as_ref()
                .map_or(0, super::burp_mirror::BurpMirror::delivery_count)
        );
        // Single machine-readable line for MobileE: read-only rollup, no
        // pairing or assembler logic lives here.
        if let Some(mirror) = pipeline.burp_mirror.as_ref() {
            let metrics = mirror.diagnostic_metrics();
            let get = |name: &str| metrics.get(name).copied().unwrap_or(0);
            eprintln!(
                "{}",
                serde_json::json!({
                    "schema": "kernsight.mirror-final/v1",
                    "session": pipeline.normalizer.session_id().to_string(),
                    "delivered": mirror.delivery_count(),
                    "ok": get("paired_responses"),
                    "no_observed_status": get("unknown_status_responses"),
                    "no_observed_host": get("hostless_requests"),
                    "unpaired_requests": get("unpaired_requests"),
                    "unpaired_responses": get("unpaired_responses"),
                    "orphan_overflow_preserved": get("orphan_overflow_preserved"),
                    "incomplete_messages": get("incomplete_messages"),
                    "perf_lost": lost,
                    "ssl_read_drop_gt0": dropped_positive,
                    "untyped_quic_fragments": get("untyped_quic_fragments"),
                    "untyped_quic_bytes": get("untyped_quic_bytes"),
                    "quic_fin_observations": get("quic_fin_observations"),
                    "quic_fin_unknown": get("quic_fin_unknown"),
                    "quic_zero_byte_events": get("quic_zero_byte_events"),
                    "untyped_quic_raw_rejected": get("untyped_quic_raw_rejected"),
                    "raw_memory_evicted_fragments": get("raw_memory_evicted_fragments"),
                    "raw_memory_evicted_bytes": get("raw_memory_evicted_bytes"),
                    "raw_idle_reaped_fragments": get("raw_idle_reaped_fragments"),
                    "raw_idle_reaped_bytes": get("raw_idle_reaped_bytes"),
                })
            );
        }
    }
    auxiliary.dispatch(
        AuxiliaryStage::Finish,
        capture_loop_result.is_ok() && !pipeline.storage_limit_reached,
        |action| -> Result<()> {
            debug_assert_eq!(action, AuxiliaryAction::MemoryDump);
            if let Some(root) = request
                .storage
                .spool_root
                .as_ref()
                .filter(|_| capture_loop_result.is_ok())
            {
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
                    let dumped = if let (Some(backend), Some(source)) =
                        (&qualified_backend, &qualified_source)
                    {
                        if pid != source.pid {
                            continue;
                        }
                        backend.copy_code(source, &dest, dump_deadline)?
                    } else {
                        crate::dexdump::dump_live_process_with_pause(
                            pid,
                            &dest,
                            dump_deadline,
                            request.collect_keys,
                            request.collect_memory_windows,
                            !(request.code_only || request.storage.capture_relation.is_some()),
                        )
                    };

                    let total = dumped
                        .memory_images
                        .saturating_add(dumped.vdex_images)
                        .saturating_add(dumped.fd_images)
                        .saturating_add(dumped.native_libs);
                    if total > 0 {
                        eprintln!(
                            "dumped pid {pid}: memory_dex={} vdex={} fd={} so={}",
                            dumped.memory_images,
                            dumped.vdex_images,
                            dumped.fd_images,
                            dumped.native_libs
                        );
                    }
                }
            }
            Ok(())
        },
    )?;

    if let Err(error) = capture_loop_result {
        if let Some(spool) = pipeline.spool.as_mut() {
            report_spool_failure(spool); // idempotent: never retries the tail twice
        }
        // Flush already accepted records before revoking further writes. A sliced
        // ring tail is unknown, not zero loss or a completed observation receipt.
        if pending_perf_tail {
            if let Some(root) = request.storage.spool_root.as_ref() {
                ksight_core::output_budget::record_failure(
                    root,
                    "perf_poll_backlog_or_scope_gap_at_observation_end",
                );
            }
        }
        std::io::stdout().flush()?;
        return Err(error); // no false DurationElapsed / capture_complete receipt
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
            .map_or(0, super::spool::SessionSpoolWriter::used_bytes),
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
    /// `已提交且等待回复的请求事务：transaction_id` -> `提交时刻（monotonic_ns`）。
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
                // Keep --inspect-jni opt-in (packer grace). Do NOT auto-enable with --mirror-http.
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
                mirror.observe_peer_on_thread(pid, tid, name);
            }
        }
        if let (Some(mirror), EventPayload::NetworkHandshake(handshake)) =
            (self.burp_mirror.as_mut(), &event.payload)
        {
            if let Some(host) = handshake_mirror_host(handshake) {
                mirror.observe_peer_on_thread(pid, tid, &host);
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
        let _phase = crate::capture_timing::enter(crate::capture_timing::Phase::Seal);
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
    let sampling = if event.header.quality.sample_one_in > 1 {
        format!(" sample=1/{}", event.header.quality.sample_one_in)
    } else {
        String::new()
    };
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
#[allow(
    clippy::too_many_lines,
    reason = "Keep this admission or delivery transaction together for review."
)]
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

#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
fn flush_capture_idle(
    spool: &mut crate::spool::SessionSpoolWriter,
) -> Result<(), crate::spool::SpoolError> {
    if let Err(error) = spool.flush_if_idle() {
        report_spool_failure(spool);
        return Err(error);
    }
    Ok(())
}
#[cfg_attr(not(any(target_os = "android", target_os = "linux")), allow(dead_code))]
fn report_spool_failure(spool: &mut crate::spool::SessionSpoolWriter) {
    let manifest_recorded = spool.finish_interrupted().is_ok();
    let diagnostics = spool.diagnostics();
    eprintln!(
        "spool_failed diagnostics={}",
        serde_json::to_string(&diagnostics).unwrap_or_else(|_| "serialization_failed".into())
    );
    if !manifest_recorded {
        eprintln!("spool_failed failure_manifest_unavailable=true");
    }
}

/// Preserve the baseline mirror adapter; qualified code capture never enables it.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn route_inspect_to_mirror(
    mirror: &mut crate::burp_mirror::BurpMirror,
    output: &crate::inspect_runtime::InspectOutput,
) {
    if let crate::inspect_runtime::InspectOutput::Plaintext {
        pid,
        tid,
        connection_id,
        raw,
        ..
    } = output
    {
        if let crate::inspect_runtime::InspectOutput::Plaintext { fragment, .. } = output {
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
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn observe_stage_target(
    request: &CaptureRequest,
    expected: Option<crate::capture_stages::TargetInstance>,
) -> Option<crate::capture_stages::TargetInstance> {
    let pid = if let Some(pid) = request.pid.or(expected.map(|i| i.pid)) {
        pid
    } else {
        let package = request.package.as_deref()?;
        let main: Vec<u32> = crate::dexdump::pids_for_package(package)
            .into_iter()
            .filter(|pid| {
                std::fs::read(format!("/proc/{pid}/cmdline"))
                    .is_ok_and(|bytes| bytes.split(|b| *b == 0).next() == Some(package.as_bytes()))
            })
            .collect();
        if main.len() != 1 {
            return None;
        }
        main[0]
    };
    if let Some(package) = request.package.as_deref() {
        let bytes = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        let cmd = bytes.split(|b| *b == 0).next()?;
        if cmd != package.as_bytes() && !cmd.starts_with(format!("{package}:").as_bytes()) {
            return None;
        }
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    crate::capture_stages::instance_from_stat(pid, &stat)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn emit_capture_stage(
    pipeline: &mut EventPipeline,
    index: usize,
    stage: &crate::capture_stages::InspectStage,
    status: &str,
    inspect: Option<&crate::inspect_runtime::InspectRuntime>,
    instance: Option<crate::capture_stages::TargetInstance>,
) -> Result<()> {
    let metrics: std::collections::BTreeMap<String, u64> = inspect
        .map(|runtime| {
            let (raw, decoded, lost) = runtime.drain_totals();
            let (pending, incomplete) = runtime.pending_depth();
            [
                ("raw_records".into(), raw),
                ("decoded".into(), decoded),
                ("perf_lost".into(), lost),
                ("pending".into(), pending),
                ("incomplete_calls".into(), incomplete),
            ]
            .into_iter()
            .collect()
        })
        .unwrap_or_default();
    let mut payload = serde_json::json!({"schema":"kernsight.capture-stage/v1","session":pipeline.normalizer.session_id().to_string(),"index":index,"stage":stage.name,"planned_seconds":stage.seconds,"stage_elapsed_ms":inspect.map(crate::inspect_runtime::InspectRuntime::stage_elapsed_ms),"state":status,"metrics":metrics,"pid":instance.map(|i|i.pid),"process_start_ticks":instance.map(|i|i.start_ticks.to_string()),"coverage":"not_attested","requested_adapters":stage.adapters().iter().map(|a|a.as_str()).collect::<Vec<_>>(),"observation_state":if stage.name == "l0" {"kernel_only"} else if metrics.get("raw_records").copied().unwrap_or(0)==0 {"not_triggered_or_blocked"} else {"observed_not_complete"},"restart":false,"resource_release":"owned_probes_dropped_on_close; unread_perf_tail_not_attested"});
    payload["recorded_unix_ms"] = serde_json::json!(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis()));
    if let Some(relation) = pipeline.storage.capture_relation.as_ref() {
        if let Some(link) = relation
            .stage_links
            .iter()
            .find(|r| r["stageKey"].as_str() == Some(stage.name.as_str()))
        {
            payload["parent_relation"] = link.clone();
        }
    }
    eprintln!("{payload}");
    pipeline.emit_inspect(ksight_model::InspectObservation {
        adapter: "capture_stage".into(),
        detail: payload.to_string(),
        metrics,
        detectability_notice:
            "sequential uprobe phases; L0 sensors persist; no automatic App restart".into(),
        ..ksight_model::InspectObservation::default()
    })
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn finish_capture_stage(
    pipeline: &mut EventPipeline,
    index: usize,
    stage: &crate::capture_stages::InspectStage,
    status: &str,
    inspect: &mut crate::inspect_runtime::InspectRuntime,
    instance: Option<crate::capture_stages::TargetInstance>,
) -> Result<()> {
    inspect.revoke_for_stage();

    emit_capture_stage(pipeline, index, stage, status, Some(inspect), instance)
}
