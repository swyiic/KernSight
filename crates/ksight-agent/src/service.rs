use std::{
    collections::BTreeMap,
    fmt::Write as _,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    capture::{
        CaptureRequest, MemorySelection, NetworkSelection, OutputOptions, SamplingOptions,
        SensorSelection, StorageOptions,
    },
    identity::valid_package_name,
    spool::{DEFAULT_COMPLETION_RESERVE_BYTES, MAX_EVENTS_PER_BATCH},
};

fn default_max_total_spool_mib() -> u64 {
    512
}

fn default_max_session_age_secs() -> u64 {
    3600
}

fn default_keep_completed_sessions() -> u32 {
    4
}

fn default_completion_reserve_kib() -> u64 {
    DEFAULT_COMPLETION_RESERVE_BYTES / 1024
}

fn default_compress_batches() -> bool {
    true
}

/// Current `ksightd` service configuration schema.
pub const CURRENT_SERVICE_CONFIG: u16 = 3;
const MAX_CONFIG_BYTES: usize = 1024 * 1024;

/// Versioned long-running collector configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    /// Configuration schema version.
    pub schema_version: u16,
    /// Deployed BPF object paths.
    pub objects: SensorObjects,
    /// Enabled global Observe sensors.
    pub sensors: ServiceSensors,
    /// Optional whole-session scope.
    pub scope: ServiceScope,
    /// Durable retention settings.
    pub storage: ServiceStorage,
    /// Explicit per-sensor kernel sampling.
    pub sampling: ServiceSampling,
    /// Atomic single-collector lease file.
    pub lock_file: PathBuf,
    /// Machine-readable daemon runtime status file.
    pub status_file: PathBuf,
    /// Detached daemon stdout/stderr destination used by the host launcher.
    pub log_file: PathBuf,
    /// Include individual thread lifecycle records in durable batches.
    pub include_threads: bool,
}

/// Deployed BPF object paths used by the collector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SensorObjects {
    /// Process lifecycle object.
    pub process: PathBuf,
    /// File-open object.
    pub file: PathBuf,
    /// Socket-connect object.
    pub network: PathBuf,
    /// Memory-region object.
    pub memory: PathBuf,
    /// Binder transaction object.
    pub binder: PathBuf,
}

/// Long-running Observe sensor selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Persistent config keeps sensor switches explicit.
pub struct ServiceSensors {
    /// Enable completed file opens.
    pub files: bool,
    /// Enable completed socket connects.
    pub network: bool,
    /// Enable socket send/receive byte-count metadata without payload bytes.
    #[serde(default)]
    pub network_io: bool,
    /// Memory capture level.
    pub memory: ServiceMemorySelection,
    /// Enable Binder transaction metadata.
    pub binder: bool,
}

/// Service memory-event verbosity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceMemorySelection {
    /// Disable the memory sensor.
    Disabled,
    /// Capture only operations requesting executable permission.
    Executable,
    /// Capture all mmap and mprotect operations.
    All,
}

/// Optional service-wide capture scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceScope {
    /// Optional thread-group ID.
    pub pid: Option<u32>,
    /// Optional effective Linux UID.
    pub uid: Option<u32>,
    /// Optional exact Android package.
    pub package: Option<String>,
}

/// Durable service retention bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceStorage {
    /// Root containing per-session spool directories.
    pub spool_root: PathBuf,
    /// Maximum complete unacknowledged batch data for one session in MiB.
    pub max_spool_mib: u64,
    /// Maximum events in one immutable batch.
    pub events_per_batch: usize,
    /// Maximum complete-batch data across the spool root in MiB; zero disables the bound.
    #[serde(default = "default_max_total_spool_mib")]
    pub max_total_spool_mib: u64,
    /// Rotate the active session after this many seconds; zero disables time rotation.
    #[serde(default = "default_max_session_age_secs")]
    pub max_session_age_secs: u64,
    /// Sealed sessions to retain after pruning.
    #[serde(default = "default_keep_completed_sessions")]
    pub keep_completed_sessions: u32,
    /// KiB reserved so a completion event can be sealed at session capacity.
    #[serde(default = "default_completion_reserve_kib")]
    pub completion_reserve_kib: u64,
    /// Compress each batch independently.
    #[serde(default = "default_compress_batches")]
    pub compress_batches: bool,
}

/// Per-sensor sampling for long-running Observe sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSampling {
    /// File-open sampling rate.
    pub file: u32,
    /// Socket-connect sampling rate.
    pub network: u32,
    /// Memory-region sampling rate.
    pub memory: u32,
    /// Binder transaction sampling rate.
    pub binder: u32,
}

impl ServiceConfig {
    /// Load a bounded UTF-8 JSON configuration document.
    ///
    /// # Errors
    ///
    /// Returns an error for I/O failure, excessive size, malformed JSON, unknown fields, or invalid
    /// structural bounds.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ServiceConfigError> {
        let file = std::fs::File::open(path)?;
        let limit = u64::try_from(MAX_CONFIG_BYTES)
            .map_err(|_| ServiceConfigError::SizeOverflow)?
            .saturating_add(1);
        let mut bytes = Vec::new();
        file.take(limit).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ServiceConfigError::TooLarge);
        }
        let config: Self = serde_json::from_slice(&bytes)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate schema, quotas, selectors, and absolute deployment paths.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported version or unsafe/unbounded setting.
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        if self.schema_version != CURRENT_SERVICE_CONFIG {
            return Err(ServiceConfigError::UnsupportedVersion(self.schema_version));
        }
        for path in [
            &self.objects.process,
            &self.objects.file,
            &self.objects.network,
            &self.objects.memory,
            &self.objects.binder,
            &self.storage.spool_root,
            &self.lock_file,
            &self.status_file,
            &self.log_file,
        ] {
            if !path.is_absolute() {
                return Err(ServiceConfigError::Invalid(format!(
                    "service path must be absolute: {}",
                    path.display()
                )));
            }
        }
        if self.scope.pid == Some(0) {
            return Err(ServiceConfigError::Invalid(
                "capture PID must be greater than zero".to_owned(),
            ));
        }
        if self
            .scope
            .package
            .as_deref()
            .is_some_and(|package| !valid_package_name(package))
        {
            return Err(ServiceConfigError::Invalid(
                "Android package selector is invalid".to_owned(),
            ));
        }
        if self.storage.max_spool_mib == 0 {
            return Err(ServiceConfigError::Invalid(
                "spool capacity must be greater than zero".to_owned(),
            ));
        }
        self.storage
            .max_spool_mib
            .checked_mul(1024 * 1024)
            .ok_or_else(|| {
                ServiceConfigError::Invalid("spool capacity overflows u64".to_owned())
            })?;
        if self.storage.events_per_batch == 0
            || self.storage.events_per_batch > MAX_EVENTS_PER_BATCH
        {
            return Err(ServiceConfigError::Invalid(format!(
                "events_per_batch must be between 1 and {MAX_EVENTS_PER_BATCH}"
            )));
        }
        for (sensor, rate) in [
            ("file", self.sampling.file),
            ("network", self.sampling.network),
            ("memory", self.sampling.memory),
            ("binder", self.sampling.binder),
        ] {
            if rate == 0 {
                return Err(ServiceConfigError::Invalid(format!(
                    "{sensor} sampling rate must be greater than zero"
                )));
            }
        }
        Ok(())
    }

    /// Verify that every configured BPF object currently exists as a regular file.
    ///
    /// # Errors
    ///
    /// Returns an error naming the first missing deployment object.
    pub fn validate_runtime_paths(&self) -> Result<(), ServiceConfigError> {
        for path in [
            &self.objects.process,
            &self.objects.file,
            &self.objects.network,
            &self.objects.memory,
            &self.objects.binder,
        ] {
            if !path.is_file() {
                return Err(ServiceConfigError::Invalid(format!(
                    "BPF object is not a regular file: {}",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    /// Convert the validated service settings into an unlimited quiet capture request.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte capacity cannot be represented safely.
    pub fn capture_request(&self) -> Result<CaptureRequest, ServiceConfigError> {
        self.validate()?;
        let max_spool_bytes = self
            .storage
            .max_spool_mib
            .checked_mul(1024 * 1024)
            .ok_or_else(|| {
                ServiceConfigError::Invalid("spool capacity overflows u64".to_owned())
            })?;
        Ok(CaptureRequest {
            collector_mode: ksight_model::CollectorMode::DetachedDaemon,
            status: None,
            process_object: self.objects.process.clone(),
            file_object: self.objects.file.clone(),
            network_object: self.objects.network.clone(),
            memory_object: self.objects.memory.clone(),
            binder_object: self.objects.binder.clone(),
            // 调度 sensor 在长驻服务模式下不启用，仅保留默认对象路径。
            sched_object: std::path::PathBuf::from("build/bpf/sched_wakeup.bpf.o"),
            sensors: SensorSelection {
                files: self.sensors.files,
                file_descriptors: false,
                network: if self.sensors.network_io {
                    NetworkSelection::Io
                } else if self.sensors.network {
                    NetworkSelection::Lifecycle
                } else {
                    NetworkSelection::Disabled
                },
                memory: match self.sensors.memory {
                    ServiceMemorySelection::Disabled => MemorySelection::Disabled,
                    ServiceMemorySelection::Executable => MemorySelection::Executable,
                    ServiceMemorySelection::All => MemorySelection::All,
                },
                binder: self.sensors.binder,
                sched: false,
            },
            output: OutputOptions {
                json: false,
                include_threads: self.include_threads,
                quiet: true,
            },
            storage: StorageOptions {
                spool_root: Some(self.storage.spool_root.clone()),
                max_spool_bytes,
                events_per_batch: self.storage.events_per_batch,
                compress_batches: self.storage.compress_batches,
                completion_reserve_bytes: self.storage.completion_reserve_kib.saturating_mul(1024),
                max_session_age_secs: self.storage.max_session_age_secs,
                max_total_spool_bytes: self.storage.max_total_spool_mib.saturating_mul(1024 * 1024),
                keep_completed_sessions: self.storage.keep_completed_sessions,
            },
            sampling: SamplingOptions {
                process: 1,
                file: self.sampling.file,
                network: self.sampling.network,
                memory: self.sampling.memory,
                binder: self.sampling.binder,
                sched: 1,
            },
            count: 0,
            duration_seconds: 0,
            pid: self.scope.pid,
            uid: self.scope.uid,
            package: self.scope.package.clone(),
            inspect: ksight_core::InspectPolicy::default(),
            inspect_adapter: crate::inspect_runtime::InspectAdapterKind::LinkerSoLoad,
            uprobe_object: PathBuf::from("/data/local/tmp/ksight/uprobe_regs.bpf.o"),
        })
    }
}

/// Exclusive long-running collector lease released on graceful shutdown.
#[derive(Debug)]
pub struct ServiceLease {
    path: PathBuf,
}

impl ServiceLease {
    /// Atomically acquire the configured collector lease.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceConfigError::AlreadyRunning`] when a live or stale lease already exists.
    pub fn acquire(path: impl AsRef<Path>) -> Result<Self, ServiceConfigError> {
        let path = path.as_ref().to_path_buf();
        let mut file = match create_lease_file(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if lease_process_is_alive(&path)? {
                    return Err(ServiceConfigError::AlreadyRunning(path));
                }
                std::fs::remove_file(&path)?;
                create_lease_file(&path)?
            }
            Err(error) => return Err(error.into()),
        };
        let result = writeln!(file, "{}", std::process::id()).and_then(|()| file.sync_all());
        if let Err(error) = result {
            let _ = std::fs::remove_file(&path);
            return Err(error.into());
        }
        Ok(Self { path })
    }
}

fn create_lease_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

fn read_lease_pid(path: &Path) -> Result<Option<u32>, ServiceConfigError> {
    match std::fs::read_to_string(path) {
        Ok(value) => Ok(value.trim().parse().ok()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn process_is_alive(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    match nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None) {
        Ok(()) | Err(nix::errno::Errno::EPERM) => true,
        Err(_) => false,
    }
}

fn process_is_collector(pid: u32) -> bool {
    let Ok(command_line) = std::fs::read(Path::new("/proc").join(pid.to_string()).join("cmdline"))
    else {
        return false;
    };
    let mut arguments = command_line
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty());
    let Some(executable) = arguments.next() else {
        return false;
    };
    let executable = String::from_utf8_lossy(executable);
    let is_agent = executable == "ksightd" || executable.ends_with("/ksightd");
    is_agent && arguments.any(|argument| argument == b"run")
}

fn lease_process_is_alive(path: &Path) -> Result<bool, ServiceConfigError> {
    Ok(read_lease_pid(path)?.is_some_and(process_is_alive))
}

/// Daemon lifecycle state derived from its lease and process table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonState {
    /// No lease exists and the daemon is stopped.
    Stopped,
    /// The lease names a live process.
    Running,
    /// A malformed or dead-process lease remains after an abnormal exit.
    Stale,
}

/// Machine-readable daemon lifecycle evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRuntimeStatus {
    /// Derived lifecycle state.
    pub state: DaemonState,
    /// Collector process ID when the lease is parseable.
    pub pid: Option<u32>,
    /// Monotonic service start timestamp when the runtime status file is valid.
    pub started_monotonic_ns: Option<u64>,
    /// Absolute service configuration used for the running process.
    pub config_file: PathBuf,
    /// Resolved collector executable when available.
    pub executable: Option<PathBuf>,
    /// Hashes of the running agent, configuration, and loaded-object inputs.
    pub integrity: Option<ComponentIntegrity>,
    /// Latest capture heartbeat and counters.
    pub health: Option<ServiceHealth>,
    /// Age of the latest health heartbeat at inspection time.
    pub heartbeat_age_ns: Option<u64>,
    /// True when the health heartbeat is no more than five seconds old.
    pub health_fresh: Option<bool>,
}

/// Immutable component identities established before sensor attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentIntegrity {
    /// `SHA-256` of the running executable.
    pub executable_sha256: Option<String>,
    /// `SHA-256` of the bounded service configuration.
    pub config_sha256: String,
    /// `SHA-256` by configured sensor object name.
    pub bpf_object_sha256: BTreeMap<String, String>,
}

/// Live whole-device capture state published by the daemon.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceHealth {
    /// Active normalized session identifier.
    pub session_id: Option<Uuid>,
    /// Sensors successfully loaded and attached for this session.
    pub attached_sensors: Vec<String>,
    /// Raw ring-buffer records consumed.
    pub raw_records: u64,
    /// Live events retained after filters.
    pub live_events: u64,
    /// Records rejected by validation.
    pub invalid_records: u64,
    /// Events excluded by requested scope.
    pub filtered_scope: u64,
    /// Thread events excluded by presentation policy.
    pub filtered_threads: u64,
    /// Events produced by the collector process itself and excluded.
    pub filtered_collector: u64,
    /// Current ring-buffer loss counters by sensor.
    pub dropped_by_sensor: BTreeMap<String, u64>,
    /// Complete durable batch bytes currently retained for the active session.
    pub spool_used_bytes: u64,
    /// Configured per-session durable capacity.
    pub spool_limit_bytes: u64,
    /// Most recent retained event monotonic timestamp.
    pub last_event_monotonic_ns: Option<u64>,
    /// Latest daemon heartbeat monotonic timestamp.
    pub heartbeat_monotonic_ns: u64,
    /// Optional target process scope.
    pub scope_pid: Option<u32>,
    /// Optional target Linux UID scope.
    pub scope_uid: Option<u32>,
    /// Optional exact Android package scope.
    pub scope_package: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RunningStatusFile {
    pid: u32,
    started_monotonic_ns: u64,
    config_file: PathBuf,
    executable: Option<PathBuf>,
    integrity: ComponentIntegrity,
    health: ServiceHealth,
}

/// Cloneable writer for atomic live-health updates.
#[derive(Debug, Clone)]
pub struct ServiceStatusHandle {
    path: PathBuf,
    base: RunningStatusFile,
}

/// Status-file guard removed only after capture has flushed or startup fails.
#[derive(Debug)]
pub struct ServiceStatusGuard {
    handle: ServiceStatusHandle,
}

impl ServiceStatusGuard {
    /// Atomically publish the current daemon process metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the status document cannot be written and synchronized.
    pub fn publish(
        path: impl AsRef<Path>,
        config_file: impl AsRef<Path>,
        config: &ServiceConfig,
    ) -> Result<Self, ServiceConfigError> {
        let path = path.as_ref().to_path_buf();
        let status = RunningStatusFile {
            pid: std::process::id(),
            started_monotonic_ns: monotonic_now_ns(),
            config_file: config_file.as_ref().to_path_buf(),
            executable: std::fs::read_link("/proc/self/exe").ok(),
            integrity: component_integrity(config_file.as_ref(), config)?,
            health: ServiceHealth {
                heartbeat_monotonic_ns: monotonic_now_ns(),
                ..ServiceHealth::default()
            },
        };
        write_status_file(&path, &status)?;
        Ok(Self {
            handle: ServiceStatusHandle { path, base: status },
        })
    }

    /// Obtain a writer that can publish capture counters while this guard is alive.
    pub fn handle(&self) -> ServiceStatusHandle {
        self.handle.clone()
    }
}

impl ServiceStatusHandle {
    /// Atomically replace only the changing health portion of daemon status.
    ///
    /// # Errors
    ///
    /// Returns an error when the runtime document cannot be synchronized.
    pub fn update(&self, health: ServiceHealth) -> Result<(), ServiceConfigError> {
        let mut status = self.base.clone();
        status.health = health;
        write_status_file(&self.path, &status)
    }
}

fn write_status_file(path: &Path, status: &RunningStatusFile) -> Result<(), ServiceConfigError> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let result = (|| -> Result<(), ServiceConfigError> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temporary)?;
        serde_json::to_writer(&mut file, status)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn component_integrity(
    config_file: &Path,
    config: &ServiceConfig,
) -> Result<ComponentIntegrity, ServiceConfigError> {
    let executable = std::fs::read_link("/proc/self/exe").ok();
    let executable_sha256 = executable.as_deref().map(hash_file).transpose()?;
    let mut bpf_object_sha256 = BTreeMap::new();
    for (name, path) in [
        ("process", &config.objects.process),
        ("file", &config.objects.file),
        ("network", &config.objects.network),
        ("memory", &config.objects.memory),
        ("binder", &config.objects.binder),
    ] {
        bpf_object_sha256.insert(name.to_owned(), hash_file(path)?);
    }
    Ok(ComponentIntegrity {
        executable_sha256,
        config_sha256: hash_file(config_file)?,
        bpf_object_sha256,
    })
}

fn hash_file(path: &Path) -> Result<String, ServiceConfigError> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    std::io::copy(&mut file, &mut digest)?;
    let bytes = digest.finalize();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}")
            .map_err(|_| ServiceConfigError::Invalid("SHA-256 encoding failed".to_owned()))?;
    }
    Ok(encoded)
}

impl Drop for ServiceStatusGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.handle.path);
    }
}

/// Inspect daemon state without mutating stale runtime files.
///
/// # Errors
///
/// Returns an error when the configuration or runtime files cannot be read.
pub fn inspect_service(
    config_file: impl AsRef<Path>,
) -> Result<ServiceRuntimeStatus, ServiceConfigError> {
    let config_file = config_file.as_ref().to_path_buf();
    let config = ServiceConfig::load(&config_file)?;
    let pid = read_lease_pid(&config.lock_file)?;
    let status = std::fs::read(&config.status_file)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<RunningStatusFile>(&bytes).ok())
        .filter(|status| Some(status.pid) == pid);
    let state = match pid {
        None if config.lock_file.exists() => DaemonState::Stale,
        None => DaemonState::Stopped,
        Some(pid) if status.is_some() && process_is_alive(pid) && process_is_collector(pid) => {
            DaemonState::Running
        }
        Some(_) => DaemonState::Stale,
    };
    let heartbeat_age_ns = status
        .as_ref()
        .map(|value| monotonic_now_ns().saturating_sub(value.health.heartbeat_monotonic_ns));
    Ok(ServiceRuntimeStatus {
        state,
        pid,
        started_monotonic_ns: status.as_ref().map(|value| value.started_monotonic_ns),
        config_file,
        executable: status.as_ref().and_then(|value| value.executable.clone()),
        integrity: status.as_ref().map(|value| value.integrity.clone()),
        health: status.as_ref().map(|value| value.health.clone()),
        heartbeat_age_ns,
        health_fresh: heartbeat_age_ns.map(|age| age <= 5_000_000_000),
    })
}

/// Request graceful daemon shutdown after validating the leased process.
///
/// # Errors
///
/// Returns an error for a missing/stale daemon or an invalid process identifier.
pub fn stop_service(
    config_file: impl AsRef<Path>,
) -> Result<ServiceRuntimeStatus, ServiceConfigError> {
    let status = inspect_service(config_file)?;
    if status.state != DaemonState::Running {
        return Err(ServiceConfigError::NotRunning(status.state));
    }
    let pid = status
        .pid
        .ok_or(ServiceConfigError::NotRunning(status.state))?;
    let raw_pid = i32::try_from(pid)
        .map_err(|_| ServiceConfigError::Invalid("daemon PID exceeds i32".to_owned()))?;
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(raw_pid),
        nix::sys::signal::Signal::SIGTERM,
    )
    .map_err(|error| ServiceConfigError::Signal(error.to_string()))?;
    Ok(status)
}

fn monotonic_now_ns() -> u64 {
    nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
        .ok()
        .and_then(|time| {
            u64::try_from(time.tv_sec())
                .ok()?
                .checked_mul(1_000_000_000)?
                .checked_add(u64::try_from(time.tv_nsec()).ok()?)
        })
        .unwrap_or(0)
}

impl Drop for ServiceLease {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Service configuration failure.
#[derive(Debug, Error)]
pub enum ServiceConfigError {
    /// Configuration I/O failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// JSON decoding failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Configuration exceeds the fixed input bound.
    #[error("service configuration exceeds {MAX_CONFIG_BYTES} bytes")]
    TooLarge,
    /// Configuration size cannot be represented safely.
    #[error("service configuration size cannot be represented")]
    SizeOverflow,
    /// Configuration schema is unsupported.
    #[error("unsupported service configuration schema {0}")]
    UnsupportedVersion(u16),
    /// A setting violates a service invariant.
    #[error("invalid service configuration: {0}")]
    Invalid(String),
    /// Another collector lease exists and requires operator inspection.
    #[error("collector lease already exists: {}", .0.display())]
    AlreadyRunning(PathBuf),
    /// No live collector exists for a stop request.
    #[error("collector is not running (state: {0:?})")]
    NotRunning(DaemonState),
    /// Sending a graceful signal failed.
    #[error("failed to signal collector: {0}")]
    Signal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_converts_bounded_service_configuration() {
        let config: ServiceConfig = serde_json::from_str(valid_json()).unwrap();
        config.validate().unwrap();
        let request = config.capture_request().unwrap();
        assert!(request.output.quiet);
        assert_eq!(request.storage.events_per_batch, 64);
        assert_eq!(request.sensors.memory, MemorySelection::Executable);
    }

    #[test]
    fn rejects_unknown_fields_and_unbounded_batches() {
        let unknown = valid_json().replace(
            "\"include_threads\": false",
            "\"include_threads\": false, \"surprise\": true",
        );
        assert!(serde_json::from_str::<ServiceConfig>(&unknown).is_err());

        let mut config: ServiceConfig = serde_json::from_str(valid_json()).unwrap();
        config.storage.events_per_batch = MAX_EVENTS_PER_BATCH + 1;
        assert!(matches!(
            config.validate(),
            Err(ServiceConfigError::Invalid(_))
        ));
    }

    fn valid_json() -> &'static str {
        r#"{
          "schema_version": 3,
          "objects": {
            "process": "/data/local/tmp/ksight/process_lifecycle.bpf.o",
            "file": "/data/local/tmp/ksight/file_open.bpf.o",
            "network": "/data/local/tmp/ksight/network_connect.bpf.o",
            "memory": "/data/local/tmp/ksight/memory_regions.bpf.o",
            "binder": "/data/local/tmp/ksight/binder_transaction.bpf.o"
          },
          "sensors": {
            "files": true,
            "network": true,
            "network_io": false,
            "memory": "executable",
            "binder": true
          },
          "scope": { "pid": null, "uid": null, "package": null },
          "storage": {
            "spool_root": "/data/local/tmp/ksight/spool",
            "max_spool_mib": 64,
            "events_per_batch": 64
          },
          "sampling": { "file": 4, "network": 1, "memory": 1, "binder": 16 },
          "lock_file": "/data/local/tmp/ksight/ksightd.lock",
          "status_file": "/data/local/tmp/ksight/ksightd.status.json",
          "log_file": "/data/local/tmp/ksight/ksightd.log",
          "include_threads": false
        }"#
    }

    #[test]
    fn service_lease_is_exclusive_and_released_on_drop() {
        let root = std::env::temp_dir().join(format!("ksight-lease-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("collector.lock");
        let lease = ServiceLease::acquire(&path).unwrap();
        assert!(matches!(
            ServiceLease::acquire(&path),
            Err(ServiceConfigError::AlreadyRunning(_))
        ));
        drop(lease);
        ServiceLease::acquire(&path).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn service_lease_reclaims_dead_process_lock() {
        let root = std::env::temp_dir().join(format!("ksight-stale-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("collector.lock");
        std::fs::write(&path, format!("{}\n", u32::MAX)).unwrap();
        let lease = ServiceLease::acquire(&path).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim(),
            std::process::id().to_string()
        );
        drop(lease);
        std::fs::remove_dir_all(root).unwrap();
    }
}
