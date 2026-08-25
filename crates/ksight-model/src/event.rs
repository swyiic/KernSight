use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{DataQuality, ProcessIdentity};

/// Version of the normalized semantic event schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaVersion {
    /// Breaking schema generation.
    pub major: u16,
    /// Backward-compatible schema feature level.
    pub minor: u16,
}

/// Visibility and collection impact of an event source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    /// Low-impact, whole-device collection.
    Observe,
    /// Explicit, selected-process semantic inspection.
    Inspect,
    /// Explicit laboratory debugger session.
    Debug,
}

/// Capture subsystem that produced an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensorKind {
    /// Process lifecycle and credentials.
    Process,
    /// Filesystem operations.
    File,
    /// Virtual memory and executable mappings.
    Memory,
    /// Socket and packet metadata.
    Network,
    /// Android Binder IPC.
    Binder,
    /// Capture and boot integrity telemetry.
    Integrity,
    /// Optional low-level syscall supplement.
    Syscall,
}

/// Metadata shared by every normalized event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventHeader {
    /// Normalized schema version.
    pub schema: SchemaVersion,
    /// Unique capture session.
    pub session_id: Uuid,
    /// Source-local monotonically increasing sequence number.
    pub source_sequence: u64,
    /// Kernel monotonic timestamp in nanoseconds.
    pub monotonic_ns: u64,
    /// CPU that emitted the raw record, if known.
    pub cpu: Option<u32>,
    /// Process identity known at normalization time.
    pub process: ProcessIdentity,
    /// Producing sensor.
    pub sensor: SensorKind,
    /// Collection mode in effect at emission time.
    pub mode: CaptureMode,
    /// Confidence, truncation, and loss metadata.
    pub quality: DataQuality,
}

/// Normalized event with a stable header and an extensible payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Event metadata.
    pub header: EventHeader,
    /// Sensor-specific facts.
    pub payload: EventPayload,
}

/// Sensor-specific normalized facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum EventPayload {
    /// Process lifecycle transition.
    ProcessLifecycle(ProcessLifecycle),
    /// Forward-compatible bounded bytes for an unknown event type.
    Opaque {
        /// Source type identifier.
        type_id: u32,
        /// Bounded raw payload.
        bytes: Vec<u8>,
    },
}

/// Process lifecycle transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessLifecycle {
    /// Transition type.
    pub kind: ProcessLifecycleKind,
    /// Parent PID where meaningful.
    pub parent_pid: Option<u32>,
    /// Executed filename where meaningful.
    pub filename: Option<String>,
    /// Exit code where meaningful.
    pub exit_code: Option<i32>,
}

/// Kind of process lifecycle transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessLifecycleKind {
    /// Process or thread creation.
    Fork,
    /// Image replacement by exec.
    Exec,
    /// Process or thread exit.
    Exit,
}
