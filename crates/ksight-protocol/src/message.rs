use ksight_model::{CaptureMode, Event, SensorKind};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ProtocolVersion;

/// Negotiated device or client capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// Stable capability identifier.
    pub name: String,
    /// Capability-specific version.
    pub version: u32,
}

/// First message sent by a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Client protocol version.
    pub protocol: ProtocolVersion,
    /// Human-readable client name.
    pub client_name: String,
    /// Client capabilities.
    pub capabilities: Vec<Capability>,
}

/// Agent response to protocol negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloAck {
    /// Accepted protocol version.
    pub protocol: ProtocolVersion,
    /// Agent semantic version.
    pub agent_version: String,
    /// Agent capabilities.
    pub capabilities: Vec<Capability>,
}

/// Start a new capture session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartSession {
    /// Client-generated session identifier.
    pub session_id: Uuid,
    /// Requested initial capture mode.
    pub mode: CaptureMode,
}

/// Policy for one capture sensor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorPolicy {
    /// Target sensor.
    pub sensor: SensorKind,
    /// Whether the sensor is enabled.
    pub enabled: bool,
    /// Keep one out of every `sample_one_in` eligible records.
    pub sample_one_in: u32,
    /// Maximum captured payload size.
    pub max_payload_bytes: u32,
}

/// Auditable policy replacement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePolicy {
    /// Strictly increasing policy generation.
    pub generation: u64,
    /// Mode associated with this policy.
    pub mode: CaptureMode,
    /// Per-sensor settings.
    pub sensors: Vec<SensorPolicy>,
}

/// Ordered batch of normalized events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventBatch {
    /// Capture session.
    pub session_id: Uuid,
    /// Agent-local ordered batch number.
    pub batch_sequence: u64,
    /// Events in source order.
    pub events: Vec<Event>,
}

/// Explicit record of missing event or batch sequences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapReport {
    /// Source sensor, if the gap is sensor-specific.
    pub sensor: Option<SensorKind>,
    /// First missing sequence.
    pub first_missing: u64,
    /// Last missing sequence, inclusive.
    pub last_missing: u64,
    /// Agent-provided reason.
    pub reason: String,
}

/// Generic command acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    /// Correlation identifier.
    pub request_id: Uuid,
    /// Whether the operation succeeded.
    pub accepted: bool,
    /// Diagnostic intended for operators.
    pub detail: Option<String>,
}

/// Connection liveness and ordering summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Agent monotonic timestamp.
    pub monotonic_ns: u64,
    /// Last produced batch.
    pub last_batch_sequence: u64,
    /// Total known dropped records.
    pub dropped_records: u64,
}

/// Top-level protocol message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum Message {
    /// Client greeting.
    Hello(Hello),
    /// Agent negotiation response.
    HelloAck(HelloAck),
    /// Start session command.
    StartSession(StartSession),
    /// Replace capture policy.
    UpdatePolicy(UpdatePolicy),
    /// Normalized event batch.
    EventBatch(EventBatch),
    /// Explicit missing-data report.
    GapReport(GapReport),
    /// Command acknowledgement.
    Ack(Ack),
    /// Liveness message.
    Heartbeat(Heartbeat),
}
