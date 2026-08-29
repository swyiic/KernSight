use ksight_model::{CaptureMode, CaptureStopReason, Event, SensorKind};
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

/// Durable unacknowledged session range advertised by the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableSessionSummary {
    /// Capture session owning the batches.
    pub session_id: Uuid,
    /// Number of complete unacknowledged batches.
    pub batch_count: u64,
    /// Number of normalized events across complete batches.
    pub event_count: u64,
    /// First unacknowledged batch sequence.
    pub first_batch_sequence: Option<u64>,
    /// Last unacknowledged batch sequence.
    pub last_batch_sequence: Option<u64>,
    /// Encoded bytes occupied by complete batches.
    pub used_bytes: u64,
    /// Lifecycle state recorded in the session manifest.
    #[serde(default)]
    pub state: DurableSessionState,
    /// True when complete batches are independently compressed.
    #[serde(default)]
    pub compressed: bool,
    /// Unix milliseconds when the session directory was created, if known.
    #[serde(default)]
    pub started_unix_ms: Option<u64>,
    /// Sealed stop reason when the session is no longer running.
    #[serde(default)]
    pub stop_reason: Option<CaptureStopReason>,
}

/// Durable session lifecycle recorded beside immutable batches.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableSessionState {
    /// Collector is still appending batches.
    #[default]
    Running,
    /// A completion event was flushed normally.
    Completed,
    /// The process exited without a completion event.
    Interrupted,
    /// This directory was sealed so capture could continue elsewhere.
    Rotated,
    /// Capture stopped because a storage bound was reached.
    StorageLimited,
}

/// Request the current durable-session inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListSessions {
    /// Client-generated request correlation identifier.
    pub request_id: Uuid,
}

/// Durable-session inventory response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInventory {
    /// Request correlation identifier.
    pub request_id: Uuid,
    /// Validated durable sessions.
    pub sessions: Vec<DurableSessionSummary>,
}

/// Request ordered replay of one durable session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayBatches {
    /// Client-generated request correlation identifier.
    pub request_id: Uuid,
    /// Capture session to replay.
    pub session_id: Uuid,
    /// Emit batches strictly after this sequence, or from the first pending batch when absent.
    pub after_batch_sequence: Option<u64>,
}

/// Marks the end of one replay response stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayComplete {
    /// Request correlation identifier.
    pub request_id: Uuid,
    /// Capture session that was replayed.
    pub session_id: Uuid,
    /// Last batch emitted for this request, if any.
    pub last_batch_sequence: Option<u64>,
}

/// Client confirmation that durable batches were received and validated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcknowledgeBatches {
    /// Client-generated request correlation identifier.
    pub request_id: Uuid,
    /// Capture session owning the batches.
    pub session_id: Uuid,
    /// Highest contiguous batch sequence safely received by the client.
    pub through_batch_sequence: u64,
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
    /// False when the short-lived control process cannot read live sensor
    /// counters from the detached collector.
    #[serde(default)]
    pub dropped_records_known: bool,
}

/// Request the agent's live collector and spool status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetStatus {
    /// Client-generated request correlation identifier.
    pub request_id: Uuid,
}

/// Durable-session last-exit evidence written by the collector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastExit {
    /// Unix milliseconds when the document was written.
    pub written_unix_ms: u64,
    /// Collector process identifier.
    pub pid: u32,
    /// Session that was active at exit, if any.
    pub session_id: Option<Uuid>,
    /// Stable stop or crash classification.
    pub reason: String,
    /// Operator-facing diagnostic.
    pub detail: Option<String>,
    /// True when the collector sealed a completion event.
    pub clean: bool,
}

/// Aggregated live status for CLI and `MobileE` reconnect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStatus {
    /// Request correlation identifier.
    pub request_id: Uuid,
    /// Active or most recent session.
    pub session_id: Option<Uuid>,
    /// Last complete batch across retained sessions.
    pub last_batch_sequence: u64,
    /// Number of durable session directories.
    pub session_count: u64,
    /// Bytes occupied by complete batches under the spool root.
    pub spool_used_bytes: u64,
    /// Latest sealed exit record, if any.
    pub last_exit: Option<LastExit>,
    /// Agent monotonic timestamp.
    pub heartbeat_monotonic_ns: u64,
    /// Durable state of `session_id`.
    #[serde(default)]
    pub latest_session_state: Option<DurableSessionState>,
    /// Known dropped records for the live collector, or `None` when status is
    /// reconstructed from durable storage only.
    #[serde(default)]
    pub dropped_records: Option<u64>,
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
    /// Durable batch confirmation.
    AcknowledgeBatches(AcknowledgeBatches),
    /// Durable-session inventory request.
    ListSessions(ListSessions),
    /// Durable-session inventory response.
    SessionInventory(SessionInventory),
    /// Durable batch replay request.
    ReplayBatches(ReplayBatches),
    /// Durable batch replay terminator.
    ReplayComplete(ReplayComplete),
    /// Explicit missing-data report.
    GapReport(GapReport),
    /// Command acknowledgement.
    Ack(Ack),
    /// Liveness message.
    Heartbeat(Heartbeat),
    /// Live status request.
    GetStatus(GetStatus),
    /// Live status response.
    AgentStatus(AgentStatus),
}
