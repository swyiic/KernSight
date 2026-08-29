//! Version negotiation and wire-level messages shared by clients and the agent.

mod framing;
mod message;
mod version;

pub use framing::{FrameError, JsonFrameCodec, DEFAULT_MAX_FRAME_BYTES};
pub use message::{
    Ack, AcknowledgeBatches, AgentStatus, Capability, DurableSessionState, DurableSessionSummary,
    EventBatch, GapReport, GetStatus, Heartbeat, Hello, HelloAck, LastExit, ListSessions, Message,
    ReplayBatches, ReplayComplete, SensorPolicy, SessionInventory, StartSession, UpdatePolicy,
};
pub use version::{ProtocolVersion, CURRENT_PROTOCOL};

/// Encode a message as JSON for local debugging and golden tests.
///
/// Production framing and binary encoding will be selected in a dedicated architecture decision.
///
/// # Errors
///
/// Returns a serialization error when a message cannot be represented as JSON.
pub fn encode_debug_json(message: &Message) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(message)
}

/// Decode a local debug JSON message.
///
/// # Errors
///
/// Returns a deserialization error for malformed or incompatible input.
pub fn decode_debug_json(bytes: &[u8]) -> Result<Message, serde_json::Error> {
    serde_json::from_slice(bytes)
}
