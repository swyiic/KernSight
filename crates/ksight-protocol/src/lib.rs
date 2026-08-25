//! Version negotiation and wire-level messages shared by clients and the agent.

mod message;
mod version;

pub use message::{
    Ack, Capability, EventBatch, GapReport, Heartbeat, Hello, HelloAck, Message, SensorPolicy,
    StartSession, UpdatePolicy,
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
