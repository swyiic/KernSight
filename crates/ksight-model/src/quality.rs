use serde::{Deserialize, Serialize};

/// Strength of a semantic interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Directly established from a stable source or schema.
    Confirmed,
    /// Derived from multiple facts with a documented inference.
    Inferred,
    /// Only part of the structure was recovered.
    Partial,
    /// Payload is preserved but not interpreted.
    Opaque,
}

/// Data-quality metadata carried with every event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataQuality {
    /// Interpretation confidence.
    pub confidence: Confidence,
    /// Whether the captured payload was truncated.
    pub truncated: bool,
    /// Number of known lost records immediately before this record.
    pub lost_before: u64,
    /// One emitted eligible event out of this many; one means unsampled.
    pub sample_one_in: u32,
    /// Human-readable capture source, such as a tracepoint name.
    pub source: String,
}
