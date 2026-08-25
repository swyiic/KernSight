use serde::{Deserialize, Serialize};

/// Runtime or static evidence artifact class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// Dalvik executable artifact.
    Dex,
    /// ELF executable or shared object.
    Elf,
    /// Raw memory snapshot.
    MemorySnapshot,
    /// Structured or unstructured plaintext evidence.
    Plaintext,
    /// Binder transaction payload.
    BinderParcel,
    /// Unknown bounded binary artifact.
    OpaqueBinary,
}

/// Provenance of an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactProvenance {
    /// Present in the original package.
    Original,
    /// Observed as loaded by the runtime.
    Loaded,
    /// Captured from live memory.
    RuntimeSnapshot,
    /// Reconstructed from multiple evidence fragments.
    Reconstructed,
    /// Structure inferred but not fully established.
    Inferred,
}

/// Content-addressed reference to an evidence artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef {
    /// Artifact class.
    pub kind: ArtifactKind,
    /// Evidence provenance.
    pub provenance: ArtifactProvenance,
    /// Lowercase SHA-256 digest.
    pub sha256: String,
    /// Byte length.
    pub size: u64,
    /// Optional source path or mapping label.
    pub label: Option<String>,
}
