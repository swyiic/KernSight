use serde::{Deserialize, Serialize};

/// Version of the client-agent wire protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    /// Breaking protocol generation.
    pub major: u16,
    /// Backward-compatible protocol feature level.
    pub minor: u16,
}

/// Initial `KernSight` protocol version.
pub const CURRENT_PROTOCOL: ProtocolVersion = ProtocolVersion { major: 1, minor: 0 };
