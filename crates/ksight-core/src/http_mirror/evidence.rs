//! Evidence attributes independent of the HTTP envelope used for display.

use serde::Serialize;

/// How a displayable message was obtained.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageOrigin {
    /// HTTP fields decoded from captured protocol bytes.
    #[default]
    ObservedHttp,
    /// A non-HTTP protocol translated into an HTTP display envelope.
    ProtocolDerived,
    /// Bytes without a captured HTTP message head.
    BodyFragment,
    /// A URL was observed, but an HTTP request was not.
    UrlHint,
    /// A request exists only to display an unpaired response.
    SyntheticRequest,
}

/// Whether the captured framing establishes a complete message.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageCompleteness {
    /// Framing was not sufficient to decide completeness.
    #[default]
    Unknown,
    /// All bytes required by the observed framing were reconstructed.
    Complete,
    /// An idle flush, missing frame, or size limit interrupted reconstruction.
    Incomplete,
}

/// Basis for associating a displayed request and response; never a finding.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingBasis {
    /// No captured peer was matched.
    #[default]
    Unpaired,
    /// HTTP/1 order on the same captured connection key (correlation only).
    ConnectionOrder,
    /// Matching HTTP/2 stream ID on the same captured connection key.
    ConnectionAndH2Stream,
    /// A synthetic request wraps an unpaired response for display.
    DisplayOnly,
}

/// Location of a reconstructed message within a capture. A connection key may
/// be an SSL pointer or a thread fallback; it is not a verified lifetime ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MirrorSource {
    /// Capture session identifier supplied by the collector.
    pub session_id: String,
    /// Process ID at the time of collection.
    pub pid: u32,
    /// Captured connection token, not a cross-session identity.
    pub connection_key: u64,
    /// Session-local reconstructed message number, not a raw event ID.
    pub message_number: u64,
}

/// Structured evidence metadata. Display transformations do not change the
/// original status, and unknown evidence stays unknown.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct MessageEvidence {
    /// Origin of the message rather than its display envelope.
    pub origin: MessageOrigin,
    /// Framing completeness independent of whether Burp accepted the bytes.
    pub completeness: MessageCompleteness,
    /// Reason for incomplete or derived output.
    pub reason: Option<&'static str>,
    /// Status used only for a non-HTTP display envelope.
    pub display_status: Option<u16>,
    /// Original declared content length before decoding or display rewriting.
    pub declared_body_bytes: Option<u64>,
    /// Bytes known to have been omitted by reconstruction limits.
    pub dropped_body_bytes: u64,
    /// Parsed destination before any display/SNI/RPC hint rewriting.
    pub original_destination: Option<(String, String)>,
    /// Entity bytes before decompression/unwrapping, only retained when transformed.
    /// Not placed into summary logs. This is not a raw TLS/frame snapshot.
    #[serde(skip)]
    pub original_entity: Option<Vec<u8>>,
    /// Ordered display transforms; never evidence that the application performed them.
    pub transformations: Vec<&'static str>,
    /// How a captured request and response were correlated.
    pub pairing: PairingBasis,
    /// Capture scope, when the message has passed through ksightd.
    pub source: Option<MirrorSource>,
}

impl MessageEvidence {
    /// Mark output whose original message boundary was not observed.
    #[must_use]
    pub fn fragment(reason: &'static str) -> Self {
        Self {
            origin: MessageOrigin::BodyFragment,
            reason: Some(reason),
            ..Self::default()
        }
    }

    /// Record a non-HTTP conversion without claiming its status was captured.
    #[must_use]
    pub fn derived(reason: &'static str, display_status: Option<u16>) -> Self {
        Self {
            origin: MessageOrigin::ProtocolDerived,
            reason: Some(reason),
            display_status,
            ..Self::default()
        }
    }
}
