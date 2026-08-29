/// Raw event record copied out of a bounded kernel channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRecord {
    /// Raw ABI version.
    pub abi_version: u16,
    /// Raw sensor identifier.
    pub sensor_id: u16,
    /// Fixed-header sequence.
    pub sequence: u64,
    /// Complete bounded bytes including the raw header.
    pub bytes: Vec<u8>,
}

impl RawRecord {
    /// Validate and copy one raw kernel record.
    ///
    /// # Errors
    ///
    /// Returns an ABI decoding error when the record is truncated or incompatible.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ksight_abi::DecodeError> {
        let header = ksight_abi::RawEventHeader::decode(bytes)?;
        Ok(Self {
            abi_version: header.abi_version,
            sensor_id: header.sensor_id,
            sequence: header.source_sequence,
            bytes: bytes.to_vec(),
        })
    }

    /// Whether this record declares the ABI implemented by this agent build.
    pub fn has_supported_abi(&self) -> bool {
        self.abi_version == ksight_abi::RAW_ABI_VERSION
    }
}

/// Pull-based boundary over ring-buffer, perf-buffer, or test collectors.
pub trait Collector {
    /// Collector-specific error.
    type Error;

    /// Read the next available bounded record.
    ///
    /// # Errors
    ///
    /// Returns an adapter-specific error when the kernel channel cannot be consumed safely.
    fn next_record(&mut self) -> Result<Option<RawRecord>, Self::Error>;

    /// Total records known to have been lost.
    fn dropped_records(&self) -> u64;

    /// Seed kernel-side socket tracking with pre-session descriptors.
    ///
    /// The default implementation is a no-op; sensors that keep a `socket_fds`
    /// map override this to enable read/write socket identification for
    /// descriptors that predate the session.
    fn seed_socket_fds(&mut self, _entries: &[(u32, i32)]) {}
}
