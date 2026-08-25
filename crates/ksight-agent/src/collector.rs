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
}
