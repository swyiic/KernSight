use ksight_model::Event;

use crate::collector::RawRecord;

/// Converts a versioned raw ABI record into a normalized semantic event.
pub trait Normalizer {
    /// Normalization error.
    type Error;

    /// Decode, validate, and enrich one record.
    ///
    /// # Errors
    ///
    /// Returns an implementation-specific error for an invalid or unsupported raw record.
    fn normalize(&mut self, record: RawRecord) -> Result<Event, Self::Error>;
}
