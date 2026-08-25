use ksight_protocol::EventBatch;

/// Durable bounded queue used while the USB client is disconnected.
pub trait Spool {
    /// Spool-specific error.
    type Error;

    /// Persist a complete immutable batch.
    ///
    /// # Errors
    ///
    /// Returns an implementation-specific persistence or capacity error.
    fn append(&mut self, batch: &EventBatch) -> Result<(), Self::Error>;

    /// Discard batches acknowledged by the client.
    ///
    /// # Errors
    ///
    /// Returns an implementation-specific persistence error.
    fn acknowledge_through(&mut self, batch_sequence: u64) -> Result<(), Self::Error>;
}
