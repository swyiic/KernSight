/// Loads, attaches, verifies, and detaches one capture sensor.
pub trait SensorLoader {
    /// Loader-specific error.
    type Error;

    /// Prepare and attach the configured sensor.
    ///
    /// # Errors
    ///
    /// Returns an adapter-specific load, verification, or attachment error.
    fn attach(&mut self) -> Result<(), Self::Error>;

    /// Verify that expected programs and links remain attached.
    ///
    /// # Errors
    ///
    /// Returns an adapter-specific error when expected state cannot be established.
    fn verify(&self) -> Result<(), Self::Error>;

    /// Detach the sensor and release its resources.
    ///
    /// # Errors
    ///
    /// Returns an adapter-specific cleanup error.
    fn detach(&mut self) -> Result<(), Self::Error>;
}
