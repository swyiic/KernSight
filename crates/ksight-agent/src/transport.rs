use ksight_protocol::Message;

/// Authenticated local transport exposed through an operator-controlled USB tunnel.
pub trait Transport {
    /// Transport-specific error.
    type Error;

    /// Receive one complete framed message.
    ///
    /// # Errors
    ///
    /// Returns an implementation-specific framing, authentication, or I/O error.
    fn receive(&mut self) -> Result<Option<Message>, Self::Error>;

    /// Send one complete framed message.
    ///
    /// # Errors
    ///
    /// Returns an implementation-specific framing, authentication, or I/O error.
    fn send(&mut self, message: &Message) -> Result<(), Self::Error>;
}
