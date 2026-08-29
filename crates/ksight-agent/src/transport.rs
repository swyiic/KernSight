use std::io::{Read, Write};

use ksight_protocol::{FrameError, JsonFrameCodec, Message};

/// Message transport exposed through an operator-controlled local channel.
///
/// Production implementations must add peer authentication and replay protection before framing
/// bytes are accepted as commands.
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

/// Strict length-delimited stream adapter used beneath the future authenticated session layer.
#[derive(Debug)]
pub struct FramedTransport<Io> {
    io: Io,
    codec: JsonFrameCodec,
}

/// Framed adapter for transports exposing independent read and write handles.
#[derive(Debug)]
pub struct SplitFramedTransport<Reader, Writer> {
    reader: Reader,
    writer: Writer,
    codec: JsonFrameCodec,
}

impl<Reader, Writer> SplitFramedTransport<Reader, Writer> {
    /// Wrap separate stream handles with the default bounded codec.
    pub fn new(reader: Reader, writer: Writer) -> Self {
        Self {
            reader,
            writer,
            codec: JsonFrameCodec::default(),
        }
    }

    /// Wrap separate stream handles with an explicitly configured codec.
    pub fn with_codec(reader: Reader, writer: Writer, codec: JsonFrameCodec) -> Self {
        Self {
            reader,
            writer,
            codec,
        }
    }

    /// Release the underlying read and write handles.
    pub fn into_parts(self) -> (Reader, Writer) {
        (self.reader, self.writer)
    }
}

impl<Io> FramedTransport<Io> {
    /// Wrap a bidirectional byte stream with the default bounded frame codec.
    pub fn new(io: Io) -> Self {
        Self {
            io,
            codec: JsonFrameCodec::default(),
        }
    }

    /// Wrap a stream with an explicitly configured codec.
    pub fn with_codec(io: Io, codec: JsonFrameCodec) -> Self {
        Self { io, codec }
    }

    /// Borrow the underlying stream for local adapter configuration or testing.
    pub fn io_mut(&mut self) -> &mut Io {
        &mut self.io
    }

    /// Release the underlying stream.
    pub fn into_inner(self) -> Io {
        self.io
    }
}

impl<Io: Read + Write> Transport for FramedTransport<Io> {
    type Error = FrameError;

    fn receive(&mut self) -> Result<Option<Message>, Self::Error> {
        self.codec.read(&mut self.io)
    }

    fn send(&mut self, message: &Message) -> Result<(), Self::Error> {
        self.codec.write(&mut self.io, message)?;
        self.io.flush()?;
        Ok(())
    }
}

impl<Reader: Read, Writer: Write> Transport for SplitFramedTransport<Reader, Writer> {
    type Error = FrameError;

    fn receive(&mut self) -> Result<Option<Message>, Self::Error> {
        self.codec.read(&mut self.reader)
    }

    fn send(&mut self, message: &Message) -> Result<(), Self::Error> {
        self.codec.write(&mut self.writer, message)?;
        self.writer.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use ksight_protocol::{Hello, CURRENT_PROTOCOL};

    use super::*;

    #[test]
    fn framed_transport_round_trips_one_message() {
        let expected = Message::Hello(Hello {
            protocol: CURRENT_PROTOCOL,
            client_name: "transport-test".to_owned(),
            capabilities: Vec::new(),
        });
        let mut transport = FramedTransport::new(Cursor::new(Vec::new()));
        transport.send(&expected).unwrap();
        transport.io_mut().set_position(0);
        assert_eq!(transport.receive().unwrap(), Some(expected));
        assert_eq!(transport.receive().unwrap(), None);
    }

    #[test]
    fn split_transport_round_trips_between_independent_handles() {
        let expected = Message::Hello(Hello {
            protocol: CURRENT_PROTOCOL,
            client_name: "split-test".to_owned(),
            capabilities: Vec::new(),
        });
        let mut outbound = Vec::new();
        let mut sender = SplitFramedTransport::new(Cursor::new(Vec::new()), &mut outbound);
        sender.send(&expected).unwrap();

        let mut sink = Vec::new();
        let mut receiver = SplitFramedTransport::new(Cursor::new(outbound), &mut sink);
        assert_eq!(receiver.receive().unwrap(), Some(expected));
    }
}
