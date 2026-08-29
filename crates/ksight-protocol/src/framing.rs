use std::io::{self, Read, Write};

use thiserror::Error;

use crate::Message;

/// Default maximum encoded protocol message size (8 MiB).
pub const DEFAULT_MAX_FRAME_BYTES: u32 = 8 * 1024 * 1024;

/// Length-delimited JSON framing for local development transports.
///
/// Each frame is a four-byte unsigned big-endian payload length followed by exactly one serialized
/// [`Message`]. Authentication and replay protection are transport concerns and must wrap this
/// codec before it is exposed outside an operator-controlled local channel.
#[derive(Debug, Clone, Copy)]
pub struct JsonFrameCodec {
    max_frame_bytes: u32,
}

impl JsonFrameCodec {
    /// Create a codec with an explicit non-zero allocation bound.
    ///
    /// # Errors
    ///
    /// Returns an error when `max_frame_bytes` is zero.
    pub fn new(max_frame_bytes: u32) -> Result<Self, FrameError> {
        if max_frame_bytes == 0 {
            return Err(FrameError::InvalidMaximum);
        }
        Ok(Self { max_frame_bytes })
    }

    /// Maximum accepted or emitted JSON payload bytes, excluding the length prefix.
    pub fn max_frame_bytes(self) -> u32 {
        self.max_frame_bytes
    }

    /// Read one complete frame, returning `None` only for a clean EOF before a new header.
    ///
    /// # Errors
    ///
    /// Returns an error for I/O failure, truncated frames, an excessive declared length, or invalid
    /// protocol JSON.
    pub fn read<R: Read>(self, reader: &mut R) -> Result<Option<Message>, FrameError> {
        let mut header = [0_u8; 4];
        let header_bytes = read_available(reader, &mut header)?;
        if header_bytes == 0 {
            return Ok(None);
        }
        if header_bytes != header.len() {
            return Err(FrameError::TruncatedHeader {
                received: header_bytes,
            });
        }

        let declared = u32::from_be_bytes(header);
        if declared > self.max_frame_bytes {
            return Err(FrameError::FrameTooLarge {
                observed: declared,
                maximum: self.max_frame_bytes,
            });
        }
        let body_len = usize::try_from(declared).map_err(|_| FrameError::LengthOverflow)?;
        let mut body = vec![0_u8; body_len];
        let body_bytes = read_available(reader, &mut body)?;
        if body_bytes != body.len() {
            return Err(FrameError::TruncatedBody {
                declared,
                received: body_bytes,
            });
        }
        Ok(Some(serde_json::from_slice(&body)?))
    }

    /// Serialize and write one complete frame.
    ///
    /// # Errors
    ///
    /// Returns an error for serialization, excessive encoded size, or I/O failure. The size is
    /// checked before any frame bytes are written.
    pub fn write<W: Write>(self, writer: &mut W, message: &Message) -> Result<(), FrameError> {
        let body = serde_json::to_vec(message)?;
        let observed = u32::try_from(body.len()).map_err(|_| FrameError::LengthOverflow)?;
        if observed > self.max_frame_bytes {
            return Err(FrameError::FrameTooLarge {
                observed,
                maximum: self.max_frame_bytes,
            });
        }
        writer.write_all(&observed.to_be_bytes())?;
        writer.write_all(&body)?;
        Ok(())
    }
}

impl Default for JsonFrameCodec {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }
}

/// Length-delimited protocol decoding or encoding failure.
#[derive(Debug, Error)]
pub enum FrameError {
    /// A zero allocation bound is invalid.
    #[error("maximum frame size must be greater than zero")]
    InvalidMaximum,
    /// An encoded or declared size cannot be represented safely.
    #[error("frame length cannot be represented on this platform")]
    LengthOverflow,
    /// A frame exceeds the configured allocation bound.
    #[error("frame length {observed} exceeds maximum {maximum} bytes")]
    FrameTooLarge {
        /// Encoded or declared body size.
        observed: u32,
        /// Configured body size bound.
        maximum: u32,
    },
    /// EOF occurred after a partial length prefix.
    #[error("truncated frame header: received {received} of 4 bytes")]
    TruncatedHeader {
        /// Header bytes received.
        received: usize,
    },
    /// EOF occurred inside a declared frame body.
    #[error("truncated frame body: declared {declared} bytes, received {received}")]
    TruncatedBody {
        /// Length encoded by the frame header.
        declared: u32,
        /// Body bytes received.
        received: usize,
    },
    /// Underlying stream I/O failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Message JSON is malformed or incompatible.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

fn read_available(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut received = 0;
    while received < buffer.len() {
        match reader.read(&mut buffer[received..]) {
            Ok(0) => break,
            Ok(count) => received += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(received)
}
