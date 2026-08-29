//! Bounded stream-framing compatibility and malformed-input tests.

use std::io::Cursor;

use ksight_protocol::{
    FrameError, Hello, JsonFrameCodec, Message, CURRENT_PROTOCOL, DEFAULT_MAX_FRAME_BYTES,
};

#[test]
fn reads_back_to_back_frames_and_clean_eof() {
    let codec = JsonFrameCodec::default();
    let first = hello("first");
    let second = hello("second");
    let mut bytes = Vec::new();
    codec.write(&mut bytes, &first).unwrap();
    codec.write(&mut bytes, &second).unwrap();

    let mut reader = Cursor::new(bytes);
    assert_eq!(codec.read(&mut reader).unwrap(), Some(first));
    assert_eq!(codec.read(&mut reader).unwrap(), Some(second));
    assert_eq!(codec.read(&mut reader).unwrap(), None);
}

#[test]
fn rejects_oversized_outbound_frame_before_writing() {
    let codec = JsonFrameCodec::new(1).unwrap();
    let mut bytes = Vec::new();
    assert!(matches!(
        codec.write(&mut bytes, &hello("too-large")),
        Err(FrameError::FrameTooLarge { .. })
    ));
    assert!(bytes.is_empty());
}

#[test]
fn rejects_oversized_declared_frame_before_body_allocation() {
    let codec = JsonFrameCodec::new(16).unwrap();
    let mut reader = Cursor::new(17_u32.to_be_bytes());
    assert!(matches!(
        codec.read(&mut reader),
        Err(FrameError::FrameTooLarge {
            observed: 17,
            maximum: 16
        })
    ));
}

#[test]
fn distinguishes_truncated_header_and_body() {
    let codec = JsonFrameCodec::default();
    let mut short_header = Cursor::new(vec![0, 0, 0]);
    assert!(matches!(
        codec.read(&mut short_header),
        Err(FrameError::TruncatedHeader { received: 3 })
    ));

    let mut short_body = Cursor::new([4_u32.to_be_bytes().as_slice(), b"{}"].concat());
    assert!(matches!(
        codec.read(&mut short_body),
        Err(FrameError::TruncatedBody {
            declared: 4,
            received: 2
        })
    ));
}

#[test]
fn default_bound_is_explicit_and_nonzero() {
    assert_eq!(
        JsonFrameCodec::default().max_frame_bytes(),
        DEFAULT_MAX_FRAME_BYTES
    );
    assert!(matches!(
        JsonFrameCodec::new(0),
        Err(FrameError::InvalidMaximum)
    ));
}

fn hello(client_name: &str) -> Message {
    Message::Hello(Hello {
        protocol: CURRENT_PROTOCOL,
        client_name: client_name.to_owned(),
        capabilities: Vec::new(),
    })
}
