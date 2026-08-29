//! Protocol debug-codec compatibility tests.

use ksight_protocol::{
    decode_debug_json, encode_debug_json, AcknowledgeBatches, GetStatus, Hello, Message,
    CURRENT_PROTOCOL,
};
use uuid::Uuid;

#[test]
fn debug_codec_round_trips_negotiation() {
    let message = Message::Hello(Hello {
        protocol: CURRENT_PROTOCOL,
        client_name: "test-client".into(),
        capabilities: Vec::new(),
    });
    let encoded = encode_debug_json(&message).expect("encode");
    let decoded = decode_debug_json(&encoded).expect("decode");
    assert_eq!(decoded, message);
}

#[test]
fn debug_codec_round_trips_batch_acknowledgement() {
    let message = Message::AcknowledgeBatches(AcknowledgeBatches {
        request_id: Uuid::new_v4(),
        session_id: Uuid::new_v4(),
        through_batch_sequence: 42,
    });
    let encoded = encode_debug_json(&message).expect("encode");
    let decoded = decode_debug_json(&encoded).expect("decode");
    assert_eq!(decoded, message);
}

#[test]
fn debug_codec_round_trips_get_status() {
    let message = Message::GetStatus(GetStatus {
        request_id: Uuid::new_v4(),
    });
    let encoded = encode_debug_json(&message).expect("encode");
    let decoded = decode_debug_json(&encoded).expect("decode");
    assert_eq!(decoded, message);
}
