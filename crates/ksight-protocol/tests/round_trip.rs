//! Protocol debug-codec compatibility tests.

use ksight_protocol::{decode_debug_json, encode_debug_json, Hello, Message, CURRENT_PROTOCOL};

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
