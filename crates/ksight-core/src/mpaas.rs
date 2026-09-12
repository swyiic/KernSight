//! Ant Financial mPaaS mobile-gateway RPC frame decoding.
//!
//! Some apps ride a binary mPaaS gateway protocol
//! on TLS: a short proprietary header followed by a JSON envelope
//! (`{"cltver",..,"body":{..},"requestId":..}`), responses optionally
//! gzip-deflated (`000133..` header then `1f 8b` or bare `{`). The frames are
//! not HTTP, so the HTTP reassembler drops them; this module lifts the JSON
//! envelope into `MirroredMessage`s so the Burp feed shows one structured
//! request/response per RPC call with tokenId, phone numbers and business
//! bodies visible, exactly like a MITM capture.

use crate::http_mirror::MirroredMessage;

/// Byte markers of the gateway envelope.
const REQUEST_MARKERS: [&[u8]; 3] = [b"\"cltver\"", b"\"appName\"", b"\"requestId\""];
const RESPONSE_MARKER: &[u8] = b"{\"status\"";
/// Length cap for envelope extraction.
const ENVELOPE_CAP: usize = 64 * 1024;

/// Whether a TLS plaintext buffer carries an mPaaS gateway frame.
#[must_use]
pub fn looks_like_mpaas(bytes: &[u8]) -> bool {
    if bytes.len() < 16 {
        return false;
    }
    if bytes.starts_with(&[0x00, 0x01, 0x33]) {
        return true;
    }
    REQUEST_MARKERS
        .iter()
        .any(|marker| bytes.windows(marker.len()).any(|w| w == *marker))
        || bytes.windows(9).any(|w| w == RESPONSE_MARKER)
}

/// Extract the first balanced JSON object starting at or after `from`.
fn extract_json_object(bytes: &[u8], from: usize) -> Option<(usize, Vec<u8>)> {
    let start = bytes[from..].iter().position(|byte| *byte == b'{')? + from;
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, &byte) in bytes[start..].iter().enumerate().take(ENVELOPE_CAP) {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some((start, bytes[start..start + index + 1].to_vec()));
                }
            }
            _ => {}
        }
    }
    None
}

/// Minimal string-field reader for the flat envelope (no JSON dependency).
fn json_string_field(json: &[u8], key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let needle = needle.as_bytes();
    let mut search = 0_usize;
    while let Some(pos) = bytes_find(json, needle, search) {
        let mut cursor = pos + needle.len();
        while cursor < json.len() && (json[cursor] == b' ' || json[cursor] == b':') {
            cursor += 1;
        }
        if json.get(cursor) == Some(&b'"') {
            let mut out = Vec::new();
            let mut index = cursor + 1;
            while index < json.len() {
                let byte = json[index];
                if byte == b'\\' && index + 1 < json.len() {
                    out.push(json[index + 1]);
                    index += 2;
                    continue;
                }
                if byte == b'"' {
                    return String::from_utf8(out).ok();
                }
                out.push(byte);
                index += 1;
            }
        } else if json
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'-')
        {
            let start = cursor;
            while cursor < json.len()
                && (json[cursor].is_ascii_digit() || matches!(json[cursor], b'-' | b'.'))
            {
                cursor += 1;
            }
            return std::str::from_utf8(&json[start..cursor])
                .ok()
                .map(ToOwned::to_owned);
        }
        search = pos + needle.len();
    }
    None
}

fn bytes_find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| position + from)
}

/// Inflate the buffer when it carries gzip/zlib payload anywhere near the head.
fn maybe_inflate(bytes: &[u8]) -> Vec<u8> {
    for magic_start in 0..bytes.len().min(24) {
        let window = &bytes[magic_start..];
        if window.starts_with(&[0x1f, 0x8b]) || window.starts_with(&[0x78, 0x9c]) {
            if let Some(inflated) = crate::inflate_inspect_buffer(window) {
                return inflated;
            }
        }
    }
    bytes.to_vec()
}

/// Decode one request envelope into a Burp-ready message. `host` is filled by
/// the caller from SNI when the envelope itself carries none.
#[must_use]
pub fn parse_mpaas_request(bytes: &[u8]) -> Option<MirroredMessage> {
    if !looks_like_mpaas(bytes) {
        return None;
    }
    let plain = maybe_inflate(bytes);
    let (offset, json) = extract_json_object(&plain, 0)?;
    // The envelope must look like a gateway request, not arbitrary JSON in a
    // document body.
    let envelope_request = REQUEST_MARKERS
        .iter()
        .any(|marker| bytes_find(&json, marker, 0).is_some());
    if !envelope_request {
        let _ = offset;
        return None;
    }
    let request_id = json_string_field(&json, "requestId");
    let app = json_string_field(&json, "appName").unwrap_or_default();
    let op = json_string_field(&json, "operationType")
        .or_else(|| json_string_field(&json, "operation-type"))
        .or_else(|| json_string_field(&json, "action"));
    let mut path = String::from("/mpaas/");
    path.push_str(&app);
    if let Some(op) = op.as_deref() {
        if !app.is_empty() {
            path.push('/');
        }
        path.push_str(op);
    }
    if let Some(request_id) = request_id.as_deref() {
        path.push_str("?requestId=");
        path.push_str(request_id);
    }
    Some(MirroredMessage {
        is_request: true,
        method: "POST".to_owned(),
        scheme: "https",
        host: String::new(),
        path,
        status: None,
        headers: vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("X-MPaas-Envelope".to_owned(), "cltver-gateway".to_owned()),
        ],
        body: json,
        websocket_upgrade: false,
        stream_id: None,
    })
}

/// Decode one response envelope (gateway header + optional gzip + status JSON).
#[must_use]
pub fn parse_mpaas_response(bytes: &[u8]) -> Option<MirroredMessage> {
    if !looks_like_mpaas(bytes) {
        return None;
    }
    let plain = maybe_inflate(bytes);
    let (_, json) = extract_json_object(&plain, 0)?;
    if bytes_find(&json, b"\"status\"", 0).is_none() {
        return None;
    }
    let status = json_string_field(&json, "status")
        .and_then(|value| value.parse::<u16>().ok())
        .map(|code| if code == 1 { 200 } else { 500 })
        .unwrap_or(200);
    Some(MirroredMessage {
        is_request: false,
        method: String::new(),
        scheme: "https",
        host: String::new(),
        path: String::new(),
        status: Some(status),
        headers: Vec::new(),
        body: json,
        websocket_upgrade: false,
        stream_id: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUEST_FRAME: &[u8] = b"\x20\x2f\x0e\x62\xc2\xa1\x23\x11\x9d\x77\x31{\"cltver\":\"10.7.1.0\",\"tokenId\":\"N_02B3C41765985EB8\",\"appName\":\"AYLCAPP\",\"body\":{\"position\":\"personal_center\"},\"version\":\"2.0\",\"sid\":\"130150002\",\"requestId\":\"ff0aa9b1d1255ebf\"}\x9a\x17";

    #[test]
    fn request_envelope_becomes_structured_post() {
        let message = parse_mpaas_request(REQUEST_FRAME).expect("request decoded");
        assert!(message.is_request);
        assert_eq!(message.method, "POST");
        assert!(message
            .path
            .starts_with("/mpaas/AYLCAPP?requestId=ff0aa9b1"));
        let body = String::from_utf8(message.body.clone()).expect("json");
        assert!(body.contains("N_02B3C41765985EB8"));
        assert!(body.contains("personal_center"));
    }

    #[test]
    fn plain_response_status_maps_to_http() {
        let frame = b"\x00\x01\x33\x00\x01\x00\x00\x01\x07{\"status\":1,\"errmsg\":\"SUCCESS\",\"requestid\":\"abc\",\"results\":{\"k\":1}}";
        let message = parse_mpaas_response(frame).expect("response decoded");
        assert!(!message.is_request);
        assert_eq!(message.status, Some(200));
        assert!(String::from_utf8(message.body).unwrap().contains("SUCCESS"));
    }

    #[test]
    fn failure_status_maps_to_500() {
        let frame = b"\x00\x01\x33\x00\x01{\"status\":0,\"errmsg\":\"SESSION_EXPIRED\"}";
        let message = parse_mpaas_response(frame).expect("decoded");
        assert_eq!(message.status, Some(500));
    }

    #[test]
    fn ordinary_http_is_not_mpaas() {
        assert!(!looks_like_mpaas(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(parse_mpaas_request(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }
}
