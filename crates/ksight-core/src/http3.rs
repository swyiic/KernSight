//! HTTP/3 STREAM frames + QPACK.
//!
//! Consumes already-copied STREAM plaintext. 1-RTT decrypt lives in
//! `quic_initial`. STREAM copy attaches only when `quic_stream_write` /
//! `xqc_stream_send` is DEFINED. Dynamic table: `Insert With Name Reference`
//! (`01` prefix) plus request-stream indexed lines when RIC is satisfied.
//! Encoder `001` capacity/literal-name instructions remain a gap.

use crate::http2::decode_huffman;
use crate::http_mirror::MirroredMessage;

const FRAME_DATA: u64 = 0x00;
const FRAME_HEADERS: u64 = 0x01;
const MAX_FRAME: usize = 64 * 1024;

/// RFC 9204 Appendix A (subset used for static-only decode; unused slots empty).
const QPACK_STATIC: [(&str, &str); 98] = [
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/octet-stream"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

/// QUIC/HTTP3 variable-length integer.
fn quic_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in buf.iter().take(len).skip(1) {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, len))
}

fn hpack_int(buf: &[u8], prefix: u8) -> Option<(usize, usize)> {
    let mask = (1usize << prefix) - 1;
    let first = usize::from(*buf.first()?) & mask;
    if first < mask {
        return Some((first, 1));
    }
    let mut value = mask;
    let mut shift = 0;
    for (index, byte) in buf.iter().enumerate().skip(1) {
        value = value.saturating_add((usize::from(byte & 0x7f)) << shift);
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
        shift += 7;
        if shift > 28 {
            return None;
        }
    }
    None
}

fn qpack_string(buf: &[u8]) -> Option<(String, usize)> {
    let first = *buf.first()?;
    let huffman = first & 0x80 != 0;
    let (len, used) = hpack_int(buf, 7)?;
    let start = used;
    let end = start.saturating_add(len);
    let slice = buf.get(start..end)?;
    let bytes = if huffman {
        decode_huffman(slice)?
    } else {
        slice.to_vec()
    };
    Some((String::from_utf8_lossy(&bytes).into_owned(), end))
}

fn qpack_static(index: usize) -> Option<(&'static str, &'static str)> {
    QPACK_STATIC.get(index).copied()
}

/// QPACK decoder with a bounded dynamic table.
///
/// Encoder-stream inserts that start with the unambiguous `01` prefix
/// (`Insert With Name Reference`) are applied. `001` capacity / literal-name
/// inserts are left unimplemented (prefix collision) — those stay a gap.
#[derive(Debug, Default)]
pub struct QpackDecoder {
    table: Vec<(String, String)>,
}

const QPACK_DYNAMIC_CAP: usize = 32;

impl QpackDecoder {
    /// Ingest encoder-stream instructions (`Insert With Name Reference` only).
    pub fn ingest_encoder(&mut self, mut bytes: &[u8]) -> bool {
        while !bytes.is_empty() {
            let first = bytes[0];
            if first & 0xc0 == 0x40 {
                let static_name = first & 0x20 != 0;
                let Some((index, used)) = hpack_int(bytes, 5) else {
                    return false;
                };
                bytes = &bytes[used..];
                let Some((value, vused)) = qpack_string(bytes) else {
                    return false;
                };
                bytes = &bytes[vused..];
                let name = if static_name {
                    let Some((name, _)) = qpack_static(index) else {
                        return false;
                    };
                    name.to_owned()
                } else if index < self.table.len() {
                    self.table[index].0.clone()
                } else {
                    return false;
                };
                if self.table.len() >= QPACK_DYNAMIC_CAP {
                    self.table.remove(0);
                }
                self.table.push((name, value));
            } else {
                return false;
            }
        }
        true
    }

    /// Decode a request/response field section. `RIC != 0` requires that many
    /// dynamic inserts already ingested.
    #[must_use]
    pub fn decode_section(&self, payload: &[u8]) -> Option<Vec<(String, String)>> {
        if payload.is_empty() {
            return None;
        }
        let (ric, used) = hpack_int(payload, 8)?;
        if ric > self.table.len() {
            return None;
        }
        let rest = payload.get(used..)?;
        let s_bit = rest.first()? & 0x80 != 0;
        let (delta, used_base) = hpack_int(rest, 7)?;
        let base = if s_bit {
            ric.checked_sub(delta)?.checked_sub(1)?
        } else {
            ric.saturating_add(delta)
        };
        let mut offset = used + used_base;
        let mut headers = Vec::new();
        while offset < payload.len() {
            let first = *payload.get(offset)?;
            if first & 0x80 != 0 {
                let static_table = first & 0x40 != 0;
                let (index, used) = hpack_int(&payload[offset..], 6)?;
                if static_table {
                    let (name, value) = qpack_static(index)?;
                    headers.push((name.to_owned(), value.to_owned()));
                } else {
                    let abs = base.checked_sub(1)?.checked_sub(index)?;
                    let (name, value) = self.table.get(abs)?;
                    headers.push((name.clone(), value.clone()));
                }
                offset += used;
            } else if first & 0x40 != 0 {
                let static_table = first & 0x10 != 0;
                let (index, used) = hpack_int(&payload[offset..], 4)?;
                let name = if static_table {
                    qpack_static(index)?.0.to_owned()
                } else {
                    let abs = base.checked_sub(1)?.checked_sub(index)?;
                    self.table.get(abs)?.0.clone()
                };
                offset += used;
                let (value, vused) = qpack_string(&payload[offset..])?;
                headers.push((name, value));
                offset += vused;
            } else {
                return None;
            }
        }
        Some(headers)
    }
}

fn decode_qpack_static(payload: &[u8]) -> Option<Vec<(String, String)>> {
    QpackDecoder::default().decode_section(payload)
}

fn take_frame(buf: &[u8]) -> Option<(u64, &[u8], usize)> {
    let (kind, tlen) = quic_varint(buf)?;
    let (length, llen) = quic_varint(buf.get(tlen..)?)?;
    let length = usize::try_from(length).ok()?;
    if length > MAX_FRAME {
        return None;
    }
    let start = tlen + llen;
    let end = start.saturating_add(length);
    let payload = buf.get(start..end)?;
    Some((kind, payload, end))
}

/// True when `bytes` starts with a well-formed HTTP/3 DATA or HEADERS frame.
#[must_use]
pub fn looks_like_http3(bytes: &[u8]) -> bool {
    let Some((kind, payload, _)) = take_frame(bytes) else {
        return false;
    };
    match kind {
        FRAME_DATA => true,
        FRAME_HEADERS => true,
        _ => false,
    }
}

/// Parse complete HTTP/3 frames from STREAM plaintext into HTTP messages.
#[must_use]
pub fn parse_http3_stream(bytes: &[u8], outbound: bool) -> Vec<MirroredMessage> {
    let mut offset = 0;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut body = Vec::new();
    let mut saw = false;
    while offset < bytes.len() {
        let Some((kind, payload, used)) = take_frame(&bytes[offset..]) else {
            break;
        };
        offset += used;
        match kind {
            FRAME_HEADERS => {
                if let Some(decoded) = decode_qpack_static(payload) {
                    headers = decoded;
                    saw = true;
                }
            }
            FRAME_DATA => {
                body.extend_from_slice(payload);
                saw = true;
            }
            _ => {}
        }
    }
    if !saw || (headers.is_empty() && body.is_empty()) {
        return Vec::new();
    }
    MirroredMessage::from_h2(&headers, body, None, outbound, true)
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_get_slash() -> Vec<u8> {
        // HEADERS len=4, QPACK RIC=0 base=0, indexed GET (17), :path / (1)
        vec![0x01, 0x04, 0x00, 0x00, 0xd1, 0xc1]
    }

    #[test]
    fn looks_like_http3_rejects_json_and_http1() {
        assert!(!looks_like_http3(br#"{"mobile":"139"}"#));
        assert!(!looks_like_http3(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(looks_like_http3(&headers_get_slash()));
    }

    #[test]
    fn parses_static_get_and_data() {
        let mut raw = headers_get_slash();
        raw.extend_from_slice(&[0x00, 0x05]);
        raw.extend_from_slice(b"hello");
        let messages = parse_http3_stream(&raw, true);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].is_request);
        assert_eq!(messages[0].method, "GET");
        assert_eq!(messages[0].path, "/");
        assert_eq!(messages[0].body, b"hello");
    }

    #[test]
    fn parses_static_status_200() {
        // HEADERS: RIC=0 base=0 indexed :status 200 (25) = 0xD9
        let raw = vec![0x01, 0x03, 0x00, 0x00, 0xd9];
        let messages = parse_http3_stream(&raw, false);
        assert_eq!(messages.len(), 1);
        assert!(!messages[0].is_request);
        assert_eq!(messages[0].status, Some(200));
    }

    #[test]
    fn qpack_dynamic_insert_name_ref_then_indexed() {
        let mut decoder = QpackDecoder::default();
        // Insert With Name Reference, T=1 static :method (17), value PATCH.
        let mut enc = vec![0x71];
        enc.push(5);
        enc.extend_from_slice(b"PATCH");
        assert!(decoder.ingest_encoder(&enc));
        // Field section: RIC=1, S=0 DeltaBase=0, indexed T=0 relative 0.
        let section = vec![0x01, 0x00, 0x80];
        let headers = decoder.decode_section(&section).expect("dynamic");
        assert_eq!(headers, vec![(":method".to_owned(), "PATCH".to_owned())]);
        assert!(QpackDecoder::default().decode_section(&section).is_none());
    }

    #[test]
    fn qpack_dynamic_blocked_when_ric_exceeds_table() {
        let section = vec![0x02, 0x00, 0x80];
        assert!(QpackDecoder::default().decode_section(&section).is_none());
    }
}
