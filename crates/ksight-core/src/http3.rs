//! HTTP/3 STREAM frames + QPACK.
//!
//! Consumes already-copied STREAM plaintext. 1-RTT decrypt lives in
//! `quic_initial`. STREAM copy attaches only when `quic_stream_write` /
//! `xqc_stream_send` is DEFINED. Encoder instructions follow RFC 9204:
//! `1` name reference, `01` literal name, `001` capacity, `000` duplicate.
//! Request-stream `001` literal names are decoded. Post-base indexes (`0001`
//! / `0000`) stay unimplemented.

use std::collections::VecDeque;

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
    qpack_string_prefix(buf, 7)
}

/// String literal whose Huffman bit sits just above a `prefix`-bit length.
fn qpack_string_prefix(buf: &[u8], prefix: u8) -> Option<(String, usize)> {
    let first = *buf.first()?;
    let huffman = first & (1u8 << prefix) != 0;
    let (len, used) = hpack_int(buf, prefix)?;
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

/// QPACK decoder with a bounded dynamic table (RFC 9204 §3.2, §4.3).
///
/// Encoder instructions are disjoint by prefix, so `001` is capacity and
/// `01` is a literal name. Name-reference inserts use the leading `1` bit.
#[derive(Debug)]
pub struct QpackDecoder {
    table: VecDeque<(String, String)>,
    inserted: usize,
    dropped: usize,
    capacity: usize,
    size: usize,
}

/// Byte ceiling. A peer capacity above this is clamped; entries are still evicted
/// with the RFC size (name + value + 32).
const QPACK_MAX_CAPACITY: usize = 4096;

impl Default for QpackDecoder {
    fn default() -> Self {
        Self {
            table: VecDeque::new(),
            inserted: 0,
            dropped: 0,
            capacity: QPACK_MAX_CAPACITY,
            size: 0,
        }
    }
}

fn qpack_entry_size(name: &str, value: &str) -> usize {
    name.len().saturating_add(value.len()).saturating_add(32)
}

impl QpackDecoder {
    /// Ingest one encoder stream: capacity, name-reference, literal name, duplicate.
    pub fn ingest_encoder(&mut self, mut bytes: &[u8]) -> bool {
        while !bytes.is_empty() {
            let first = bytes[0];
            if first & 0x80 != 0 {
                let static_name = first & 0x40 != 0;
                let Some((index, used)) = hpack_int(bytes, 6) else {
                    return false;
                };
                bytes = &bytes[used..];
                let Some((value, value_len)) = qpack_string(bytes) else {
                    return false;
                };
                bytes = &bytes[value_len..];
                let name = if static_name {
                    let Some((name, _)) = qpack_static(index) else {
                        return false;
                    };
                    name.to_owned()
                } else if let Some((name, _)) = self.get_relative(index) {
                    name.clone()
                } else {
                    return false;
                };
                if !self.insert(name, value) {
                    return false;
                }
            } else if first & 0xc0 == 0x40 {
                let Some((name, nused)) = qpack_string_prefix(bytes, 5) else {
                    return false;
                };
                bytes = &bytes[nused..];
                let Some((value, vused)) = qpack_string(bytes) else {
                    return false;
                };
                bytes = &bytes[vused..];
                if !self.insert(name, value) {
                    return false;
                }
            } else if first & 0xe0 == 0x20 {
                let Some((capacity, used)) = hpack_int(bytes, 5) else {
                    return false;
                };
                bytes = &bytes[used..];
                self.set_capacity(capacity);
            } else if first & 0xe0 == 0 {
                let Some((index, used)) = hpack_int(bytes, 5) else {
                    return false;
                };
                bytes = &bytes[used..];
                let copied = self
                    .get_relative(index)
                    .map(|(name, value)| (name.clone(), value.clone()));
                let Some((name, value)) = copied else {
                    return false;
                };
                if !self.insert(name, value) {
                    return false;
                }
            }
        }
        true
    }

    fn set_capacity(&mut self, capacity: usize) {
        self.capacity = capacity.min(QPACK_MAX_CAPACITY);
        self.evict_overflow();
    }

    fn insert(&mut self, name: String, value: String) -> bool {
        let extra = qpack_entry_size(&name, &value);
        if extra > self.capacity || !self.evict_to_fit(extra) {
            return false;
        }
        self.size = self.size.saturating_add(extra);
        self.table.push_back((name, value));
        self.inserted = self.inserted.saturating_add(1);
        true
    }

    fn evict_to_fit(&mut self, extra: usize) -> bool {
        while self.size.saturating_add(extra) > self.capacity {
            if !self.evict_oldest() {
                return false;
            }
        }
        true
    }

    fn evict_overflow(&mut self) {
        while self.size > self.capacity {
            if !self.evict_oldest() {
                break;
            }
        }
    }

    fn evict_oldest(&mut self) -> bool {
        let Some((name, value)) = self.table.pop_front() else {
            return false;
        };
        self.size = self.size.saturating_sub(qpack_entry_size(&name, &value));
        self.dropped = self.dropped.saturating_add(1);
        true
    }

    /// Relative index 0 is the most recently inserted entry still tracked.
    fn get_relative(&self, relative: usize) -> Option<&(String, String)> {
        let absolute = self.inserted.checked_sub(1)?.checked_sub(relative)?;
        self.get_absolute(absolute)
    }

    fn get_absolute(&self, absolute: usize) -> Option<&(String, String)> {
        let pos = absolute.checked_sub(self.dropped)?;
        self.table.get(pos)
    }

    /// Decode a request/response field section. `RIC != 0` requires that many
    /// dynamic inserts already ingested.
    #[must_use]
    pub fn decode_section(&self, payload: &[u8]) -> Option<Vec<(String, String)>> {
        if payload.is_empty() {
            return None;
        }
        let (ric, used) = hpack_int(payload, 8)?;
        if ric > self.inserted {
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
                    let (name, value) = self.get_absolute(abs)?;
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
                    self.get_absolute(abs)?.0.clone()
                };
                offset += used;
                let (value, value_len) = qpack_string(&payload[offset..])?;
                headers.push((name, value));
                offset += value_len;
            } else if first & 0xe0 == 0x20 {
                // Literal Field Line With Literal Name: 001 N H namelen(3).
                let (name, nused) = qpack_string_prefix(&payload[offset..], 3)?;
                offset += nused;
                let (value, value_len) = qpack_string(&payload[offset..])?;
                headers.push((name, value));
                offset += value_len;
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
    let Some((kind, _payload, _)) = take_frame(bytes) else {
        return false;
    };
    matches!(kind, FRAME_DATA | FRAME_HEADERS)
}

/// Leading empty DATA / HEADERS frames (`0x00 0x00`, `0x01 0x00`).
///
/// A length-zero frame is well-formed and still not enough to choose HTTP/3.
#[must_use]
pub fn leading_empty_http3_prefix(bytes: &[u8]) -> usize {
    let mut offset = 0;
    while offset < bytes.len() {
        let Some((kind, payload, used)) = take_frame(&bytes[offset..]) else {
            break;
        };
        if !matches!(kind, FRAME_DATA | FRAME_HEADERS) || !payload.is_empty() {
            break;
        }
        offset += used;
    }
    offset
}

/// QPACK produced headers, or a DATA frame carried a non-empty body.
#[must_use]
pub fn http3_confirmed(bytes: &[u8]) -> bool {
    let mut offset = 0;
    while offset < bytes.len() {
        let Some((kind, payload, used)) = take_frame(&bytes[offset..]) else {
            break;
        };
        match kind {
            FRAME_HEADERS => {
                if decode_qpack_static(payload).is_some_and(|headers| !headers.is_empty()) {
                    return true;
                }
            }
            FRAME_DATA if !payload.is_empty() => return true,
            _ => {}
        }
        offset += used;
    }
    false
}

/// Why a confirmed HTTP/3 buffer did or did not become a message.
///
/// Counts only. The variant does not carry headers, paths, or body bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Http3ParseOutcome {
    /// `from_h2` produced a message. The `http3` tag is on that message.
    Yielded,
    /// Outbound DATA with no decoded headers. No `:method`, so no request.
    OutboundDataOnly,
    /// A complete non-empty HEADERS payload failed QPACK (dynamic or post-base).
    QpackRejected,
    /// Bytes remain after the last complete frame.
    TrailingPartial,
    /// Confirmed, but none of the cases above.
    Unclassified,
}

impl Http3ParseOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Yielded => "yielded",
            Self::OutboundDataOnly => "outbound_data_only",
            Self::QpackRejected => "qpack_rejected",
            Self::TrailingPartial => "trailing_partial",
            Self::Unclassified => "unclassified",
        }
    }
}

/// Messages plus the reason a buffer did not produce one.
#[derive(Debug)]
pub struct Http3Explanation {
    pub messages: Vec<MirroredMessage>,
    pub outcome: Http3ParseOutcome,
}

/// Parse complete HTTP/3 frames and record why the buffer stopped.
#[must_use]
pub fn explain_http3_stream(bytes: &[u8], outbound: bool) -> Http3Explanation {
    let mut offset = 0;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut body = Vec::new();
    let mut saw = false;
    let mut saw_body = false;
    let mut qpack_rejected = false;
    while offset < bytes.len() {
        let Some((kind, payload, used)) = take_frame(&bytes[offset..]) else {
            break;
        };
        offset += used;
        match kind {
            FRAME_HEADERS => {
                if payload.is_empty() {
                    continue;
                }
                if let Some(decoded) = decode_qpack_static(payload) {
                    headers = decoded;
                    saw = true;
                } else {
                    qpack_rejected = true;
                }
            }
            FRAME_DATA => {
                if !payload.is_empty() {
                    saw_body = true;
                }
                body.extend_from_slice(payload);
                saw = true;
            }
            _ => {}
        }
    }
    let trailing_partial = offset < bytes.len();
    let messages = if !saw || (headers.is_empty() && body.is_empty()) {
        Vec::new()
    } else {
        let mut messages: Vec<MirroredMessage> =
            MirroredMessage::from_h2(&headers, body, None, outbound, true)
                .into_iter()
                .collect();
        for message in &mut messages {
            message.evidence.transformations.push("http3");
        }
        messages
    };
    let outcome = if !messages.is_empty() {
        Http3ParseOutcome::Yielded
    } else if qpack_rejected {
        Http3ParseOutcome::QpackRejected
    } else if trailing_partial {
        Http3ParseOutcome::TrailingPartial
    } else if outbound && saw_body {
        Http3ParseOutcome::OutboundDataOnly
    } else {
        Http3ParseOutcome::Unclassified
    };
    Http3Explanation { messages, outcome }
}

/// Parse complete HTTP/3 frames from STREAM plaintext into HTTP messages.
#[must_use]
pub fn parse_http3_stream(bytes: &[u8], outbound: bool) -> Vec<MirroredMessage> {
    explain_http3_stream(bytes, outbound).messages
}

