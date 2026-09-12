//! HTTP/2 frame walk and HPACK decode of already-copied TLS/JNI buffers.
//!
//! This is report-side analysis of Inspect/dump bytes, not MITM and not QUIC.

use std::collections::HashMap;

use crate::http_plain::ParsedHttpPlain;

const STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// RFC 7541 Appendix B Huffman encode table: (code, bit length) for bytes 0..=255.
#[allow(clippy::unreadable_literal)]
const HUFFMAN: [(u32, u8); 256] = [
    (0x1ff8, 13),
    (0x7fffd8, 23),
    (0xfffffe2, 28),
    (0xfffffe3, 28),
    (0xfffffe4, 28),
    (0xfffffe5, 28),
    (0xfffffe6, 28),
    (0xfffffe7, 28),
    (0xfffffe8, 28),
    (0xffffea, 24),
    (0x3ffffffc, 30),
    (0xfffffe9, 28),
    (0xfffffea, 28),
    (0x3ffffffd, 30),
    (0xfffffeb, 28),
    (0xfffffec, 28),
    (0xfffffed, 28),
    (0xfffffee, 28),
    (0xfffffef, 28),
    (0xffffff0, 28),
    (0xffffff1, 28),
    (0xffffff2, 28),
    (0x3ffffffe, 30),
    (0xffffff3, 28),
    (0xffffff4, 28),
    (0xffffff5, 28),
    (0xffffff6, 28),
    (0xffffff7, 28),
    (0xffffff8, 28),
    (0xffffff9, 28),
    (0xffffffa, 28),
    (0xffffffb, 28),
    (0x14, 6),
    (0x3f8, 10),
    (0x3f9, 10),
    (0xffa, 12),
    (0x1ff9, 13),
    (0x15, 6),
    (0xf8, 8),
    (0x7fa, 11),
    (0x3fa, 10),
    (0x3fb, 10),
    (0xf9, 8),
    (0x7fb, 11),
    (0xfa, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6),
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6),
    (0x1a, 6),
    (0x1b, 6),
    (0x1c, 6),
    (0x1d, 6),
    (0x1e, 6),
    (0x1f, 6),
    (0x5c, 7),
    (0xfb, 8),
    (0x7ffc, 15),
    (0x20, 6),
    (0xffb, 12),
    (0x3fc, 10),
    (0x1ffa, 13),
    (0x21, 6),
    (0x5d, 7),
    (0x5e, 7),
    (0x5f, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7),
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7),
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6a, 7),
    (0x6b, 7),
    (0x6c, 7),
    (0x6d, 7),
    (0x6e, 7),
    (0x6f, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7),
    (0xfc, 8),
    (0x73, 7),
    (0xfd, 8),
    (0x1ffb, 13),
    (0x7fff0, 19),
    (0x1ffc, 13),
    (0x3ffc, 14),
    (0x22, 6),
    (0x7ffd, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5),
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6),
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7),
    (0x28, 6),
    (0x29, 6),
    (0x2a, 6),
    (0x7, 5),
    (0x2b, 6),
    (0x76, 7),
    (0x2c, 6),
    (0x8, 5),
    (0x9, 5),
    (0x2d, 6),
    (0x77, 7),
    (0x78, 7),
    (0x79, 7),
    (0x7a, 7),
    (0x7b, 7),
    (0x7ffe, 15),
    (0x7fc, 11),
    (0x3ffd, 14),
    (0x1ffd, 13),
    (0xffffffc, 28),
    (0xfffe6, 20),
    (0x3fffd2, 22),
    (0xfffe7, 20),
    (0xfffe8, 20),
    (0x3fffd3, 22),
    (0x3fffd4, 22),
    (0x3fffd5, 22),
    (0x7fffd9, 23),
    (0x3fffd6, 22),
    (0x7fffda, 23),
    (0x7fffdb, 23),
    (0x7fffdc, 23),
    (0x7fffdd, 23),
    (0x7fffde, 23),
    (0xffffeb, 24),
    (0x7fffdf, 23),
    (0xffffec, 24),
    (0xffffed, 24),
    (0x3fffd7, 22),
    (0x7fffe0, 23),
    (0xffffee, 24),
    (0x7fffe1, 23),
    (0x7fffe2, 23),
    (0x7fffe3, 23),
    (0x7fffe4, 23),
    (0x1fffdc, 21),
    (0x3fffd8, 22),
    (0x7fffe5, 23),
    (0x3fffd9, 22),
    (0x7fffe6, 23),
    (0x7fffe7, 23),
    (0xffffef, 24),
    (0x3fffda, 22),
    (0x1fffdd, 21),
    (0xfffe9, 20),
    (0x3fffdb, 22),
    (0x3fffdc, 22),
    (0x7fffe8, 23),
    (0x7fffe9, 23),
    (0x1fffde, 21),
    (0x7fffea, 23),
    (0x3fffdd, 22),
    (0x3fffde, 22),
    (0xfffff0, 24),
    (0x1fffdf, 21),
    (0x3fffdf, 22),
    (0x7fffeb, 23),
    (0x7fffec, 23),
    (0x1fffe0, 21),
    (0x1fffe1, 21),
    (0x3fffe0, 22),
    (0x1fffe2, 21),
    (0x7fffed, 23),
    (0x3fffe1, 22),
    (0x7fffee, 23),
    (0x7fffef, 23),
    (0xfffea, 20),
    (0x3fffe2, 22),
    (0x3fffe3, 22),
    (0x3fffe4, 22),
    (0x7ffff0, 23),
    (0x3fffe5, 22),
    (0x3fffe6, 22),
    (0x7ffff1, 23),
    (0x3ffffe0, 26),
    (0x3ffffe1, 26),
    (0xfffeb, 20),
    (0x7fff1, 19),
    (0x3fffe7, 22),
    (0x7ffff2, 23),
    (0x3fffe8, 22),
    (0x1ffffec, 25),
    (0x3ffffe2, 26),
    (0x3ffffe3, 26),
    (0x3ffffe4, 26),
    (0x7ffffde, 27),
    (0x7ffffdf, 27),
    (0x3ffffe5, 26),
    (0xfffff1, 24),
    (0x1ffffed, 25),
    (0x7fff2, 19),
    (0x1fffe3, 21),
    (0x3ffffe6, 26),
    (0x7ffffe0, 27),
    (0x7ffffe1, 27),
    (0x3ffffe7, 26),
    (0x7ffffe2, 27),
    (0xfffff2, 24),
    (0x1fffe4, 21),
    (0x1fffe5, 21),
    (0x3ffffe8, 26),
    (0x3ffffe9, 26),
    (0xffffffd, 28),
    (0x7ffffe3, 27),
    (0x7ffffe4, 27),
    (0x7ffffe5, 27),
    (0xfffec, 20),
    (0xfffff3, 24),
    (0xfffed, 20),
    (0x1fffe6, 21),
    (0x3fffe9, 22),
    (0x1fffe7, 21),
    (0x1fffe8, 21),
    (0x7ffff3, 23),
    (0x3fffea, 22),
    (0x3fffeb, 22),
    (0x1ffffee, 25),
    (0x1ffffef, 25),
    (0xfffff4, 24),
    (0xfffff5, 24),
    (0x3ffffea, 26),
    (0x7ffff4, 23),
    (0x3ffffeb, 26),
    (0x7ffffe6, 27),
    (0x3ffffec, 26),
    (0x3ffffed, 26),
    (0x7ffffe7, 27),
    (0x7ffffe8, 27),
    (0x7ffffe9, 27),
    (0x7ffffea, 27),
    (0x7ffffeb, 27),
    (0xffffffe, 28),
    (0x7ffffec, 27),
    (0x7ffffed, 27),
    (0x7ffffee, 27),
    (0x7ffffef, 27),
    (0x7fffff0, 27),
    (0x3ffffee, 26),
];

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const ASSEMBLER_CAP: usize = 1024 * 1024;
const STREAM_BODY_CAP: usize = 1024 * 1024;

/// Walk HTTP/2 frames and emit request/response rows plus URLs from DATA.
#[must_use]
pub fn parse_http2(bytes: &[u8]) -> Vec<ParsedHttpPlain> {
    let mut assembler = Http2Assembler::default();
    assembler.push(bytes)
}

/// Bytes to scan when the first TLS/JNI copy is mid-frame (Alipay warm attach).
const HTTP2_RESYNC_SCAN: usize = 256;

/// Offset of the first HTTP/2 preface or plausible frame header in `bytes`.
///
/// Mid-stream attach often misses the connection preface; the first readable
/// copy may start a few bytes into a prior frame. Prefer offset 0 when valid,
/// otherwise require a strong frame type (DATA/HEADERS/SETTINGS/CONTINUATION)
/// and either a following frame header or a complete HEADERS/SETTINGS frame.
#[must_use]
pub fn http2_sync_offset(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    if bytes.starts_with(PREFACE) || PREFACE.starts_with(bytes) {
        return Some(0);
    }
    if bytes.len() < 9 {
        return None;
    }
    let last = bytes.len().saturating_sub(9).min(HTTP2_RESYNC_SCAN);
    for i in 0..=last {
        let Some((frame_end, frame_ty, _, _, _)) = frame_header_ok(bytes, i, 16 * 1024) else {
            continue;
        };
        if i == 0 {
            return Some(0);
        }
        // Mid-buffer: only lock onto common request/control frames to limit
        // false positives in binary app payloads.
        if !matches!(frame_ty, 0x0 | 0x1 | 0x4 | 0x9) {
            continue;
        }
        if frame_end + 9 <= bytes.len() && frame_header_ok(bytes, frame_end, 16 * 1024).is_some() {
            return Some(i);
        }
        if matches!(frame_ty, 0x1 | 0x4) && frame_end <= bytes.len() && frame_end > i + 9 {
            return Some(i);
        }
        if matches!(frame_ty, 0x1 | 0x4) && frame_end > bytes.len() {
            // Incomplete but typed HEADERS/SETTINGS — still sync so the
            // assembler can wait for the rest instead of staying Unknown.
            return Some(i);
        }
    }
    None
}

/// True when a buffer starts like an HTTP/2 preface or a well-formed frame header.
#[must_use]
pub fn looks_like_http2(bytes: &[u8]) -> bool {
    http2_sync_offset(bytes).is_some()
}

/// One completed HTTP/2 request or response after HEADERS+DATA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct H2Message {
    /// Decoded HPACK name/value pairs, including pseudo-headers.
    pub headers: Vec<(String, String)>,
    /// DATA payload, inflated when the bytes were gzip/zlib.
    pub body: Vec<u8>,
    /// HTTP/2 stream identifier.
    pub stream_id: u32,
}

#[derive(Debug, Default)]
struct PartialH2 {
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Reassemble HTTP/2 frames and HPACK state across TLS/JNI copy fragments.
#[derive(Debug)]
pub(crate) struct Http2Assembler {
    buf: Vec<u8>,
    decoder: HpackDecoder,
    pending: Vec<u8>,
    in_headers: bool,
    aligned: bool,
    headers_stream: u32,
    /// END_STREAM seen on the initial HEADERS frame of the current block.
    /// CONTINUATION must honor this when END_HEADERS finally arrives.
    headers_end_stream: bool,
    /// SETTINGS_MAX_FRAME_SIZE (default 16384).
    max_frame_size: usize,
    streams: HashMap<u32, PartialH2>,
    h2_messages: Vec<H2Message>,
    /// Last :authority/Host seen on this TLS connection. Later multiplexed
    /// streams often omit it (HPACK index / inspect attached mid-session).
    last_authority: Option<String>,
}

impl Default for Http2Assembler {
    fn default() -> Self {
        Self {
            buf: Vec::new(),
            decoder: HpackDecoder::default(),
            pending: Vec::new(),
            in_headers: false,
            aligned: false,
            headers_stream: 0,
            headers_end_stream: false,
            // Inspect often attaches after SETTINGS. RFC initial 16KiB
            // rejected CCB/Alipay 64KiB DATA (cycle-002655 buffered=64332
            // orig=0). Cap at inspect copy size; SETTINGS may still raise.
            max_frame_size: 256 * 1024,
            streams: HashMap::new(),
            h2_messages: Vec::new(),
            last_authority: None,
        }
    }
}

impl Http2Assembler {
    pub(crate) fn buffered_bytes(&self) -> usize {
        self.buf
            .len()
            .saturating_add(self.pending.len())
            .saturating_add(
                self.streams
                    .values()
                    .map(|stream| {
                        stream.body.len().saturating_add(
                            stream
                                .headers
                                .iter()
                                .map(|(name, value)| name.len().saturating_add(value.len()))
                                .sum::<usize>(),
                        )
                    })
                    .sum::<usize>(),
            )
    }

    pub(crate) fn ends_with(&self, bytes: &[u8]) -> bool {
        !bytes.is_empty() && self.buf.ends_with(bytes)
    }

    /// Unparsed frame bytes + pending HPACK after seal_finish. Used so
    /// incomplete large DATA still becomes an orphan response.
    pub(crate) fn take_remainder(&mut self) -> Vec<u8> {
        let mut out = std::mem::take(&mut self.buf);
        out.extend(std::mem::take(&mut self.pending));
        for (_, partial) in self.streams.drain() {
            out.extend(partial.body);
        }
        out
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) -> Vec<ParsedHttpPlain> {
        if bytes.is_empty() {
            return Vec::new();
        }
        self.buf.extend_from_slice(bytes);
        if self.buf.len() > ASSEMBLER_CAP {
            let drop = self.buf.len().saturating_sub(ASSEMBLER_CAP);
            self.buf.drain(..drop);
            self.aligned = false;
            self.in_headers = false;
            self.headers_end_stream = false;
            self.pending.clear();
            self.decoder = HpackDecoder::default();
        }
        self.drain()
    }

    /// Completed HTTP/2 messages with full header values, for Burp reconstruction.
    pub(crate) fn take_h2_messages(&mut self) -> Vec<H2Message> {
        std::mem::take(&mut self.h2_messages)
    }

    fn finish_stream(&mut self, stream: u32) {
        let Some(mut partial) = self.streams.remove(&stream) else {
            return;
        };
        if partial.headers.is_empty() {
            if partial.body.is_empty() {
                return;
            }
            // DATA-only copy (inspect attached after HEADERS). Salvage as a
            // response so SSL_read plaintext still pairs instead of orig=0.
            self.h2_messages.push(H2Message {
                headers: vec![(":status".to_owned(), "200".to_owned())],
                body: crate::inflate_inspect_buffer(&partial.body).unwrap_or(partial.body),
                stream_id: stream,
            });
            return;
        }
        let has_authority = partial.headers.iter().any(|(name, value)| {
            (name.eq_ignore_ascii_case(":authority") || name.eq_ignore_ascii_case("host"))
                && !value.is_empty()
        });
        if let Some((_, value)) = partial.headers.iter().find(|(name, value)| {
            (name.eq_ignore_ascii_case(":authority") || name.eq_ignore_ascii_case("host"))
                && !value.is_empty()
        }) {
            if let Some(host) = crate::http_plain::parse_host_token(value) {
                self.last_authority = Some(host);
            }
        } else if !has_authority {
            if let Some(authority) = self.last_authority.clone() {
                partial.headers.push((":authority".to_owned(), authority));
            }
        }
        let grpc = partial.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type") && value.to_ascii_lowercase().contains("grpc")
        });
        let body = if grpc {
            unwrap_grpc_length_prefixed(&partial.body)
        } else {
            crate::inflate_inspect_buffer(&partial.body).unwrap_or(partial.body)
        };
        self.h2_messages.push(H2Message {
            headers: partial.headers,
            body,
            stream_id: stream,
        });
    }

    /// Promote open streams that already decoded HEADERS but never saw
    /// END_STREAM (common when the final DATA copy is missed / idle soft-flush).
    pub(crate) fn soft_finish_open_streams(&mut self) {
        let open: Vec<u32> = self
            .streams
            .iter()
            .filter(|(_, partial)| !partial.headers.is_empty())
            .map(|(id, _)| *id)
            .collect();
        for stream in open {
            self.finish_stream(stream);
        }
    }

    /// Session-end: also emit DATA-only streams that never saw HEADERS.
    pub(crate) fn seal_finish_open_streams(&mut self) {
        self.soft_finish_open_streams();
        let data_only: Vec<u32> = self
            .streams
            .iter()
            .filter(|(_, partial)| !partial.body.is_empty())
            .map(|(id, _)| *id)
            .collect();
        for stream in data_only {
            self.finish_stream(stream);
        }
    }

    fn drain(&mut self) -> Vec<ParsedHttpPlain> {
        let mut out = Vec::new();
        let mut index = 0_usize;
        if !self.aligned && self.buf.starts_with(PREFACE) {
            index = PREFACE.len();
            self.aligned = true;
            out.push(preface_row());
        } else if !self.aligned && !self.buf.is_empty() && PREFACE.starts_with(self.buf.as_slice())
        {
            return out;
        }
        while index + 9 <= self.buf.len() && out.len() < 16 {
            let Some((frame_end, frame_ty, flags, header_end, stream)) =
                frame_header_ok(&self.buf, index, self.max_frame_size)
            else {
                if self.aligned {
                    self.aligned = false;
                    self.in_headers = false;
                    self.headers_end_stream = false;
                    self.pending.clear();
                }
                index = index.saturating_add(1);
                continue;
            };
            if frame_end > self.buf.len() {
                break;
            }
            self.aligned = true;
            let mut payload = &self.buf[header_end..frame_end];
            match frame_ty {
                0x1 | 0x9 => {
                    if frame_ty == 0x1 {
                        self.pending.clear();
                        self.in_headers = true;
                        self.headers_stream = stream;
                        // Remember END_STREAM from the initial HEADERS; CONTINUATION
                        // carries END_HEADERS but must not clear this bit.
                        self.headers_end_stream = flags & 0x01 != 0;
                        if flags & 0x08 != 0 {
                            let pad = usize::from(payload.first().copied().unwrap_or(0));
                            payload = payload
                                .get(1..payload.len().saturating_sub(pad))
                                .unwrap_or(&[]);
                        }
                        if flags & 0x20 != 0 {
                            payload = payload.get(5..).unwrap_or(&[]);
                        }
                    } else if !self.in_headers {
                        index = frame_end;
                        continue;
                    }
                    self.pending.extend_from_slice(payload);
                    if flags & 0x04 != 0 {
                        let headers = self.decoder.decode_block(&self.pending);
                        self.pending.clear();
                        self.in_headers = false;
                        let end_stream = self.headers_end_stream || (flags & 0x01 != 0);
                        self.headers_end_stream = false;
                        if let Some(parsed) = headers_to_parsed(&headers) {
                            out.push(parsed);
                        }
                        let entry = self.streams.entry(self.headers_stream).or_default();
                        if entry.headers.is_empty() {
                            entry.headers.clone_from(&headers);
                        } else {
                            // A later HEADERS block is a trailer. Preserve the
                            // request/response pseudo-headers needed to identify
                            // the message and append only normal trailer fields.
                            entry.headers.extend(
                                headers
                                    .iter()
                                    .filter(|(name, _)| !name.starts_with(':'))
                                    .cloned(),
                            );
                        }
                        if end_stream {
                            self.finish_stream(self.headers_stream);
                        }
                    }
                }
                0x4 => {
                    // SETTINGS — honor SETTINGS_MAX_FRAME_SIZE (0x5).
                    apply_settings(payload, flags, &mut self.max_frame_size);
                }
                0x0 => {
                    out.extend(data_to_parsed(payload, flags));
                    let mut body = payload;
                    if flags & 0x08 != 0 {
                        let pad = usize::from(body.first().copied().unwrap_or(0));
                        body = body.get(1..body.len().saturating_sub(pad)).unwrap_or(&[]);
                    }
                    let entry = self.streams.entry(stream).or_default();
                    let remaining = STREAM_BODY_CAP.saturating_sub(entry.body.len());
                    entry
                        .body
                        .extend_from_slice(&body[..body.len().min(remaining)]);
                    if flags & 0x01 != 0 {
                        self.finish_stream(stream);
                    }
                }
                0x3 => {
                    // RST_STREAM makes the partial message unusable and bounds
                    // state retained for abruptly closed app connections.
                    self.streams.remove(&stream);
                }
                0x7 => {
                    // GOAWAY ends the connection-level stream namespace.
                    self.streams.clear();
                }
                _ => {}
            }
            index = frame_end;
        }
        if index > 0 {
            self.buf.drain(..index);
        }
        out
    }
}

fn preface_row() -> ParsedHttpPlain {
    ParsedHttpPlain {
        kind: "http2_preface",
        method: "PRI".to_owned(),
        host: None,
        scheme: None,
        path: String::new(),
        status: None,
        query_keys: Vec::new(),
        header_names: Vec::new(),
        redacted_headers: Vec::new(),
        body_keys: Vec::new(),
        redacted_body_keys: Vec::new(),
        content_type: None,
        third_party: false,
    }
}

fn apply_settings(payload: &[u8], flags: u8, max_frame_size: &mut usize) {
    if flags & 0x01 != 0 {
        // ACK — no payload.
        return;
    }
    let mut index = 0_usize;
    while index + 6 <= payload.len() {
        let id = u16::from_be_bytes([payload[index], payload[index + 1]]);
        let value = u32::from_be_bytes([
            payload[index + 2],
            payload[index + 3],
            payload[index + 4],
            payload[index + 5],
        ]);
        if id == 0x5 {
            // SETTINGS_MAX_FRAME_SIZE: initial 16384, max 2^24-1.
            let size = value as usize;
            if (16 * 1024..=16 * 1024 * 1024 - 1).contains(&size) {
                *max_frame_size = size;
            }
        }
        index += 6;
    }
}

fn frame_header_ok(
    bytes: &[u8],
    index: usize,
    max_frame_size: usize,
) -> Option<(usize, u8, u8, usize, u32)> {
    let len = u32::from_be_bytes([0, bytes[index], bytes[index + 1], bytes[index + 2]]) as usize;
    let frame_ty = bytes[index + 3];
    let flags = bytes[index + 4];
    let stream = u32::from_be_bytes([
        bytes[index + 5] & 0x7f,
        bytes[index + 6],
        bytes[index + 7],
        bytes[index + 8],
    ]);
    let known = frame_ty <= 0x9;
    let stream_ok = match frame_ty {
        0x0 | 0x1 | 0x9 => stream != 0,
        0x4 | 0x6 | 0x7 => stream == 0,
        0x2 | 0x3 | 0x5 | 0x8 => true,
        _ => false,
    };
    let max_frame = max_frame_size.max(16 * 1024).min(16 * 1024 * 1024);
    if !known || !stream_ok || len > max_frame {
        return None;
    }
    let header_end = index.saturating_add(9);
    Some((
        header_end.saturating_add(len),
        frame_ty,
        flags,
        header_end,
        stream,
    ))
}

fn data_to_parsed(payload: &[u8], flags: u8) -> Vec<ParsedHttpPlain> {
    let mut body = payload;
    if flags & 0x08 != 0 {
        let pad = usize::from(body.first().copied().unwrap_or(0));
        let Some(stripped) = body.get(1..body.len().saturating_sub(pad)) else {
            return Vec::new();
        };
        body = stripped;
    }
    let inflated = crate::inflate_inspect_buffer(body).unwrap_or_else(|| body.to_vec());
    let mut out = Vec::new();
    if let Some(parsed) =
        crate::parse_http_plain_bytes(&inflated, "text").filter(|row| row.kind != "http2_preface")
    {
        out.push(parsed);
    }
    for parsed in crate::http_plain::embedded_http_urls(&inflated) {
        if !out.iter().any(|seen| {
            seen.host == parsed.host && seen.path == parsed.path && seen.kind == parsed.kind
        }) {
            out.push(parsed);
        }
        if out.len() >= 16 {
            break;
        }
    }
    out
}

fn headers_to_parsed(headers: &[(String, String)]) -> Option<ParsedHttpPlain> {
    if headers.is_empty() {
        return None;
    }
    let mut method = String::new();
    let mut scheme = None;
    let mut authority = None;
    let mut path = String::new();
    let mut status = None;
    let mut header_names = Vec::new();
    let mut redacted = Vec::new();
    let mut content_type = None;
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            ":method" => method.clone_from(value),
            ":scheme" => {
                scheme = (value == "http" || value == "https").then_some(if value == "http" {
                    "http"
                } else {
                    "https"
                });
            }
            ":authority" | "host" => authority = crate::http_plain::parse_host_token(value),
            ":path" => path = value.chars().take(512).collect(),
            ":status" => status = value.parse().ok(),
            "content-type" => content_type = Some(value.chars().take(96).collect()),
            _ => {}
        }
        if header_names.len() < 24 && !lower.starts_with(':') {
            header_names.push(name.clone());
        }
        if crate::http_plain::header_is_sensitive(&lower) {
            redacted.push(format!("{name}=[REDACTED]"));
        }
    }
    let (query_path, query_keys) = split_query(&path);
    let host = authority;
    let third_party = host.as_deref().is_some_and(crate::is_third_party_host);
    let grpc = content_type
        .as_deref()
        .is_some_and(|value: &str| value.to_ascii_lowercase().contains("grpc"));
    let kind = if status.is_some() {
        "http2_response"
    } else if (matches!(
        method.as_str(),
        "GET" | "POST" | "HEAD" | "PUT" | "DELETE" | "PATCH" | "OPTIONS"
    ) && (host.is_some() || grpc))
        || (grpc && !path.is_empty())
    {
        "http2_request"
    } else {
        return None;
    };
    Some(ParsedHttpPlain {
        kind,
        method: if method.is_empty() {
            "HTTP".to_owned()
        } else {
            method
        },
        host,
        scheme,
        path: if kind == "http2_response" {
            String::new()
        } else {
            query_path
        },
        status,
        query_keys,
        header_names,
        redacted_headers: redacted,
        body_keys: Vec::new(),
        redacted_body_keys: Vec::new(),
        content_type,
        third_party,
    })
}

/// Strip gRPC length-prefixed DATA frames (`compressed` byte + big-endian length).
///
/// Uncompressed messages are concatenated. Compressed messages are inflated
/// when the payload looks like gzip/zlib. Incomplete or non-gRPC buffers are
/// returned unchanged so Burp still sees the copied bytes.
#[must_use]
pub fn unwrap_grpc_length_prefixed(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() < 5 {
        return bytes.to_vec();
    }
    let mut offset = 0_usize;
    let mut out = Vec::new();
    let mut saw_frame = false;
    while offset + 5 <= bytes.len() {
        let compressed = bytes[offset];
        if compressed > 1 {
            return bytes.to_vec();
        }
        let len = u32::from_be_bytes([
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
        ]) as usize;
        offset += 5;
        if len > STREAM_BODY_CAP || offset.saturating_add(len) > bytes.len() {
            return bytes.to_vec();
        }
        let payload = &bytes[offset..offset + len];
        offset += len;
        saw_frame = true;
        if compressed == 1 {
            match crate::inflate_inspect_buffer(payload) {
                Some(plain) => out.extend_from_slice(&plain),
                None => out.extend_from_slice(payload),
            }
        } else {
            out.extend_from_slice(payload);
        }
    }
    if saw_frame && offset == bytes.len() {
        out
    } else {
        bytes.to_vec()
    }
}

fn split_query(target: &str) -> (String, Vec<String>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut keys = Vec::new();
    for pair in query.split('&') {
        if keys.len() >= 24 {
            break;
        }
        let key = pair.split('=').next().unwrap_or("").trim();
        if key.is_empty() || keys.iter().any(|seen| seen == key) {
            continue;
        }
        keys.push(key.chars().take(64).collect());
    }
    (path.chars().take(256).collect(), keys)
}

#[derive(Debug)]
struct HpackDecoder {
    dynamic: Vec<(String, String)>,
    max_size: usize,
    size: usize,
}

impl Default for HpackDecoder {
    fn default() -> Self {
        Self {
            dynamic: Vec::new(),
            max_size: 4096,
            size: 0,
        }
    }
}

impl HpackDecoder {
    fn decode_block(&mut self, block: &[u8]) -> Vec<(String, String)> {
        let mut headers = Vec::new();
        let mut cur = 0_usize;
        while cur < block.len() && headers.len() < 32 {
            let first = block[cur];
            if first & 0x80 != 0 {
                let Some((index, used)) = decode_int(block, cur, 7) else {
                    break;
                };
                cur = cur.saturating_add(used);
                if let Some(header) = self.lookup(index) {
                    headers.push(header);
                }
                continue;
            }
            if first & 0xe0 == 0x20 {
                let Some((size, used)) = decode_int(block, cur, 5) else {
                    break;
                };
                cur = cur.saturating_add(used);
                self.max_size = size.min(16 * 1024);
                self.evict();
                continue;
            }
            let (prefix, incremental) = if first & 0xc0 == 0x40 {
                (6_u8, true)
            } else {
                (4_u8, false)
            };
            let Some((index, used)) = decode_int(block, cur, prefix) else {
                break;
            };
            cur = cur.saturating_add(used);
            let name = if index == 0 {
                let Some((n, name_len)) = decode_string(block, cur) else {
                    break;
                };
                cur = cur.saturating_add(name_len);
                n
            } else {
                self.lookup(index).map(|(n, _)| n).unwrap_or_default()
            };
            let Some((value, value_len)) = decode_string(block, cur) else {
                break;
            };
            cur = cur.saturating_add(value_len);
            if name.is_empty() {
                continue;
            }
            if incremental {
                self.insert(name.clone(), value.clone());
            }
            headers.push((name, value));
        }
        headers
    }

    fn lookup(&self, index: usize) -> Option<(String, String)> {
        if index == 0 {
            return None;
        }
        if index <= STATIC_TABLE.len() {
            let (n, v) = STATIC_TABLE[index - 1];
            return Some((n.to_owned(), v.to_owned()));
        }
        let dyn_index = index - STATIC_TABLE.len() - 1;
        self.dynamic.get(dyn_index).cloned()
    }

    fn insert(&mut self, name: String, value: String) {
        let entry = name.len().saturating_add(value.len()).saturating_add(32);
        self.dynamic.insert(0, (name, value));
        self.size = self.size.saturating_add(entry);
        self.evict();
    }

    fn evict(&mut self) {
        while self.size > self.max_size && !self.dynamic.is_empty() {
            if let Some((name, value)) = self.dynamic.pop() {
                self.size = self
                    .size
                    .saturating_sub(name.len().saturating_add(value.len()).saturating_add(32));
            }
        }
    }
}

fn decode_int(buf: &[u8], offset: usize, prefix_bits: u8) -> Option<(usize, usize)> {
    let first = *buf.get(offset)?;
    let mask = if prefix_bits >= 8 {
        0xff
    } else {
        (1_u8 << prefix_bits) - 1
    };
    let mut value = usize::from(first & mask);
    if value < usize::from(mask) {
        return Some((value, 1));
    }
    let mut m = 0_u32;
    let mut used = 1_usize;
    loop {
        let byte = *buf.get(offset.saturating_add(used))?;
        used = used.saturating_add(1);
        value = value.saturating_add(usize::from(byte & 0x7f).saturating_mul(1_usize << m));
        m = m.saturating_add(7);
        if byte & 0x80 == 0 || used > 8 {
            break;
        }
    }
    Some((value, used))
}

fn decode_string(buf: &[u8], offset: usize) -> Option<(String, usize)> {
    let first = *buf.get(offset)?;
    let huffman = first & 0x80 != 0;
    let (len, used) = decode_int(buf, offset, 7)?;
    let start = offset.saturating_add(used);
    let end = start.saturating_add(len);
    let slice = buf.get(start..end)?;
    let bytes = if huffman {
        decode_huffman(slice)?
    } else {
        slice.to_vec()
    };
    let text = String::from_utf8_lossy(&bytes).into_owned();
    Some((text, used.saturating_add(len)))
}

fn decode_huffman(src: &[u8]) -> Option<Vec<u8>> {
    if src.is_empty() {
        return Some(Vec::new());
    }
    let mut acc = 0_u64;
    let mut acc_bits = 0_u32;
    let mut out = Vec::new();
    for byte in src {
        acc = (acc << 8) | u64::from(*byte);
        acc_bits = acc_bits.saturating_add(8);
        loop {
            let mut matched = None;
            for (sym, (code, nbits)) in HUFFMAN.iter().enumerate() {
                let n = u32::from(*nbits);
                if acc_bits < n {
                    continue;
                }
                let shift = acc_bits - n;
                if (acc >> shift) & ((1_u64 << n) - 1) == u64::from(*code)
                    && matched.is_none_or(|(_, bits)| n > bits)
                {
                    matched = Some((sym, n));
                }
            }
            let Some((sym, n)) = matched else {
                break;
            };
            acc &= (1_u64 << (acc_bits - n)) - 1;
            acc_bits -= n;
            out.push(u8::try_from(sym).ok()?);
            if out.len() > 4096 {
                return Some(out);
            }
        }
        if acc_bits > 40 {
            break;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7541_c41_first_request() {
        let block = [
            0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ];
        let mut decoder = HpackDecoder::default();
        let headers = decoder.decode_block(&block);
        assert!(
            headers.iter().any(|(n, v)| n == ":method" && v == "GET"),
            "{headers:?}"
        );
        assert!(headers.iter().any(|(n, v)| n == ":path" && v == "/"));
        assert!(headers
            .iter()
            .any(|(n, v)| n == ":authority" && v == "www.example.com"));
        let mut frame = vec![
            0,
            0,
            u8::try_from(block.len()).unwrap(),
            0x1,
            0x04,
            0,
            0,
            0,
            1,
        ];
        frame.extend_from_slice(&block);
        let parsed = parse_http2(&frame);
        assert!(
            parsed.iter().any(|row| {
                row.kind == "http2_request"
                    && row.method == "GET"
                    && row.host.as_deref() == Some("www.example.com")
                    && row.path == "/"
            }),
            "{parsed:?}"
        );
    }

    #[test]
    fn huffman_www_example_com() {
        let encoded = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        let decoded = decode_huffman(&encoded).expect("huff");
        assert_eq!(String::from_utf8_lossy(&decoded), "www.example.com");
    }

    #[test]
    fn rfc7541_c41_huffman_request_and_query() {
        let block = [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        let mut frame = vec![
            0,
            0,
            u8::try_from(block.len()).unwrap(),
            0x1,
            0x04,
            0,
            0,
            0,
            1,
        ];
        frame.extend_from_slice(&block);
        let parsed = parse_http2(&frame);
        assert!(
            parsed.iter().any(|row| {
                row.kind == "http2_request"
                    && row.method == "GET"
                    && row.host.as_deref() == Some("www.example.com")
                    && row.path == "/"
                    && row.scheme == Some("http")
            }),
            "{parsed:?}"
        );
        let query_block = [
            0x82, 0x87, 0x04, 0x17, b'/', b'v', b'1', b'/', b's', b'e', b's', b's', b'i', b'o',
            b'n', b'?', b't', b'o', b'k', b'e', b'n', b'=', b'x', b'&', b'q', b'=', b'1', 0x41,
            0x0b, b'a', b'p', b'i', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        ];
        let mut query_frame = vec![
            0,
            0,
            u8::try_from(query_block.len()).unwrap(),
            0x1,
            0x04,
            0,
            0,
            0,
            1,
        ];
        query_frame.extend_from_slice(&query_block);
        let parsed = parse_http2(&query_frame);
        assert!(
            parsed.iter().any(|row| {
                row.kind == "http2_request"
                    && row.host.as_deref() == Some("api.example")
                    && row.path == "/v1/session"
                    && row.query_keys.iter().any(|key| key == "token")
                    && row.scheme == Some("https")
            }),
            "{parsed:?}"
        );
    }

    #[test]
    fn http2_sync_offset_skips_mid_frame_preamble() {
        let block = [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        let mut frame = vec![
            0,
            0,
            u8::try_from(block.len()).unwrap(),
            0x1,
            0x05,
            0,
            0,
            0,
            1,
        ];
        frame.extend_from_slice(&block);
        let mut junk = vec![0xab, 0xcd, 0xef, 0x01, 0x02];
        junk.extend_from_slice(&frame);
        assert_eq!(super::http2_sync_offset(&junk), Some(5));
        assert!(super::looks_like_http2(&junk));
        // Random noise alone should not sync.
        assert_eq!(
            super::http2_sync_offset(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99]),
            None
        );
    }

    #[test]
    fn splits_headers_frame_and_keeps_dynamic_table() {
        let first = [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        let mut frame1 = vec![
            0,
            0,
            u8::try_from(first.len()).unwrap(),
            0x1,
            0x04,
            0,
            0,
            0,
            1,
        ];
        frame1.extend_from_slice(&first);
        let mut assembler = Http2Assembler::default();
        let mid = 9_usize;
        let first_rows = assembler.push(&frame1[..mid]);
        assert!(
            first_rows.is_empty(),
            "incomplete HEADERS must wait: {first_rows:?}"
        );
        let first_rows = assembler.push(&frame1[mid..]);
        assert!(
            first_rows.iter().any(|row| {
                row.kind == "http2_request" && row.host.as_deref() == Some("www.example.com")
            }),
            "{first_rows:?}"
        );
        let second = [
            0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65,
        ];
        let mut frame2 = vec![
            0,
            0,
            u8::try_from(second.len()).unwrap(),
            0x1,
            0x04,
            0,
            0,
            0,
            3,
        ];
        frame2.extend_from_slice(&second);
        let second_rows = assembler.push(&frame2);
        assert!(
            second_rows.iter().any(|row| {
                row.kind == "http2_request"
                    && row.host.as_deref() == Some("www.example.com")
                    && row.header_names.iter().any(|name| name == "cache-control")
            }),
            "{second_rows:?}"
        );
    }

    #[test]
    fn data_frame_inflates_gzip_json_url() {
        use std::io::Write as _;
        let plain = br#"{"url":"https://ebs.app.example/api/session"}"#;
        let mut gz = Vec::new();
        {
            let mut encoder =
                flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
            encoder.write_all(plain).expect("gzip");
            encoder.finish().expect("gzip finish");
        }
        let len = u32::try_from(gz.len()).expect("frame");
        let mut frame = vec![
            u8::try_from((len >> 16) & 0xff).unwrap(),
            u8::try_from((len >> 8) & 0xff).unwrap(),
            u8::try_from(len & 0xff).unwrap(),
            0x0,
            0x01,
            0,
            0,
            0,
            1,
        ];
        frame.extend_from_slice(&gz);
        let parsed = parse_http2(&frame);
        assert!(
            parsed
                .iter()
                .any(|row| row.host.as_deref() == Some("ebs.app.example")
                    && row.path == "/api/session"),
            "{parsed:?}"
        );
    }

    #[test]
    fn grpc_length_prefix_unwraps_uncompressed_messages() {
        let msg = b"\x0a\x05hello";
        let mut framed = vec![0, 0, 0, 0, u8::try_from(msg.len()).unwrap()];
        framed.extend_from_slice(msg);
        assert_eq!(super::unwrap_grpc_length_prefixed(&framed), msg);
        assert_eq!(super::unwrap_grpc_length_prefixed(b"not-grpc"), b"not-grpc");
    }

    #[test]
    fn continuation_preserves_headers_end_stream() {
        // HEADERS with END_STREAM but without END_HEADERS, then CONTINUATION+END_HEADERS.
        let block = [
            0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ];
        let mid = 8_usize;
        let mut headers = vec![
            0,
            0,
            u8::try_from(mid).unwrap(),
            0x1,
            0x01, // END_STREAM only
            0,
            0,
            0,
            5,
        ];
        headers.extend_from_slice(&block[..mid]);
        let rest = &block[mid..];
        let mut cont = vec![
            0,
            0,
            u8::try_from(rest.len()).unwrap(),
            0x9,
            0x04, // END_HEADERS
            0,
            0,
            0,
            5,
        ];
        cont.extend_from_slice(rest);
        let mut assembler = Http2Assembler::default();
        let _ = assembler.push(&headers);
        let _ = assembler.push(&cont);
        let messages = assembler.take_h2_messages();
        assert_eq!(messages.len(), 1, "{messages:?}");
        assert_eq!(messages[0].stream_id, 5);
        assert!(messages[0]
            .headers
            .iter()
            .any(|(n, v)| n == ":method" && v == "GET"));
    }

    #[test]
    fn settings_max_frame_size_is_respected() {
        let mut assembler = Http2Assembler::default();
        assert_eq!(assembler.max_frame_size, 256 * 1024);
        // SETTINGS frame: id=0x5 value=65536
        let settings = vec![
            0, 0, 6, // length
            0x4, 0x0, // SETTINGS
            0, 0, 0, 0, // stream 0
            0x00, 0x05, 0x00, 0x01, 0x00, 0x00, // id=5 value=65536
        ];
        let _ = assembler.push(&settings);
        assert_eq!(assembler.max_frame_size, 65536);
        // A 20KiB DATA frame should now be accepted (previously rejected at 16KiB).
        let len = 20 * 1024;
        let mut data = vec![
            u8::try_from((len >> 16) & 0xff).unwrap(),
            u8::try_from((len >> 8) & 0xff).unwrap(),
            u8::try_from(len & 0xff).unwrap(),
            0x0,
            0x01,
            0,
            0,
            0,
            1,
        ];
        data.extend(std::iter::repeat(b'z').take(len));
        // Seed stream headers so finish on END_STREAM yields a message.
        assembler.streams.insert(
            1,
            PartialH2 {
                headers: vec![
                    (":method".into(), "POST".into()),
                    (":path".into(), "/".into()),
                ],
                body: Vec::new(),
            },
        );
        let _ = assembler.push(&data);
        let messages = assembler.take_h2_messages();
        assert_eq!(messages.len(), 1, "{messages:?}");
        assert_eq!(messages[0].body.len(), len);
        assert_eq!(messages[0].stream_id, 1);
    }
}
