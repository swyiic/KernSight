//! Reconstruct HTTP/1 and HTTP/2 plaintext copies into Burp-feedable messages.
//!
//! This is report/device-side analysis of already-copied `SSL_write`/`SSL_read`
//! buffers. The app's TLS session is not terminated and no VPN/iptables path is
//! installed. Flutter Dart TLS and QUIC/HTTP3 remain out of scope.

use std::net::{SocketAddr, ToSocketAddrs};

use crate::http2::{looks_like_http2, Http2Assembler};

/// TCP port on the device that plays original `SSL_read` responses back to Burp.
pub const BURP_PLAYBACK_PORT: u16 = 18_081;

/// HTTP CONNECT listener on the phone so Burp can fetch origins through the
/// device network (`adb forward tcp:18888 tcp:18888` → `127.0.0.1:18888`).
pub const BURP_UPSTREAM_PORT: u16 = 18_888;

/// Bound one reconstructed HTTP/1 message while still allowing ordinary
/// avatar/photo multipart uploads to survive 64 KiB boundary fragments.
const ASSEMBLER_CAP: usize = 8 * 1024 * 1024;
/// Keep a small prefix while the first TLS/JNI copies are too short to
/// identify the application protocol. Native boundaries may split `POST`,
/// `HTTP/1.1`, or the HTTP/2 preface across consecutive probe hits.
const PROTOCOL_PROBE_CAP: usize = 64 * 1024;
const HOP_BY_HOP: &[&str] = &[
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
];

/// One reconstructed HTTP/1.1 or HTTP/2-translated request or response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirroredMessage {
    /// True for requests, false for responses.
    pub is_request: bool,
    /// `GET` / `POST` / … or empty on a response.
    pub method: String,
    /// `http` or `https`. TLS inspect defaults to `https` when the copy omits it.
    pub scheme: &'static str,
    /// Host without a port, or with an explicit non-default port.
    pub host: String,
    /// Path including the query string.
    pub path: String,
    /// Response status when this is a response.
    pub status: Option<u16>,
    /// Original header names and values, not redacted.
    pub headers: Vec<(String, String)>,
    /// Request or response body as copied (app-layer encryption is left intact).
    pub body: Vec<u8>,
    /// True when this is an HTTP Upgrade to WebSocket.
    pub websocket_upgrade: bool,
}

impl MirroredMessage {
    /// Absolute-form request Burp's HTTP proxy accepts without a CONNECT/TLS crate.
    #[must_use]
    pub fn to_proxy_absolute(&self) -> Vec<u8> {
        let path = if self.path.is_empty() {
            "/"
        } else {
            self.path.as_str()
        };
        let target = format!("{}://{}{}", self.scheme, self.host, path);
        self.write_http1(self.method.as_str(), &target, Some(&self.host))
    }

    /// Absolute-form request whose upstream is the device playback listener.
    #[must_use]
    pub fn to_proxy_playback(&self, callback_host: &str, playback_port: u16) -> Vec<u8> {
        let path = if self.path.is_empty() {
            "/"
        } else {
            self.path.as_str()
        };
        let target = format!("http://{callback_host}:{playback_port}{path}");
        self.write_http1(self.method.as_str(), &target, Some(&self.host))
    }

    /// Playback request tagged with an opaque ID so concurrent Burp fetches
    /// can retrieve the response paired with this exact reconstructed request.
    #[must_use]
    pub fn to_proxy_playback_with_id(
        &self,
        callback_host: &str,
        playback_port: u16,
        playback_id: &str,
    ) -> Vec<u8> {
        let mut wire = self.to_proxy_playback(callback_host, playback_port);
        if playback_id.is_empty() {
            return wire;
        }
        if let Some(position) = wire.windows(4).position(|window| window == b"\r\n\r\n") {
            let header = format!("\r\nX-KernSight-Playback-ID: {playback_id}");
            wire.splice(position..position, header.bytes());
        }
        wire
    }

    /// Origin-form HTTP/1.1 response for the playback listener to return to Burp.
    #[must_use]
    pub fn to_http1_response(&self) -> Vec<u8> {
        let status = self.status.unwrap_or(200);
        let reason = reason_phrase(status);
        let start = format!("HTTP/1.1 {status} {reason}");
        self.write_http1_start(&start, None)
    }

    /// Build a GET so Burp can store an `SSL_read` response when the matching
    /// `SSL_write` was ciphertext or HTTP/2 at a stack we did not copy.
    ///
    /// Host comes from this response (`Access-Control-Allow-Origin`, `Location`,
    /// `Via`) or `self.host`. Empty host is left empty so the caller can fill
    /// SNI / JNI URL instead of inventing `mirrored.invalid`.
    #[must_use]
    pub fn synthetic_request_for_response(&self) -> Self {
        let host = host_from_response_headers(&self.headers)
            .or_else(|| (!self.host.is_empty()).then(|| self.host.clone()))
            .unwrap_or_default();
        Self {
            is_request: true,
            method: "GET".to_owned(),
            scheme: "https",
            host,
            path: "/".to_owned(),
            status: None,
            headers: Vec::new(),
            body: Vec::new(),
            websocket_upgrade: false,
        }
    }

    fn write_http1(&self, method: &str, target: &str, host: Option<&str>) -> Vec<u8> {
        let start = format!("{method} {target} HTTP/1.1");
        self.write_http1_start(&start, host)
    }

    fn write_http1_start(&self, start_line: &str, host: Option<&str>) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            start_line
                .len()
                .saturating_add(self.body.len())
                .saturating_add(256),
        );
        out.extend_from_slice(start_line.as_bytes());
        out.extend_from_slice(b"\r\n");
        if let Some(host) = host.filter(|value| !value.is_empty()) {
            out.extend_from_slice(b"Host: ");
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        for (name, value) in &self.headers {
            if skip_header(name, self.websocket_upgrade) {
                continue;
            }
            if host.is_some() && name.eq_ignore_ascii_case("host") {
                continue;
            }
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        if self.websocket_upgrade {
            if !has_header(&self.headers, "connection") {
                out.extend_from_slice(b"Connection: Upgrade\r\n");
            }
            if !has_header(&self.headers, "upgrade") {
                out.extend_from_slice(b"Upgrade: websocket\r\n");
            }
        } else if !has_header(&self.headers, "connection") {
            out.extend_from_slice(b"Connection: close\r\n");
        }
        let skip_length = self.body.is_empty() && matches!(self.method.as_str(), "GET" | "HEAD");
        if !skip_length {
            let length = self.body.len();
            out.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    fn from_h2(headers: &[(String, String)], body: Vec<u8>) -> Option<Self> {
        let mut method = String::new();
        let mut scheme = "https";
        let mut host = String::new();
        let mut path = String::from("/");
        let mut status = None;
        let mut out_headers = Vec::new();
        let mut websocket_upgrade = false;
        for (name, value) in headers {
            let lower = name.to_ascii_lowercase();
            match lower.as_str() {
                ":method" => method.clone_from(value),
                ":scheme" => {
                    scheme = if value.eq_ignore_ascii_case("http") {
                        "http"
                    } else {
                        "https"
                    };
                }
                ":authority" | "host" => {
                    if host.is_empty() {
                        host = host_from_token(value);
                    }
                    if lower == "host" {
                        out_headers.push((name.clone(), value.clone()));
                    }
                }
                ":path" => {
                    path = if value.is_empty() {
                        "/".to_owned()
                    } else {
                        value.clone()
                    };
                }
                ":status" => status = value.parse().ok(),
                ":protocol" => {
                    if value.eq_ignore_ascii_case("websocket") {
                        websocket_upgrade = true;
                    }
                }
                _ => {
                    if lower == "upgrade" && value.to_ascii_lowercase().contains("websocket") {
                        websocket_upgrade = true;
                    }
                    out_headers.push((name.clone(), value.clone()));
                }
            }
        }
        let is_request = status.is_none();
        if is_request {
            if method.is_empty() || host.is_empty() {
                return None;
            }
        } else if method.is_empty() {
            "HTTP".clone_into(&mut method);
        }
        Some(Self {
            is_request,
            method,
            scheme,
            host,
            path,
            status,
            headers: out_headers,
            body,
            websocket_upgrade,
        })
    }
}

/// Reassemble HTTP/1.1 and HTTP/2 copies for one TLS direction.
#[derive(Debug, Default)]
pub struct StreamReassembler {
    mode: StreamMode,
    protocol_probe: Vec<u8>,
    http1: Http1Assembler,
    http2: Http2Assembler,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum StreamMode {
    #[default]
    Unknown,
    Http1,
    Http2,
}

impl StreamReassembler {
    /// Current protocol classification for diagnostics. `unknown` means the
    /// accepted boundary bytes have not exposed an HTTP/1 start line or an
    /// HTTP/2 preface/frame boundary yet.
    #[must_use]
    pub const fn protocol(&self) -> &'static str {
        match self.mode {
            StreamMode::Unknown => "unknown",
            StreamMode::Http1 => "http1",
            StreamMode::Http2 => "http2",
        }
    }

    /// Bytes retained while waiting for a complete message.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        match self.mode {
            StreamMode::Unknown => self.protocol_probe.len(),
            StreamMode::Http1 => self.http1.buf.len(),
            StreamMode::Http2 => self.http2.buffered_bytes(),
        }
    }

    /// Push one Inspect copy. Complete messages are returned in order.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<MirroredMessage> {
        if bytes.is_empty() {
            return Vec::new();
        }
        match self.mode {
            StreamMode::Unknown => {
                self.protocol_probe.extend_from_slice(bytes);
                if self.protocol_probe.len() > PROTOCOL_PROBE_CAP {
                    let discard = self.protocol_probe.len().saturating_sub(PROTOCOL_PROBE_CAP);
                    self.protocol_probe.drain(..discard);
                }
                if looks_like_http1(&self.protocol_probe) {
                    self.mode = StreamMode::Http1;
                    let buffered = std::mem::take(&mut self.protocol_probe);
                    self.http1.push(&buffered)
                } else if looks_like_http2(&self.protocol_probe) {
                    self.mode = StreamMode::Http2;
                    let buffered = std::mem::take(&mut self.protocol_probe);
                    self.push_h2(&buffered)
                } else {
                    Vec::new()
                }
            }
            StreamMode::Http1 => self.http1.push(bytes),
            StreamMode::Http2 => self.push_h2(bytes),
        }
    }

    /// Emit a truncated HTTP/1 message still sitting in the assembler.
    ///
    /// A capture can end before `Transfer-Encoding: chunked` sees its terminal
    /// `0` chunk. Flushing lets
    /// Burp store the headers and partial body instead of waiting forever.
    pub fn flush(&mut self) -> Vec<MirroredMessage> {
        match self.mode {
            StreamMode::Http1 => self.http1.flush(),
            StreamMode::Http2 => self.push_h2(&[]),
            StreamMode::Unknown => {
                self.protocol_probe.clear();
                Vec::new()
            }
        }
    }

    fn push_h2(&mut self, bytes: &[u8]) -> Vec<MirroredMessage> {
        if !bytes.is_empty() {
            let _ = self.http2.push(bytes);
        }
        self.http2
            .take_h2_messages()
            .into_iter()
            .filter_map(|message| MirroredMessage::from_h2(&message.headers, message.body))
            .collect()
    }
}

/// HTTP/1.1 header+body reassembly across `SSL_write`/`SSL_read` fragments.
#[derive(Debug, Default)]
struct Http1Assembler {
    buf: Vec<u8>,
}

impl Http1Assembler {
    fn push(&mut self, bytes: &[u8]) -> Vec<MirroredMessage> {
        self.buf.extend_from_slice(bytes);
        if self.buf.len() > ASSEMBLER_CAP {
            let mut out = self.drain(true);
            if self.buf.len() > ASSEMBLER_CAP {
                let drop = self.buf.len().saturating_sub(ASSEMBLER_CAP);
                self.buf.drain(..drop);
            }
            out.extend(self.drain(false));
            return out;
        }
        self.drain(false)
    }

    fn flush(&mut self) -> Vec<MirroredMessage> {
        self.drain(true)
    }

    fn drain(&mut self, incomplete_ok: bool) -> Vec<MirroredMessage> {
        let mut out = Vec::new();
        loop {
            match take_http1(&mut self.buf, incomplete_ok) {
                TakeResult::Message(message) => out.push(message),
                TakeResult::NeedMore => break,
                TakeResult::Skip(skip) => {
                    if incomplete_ok {
                        break;
                    }
                    let skip = skip.max(1).min(self.buf.len());
                    self.buf.drain(..skip);
                }
            }
            if out.len() >= 8 {
                break;
            }
        }
        out
    }
}

enum TakeResult {
    Message(MirroredMessage),
    NeedMore,
    Skip(usize),
}

fn take_http1(buf: &mut Vec<u8>, incomplete_ok: bool) -> TakeResult {
    let start = match find_http1_start(buf) {
        Some(0) => 0,
        Some(index) => return TakeResult::Skip(index),
        None => {
            if buf.len() > 8 {
                return TakeResult::Skip(buf.len().saturating_sub(4));
            }
            return TakeResult::NeedMore;
        }
    };
    if start > 0 {
        buf.drain(..start);
    }
    let Some(header_end) = find_header_end(buf) else {
        return TakeResult::NeedMore;
    };
    let head = buf[..header_end].to_vec();
    let Some((message, body_needed, chunked)) = parse_http1_head(&head) else {
        return TakeResult::Skip(1);
    };
    let body_start = header_end;
    if chunked {
        match take_chunked_body(&buf[body_start..]) {
            Some(body) => {
                let consumed = body_start
                    .saturating_add(chunked_consumed(&buf[body_start..]).unwrap_or(body.len()));
                if consumed > buf.len() {
                    return TakeResult::NeedMore;
                }
                buf.drain(..consumed);
                let mut message = message;
                message.body = body;
                return TakeResult::Message(message);
            }
            None if incomplete_ok && buf.len() > body_start => {
                let mut message = message;
                message.body = partial_chunked_body(&buf[body_start..]);
                buf.clear();
                return TakeResult::Message(message);
            }
            None => return TakeResult::NeedMore,
        }
    }
    let available = buf.len().saturating_sub(body_start);
    if available < body_needed {
        if (incomplete_ok && available > 0) || buf.len() >= ASSEMBLER_CAP {
            let mut message = message;
            message.body = buf[body_start..].to_vec();
            buf.clear();
            return TakeResult::Message(message);
        }
        return TakeResult::NeedMore;
    }
    let body_end = body_start.saturating_add(body_needed);
    let mut message = message;
    message.body = buf[body_start..body_end].to_vec();
    buf.drain(..body_end);
    TakeResult::Message(message)
}

fn parse_http1_head(head: &[u8]) -> Option<(MirroredMessage, usize, bool)> {
    let text = String::from_utf8_lossy(head);
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut lines = text.lines();
    let start = lines.next()?.trim();
    if start.is_empty() {
        return None;
    }
    let mut parts = start.splitn(3, ' ');
    let first = parts.next()?;
    let (is_request, method, mut path, status) = if first.starts_with("HTTP/") {
        (
            false,
            "HTTP".to_owned(),
            String::from("/"),
            parts.next().and_then(|value| value.parse().ok()),
        )
    } else if is_method(first) {
        let target = parts.next().unwrap_or("/");
        (true, first.to_owned(), origin_path(target), None)
    } else {
        return None;
    };
    let mut host = String::new();
    let mut headers = Vec::new();
    let mut content_length = None;
    let mut chunked = false;
    let mut websocket_upgrade = false;
    let mut scheme = "https";
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() {
            continue;
        }
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "host" => host = host_from_token(value),
            "content-length" => content_length = value.parse().ok(),
            "transfer-encoding" => {
                chunked = value
                    .to_ascii_lowercase()
                    .split(',')
                    .any(|item| item.trim() == "chunked");
            }
            "upgrade" => {
                if value.to_ascii_lowercase().contains("websocket") {
                    websocket_upgrade = true;
                }
            }
            _ => {}
        }
        headers.push((name.to_owned(), value.to_owned()));
    }
    if let Some(absolute) = absolute_target(start) {
        if host.is_empty() {
            host.clone_from(&absolute.host);
        }
        path = absolute.path;
        scheme = absolute.scheme;
    }
    let body_needed = if chunked
        || (matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS" | "CONNECT")
            && content_length.is_none())
    {
        0
    } else {
        content_length.unwrap_or(0)
    };
    Some((
        MirroredMessage {
            is_request,
            method,
            scheme,
            host,
            path,
            status,
            headers,
            body: Vec::new(),
            websocket_upgrade,
        },
        body_needed,
        chunked,
    ))
}

struct AbsoluteTarget {
    scheme: &'static str,
    host: String,
    path: String,
}

fn absolute_target(start_line: &str) -> Option<AbsoluteTarget> {
    let mut parts = start_line.splitn(3, ' ');
    let _method = parts.next()?;
    let target = parts.next()?;
    let (scheme, rest) = if let Some(rest) = target.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = target.strip_prefix("http://") {
        ("http", rest)
    } else {
        return None;
    };
    let (host, path) = rest
        .split_once('/')
        .map_or((rest, "/"), |split| (split.0, &rest[split.0.len()..]));
    Some(AbsoluteTarget {
        scheme,
        host: host_from_token(host),
        path: if path.is_empty() {
            "/".to_owned()
        } else {
            path.to_owned()
        },
    })
}

fn origin_path(target: &str) -> String {
    if target.starts_with("http://") || target.starts_with("https://") {
        return absolute_target(&format!("GET {target} HTTP/1.1"))
            .map_or_else(|| "/".to_owned(), |value| value.path);
    }
    if target.is_empty() {
        "/".to_owned()
    } else {
        target.to_owned()
    }
}

fn find_http1_start(bytes: &[u8]) -> Option<usize> {
    let mut index = 0_usize;
    while index < bytes.len() {
        if http1_at(bytes, index) {
            return Some(index);
        }
        index += 1;
    }
    None
}

fn http1_at(bytes: &[u8], index: usize) -> bool {
    const STARTS: [&[u8]; 10] = [
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"PATCH ",
        b"OPTIONS ",
        b"CONNECT ",
        b"HTTP/1.0",
        b"HTTP/1.1",
    ];
    let rest = &bytes[index..];
    STARTS.iter().any(|needle| rest.starts_with(needle))
}

fn looks_like_http1(bytes: &[u8]) -> bool {
    find_http1_start(bytes).is_some_and(|index| index < 16)
}

fn is_method(value: &str) -> bool {
    matches!(
        value,
        "GET" | "POST" | "HEAD" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "CONNECT"
    )
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
        .or_else(|| {
            bytes
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|index| index + 2)
        })
}

fn partial_chunked_body(bytes: &[u8]) -> Vec<u8> {
    let mut index = 0_usize;
    let mut body = Vec::new();
    while index < bytes.len() {
        let rest = &bytes[index..];
        let Some(line_end) = rest.iter().position(|byte| *byte == b'\n') else {
            body.extend_from_slice(rest);
            break;
        };
        let line = std::str::from_utf8(&rest[..line_end])
            .unwrap_or("")
            .trim()
            .trim_end_matches('\r');
        let Ok(size) = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
        else {
            body.extend_from_slice(rest);
            break;
        };
        index = index.saturating_add(line_end).saturating_add(1);
        if size == 0 {
            break;
        }
        if index.saturating_add(size) > bytes.len() {
            body.extend_from_slice(&bytes[index..]);
            break;
        }
        body.extend_from_slice(&bytes[index..index + size]);
        index = index.saturating_add(size);
        if bytes.get(index) == Some(&b'\r') {
            index = index.saturating_add(1);
        }
        if bytes.get(index) == Some(&b'\n') {
            index = index.saturating_add(1);
        }
    }
    body
}

fn take_chunked_body(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut index = 0_usize;
    let mut body = Vec::new();
    while index < bytes.len() {
        let rest = &bytes[index..];
        let line_end = rest.iter().position(|byte| *byte == b'\n')?;
        let line = std::str::from_utf8(&rest[..line_end])
            .ok()?
            .trim()
            .trim_end_matches('\r');
        let size = usize::from_str_radix(line.split(';').next()?.trim(), 16).ok()?;
        index = index.saturating_add(line_end).saturating_add(1);
        if size == 0 {
            return Some(body);
        }
        if index.saturating_add(size) > bytes.len() {
            return None;
        }
        body.extend_from_slice(&bytes[index..index + size]);
        index = index.saturating_add(size);
        if bytes.get(index) == Some(&b'\r') {
            index = index.saturating_add(1);
        }
        if bytes.get(index) == Some(&b'\n') {
            index = index.saturating_add(1);
        }
        if body.len() > ASSEMBLER_CAP {
            return Some(body);
        }
    }
    None
}

fn chunked_consumed(bytes: &[u8]) -> Option<usize> {
    let mut index = 0_usize;
    while index < bytes.len() {
        let rest = &bytes[index..];
        let line_end = rest.iter().position(|byte| *byte == b'\n')?;
        let line = std::str::from_utf8(&rest[..line_end])
            .ok()?
            .trim()
            .trim_end_matches('\r');
        let size = usize::from_str_radix(line.split(';').next()?.trim(), 16).ok()?;
        index = index.saturating_add(line_end).saturating_add(1);
        if size == 0 {
            if bytes.get(index) == Some(&b'\r') {
                index = index.saturating_add(1);
            }
            if bytes.get(index) == Some(&b'\n') {
                index = index.saturating_add(1);
            }
            return Some(index);
        }
        index = index.saturating_add(size);
        if bytes.get(index) == Some(&b'\r') {
            index = index.saturating_add(1);
        }
        if bytes.get(index) == Some(&b'\n') {
            index = index.saturating_add(1);
        }
    }
    None
}

fn skip_header(name: &str, websocket: bool) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower == "content-length" || lower == "host" {
        return true;
    }
    if websocket && (lower == "connection" || lower == "upgrade") {
        return false;
    }
    HOP_BY_HOP.contains(&lower.as_str())
}

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case(name))
}

fn host_from_response_headers(headers: &[(String, String)]) -> Option<String> {
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if lower == "access-control-allow-origin" || lower == "location" {
            if let Some(host) = host_from_origin(value) {
                return Some(host);
            }
        }
    }
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if lower == "x-cache" {
            if let Some(host) = value.split_whitespace().last() {
                let host = host_from_token(host);
                if usable_host(&host) {
                    return Some(host);
                }
            }
        }
        if lower == "via" {
            for token in value.split([' ', ',', '(', ')']) {
                let host = host_from_token(token);
                if usable_host(&host)
                    && host.bytes().any(|byte| byte.is_ascii_alphabetic())
                    && !host.eq_ignore_ascii_case("http")
                    && !host.eq_ignore_ascii_case("https")
                {
                    return Some(host);
                }
            }
        }
    }
    None
}

fn host_from_origin(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value == "*" || value.eq_ignore_ascii_case("null") {
        return None;
    }
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .unwrap_or(value);
    let host = host_from_token(rest.split('/').next().unwrap_or(rest));
    if host.contains('.') {
        Some(host)
    } else {
        None
    }
}

/// Turn a JNI `https://host/path` string into a GET Burp can store.
#[must_use]
pub fn request_from_http_url(bytes: &[u8]) -> Option<MirroredMessage> {
    let text = std::str::from_utf8(bytes).ok()?.trim();
    if text.len() < 12 || text.len() > 2048 {
        return None;
    }
    let line = text.lines().next()?.trim();
    if line.contains("HTTP/1.") || line.contains("HTTP/2") {
        return None;
    }
    if line.contains('<') || line.contains('{') || line.contains(' ') {
        return None;
    }
    parse_http_url_line(line)
}

/// Pull `http(s)://host/path` out of JNI JSON / HTML / mixed copies.
#[must_use]
pub fn requests_from_embedded_http_urls(bytes: &[u8]) -> Vec<MirroredMessage> {
    let mut out: Vec<MirroredMessage> = Vec::new();
    let mut index = 0_usize;
    while index + 8 < bytes.len() && out.len() < 16 {
        let rest = &bytes[index..];
        let scheme_len = if rest.starts_with(b"https://") {
            8_usize
        } else if rest.starts_with(b"http://") {
            7_usize
        } else {
            index += 1;
            continue;
        };
        let mut end = scheme_len;
        while end < rest.len() {
            match rest[end] {
                b'"' | b'\'' | b'<' | b'>' | b' ' | b'\n' | b'\r' | b'\t' | b')' | b']' | b'}'
                | b'\\' | b',' | 0 => break,
                _ => end += 1,
            }
        }
        if let Some(message) = std::str::from_utf8(&rest[..end])
            .ok()
            .and_then(parse_http_url_line)
        {
            if !skip_embedded_host(&message.host)
                && !out
                    .iter()
                    .any(|item| item.host == message.host && item.path == message.path)
            {
                out.push(message);
            }
        }
        index += end.max(1);
    }
    out
}

fn parse_http_url_line(line: &str) -> Option<MirroredMessage> {
    let line = line.trim();
    if line.len() < 12 || line.len() > 2048 {
        return None;
    }
    let (scheme, rest) = if let Some(rest) = line.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = line.strip_prefix("http://") {
        ("http", rest)
    } else {
        return None;
    };
    if rest.is_empty() || rest.contains(' ') || rest.contains('<') || rest.contains('{') {
        return None;
    }
    let (host_part, path) = match rest.split_once('/') {
        Some((host, path)) => (host, format!("/{path}")),
        None => (rest, "/".to_owned()),
    };
    let host = host_from_token(host_part.split('?').next().unwrap_or(host_part));
    if host.is_empty() || !host.contains('.') {
        return None;
    }
    Some(MirroredMessage {
        is_request: true,
        method: "GET".to_owned(),
        scheme,
        host,
        path,
        status: None,
        headers: Vec::new(),
        body: Vec::new(),
        websocket_upgrade: false,
    })
}

fn skip_embedded_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host.ends_with("w3.org")
        || host.ends_with("schemas.android.com")
        || host.ends_with("xmlsoap.org")
        || host.ends_with("apache.org")
}

fn host_from_token(value: &str) -> String {
    let host = value
        .trim()
        .trim_matches(|ch: char| ch == '[' || ch == ']')
        .split('/')
        .next()
        .unwrap_or(value)
        .trim()
        .to_owned();
    if usable_host(&host) {
        host
    } else {
        String::new()
    }
}

fn usable_host(host: &str) -> bool {
    !host.is_empty()
        && !host.contains('*')
        && !host.ends_with('+')
        && !host.contains("empty-sockaddr")
        && (host.contains('.') || host.contains(':'))
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        101 => "Switching Protocols",
        201 => "Created",
        204 => "No Content",
        301 | 302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

/// Parse `host:port` for `--mirror-burp`. IPv4 and hostnames are accepted.
///
/// # Errors
///
/// Returns a message when the value is empty or cannot be resolved.
pub fn parse_mirror_endpoint(value: &str) -> Result<SocketAddr, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("empty --mirror-burp host:port".to_owned());
    }
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }
    value
        .to_socket_addrs()
        .map_err(|error| format!("invalid --mirror-burp {value}: {error}"))?
        .next()
        .ok_or_else(|| format!("invalid --mirror-burp {value}"))
}

/// Recover Inspect preview bytes for HTTP reconstruction.
#[must_use]
pub fn fragment_bytes(preview: &str, preview_encoding: &str, content_class: &str) -> Vec<u8> {
    if content_class == "tls_record" || preview.is_empty() {
        return Vec::new();
    }
    if preview_encoding == "hex" {
        return crate::decode_hex_bytes(preview).unwrap_or_default();
    }
    preview.replace('\0', "\n").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::{
        fragment_bytes, host_from_token, parse_mirror_endpoint, request_from_http_url,
        requests_from_embedded_http_urls, StreamReassembler, BURP_PLAYBACK_PORT,
    };

    #[test]
    fn malformed_discovery_hosts_are_not_promoted_to_http_hosts() {
        assert!(host_from_token("*.example.test").is_empty());
        assert!(host_from_token("api.example.test+").is_empty());
        assert!(host_from_token("empty-sockaddr").is_empty());
        assert_eq!(host_from_token("api.example.test"), "api.example.test");
    }

    #[test]
    fn post_headers_and_body_round_trip_to_burp_absolute_form() {
        let raw = b"POST /v1/login HTTP/1.1\r\nHost: api.bank.com\r\nContent-Type: application/json\r\nAuthorization: Bearer secret\r\nContent-Length: 12\r\n\r\n{\"user\":\"a\"}";
        let mut stream = StreamReassembler::default();
        let messages = stream.push(raw);
        assert_eq!(messages.len(), 1);
        let message = &messages[0];
        assert!(message.is_request);
        assert_eq!(message.method, "POST");
        assert_eq!(message.host, "api.bank.com");
        assert_eq!(message.path, "/v1/login");
        assert_eq!(message.body, br#"{"user":"a"}"#);
        assert!(message.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("authorization") && value == "Bearer secret"
        }));
        let wire = message.to_proxy_absolute();
        let text = String::from_utf8_lossy(&wire);
        assert!(text.starts_with("POST https://api.bank.com/v1/login HTTP/1.1\r\n"));
        assert!(text.contains("Host: api.bank.com\r\n"));
        assert!(text.contains("Authorization: Bearer secret\r\n"));
        assert!(text.contains("Content-Length: 12\r\n"));
        assert!(text.ends_with("{\"user\":\"a\"}"));
        let playback = message.to_proxy_playback("192.168.3.20", BURP_PLAYBACK_PORT);
        let playback_text = String::from_utf8_lossy(&playback);
        assert!(playback_text.starts_with("POST http://192.168.3.20:18081/v1/login HTTP/1.1"));
        assert!(playback_text.contains("Host: api.bank.com\r\n"));
        let tagged = message.to_proxy_playback_with_id(
            "127.0.0.1",
            BURP_PLAYBACK_PORT,
            "session-connection-request",
        );
        let tagged = String::from_utf8_lossy(&tagged);
        assert!(tagged.contains("X-KernSight-Playback-ID: session-connection-request\r\n"));
    }

    #[test]
    fn splits_headers_then_body_across_ssl_writes() {
        let mut stream = StreamReassembler::default();
        assert!(stream
            .push(b"POST /pay HTTP/1.1\r\nHost: pay.example\r\nContent-Length: 4\r\n\r\n")
            .is_empty());
        let messages = stream.push(b"ABCD");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].path, "/pay");
        assert_eq!(messages[0].body, b"ABCD");
    }

    #[test]
    fn protocol_detection_survives_a_split_start_line() {
        let mut stream = StreamReassembler::default();
        assert!(stream.push(b"PO").is_empty());
        assert_eq!(stream.buffered_bytes(), 2);
        let messages = stream
            .push(b"ST /submit HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 2\r\n\r\n{}");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].method, "POST");
        assert_eq!(messages[0].path, "/submit");
        assert_eq!(stream.protocol(), "http1");
    }

    #[test]
    fn response_playback_keeps_status_and_body() {
        let mut stream = StreamReassembler::default();
        let messages = stream.push(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: sid=1\r\nContent-Length: 11\r\n\r\n{\"ok\":true}",
        );
        assert_eq!(messages.len(), 1);
        assert!(!messages[0].is_request);
        assert_eq!(messages[0].status, Some(200));
        let wire = messages[0].to_http1_response();
        let text = String::from_utf8_lossy(&wire);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Set-Cookie: sid=1\r\n"));
        assert!(text.contains("{\"ok\":true}"));
    }

    #[test]
    fn websocket_upgrade_is_flagged() {
        let mut stream = StreamReassembler::default();
        let messages = stream.push(
            b"GET /ws HTTP/1.1\r\nHost: api.bank.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        );
        assert_eq!(messages.len(), 1);
        assert!(messages[0].websocket_upgrade);
        let absolute = messages[0].to_proxy_absolute();
        let wire = String::from_utf8_lossy(&absolute);
        assert!(wire.contains("Upgrade: websocket"));
        assert!(wire.contains("Connection: Upgrade"));
    }

    #[test]
    fn http2_headers_become_http1_for_burp() {
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
        let mut stream = StreamReassembler::default();
        let messages = stream.push(&frame);
        assert_eq!(messages.len(), 1, "{messages:?}");
        assert_eq!(messages[0].method, "GET");
        assert_eq!(messages[0].host, "www.example.com");
        assert_eq!(messages[0].path, "/");
        assert_eq!(messages[0].scheme, "http");
        let absolute = messages[0].to_proxy_absolute();
        let wire = String::from_utf8_lossy(&absolute);
        assert!(wire.starts_with("GET http://www.example.com/ HTTP/1.1"));
    }

    #[test]
    fn parse_mirror_endpoint_accepts_ipv4() {
        let addr = parse_mirror_endpoint("192.168.3.9:8080").unwrap();
        assert_eq!(addr.to_string(), "192.168.3.9:8080");
        assert!(parse_mirror_endpoint("").is_err());
    }

    #[test]
    fn tls_record_previews_are_dropped() {
        assert!(fragment_bytes("TLS handshake", "tls_record", "tls_record").is_empty());
        assert_eq!(fragment_bytes("504f5354", "hex", "binary"), b"POST");
    }

    #[test]
    fn unpaired_response_synthesizes_host_from_via() {
        let mut stream = StreamReassembler::default();
        let messages = stream.push(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nVia: 1.1 cachewc112.10jqka.com.cn (squid)\r\nContent-Length: 2\r\n\r\n{}",
        );
        assert_eq!(messages.len(), 1);
        let request = messages[0].synthetic_request_for_response();
        assert_eq!(request.method, "GET");
        assert_eq!(request.host, "cachewc112.10jqka.com.cn");
        assert_eq!(request.path, "/");
        let playback = request.to_proxy_playback("192.168.3.116", BURP_PLAYBACK_PORT);
        let text = String::from_utf8_lossy(&playback);
        assert!(text.starts_with("GET http://192.168.3.116:18081/ HTTP/1.1"));
        assert!(text.contains("Host: cachewc112.10jqka.com.cn"));
    }

    #[test]
    fn browser_get_keeps_host_user_agent_and_accept() {
        let raw = b"GET / HTTP/1.1\r\nHost: 221.6.56.123:7080\r\nDNT: 1\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36\r\nAccept: text/html,application/xhtml+xml\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: zh-CN,zh;q=0.9\r\nConnection: keep-alive\r\n\r\n";
        let mut stream = StreamReassembler::default();
        let messages = stream.push(raw);
        assert_eq!(messages.len(), 1);
        let message = &messages[0];
        assert_eq!(message.method, "GET");
        assert_eq!(message.host, "221.6.56.123:7080");
        assert_eq!(message.path, "/");
        assert!(message
            .headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("user-agent") && v.contains("Mozilla/5.0")));
        assert!(message
            .headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("accept") && v.contains("text/html")));
        let playback = message.to_proxy_playback("127.0.0.1", BURP_PLAYBACK_PORT);
        let wire = String::from_utf8_lossy(&playback);
        assert!(wire.contains("Host: 221.6.56.123:7080"));
        assert!(wire.contains("User-Agent: Mozilla/5.0"));
        assert!(wire.contains("Accept: text/html"));
        assert!(wire.contains("Connection: keep-alive"));
        assert!(wire.starts_with("GET http://127.0.0.1:18081/ HTTP/1.1"));
    }

    #[test]
    fn multipart_upload_keeps_jpeg_body() {
        let mut body = b"--bnd\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"a.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n".to_vec();
        body.extend_from_slice(&[0xff, 0xd8, 0xff, 0xe0, 1, 2, 3, 4]);
        body.extend_from_slice(b"\r\n--bnd--\r\n");
        let mut raw = format!(
            "POST /upload HTTP/1.1\r\nHost: 221.6.56.123:7080\r\nContent-Type: multipart/form-data; boundary=bnd\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw.extend_from_slice(&body);
        let mut stream = StreamReassembler::default();
        let messages = stream.push(&raw);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].method, "POST");
        assert_eq!(messages[0].path, "/upload");
        assert!(messages[0].body.windows(3).any(|w| w == [0xff, 0xd8, 0xff]));
        let wire = messages[0].to_proxy_playback("127.0.0.1", BURP_PLAYBACK_PORT);
        assert!(wire.windows(3).any(|w| w == [0xff, 0xd8, 0xff]));
        assert!(String::from_utf8_lossy(&wire).contains("multipart/form-data"));
    }

    #[test]
    fn multipart_upload_waits_for_every_boundary_fragment() {
        let image = vec![0x5a; 384 * 1024];
        let mut body = b"--ksight\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"avatar.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n\xff\xd8\xff"
            .to_vec();
        body.extend_from_slice(&image);
        body.extend_from_slice(b"\r\n--ksight--\r\n");
        let mut raw = format!(
            "POST /profile/avatar HTTP/1.1\r\nHost: upload.example.test\r\nContent-Type: multipart/form-data; boundary=ksight\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        raw.extend_from_slice(&body);

        let mut stream = StreamReassembler::default();
        let mut messages = Vec::new();
        for fragment in raw.chunks(32 * 1024) {
            messages.extend(stream.push(fragment));
        }
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].path, "/profile/avatar");
        assert_eq!(messages[0].body, body);
    }

    #[test]
    fn truncated_chunked_html_flushes_partial_body() {
        let raw = b"HTTP/1.1 200 \r\nContent-Type: text/html;charset=utf-8\r\nTransfer-Encoding: chunked\r\nAccess-Control-Allow-Origin: https://static.mywap2.icbc.com.cn\r\n\r\n5a\r\n<html>icbc partial";
        let mut stream = StreamReassembler::default();
        assert!(stream.push(raw).is_empty());
        let messages = stream.flush();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].status, Some(200));
        assert!(messages[0].body.windows(5).any(|w| w == b"<html"));
        let request = messages[0].synthetic_request_for_response();
        assert_eq!(request.host, "static.mywap2.icbc.com.cn");
        assert_ne!(request.host, "mirrored.invalid");
    }

    #[test]
    fn jni_https_url_becomes_get_with_host_and_path() {
        let message = request_from_http_url(
            b"https://mywap2.icbc.com.cn/ICBCWAPBank/servlet/WapNoSessionReqServlet",
        )
        .expect("url");
        assert_eq!(message.method, "GET");
        assert_eq!(message.host, "mywap2.icbc.com.cn");
        assert_eq!(message.path, "/ICBCWAPBank/servlet/WapNoSessionReqServlet");
        assert!(request_from_http_url(b"<?xml version='1.0'?>").is_none());
        assert!(request_from_http_url(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_none());
    }

    #[test]
    fn jni_json_loadurl_becomes_icbc_gets() {
        let json = br#"{"opdata":{"template":{"components":[{"loadUrl":"https://mywap2.icbc.com.cn/ICBCWAPBankCard/Monorepo/userTips/index.html","componentName":"tips"},{"loadUrl":"https://mywap2.icbc.com.cn","componentName":"ops"}]}}}"#;
        let messages = requests_from_embedded_http_urls(json);
        assert!(
            messages.iter().any(|item| {
                item.host == "mywap2.icbc.com.cn"
                    && item.path == "/ICBCWAPBankCard/Monorepo/userTips/index.html"
            }),
            "{messages:?}"
        );
        assert!(messages
            .iter()
            .any(|item| item.host == "mywap2.icbc.com.cn" && item.path == "/"));
    }

    #[test]
    fn get_without_host_parses_so_sni_can_fill_later() {
        let mut stream = StreamReassembler::default();
        let messages = stream.push(b"GET /login HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\n\r\n");
        assert_eq!(messages.len(), 1);
        assert!(messages[0].is_request);
        assert_eq!(messages[0].path, "/login");
        assert!(messages[0].host.is_empty());
    }

    #[test]
    fn flush_does_not_emit_post_headers_before_body() {
        let mut stream = StreamReassembler::default();
        assert!(stream
            .push(b"POST /pay HTTP/1.1\r\nHost: pay.example\r\nContent-Length: 4\r\n\r\n")
            .is_empty());
        assert!(stream.flush().is_empty());
        let messages = stream.push(b"ABCD");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].body, b"ABCD");
    }
}
