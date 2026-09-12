//! Reconstruct HTTP/1 and HTTP/2 plaintext copies into Burp-feedable messages.
//!
//! This is report/device-side analysis of already-copied `SSL_write`/`SSL_read`
//! buffers. The app's TLS session is not terminated and no VPN/iptables path is
//! installed. Flutter Dart TLS and QUIC/HTTP3 remain out of scope.

use std::net::{SocketAddr, ToSocketAddrs};

use crate::http2::{http2_sync_offset, looks_like_http2, Http2Assembler};

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
    /// HTTP/2 stream identifier when reconstructed from H2; `None` for HTTP/1.
    pub stream_id: Option<u32>,
}

/// Ensure path is empty→`/` or starts with `/` so absolute URLs never glue host+path
/// (`https://hostgotoBackground`). Some H2 `:path` values omit the leading slash.
fn ensure_absolute_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

/// True when `host` already carries an explicit `:port` (`a.b:28630`, `[::1]:443`).
fn host_has_explicit_port(host: &str) -> bool {
    if let Some(rest) = host.strip_prefix('[') {
        return rest
            .rsplit_once(']')
            .and_then(|(_, suffix)| suffix.strip_prefix(':'))
            .is_some_and(|port| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()));
    }
    host.rsplit_once(':')
        .is_some_and(|(_, port)| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
}

/// Request-target Burp's HTTP proxy actually records and forwards to upstream :18888.
///
/// `https://host/path` makes Burp CONNECT (TLS inject on :18888 is deferred) and
/// the listener returns its own HTML 200 (`Failed to connect to 127.0.0.1:18888`
/// when the forward is down). History keeps `http://host:443/path`.
fn proxy_absolute_target(scheme: &str, host: &str, path: &str) -> String {
    if host_has_explicit_port(host) || scheme.eq_ignore_ascii_case("http") {
        format!("http://{host}{path}")
    } else {
        format!("http://{host}:443{path}")
    }
}

impl MirroredMessage {
    /// Absolute-form request Burp's HTTP proxy accepts without a CONNECT/TLS crate.
    ///
    /// TLS copies are sent as `http://host:443/path` so Burp treats them as
    /// plaintext HTTP to the upstream playback listener, not CONNECT+TLS.
    #[must_use]
    pub fn to_proxy_absolute(&self) -> Vec<u8> {
        let path = ensure_absolute_path(&self.path);
        let target = proxy_absolute_target(self.scheme, &self.host, &path);
        self.write_http1(self.method.as_str(), &target, Some(&self.host))
    }

    /// Absolute-form request whose upstream is the device playback listener.
    #[must_use]
    pub fn to_proxy_playback(&self, callback_host: &str, playback_port: u16) -> Vec<u8> {
        let path = ensure_absolute_path(&self.path);
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

    /// Absolute `http://host:443/path` form tagged with a playback id.
    ///
    /// Burp history/Repeater show the real host. Pair with playback on
    /// [`BURP_UPSTREAM_PORT`] (`adb forward tcp:18888`) so history shows the
    /// captured `SSL_read` when Burp's upstream reaches that listener.
    #[must_use]
    pub fn to_proxy_absolute_with_id(&self, playback_id: &str) -> Vec<u8> {
        let mut wire = self.to_proxy_absolute();
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
            stream_id: self.stream_id,
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
        } else {
            // Always force close on proxy absolute/playback wire. Preserving
            // Connection: keep-alive makes Burp hold the TCP socket open, so
            // drain_http-style reads time out → empty absolute_reply → why=empty.
            out.extend_from_slice(b"Connection: close\r\n");
        }
        let skip_length = self.body.is_empty() && matches!(self.method.as_str(), "GET" | "HEAD");
        if !skip_length {
            let length = self.body.len();
            out.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
        }
        if let Some(stream_id) = self.stream_id {
            out.extend_from_slice(format!("X-KernSight-H2-Stream-ID: {stream_id}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }

    fn from_h2(
        headers: &[(String, String)],
        body: Vec<u8>,
        stream_id: Option<u32>,
    ) -> Option<Self> {
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
                    path = ensure_absolute_path(value);
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
        let grpc = out_headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type") && value.to_ascii_lowercase().contains("grpc")
        }) || headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("grpc-status"));
        if let Some((_, value)) = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("grpc-status"))
        {
            if status.is_none() {
                status = Some(if value == "0" { 200 } else { 503 });
            }
        }
        if grpc && method.is_empty() && status.is_none() {
            "POST".clone_into(&mut method);
        }
        let body = if grpc {
            crate::unwrap_grpc_length_prefixed(&body)
        } else {
            body
        };
        let body = crate::inflate_http_entity(&out_headers, &body);
        let is_request = status.is_none();
        if is_request {
            // Require :method; host/:authority may be absent on DATA-only or
            // authority-less fragments — burp_mirror::finish_request fills SNI/peer.
            // gRPC-H2 (datagw-edge/streamgrpc) often omits :authority on DATA-only
            // copies; still emit so Burp sees POST + content-type application/grpc.
            if method.is_empty() {
                return None;
            }
        } else if method.is_empty() {
            "HTTP".clone_into(&mut method);
        }
        let mut message = Self {
            is_request,
            method,
            scheme,
            host,
            path,
            status,
            headers: out_headers,
            body,
            websocket_upgrade,
            stream_id,
        };
        message.apply_gateway_rpc_hints();
        Some(message)
    }

    /// Lift mPaaS / Alipay `Operation-Type` into `:path` so Burp history shows
    /// the RPC name when H2 `:path` is `/` or `/mgw.htm`.
    pub fn apply_gateway_rpc_hints(&mut self) {
        if !self.is_request {
            return;
        }
        let op = header_ci(&self.headers, "operation-type")
            .or_else(|| header_ci(&self.headers, "operationtype"))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .or_else(|| jsonish_string_field(&self.body, "operationType"))
            .or_else(|| jsonish_string_field(&self.body, "operation-type"));
        if let Some(op) = op {
            if matches!(self.path.as_str(), "/" | "/mgw.htm" | "") {
                self.path = ensure_absolute_path(&op);
            }
            if !has_header(&self.headers, "operation-type") {
                self.headers.push(("Operation-Type".to_owned(), op.clone()));
            }
        }
        // Any header whose value is an absolute http(s) URL can fill Host/path
        // (Alipay nb_url, Origin, some gRPC/gateway wrappers). Prefer names
        // that look like a request URL, then any remaining https:// value.
        let mut url_headers: Vec<(bool, String)> = self
            .headers
            .iter()
            .filter_map(|(name, value)| {
                let value = value.trim();
                if value.is_empty() {
                    return None;
                }
                let lower = name.to_ascii_lowercase();
                if lower == "referer" || lower == "referrer" {
                    return None;
                }
                let preferred = lower.contains("url")
                    || lower == "origin"
                    || lower.ends_with("-host")
                    || lower == "host";
                Some((preferred, value.to_owned()))
            })
            .collect();
        url_headers.sort_by_key(|(preferred, _)| std::cmp::Reverse(*preferred));
        for (_, value) in url_headers {
            if let Some((host, path)) = split_http_url(&value) {
                if self.host.is_empty() && looks_like_http_host(&host) {
                    self.host = host;
                }
                if matches!(self.path.as_str(), "/" | "") {
                    self.path = path;
                }
                if looks_like_http_host(&self.host) {
                    break;
                }
            } else if value.starts_with('/') && matches!(self.path.as_str(), "/" | "") {
                self.path = value;
            }
        }
        if matches!(self.path.as_str(), "/" | "") {
            if let Some(rpc) = header_ci(&self.headers, "x-simple-rpc")
                .map(str::trim)
                .filter(|value| {
                    !value.is_empty()
                        && *value != "1"
                        && *value != "true"
                        && (value.contains('.') || value.contains('/'))
                })
                .map(ToOwned::to_owned)
            {
                self.path = ensure_absolute_path(&rpc);
            }
        }
    }
}

fn looks_like_http_host(host: &str) -> bool {
    !host.is_empty() && (host.contains('.') || host.contains(':')) && !host.starts_with('/')
}

fn split_http_url(value: &str) -> Option<(String, String)> {
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))?;
    let (host, path) = match rest.split_once('/') {
        Some((host, tail)) => (
            host,
            if tail.is_empty() {
                "/".to_owned()
            } else {
                format!("/{tail}")
            },
        ),
        None => (rest, "/".to_owned()),
    };
    let host = host.split(':').next().unwrap_or(host).to_owned();
    if host.is_empty() {
        None
    } else {
        Some((host, path))
    }
}

fn header_ci<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn jsonish_string_field(body: &[u8], key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let needle = needle.as_bytes();
    let mut search = 0_usize;
    while let Some(rel) = body[search..]
        .windows(needle.len())
        .position(|window| window == needle)
    {
        let mut cursor = search + rel + needle.len();
        while cursor < body.len() && matches!(body[cursor], b' ' | b'\t' | b'\n' | b'\r' | b':') {
            cursor += 1;
        }
        if body.get(cursor) == Some(&b'"') {
            let mut out = Vec::new();
            cursor += 1;
            while cursor < body.len() {
                let byte = body[cursor];
                if byte == b'\\' {
                    if let Some(&next) = body.get(cursor + 1) {
                        out.push(next);
                        cursor += 2;
                        continue;
                    }
                    break;
                }
                if byte == b'"' {
                    return String::from_utf8(out)
                        .ok()
                        .filter(|value| !value.is_empty());
                }
                out.push(byte);
                cursor += 1;
                if out.len() > 256 {
                    break;
                }
            }
        }
        search += rel + needle.len();
    }
    None
}

/// Reassemble HTTP/1.1 and HTTP/2 copies for one TLS direction.
#[derive(Debug, Default)]
pub struct StreamReassembler {
    mode: StreamMode,
    protocol_probe: Vec<u8>,
    http1: Http1Assembler,
    http2: Http2Assembler,
    websocket: Vec<u8>,
    /// Send assembler emits WebSocket frames as requests; recv as responses.
    outbound: bool,
    /// Next HTTP/1 response is body-less (response to HEAD).
    next_response_no_body: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum StreamMode {
    #[default]
    Unknown,
    Http1,
    Http2,
    Websocket,
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
            StreamMode::Websocket => "websocket",
        }
    }

    /// Mark this assembler as the send (true) or recv (false) half.
    pub fn set_outbound(&mut self, outbound: bool) {
        self.outbound = outbound;
    }

    /// Mark the next HTTP/1 response as body-less (RFC: response to HEAD).
    pub fn expect_head_response(&mut self) {
        self.next_response_no_body = true;
    }

    fn apply_no_body_hint(&mut self) {
        if self.next_response_no_body {
            self.http1.force_no_body = true;
            self.next_response_no_body = false;
        }
    }

    /// Bytes retained while waiting for a complete message.
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        match self.mode {
            StreamMode::Unknown => self.protocol_probe.len(),
            StreamMode::Http1 => self.http1.buf.len(),
            StreamMode::Http2 => self.http2.buffered_bytes(),
            StreamMode::Websocket => self.websocket.len(),
        }
    }

    /// True when `bytes` is already the trailing contents of the live buffer.
    ///
    /// Used by burp_mirror debounce to detect probe duplicates that would not
    /// advance reassembly (repeated SSL_write hits of an already-accepted
    /// fragment still sitting in the assembler).
    #[must_use]
    pub fn ends_with(&self, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }
        match self.mode {
            StreamMode::Unknown => self.protocol_probe.ends_with(bytes),
            StreamMode::Http1 => self.http1.buf.ends_with(bytes),
            StreamMode::Http2 => self.http2.ends_with(bytes),
            StreamMode::Websocket => self.websocket.ends_with(bytes),
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
                    self.apply_no_body_hint();
                    let messages = self.http1.push(&buffered);
                    self.promote_websocket(messages)
                } else if let Some(message) = take_mpaas_message(&self.protocol_probe) {
                    self.protocol_probe.clear();
                    vec![message]
                } else if let Some(offset) = http2_sync_offset(&self.protocol_probe) {
                    self.mode = StreamMode::Http2;
                    if offset > 0 {
                        self.protocol_probe.drain(..offset);
                    }
                    let buffered = std::mem::take(&mut self.protocol_probe);
                    self.push_h2(&buffered)
                } else if orphan_body_looks_complete(&self.protocol_probe) {
                    // Missed SSL_read status-line: emit complete-looking orphan
                    // bodies immediately so Burp pairing happens before
                    // PAIRING_GRACE sweeps the matching request unpaired.
                    self.flush_unknown(false)
                } else {
                    Vec::new()
                }
            }
            StreamMode::Http1 => {
                self.apply_no_body_hint();
                let messages = self.http1.push(bytes);
                self.promote_websocket(messages)
            }
            StreamMode::Http2 => self.push_h2(bytes),
            StreamMode::Websocket => self.push_ws(bytes),
        }
    }

    fn promote_websocket(&mut self, messages: Vec<MirroredMessage>) -> Vec<MirroredMessage> {
        if messages.iter().any(|message| message.websocket_upgrade) {
            self.mode = StreamMode::Websocket;
        }
        messages
    }

    fn push_ws(&mut self, bytes: &[u8]) -> Vec<MirroredMessage> {
        if !bytes.is_empty() {
            self.websocket.extend_from_slice(bytes);
            if self.websocket.len() > ASSEMBLER_CAP {
                let discard = self.websocket.len().saturating_sub(ASSEMBLER_CAP);
                self.websocket.drain(..discard);
            }
        }
        let mut out = Vec::new();
        while let Some(message) = take_ws_frame(&mut self.websocket, self.outbound) {
            out.push(message);
        }
        out
    }

    /// Emit a truncated HTTP/1 message still sitting in the assembler.
    ///
    /// A capture can end before `Transfer-Encoding: chunked` sees its terminal
    /// `0` chunk. Flushing lets
    /// Burp store the headers and partial body instead of waiting forever.
    ///
    /// `StreamMode::Unknown` used to clear `protocol_probe` and return nothing.
    /// That silently dropped SSL_read bodies whose status-line fragment was
    /// missed (uretprobe gap / debounce), leaving Burp with unpaired 204s.
    /// Flush now late-promotes HTTP/1|/2 when possible and otherwise salvages
    /// printable orphan bodies as synthetic HTTP/1 responses.
    pub fn flush(&mut self) -> Vec<MirroredMessage> {
        match self.mode {
            StreamMode::Http1 => {
                self.apply_no_body_hint();
                let messages = self.http1.flush();
                self.promote_websocket(messages)
            }
            StreamMode::Http2 => self.push_h2(&[]),
            StreamMode::Websocket => self.push_ws(&[]),
            StreamMode::Unknown => self.flush_unknown(true),
        }
    }

    /// Soft-flush for idle recv: emit salvageable Unknown probes, but keep
    /// short/ambiguous prefixes so a split `HTTP/1.1` start is not wiped by
    /// `RECV_SOFT_FLUSH_IDLE` before the next fragment arrives.
    pub fn soft_flush(&mut self) -> Vec<MirroredMessage> {
        match self.mode {
            StreamMode::Http1 => {
                self.apply_no_body_hint();
                let messages = self.http1.flush();
                self.promote_websocket(messages)
            }
            StreamMode::Http2 => self.push_h2(&[]),
            StreamMode::Websocket => self.push_ws(&[]),
            StreamMode::Unknown => self.flush_unknown(false),
        }
    }

    /// Recv-idle flush: HTTP/2 also salvages DATA-only streams (missed HEADERS)
    /// so pairing can attach orig=status before PAIRING_GRACE. Send idle still
    /// uses [`Self::soft_flush`] so DATA-only request bodies are not turned
    /// into fake 200 responses.
    pub fn recv_idle_flush(&mut self) -> Vec<MirroredMessage> {
        if matches!(self.mode, StreamMode::Http2) {
            self.http2.seal_finish_open_streams();
            return self.push_h2(&[]);
        }
        self.soft_flush()
    }

    /// Session-end recv salvage: soft_flush, then hard flush, then force-emit
    /// any leftover bytes (incomplete headers / non-orphan body) so Burp can
    /// still pair before unpaired Stop. Prefer this over bare `flush()` on seal.
    pub fn seal_flush(&mut self) -> Vec<MirroredMessage> {
        if matches!(self.mode, StreamMode::Http2) {
            self.http2.seal_finish_open_streams();
            let mut out = self.push_h2(&[]);
            if self.buffered_bytes() > 0 {
                let rem = self.http2.take_remainder();
                if let Some(message) = remainder_as_orphan_response(&rem) {
                    out.push(message);
                }
            }
            return out;
        }
        // Soft first so short Unknown prefixes are not discarded before we can
        // salvage; hard flush alone used to wipe BOC-sized residue with no emit.
        let mut out = self.soft_flush();
        if self.buffered_bytes() > 0 {
            let rem = self.remainder_bytes();
            // Incomplete HTTP/1 headers (no CRLFCRLF): close and retry once.
            if find_header_end(&rem).is_none() && looks_like_http1(&rem) {
                let mut closed = rem.clone();
                if !closed.ends_with(b"\r\n") {
                    closed.extend_from_slice(b"\r\n");
                }
                closed.extend_from_slice(b"\r\n");
                self.clear_buffers();
                self.mode = StreamMode::Http1;
                self.apply_no_body_hint();
                out.extend(self.http1.push(&closed));
                out.extend(self.http1.flush());
            } else if let Some(message) = remainder_as_orphan_response(&rem) {
                self.clear_buffers();
                out.push(message);
            }
        }
        // Drain anything still commit-able (complete-enough HTTP/1|/2).
        out.extend(self.flush());
        if self.buffered_bytes() > 0 {
            if let Some(message) = remainder_as_orphan_response(&self.remainder_bytes()) {
                self.clear_buffers();
                out.push(message);
            } else {
                self.clear_buffers();
            }
        }
        out
    }

    fn remainder_bytes(&self) -> Vec<u8> {
        match self.mode {
            StreamMode::Unknown => self.protocol_probe.clone(),
            StreamMode::Http1 => self.http1.buf.clone(),
            StreamMode::Http2 => Vec::new(),
            StreamMode::Websocket => self.websocket.clone(),
        }
    }

    fn clear_buffers(&mut self) {
        self.protocol_probe.clear();
        self.http1.buf.clear();
        self.websocket.clear();
        self.mode = StreamMode::Unknown;
        self.next_response_no_body = false;
        self.http1.force_no_body = false;
    }

    fn flush_unknown(&mut self, discard_remainder: bool) -> Vec<MirroredMessage> {
        if self.protocol_probe.is_empty() {
            return Vec::new();
        }
        if looks_like_http1(&self.protocol_probe) {
            self.mode = StreamMode::Http1;
            let buffered = std::mem::take(&mut self.protocol_probe);
            self.apply_no_body_hint();
            let mut out = self.http1.push(&buffered);
            out.extend(self.http1.flush());
            return out;
        }
        if let Some(message) = take_mpaas_message(&self.protocol_probe) {
            self.protocol_probe.clear();
            return vec![message];
        }
        if let Some(offset) = http2_sync_offset(&self.protocol_probe) {
            self.mode = StreamMode::Http2;
            if offset > 0 {
                self.protocol_probe.drain(..offset);
            }
            let buffered = std::mem::take(&mut self.protocol_probe);
            let mut out = self.push_h2(&buffered);
            out.extend(self.push_h2(&[]));
            return out;
        }
        if let Some(message) = orphan_body_as_response(&self.protocol_probe) {
            self.protocol_probe.clear();
            return vec![message];
        }
        if discard_remainder {
            self.protocol_probe.clear();
        }
        Vec::new()
    }

    fn push_h2(&mut self, bytes: &[u8]) -> Vec<MirroredMessage> {
        if !bytes.is_empty() {
            let _ = self.http2.push(bytes);
        } else {
            // soft_flush / flush: promote HEADERS-complete streams that never
            // saw END_STREAM so Alipay-like fragmented H2 still reconstructs.
            self.http2.soft_finish_open_streams();
        }
        let mut out = Vec::new();
        for message in self.http2.take_h2_messages() {
            if let Some(mirrored) =
                MirroredMessage::from_h2(&message.headers, message.body, Some(message.stream_id))
            {
                out.push(mirrored);
            }
            // from_h2 None (no :method) is dropped; incomplete frames stay in
            // Http2Assembler until more DATA/HEADERS arrive.
        }
        out
    }
}

/// HTTP/1.1 header+body reassembly across `SSL_write`/`SSL_read` fragments.
#[derive(Debug, Default)]
struct Http1Assembler {
    buf: Vec<u8>,
    /// Force the next parsed response to body_needed=0 (HEAD).
    force_no_body: bool,
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
            match take_http1(&mut self.buf, incomplete_ok, self.force_no_body) {
                TakeResult::Message(mut message) => {
                    message.body = crate::inflate_http_entity(&message.headers, &message.body);
                    message.apply_gateway_rpc_hints();
                    if !message.is_request {
                        self.force_no_body = false;
                    }
                    out.push(message);
                }
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

fn take_http1(buf: &mut Vec<u8>, incomplete_ok: bool, force_no_body: bool) -> TakeResult {
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
    let Some((message, mut body_needed, chunked)) = parse_http1_head(&head) else {
        return TakeResult::Skip(1);
    };
    let mut chunked = chunked;
    if force_no_body && !message.is_request {
        body_needed = 0;
        chunked = false;
    }
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
                message.body = crate::inflate_http_entity(&message.headers, &body);
                return TakeResult::Message(message);
            }
            None if incomplete_ok && buf.len() > body_start => {
                let mut message = message;
                message.body = partial_chunked_body(&buf[body_start..]);
                buf.clear();
                return TakeResult::Message(message);
            }
            None => {
                // Keep-alive desync: after a chunked response the next SSL_read
                // may be terminal-chunk residue (`0\r\n\r\n`) plus non-HTTP
                // (or a huge bogus "chunk size" from binary). Prefer resyncing to
                // the next HTTP/1 start over buffering forever.
                let pending = &buf[body_start..];
                if let Some(rel) = find_http1_start(pending) {
                    if rel > 0 {
                        let mut message = message;
                        message.body = partial_chunked_body(&pending[..rel]);
                        buf.drain(..body_start.saturating_add(rel));
                        return TakeResult::Message(message);
                    }
                }
                if let Some(end) = find_chunked_terminal(pending) {
                    let mut message = message;
                    message.body = partial_chunked_body(&pending[..end]);
                    let mut consumed = body_start.saturating_add(end);
                    // Drop contiguous non-HTTP residue until the next message.
                    if let Some(rel) = find_http1_start(&buf[consumed..]) {
                        consumed = consumed.saturating_add(rel);
                    } else if buf.len().saturating_sub(consumed) > 8 {
                        // Leave a tiny tail for overlap with the next push.
                        consumed = buf.len().saturating_sub(4);
                    }
                    buf.drain(..consumed.min(buf.len()));
                    return TakeResult::Message(message);
                }
                // Do NOT commit a partial chunked body at an arbitrary 8KiB
                // watermark — that desyncs keep-alive. Wait for terminal chunk,
                // soft_flush/EOF (incomplete_ok), or ASSEMBLER_CAP pressure.
                if incomplete_ok && (!pending.is_empty() || !message.is_request) {
                    // Responses: headers-only still emits on soft_flush so
                    // pairing can attach orig=status before PAIRING_GRACE.
                    // Requests: keep waiting until some chunk bytes arrive.
                    let mut message = message;
                    message.body = partial_chunked_body(pending);
                    buf.clear();
                    return TakeResult::Message(message);
                }
                if buf.len() >= ASSEMBLER_CAP {
                    let mut message = message;
                    message.body = partial_chunked_body(pending);
                    buf.clear();
                    return TakeResult::Message(message);
                }
                return TakeResult::NeedMore;
            }
        }
    }
    const UNTIL_CLOSE: usize = usize::MAX;
    let available = buf.len().saturating_sub(body_start);
    if body_needed == UNTIL_CLOSE {
        // Response with no Content-Length / not chunked: body ends on
        // connection close. Accumulate until soft_flush/EOF or cap.
        if incomplete_ok || buf.len() >= ASSEMBLER_CAP {
            let mut message = message;
            message.body = buf[body_start..].to_vec();
            buf.clear();
            return TakeResult::Message(message);
        }
        return TakeResult::NeedMore;
    }
    if available < body_needed {
        // Soft_flush/EOF: responses may emit headers-only (available==0) so
        // pairing can carry orig=status. Requests still require body bytes so
        // POST is not truncated before the body copy arrives.
        let allow_incomplete = if message.is_request {
            incomplete_ok && available > 0
        } else {
            incomplete_ok
        };
        if allow_incomplete || buf.len() >= ASSEMBLER_CAP {
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
    let (is_request, method, mut path, status, truncated_status_prefix) =
        if first.starts_with("HTTP/") {
            (
                false,
                "HTTP".to_owned(),
                String::from("/"),
                parts.next().and_then(|value| value.parse().ok()),
                false,
            )
        } else if is_bare_http_version(first) {
            // Lost leading `HTTP/` (truncated SSL_read: `1.1 200 ...`).
            (
                false,
                "HTTP".to_owned(),
                String::from("/"),
                parts.next().and_then(|value| value.parse().ok()),
                true,
            )
        } else if is_method(first) {
            let target = parts.next().unwrap_or("/");
            (true, first.to_owned(), origin_path(target), None, false)
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
    if truncated_status_prefix {
        headers.push((
            "X-KernSight-Truncated-Status-Prefix".to_owned(),
            "1".to_owned(),
        ));
    }
    if let Some(absolute) = absolute_target(start) {
        if host.is_empty() {
            host.clone_from(&absolute.host);
        }
        path = absolute.path;
        scheme = absolute.scheme;
    }
    // Body framing (RFC 7230 §3.3):
    // - 1xx / 204 / 304: never a message body (ignore CL / TE)
    // - HEAD requests: never a message body
    // - responses without CL and not chunked: until connection close
    // - GET/OPTIONS/CONNECT without CL: empty body
    const UNTIL_CLOSE: usize = usize::MAX;
    let no_body_status =
        status.is_some_and(|code| (100..200).contains(&code) || code == 204 || code == 304);
    let chunked = chunked && !no_body_status && !(is_request && method == "HEAD");
    let body_needed = if no_body_status || (is_request && method == "HEAD") {
        0
    } else if chunked {
        0
    } else if !is_request && content_length.is_none() {
        UNTIL_CLOSE
    } else if is_request
        && matches!(method.as_str(), "GET" | "OPTIONS" | "CONNECT")
        && content_length.is_none()
    {
        0
    } else {
        content_length.unwrap_or(0)
    };
    let mut message = MirroredMessage {
        is_request,
        method,
        scheme,
        host,
        path,
        status,
        headers,
        body: Vec::new(),
        websocket_upgrade,
        stream_id: None,
    };
    message.apply_gateway_rpc_hints();
    Some((message, body_needed, chunked))
}

fn take_mpaas_message(bytes: &[u8]) -> Option<MirroredMessage> {
    if !crate::mpaas::looks_like_mpaas(bytes) {
        return None;
    }
    crate::mpaas::parse_mpaas_request(bytes).or_else(|| crate::mpaas::parse_mpaas_response(bytes))
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
    if STARTS.iter().any(|needle| rest.starts_with(needle)) {
        return true;
    }
    // OkHttp keep-alive: prior SSL_read ended mid-`HTTP/` so the next
    // fragment begins `1.1 200 ...` (or `1.0`/`2.0`). Only accept at buffer
    // start or after LF so JSON bodies containing "1.1 200" do not resync.
    bare_http_version_status_at(bytes, index)
}

/// True when `bytes[index..]` looks like an HTTP status line that lost the
/// leading `HTTP/` prefix (`1.1 200 OK`).
fn bare_http_version_status_at(bytes: &[u8], index: usize) -> bool {
    if index > 0 && bytes[index - 1] != b'\n' {
        return false;
    }
    let rest = &bytes[index..];
    for ver in [b"1.0 ".as_slice(), b"1.1 ".as_slice(), b"2.0 ".as_slice()] {
        if !rest.starts_with(ver) || rest.len() < ver.len() + 3 {
            continue;
        }
        let code = &rest[ver.len()..ver.len() + 3];
        if code.iter().all(u8::is_ascii_digit) {
            return true;
        }
    }
    false
}

fn is_bare_http_version(token: &str) -> bool {
    matches!(token, "1.0" | "1.1" | "2.0")
}

fn take_ws_frame(buf: &mut Vec<u8>, outbound: bool) -> Option<MirroredMessage> {
    if buf.len() < 2 {
        return None;
    }
    let b0 = buf[0];
    let b1 = buf[1];
    let opcode = b0 & 0x0f;
    let masked = b1 & 0x80 != 0;
    let mut len = u64::from(b1 & 0x7f);
    let mut offset = 2_usize;
    if len == 126 {
        if buf.len() < 4 {
            return None;
        }
        len = u64::from(u16::from_be_bytes([buf[2], buf[3]]));
        offset = 4;
    } else if len == 127 {
        if buf.len() < 10 {
            return None;
        }
        len = u64::from_be_bytes(buf[2..10].try_into().ok()?);
        offset = 10;
    }
    if masked {
        offset = offset.saturating_add(4);
    }
    let payload_len = usize::try_from(len).ok()?;
    if buf.len() < offset.saturating_add(payload_len) {
        return None;
    }
    if opcode == 0x8 {
        buf.drain(..offset.saturating_add(payload_len));
        return None;
    }
    let mut payload = buf[offset..offset + payload_len].to_vec();
    if masked {
        let mask = &buf[offset - 4..offset];
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    buf.drain(..offset.saturating_add(payload_len));
    Some(MirroredMessage {
        is_request: outbound,
        method: "WS".to_owned(),
        scheme: "https",
        host: String::new(),
        path: "/".to_owned(),
        status: if outbound { None } else { Some(101) },
        headers: vec![("Upgrade".to_owned(), "websocket".to_owned())],
        body: payload,
        websocket_upgrade: true,
        stream_id: None,
    })
}

/// True when the buffer contains an HTTP/1 request or status line.
#[must_use]
pub fn looks_like_http_plain(bytes: &[u8]) -> bool {
    looks_like_http1(bytes) || looks_like_http2(bytes)
}

fn looks_like_http1(bytes: &[u8]) -> bool {
    // Allow a modest binary/TLS-residue preamble before the HTTP/1 start so
    // keep-alive desync and mid-stream SSL_read resync still lock onto HTTP
    // instead of sitting forever in Unknown (which yields Burp 204).
    find_http1_start(bytes).is_some_and(|index| index < 4096)
}

/// True when `bytes` look like an application-body fragment without an HTTP
/// start line — e.g. mid-JSON from an SSL_read whose status-line copy was lost.
fn looks_like_orphan_http_body(bytes: &[u8]) -> bool {
    if bytes.len() < 16 {
        return false;
    }
    // Obvious TLS record headers are not HTTP bodies.
    if bytes.len() >= 3 && matches!(bytes[0], 0x14 | 0x15 | 0x16 | 0x17) && bytes[1] == 0x03 {
        return false;
    }
    if looks_like_http1(bytes) || looks_like_http2(bytes) {
        return false;
    }
    let sample_len = bytes.len().min(256);
    let sample = &bytes[..sample_len];
    // Prefer valid UTF-8: CJK JSON fails ASCII-printable ratio
    // because multi-byte codepoints are not ascii_graphic.
    if let Ok(text) = std::str::from_utf8(sample) {
        let trimmed = text.trim_start();
        return trimmed.starts_with('{')
            || trimmed.starts_with('[')
            || trimmed.starts_with('"')
            || trimmed.starts_with('<')
            || text.contains("\":")
            || text.contains("\": ");
    }
    let printable = sample
        .iter()
        .filter(|byte| {
            byte.is_ascii_graphic()
                || matches!(*byte, b' ' | b'\t' | b'\r' | b'\n')
                || **byte >= 0x80
        })
        .count();
    if (printable as f64) / (sample_len as f64) < 0.85 {
        return false;
    }
    let text = String::from_utf8_lossy(sample);
    let trimmed = text.trim_start();
    trimmed.starts_with('{')
        || trimmed.starts_with('[')
        || trimmed.starts_with('"')
        || trimmed.starts_with('<')
        || text.contains("\":")
}

/// True when an orphan body looks finished enough to salvage without waiting
/// for recv idle soft-flush (balanced JSON/HTML-ish terminator).
fn orphan_body_looks_complete(bytes: &[u8]) -> bool {
    if !looks_like_orphan_http_body(bytes) {
        return false;
    }
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text.trim_end(),
        Err(_) => {
            let Some(last) = bytes.iter().rposition(|byte| !byte.is_ascii_whitespace()) else {
                return false;
            };
            return matches!(bytes[last], b'}' | b']' | b'>') && bytes.len() >= 64;
        }
    };
    if !(text.ends_with('}') || text.ends_with(']') || text.ends_with('>')) {
        return false;
    }
    if text.contains("\":")
        || text.starts_with('{')
        || text.starts_with('[')
        || bytes.windows(2).any(|window| window == b"\":")
    {
        let mut depth = 0_i32;
        for ch in text.chars() {
            match ch {
                '{' | '[' => depth += 1,
                '}' | ']' => {
                    depth -= 1;
                    if depth < 0 {
                        return false;
                    }
                }
                _ => {}
            }
        }
        return depth == 0 && text.len() >= 32;
    }
    text.len() >= 64
}

fn orphan_body_as_response(bytes: &[u8]) -> Option<MirroredMessage> {
    if !looks_like_orphan_http_body(bytes) {
        return None;
    }
    let content_type = if bytes.first().is_some_and(|b| matches!(b, b'{' | b'['))
        || bytes.windows(2).any(|window| window == b"\":")
    {
        "application/json"
    } else if bytes.starts_with(b"<") || bytes.windows(2).any(|window| window == b"</") {
        "text/html"
    } else {
        "text/plain"
    };
    // Status unknown when the SSL_read status-line fragment was missed.
    // Playback still needs a wire status (None → 200) but headers mark salvage.
    Some(MirroredMessage {
        is_request: false,
        method: String::new(),
        scheme: "https",
        host: String::new(),
        path: "/".to_owned(),
        // Wire/playback use 200; orig metrics treat Missing-Status salvage as 200
        // so paired orphan bodies count as orig≠0 instead of unpaired 0.
        status: Some(200),
        headers: vec![
            ("Content-Type".to_owned(), content_type.to_owned()),
            ("Content-Length".to_owned(), bytes.len().to_string()),
            ("X-KernSight-Orphan-Body".to_owned(), "1".to_owned()),
            ("X-KernSight-Missing-Status".to_owned(), "1".to_owned()),
        ],
        body: bytes.to_vec(),
        websocket_upgrade: false,
        stream_id: None,
    })
}

/// Seal-time orphan: looser than mid-stream (accept any substantial non-TLS
/// leftover, including incomplete HTTP/1 header blocks already promoted).
fn remainder_as_orphan_response(bytes: &[u8]) -> Option<MirroredMessage> {
    if bytes.len() < 8 {
        return None;
    }
    if bytes.len() >= 3 && matches!(bytes[0], 0x14 | 0x15 | 0x16 | 0x17) && bytes[1] == 0x03 {
        return None;
    }
    if let Some(message) = orphan_body_as_response(bytes) {
        return Some(message);
    }
    // Incomplete HTTP/1 response head without body delimiter — synthesize
    // from status line when present; otherwise treat as opaque body.
    if let Some(index) = find_http1_start(bytes) {
        let slice = &bytes[index..];
        if slice.starts_with(b"HTTP/1.") || bare_http_version_status_at(slice, 0) {
            let line_end = slice
                .iter()
                .position(|b| *b == b'\n')
                .unwrap_or(slice.len().min(64));
            let line = std::str::from_utf8(&slice[..line_end]).unwrap_or("").trim();
            let status = if line.starts_with("HTTP/") {
                line.split_whitespace()
                    .nth(1)
                    .and_then(|code| code.parse::<u16>().ok())
                    .unwrap_or(200)
            } else {
                // `1.1 200 OK` — status is the second token.
                line.split_whitespace()
                    .nth(1)
                    .and_then(|code| code.parse::<u16>().ok())
                    .unwrap_or(200)
            };
            return Some(MirroredMessage {
                is_request: false,
                method: String::new(),
                scheme: "https",
                host: String::new(),
                path: "/".to_owned(),
                status: Some(status),
                headers: vec![
                    ("Content-Length".to_owned(), "0".to_owned()),
                    ("X-KernSight-Seal-Salvage".to_owned(), "1".to_owned()),
                    ("X-KernSight-Incomplete-Headers".to_owned(), "1".to_owned()),
                ],
                body: Vec::new(),
                websocket_upgrade: false,
                stream_id: None,
            });
        }
    }
    // Opaque leftover (gzip/protobuf mid-body, etc.)
    Some(MirroredMessage {
        is_request: false,
        method: String::new(),
        scheme: "https",
        host: String::new(),
        path: "/".to_owned(),
        status: Some(200),
        headers: vec![
            (
                "Content-Type".to_owned(),
                "application/octet-stream".to_owned(),
            ),
            ("Content-Length".to_owned(), bytes.len().to_string()),
            ("X-KernSight-Orphan-Body".to_owned(), "1".to_owned()),
            ("X-KernSight-Seal-Salvage".to_owned(), "1".to_owned()),
        ],
        body: bytes.to_vec(),
        websocket_upgrade: false,
        stream_id: None,
    })
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

/// Locate the end of a chunked body at/after an explicit `0` terminal chunk.
///
/// Returns the index just past `0\r\n\r\n` (or `0\n\n`) when present. This
/// recovers when SSL_read delivers the terminal chunk glued to non-HTTP bytes
/// that would otherwise keep `take_chunked_body` waiting forever.
fn find_chunked_terminal(bytes: &[u8]) -> Option<usize> {
    for (index, window) in bytes.windows(5).enumerate() {
        if window == b"\r\n0\r\n" {
            let mut end = index + 5;
            if bytes.get(end) == Some(&b'\r') {
                end += 1;
            }
            if bytes.get(end) == Some(&b'\n') {
                end += 1;
                return Some(end);
            }
            // `\r\n0\r\n` without a second CRLF still ends the chunked body
            // when non-HTTP residue follows.
            return Some(end);
        }
    }
    if bytes.starts_with(b"0\r\n\r\n") {
        return Some(5);
    }
    if bytes.starts_with(b"0\n\n") {
        return Some(3);
    }
    if bytes.starts_with(b"0\r\n") && bytes.len() >= 3 {
        let mut end = 3usize;
        if bytes.get(end) == Some(&b'\r') {
            end += 1;
        }
        if bytes.get(end) == Some(&b'\n') {
            end += 1;
        }
        return Some(end);
    }
    None
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
        // Binary residue after keep-alive often parses as a huge hex "size".
        // Fail fast so the caller can resync instead of buffering forever.
        if size > ASSEMBLER_CAP {
            return None;
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
    // Strip hop-by-hop Connection keep-alive on proxy wire; websocket keeps it.
    if lower == "connection" {
        return !websocket;
    }
    if websocket && lower == "upgrade" {
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
            // Require a real DNS label (dot) and reject spanner/CDN tokens like
            // `mobilegw-54-49022:7088[200` that usable_host accepts via `:`.
            for token in value.split([' ', ',', '(', ')']) {
                let host = host_from_token(token);
                if usable_host(&host)
                    && host.contains('.')
                    && !host.contains('[')
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
        stream_id: None,
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
        && !host.starts_with("dirn:")
        && !host.starts_with("content:")
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
#[path = "tests.rs"]
mod tests;
