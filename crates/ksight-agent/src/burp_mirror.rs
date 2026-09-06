//! Mirror reconstructed HTTP/WS plaintext to a Burp listener.
//!
//! The target app keeps its original TLS session. ksightd copies `SSL_write`/
//! `SSL_read` buffers, rebuilds HTTP, and feeds Burp as a proxy client. Original
//! responses are played back on [`ksight_core::BURP_PLAYBACK_PORT`] so Burp HTTP
//! history fills without Repeater and without a second POST to the real server.
//! If playback is unreachable, the request is sent as `https://host/path` so Burp
//! still records a response. No VPN, iptables, or app proxy settings are touched.

use std::collections::{HashMap, VecDeque};
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ksight_core::{
    fragment_bytes, parse_mirror_endpoint, request_from_http_url, requests_from_embedded_http_urls,
    MirroredMessage, StreamReassembler, BURP_PLAYBACK_PORT,
};
use ksight_model::InspectPlaintext;

/// Live Burp feed for one capture session.
pub struct BurpMirror {
    tx: Sender<MirrorJob>,
    streams: HashMap<(u32, u32), DirectionStreams>,
    pending_by_pid: HashMap<u32, VecDeque<MirroredMessage>>,
    peer_host: HashMap<u32, String>,
    last_url: HashMap<u32, (String, String)>,
    seen_urls: HashMap<u32, VecDeque<String>>,
    stop: Arc<AtomicBool>,
}

struct DirectionStreams {
    send: StreamReassembler,
    recv: StreamReassembler,
}

enum MirrorJob {
    Exchange(Box<(MirroredMessage, Option<MirroredMessage>)>),
    Stop,
}

impl BurpMirror {
    /// Bind playback and start the worker that talks to `host:port`.
    ///
    /// # Errors
    ///
    /// Returns when the endpoint cannot be parsed.
    pub fn start(endpoint: &str) -> Result<Self, String> {
        let endpoint = parse_mirror_endpoint(endpoint)?;
        let queue = Arc::new(Mutex::new(VecDeque::<Vec<u8>>::new()));
        let stop = Arc::new(AtomicBool::new(false));
        if let Ok(listener) = TcpListener::bind(("0.0.0.0", BURP_PLAYBACK_PORT)) {
            let queue = Arc::clone(&queue);
            let stop = Arc::clone(&stop);
            let _ = std::thread::Builder::new()
                .name("ksight-burp-playback".to_owned())
                .spawn(move || playback_loop(&listener, &queue, &stop));
        } else {
            eprintln!("burp-mirror playback bind :{BURP_PLAYBACK_PORT} failed; Burp will fetch live responses");
        }
        let (tx, rx) = mpsc::channel();
        let worker_queue = Arc::clone(&queue);
        let _ = std::thread::Builder::new()
            .name("ksight-burp-mirror".to_owned())
            .spawn(move || worker_loop(endpoint, &rx, &worker_queue));
        Ok(Self {
            tx,
            streams: HashMap::new(),
            pending_by_pid: HashMap::new(),
            peer_host: HashMap::new(),
            last_url: HashMap::new(),
            seen_urls: HashMap::new(),
            stop,
        })
    }

    /// Remember SNI / HTTP Host / `ip:port` from L0 first-write for this process.
    /// Used to fill empty Host on reconstructed HTTP. Does not emit a synthetic
    /// `GET /` — those are not replayable API calls.
    pub fn observe_peer(&mut self, pid: u32, host: String) {
        if pid > 0 && looks_like_mirror_host(&host) {
            self.peer_host.insert(pid, host);
        }
    }

    /// Reconstruct TLS/JNI/first-write copies and queue HTTP exchanges that have a real request.
    pub fn observe_bytes(
        &mut self,
        pid: u32,
        tid: u32,
        adapter: &str,
        direction: &str,
        bytes: &[u8],
    ) {
        if bytes.is_empty() {
            return;
        }
        if !(adapter.starts_with("tls_ssl")
            || adapter.starts_with("jni_")
            || adapter == "handshake_http")
        {
            return;
        }
        let owned;
        let bytes = if adapter == "handshake_http"
            && !bytes.windows(4).any(|window| window == b"\r\n\r\n")
            && !bytes.windows(2).any(|window| window == b"\n\n")
        {
            owned = [bytes, b"\r\n\r\n"].concat();
            owned.as_slice()
        } else {
            bytes
        };
        if let Some(request) = request_from_http_url(bytes) {
            self.emit_request(pid, request, false);
            return;
        }
        if adapter.starts_with("jni_") {
            for request in requests_from_embedded_http_urls(bytes) {
                self.emit_request(pid, request, false);
            }
        }
        let stream = self
            .streams
            .entry((pid, tid))
            .or_insert_with(|| DirectionStreams {
                send: StreamReassembler::default(),
                recv: StreamReassembler::default(),
            });
        let outbound = outbound_copy(adapter, direction, bytes);
        let mut messages = if outbound {
            stream.send.push(bytes)
        } else {
            stream.recv.push(bytes)
        };
        let flushed = if outbound {
            stream.send.flush()
        } else {
            stream.recv.flush()
        };
        messages.extend(flushed);
        for message in messages {
            self.handle_message(pid, message);
        }
        if self.streams.len() > 256 {
            self.streams.clear();
        }
    }

    fn handle_message(&mut self, pid: u32, message: MirroredMessage) {
        if message.is_request {
            // Send reconstructed HTTP as soon as it is complete so Burp
            // history fills during a live session, not only on stop.
            self.emit_request(pid, message, false);
            return;
        }
        let request = self
            .pending_by_pid
            .get_mut(&pid)
            .and_then(VecDeque::pop_front)
            .or_else(|| self.synthesize_request(pid, &message));
        if let Some(request) = request {
            enqueue(&self.tx, request, Some(message));
        }
    }

    fn emit_request(&mut self, pid: u32, mut request: MirroredMessage, wait_for_response: bool) {
        self.finish_request(pid, &mut request);
        if request.host.is_empty() {
            return;
        }
        let key = format!("{} {}", request.host, request.path);
        let seen = self.seen_urls.entry(pid).or_default();
        if seen.iter().any(|item| item == &key) {
            return;
        }
        if seen.len() >= 64 {
            seen.pop_front();
        }
        seen.push_back(key);
        if wait_for_response {
            if let Some(previous) = self
                .pending_by_pid
                .get_mut(&pid)
                .and_then(VecDeque::pop_front)
            {
                enqueue(&self.tx, previous, None);
            }
            self.pending_by_pid
                .entry(pid)
                .or_default()
                .push_back(request);
            return;
        }
        enqueue(&self.tx, request, None);
    }

    fn finish_request(&mut self, pid: u32, request: &mut MirroredMessage) {
        if request.host.is_empty() {
            if let Some(host) = self.peer_host.get(&pid) {
                request.host.clone_from(host);
            }
        }
        if request.host.is_empty() {
            if let Some((host, path)) = self.last_url.get(&pid) {
                request.host.clone_from(host);
                if request.path == "/" {
                    request.path.clone_from(path);
                }
            }
        }
        if !request.host.is_empty() {
            self.last_url
                .insert(pid, (request.host.clone(), request.path.clone()));
        }
    }

    fn synthesize_request(&self, pid: u32, response: &MirroredMessage) -> Option<MirroredMessage> {
        let mut request = response.synthetic_request_for_response();
        if let Some((host, path)) = self.last_url.get(&pid) {
            if request.host.is_empty() || same_site(&request.host, host) {
                request.host.clone_from(host);
                if request.path == "/" {
                    request.path.clone_from(path);
                }
            }
        }
        if request.host.is_empty() {
            if let Some(host) = self.peer_host.get(&pid) {
                request.host.clone_from(host);
            }
        }
        if request.host.is_empty() {
            return None;
        }
        Some(request)
    }

    /// Inspect preview fallback when raw bytes were not attached.
    pub fn observe_plaintext(&mut self, pid: u32, tid: u32, fragment: &InspectPlaintext) {
        let bytes = fragment_bytes(
            &fragment.preview,
            &fragment.preview_encoding,
            &fragment.content_class,
        );
        self.observe_bytes(pid, tid, &fragment.adapter, &fragment.direction, &bytes);
    }
}

fn looks_like_mirror_host(host: &str) -> bool {
    if host.is_empty() || host.starts_with('/') || host.contains("empty-sockaddr") {
        return false;
    }
    host.contains('.') || host.contains(':')
}

fn outbound_copy(adapter: &str, direction: &str, bytes: &[u8]) -> bool {
    if bytes.starts_with(b"HTTP/1.0") || bytes.starts_with(b"HTTP/1.1") {
        return false;
    }
    if bytes.starts_with(b"GET ")
        || bytes.starts_with(b"POST ")
        || bytes.starts_with(b"HEAD ")
        || bytes.starts_with(b"PUT ")
        || bytes.starts_with(b"DELETE ")
        || bytes.starts_with(b"PATCH ")
        || bytes.starts_with(b"OPTIONS ")
        || bytes.starts_with(b"CONNECT ")
        || adapter == "handshake_http"
    {
        return true;
    }
    direction == "send"
}

fn same_site(left: &str, right: &str) -> bool {
    let strip = |value: &str| {
        value
            .rsplit_once(':')
            .filter(|(_, port)| port.bytes().all(|byte| byte.is_ascii_digit()))
            .map_or(value, |(host, _)| host)
            .trim_start_matches('.')
            .to_ascii_lowercase()
    };
    let left = strip(left);
    let right = strip(right);
    left == right || left.ends_with(&format!(".{right}")) || right.ends_with(&format!(".{left}"))
}

fn upload_kind(body: &[u8]) -> &'static str {
    if body.len() >= 3 && body[0] == 0xff && body[1] == 0xd8 && body[2] == 0xff {
        " jpeg"
    } else if body.starts_with(b"\x89PNG") {
        " png"
    } else if body.windows(19).any(|w| w == b"multipart/form-data")
        || body
            .windows(30)
            .any(|w| w.starts_with(b"Content-Disposition: form-data"))
    {
        " multipart"
    } else {
        ""
    }
}

fn enqueue(tx: &Sender<MirrorJob>, request: MirroredMessage, response: Option<MirroredMessage>) {
    let _ = tx.send(MirrorJob::Exchange(Box::new((request, response))));
}

impl Drop for BurpMirror {
    fn drop(&mut self) {
        let tx = self.tx.clone();
        for queue in self.pending_by_pid.values_mut() {
            while let Some(request) = queue.pop_front() {
                enqueue(&tx, request, None);
            }
        }
        let _ = tx.send(MirrorJob::Stop);
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn worker_loop(
    endpoint: SocketAddr,
    rx: &mpsc::Receiver<MirrorJob>,
    queue: &Arc<Mutex<VecDeque<Vec<u8>>>>,
) {
    while let Ok(job) = rx.recv() {
        match job {
            MirrorJob::Stop => break,
            MirrorJob::Exchange(pair) => {
                let (request, response) = *pair;
                if let Err(error) = deliver(endpoint, &request, response.as_ref(), queue) {
                    log_mirror(&format!("burp-mirror deliver failed: {error}"));
                }
            }
        }
    }
}

fn deliver(
    endpoint: SocketAddr,
    request: &MirroredMessage,
    response: Option<&MirroredMessage>,
    queue: &Mutex<VecDeque<Vec<u8>>>,
) -> Result<(), String> {
    let mut stream = TcpStream::connect_timeout(&endpoint, Duration::from_secs(3))
        .map_err(|error| format!("connect {endpoint}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    let playback_body = response.map_or_else(
        || b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        MirroredMessage::to_http1_response,
    );
    if let Ok(mut q) = queue.lock() {
        if q.len() >= 64 {
            q.pop_front();
        }
        q.push_back(playback_body);
    }
    // Always play the original (or 204) back through adb-forwarded
    // 127.0.0.1:18081. Absolute https://host/path would make Burp fetch the
    // real bank. Phone WLAN IPs make Burp treat the URL as its own listener.
    let wire = request.to_proxy_playback("127.0.0.1", BURP_PLAYBACK_PORT);
    stream
        .write_all(&wire)
        .map_err(|error| format!("write: {error}"))?;
    let _ = stream.flush();
    let reply = drain_http(&mut stream);
    let reply_line = reply
        .split(|byte| *byte == b'\n')
        .next()
        .map(|line| String::from_utf8_lossy(line).trim().to_owned())
        .unwrap_or_default();
    let upload = upload_kind(&request.body);
    log_mirror(&format!(
        "burp-mirror ok {} {}{} orig={} burp='{}' wire={} headers={} body={}{}",
        request.method,
        request.host,
        request.path,
        response.and_then(|item| item.status).unwrap_or(0),
        reply_line.chars().take(80).collect::<String>(),
        wire.len(),
        request.headers.len(),
        request.body.len(),
        upload
    ));
    Ok(())
}

fn log_mirror(line: &str) {
    eprintln!("{line}");
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/data/local/tmp/ksight/burp-mirror.log")
    {
        let _ = writeln!(file, "{line}");
    }
}

fn drain_http(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.len() >= 512 * 1024 {
                    break;
                }
            }
        }
    }
    out
}

fn playback_loop(
    listener: &TcpListener,
    queue: &Arc<Mutex<VecDeque<Vec<u8>>>>,
    stop: &Arc<AtomicBool>,
) {
    let _ = listener.set_nonblocking(true);
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                let _ = drain_http(&mut stream);
                let body = queue
                    .lock()
                    .ok()
                    .and_then(|mut q| q.pop_front())
                    .unwrap_or_else(|| {
                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_vec()
                    });
                let _ = stream.write_all(&body);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BurpMirror;
    use ksight_model::InspectPlaintext;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn forwards_reconstructed_post_to_a_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let received = thread::spawn(move || {
            listener.set_nonblocking(false).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut buf = vec![0_u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
        mirror.observe_plaintext(
            1,
            1,
            &InspectPlaintext {
                adapter: "tls_ssl_write".into(),
                direction: "send".into(),
                library: "libssl.so".into(),
                build_id: None,
                offset: None,
                requested_bytes: 64,
                captured_bytes: 64,
                truncated: false,
                sha256: String::new(),
                preview:
                    "POST /v1/login HTTP/1.1\r\nHost: api.bank.com\r\nContent-Length: 2\r\n\r\n{}"
                        .into(),
                preview_encoding: "utf8_lossy".into(),
                content_class: "text".into(),
            },
        );
        mirror.observe_plaintext(
            1,
            1,
            &InspectPlaintext {
                adapter: "tls_ssl_read".into(),
                direction: "recv".into(),
                library: "libssl.so".into(),
                build_id: None,
                offset: None,
                requested_bytes: 40,
                captured_bytes: 40,
                truncated: false,
                sha256: String::new(),
                preview: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{\"ok\"}".into(),
                preview_encoding: "utf8_lossy".into(),
                content_class: "text".into(),
            },
        );
        drop(mirror);
        let body = received.join().unwrap();
        assert!(
            body.contains("POST ")
                && body.contains("/v1/login")
                && body.contains("Host: api.bank.com"),
            "{body}"
        );
        assert!(body.contains("{}"), "{body}");
    }

    #[test]
    fn handshake_prefix_without_header_terminator_still_mirrors_browser_get() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let received = thread::spawn(move || {
            listener.set_nonblocking(false).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut buf = vec![0_u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
        mirror.observe_bytes(
            9,
            9,
            "handshake_http",
            "send",
            b"GET / HTTP/1.1\r\nHost: 221.6.56.123:7080\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: keep-alive",
        );
        drop(mirror);
        let body = received.join().unwrap();
        assert!(body.contains("Host: 221.6.56.123:7080"), "{body}");
        assert!(body.contains("User-Agent: Mozilla/5.0"), "{body}");
        assert!(body.contains("Accept: text/html"), "{body}");
    }

    #[test]
    fn icbc_jni_url_pairs_truncated_ssl_read_html() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let received = thread::spawn(move || {
            listener.set_nonblocking(false).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut buf = vec![0_u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
        mirror.observe_bytes(
            27158,
            12,
            "jni_get_string_region",
            "java_to_native",
            b"https://mywap2.icbc.com.cn/ICBCWAPBank/servlet/WapNoSessionReqServlet",
        );
        mirror.observe_bytes(
            27158,
            13,
            "tls_ssl_read",
            "recv",
            b"HTTP/1.1 200 \r\nContent-Type: text/html;charset=utf-8\r\nTransfer-Encoding: chunked\r\nAccess-Control-Allow-Origin: https://static.mywap2.icbc.com.cn\r\n\r\n80\r\n<html>icbc wap",
        );
        drop(mirror);
        let body = received.join().unwrap();
        assert!(body.contains("Host: mywap2.icbc.com.cn"), "{body}");
        assert!(
            body.contains("/ICBCWAPBank/servlet/WapNoSessionReqServlet"),
            "{body}"
        );
        assert!(!body.contains("mirrored.invalid"), "{body}");
    }

    #[test]
    fn unpaired_ssl_read_uses_acao_host_not_mirrored_invalid() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let received = thread::spawn(move || {
            listener.set_nonblocking(false).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut buf = vec![0_u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
        mirror.observe_bytes(
            7,
            7,
            "tls_ssl_read",
            "recv",
            b"HTTP/1.1 200 \r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nAccess-Control-Allow-Origin: https://static.mywap2.icbc.com.cn\r\n\r\n10\r\n<html>partial",
        );
        drop(mirror);
        let body = received.join().unwrap();
        assert!(body.contains("Host: static.mywap2.icbc.com.cn"), "{body}");
        assert!(!body.contains("mirrored.invalid"), "{body}");
    }

    #[test]
    fn handshake_sni_fills_host_on_ssl_read_http() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let received = thread::spawn(move || {
            listener.set_nonblocking(false).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut buf = vec![0_u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
        mirror.observe_peer(5883, "mims.icbc.com.cn".into());
        mirror.observe_bytes(
            5883,
            1,
            "tls_ssl_read",
            "recv",
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        );
        drop(mirror);
        let body = received.join().unwrap();
        assert!(body.contains("Host: mims.icbc.com.cn"), "{body}");
        assert!(!body.contains("mirrored.invalid"), "{body}");
    }

    #[test]
    fn jni_json_loadurl_is_sent_before_stop() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let received = thread::spawn(move || {
            listener.set_nonblocking(false).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut buf = vec![0_u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
        mirror.observe_bytes(
            21428,
            1,
            "jni_new_string_utf",
            "native_to_java",
            br#"{"loadUrl":"https://mywap2.icbc.com.cn/ICBCWAPBankCard/Monorepo/userTips/index.html"}"#,
        );
        let body = received.join().unwrap();
        drop(mirror);
        assert!(body.contains("Host: mywap2.icbc.com.cn"), "{body}");
        assert!(
            body.contains("/ICBCWAPBankCard/Monorepo/userTips/index.html"),
            "{body}"
        );
    }
}
