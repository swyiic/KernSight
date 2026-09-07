//! Mirror reconstructed HTTP/WS plaintext to a Burp listener.
//!
//! The target app keeps its original TLS session. ksightd copies `SSL_write`/
//! `SSL_read` buffers, rebuilds HTTP, and feeds Burp as a proxy client. Original
//! responses are played back on [`ksight_core::BURP_PLAYBACK_PORT`] so Burp HTTP
//! history fills without Repeater and without a second POST to the real server.
//! If playback is unreachable, the request is sent as `https://host/path` so Burp
//! still records a response. No VPN, iptables, or app proxy settings are touched.

use std::collections::{hash_map::DefaultHasher, BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::OpenOptions;
use std::hash::{Hash as _, Hasher as _};
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ksight_core::{
    fragment_bytes, parse_mirror_endpoint, request_from_http_url, requests_from_embedded_http_urls,
    MirroredMessage, StreamReassembler, BURP_PLAYBACK_PORT,
};
use ksight_model::InspectPlaintext;

/// Live Burp feed for one capture session.
pub struct BurpMirror {
    tx: Sender<MirrorJob>,
    delivery_metrics: Arc<DeliveryMetrics>,
    observed_fragments: u64,
    observed_bytes: u64,
    reconstructed_messages: u64,
    reconstructed_requests: u64,
    reconstructed_responses: u64,
    rejected_fragments: u64,
    duplicate_fragments: u64,
    fragment_pushes_without_message: u64,
    evicted_streams: u64,
    hostless_requests: u64,
    queue_failures: u64,
    streams: HashMap<(u32, u64), DirectionStreams>,
    peer_hosts: HashMap<u32, HashSet<String>>,
    last_url: HashMap<(u32, u64), (String, String)>,
    recent_fragments: HashMap<(u32, u64, bool, u64), Instant>,
    stop: Arc<AtomicBool>,
}

#[derive(Default)]
struct DeliveryMetrics {
    delivered: AtomicU64,
    attempt_failed: AtomicU64,
    retry_pending: AtomicU64,
    retry_delivered: AtomicU64,
    retry_exhausted: AtomicU64,
}

struct DirectionStreams {
    send: StreamReassembler,
    recv: StreamReassembler,
    last_seen: Instant,
}

#[derive(Default)]
struct PlaybackStore {
    entries: VecDeque<(String, Vec<u8>)>,
}

impl PlaybackStore {
    fn insert(&mut self, id: String, response: Vec<u8>) {
        while self.entries.len() >= 64 {
            self.entries.pop_front();
        }
        self.entries.push_back((id, response));
    }

    fn take(&mut self, id: Option<&str>) -> Option<Vec<u8>> {
        if let Some(id) = id {
            if let Some(position) = self.entries.iter().position(|(stored, _)| stored == id) {
                return self.entries.remove(position).map(|(_, response)| response);
            }
            return None;
        }
        self.entries.pop_front().map(|(_, response)| response)
    }
}

enum MirrorJob {
    Request(Box<MirroredMessage>, u32, u64),
    Response {
        response: Box<MirroredMessage>,
        fallback: Option<Box<MirroredMessage>>,
        pid: u32,
        stream_id: u64,
    },
    Stop,
}

/// How long a completed request waits for its response copy before it is
/// delivered alone so Burp history keeps filling during a live session.
const PAIRING_GRACE: Duration = Duration::from_secs(2);
/// Maximum requests held per process before the oldest flushes unpaired.
const PENDING_CAP: usize = 32;
const STREAM_CAP: usize = 256;
const RETRY_CAP: usize = 128;
const MAX_DELIVERY_ATTEMPTS: u8 = 6;
static NEXT_PLAYBACK_ID: AtomicU64 = AtomicU64::new(1);

struct RetryDelivery {
    request: MirroredMessage,
    response: Option<MirroredMessage>,
    attempts: u8,
    next_attempt: Instant,
}

impl BurpMirror {
    /// Bind playback and start the worker that talks to `host:port`.
    ///
    /// # Errors
    ///
    /// Returns when the endpoint cannot be parsed.
    pub fn start(endpoint: &str) -> Result<Self, String> {
        Self::start_for_session(endpoint, None)
    }

    /// Start a mirror whose durable log rows are tagged with the capture session.
    ///
    /// # Errors
    ///
    /// Returns when the endpoint cannot be parsed.
    pub fn start_for_session(endpoint: &str, session_id: Option<&str>) -> Result<Self, String> {
        let endpoint = parse_mirror_endpoint(endpoint)?;
        let session_id = session_id.unwrap_or("-").to_owned();
        let queue = Arc::new(Mutex::new(PlaybackStore::default()));
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
        let delivery_metrics = Arc::new(DeliveryMetrics::default());
        let worker_metrics = Arc::clone(&delivery_metrics);
        let worker_session_id = session_id.clone();
        let _ = std::thread::Builder::new()
            .name("ksight-burp-mirror".to_owned())
            .spawn(move || {
                worker_loop(
                    endpoint,
                    &rx,
                    &worker_queue,
                    &worker_metrics,
                    &worker_session_id,
                );
            });
        log_mirror(
            &session_id,
            &format!("burp-mirror session-start endpoint={endpoint} playback={BURP_PLAYBACK_PORT}"),
        );
        Ok(Self {
            tx,
            delivery_metrics,
            observed_fragments: 0,
            observed_bytes: 0,
            reconstructed_messages: 0,
            reconstructed_requests: 0,
            reconstructed_responses: 0,
            rejected_fragments: 0,
            duplicate_fragments: 0,
            fragment_pushes_without_message: 0,
            evicted_streams: 0,
            hostless_requests: 0,
            queue_failures: 0,
            streams: HashMap::new(),
            peer_hosts: HashMap::new(),
            last_url: HashMap::new(),
            recent_fragments: HashMap::new(),
            stop,
        })
    }

    /// Successful deliveries to the Burp listener so far.
    #[must_use]
    pub fn delivery_count(&self) -> u64 {
        self.delivery_metrics.delivered.load(Ordering::Relaxed)
    }

    /// Machine-readable-enough counters persisted as an Inspect observation.
    #[must_use]
    pub fn diagnostic_detail(&self) -> String {
        self.diagnostic_metrics()
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Structured counters carried by the normalized Inspect observation and
    /// consumed directly by `MobileE`. No payload, URL, header, or field name is
    /// included in this map.
    #[must_use]
    pub fn diagnostic_metrics(&self) -> BTreeMap<String, u64> {
        let mut metrics = BTreeMap::new();
        let mut unknown_streams = 0_u64;
        let mut http1_streams = 0_u64;
        let mut http2_streams = 0_u64;
        let mut buffered_bytes = 0_u64;
        for streams in self.streams.values() {
            for assembler in [&streams.send, &streams.recv] {
                match assembler.protocol() {
                    "http1" => http1_streams = http1_streams.saturating_add(1),
                    "http2" => http2_streams = http2_streams.saturating_add(1),
                    _ => unknown_streams = unknown_streams.saturating_add(1),
                }
                buffered_bytes = buffered_bytes
                    .saturating_add(u64::try_from(assembler.buffered_bytes()).unwrap_or(u64::MAX));
            }
        }
        metrics.insert("observed_fragments".to_owned(), self.observed_fragments);
        metrics.insert("observed_bytes".to_owned(), self.observed_bytes);
        metrics.insert(
            "reconstructed_messages".to_owned(),
            self.reconstructed_messages,
        );
        metrics.insert(
            "reconstructed_requests".to_owned(),
            self.reconstructed_requests,
        );
        metrics.insert(
            "reconstructed_responses".to_owned(),
            self.reconstructed_responses,
        );
        metrics.insert("delivered".to_owned(), self.delivery_count());
        metrics.insert(
            "delivery_attempt_failed".to_owned(),
            self.delivery_metrics.attempt_failed.load(Ordering::Relaxed),
        );
        metrics.insert(
            "retry_pending".to_owned(),
            self.delivery_metrics.retry_pending.load(Ordering::Relaxed),
        );
        metrics.insert(
            "retry_delivered".to_owned(),
            self.delivery_metrics
                .retry_delivered
                .load(Ordering::Relaxed),
        );
        metrics.insert(
            "delivery_failed".to_owned(),
            self.delivery_metrics
                .retry_exhausted
                .load(Ordering::Relaxed),
        );
        metrics.insert("rejected_fragments".to_owned(), self.rejected_fragments);
        metrics.insert("duplicate_fragments".to_owned(), self.duplicate_fragments);
        metrics.insert(
            "fragment_pushes_without_message".to_owned(),
            self.fragment_pushes_without_message,
        );
        metrics.insert("evicted_streams".to_owned(), self.evicted_streams);
        metrics.insert("hostless_requests".to_owned(), self.hostless_requests);
        metrics.insert("queue_failures".to_owned(), self.queue_failures);
        metrics.insert(
            "active_streams".to_owned(),
            u64::try_from(self.streams.len()).unwrap_or(u64::MAX),
        );
        metrics.insert("unknown_directions".to_owned(), unknown_streams);
        metrics.insert("http1_directions".to_owned(), http1_streams);
        metrics.insert("http2_directions".to_owned(), http2_streams);
        metrics.insert("buffered_bytes".to_owned(), buffered_bytes);
        metrics
    }

    /// Remember SNI / HTTP Host / `ip:port` from L0 first-write for this process.
    /// Used to fill empty Host on reconstructed HTTP. Does not emit a synthetic
    /// `GET /` — those are not replayable API calls.
    pub fn observe_peer(&mut self, pid: u32, host: String) {
        if pid > 0 && looks_like_mirror_host(&host) {
            self.peer_hosts.entry(pid).or_default().insert(host);
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
        self.observe_bytes_for_connection(pid, tid, None, adapter, direction, bytes);
    }

    /// Reconstruct bytes using an SSL/session object when available. Threads
    /// are only a fallback because one connection can migrate across threads.
    pub fn observe_bytes_for_connection(
        &mut self,
        pid: u32,
        tid: u32,
        connection_id: Option<u64>,
        adapter: &str,
        direction: &str,
        bytes: &[u8],
    ) {
        if bytes.is_empty() {
            return;
        }
        self.observed_fragments = self.observed_fragments.saturating_add(1);
        self.observed_bytes = self
            .observed_bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if !(adapter.starts_with("tls_ssl")
            || adapter.starts_with("jni_")
            || adapter.starts_with("vendor_boundary:")
            || adapter == "handshake_http")
        {
            self.rejected_fragments = self.rejected_fragments.saturating_add(1);
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
        let stream_key = connection_id
            .filter(|value| *value >= 0x1000)
            .unwrap_or(0x8000_0000_0000_0000 | u64::from(tid));
        if let Some(request) = request_from_http_url(bytes) {
            self.reconstructed_messages = self.reconstructed_messages.saturating_add(1);
            self.reconstructed_requests = self.reconstructed_requests.saturating_add(1);
            self.emit_request(pid, stream_key, request);
            return;
        }
        if adapter.starts_with("jni_") {
            for request in requests_from_embedded_http_urls(bytes) {
                self.reconstructed_messages = self.reconstructed_messages.saturating_add(1);
                self.reconstructed_requests = self.reconstructed_requests.saturating_add(1);
                self.emit_request(pid, stream_key, request);
            }
        }
        let outbound = outbound_copy(adapter, direction, bytes);
        if self.is_duplicate_fragment(pid, stream_key, outbound, bytes) {
            self.duplicate_fragments = self.duplicate_fragments.saturating_add(1);
            return;
        }
        if !self.streams.contains_key(&(pid, stream_key)) && self.streams.len() >= STREAM_CAP {
            if let Some(oldest) = self
                .streams
                .iter()
                .min_by_key(|(_, stream)| stream.last_seen)
                .map(|(key, _)| *key)
            {
                self.streams.remove(&oldest);
                self.evicted_streams = self.evicted_streams.saturating_add(1);
            }
        }
        let stream = self
            .streams
            .entry((pid, stream_key))
            .or_insert_with(|| DirectionStreams {
                send: StreamReassembler::default(),
                recv: StreamReassembler::default(),
                last_seen: Instant::now(),
            });
        stream.last_seen = Instant::now();
        let messages = if outbound {
            stream.send.push(bytes)
        } else {
            stream.recv.push(bytes)
        };
        self.reconstructed_messages = self
            .reconstructed_messages
            .saturating_add(u64::try_from(messages.len()).unwrap_or(u64::MAX));
        if messages.is_empty() {
            self.fragment_pushes_without_message =
                self.fragment_pushes_without_message.saturating_add(1);
        }
        for message in messages {
            if message.is_request {
                self.reconstructed_requests = self.reconstructed_requests.saturating_add(1);
            } else {
                self.reconstructed_responses = self.reconstructed_responses.saturating_add(1);
            }
            self.handle_message(pid, stream_key, message);
        }
    }

    fn is_duplicate_fragment(
        &mut self,
        pid: u32,
        stream_id: u64,
        outbound: bool,
        bytes: &[u8],
    ) -> bool {
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        let key = (pid, stream_id, outbound, hasher.finish());
        let now = Instant::now();
        let duplicate = self
            .recent_fragments
            .get(&key)
            .is_some_and(|seen| now.duration_since(*seen) <= Duration::from_millis(100));
        self.recent_fragments.insert(key, now);
        if self.recent_fragments.len() > 512 {
            self.recent_fragments
                .retain(|_, seen| now.duration_since(*seen) <= Duration::from_secs(2));
        }
        duplicate
    }

    fn handle_message(&mut self, pid: u32, stream_id: u64, message: MirroredMessage) {
        if message.is_request {
            self.emit_request(pid, stream_id, message);
            return;
        }
        // Pairing happens on the worker thread; the fallback GET keeps an
        // SSL_read-only response visible when no request is in flight.
        let fallback = self.synthesize_request(pid, stream_id, &message);
        if self
            .tx
            .send(MirrorJob::Response {
                response: Box::new(message),
                fallback: fallback.map(Box::new),
                pid,
                stream_id,
            })
            .is_err()
        {
            self.queue_failures = self.queue_failures.saturating_add(1);
        }
    }

    fn emit_request(&mut self, pid: u32, stream_id: u64, mut request: MirroredMessage) {
        self.finish_request(pid, stream_id, &mut request);
        if !looks_like_mirror_host(&request.host) {
            self.hostless_requests = self.hostless_requests.saturating_add(1);
            return;
        }
        // Repeated requests to the same endpoint are meaningful (login,
        // captcha refresh, OTP retry). Fragment-level debounce above removes
        // duplicate probes without suppressing those requests.
        if self
            .tx
            .send(MirrorJob::Request(Box::new(request), pid, stream_id))
            .is_err()
        {
            self.queue_failures = self.queue_failures.saturating_add(1);
        }
    }

    fn finish_request(&mut self, pid: u32, stream_id: u64, request: &mut MirroredMessage) {
        if request.host.is_empty() {
            if let Some((host, path)) = self.last_url.get(&(pid, stream_id)) {
                host.clone_into(&mut request.host);
                if request.path == "/" {
                    path.clone_into(&mut request.path);
                }
            }
        }
        if request.host.is_empty() {
            if let Some(host) = self.unique_peer_host(pid) {
                host.clone_into(&mut request.host);
            }
        }
        if !request.host.is_empty() {
            self.last_url.insert(
                (pid, stream_id),
                (request.host.clone(), request.path.clone()),
            );
            self.peer_hosts
                .entry(pid)
                .or_default()
                .insert(request.host.clone());
        }
    }

    fn synthesize_request(
        &self,
        pid: u32,
        stream_id: u64,
        response: &MirroredMessage,
    ) -> Option<MirroredMessage> {
        let mut request = response.synthetic_request_for_response();
        if let Some((host, path)) = self.last_url.get(&(pid, stream_id)) {
            if request.host.is_empty() || same_site(&request.host, host) {
                request.host.clone_from(host);
                if request.path == "/" {
                    request.path.clone_from(path);
                }
            }
        } else if let Some((host, path)) = self.unique_url_for_pid(pid) {
            if request.host.is_empty() || same_site(&request.host, host) {
                host.clone_into(&mut request.host);
                if request.path == "/" {
                    path.clone_into(&mut request.path);
                }
            }
        }
        if request.host.is_empty() {
            if let Some(host) = self.unique_peer_host(pid) {
                host.clone_into(&mut request.host);
            }
        }
        if request.host.is_empty() {
            return None;
        }
        Some(request)
    }

    fn unique_peer_host(&self, pid: u32) -> Option<&str> {
        let hosts = self.peer_hosts.get(&pid)?;
        (hosts.len() == 1)
            .then(|| hosts.iter().next().map(String::as_str))
            .flatten()
    }

    fn unique_url_for_pid(&self, pid: u32) -> Option<(&str, &str)> {
        let mut matches = self
            .last_url
            .iter()
            .filter(|((candidate_pid, _), _)| *candidate_pid == pid)
            .map(|(_, (host, path))| (host.as_str(), path.as_str()));
        let first = matches.next()?;
        matches.next().is_none().then_some(first)
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
    if host.is_empty()
        || host.starts_with('/')
        || host.contains("empty-sockaddr")
        || host.contains('*')
        || host.ends_with('+')
    {
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

impl Drop for BurpMirror {
    fn drop(&mut self) {
        // Only flush incomplete streams when the capture ends. Flushing after
        // every SSL boundary hit would split a multipart/photo upload at the
        // first 64 KiB fragment and silently discard the remaining body.
        let mut pending = Vec::new();
        for ((pid, stream_id), streams) in &mut self.streams {
            pending.extend(
                streams
                    .send
                    .flush()
                    .into_iter()
                    .map(|item| (*pid, *stream_id, item)),
            );
            pending.extend(
                streams
                    .recv
                    .flush()
                    .into_iter()
                    .map(|item| (*pid, *stream_id, item)),
            );
        }
        for (pid, stream_id, message) in pending {
            self.handle_message(pid, stream_id, message);
        }
        let _ = self.tx.send(MirrorJob::Stop);
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn worker_loop(
    endpoint: SocketAddr,
    rx: &mpsc::Receiver<MirrorJob>,
    queue: &Arc<Mutex<PlaybackStore>>,
    metrics: &DeliveryMetrics,
    session_id: &str,
) {
    let runtime = DeliveryRuntime {
        endpoint,
        queue,
        metrics,
        session_id,
    };
    let mut pending: HashMap<(u32, u64), VecDeque<(MirroredMessage, Instant)>> = HashMap::new();
    let mut retries = VecDeque::new();
    loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(MirrorJob::Stop) => {
                flush_pending(&mut pending, &mut retries, &runtime);
                let abandoned = u64::try_from(retries.len()).unwrap_or(u64::MAX);
                metrics
                    .retry_exhausted
                    .fetch_add(abandoned, Ordering::Relaxed);
                metrics.retry_pending.store(0, Ordering::Relaxed);
                if abandoned > 0 {
                    log_mirror(
                        session_id,
                        &format!("burp-mirror stop abandoned_retries={abandoned}"),
                    );
                }
                log_mirror(session_id, "burp-mirror session-stop");
                break;
            }
            Ok(MirrorJob::Request(request, pid, stream_id)) => {
                let slot = pending.entry((pid, stream_id)).or_default();
                while slot.len() >= PENDING_CAP {
                    match slot.pop_front() {
                        Some((stale, _)) => {
                            enqueue_delivery(&runtime, &mut retries, stale, None);
                        }
                        None => break,
                    }
                }
                slot.push_back((*request, Instant::now()));
            }
            Ok(MirrorJob::Response {
                response,
                fallback,
                pid,
                stream_id,
            }) => {
                let request = pending
                    .get_mut(&(pid, stream_id))
                    .and_then(VecDeque::pop_front)
                    .map(|(request, _)| request)
                    .or_else(|| fallback.map(|fallback| *fallback));
                if let Some(request) = request {
                    enqueue_delivery(&runtime, &mut retries, request, Some(*response));
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        sweep_expired(&mut pending, &mut retries, &runtime);
        sweep_retries(&runtime, &mut retries);
    }
}

struct DeliveryRuntime<'a> {
    endpoint: SocketAddr,
    queue: &'a Mutex<PlaybackStore>,
    metrics: &'a DeliveryMetrics,
    session_id: &'a str,
}

fn enqueue_delivery(
    runtime: &DeliveryRuntime<'_>,
    retries: &mut VecDeque<RetryDelivery>,
    request: MirroredMessage,
    response: Option<MirroredMessage>,
) {
    match deliver(
        runtime.endpoint,
        &request,
        response.as_ref(),
        runtime.queue,
        runtime.session_id,
    ) {
        Ok(()) => {
            runtime.metrics.delivered.fetch_add(1, Ordering::Relaxed);
        }
        Err(error) => {
            runtime
                .metrics
                .attempt_failed
                .fetch_add(1, Ordering::Relaxed);
            while retries.len() >= RETRY_CAP {
                retries.pop_front();
                runtime
                    .metrics
                    .retry_exhausted
                    .fetch_add(1, Ordering::Relaxed);
            }
            retries.push_back(RetryDelivery {
                request,
                response,
                attempts: 1,
                next_attempt: Instant::now() + retry_delay(1),
            });
            runtime.metrics.retry_pending.store(
                u64::try_from(retries.len()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            log_mirror(
                runtime.session_id,
                &format!("burp-mirror deliver queued retry=1/{MAX_DELIVERY_ATTEMPTS}: {error}"),
            );
        }
    }
}

fn sweep_retries(runtime: &DeliveryRuntime<'_>, retries: &mut VecDeque<RetryDelivery>) {
    let now = Instant::now();
    let queued = retries.len();
    for _ in 0..queued {
        let Some(mut item) = retries.pop_front() else {
            break;
        };
        if item.next_attempt > now {
            retries.push_back(item);
            continue;
        }
        match deliver(
            runtime.endpoint,
            &item.request,
            item.response.as_ref(),
            runtime.queue,
            runtime.session_id,
        ) {
            Ok(()) => {
                runtime.metrics.delivered.fetch_add(1, Ordering::Relaxed);
                runtime
                    .metrics
                    .retry_delivered
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(error) => {
                runtime
                    .metrics
                    .attempt_failed
                    .fetch_add(1, Ordering::Relaxed);
                item.attempts = item.attempts.saturating_add(1);
                if item.attempts >= MAX_DELIVERY_ATTEMPTS {
                    runtime
                        .metrics
                        .retry_exhausted
                        .fetch_add(1, Ordering::Relaxed);
                    log_mirror(
                        runtime.session_id,
                        &format!(
                            "burp-mirror deliver exhausted attempts={}: {error}",
                            item.attempts
                        ),
                    );
                } else {
                    item.next_attempt = Instant::now() + retry_delay(item.attempts);
                    log_mirror(
                        runtime.session_id,
                        &format!(
                            "burp-mirror deliver retry={}/{} failed: {error}",
                            item.attempts, MAX_DELIVERY_ATTEMPTS
                        ),
                    );
                    retries.push_back(item);
                }
            }
        }
    }
    runtime.metrics.retry_pending.store(
        u64::try_from(retries.len()).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
}

fn retry_delay(attempt: u8) -> Duration {
    Duration::from_secs(1_u64 << u32::from(attempt.saturating_sub(1).min(5)))
}

/// Deliver requests whose pairing grace elapsed without a response copy.
fn sweep_expired(
    pending: &mut HashMap<(u32, u64), VecDeque<(MirroredMessage, Instant)>>,
    retries: &mut VecDeque<RetryDelivery>,
    runtime: &DeliveryRuntime<'_>,
) {
    let now = Instant::now();
    for slot in pending.values_mut() {
        while let Some((_, queued_at)) = slot.front() {
            if now.duration_since(*queued_at) < PAIRING_GRACE {
                break;
            }
            let (request, _) = slot.pop_front().expect("front checked");
            enqueue_delivery(runtime, retries, request, None);
        }
    }
    pending.retain(|_, slot| !slot.is_empty());
}

/// Deliver every still-pending request unpaired; used when the session ends.
fn flush_pending(
    pending: &mut HashMap<(u32, u64), VecDeque<(MirroredMessage, Instant)>>,
    retries: &mut VecDeque<RetryDelivery>,
    runtime: &DeliveryRuntime<'_>,
) {
    for slot in pending.values_mut() {
        while let Some((request, _)) = slot.pop_front() {
            enqueue_delivery(runtime, retries, request, None);
        }
    }
    pending.clear();
}

fn deliver(
    endpoint: SocketAddr,
    request: &MirroredMessage,
    response: Option<&MirroredMessage>,
    queue: &Mutex<PlaybackStore>,
    session_id: &str,
) -> Result<(), String> {
    let mut stream = TcpStream::connect_timeout(&endpoint, Duration::from_secs(3))
        .map_err(|error| format!("connect {endpoint}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(6)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    let playback_body = response.map_or_else(
        || b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        MirroredMessage::to_http1_response,
    );
    let playback_id = format!(
        "{:x}-{:x}",
        std::process::id(),
        NEXT_PLAYBACK_ID.fetch_add(1, Ordering::Relaxed)
    );
    if let Ok(mut q) = queue.lock() {
        q.insert(playback_id.clone(), playback_body);
    }
    // Always play the original (or 204) back through adb-forwarded
    // 127.0.0.1:18081. Absolute https://host/path would make Burp fetch the
    // real bank. Phone WLAN IPs make Burp treat the URL as its own listener.
    let wire = request.to_proxy_playback_with_id("127.0.0.1", BURP_PLAYBACK_PORT, &playback_id);
    stream
        .write_all(&wire)
        .map_err(|error| format!("write: {error}"))?;
    let _ = stream.flush();
    let reply = drain_http(&mut stream);
    if reply.is_empty() {
        return Err(
            "Burp accepted the mirror request but returned no response within 6s; turn Intercept off and bypass upstream for 127.0.0.1:18081"
                .to_owned(),
        );
    }
    if reply
        .windows(b"Burp Suite Professional".len())
        .any(|window| window == b"Burp Suite Professional")
        && reply
            .windows(b"<h1>Error</h1>".len())
            .any(|window| window == b"<h1>Error</h1>")
    {
        return Err(
            "Burp generated an upstream error for the playback request; bypass upstream for 127.0.0.1:18081"
                .to_owned(),
        );
    }
    let reply_line = reply
        .split(|byte| *byte == b'\n')
        .next()
        .map(|line| String::from_utf8_lossy(line).trim().to_owned())
        .unwrap_or_default();
    let upload = upload_kind(&request.body);
    log_mirror(
        session_id,
        &format!(
            "burp-mirror ok {} {}{} orig={} burp='{}' wire={} headers={} body={}{} playback_id={playback_id}",
            request.method,
            request.host,
            request.path,
            response.and_then(|item| item.status).unwrap_or(0),
            reply_line.chars().take(80).collect::<String>(),
            wire.len(),
            request.headers.len(),
            request.body.len(),
            upload
        ),
    );
    Ok(())
}

fn log_mirror(session_id: &str, line: &str) {
    let unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    let line = format!("unix_ms={unix_ms} session={session_id} {line}");
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

fn read_http_message(stream: &mut TcpStream, cap: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut expected = None;
    let mut buf = [0_u8; 4096];
    while out.len() < cap {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if expected.is_none() {
                    if let Some(header_end) = out.windows(4).position(|item| item == b"\r\n\r\n") {
                        let body_length = header_value(&out[..header_end], "content-length")
                            .and_then(|value| value.parse::<usize>().ok())
                            .unwrap_or(0);
                        expected = Some(header_end.saturating_add(4).saturating_add(body_length));
                    }
                }
                if expected.is_some_and(|length| out.len() >= length) {
                    break;
                }
            }
        }
    }
    out
}

fn header_value(message: &[u8], wanted: &str) -> Option<String> {
    let text = String::from_utf8_lossy(message);
    text.lines().skip(1).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case(wanted)
            .then(|| value.trim().to_owned())
    })
}

fn playback_loop(
    listener: &TcpListener,
    queue: &Arc<Mutex<PlaybackStore>>,
    stop: &Arc<AtomicBool>,
) {
    let _ = listener.set_nonblocking(true);
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                let request = read_http_message(&mut stream, 8 * 1024 * 1024);
                let playback_id = header_value(&request, "x-kernsight-playback-id");
                let body = queue
                    .lock()
                    .ok()
                    .and_then(|mut q| q.take(playback_id.as_deref()))
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
    use super::{
        header_value, looks_like_mirror_host, read_http_message, BurpMirror, PlaybackStore,
        STREAM_CAP,
    };
    use ksight_model::InspectPlaintext;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn playback_store_pairs_out_of_order_fetches_by_id() {
        let mut store = PlaybackStore::default();
        store.insert("first".into(), b"response-one".to_vec());
        store.insert("second".into(), b"response-two".to_vec());
        assert_eq!(
            store.take(Some("second")).as_deref(),
            Some(b"response-two".as_slice())
        );
        assert_eq!(
            store.take(Some("first")).as_deref(),
            Some(b"response-one".as_slice())
        );
        assert!(store.take(Some("missing")).is_none());
    }

    #[test]
    fn playback_id_header_is_case_insensitive() {
        let request =
            b"GET / HTTP/1.1\r\nHost: localhost\r\nX-KernSight-Playback-ID: abc-123\r\n\r\n";
        assert_eq!(
            header_value(request, "x-kernsight-playback-id").as_deref(),
            Some("abc-123")
        );
    }

    #[test]
    fn playback_reader_does_not_wait_for_keep_alive_close() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let reader = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            read_http_message(&mut stream, 4096)
        });
        let mut client = std::net::TcpStream::connect(addr).unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n")
            .unwrap();
        let message = reader.join().unwrap();
        assert!(message.ends_with(b"\r\n\r\n"));
    }

    #[test]
    fn stream_capacity_evicts_oldest_instead_of_clearing_all() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
        for connection in 0..=STREAM_CAP {
            mirror.observe_bytes_for_connection(
                31,
                1,
                Some(0x1000 + connection as u64),
                "tls_ssl_write",
                "send",
                b"partial",
            );
        }
        assert_eq!(mirror.streams.len(), STREAM_CAP);
    }

    #[test]
    fn rejects_wildcard_and_malformed_peer_hosts() {
        assert!(!looks_like_mirror_host("*.example.test"));
        assert!(!looks_like_mirror_host("api.example.test+"));
        assert!(!looks_like_mirror_host("empty-sockaddr"));
        assert!(looks_like_mirror_host("api.example.test"));
        assert!(looks_like_mirror_host("192.0.2.1:443"));
    }

    #[test]
    fn repeated_endpoint_requests_with_distinct_bodies_are_not_suppressed() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let received = thread::spawn(move || {
            let mut wires = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut buf = vec![0_u8; 4096];
                let n = stream.read(&mut buf).unwrap_or(0);
                wires.push(String::from_utf8_lossy(&buf[..n]).into_owned());
                let _ = stream.write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
            wires
        });
        let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
        mirror.observe_bytes_for_connection(
            21,
            101,
            Some(0x1111),
            "tls_ssl_write",
            "send",
            b"POST /verify HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 3\r\n\r\none",
        );
        mirror.observe_bytes_for_connection(
            21,
            102,
            Some(0x1111),
            "tls_ssl_write",
            "send",
            b"POST /verify HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 3\r\n\r\ntwo",
        );
        drop(mirror);
        let wires = received.join().unwrap();
        assert_eq!(wires.len(), 2);
        assert!(wires.iter().any(|wire| wire.ends_with("one")), "{wires:?}");
        assert!(wires.iter().any(|wire| wire.ends_with("two")), "{wires:?}");
    }

    #[test]
    fn delivery_retries_after_listener_becomes_available() {
        let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = reservation.local_addr().unwrap();
        drop(reservation);

        let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
        mirror.observe_bytes_for_connection(
            22,
            201,
            Some(0x2222),
            "tls_ssl_write",
            "send",
            b"GET /retry HTTP/1.1\r\nHost: api.example.test\r\n\r\n",
        );
        thread::sleep(Duration::from_millis(2_500));

        let listener = TcpListener::bind(addr).unwrap();
        let received = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_message(&mut stream, 4096);
            let _ = stream.write_all(
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            request
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        while std::time::Instant::now() < deadline
            && mirror
                .diagnostic_metrics()
                .get("retry_delivered")
                .copied()
                .unwrap_or(0)
                == 0
        {
            thread::sleep(Duration::from_millis(50));
        }
        let metrics = mirror.diagnostic_metrics();
        assert_eq!(metrics.get("retry_delivered"), Some(&1));
        assert_eq!(metrics.get("delivery_failed"), Some(&0));
        assert!(received.join().unwrap().starts_with(b"GET "));
    }

    #[test]
    fn exact_duplicate_probe_fragment_is_debounced() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let received = thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            let mut count = 0;
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        count += 1;
                        let mut buf = vec![0_u8; 4096];
                        let _ = stream.read(&mut buf);
                        let _ = stream.write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept failed: {error}"),
                }
            }
            count
        });
        let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
        let raw = b"POST /once HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 2\r\n\r\n{}";
        mirror.observe_bytes_for_connection(22, 201, Some(0x2222), "tls_ssl_write", "send", raw);
        mirror.observe_bytes_for_connection(22, 201, Some(0x2222), "tls_ssl_write", "send", raw);
        let metrics = mirror.diagnostic_metrics();
        assert_eq!(metrics.get("observed_fragments"), Some(&2));
        assert_eq!(metrics.get("duplicate_fragments"), Some(&1));
        assert_eq!(metrics.get("reconstructed_requests"), Some(&1));
        assert_eq!(metrics.get("reconstructed_responses"), Some(&0));
        assert_eq!(metrics.get("queue_failures"), Some(&0));
        drop(mirror);
        assert_eq!(received.join().unwrap(), 1);
    }

    #[test]
    fn request_waits_for_response_and_pairs_status() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let received = thread::spawn(move || {
            listener.set_nonblocking(false).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut buf = vec![0_u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
        mirror.observe_plaintext(
            7,
            7,
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
                    "POST /api/pay HTTP/1.1\r\nHost: api.bank.com\r\nContent-Length: 2\r\n\r\n{}"
                        .into(),
                preview_encoding: "utf8_lossy".into(),
                content_class: "text".into(),
            },
        );
        mirror.observe_plaintext(
            7,
            7,
            &InspectPlaintext {
                adapter: "tls_ssl_read".into(),
                direction: "recv".into(),
                library: "libssl.so".into(),
                build_id: None,
                offset: None,
                requested_bytes: 48,
                captured_bytes: 48,
                truncated: false,
                sha256: String::new(),
                preview: "HTTP/1.1 402 Payment Required\r\nContent-Length: 5\r\n\r\n{\"no\"}"
                    .into(),
                preview_encoding: "utf8_lossy".into(),
                content_class: "text".into(),
            },
        );
        drop(mirror);
        let wire = received.join().unwrap();
        // Playback form: absolute target at the device playback listener, with
        // the original Host preserved for Burp history.
        assert!(
            wire.starts_with("POST http://127.0.0.1:18081/api/pay HTTP/1.1\r\n"),
            "wire prefix: {wire}"
        );
        assert!(wire.contains("Host: api.bank.com\r\n"), "wire: {wire}");
        // The playback listener returned the ORIGINAL 402 response, not 204.
        assert!(!wire.contains("HTTP/1.1 204 No Content"), "wire: {wire}");
    }

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
