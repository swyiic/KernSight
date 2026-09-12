//! Mirror reconstructed HTTP/WS plaintext to a Burp listener.
//!
//! The target app keeps its original TLS session. ksightd copies `SSL_write`/
//! `SSL_read` buffers, rebuilds HTTP, and feeds Burp as a proxy client.
//!
//! Primary wire is always absolute `POST http://host:443/path HTTP/1.1` with
//! `X-KernSight-Playback-ID` and `Connection: close`. Burp Proxy history /
//! Repeater therefore keep the real API URL — never `/_ksight/...` and never
//! `http://phone:18081/...` as the visible request.
//!
//! `https://host/path` makes this Burp CONNECT to upstream :18888; TLS inject
//! on that helper is deferred, so history never records the request and the
//! listener returns its own HTML 200. `http://host:443/path` is plaintext HTTP
//! to :18888 and is what HTTP history stores.
//!
//! Captured bodies (no live origin):
//! 1. Queue the reconstructed response on [`ksight_core::BURP_PLAYBACK_PORT`]
//!    (legacy) and on [`ksight_core::BURP_UPSTREAM_PORT`].
//! 2. Point Burp **Upstream proxy** at `127.0.0.1:18888` on hotspot (`adb forward`), or `phone:18888` on home Wi-Fi.
//! 3. When Burp fetches via that upstream and the request carries
//!    `X-KernSight-Playback-ID` (plain absolute HTTP to :18888), the helper
//!    returns the queued body without dialing the origin. CONNECT accepts the
//!    tunnel but does not dial origin (avoids Clash stalls); TLS body inject is
//!    deferred pending a musl-safe terminator.
//!
//! Short absolute read timeout + skip-streak avoid 14s stalls when upstream is
//! misconfigured; fallback never rewrites the visible request to `:18081`.

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
    MirroredMessage, StreamReassembler, BURP_PLAYBACK_PORT, BURP_UPSTREAM_PORT,
};
use ksight_model::InspectPlaintext;

/// Live Burp feed for one capture session.
pub struct BurpMirror {
    tx: Sender<MirrorJob>,
    delivery_metrics: Arc<DeliveryMetrics>,
    network_connects: u64,
    network_handshakes: u64,
    observed_fragments: u64,
    observed_bytes: u64,
    reconstructed_messages: u64,
    reconstructed_requests: u64,
    reconstructed_responses: u64,
    /// TLS/JNI copies classified outbound (SSL_write).
    send_fragments: u64,
    /// TLS/JNI copies classified inbound (SSL_read).
    recv_fragments: u64,
    rejected_fragments: u64,
    duplicate_fragments: u64,
    duplicate_probe: u64,
    duplicate_suppressed_progress: u64,
    fragment_pushes_without_message: u64,
    evicted_streams: u64,
    hostless_requests: u64,
    queue_failures: u64,
    standard_tls_fragments: u64,
    vendor_fragments: u64,
    jni_fragments: u64,
    handshake_fragments: u64,
    stack_coverage: StackCoverageSnapshot,
    streams: HashMap<(u32, u64), DirectionStreams>,
    peer_hosts: HashMap<u32, HashSet<String>>,
    last_url: HashMap<(u32, u64), (String, String)>,
    /// Most recent Host/path per pid — orphan SSL_read fallback when multiple
    /// peer hosts make `unique_peer_host` / `unique_url_for_pid` return None.
    recent_url: HashMap<u32, (String, String)>,
    /// Most recent SNI/peer host per pid (even when peer_hosts has many).
    /// Fills authority-less H2 / Host-less HTTP/1 before unique_peer_host can.
    recent_peer: HashMap<u32, String>,
    /// Requests reconstructed without a usable Host; retried when SNI/peer
    /// binds to the same SSL* `stream_key` (not pid-wide).
    pending_hostless: VecDeque<(u32, u64, MirroredMessage)>,
    /// Ranked SNI/Host book shared with the delivery worker. Fill prefers
    /// first-party API hosts over turkey-sls / CDN telemetry.
    peer_book: Arc<Mutex<PeerHostBook>>,
    /// Capture session id for hostless diagnostic lines.
    session_id: String,
    /// Last accepted fragment fingerprint per (pid, stream_key, outbound).
    recent_fragments: HashMap<(u32, u64, bool), RecentFragment>,
    /// Sticky tid→SSL* so a brief missing connection_id on one side still
    /// joins the same stream_key as its peer (OkHttp thread pools).
    tid_connection: HashMap<(u32, u32), (u64, Instant)>,
    /// Handshake/connect SNI waiting for the next SSL stream_key on that tid.
    pending_tid_sni: HashMap<(u32, u32), String>,
    /// Cross-adapter content fingerprint (pid, hash) so JNI/TLS/vendor copies
    /// of the same bytes are not reconstructed twice.
    content_seen: HashMap<(u32, u64), Instant>,
    /// Peek (= consumes=false) preview evidence. Does not advance the stream
    /// cursor; a later recv that shares a prefix becomes canonical. Timed-out
    /// peeks may promote as low-confidence inbound.
    pending_peeks: VecDeque<PendingPeek>,
    /// Recently promoted peeks. A matching read still invalidates them so a
    /// late SSL_read does not double-deliver after PEEK_PROMOTE_IDLE.
    promoted_peeks: VecDeque<PendingPeek>,
    /// Live keylog secrets for decrypting Inspect `tls_record` copies.
    keylog_secrets: Vec<ksight_core::KeylogSecret>,
    /// Pids with buffered recv bytes; worker defers unpaired grace sweep.
    recv_busy_pids: Arc<Mutex<HashSet<u32>>>,
    stop: Arc<AtomicBool>,
    /// Joined in Drop before playback `stop` so end-of-session delivers still hit :18081.
    worker: Option<std::thread::JoinHandle<()>>,
}

/// Current mapped-network-stack inventory. It contains capability counts only.
#[derive(Debug, Clone, Copy, Default)]
pub struct StackCoverageSnapshot {
    pub candidates: u64,
    pub export_candidates: u64,
    pub pinned_boundaries: u64,
    pub empirical_boundaries: u64,
    pub keylog_candidates: u64,
    pub uncovered: u64,
}

#[derive(Default)]
struct DeliveryMetrics {
    delivered: AtomicU64,
    attempt_failed: AtomicU64,
    retry_pending: AtomicU64,
    retry_delivered: AtomicU64,
    retry_exhausted: AtomicU64,
}

fn new_direction_streams() -> DirectionStreams {
    let mut send = StreamReassembler::default();
    let mut recv = StreamReassembler::default();
    send.set_outbound(true);
    recv.set_outbound(false);
    DirectionStreams {
        send,
        recv,
        send_accepted: 0,
        recv_accepted: 0,
        send_last: Vec::new(),
        recv_last: Vec::new(),
        last_seen: Instant::now(),
        send_last_seen: Instant::now(),
        recv_last_seen: Instant::now(),
    }
}

fn looks_like_tls_record(bytes: &[u8]) -> bool {
    bytes.len() >= 5 && bytes[1] == 0x03 && matches!(bytes[0], 0x14 | 0x15 | 0x16 | 0x17)
}

struct DirectionStreams {
    send: StreamReassembler,
    recv: StreamReassembler,
    /// Monotonic bytes accepted into `send` (survives message drain).
    send_accepted: u64,
    /// Monotonic bytes accepted into `recv` (survives message drain).
    recv_accepted: u64,
    /// Last fragment accepted on send, for progressive/truncated coalesce.
    send_last: Vec<u8>,
    /// Last fragment accepted on recv, for progressive/truncated coalesce.
    recv_last: Vec<u8>,
    last_seen: Instant,
    /// Last outbound (SSL_write) accept — H2 soft-finish keys off this.
    send_last_seen: Instant,
    /// Last inbound (SSL_read) accept — soft-flush keys off this, not send.
    recv_last_seen: Instant,
}

/// Fingerprint of the last accepted fragment on one stream direction.
struct RecentFragment {
    hash: u64,
    len: u32,
    /// `*_accepted` after this fragment was pushed.
    pos_after: u64,
    seen_at: Instant,
}

/// Non-consuming peek preview held until a matching recv or timeout.
#[derive(Clone)]
struct PendingPeek {
    pid: u32,
    stream_key: u64,
    /// Content fingerprint for dedupe key.
    hash: u64,
    len: u32,
    bytes: Vec<u8>,
    adapter: String,
    seen_at: Instant,
}

#[derive(Default)]
struct PlaybackStore {
    entries: VecDeque<(String, Vec<u8>)>,
    /// Soft index: latest playback id queued for a Host (CONNECT fallback).
    by_host: HashMap<String, String>,
}

impl PlaybackStore {
    fn insert(&mut self, id: String, response: Vec<u8>) {
        while self.entries.len() >= 64 {
            if let Some((old_id, _)) = self.entries.pop_front() {
                self.by_host.retain(|_, stored| stored != &old_id);
            }
        }
        self.entries.push_back((id, response));
    }

    fn insert_for_host(&mut self, host: &str, id: String, response: Vec<u8>) {
        let host_key = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
        self.by_host.insert(host_key, id.clone());
        self.insert(id, response);
    }

    fn take(&mut self, id: Option<&str>) -> Option<Vec<u8>> {
        if let Some(id) = id {
            if let Some(position) = self.entries.iter().position(|(stored, _)| stored == id) {
                let (_, response) = self.entries.remove(position)?;
                self.by_host.retain(|_, stored| stored != id);
                return Some(response);
            }
            return None;
        }
        let (id, response) = self.entries.pop_front()?;
        self.by_host.retain(|_, stored| stored != &id);
        Some(response)
    }

    fn take_for_host(&mut self, host: &str) -> Option<Vec<u8>> {
        let host_key = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
        let id = self.by_host.get(&host_key).cloned();
        self.take(id.as_deref())
    }
}

/// Ranked SNI / Host observations for filling authority-less H2.
#[derive(Debug, Default)]
struct PeerHostBook {
    by_pid: HashMap<u32, Vec<String>>,
    session: Vec<String>,
    by_stream: HashMap<(u32, u64), String>,
    /// Handshake/connect SNI that has not yet bound to an SSL* stream_key.
    /// Seal-time fill may use this only when the pid has exactly one leftover
    /// non-telemetry name — never at handshake time (CDN/API races).
    unbound: HashMap<u32, Vec<String>>,
}

impl PeerHostBook {
    fn remember(&mut self, pid: u32, host: &str) {
        if !looks_like_mirror_host(host) {
            return;
        }
        remember_host_list(&mut self.session, host);
        remember_host_list(self.by_pid.entry(pid).or_default(), host);
    }

    fn bind_stream(&mut self, pid: u32, stream: u64, host: &str) {
        if looks_like_mirror_host(host) {
            self.by_stream.insert((pid, stream), host.to_owned());
            self.take_unbound(pid, host);
        }
    }

    fn remember_unbound(&mut self, pid: u32, host: &str) {
        if !looks_like_mirror_host(host) || is_cdn_steal_host(host) {
            return;
        }
        remember_host_list(self.unbound.entry(pid).or_default(), host);
    }

    fn take_unbound(&mut self, pid: u32, host: &str) {
        let Some(list) = self.unbound.get_mut(&pid) else {
            return;
        };
        list.retain(|item| !item.eq_ignore_ascii_case(host));
        if list.is_empty() {
            self.unbound.remove(&pid);
        }
    }

    fn unique_unbound(&self, pid: u32) -> Option<&str> {
        let list = self.unbound.get(&pid)?;
        let mut only: Option<&str> = None;
        for host in list {
            if is_cdn_steal_host(host) {
                continue;
            }
            match only {
                None => only = Some(host.as_str()),
                Some(existing) if existing.eq_ignore_ascii_case(host) => {}
                Some(_) => return None,
            }
        }
        only
    }

    fn rebind_stream(&mut self, pid: u32, from: u64, to: u64) {
        if from == to {
            return;
        }
        if let Some(host) = self.by_stream.remove(&(pid, from)) {
            self.by_stream.entry((pid, to)).or_insert(host);
        }
    }

    fn fill(&self, request: &mut MirroredMessage, pid: u32, stream: u64) {
        // Last-resort placeholders (mobilegw/loggw) may still be replaced by
        // a later handshake SNI on this stream. Real Hosts stay put unless
        // last_url stamped a sibling that this path must not inherit
        // (cycle-025223 SystemLogHandler ← jump.m.cmbchina.cn /pk.htm).
        if looks_like_mirror_host(&request.host) && !is_last_resort_host(&request.host) {
            let reject = (looks_like_cmb_mainpage_path(&request.path)
                && !is_cmb_mainpage_host(&request.host))
                || (looks_like_cmb_log_path(&request.path) && !is_cmb_log_host(&request.host))
                || (is_alipay_dae_csv(request)
                    && !request.host.to_ascii_lowercase().contains("datagw"))
                || skip_inherited_cmb_avatar(&request.path, &request.host);
            if !reject {
                return;
            }
            request.host.clear();
        }
        // Only the same TLS connection. Pid/session-wide SNI is how turkey-sls,
        // datagw, ACS, and bank CDNs stamp the wrong host onto a sibling RPC.
        if let Some(host) = self.by_stream.get(&(pid, stream)) {
            // Same-SSL* SNI is usually right, but CMB multiplex leftovers
            // (wangdun/log) must not stamp /mainpage/ or SystemLogHandler.
            let skip = (looks_like_cmb_mainpage_path(&request.path)
                && !is_cmb_mainpage_host(host))
                || (looks_like_cmb_log_path(&request.path) && !is_cmb_log_host(host))
                // cycle-024809 D-AE 2048-byte CSV stamped mobilegw from the
                // same SSL* as mgw. Diagnosis CSV only accepts datagw.
                || (is_alipay_dae_csv(request)
                    && !host.to_ascii_lowercase().contains("datagw"))
                // cycle-035815 avatar COS path inherited mbmodule-mainopenapi.
                || skip_inherited_cmb_avatar(&request.path, host);
            if !skip {
                request.host.clone_from(host);
                return;
            }
        }
        // Path/header-constrained: /mgw.htm may use an observed mobilegw SNI
        // on this pid. Not a pid-wide steal of datagw/CDN.
        if let Some(host) = self.match_observed_host(request, pid) {
            request.host = host;
            return;
        }
        if request.path.to_ascii_lowercase().contains("/loggw") {
            "loggw.alipay.com".clone_into(&mut request.host);
            return;
        }
        if is_alipay_dae_csv(request) {
            if let Some(host) = self.observed_datagw_host(pid) {
                request.host = host;
            } else {
                "datagw-edge.alipay.com".clone_into(&mut request.host);
            }
            return;
        }
        if looks_like_cmb_log_path(&request.path) {
            if let Some(host) = self.cmb_host_for_path(pid, &request.path) {
                request.host = host;
            }
            return;
        }
        if looks_like_cmb_mainpage_path(&request.path) {
            if let Some(host) = self.cmb_host_for_path(pid, &request.path) {
                request.host = host;
            } else {
                "mbmodule-mainopenapi.paas.cmbchina.com".clone_into(&mut request.host);
            }
            return;
        }
        if looks_like_ccb_touch_po(&request.path) {
            "touch.ccb.com".clone_into(&mut request.host);
            return;
        }
        if looks_like_ccb_mbsmps(&request.path) {
            "xc.mp3.ccb.cn".clone_into(&mut request.host);
            return;
        }
        if looks_like_cmb_avatar_path(&request.path) {
            if let Some(host) = self.observed_cmb_avatar_host(pid) {
                request.host = host;
            } else {
                // cycle-040511 GET s3gw.cmbimg.cn/…/lx3301-avatar orig=200.
                "s3gw.cmbimg.cn".clone_into(&mut request.host);
            }
            return;
        }
        // Path-constrained last-resort so pairing sees a Host mid-session
        // (same-stream companions inherit via last_url). Unique unbound SNI
        // still wins first via match_observed_host / by_stream above.
        if is_mgw_request(request) {
            "mobilegw.alipay.com".clone_into(&mut request.host);
        }
    }

    fn match_observed_host(&self, request: &MirroredMessage, pid: u32) -> Option<String> {
        if !is_mgw_request(request) {
            return None;
        }
        let mut pick: Option<String> = None;
        let mut conflict = false;
        let mut consider = |host: &str| {
            if conflict || !is_gateway_host(host) {
                return;
            }
            match pick.as_deref() {
                None => pick = Some(host.to_owned()),
                Some(existing) if existing.eq_ignore_ascii_case(host) => {}
                Some(_) => {
                    pick = None;
                    conflict = true;
                }
            }
        };
        for ((process, _), host) in &self.by_stream {
            if *process == pid {
                consider(host);
            }
        }
        if let Some(list) = self.unbound.get(&pid) {
            for host in list {
                consider(host);
            }
        }
        if let Some(list) = self.by_pid.get(&pid) {
            for host in list {
                consider(host);
            }
        }
        pick
    }

    fn cmb_host_for_path(&self, pid: u32, path: &str) -> Option<String> {
        let mut module = None;
        let mut api = None;
        let mut log = None;
        let mut consider = |host: &str| {
            let lower = host.to_ascii_lowercase();
            if !lower.contains("cmbchina.com") || !looks_like_mirror_host(host) {
                return;
            }
            if lower.starts_with("log.") {
                if log.is_none() {
                    log = Some(host.to_owned());
                }
            } else if lower.contains("mbmodule") || lower.contains("mainopenapi") {
                if module.is_none() {
                    module = Some(host.to_owned());
                }
            } else if is_cmb_mainpage_host(host) && api.is_none() {
                api = Some(host.to_owned());
            }
        };
        for ((process, _), host) in &self.by_stream {
            if *process == pid {
                consider(host);
            }
        }
        if let Some(list) = self.by_pid.get(&pid) {
            for host in list {
                consider(host);
            }
        }
        if let Some(list) = self.unbound.get(&pid) {
            for host in list {
                consider(host);
            }
        }
        if looks_like_cmb_log_path(path) {
            // SystemLogHandler → log.cmbchina.com only; never mobile/wangdun.
            log
        } else {
            module.or(api)
        }
    }

    fn fill_seal(&self, request: &mut MirroredMessage, pid: u32, stream: u64) {
        // Seal still only accepts API hosts. Session-wide non-telemetry
        // (acs.m.taobao.com, render.alipay.com) used to stamp hostless mgw
        // POSTs and hide them in Burp under the wrong site.
        self.fill(request, pid, stream);
        if looks_like_mirror_host(&request.host) {
            let reject = (looks_like_cmb_mainpage_path(&request.path)
                && !is_cmb_mainpage_host(&request.host))
                || (looks_like_cmb_log_path(&request.path) && !is_cmb_log_host(&request.host))
                || (is_alipay_dae_csv(request)
                    && !request.host.to_ascii_lowercase().contains("datagw"))
                || skip_inherited_cmb_avatar(&request.path, &request.host);
            if !reject {
                return;
            }
            request.host.clear();
        }
        // Handshake SNI on a tid that never saw this SSL*: use it only when
        // this pid has exactly one leftover unbound name. Two leftovers stay
        // missing-sni.invalid rather than guessing CDN vs API.
        if let Some(host) = self.unique_unbound(pid) {
            // Non-gateway leftover (render.alipay.com, …) must not stamp mgw
            // and must not skip the mobilegw last resort below.
            let skip_for_mgw = is_mgw_request(request) && !is_gateway_host(host);
            let skip_for_cmb =
                looks_like_cmb_mainpage_path(&request.path) && !is_cmb_mainpage_host(host);
            // SystemLogHandler must not inherit wangdungateway leftover
            // (cycle-233657 orig=0 on log POSTs stamped as wangdun).
            let skip_for_cmb_log = looks_like_cmb_log_path(&request.path) && !is_cmb_log_host(host);
            // Never invent wangdungateway onto a sibling RPC (cycle-235515
            // /mainpage/ + avatar sealed as wangdun leftover).
            let skip_wangdun = is_wangdun_host(host);
            // cycle-021444 D-VM/D-AE unique leftover was mobilegw → 2048-byte
            // diagnosis CSV sealed as POST mobilegw. Only datagw may stamp these.
            let skip_for_dae =
                is_alipay_dae_csv(request) && !host.to_ascii_lowercase().contains("datagw");
            let skip_for_avatar = skip_inherited_cmb_avatar(&request.path, host);
            if !(skip_for_mgw
                || skip_for_cmb
                || skip_for_cmb_log
                || skip_wangdun
                || skip_for_dae
                || skip_for_avatar)
            {
                host.clone_into(&mut request.host);
                return;
            }
        }
        // Last resort for Alipay gateway RPCs whose handshake SNI was never
        // copied. Prefer this over missing-sni.invalid on /mgw.htm.
        if is_mgw_request(request) {
            "mobilegw.alipay.com".clone_into(&mut request.host);
            return;
        }
        if request.path.to_ascii_lowercase().contains("/loggw") {
            "loggw.alipay.com".clone_into(&mut request.host);
            return;
        }
        if looks_like_cmb_log_path(&request.path) {
            if let Some(host) = self.cmb_host_for_path(pid, &request.path) {
                request.host = host;
            } else {
                "log.cmbchina.com".clone_into(&mut request.host);
            }
            return;
        }
        if looks_like_cmb_mainpage_path(&request.path) {
            if let Some(host) = self.cmb_host_for_path(pid, &request.path) {
                request.host = host;
            } else {
                "mbmodule-mainopenapi.paas.cmbchina.com".clone_into(&mut request.host);
            }
            return;
        }
        if is_alipay_dae_csv(request) {
            if let Some(host) = self.observed_datagw_host(pid) {
                request.host = host;
            } else {
                "datagw-edge.alipay.com".clone_into(&mut request.host);
            }
            return;
        }
        if looks_like_ccb_touch_po(&request.path) {
            "touch.ccb.com".clone_into(&mut request.host);
            return;
        }
        if looks_like_ccb_mbsmps(&request.path) {
            "xc.mp3.ccb.cn".clone_into(&mut request.host);
            return;
        }
        if looks_like_cmb_avatar_path(&request.path) {
            if let Some(host) = self.observed_cmb_avatar_host(pid) {
                request.host = host;
            } else {
                "s3gw.cmbimg.cn".clone_into(&mut request.host);
            }
        }
    }

    fn observed_datagw_host(&self, pid: u32) -> Option<String> {
        let mut pick = None;
        let mut consider = |host: &str| {
            if pick.is_some() {
                return;
            }
            let lower = host.to_ascii_lowercase();
            if lower.contains("datagw") && looks_like_mirror_host(host) {
                pick = Some(host.to_owned());
            }
        };
        for ((process, _), host) in &self.by_stream {
            if *process == pid {
                consider(host);
            }
        }
        if let Some(list) = self.by_pid.get(&pid) {
            for host in list {
                consider(host);
            }
        }
        if let Some(list) = self.unbound.get(&pid) {
            for host in list {
                consider(host);
            }
        }
        pick
    }

    fn observed_cmb_avatar_host(&self, pid: u32) -> Option<String> {
        let mut pick = None;
        let mut consider = |host: &str| {
            if pick.is_some() {
                return;
            }
            if is_cmb_avatar_host(host) && looks_like_mirror_host(host) {
                pick = Some(host.to_owned());
            }
        };
        for ((process, _), host) in &self.by_stream {
            if *process == pid {
                consider(host);
            }
        }
        if let Some(list) = self.by_pid.get(&pid) {
            for host in list {
                consider(host);
            }
        }
        if let Some(list) = self.unbound.get(&pid) {
            for host in list {
                consider(host);
            }
        }
        pick
    }
}

fn looks_like_cmb_avatar_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    path.contains("lx3301-avatar") || path.contains("avatar-prd-cos")
}

fn skip_inherited_cmb_avatar(path: &str, host: &str) -> bool {
    // cycle-035815 GET /s/…/lx3301-avatar… inherited mbmodule-mainopenapi.
    looks_like_cmb_avatar_path(path) && host.to_ascii_lowercase().contains("cmbchina")
}

fn looks_like_cmb_log_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    path.contains("systemloghandler") || path.contains("cmbbank_mobile")
}

fn looks_like_cmb_mainpage_path(path: &str) -> bool {
    path.to_ascii_lowercase().contains("/mainpage/")
}

fn is_wangdun_host(host: &str) -> bool {
    host.to_ascii_lowercase().contains("wangdungateway")
}

fn is_cmb_log_host(host: &str) -> bool {
    host.to_ascii_lowercase().starts_with("log.")
        && host.to_ascii_lowercase().contains("cmbchina.com")
}

fn is_cmb_api_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    lower.contains("cmbchina.com")
        && looks_like_mirror_host(host)
        && !lower.starts_with("log.")
        && !is_wangdun_host(host)
        && !is_telemetry_host(host)
}

fn is_cmb_mainpage_host(host: &str) -> bool {
    // cycle-071908 /mainpage/debit inherited aicustservicegateway.paas
    // (longpresswake sibling). Only hosts observed serving /mainpage/:
    // mbmodule-mainopenapi, mbmodule-openapi, dfpgw.
    let lower = host.to_ascii_lowercase();
    is_cmb_api_host(host)
        && (lower.contains("mbmodule") || lower.contains("mainopenapi") || lower.contains("dfpgw"))
        && !lower.contains("aicustservice")
}

fn remember_host_list(list: &mut Vec<String>, host: &str) {
    list.retain(|item| item != host);
    list.insert(0, host.to_owned());
    if list.len() > 32 {
        list.truncate(32);
    }
}

fn is_telemetry_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host.contains("turkey-sls")
        || host.contains("log.aliyuncs")
        || host.contains("alibabachengdun")
        || host.contains("umeng")
        || host.contains("mmstat")
        || host.contains("cnzz")
        || host.contains("crashlytics")
        || host.contains("google-analytics")
        || host.contains("alicdn.com")
        || host.contains("alipayobjects")
        || host.contains("datagw")
        || host.contains("loggw")
        || host.contains("mdn.")
        || host.contains("cdn-mum")
        || host.contains(".sls.")
        || host.contains("logs.alipay")
}

/// CCB imageadv / adv.gif hosts must not steal empty-host SSL_read meant for
/// ccbNewClient / mbsmps/txCtrl (cycle-021444 orig=0 on GET xc.mp3.ccb.cn).
fn is_ad_asset_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host.contains("imageadv")
        || host.contains("adpic")
        || host.contains("adv.ccb.com")
        || host.contains("image1.ccb.com")
        || host.contains("imageadv.ccb")
}

/// Pid-wide fill must never stamp these onto a sibling RPC (Alipay mgw vs ACS).
fn is_cdn_steal_host(host: &str) -> bool {
    if is_telemetry_host(host) {
        return true;
    }
    let host = host.to_ascii_lowercase();
    host.contains("acs.")
        || host.contains(".acs.")
        || host.contains("amdc")
        || host.contains("taobao.com")
        || host.contains("tmall.com")
}

fn is_gateway_host(host: &str) -> bool {
    if !looks_like_mirror_host(host) || is_cdn_steal_host(host) {
        return false;
    }
    let host = host.to_ascii_lowercase();
    host.contains("mobilegw")
        || host.contains("mgw.")
        || host.contains(".mgw")
        || host.starts_with("mgw")
        || host.contains("gateway")
        || host.contains("gw.alipay")
        || host.contains("mgs.alipay")
}

fn is_last_resort_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("mobilegw.alipay.com")
        || host.eq_ignore_ascii_case("loggw.alipay.com")
        || host.eq_ignore_ascii_case("datagw-edge.alipay.com")
        || host.eq_ignore_ascii_case("log.cmbchina.com")
        || host.eq_ignore_ascii_case("s3gw.cmbimg.cn")
        || host.eq_ignore_ascii_case("mbmodule-mainopenapi.paas.cmbchina.com")
}

fn is_cmb_avatar_host(host: &str) -> bool {
    // cycle-040511 COS was s3gw.cmbimg.cn. cycle-054138 observed
    // mbmodulecdn.cmbimg.cn for default.zip — must not stamp avatar.
    let lower = host.to_ascii_lowercase();
    lower.contains("s3gw") && lower.contains("cmbimg.cn")
}

fn looks_like_ccb_touch_po(path: &str) -> bool {
    // cycle-024809 hostless POST /po?v=3.0.2&t=a&aid=ccvcrg3werfpisbk
    // sealed missing-sni; every hosted copy of this RPC is touch.ccb.com.
    let path = path.to_ascii_lowercase();
    path.contains("/po?") && path.contains("aid=ccvcrg")
}

fn looks_like_ccb_mbsmps(path: &str) -> bool {
    // cycle-025652 hostless POST /mbsmps/V2/txCtrl — hosted copies are xc.mp3.ccb.cn.
    path.to_ascii_lowercase().contains("/mbsmps/")
}

fn is_alipay_dae_csv(request: &MirroredMessage) -> bool {
    // Alipay diagnosis CSV: D-AE / D-VM / D-MM (cycle-022500) + future D-??,
    // plus cycle-023449 H5-VM,2048-byte Android-container (not D-??).
    let body = request.body.as_slice();
    let d = body.get(..5).unwrap_or(&[]);
    if d.len() == 5
        && d[0] == b'D'
        && d[1] == b'-'
        && d[4] == b','
        && d[2].is_ascii_uppercase()
        && d[3].is_ascii_uppercase()
    {
        return true;
    }
    let h5 = body.get(..6).unwrap_or(&[]);
    h5.len() == 6
        && h5.starts_with(b"H5-")
        && h5[5] == b','
        && h5[3].is_ascii_uppercase()
        && h5[4].is_ascii_uppercase()
}

fn is_mgw_request(request: &MirroredMessage) -> bool {
    let path = request.path.to_ascii_lowercase();
    if path.contains("mgw.htm") || path.contains("/mgw") {
        return true;
    }
    if request.headers.iter().any(|(name, _)| {
        let name = name.to_ascii_lowercase();
        name == "operation-type"
            || name == "operationtype"
            || name.contains("mmtp-ext")
            || name.contains("mgw-ext")
            || name.contains("mgw_ext")
            || name == "x-simple-rpc"
            || name == "nb_url"
            || name == "nbappid"
            || name == "nbversion"
            // Alipay H2 mgw dictionary id; hostless protobuf POSTs use this
            // without Operation-Type / /mgw.htm (cycle-plaintext missing-sni).
            || name == "zstd-dict-id"
            // cycle-014740 hostless POST / companions of mgw (miniwua / x-ant-*).
            || name == "miniwua"
            || name == "x-ant-i18n-support"
            || name == "x-bs-apt"
            || name == "rpc-attr-version"
    }) {
        return true;
    }
    if request.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type")
            && value.to_ascii_lowercase().contains("application/protobuf")
    }) {
        return true;
    }
    // cycle-021923 H2 HEADERS-only POST / (hdrs=content-encoding,content-length)
    // sealed missing-sni before DATA arrived with zstd magic. D-AE CSV has
    // neither this header nor the magic.
    if request.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-encoding") && value.to_ascii_lowercase().contains("zstd")
    }) {
        return true;
    }
    // Host-less JSON/protobuf POSTs (no Operation-Type header) still belong
    // to mgw when the body carries gateway RPC fields.
    let body = request
        .body
        .get(..request.body.len().min(256))
        .unwrap_or(&[]);
    [
        b"alipaySsoToken".as_slice(),
        b"operationType",
        b"commonParas",
        b"\"bizType\"",
        // Protobuf length-prefixed (0x11=17) — not the D-AE CSV token.
        b"\x11Android-container",
        // cycle-011833 hostless application/protobuf pullDown/lat-lng
        // sealed missing-sni; D-AE CSV does not contain this token.
        b"pullDown",
        // cycle-013733 hostless JSON baseInfoReq/appIds sealed missing-sni.
        b"baseInfoReq",
        // cycle-021923 hostless POST / with content-encoding and zstd magic
        // (0x28 0xB5 0x2F 0xFD) sealed missing-sni; D-AE CSV is ASCII.
        b"\x28\xb5\x2f\xfd",
        // cycle-004347 POST /mgw.htm application/protobuf carried this
        // stable 64-hex token; cycle-045950 lost path/headers and sealed
        // missing-sni. D-AE CSV does not contain it.
        b"@928566fe2744232d",
    ]
    .into_iter()
    .any(|needle| body.windows(needle.len()).any(|window| window == needle))
}

fn rpc_hostless_hint(request: &MirroredMessage) -> String {
    let mut parts = Vec::new();
    let names: Vec<&str> = request
        .headers
        .iter()
        .map(|(name, _)| name.as_str())
        .take(12)
        .collect();
    if !names.is_empty() {
        parts.push(format!("hdrs={}", names.join(",")));
    }
    for (name, value) in &request.headers {
        let lower = name.to_ascii_lowercase();
        if lower == "operation-type"
            || lower == "content-type"
            || lower == "x-mpaas-envelope"
            || lower == "mqp-apiver"
            || lower == "nb_url"
            || lower == "x-simple-rpc"
            || lower == "nbappid"
        {
            parts.push(format!("{name}={value}"));
        }
    }
    if !request.body.is_empty() {
        let take = request.body.len().min(64);
        let preview = String::from_utf8_lossy(&request.body[..take]).replace('\n', " ");
        parts.push(format!("body={preview:?}"));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" {}", parts.join(" "))
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
/// Mirror mode often sees SSL_read bodies arrive hundreds of ms to a few
/// seconds after SSL_write; 2s was flushing unpaired (Burp 204) too early.
const PAIRING_GRACE: Duration = Duration::from_secs(12);
/// POSTs (mgw / GetQrpay / ccbNewClient) often see SSL_read hundreds of ms
/// to tens of seconds later; 30s was still flushing orig=0 before seal.
const POST_PAIRING_GRACE: Duration = Duration::from_secs(50);
/// Tid-only stream_key when SSL* is not yet known. High bit so it cannot
/// collide with a userspace SSL object pointer (`connection_id >= 0x1000`).
const TID_STREAM_FLAG: u64 = 0x8000_0000_0000_0000;
const PENDING_HOSTLESS_CAP: usize = 32;

fn tid_stream_key(tid: u32) -> u64 {
    TID_STREAM_FLAG | u64::from(tid)
}

fn is_tid_stream_key(key: u64) -> bool {
    key & TID_STREAM_FLAG != 0
}
/// How long an unmatched SSL_read response is kept for a late SSL_write.
/// Hostless requests used to sit on the producer until session-end (~35s)
/// while this 12s window dropped the already-copied SSL_read → orig=0.
const ORPHAN_RESPONSE_GRACE: Duration = Duration::from_secs(90);
/// Cap orphan responses per (pid, stream/conn key) to bound memory.
const ORPHAN_RESPONSE_CAP: usize = 16;
/// Soft-flush incomplete HTTP/1 responses after recv goes idle so partial
/// chunked/CL bodies can still pair before PAIRING_GRACE expires.
const RECV_SOFT_FLUSH_IDLE: Duration = Duration::from_millis(500);
/// Soft-finish H2 send streams after HEADERS without END_STREAM (Alipay).
/// Longer than recv so DATA coalesces; HTTP/1 send is never soft-flushed.
const SEND_SOFT_FLUSH_IDLE: Duration = Duration::from_millis(800);
/// How long a tid→connection_id sticky entry remains usable.
const TID_CONNECTION_STICKY: Duration = Duration::from_secs(90);
/// Maximum requests held per process before the oldest flushes unpaired.
const PENDING_CAP: usize = 32;
const STREAM_CAP: usize = 256;
const RETRY_CAP: usize = 128;
const MAX_DELIVERY_ATTEMPTS: u8 = 6;
/// Probe double-fires land within a few milliseconds; keep this short so
/// back-to-back identical requests on the same connection are not eaten.
const FRAGMENT_DEBOUNCE: Duration = Duration::from_millis(25);
/// Peek preview window: matching recv within this time wins as canonical.
const PEEK_MATCH_WINDOW: Duration = Duration::from_millis(1500);
/// Promote unmatched peek as low-confidence inbound after this idle.
const PEEK_PROMOTE_IDLE: Duration = Duration::from_millis(2500);
/// How long a promoted peek fingerprint can still be invalidated by a read.
const PROMOTED_PEEK_RETAIN: Duration = Duration::from_secs(8);
const PENDING_PEEK_CAP: usize = 64;
/// Retain last accepted fragment bytes for progressive/truncated coalesce.
const LAST_FRAGMENT_CAP: usize = 64 * 1024;
/// Short absolute probe — avoid 14s×2 stalls when Clash/VPN cannot reach origin.
const ABS_PROBE_TIMEOUT: Duration = Duration::from_millis(1_800);
/// After this many consecutive absolute timeouts, skip absolute for the session.
const ABS_TIMEOUT_SKIP_AFTER: u64 = 3;
/// Playback / identity delivery read budget (LAN :18081).
const PLAYBACK_READ_TIMEOUT: Duration = Duration::from_secs(10);
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
            eprintln!("burp-mirror playback bind :{BURP_PLAYBACK_PORT} failed; legacy :18081 fetch unavailable");
        }
        if let Ok(listener) = TcpListener::bind(("0.0.0.0", BURP_UPSTREAM_PORT)) {
            let queue = Arc::clone(&queue);
            let stop = Arc::clone(&stop);
            let _ = std::thread::Builder::new()
                .name("ksight-burp-upstream".to_owned())
                .spawn(move || upstream_loop(&listener, &queue, &stop));
        } else {
            eprintln!(
                "burp-mirror upstream bind :{BURP_UPSTREAM_PORT} failed; set Burp upstream to phone:{BURP_UPSTREAM_PORT} after freeing the port"
            );
        }
        let (tx, rx) = mpsc::channel();
        let worker_queue = Arc::clone(&queue);
        let delivery_metrics = Arc::new(DeliveryMetrics::default());
        let worker_metrics = Arc::clone(&delivery_metrics);
        let worker_session_id = session_id.clone();
        let recv_busy_pids = Arc::new(Mutex::new(HashSet::new()));
        let worker_recv_busy = Arc::clone(&recv_busy_pids);
        let peer_book = Arc::new(Mutex::new(PeerHostBook::default()));
        let worker_peers = Arc::clone(&peer_book);
        let worker = std::thread::Builder::new()
            .name("ksight-burp-mirror".to_owned())
            .spawn(move || {
                worker_loop(
                    endpoint,
                    &rx,
                    &worker_queue,
                    &worker_metrics,
                    &worker_session_id,
                    &worker_recv_busy,
                    &worker_peers,
                );
            })
            .ok();
        log_mirror(
            &session_id,
            &format!(
                "burp-mirror session-start endpoint={endpoint} playback={BURP_PLAYBACK_PORT} upstream={BURP_UPSTREAM_PORT} abs_probe_ms={} form=absolute",
                ABS_PROBE_TIMEOUT.as_millis()
            ),
        );
        Ok(Self {
            tx,
            delivery_metrics,
            network_connects: 0,
            network_handshakes: 0,
            observed_fragments: 0,
            observed_bytes: 0,
            reconstructed_messages: 0,
            reconstructed_requests: 0,
            reconstructed_responses: 0,
            send_fragments: 0,
            recv_fragments: 0,
            rejected_fragments: 0,
            duplicate_fragments: 0,
            duplicate_probe: 0,
            duplicate_suppressed_progress: 0,
            fragment_pushes_without_message: 0,
            evicted_streams: 0,
            hostless_requests: 0,
            queue_failures: 0,
            standard_tls_fragments: 0,
            vendor_fragments: 0,
            jni_fragments: 0,
            handshake_fragments: 0,
            stack_coverage: StackCoverageSnapshot::default(),
            streams: HashMap::new(),
            peer_hosts: HashMap::new(),
            last_url: HashMap::new(),
            recent_url: HashMap::new(),
            recent_peer: HashMap::new(),
            pending_hostless: VecDeque::new(),
            peer_book,
            session_id,
            recent_fragments: HashMap::new(),
            tid_connection: HashMap::new(),
            pending_tid_sni: HashMap::new(),
            content_seen: HashMap::new(),
            pending_peeks: VecDeque::new(),
            promoted_peeks: VecDeque::new(),
            keylog_secrets: Vec::new(),
            recv_busy_pids,
            stop,
            worker,
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
        metrics.insert("network_connects".to_owned(), self.network_connects);
        metrics.insert("network_handshakes".to_owned(), self.network_handshakes);
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
        metrics.insert("send_fragments".to_owned(), self.send_fragments);
        metrics.insert("recv_fragments".to_owned(), self.recv_fragments);
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
        metrics.insert("duplicate_probe".to_owned(), self.duplicate_probe);
        metrics.insert(
            "duplicate_suppressed_progress".to_owned(),
            self.duplicate_suppressed_progress,
        );
        metrics.insert(
            "fragment_pushes_without_message".to_owned(),
            self.fragment_pushes_without_message,
        );
        metrics.insert("evicted_streams".to_owned(), self.evicted_streams);
        metrics.insert("hostless_requests".to_owned(), self.hostless_requests);
        metrics.insert("queue_failures".to_owned(), self.queue_failures);
        metrics.insert(
            "standard_tls_fragments".to_owned(),
            self.standard_tls_fragments,
        );
        metrics.insert("vendor_fragments".to_owned(), self.vendor_fragments);
        metrics.insert("jni_fragments".to_owned(), self.jni_fragments);
        metrics.insert("handshake_fragments".to_owned(), self.handshake_fragments);
        metrics.insert(
            "stack_candidates".to_owned(),
            self.stack_coverage.candidates,
        );
        metrics.insert(
            "stack_export_candidates".to_owned(),
            self.stack_coverage.export_candidates,
        );
        metrics.insert(
            "stack_pinned_boundaries".to_owned(),
            self.stack_coverage.pinned_boundaries,
        );
        metrics.insert(
            "stack_empirical_boundaries".to_owned(),
            self.stack_coverage.empirical_boundaries,
        );
        metrics.insert(
            "stack_keylog_candidates".to_owned(),
            self.stack_coverage.keylog_candidates,
        );
        metrics.insert("stack_uncovered".to_owned(), self.stack_coverage.uncovered);
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

    /// Count an in-scope L0 connect without retaining its endpoint.
    pub fn observe_network_connect(&mut self) {
        self.network_connects = self.network_connects.saturating_add(1);
    }

    /// Count an in-scope first-write/handshake observation without retaining bytes.
    pub fn observe_network_handshake(&mut self) {
        self.network_handshakes = self.network_handshakes.saturating_add(1);
    }

    /// Replace the current mapped stack inventory after a throttled maps scan.
    pub fn set_stack_coverage(&mut self, snapshot: StackCoverageSnapshot) {
        self.stack_coverage = snapshot;
    }

    /// Remember SNI / HTTP Host / `ip:port` from L0 first-write for this process.
    /// Used to fill empty Host on reconstructed HTTP. Does not emit a synthetic
    /// `GET /` — those are not replayable API calls.
    pub fn observe_peer(&mut self, pid: u32, host: String) {
        self.observe_peer_on_thread(pid, 0, host);
    }

    /// Bind handshake/connect SNI to the SSL connection this thread uses next.
    /// `tid == 0` records the name only; it never fills a different connection.
    pub fn observe_peer_on_thread(&mut self, pid: u32, tid: u32, host: String) {
        if pid == 0 || !looks_like_mirror_host(&host) {
            return;
        }
        self.peer_hosts.entry(pid).or_default().insert(host.clone());
        if !is_telemetry_host(&host) {
            self.recent_peer.insert(pid, host.clone());
        } else {
            self.recent_peer.entry(pid).or_insert_with(|| host.clone());
        }
        let bound_cid = if let Ok(mut book) = self.peer_book.lock() {
            book.remember(pid, &host);
            if tid != 0 {
                if let Some((cid, _)) = self.tid_connection.get(&(pid, tid)).copied() {
                    book.bind_stream(pid, cid, &host);
                    Some(cid)
                } else {
                    self.pending_tid_sni.insert((pid, tid), host.clone());
                    book.remember_unbound(pid, &host);
                    // Single waiting SSL* on this pid: hostless /mgw.htm takes
                    // this handshake SNI when it is a gateway name (not CDN).
                    if is_gateway_host(&host) && !is_wangdun_host(&host) {
                        if let Some((stream, true)) = self.unique_waiting_hostless_stream(pid) {
                            book.bind_stream(pid, stream, &host);
                            Some(stream)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            } else {
                None
            }
        } else if tid != 0 {
            self.tid_connection
                .get(&(pid, tid))
                .map(|(cid, _)| *cid)
                .or_else(|| {
                    self.pending_tid_sni.insert((pid, tid), host.clone());
                    None
                })
        } else {
            None
        };
        if let Some(cid) = bound_cid {
            self.retry_pending_hostless_stream(pid, cid);
        } else {
            self.retry_pending_hostless(pid);
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
        // SSL_peek / consumes=false: preview evidence only — do not advance
        // the stream cursor. A later recv that shares a prefix is canonical.
        if direction == "peek" {
            let stream_key = self.stream_key_for(pid, tid, connection_id);
            self.record_peek(pid, stream_key, adapter, bytes);
            return;
        }
        // Conscrypt/BIO noise: all-zero SSL_write copies inflate Unknown send
        // buffers (BOC leftover buffered_bytes / unknown_directions) and never
        // promote to HTTP. Drop before stream accounting.
        if is_inert_tls_fragment(bytes) {
            self.rejected_fragments = self.rejected_fragments.saturating_add(1);
            return;
        }
        // Flush idle recv/send from sibling streams before accepting new bytes so
        // partial SSL_read HTTP / H2 HEADERS can pair before PAIRING_GRACE.
        self.soft_flush_idle_recv();
        self.soft_flush_idle_send();
        self.observed_fragments = self.observed_fragments.saturating_add(1);
        self.observed_bytes = self
            .observed_bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if adapter.starts_with("tls_ssl") {
            self.standard_tls_fragments = self.standard_tls_fragments.saturating_add(1);
        } else if adapter.starts_with("vendor_boundary:") {
            self.vendor_fragments = self.vendor_fragments.saturating_add(1);
        } else if adapter.starts_with("jni_") {
            self.jni_fragments = self.jni_fragments.saturating_add(1);
        } else if adapter == "handshake_http" {
            self.handshake_fragments = self.handshake_fragments.saturating_add(1);
        }
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
        let stream_key = self.stream_key_for(pid, tid, connection_id);
        if adapter.starts_with("jni_") {
            // JNI strings fill Host on parked TLS requests. HTTP-shaped JNI
            // copies join the same stream as TLS; URL-only copies stay Host
            // evidence / synthetic GET.
            let absorbed = self.absorb_copy_hosts(pid, tid, stream_key, adapter, bytes);
            let http_like = ksight_core::looks_like_http_plain(bytes);
            if !http_like {
                if absorbed {
                    return;
                }
                if let Some(request) = request_from_http_url(bytes) {
                    if url_host_is_api_fill(&request.host) && path_is_printable_url(&request.path) {
                        self.reconstructed_messages = self.reconstructed_messages.saturating_add(1);
                        self.reconstructed_requests = self.reconstructed_requests.saturating_add(1);
                        self.emit_request(pid, stream_key, request);
                    }
                }
                return;
            }
        }
        let _ = self.absorb_copy_hosts(pid, tid, stream_key, adapter, bytes);
        if let Some(request) = request_from_http_url(bytes) {
            self.reconstructed_messages = self.reconstructed_messages.saturating_add(1);
            self.reconstructed_requests = self.reconstructed_requests.saturating_add(1);
            self.emit_request(pid, stream_key, request);
            return;
        }
        let decrypted_store;
        let bytes = if looks_like_tls_record(bytes) {
            match ksight_core::decrypt_tls_application_data(bytes, &self.keylog_secrets) {
                Some(plain) if !plain.is_empty() => {
                    decrypted_store = plain;
                    decrypted_store.as_slice()
                }
                _ => bytes,
            }
        } else {
            bytes
        };
        if self.remember_content(pid, bytes)
            && (adapter.starts_with("jni_") || adapter.starts_with("vendor_boundary:"))
        {
            return;
        }
        let outbound = outbound_copy(adapter, direction, bytes);
        if outbound {
            self.send_fragments = self.send_fragments.saturating_add(1);
        } else {
            // Prefer consuming read over prior peek with shared prefix,
            // including peeks already past PEEK_MATCH_WINDOW / promote start.
            let stream_key = self.stream_key_for(pid, tid, connection_id);
            self.suppress_peeks_matched_by_recv(pid, stream_key, bytes);
            if self.invalidate_promoted_peek_matched_by_recv(pid, stream_key, bytes) {
                self.duplicate_fragments = self.duplicate_fragments.saturating_add(1);
                return;
            }
            self.recv_fragments = self.recv_fragments.saturating_add(1);
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
        {
            let stream = self
                .streams
                .entry((pid, stream_key))
                .or_insert_with(new_direction_streams);
            stream.last_seen = Instant::now();
        }

        // Snapshot stream-direction state so recent_fragments can be updated
        // without holding a borrow across &mut self helper calls.
        let (accepted_before, already_applied, stale_shorter, progressive_tail) = {
            let stream = self
                .streams
                .get(&(pid, stream_key))
                .expect("stream inserted above");
            let accepted_before = if outbound {
                stream.send_accepted
            } else {
                stream.recv_accepted
            };
            let assembler = if outbound { &stream.send } else { &stream.recv };
            let last = if outbound {
                stream.send_last.as_slice()
            } else {
                stream.recv_last.as_slice()
            };
            let already_applied = assembler.ends_with(bytes);
            let stale_shorter =
                !last.is_empty() && last.starts_with(bytes) && last.len() > bytes.len();
            let progressive_tail = if !last.is_empty()
                && bytes.starts_with(last)
                && bytes.len() > last.len()
                && assembler.ends_with(last)
            {
                Some(last.len())
            } else {
                None
            };
            (
                accepted_before,
                already_applied,
                stale_shorter,
                progressive_tail,
            )
        };

        if already_applied || stale_shorter {
            self.duplicate_fragments = self.duplicate_fragments.saturating_add(1);
            self.duplicate_probe = self.duplicate_probe.saturating_add(1);
            return;
        }

        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        let hash = hasher.finish();
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        let now = Instant::now();
        let recent_key = (pid, stream_key, outbound);
        if let Some(prev) = self.recent_fragments.get(&recent_key) {
            let same_bytes = prev.hash == hash && prev.len == len;
            let within = now.duration_since(prev.seen_at) <= FRAGMENT_DEBOUNCE;
            if same_bytes && within && prev.pos_after == accepted_before {
                self.duplicate_fragments = self.duplicate_fragments.saturating_add(1);
                self.duplicate_probe = self.duplicate_probe.saturating_add(1);
                return;
            }
            if same_bytes && prev.pos_after != accepted_before {
                self.duplicate_suppressed_progress =
                    self.duplicate_suppressed_progress.saturating_add(1);
            }
        }

        let push_bytes: &[u8] = if let Some(start) = progressive_tail {
            self.duplicate_suppressed_progress =
                self.duplicate_suppressed_progress.saturating_add(1);
            &bytes[start..]
        } else {
            bytes
        };

        let stream = self
            .streams
            .get_mut(&(pid, stream_key))
            .expect("stream inserted above");
        let messages = if outbound {
            stream.send.push(push_bytes)
        } else {
            stream.recv.push(push_bytes)
        };
        // HEAD responses never carry a body even when Content-Length is set.
        if outbound {
            for message in &messages {
                if message.is_request && message.method.eq_ignore_ascii_case("HEAD") {
                    stream.recv.expect_head_response();
                    break;
                }
            }
        }
        let added = u64::try_from(push_bytes.len()).unwrap_or(u64::MAX);
        if outbound {
            stream.send_accepted = stream.send_accepted.saturating_add(added);
            replace_last_fragment(&mut stream.send_last, bytes);
            stream.send_last_seen = Instant::now();
        } else {
            stream.recv_accepted = stream.recv_accepted.saturating_add(added);
            replace_last_fragment(&mut stream.recv_last, bytes);
            stream.recv_last_seen = Instant::now();
        }
        let pos_after = if outbound {
            stream.send_accepted
        } else {
            stream.recv_accepted
        };
        self.recent_fragments.insert(
            recent_key,
            RecentFragment {
                hash,
                len,
                pos_after,
                seen_at: Instant::now(),
            },
        );
        if self.recent_fragments.len() > 512 {
            let trim_now = Instant::now();
            self.recent_fragments
                .retain(|_, seen| trim_now.duration_since(seen.seen_at) <= Duration::from_secs(2));
        }
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
        self.soft_flush_idle_recv();
        self.soft_flush_idle_send();
        self.refresh_recv_busy();
    }

    /// Prefer SSL*/connection_id when present; otherwise reuse a recent tid sticky
    /// mapping so write/read on OkHttp pools still share one stream_key.
    fn stream_key_for(&mut self, pid: u32, tid: u32, connection_id: Option<u64>) -> u64 {
        let real_cid = connection_id.filter(|value| *value >= 0x1000);
        let prev = self.tid_connection.get(&(pid, tid)).copied();
        let cid = if let Some(cid) = real_cid {
            if let Some((prev_cid, _)) = prev {
                if is_tid_stream_key(prev_cid) && prev_cid != cid {
                    self.migrate_stream_key(pid, prev_cid, cid);
                }
            }
            cid
        } else if let Some((cid, seen)) = prev {
            if Instant::now().duration_since(seen) <= TID_CONNECTION_STICKY {
                cid
            } else {
                tid_stream_key(tid)
            }
        } else {
            tid_stream_key(tid)
        };
        self.tid_connection
            .insert((pid, tid), (cid, Instant::now()));
        if self.tid_connection.len() > 1024 {
            let now = Instant::now();
            self.tid_connection
                .retain(|_, (_, seen)| now.duration_since(*seen) <= TID_CONNECTION_STICKY);
        }
        if let Some(host) = self.pending_tid_sni.remove(&(pid, tid)) {
            if let Ok(mut book) = self.peer_book.lock() {
                book.bind_stream(pid, cid, &host);
            }
            self.retry_pending_hostless_stream(pid, cid);
        }
        cid
    }

    fn migrate_stream_key(&mut self, pid: u32, from: u64, to: u64) {
        if from == to {
            return;
        }
        if let Ok(mut book) = self.peer_book.lock() {
            book.rebind_stream(pid, from, to);
        }
        for item in &mut self.pending_hostless {
            if item.0 == pid && item.1 == from {
                item.1 = to;
            }
        }
        if let Some(from_stream) = self.streams.remove(&(pid, from)) {
            self.streams.entry((pid, to)).or_insert(from_stream);
        }
        if let Some(url) = self.last_url.remove(&(pid, from)) {
            self.last_url.entry((pid, to)).or_insert(url);
        }
        self.retry_pending_hostless_stream(pid, to);
    }

    /// Emit incomplete recv HTTP messages after a short idle gap so pairing can
    /// attach SSL_read bodies that never see a terminal chunk / full CL.
    fn soft_flush_idle_recv(&mut self) {
        self.promote_stale_peeks();
        let now = Instant::now();
        let mut flushed = Vec::new();
        for ((pid, stream_id), streams) in &mut self.streams {
            if streams.recv.buffered_bytes() == 0 {
                continue;
            }
            if now.duration_since(streams.recv_last_seen) < RECV_SOFT_FLUSH_IDLE {
                continue;
            }
            // Never soft-flush HTTP/1 send here: multipart uploads must stay intact.
            // Recv idle also salvages H2 DATA-only so pairing beats PAIRING_GRACE.
            for message in streams.recv.recv_idle_flush() {
                flushed.push((*pid, *stream_id, message));
            }
        }
        for (pid, stream_id, message) in flushed {
            self.reconstructed_messages = self.reconstructed_messages.saturating_add(1);
            if message.is_request {
                self.reconstructed_requests = self.reconstructed_requests.saturating_add(1);
            } else {
                self.reconstructed_responses = self.reconstructed_responses.saturating_add(1);
            }
            self.handle_message(pid, stream_id, message);
        }
    }

    /// Soft-finish idle HTTP/2 *send* streams that decoded HEADERS but never
    /// saw END_STREAM (Alipay fragmented DATA / missed final write). HTTP/1
    /// send is intentionally skipped so multipart uploads stay intact.
    fn soft_flush_idle_send(&mut self) {
        let now = Instant::now();
        let mut flushed = Vec::new();
        for ((pid, stream_id), streams) in &mut self.streams {
            if streams.send.protocol() != "http2" {
                continue;
            }
            // H2 buffered_bytes may be 0 while open streams still hold HEADERS
            // waiting for END_STREAM — still soft-finish those.
            if now.duration_since(streams.send_last_seen) < SEND_SOFT_FLUSH_IDLE {
                continue;
            }
            for message in streams.send.soft_flush() {
                flushed.push((*pid, *stream_id, message));
            }
        }
        for (pid, stream_id, message) in flushed {
            self.reconstructed_messages = self.reconstructed_messages.saturating_add(1);
            if message.is_request {
                self.reconstructed_requests = self.reconstructed_requests.saturating_add(1);
            } else {
                self.reconstructed_responses = self.reconstructed_responses.saturating_add(1);
            }
            self.handle_message(pid, stream_id, message);
        }
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

    /// Pull API hosts out of JNI URL strings (and whole-buffer `https://…`
    /// copies) into the SNI book so a hostless TLS POST on the same pid can
    /// inherit them. Returns true when a parked hostless request was filled,
    /// in which case the caller must not also emit a synthetic GET.
    fn absorb_copy_hosts(
        &mut self,
        pid: u32,
        tid: u32,
        stream: u64,
        adapter: &str,
        bytes: &[u8],
    ) -> bool {
        let _ = tid;
        let mut urls = Vec::new();
        if let Some(request) = request_from_http_url(bytes) {
            urls.push(request);
        }
        if adapter.starts_with("jni_") {
            urls.extend(requests_from_embedded_http_urls(bytes));
        }
        if urls.is_empty() {
            return false;
        }
        let mut remembered = false;
        if let Ok(mut book) = self.peer_book.lock() {
            for url in &urls {
                if !url_host_is_api_fill(&url.host) {
                    continue;
                }
                book.remember(pid, &url.host);
                book.bind_stream(pid, stream, &url.host);
                remembered = true;
            }
        }
        if !remembered {
            return false;
        }
        let waiting = self
            .pending_hostless
            .iter()
            .any(|(pending_pid, _, request)| {
                *pending_pid == pid && urls.iter().any(|url| url_fills_hostless(url, request))
            });
        self.retry_pending_hostless(pid);
        waiting
    }

    fn emit_request(&mut self, pid: u32, stream_id: u64, mut request: MirroredMessage) {
        request.apply_gateway_rpc_hints();
        self.finish_request(pid, stream_id, &mut request);
        let mut hosted = looks_like_mirror_host(&request.host);
        if let Ok(mut book) = self.peer_book.lock() {
            if looks_like_mirror_host(&request.host) {
                book.remember(pid, &request.host);
                book.bind_stream(pid, stream_id, &request.host);
                hosted = true;
            } else {
                book.fill(&mut request, pid, stream_id);
                hosted = looks_like_mirror_host(&request.host);
            }
        }
        if hosted {
            self.retry_pending_hostless(pid);
        }
        if !looks_like_mirror_host(&request.host) {
            self.hostless_requests = self.hostless_requests.saturating_add(1);
            let hint = rpc_hostless_hint(&request);
            log_mirror(
                &self.session_id,
                &format!(
                    "burp-mirror hostless pid={pid} stream={stream_id} {} {}{hint} (waiting for API SNI)",
                    request.method, request.path
                ),
            );
            while self.pending_hostless.len() >= PENDING_HOSTLESS_CAP {
                let _ = self.pending_hostless.pop_front();
            }
            self.pending_hostless
                .push_back((pid, stream_id, request.clone()));
        }
        // Queue hostless immediately so SSL_read orphans can pair across
        // stream_key instead of waiting until seal (orig=0).
        self.queue_request(pid, stream_id, request);
    }

    fn queue_request(&mut self, pid: u32, stream_id: u64, request: MirroredMessage) {
        // Repeated requests to the same endpoint are meaningful.
        // Fragment-level debounce above removes duplicate probes
        // without suppressing those requests.
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
                // cycle-025223: GET jump.m.cmbchina.cn/pk.htm then POST
                // SystemLogHandler on the same stream inherited jump.m.
                // cycle-024809: D-AE CSV inherited same-stream mobilegw.
                let skip = (looks_like_cmb_log_path(&request.path) && !is_cmb_log_host(host))
                    || (looks_like_cmb_mainpage_path(&request.path) && !is_cmb_mainpage_host(host))
                    || skip_inherited_cmb_avatar(&request.path, host)
                    || (is_alipay_dae_csv(request)
                        && !host.to_ascii_lowercase().contains("datagw"));
                if !skip {
                    host.clone_into(&mut request.host);
                    if request.path == "/" {
                        path.clone_into(&mut request.path);
                    }
                }
            }
        }
        if request.host.is_empty() {
            if let Ok(book) = self.peer_book.lock() {
                book.fill(request, pid, stream_id);
            }
        }
        if !request.host.is_empty() {
            self.last_url.insert(
                (pid, stream_id),
                (request.host.clone(), request.path.clone()),
            );
            self.recent_url
                .insert(pid, (request.host.clone(), request.path.clone()));
            self.recent_peer.insert(pid, request.host.clone());
            self.peer_hosts
                .entry(pid)
                .or_default()
                .insert(request.host.clone());
        }
    }

    fn synthesize_request(
        &self,
        _pid: u32,
        _stream_id: u64,
        response: &MirroredMessage,
    ) -> Option<MirroredMessage> {
        // Immediate synthetic fallback may ONLY use response-intrinsic host
        // (Via / ACAO / Location / response.host). Filling from last_url /
        // recent_url invents GET /loggw/logUpload.do that steals SSL_read
        // bodies from real POSTs about to land → Burp orig=0 clusters.
        // True SSL_read-only visibility still works when Via/ACAO is clean;
        // otherwise the response stays orphan for late-request pairing.
        let request = response.synthetic_request_for_response();
        if looks_like_mirror_host(&request.host) {
            Some(request)
        } else {
            None
        }
    }

    fn unique_peer_host(&self, pid: u32) -> Option<&str> {
        let hosts = self.peer_hosts.get(&pid)?;
        (hosts.len() == 1)
            .then(|| hosts.iter().next().map(String::as_str))
            .flatten()
    }

    #[allow(dead_code)] // kept for finish_request/synth experiments; synth no longer fills last_url
    fn unique_url_for_pid(&self, pid: u32) -> Option<(&str, &str)> {
        let mut matches = self
            .last_url
            .iter()
            .filter(|((candidate_pid, _), _)| *candidate_pid == pid)
            .map(|(_, (host, path))| (host.as_str(), path.as_str()));
        let first = matches.next()?;
        matches.next().is_none().then_some(first)
    }

    /// Retry authority-less requests parked until SNI/peer arrived for `pid`.
    fn retry_pending_hostless(&mut self, pid: u32) {
        self.retry_pending_hostless_matching(pid, None);
    }

    fn retry_pending_hostless_stream(&mut self, pid: u32, stream: u64) {
        self.retry_pending_hostless_matching(pid, Some(stream));
    }

    fn retry_pending_hostless_matching(&mut self, pid: u32, stream: Option<u64>) {
        if self.pending_hostless.is_empty() {
            return;
        }
        let mut kept = VecDeque::new();
        while let Some((pending_pid, stream_id, mut request)) = self.pending_hostless.pop_front() {
            let same_stream = stream.is_none_or(|value| value == stream_id);
            if pending_pid != pid || !same_stream {
                kept.push_back((pending_pid, stream_id, request));
                continue;
            }
            self.finish_request(pending_pid, stream_id, &mut request);
            if let Ok(book) = self.peer_book.lock() {
                book.fill(&mut request, pending_pid, stream_id);
            }
            if !looks_like_mirror_host(&request.host) {
                kept.push_back((pending_pid, stream_id, request));
                continue;
            }
            // Already queued at emit; worker fills Host from peer_book.
        }
        self.pending_hostless = kept;
    }

    /// Unique parked hostless SSL* for `pid`. Second value is true when that
    /// waiter is an Alipay `/mgw.htm` (or gateway-header) request.
    fn unique_waiting_hostless_stream(&self, pid: u32) -> Option<(u64, bool)> {
        let mut only: Option<(u64, bool)> = None;
        for (pending_pid, stream, request) in &self.pending_hostless {
            if *pending_pid != pid {
                continue;
            }
            let mgw = is_mgw_request(request);
            match only {
                None => only = Some((*stream, mgw)),
                Some((existing, was_mgw)) if existing == *stream => {
                    only = Some((existing, was_mgw || mgw));
                }
                Some(_) => return None,
            }
        }
        only
    }

    /// Publish which pids still hold recv bytes so the worker can defer
    /// unpaired PAIRING_GRACE sweeps until orphan/HTTP soft-flush can pair.
    fn refresh_recv_busy(&self) {
        let Ok(mut busy) = self.recv_busy_pids.lock() else {
            return;
        };
        busy.clear();
        for ((pid, _), streams) in &self.streams {
            if streams.recv.buffered_bytes() > 0 {
                busy.insert(*pid);
            }
        }
    }

    /// Accept keylog lines (standard or probe-debug) for live tls_record decrypt.
    pub fn ingest_keylog_lines(&mut self, lines: &[String]) {
        if lines.is_empty() {
            return;
        }
        let joined = lines.join("\n");
        self.keylog_secrets
            .extend(ksight_core::parse_keylog(&joined));
        if self.keylog_secrets.len() > 256 {
            let drop = self.keylog_secrets.len() - 256;
            self.keylog_secrets.drain(..drop);
        }
    }

    fn remember_content(&mut self, pid: u32, bytes: &[u8]) -> bool {
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        let hash = hasher.finish();
        let now = Instant::now();
        let key = (pid, hash);
        if let Some(seen) = self.content_seen.get(&key) {
            if now.duration_since(*seen) <= Duration::from_millis(2500) {
                return true;
            }
        }
        self.content_seen.insert(key, now);
        if self.content_seen.len() > 1024 {
            self.content_seen
                .retain(|_, seen| now.duration_since(*seen) <= Duration::from_secs(8));
        }
        false
    }

    /// Inspect preview fallback when raw bytes were not attached.
    pub fn observe_plaintext(&mut self, pid: u32, tid: u32, fragment: &InspectPlaintext) {
        let bytes = fragment_bytes(
            &fragment.preview,
            &fragment.preview_encoding,
            &fragment.content_class,
        );
        let direction = if !fragment.consumes
            && (fragment.direction == "recv" || fragment.direction == "peek")
        {
            "peek"
        } else {
            fragment.direction.as_str()
        };
        self.observe_bytes(pid, tid, &fragment.adapter, direction, &bytes);
    }

    /// Store peek preview without advancing the assembler cursor.
    fn record_peek(&mut self, pid: u32, stream_key: u64, adapter: &str, bytes: &[u8]) {
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        let hash = hasher.finish();
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        let now = Instant::now();
        // Dedupe key: connection + direction(peek) + fingerprint + length + window.
        if self.pending_peeks.iter().any(|peek| {
            peek.pid == pid
                && peek.stream_key == stream_key
                && peek.hash == hash
                && peek.len == len
                && now.duration_since(peek.seen_at) <= PEEK_MATCH_WINDOW
        }) {
            self.duplicate_fragments = self.duplicate_fragments.saturating_add(1);
            return;
        }
        while self.pending_peeks.len() >= PENDING_PEEK_CAP {
            self.pending_peeks.pop_front();
        }
        self.pending_peeks.push_back(PendingPeek {
            pid,
            stream_key,
            hash,
            len,
            bytes: bytes.to_vec(),
            adapter: adapter.to_owned(),
            seen_at: now,
        });
        self.observed_fragments = self.observed_fragments.saturating_add(1);
    }

    fn suppress_peeks_matched_by_recv(&mut self, pid: u32, stream_key: u64, recv: &[u8]) {
        self.pending_peeks.retain(|peek| {
            if peek.pid != pid || peek.stream_key != stream_key {
                return true;
            }
            // Age must not keep a matching peek: a read arriving after
            // PEEK_MATCH_WINDOW (or after promote-window start) still wins.
            let share = recv.starts_with(&peek.bytes) || peek.bytes.starts_with(recv);
            !share
        });
    }

    /// After a peek was promoted, a matching read is still canonical: drop the
    /// promoted fingerprint and skip re-injecting the same bytes.
    fn invalidate_promoted_peek_matched_by_recv(
        &mut self,
        pid: u32,
        stream_key: u64,
        recv: &[u8],
    ) -> bool {
        let now = Instant::now();
        let mut matched = false;
        self.promoted_peeks.retain(|peek| {
            if now.saturating_duration_since(peek.seen_at) > PROMOTED_PEEK_RETAIN {
                return false;
            }
            if peek.pid != pid || peek.stream_key != stream_key {
                return true;
            }
            let share = recv.starts_with(&peek.bytes) || peek.bytes.starts_with(recv);
            if share {
                matched = true;
                return false;
            }
            true
        });
        matched
    }

    /// Promote timed-out peeks as low-confidence inbound (no matching read).
    fn promote_stale_peeks(&mut self) {
        let now = Instant::now();
        let mut promote = Vec::new();
        self.pending_peeks.retain(|peek| {
            if now.duration_since(peek.seen_at) < PEEK_PROMOTE_IDLE {
                return true;
            }
            promote.push(peek.clone());
            false
        });
        for peek in promote {
            // Feed as peek again would re-queue; push as low-confidence recv
            // without marking consumes. Use a tagged adapter so diagnostics
            // show the promotion path.
            let adapter = format!("{}:peek_promote", peek.adapter);
            // Directly push onto recv assembler as low-confidence evidence.
            self.push_promoted_peek(peek.pid, peek.stream_key, &adapter, &peek.bytes);
            while self.promoted_peeks.len() >= PENDING_PEEK_CAP {
                self.promoted_peeks.pop_front();
            }
            self.promoted_peeks.push_back(peek);
        }
    }

    fn push_promoted_peek(&mut self, pid: u32, stream_key: u64, adapter: &str, bytes: &[u8]) {
        if bytes.is_empty() || is_inert_tls_fragment(bytes) {
            return;
        }
        if !self.streams.contains_key(&(pid, stream_key)) && self.streams.len() >= STREAM_CAP {
            return;
        }
        let stream = self
            .streams
            .entry((pid, stream_key))
            .or_insert_with(new_direction_streams);
        stream.last_seen = Instant::now();
        let messages = stream.recv.push(bytes);
        let added = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        stream.recv_accepted = stream.recv_accepted.saturating_add(added);
        replace_last_fragment(&mut stream.recv_last, bytes);
        stream.recv_last_seen = Instant::now();
        self.recv_fragments = self.recv_fragments.saturating_add(1);
        let _ = adapter;
        for message in messages {
            // Low-confidence: still handle so Burp can see something when
            // SSL_read never arrived, but tag via existing path.
            self.reconstructed_messages = self.reconstructed_messages.saturating_add(1);
            if message.is_request {
                self.reconstructed_requests = self.reconstructed_requests.saturating_add(1);
            } else {
                self.reconstructed_responses = self.reconstructed_responses.saturating_add(1);
            }
            self.handle_message(pid, stream_key, message);
        }
    }
}

fn url_host_is_api_fill(host: &str) -> bool {
    if !looks_like_mirror_host(host) || is_wangdun_host(host) || is_ad_asset_host(host) {
        return false;
    }
    let lower = host.to_ascii_lowercase();
    is_gateway_host(host)
        || is_cmb_mainpage_host(host)
        || is_cmb_log_host(host)
        || is_cmb_avatar_host(host)
        || is_cmb_api_host(host)
        || lower.contains("datagw")
        || lower.contains("loggw")
        || (lower.contains("ccb.com") && !is_ad_asset_host(host))
        || lower.contains("ccb.cn")
        || lower.contains("boc.cn")
        || lower.contains("cmbchina.")
}

fn path_is_printable_url(path: &str) -> bool {
    !path.is_empty()
        && path.bytes().all(|byte| {
            byte.is_ascii()
                && (byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'/' | b'?' | b'=' | b'&' | b'%' | b'.' | b'-' | b'_' | b':' | b'+' | b'~'
                    ))
        })
}

fn url_fills_hostless(url: &MirroredMessage, hostless: &MirroredMessage) -> bool {
    if !url_host_is_api_fill(&url.host) {
        return false;
    }
    let url_path = url.path.to_ascii_lowercase();
    let hostless_path = hostless.path.to_ascii_lowercase();
    if looks_like_cmb_mainpage_path(&hostless_path) {
        return is_cmb_mainpage_host(&url.host)
            && (url_path.contains("/mainpage/") || hostless_path.contains("/mainpage/"));
    }
    if looks_like_cmb_log_path(&hostless_path) {
        return is_cmb_log_host(&url.host);
    }
    if is_alipay_dae_csv(hostless) {
        return url.host.to_ascii_lowercase().contains("datagw");
    }
    if is_mgw_request(hostless) {
        return is_gateway_host(&url.host);
    }
    if hostless_path.len() > 1
        && (hostless_path == url_path
            || url_path.starts_with(&hostless_path)
            || hostless_path.starts_with(&url_path))
    {
        return true;
    }
    false
}

fn looks_like_mirror_host(host: &str) -> bool {
    if host.is_empty()
        || host.starts_with('/')
        || host.contains("empty-sockaddr")
        || host.contains('*')
        || host.ends_with('+')
        || host.contains('[')
        // Android content/dirn URIs once leaked as Host (e.g. `dirn:-2:-2`).
        || host.starts_with("dirn:")
        || host.starts_with("content:")
    {
        return false;
    }
    host.contains('.') || host.contains(':')
}

fn fill_request_host_from_peers(
    request: &mut MirroredMessage,
    pid: u32,
    stream: u64,
    peer_book: &Mutex<PeerHostBook>,
) {
    let Ok(book) = peer_book.lock() else {
        return;
    };
    book.fill(request, pid, stream);
}

fn fill_request_host_for_seal(
    request: &mut MirroredMessage,
    pid: u32,
    stream: u64,
    peer_book: &Mutex<PeerHostBook>,
) {
    let Ok(book) = peer_book.lock() else {
        return;
    };
    book.fill_seal(request, pid, stream);
}

fn refresh_pending_hosts(
    pending: &mut HashMap<
        (u32, u64),
        VecDeque<(MirroredMessage, Option<MirroredMessage>, Instant)>,
    >,
    peer_book: &Mutex<PeerHostBook>,
) {
    for ((pid, stream_id), slot) in pending.iter_mut() {
        for (request, response, _) in slot.iter_mut() {
            if looks_like_mirror_host(&request.host) {
                continue;
            }
            fill_request_host_from_peers(request, *pid, *stream_id, peer_book);
            if !looks_like_mirror_host(&request.host) {
                if let Some(resp) = response.as_ref() {
                    if looks_like_mirror_host(&resp.host) && !is_cdn_steal_host(&resp.host) {
                        request.host.clone_from(&resp.host);
                    }
                }
            }
        }
    }
}

fn take_ready_pairs(
    pending: &mut HashMap<
        (u32, u64),
        VecDeque<(MirroredMessage, Option<MirroredMessage>, Instant)>,
    >,
) -> Vec<(MirroredMessage, Option<MirroredMessage>)> {
    let mut ready = Vec::new();
    for slot in pending.values_mut() {
        let mut kept = VecDeque::new();
        while let Some((request, response, queued_at)) = slot.pop_front() {
            if looks_like_mirror_host(&request.host) && response.is_some() {
                ready.push((request, response));
            } else {
                kept.push_back((request, response, queued_at));
            }
        }
        *slot = kept;
    }
    pending.retain(|_, slot| !slot.is_empty());
    ready
}

fn replace_last_fragment(slot: &mut Vec<u8>, bytes: &[u8]) {
    slot.clear();
    let take = bytes.len().min(LAST_FRAGMENT_CAP);
    slot.extend_from_slice(&bytes[..take]);
}

/// True for near-all-zero TLS copies that never look like HTTP (BIO/padding).
fn is_inert_tls_fragment(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    let nonzero = bytes.iter().filter(|byte| **byte != 0).count();
    // <5% nonzero ⇒ treat as inert padding / cleared buffer snapshot.
    nonzero.saturating_mul(20) < bytes.len()
}

fn outbound_copy(adapter: &str, direction: &str, bytes: &[u8]) -> bool {
    // Standard OpenSSL/BoringSSL/Conscrypt probes: adapter name is authoritative.
    // Mis-tagged direction must not park SSL_read plaintext on the send assembler
    // (unknown_directions / buffered responses that never pair).
    if adapter.contains("ssl_read") {
        return false;
    }
    if adapter.contains("ssl_write") {
        if bytes.starts_with(b"HTTP/1.0") || bytes.starts_with(b"HTTP/1.1") {
            return false;
        }
        return true;
    }
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

impl BurpMirror {
    /// Flush incomplete streams and join the delivery worker while playback
    /// ports are still up. Safe to call before reading `delivery_count` at
    /// capture end; `Drop` is a no-op if already sealed.
    pub fn seal(&mut self) {
        if self.worker.is_none() {
            return;
        }
        // Only flush incomplete streams when the capture ends. Flushing after
        // every SSL boundary hit would split a multipart/photo upload at the
        // first 64 KiB fragment and silently discard the remaining body.
        //
        // Recv uses seal_flush (soft_flush + orphan/incomplete-header salvage)
        // BEFORE Stop's unpaired flush so buffered SSL_read can still pair
        // (BOC: recon_resp=0 / buffered≈5KiB → orig=0).
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
                    .seal_flush()
                    .into_iter()
                    .map(|item| (*pid, *stream_id, item)),
            );
        }
        for (pid, stream_id, message) in pending {
            self.reconstructed_messages = self.reconstructed_messages.saturating_add(1);
            if message.is_request {
                self.reconstructed_requests = self.reconstructed_requests.saturating_add(1);
            } else {
                self.reconstructed_responses = self.reconstructed_responses.saturating_add(1);
            }
            self.handle_message(pid, stream_id, message);
        }
        self.refresh_recv_busy();
        // Last chance: SNI/peer may have landed after the hostless H2/HTTP
        // request was parked (or recent_url filled from a sibling stream).
        let pending_pids: Vec<u32> = self
            .pending_hostless
            .iter()
            .map(|(pid, _, _)| *pid)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        for pid in pending_pids {
            self.retry_pending_hostless(pid);
        }
        // Hostless requests were already queued for pairing; do not re-send.
        self.pending_hostless.clear();
        // Stop the worker first while playback :18081 is still accepting. Setting
        // `stop` earlier made Burp's fetch to 127.0.0.1:18081 fail at session-end
        // (upstream error / abandoned_retries) even when mid-run pairing worked.
        let _ = self.tx.send(MirrorJob::Stop);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for BurpMirror {
    fn drop(&mut self) {
        self.seal();
    }
}

fn worker_loop(
    endpoint: SocketAddr,
    rx: &mpsc::Receiver<MirrorJob>,
    queue: &Arc<Mutex<PlaybackStore>>,
    metrics: &DeliveryMetrics,
    session_id: &str,
    recv_busy_pids: &Mutex<HashSet<u32>>,
    peer_book: &Mutex<PeerHostBook>,
) {
    let absolute_timeout_streak = AtomicU64::new(0);
    let runtime = DeliveryRuntime {
        endpoint,
        queue,
        metrics,
        session_id,
        absolute_timeout_streak: &absolute_timeout_streak,
    };
    let mut pending: HashMap<
        (u32, u64),
        VecDeque<(MirroredMessage, Option<MirroredMessage>, Instant)>,
    > = HashMap::new();
    // Responses that arrived before their request (common on HTTP/2 / Alipay).
    let mut orphan_responses: HashMap<(u32, u64), VecDeque<(MirroredMessage, Instant)>> =
        HashMap::new();
    let mut retries = VecDeque::new();
    loop {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(MirrorJob::Stop) => {
                flush_pending(
                    &mut pending,
                    &mut orphan_responses,
                    &mut retries,
                    &runtime,
                    peer_book,
                );
                orphan_responses.clear();
                // Playback is still up (Drop joins us before flipping `stop`).
                // Give in-flight retries a short final window so paired orig≠0
                // bodies are not abandoned solely because of teardown ordering.
                let drain_deadline = Instant::now() + Duration::from_secs(12);
                while !retries.is_empty() && Instant::now() < drain_deadline {
                    sweep_retries(&runtime, &mut retries);
                    if retries.is_empty() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(40));
                }
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
                let mut request = *request;
                fill_request_host_from_peers(&mut request, pid, stream_id, peer_book);
                if let Some(response) =
                    take_orphan_response(&mut orphan_responses, pid, stream_id, &request)
                {
                    if !looks_like_mirror_host(&request.host)
                        && looks_like_mirror_host(&response.host)
                    {
                        request.host.clone_from(&response.host);
                    }
                    if !looks_like_mirror_host(&request.host) {
                        fill_request_host_for_seal(&mut request, pid, stream_id, peer_book);
                    }
                    if looks_like_mirror_host(&request.host) {
                        enqueue_delivery(&runtime, &mut retries, request, Some(response));
                    } else {
                        pending.entry((pid, stream_id)).or_default().push_back((
                            request,
                            Some(response),
                            Instant::now(),
                        ));
                    }
                } else {
                    let slot = pending.entry((pid, stream_id)).or_default();
                    while slot.len() >= PENDING_CAP {
                        match slot.pop_front() {
                            Some((mut stale, stale_resp, _)) => {
                                fill_request_host_from_peers(&mut stale, pid, stream_id, peer_book);
                                // Skip unpaired empty-host flushes — wait for SNI.
                                if looks_like_mirror_host(&stale.host) {
                                    enqueue_delivery(&runtime, &mut retries, stale, stale_resp);
                                }
                            }
                            None => break,
                        }
                    }
                    slot.push_back((request, None, Instant::now()));
                }
            }
            Ok(MirrorJob::Response {
                response,
                fallback,
                pid,
                stream_id,
            }) => {
                // 1xx (esp. 100 Continue) must not consume the pending request
                // pairing slot — the real response follows on the same stream.
                if response
                    .status
                    .is_some_and(|code| (100..200).contains(&code))
                {
                    continue;
                }
                let request = take_pending_for_response(&mut pending, pid, stream_id, &response)
                    .or_else(|| take_pending_for_pid(&mut pending, pid, &response.host))
                    .or_else(|| {
                        // Never invent synthetic while this pid still has pending
                        // requests — last_url-shaped GET would steal the body.
                        let pid_has_pending = pending
                            .iter()
                            .any(|((process, _), slot)| *process == pid && !slot.is_empty());
                        if pid_has_pending {
                            return None;
                        }
                        // Only synthesize when Via/ACAO/Location yielded a real host.
                        // Spanner Via junk used to steal the response as GET mobilegw-54…:7088[200
                        // while real mgw POSTs stayed hostless → Burp 204 / orig=0.
                        fallback.and_then(|fb| {
                            let mut fb = *fb;
                            fill_request_host_from_peers(&mut fb, pid, stream_id, peer_book);
                            looks_like_mirror_host(&fb.host).then_some(fb)
                        })
                    });
                if let Some(mut request) = request {
                    fill_request_host_from_peers(&mut request, pid, stream_id, peer_book);
                    if !looks_like_mirror_host(&request.host)
                        && looks_like_mirror_host(&response.host)
                    {
                        request.host.clone_from(&response.host);
                    }
                    if !looks_like_mirror_host(&request.host) {
                        fill_request_host_for_seal(&mut request, pid, stream_id, peer_book);
                    }
                    if looks_like_mirror_host(&request.host) {
                        enqueue_delivery(&runtime, &mut retries, request, Some(*response));
                    } else {
                        // Keep the pair until SNI/path fill or session seal.
                        // Storing the response as a TTL orphan used to drop
                        // Alipay SSL_read copies at 12s while hostless POSTs
                        // waited for mobilegw SNI.
                        pending.entry((pid, stream_id)).or_default().push_back((
                            request,
                            Some(*response),
                            Instant::now(),
                        ));
                    }
                } else {
                    // Keep for a late request on the same stream / host (Alipay H2).
                    store_orphan_response(&mut orphan_responses, pid, stream_id, *response);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                refresh_pending_hosts(&mut pending, peer_book);
                for (request, response) in take_ready_pairs(&mut pending) {
                    enqueue_delivery(&runtime, &mut retries, request, response);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        sweep_expired(
            &mut pending,
            &mut orphan_responses,
            &mut retries,
            &runtime,
            recv_busy_pids,
            peer_book,
        );
        sweep_orphan_responses(&mut orphan_responses);
        sweep_retries(&runtime, &mut retries);
    }
}

struct DeliveryRuntime<'a> {
    endpoint: SocketAddr,
    queue: &'a Mutex<PlaybackStore>,
    metrics: &'a DeliveryMetrics,
    session_id: &'a str,
    absolute_timeout_streak: &'a AtomicU64,
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
        runtime.absolute_timeout_streak,
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
            runtime.absolute_timeout_streak,
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

fn store_orphan_response(
    orphans: &mut HashMap<(u32, u64), VecDeque<(MirroredMessage, Instant)>>,
    pid: u32,
    stream_id: u64,
    response: MirroredMessage,
) {
    let slot = orphans.entry((pid, stream_id)).or_default();
    while slot.len() >= ORPHAN_RESPONSE_CAP {
        slot.pop_front();
    }
    slot.push_back((response, Instant::now()));
}

fn orphan_usable_for_request(request: &MirroredMessage, response: &MirroredMessage) -> bool {
    let req_hostless = !looks_like_mirror_host(&request.host);
    let same = looks_like_mirror_host(&request.host)
        && looks_like_mirror_host(&response.host)
        && (same_site(&response.host, &request.host)
            || response.host.eq_ignore_ascii_case(&request.host));
    if same {
        return true;
    }
    // datagw / turkey-sls / ACS must not steal empty-host API orphans.
    if is_cdn_steal_host(&request.host) || is_cdn_steal_host(&response.host) {
        return false;
    }
    // SystemLogHandler last-resorts log.cmbchina.com and must not take
    // empty-host SSL_read meant for GetRedPoint / wangdun APIs
    // (cycle-010644 orig=0 on wd-config/trtd while log POST orig=200).
    if looks_like_cmb_log_path(&request.path) && !looks_like_mirror_host(&response.host) {
        return false;
    }
    // CCB ads/gifs must not take empty-host SSL_read meant for txCtrl / ccbNewClient.
    if is_ad_asset_host(&request.host) && !looks_like_mirror_host(&response.host) {
        return false;
    }
    // Hostless Alipay mgw may take an empty-host SSL_read across stream_key.
    if req_hostless {
        return true;
    }
    if !looks_like_mirror_host(&response.host) && is_mgw_request(request) {
        return true;
    }
    // CCB ccbNewClient / CMB GetRedPoint: SSL_write and SSL_read disagree on
    // stream_key so the HTTP status copy has an empty Host. Pair it to a hosted
    // non-telemetry API when the reconstructed response actually has a status
    // (not a header-less salvage). datagw/ACS stay blocked above.
    !looks_like_mirror_host(&response.host)
        && looks_like_mirror_host(&request.host)
        && !is_cdn_steal_host(&request.host)
        && response.status.is_some()
}

fn take_orphan_response(
    orphans: &mut HashMap<(u32, u64), VecDeque<(MirroredMessage, Instant)>>,
    pid: u32,
    stream_id: u64,
    request: &MirroredMessage,
) -> Option<MirroredMessage> {
    // Prefer same connection/stream key.
    if let Some(slot) = orphans.get_mut(&(pid, stream_id)) {
        if let Some(h2_id) = request.stream_id {
            if let Some(idx) = slot
                .iter()
                .position(|(resp, _)| resp.stream_id == Some(h2_id))
            {
                return slot.remove(idx).map(|(response, _)| response);
            }
        }
        if let Some((response, _)) = slot.pop_front() {
            if slot.is_empty() {
                orphans.remove(&(pid, stream_id));
            }
            return Some(response);
        }
    }
    // Same pid, other stream_key: pair hostless ↔ empty-host, or same-host.
    // Never let datagw/ACS/turkey-sls steal an API orphan.
    let key = orphans
        .iter()
        .filter(|((process, key), slot)| *process == pid && *key != stream_id && !slot.is_empty())
        .filter(|(_, slot)| {
            slot.front()
                .is_some_and(|(resp, _)| orphan_usable_for_request(request, resp))
        })
        .min_by_key(|(_, slot)| {
            slot.front()
                .map(|(_, queued_at)| *queued_at)
                .unwrap_or_else(Instant::now)
        })
        .map(|(key, _)| *key)?;
    let slot = orphans.get_mut(&key)?;
    let (response, _) = slot.pop_front()?;
    if slot.is_empty() {
        orphans.remove(&key);
    }
    Some(response)
}

fn sweep_orphan_responses(orphans: &mut HashMap<(u32, u64), VecDeque<(MirroredMessage, Instant)>>) {
    let now = Instant::now();
    for slot in orphans.values_mut() {
        while let Some((_, queued_at)) = slot.front() {
            if now.duration_since(*queued_at) < ORPHAN_RESPONSE_GRACE {
                break;
            }
            slot.pop_front();
        }
    }
    orphans.retain(|_, slot| !slot.is_empty());
}

/// Pair a response to a pending request.
///
/// Prefer HTTP/2 `MirroredMessage.stream_id` match (multiplexed out-of-order
/// responses on one TLS connection) before FIFO `pop_front` on the TCP key.
fn take_pending_for_response(
    pending: &mut HashMap<
        (u32, u64),
        VecDeque<(MirroredMessage, Option<MirroredMessage>, Instant)>,
    >,
    pid: u32,
    conn_key: u64,
    response: &MirroredMessage,
) -> Option<MirroredMessage> {
    if let Some(h2_id) = response.stream_id {
        // Exact connection + H2 stream.
        if let Some(slot) = pending.get_mut(&(pid, conn_key)) {
            if let Some(idx) = slot
                .iter()
                .position(|(req, resp, _)| resp.is_none() && req.stream_id == Some(h2_id))
            {
                return slot.remove(idx).map(|(request, _, _)| request);
            }
        }
        // Same pid, any connection: H2 stream ids are unique per connection but
        // write/read may disagree on conn_key; still prefer H2 id over FIFO.
        let cross = pending
            .iter()
            .filter(|((process, _), slot)| *process == pid && !slot.is_empty())
            .find_map(|(key, slot)| {
                slot.iter()
                    .position(|(req, resp, _)| resp.is_none() && req.stream_id == Some(h2_id))
                    .map(|idx| (*key, idx))
            });
        if let Some((key, idx)) = cross {
            return pending
                .get_mut(&key)
                .and_then(|slot| slot.remove(idx))
                .map(|(request, _, _)| request);
        }
    }
    pending.get_mut(&(pid, conn_key)).and_then(|slot| {
        let idx = slot.iter().position(|(_, resp, _)| resp.is_none())?;
        slot.remove(idx).map(|(request, _, _)| request)
    })
}

/// When SSL_write and SSL_read disagree on stream_key, still pair a pending
/// request for this pid rather than dropping the response copy.
/// Prefer same-host, then hostless; never let datagw/ACS steal an API waiter.
fn take_pending_for_pid(
    pending: &mut HashMap<
        (u32, u64),
        VecDeque<(MirroredMessage, Option<MirroredMessage>, Instant)>,
    >,
    pid: u32,
    response_host: &str,
) -> Option<MirroredMessage> {
    let take_unpaired =
        |slot: &mut VecDeque<(MirroredMessage, Option<MirroredMessage>, Instant)>,
         pred: &dyn Fn(&MirroredMessage) -> bool| {
            let idx = slot
                .iter()
                .position(|(req, resp, _)| resp.is_none() && pred(req))?;
            slot.remove(idx).map(|(request, _, _)| request)
        };
    if looks_like_mirror_host(response_host) {
        let host_key = pending
            .iter()
            .filter(|((process, _), slot)| *process == pid && !slot.is_empty())
            .find_map(|(key, slot)| {
                slot.iter()
                    .position(|(req, resp, _)| {
                        resp.is_none()
                            && looks_like_mirror_host(&req.host)
                            && (same_site(&req.host, response_host)
                                || req.host.eq_ignore_ascii_case(response_host))
                    })
                    .map(|_| *key)
            });
        if let Some(key) = host_key {
            return pending.get_mut(&key).and_then(|slot| {
                take_unpaired(slot, &|req| {
                    looks_like_mirror_host(&req.host)
                        && (same_site(&req.host, response_host)
                            || req.host.eq_ignore_ascii_case(response_host))
                })
            });
        }
        if is_cdn_steal_host(response_host) {
            return None;
        }
    }
    let oldest_key = |pending: &HashMap<
        (u32, u64),
        VecDeque<(MirroredMessage, Option<MirroredMessage>, Instant)>,
    >,
                      pred: &dyn Fn(&MirroredMessage) -> bool| {
        pending
            .iter()
            .filter(|((process, _), slot)| {
                *process == pid
                    && slot
                        .iter()
                        .any(|(req, resp, _)| resp.is_none() && pred(req))
            })
            .min_by_key(|(_, slot)| {
                slot.iter()
                    .find(|(req, resp, _)| resp.is_none() && pred(req))
                    .map(|(_, _, queued_at)| *queued_at)
                    .unwrap_or_else(Instant::now)
            })
            .map(|(key, _)| *key)
    };
    // Hostless mgw / CMB /mainpage/ — not SystemLogHandler telemetry.
    let hostless_api = |req: &MirroredMessage| {
        !looks_like_mirror_host(&req.host)
            && !looks_like_cmb_log_path(&req.path)
            && (is_mgw_request(req) || looks_like_cmb_mainpage_path(&req.path))
    };
    // Hosted bank/Alipay APIs (CCB ccbNewClient, CMB /mainpage/). Log POSTs
    // last-resort log.cmbchina.com and must not steal these empty-host copies
    // (cycle-003731 /mainpage/ orig=0 while hostless SystemLogHandler waited).
    // Ads (imageadv) also skip — cycle-021444 txCtrl orig=0 while gifs paired.
    let hosted_api = |req: &MirroredMessage| {
        looks_like_mirror_host(&req.host)
            && !is_cdn_steal_host(&req.host)
            && !looks_like_cmb_log_path(&req.path)
            && !is_ad_asset_host(&req.host)
    };
    let hostless_other = |req: &MirroredMessage| {
        !looks_like_mirror_host(&req.host)
            && !looks_like_cmb_log_path(&req.path)
            && !is_ad_asset_host(&req.host)
    };
    if !looks_like_mirror_host(response_host) {
        if let Some(key) = oldest_key(pending, &hostless_api) {
            return pending
                .get_mut(&key)
                .and_then(|slot| take_unpaired(slot, &hostless_api));
        }
        if let Some(key) = oldest_key(pending, &hosted_api) {
            return pending
                .get_mut(&key)
                .and_then(|slot| take_unpaired(slot, &hosted_api));
        }
        if let Some(key) = oldest_key(pending, &hostless_other) {
            return pending
                .get_mut(&key)
                .and_then(|slot| take_unpaired(slot, &hostless_other));
        }
        return None;
    }
    // Named leftover host, no same-host waiter: only hostless API, never log.
    oldest_key(pending, &hostless_api).and_then(|key| {
        pending
            .get_mut(&key)
            .and_then(|slot| take_unpaired(slot, &hostless_api))
    })
}

/// Deliver requests whose pairing grace elapsed without a response copy.
fn sweep_expired(
    pending: &mut HashMap<
        (u32, u64),
        VecDeque<(MirroredMessage, Option<MirroredMessage>, Instant)>,
    >,
    orphans: &mut HashMap<(u32, u64), VecDeque<(MirroredMessage, Instant)>>,
    retries: &mut VecDeque<RetryDelivery>,
    runtime: &DeliveryRuntime<'_>,
    recv_busy_pids: &Mutex<HashSet<u32>>,
    peer_book: &Mutex<PeerHostBook>,
) {
    let now = Instant::now();
    let busy = recv_busy_pids.lock().ok();
    for ((pid, stream_id), slot) in pending.iter_mut() {
        if busy.as_ref().is_some_and(|set| set.contains(pid)) {
            // Recv still buffering (often orphan body missing status-line) —
            // hold unpaired flush so soft/eager salvage can still pair.
            continue;
        }
        while let Some((front_req, _, queued_at)) = slot.front() {
            let grace = if front_req.method.eq_ignore_ascii_case("GET")
                || front_req.method.eq_ignore_ascii_case("HEAD")
            {
                PAIRING_GRACE
            } else {
                POST_PAIRING_GRACE
            };
            if now.duration_since(*queued_at) < grace {
                break;
            }
            let queued_at = *queued_at;
            let (mut request, response, _) = slot.pop_front().expect("front checked");
            fill_request_host_from_peers(&mut request, *pid, *stream_id, peer_book);
            if !looks_like_mirror_host(&request.host) {
                // Keep waiting for SNI/peer rather than Burp-204 with empty Host.
                slot.push_front((request, response, queued_at));
                break;
            }
            let response =
                response.or_else(|| take_orphan_response(orphans, *pid, *stream_id, &request));
            if response.is_none()
                && orphans
                    .iter()
                    .any(|((process, _), slot)| *process == *pid && !slot.is_empty())
            {
                // An SSL_read copy for this pid is waiting on another
                // stream_key — hold rather than orig=0.
                slot.push_front((request, None, queued_at));
                break;
            }
            enqueue_delivery(runtime, retries, request, response);
        }
    }
    pending.retain(|_, slot| !slot.is_empty());
}

/// Deliver every still-pending request unpaired; used when the session ends.
fn flush_pending(
    pending: &mut HashMap<
        (u32, u64),
        VecDeque<(MirroredMessage, Option<MirroredMessage>, Instant)>,
    >,
    orphans: &mut HashMap<(u32, u64), VecDeque<(MirroredMessage, Instant)>>,
    retries: &mut VecDeque<RetryDelivery>,
    runtime: &DeliveryRuntime<'_>,
    peer_book: &Mutex<PeerHostBook>,
) {
    for ((pid, stream_id), slot) in pending.iter_mut() {
        while let Some((mut request, held, _)) = slot.pop_front() {
            fill_request_host_for_seal(&mut request, *pid, *stream_id, peer_book);
            let response =
                held.or_else(|| take_orphan_response(orphans, *pid, *stream_id, &request));
            if let Some(ref response) = response {
                if !looks_like_mirror_host(&request.host) && looks_like_mirror_host(&response.host)
                {
                    request.host.clone_from(&response.host);
                }
            }
            if !looks_like_mirror_host(&request.host) {
                "missing-sni.invalid".clone_into(&mut request.host);
            }
            enqueue_delivery(runtime, retries, request, response);
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
    absolute_timeout_streak: &AtomicU64,
) -> Result<(), String> {
    let mut stream = TcpStream::connect_timeout(&endpoint, Duration::from_secs(3))
        .map_err(|error| format!("connect {endpoint}: {error}"))?;
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
        q.insert_for_host(&request.host, playback_id.clone(), playback_body);
    }
    // Visible wire is always absolute http://host:443/path — never /_ksight or :18081.
    let absolute = request.to_proxy_absolute_with_id(&playback_id);
    let streak = absolute_timeout_streak.load(Ordering::Relaxed);
    let skip_absolute = streak >= ABS_TIMEOUT_SKIP_AFTER;
    if skip_absolute {
        log_mirror(
            session_id,
            &format!(
                "burp-mirror absolute-skipped streak={streak} → still absolute wire (no :18081 rewrite) abs_wire={}",
                absolute.len()
            ),
        );
    }
    let read_timeout = if skip_absolute {
        Duration::from_millis(400)
    } else {
        ABS_PROBE_TIMEOUT
    };
    let (absolute_reply, abs_read_why) =
        write_and_read_burp_reply(&mut stream, &absolute, read_timeout)?;
    let abs_line = absolute_reply
        .split(|byte| *byte == b'\n')
        .next()
        .map(|line| String::from_utf8_lossy(line).trim().to_owned())
        .unwrap_or_default();
    // Burp's own listener page is HTTP 200 with this title, including
    // `<h1>Error</h1>Failed to connect to 127.0.0.1:18888`. That is not an
    // origin/playback 200 and is not HTTP history.
    let absolute_burp_error = absolute_reply
        .windows(b"Burp Suite Professional".len())
        .any(|window| window == b"Burp Suite Professional");
    let absolute_bad = absolute_reply.is_empty() || absolute_burp_error;
    let (wire_kind, reply) = if !absolute_bad {
        absolute_timeout_streak.store(0, Ordering::Relaxed);
        ("absolute", absolute_reply)
    } else {
        let why = if absolute_reply.is_empty() {
            abs_read_why
        } else if absolute_burp_error {
            "burp_error"
        } else if abs_line.is_empty() {
            "short"
        } else {
            "other"
        };
        if why == "timeout" && !skip_absolute {
            let next = absolute_timeout_streak.fetch_add(1, Ordering::Relaxed) + 1;
            log_mirror(
                session_id,
                &format!(
                    "burp-mirror absolute-rejected why={why} streak={next}/{ABS_TIMEOUT_SKIP_AFTER} abs_line='{}' abs_bytes={} (kept absolute; hotspot→Burp upstream 127.0.0.1:{BURP_UPSTREAM_PORT} via adb forward, NOT phone LAN IP; home Wi-Fi→phone:18888)",
                    abs_line.chars().take(80).collect::<String>(),
                    absolute_reply.len()
                ),
            );
        } else {
            log_mirror(
                session_id,
                &format!(
                    "burp-mirror absolute-rejected why={why} abs_line='{}' abs_bytes={} (kept absolute; no :18081 rewrite)",
                    abs_line.chars().take(80).collect::<String>(),
                    absolute_reply.len()
                ),
            );
        }
        // Clash/TUN can eat Burp's origin fetch (orig0 / empty reply) without
        // us editing FlClash. Listener HTML means upstream :18888 is down or
        // the request was CONNECT; do not log burp-mirror ok.
        if absolute_burp_error {
            return Err(format!(
                "Burp listener page (not origin/playback) why={why}; adb forward tcp:{BURP_UPSTREAM_PORT} and wire http://host:443; abs_line='{}' abs_bytes={}",
                abs_line.chars().take(80).collect::<String>(),
                absolute_reply.len()
            ));
        }
        if absolute_reply.is_empty() {
            if response.is_some() {
                log_mirror(
                    session_id,
                    &format!(
                        "burp-mirror absolute-empty why={why} kept playback orig={} (Clash/18081; not rewriting FlClash)",
                        response.and_then(|item| item.status).unwrap_or(0)
                    ),
                );
                return Ok(());
            }
            return Err(format!(
                "Burp absolute fetch returned no response ({why}); on hotspot set Burp upstream 127.0.0.1:{BURP_UPSTREAM_PORT} (adb forward) not phone LAN; home Wi-Fi may use phone:18888; allow unsafe SSL for that upstream"
            ));
        }
        ("absolute", absolute_reply)
    };
    let reply_line = reply
        .split(|byte| *byte == b'\n')
        .next()
        .map(|line| String::from_utf8_lossy(line).trim().to_owned())
        .unwrap_or_default();
    let upload = upload_kind(&request.body);
    log_mirror(
        session_id,
        &format!(
            "burp-mirror ok {} {}{} orig={} burp='{}' form={wire_kind} wire={} headers={} body={}{} playback_id={playback_id}",
            request.method,
            request.host,
            request.path,
            response.and_then(|item| item.status).unwrap_or(0),
            reply_line.chars().take(80).collect::<String>(),
            absolute.len(),
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

fn write_and_read_burp_reply(
    stream: &mut TcpStream,
    wire: &[u8],
    read_timeout: Duration,
) -> Result<(Vec<u8>, &'static str), String> {
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|error| error.to_string())?;
    stream
        .write_all(wire)
        .map_err(|error| format!("write: {error}"))?;
    let _ = stream.flush();
    Ok(read_http_message_with_why(stream, 512 * 1024))
}

/// Read one complete HTTP/1 message (headers + Content-Length body) without
/// requiring the peer to close the TCP connection (keep-alive safe).
fn read_http_message_with_why(stream: &mut TcpStream, cap: usize) -> (Vec<u8>, &'static str) {
    let mut out = Vec::new();
    let mut expected = None;
    let mut buf = [0_u8; 4096];
    let mut why: &'static str = "empty";
    while out.len() < cap {
        match stream.read(&mut buf) {
            Ok(0) => {
                why = if out.is_empty() { "eof" } else { "eof_short" };
                break;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                why = if out.is_empty() {
                    "timeout"
                } else if expected.is_some_and(|length| out.len() >= length) {
                    "ok"
                } else {
                    "timeout_short"
                };
                break;
            }
            Err(_) => {
                why = if out.is_empty() {
                    "error"
                } else {
                    "error_short"
                };
                break;
            }
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
                    why = "ok";
                    break;
                }
            }
        }
    }
    if out.is_empty() && why == "ok" {
        why = "empty";
    }
    (out, why)
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

fn upstream_loop(
    listener: &TcpListener,
    queue: &Arc<Mutex<PlaybackStore>>,
    stop: &Arc<AtomicBool>,
) {
    let _ = listener.set_nonblocking(true);
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let queue = Arc::clone(queue);
                let _ = std::thread::Builder::new()
                    .name("ksight-burp-upstream-conn".to_owned())
                    .spawn(move || {
                        if let Err(error) = handle_upstream_client(stream, &queue) {
                            eprintln!("burp-mirror upstream: {error}");
                        }
                    });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
}

fn handle_upstream_client(
    mut stream: TcpStream,
    queue: &Mutex<PlaybackStore>,
) -> Result<(), String> {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(8)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(8)));
    let header_buf = read_http_headers(&mut stream, 16 * 1024)?;
    if header_buf.is_empty() {
        return Ok(());
    }
    if looks_like_connect(&header_buf) {
        let host = connect_host(&header_buf).unwrap_or_default();
        let header_end = header_buf
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|pos| pos + 4)
            .unwrap_or(header_buf.len());
        let early = &header_buf[header_end..];
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n")
            .map_err(|error| error.to_string())?;
        // No live origin. Prefer queued body when Burp (or a test client) speaks
        // plain HTTP in the tunnel; TLS ClientHello cannot be terminated without
        // a musl-friendly TLS stack — close quickly so Absolute history keeps the
        // real URL without a Clash/origin stall.
        return serve_connect_tunnel(&mut stream, queue, host.as_str(), early);
    }
    serve_playback_plain(&mut stream, &header_buf, queue, None)
}

fn serve_playback_plain(
    stream: &mut TcpStream,
    header_buf: &[u8],
    queue: &Mutex<PlaybackStore>,
    forced_host: Option<&str>,
) -> Result<(), String> {
    let body = take_playback_for_request(header_buf, queue, forced_host);
    stream
        .write_all(&body)
        .map_err(|error| format!("upstream write: {error}"))?;
    Ok(())
}

fn serve_connect_tunnel(
    stream: &mut TcpStream,
    queue: &Mutex<PlaybackStore>,
    connect_host: &str,
    early: &[u8],
) -> Result<(), String> {
    let mut first = early.to_vec();
    if first.is_empty() {
        let mut tmp = [0_u8; 1024];
        match stream.read(&mut tmp) {
            Ok(n) if n > 0 => first.extend_from_slice(&tmp[..n]),
            _ => {}
        }
    }
    if first.is_empty() {
        return Ok(());
    }
    // TLS record ContentType=0x16 (Handshake) — cannot plaintext-inject.
    if first.first() == Some(&0x16) {
        let body = queue
            .lock()
            .ok()
            .and_then(|mut q| q.take_for_host(connect_host));
        let _ = body; // reserved for future musl-safe TLS terminate
        eprintln!(
            "burp-mirror upstream CONNECT {connect_host}: TLS ClientHello (no origin dial; configure absolute history URL; body needs TLS terminate)"
        );
        return Ok(());
    }
    // Plain HTTP inside CONNECT tunnel (unusual, but enables Playback-ID tests /
    // tooling that skips TLS).
    let mut request = first;
    if !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let mut tmp = [0_u8; 4096];
        loop {
            match stream.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    request.extend_from_slice(&tmp[..n]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                    if request.len() > 16 * 1024 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }
    serve_playback_plain(stream, &request, queue, Some(connect_host))
}

fn take_playback_for_request(
    request: &[u8],
    queue: &Mutex<PlaybackStore>,
    forced_host: Option<&str>,
) -> Vec<u8> {
    let playback_id = header_value(request, "x-kernsight-playback-id");
    let host = forced_host
        .map(str::to_owned)
        .or_else(|| header_value(request, "host"));
    let body = queue.lock().ok().and_then(|mut q| {
        if let Some(response) = q.take(playback_id.as_deref()) {
            return Some(response);
        }
        host.as_deref().and_then(|host| q.take_for_host(host))
    });
    body.unwrap_or_else(|| {
        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
    })
}

fn read_http_headers(stream: &mut TcpStream, cap: usize) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut tmp = [0_u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
                if buf.len() >= cap {
                    return Err("upstream headers too large".to_owned());
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(buf)
}

fn looks_like_connect(buf: &[u8]) -> bool {
    buf.len() >= 8 && buf[..8].eq_ignore_ascii_case(b"CONNECT ")
}

fn connect_host(buf: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(buf).ok()?;
    let line = text.lines().next()?;
    let rest = if line.len() >= 8 && line[..8].eq_ignore_ascii_case("CONNECT ") {
        &line[8..]
    } else {
        return None;
    };
    let authority = rest.split_whitespace().next()?;
    let host = authority
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(authority);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    (!host.is_empty()).then(|| host.to_owned())
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
#[path = "tests.rs"]
mod tests;
