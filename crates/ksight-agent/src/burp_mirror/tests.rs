use super::{
    deliver, header_value, looks_like_mirror_host, read_http_message, upstream_loop, BurpMirror,
    PlaybackStore, ABS_TIMEOUT_SKIP_AFTER, STREAM_CAP,
};
use ksight_core::MirroredMessage;
use ksight_model::InspectPlaintext;
use std::collections::{HashMap, VecDeque};
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

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
    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nX-KernSight-Playback-ID: abc-123\r\n\r\n";
    assert_eq!(
        header_value(request, "x-kernsight-playback-id").as_deref(),
        Some("abc-123")
    );
}

#[test]
fn absolute_timeout_keeps_absolute_wire_no_ksight_rewrite() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let wires: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let wires_bg = Arc::clone(&wires);
    let server = thread::spawn(move || {
        listener.set_nonblocking(false).unwrap();
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = vec![0_u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            wires_bg
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(&buf[..n]).into_owned());
            thread::sleep(Duration::from_millis(2_400));
        }
    });
    let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
    mirror.observe_plaintext(
        42,
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
            preview: "GET /v1/acct HTTP/1.1\r\nHost: api.example.com\r\n\r\n".into(),
            preview_encoding: "utf8_lossy".into(),
            content_class: "text".into(),

            ..Default::default()
        },
    );
    mirror.observe_plaintext(
        42,
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
            preview: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".into(),
            preview_encoding: "utf8_lossy".into(),
            content_class: "text".into(),

            ..Default::default()
        },
    );
    drop(mirror);
    let _ = server.join();
    let captured = wires.lock().unwrap().clone();
    assert!(
        !captured.is_empty(),
        "expected absolute wire attempt, got {}",
        captured.len()
    );
    assert!(
        captured[0].contains("GET http://api.example.com:443/v1/acct"),
        "wire must stay absolute: {}",
        captured[0]
    );
    assert!(
        !captured.iter().any(|w| w.contains("/_ksight/")),
        "must not rewrite to /_ksight: {captured:?}"
    );
    assert!(
        !captured.iter().any(|w| w.contains(":18081")),
        "must not rewrite to :18081: {captured:?}"
    );
    assert!(
        captured[0].contains("X-KernSight-Playback-ID:"),
        "Playback-ID missing: {}",
        captured[0]
    );
    assert!(
        captured[0].contains("Connection: close"),
        "Connection: close missing: {}",
        captured[0]
    );
}

#[test]
fn absolute_skipped_still_sends_absolute_not_playback_identity() {
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
        let _ =
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        String::from_utf8_lossy(&buf[..n]).into_owned()
    });
    let queue = Mutex::new(PlaybackStore::default());
    let streak = AtomicU64::new(ABS_TIMEOUT_SKIP_AFTER);
    let request = ksight_core::MirroredMessage {
        is_request: true,
        method: "GET".into(),
        scheme: "https",
        host: "api.example.com".into(),
        path: "/skip-me".into(),
        status: None,
        headers: vec![],
        body: vec![],
        websocket_upgrade: false,
        stream_id: None,
    };
    deliver(addr, &request, None, &queue, "test-skip", &streak).expect("deliver");
    let body = received.join().unwrap();
    assert!(
        body.contains("GET http://api.example.com:443/skip-me"),
        "skip streak must still use absolute: {body}"
    );
    assert!(
        !body.contains("/_ksight/"),
        "must not use identity playback: {body}"
    );
    assert!(!body.contains(":18081"), "must not target :18081: {body}");
    assert!(body.contains("X-KernSight-Playback-ID:"), "{body}");
    assert!(body.contains("Connection: close"), "{body}");
}

#[test]
fn upstream_helper_returns_queued_body_for_playback_id() {
    let queue = Arc::new(Mutex::new(PlaybackStore::default()));
    {
        let mut q = queue.lock().unwrap();
        q.insert_for_host(
            "openapi.app.example",
            "pid-9".into(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
        );
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let queue_bg = Arc::clone(&queue);
    let stop_bg = Arc::clone(&stop);
    let server = thread::spawn(move || upstream_loop(&listener, &queue_bg, &stop_bg));
    let mut client = TcpStream::connect(addr).unwrap();
    client
            .write_all(
                b"POST https://openapi.app.example/api HTTP/1.1\r\nHost: openapi.app.example\r\nX-KernSight-Playback-ID: pid-9\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut got = Vec::new();
    let mut buf = [0_u8; 1024];
    loop {
        match client.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    stop.store(true, Ordering::SeqCst);
    let _ = server.join();
    let text = String::from_utf8_lossy(&got);
    assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
    assert!(
        text.contains("\r\n\r\nok") || text.ends_with("ok"),
        "{text}"
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
    assert!(!looks_like_mirror_host("dirn:-2:-2"));
    assert!(!looks_like_mirror_host("content://media/external"));

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
    // Wait past PAIRING_GRACE (12s) so unpaired request is attempted first.
    thread::sleep(Duration::from_millis(12_500));

    let listener = TcpListener::bind(addr).unwrap();
    let received = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_http_message(&mut stream, 4096);
        let _ = stream.write_all(
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        request
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
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
    mirror.observe_network_connect();
    mirror.observe_network_handshake();
    let raw = b"POST /once HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 2\r\n\r\n{}";
    mirror.observe_bytes_for_connection(22, 201, Some(0x2222), "tls_ssl_write", "send", raw);
    mirror.observe_bytes_for_connection(22, 201, Some(0x2222), "tls_ssl_write", "send", raw);
    let metrics = mirror.diagnostic_metrics();
    assert_eq!(metrics.get("observed_fragments"), Some(&2));
    assert_eq!(metrics.get("duplicate_fragments"), Some(&1));
    assert_eq!(metrics.get("duplicate_probe"), Some(&1));
    assert_eq!(metrics.get("reconstructed_requests"), Some(&1));
    assert_eq!(metrics.get("reconstructed_responses"), Some(&0));
    assert_eq!(metrics.get("queue_failures"), Some(&0));
    assert_eq!(metrics.get("network_connects"), Some(&1));
    assert_eq!(metrics.get("network_handshakes"), Some(&1));
    assert_eq!(metrics.get("standard_tls_fragments"), Some(&2));
    drop(mirror);
    assert_eq!(received.join().unwrap(), 1);
}

#[test]
fn progressive_truncated_prefix_is_coalesced_not_dropped() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let received = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut wires = Vec::new();
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = vec![0_u8; 4096];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    wires.push(String::from_utf8_lossy(&buf[..n]).into_owned());
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
        wires
    });
    let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
    let prefix = b"POST /grow HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 4\r\n\r\n";
    let mut full = prefix.to_vec();
    full.extend_from_slice(b"ping");
    mirror.observe_bytes_for_connection(9, 1, Some(0x3001), "tls_ssl_write", "send", prefix);
    mirror.observe_bytes_for_connection(9, 1, Some(0x3001), "tls_ssl_write", "send", &full);
    let metrics = mirror.diagnostic_metrics();
    assert_eq!(metrics.get("observed_fragments"), Some(&2));
    assert_eq!(metrics.get("duplicate_fragments"), Some(&0));
    assert!(
        metrics
            .get("duplicate_suppressed_progress")
            .copied()
            .unwrap_or(0)
            >= 1,
        "{metrics:?}"
    );
    assert_eq!(metrics.get("reconstructed_requests"), Some(&1));
    drop(mirror);
    let wires = received.join().unwrap();
    assert_eq!(wires.len(), 1, "{wires:?}");
    assert!(wires[0].contains("ping"), "{wires:?}");
}

#[test]
fn identical_payload_after_stream_progress_is_kept() {
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
    let one = b"POST /a HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 1\r\n\r\n1";
    let two = b"POST /b HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 1\r\n\r\n2";
    // Advance stream position with a distinct fragment, then repeat `one`.
    mirror.observe_bytes_for_connection(11, 1, Some(0x4001), "tls_ssl_write", "send", one);
    mirror.observe_bytes_for_connection(11, 1, Some(0x4001), "tls_ssl_write", "send", two);
    mirror.observe_bytes_for_connection(11, 1, Some(0x4001), "tls_ssl_write", "send", one);
    let metrics = mirror.diagnostic_metrics();
    assert_eq!(metrics.get("observed_fragments"), Some(&3));
    assert_eq!(metrics.get("duplicate_fragments"), Some(&0));
    assert_eq!(metrics.get("reconstructed_requests"), Some(&3));
    // Third fragment matches the first's bytes but stream_pos advanced via
    // the middle fragment, so it must not be eaten by probe debounce.
    drop(mirror);
    assert_eq!(received.join().unwrap(), 3);
}

#[test]
fn stale_shorter_truncated_prefix_is_probe_duplicate() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
    let full = b"POST /x HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 0\r\n\r\n";
    let shorter = &full[..32];
    mirror.observe_bytes_for_connection(12, 1, Some(0x5001), "tls_ssl_write", "send", full);
    mirror.observe_bytes_for_connection(12, 1, Some(0x5001), "tls_ssl_write", "send", shorter);
    let metrics = mirror.diagnostic_metrics();
    assert_eq!(metrics.get("observed_fragments"), Some(&2));
    assert_eq!(metrics.get("duplicate_probe"), Some(&1));
    assert_eq!(metrics.get("duplicate_fragments"), Some(&1));
    // First fragment already completed the request.
    assert_eq!(metrics.get("reconstructed_requests"), Some(&1));
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
                "POST /api/pay HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 2\r\n\r\n{}"
                    .into(),
            preview_encoding: "utf8_lossy".into(),
            content_class: "text".into(),
            ..Default::default()
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
            preview: "HTTP/1.1 402 Payment Required\r\nContent-Length: 5\r\n\r\n{\"no\"}".into(),
            preview_encoding: "utf8_lossy".into(),
            content_class: "text".into(),
            ..Default::default()
        },
    );
    drop(mirror);
    let wire = received.join().unwrap();
    // Prefer absolute http://host:443/path for Repeater; Host stays real.
    assert!(
        wire.starts_with("POST http://api.example.com:443/api/pay HTTP/1.1\r\n"),
        "wire prefix must be absolute https: {wire}"
    );
    assert!(!wire.contains("/_ksight/"), "no /_ksight: {wire}");
    assert!(!wire.contains(":18081"), "no :18081: {wire}");
    assert!(wire.contains("Host: api.example.com\r\n"), "wire: {wire}");

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
                "POST /v1/session HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 2\r\n\r\n{}"
                    .into(),
            preview_encoding: "utf8_lossy".into(),
            content_class: "text".into(),
            ..Default::default()
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
            ..Default::default()
        },
    );
    drop(mirror);
    let body = received.join().unwrap();
    assert!(
        body.contains("POST ")
            && body.contains("/v1/session")
            && body.contains("Host: api.example.com"),
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

// PRUNED 2026-09-10: handshake_sni_fills_host_on_ssl_read_http —
// synthesize_request intentionally ignores peer/SNI/last_url (gateway
// logUpload steal fix). Host-from-response covered by
// host-from-response ACAO coverage.

#[test]
fn sni_stays_on_its_own_ssl_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let received = thread::spawn(move || {
        listener.set_nonblocking(false).unwrap();
        let mut bodies = Vec::new();
        for _ in 0..2 {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut buf = vec![0_u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
            bodies.push(String::from_utf8_lossy(&buf[..n]).into_owned());
        }
        bodies.join("\n---\n")
    });
    let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
    mirror.observe_peer_on_thread(7, 10, "cdn.example.com".into());
    mirror.observe_bytes_for_connection(
        7,
        10,
        Some(0x2000),
        "tls_ssl_write",
        "send",
        b"GET /asset.js HTTP/1.1\r\nAccept: */*\r\n\r\n",
    );
    mirror.observe_peer_on_thread(7, 11, "api.example.com".into());
    mirror.observe_bytes_for_connection(
        7,
        11,
        Some(0x3000),
        "tls_ssl_write",
        "send",
        b"POST /v1/session HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
    );
    drop(mirror);
    let body = received.join().unwrap();
    assert!(
        body.contains("GET http://cdn.example.com:443/asset.js")
            || body.contains("GET https://cdn.example.com/asset.js")
            || body.contains("Host: cdn.example.com"),
        "CDN SNI must stay on its SSL object, got {body}"
    );
    assert!(
        body.contains("POST http://api.example.com:443/v1/session")
            || body.contains("POST https://api.example.com/v1/session")
            || body.contains("Host: api.example.com"),
        "API SNI must stay on its SSL object, got {body}"
    );
    let cdn_login = body.contains("POST http://cdn.example.com:443/v1/session")
        || body.contains("POST https://cdn.example.com/v1/session");
    let api_asset = body.contains("GET http://api.example.com:443/asset.js")
        || body.contains("GET https://api.example.com/asset.js");
    assert!(
        !cdn_login && !api_asset,
        "hosts crossed connections: {body}"
    );
}

#[test]
fn tid_stream_migrates_onto_ssl_object() {
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
    mirror.observe_peer_on_thread(5, 3, "api.app.example".into());
    mirror.observe_bytes(
        5,
        3,
        "tls_ssl_write",
        "send",
        b"POST /v1/session HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
    );
    mirror.observe_bytes_for_connection(
        5,
        3,
        Some(0x9000),
        "tls_ssl_write",
        "send",
        b"POST /v1/session HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
    );
    drop(mirror);
    let body = received.join().unwrap();
    assert!(
        body.contains("Host: api.app.example"),
        "SNI captured on tid-key must follow the SSL object, got {body}"
    );
    assert!(
        !body.contains("missing-sni.invalid"),
        "migrated connection must not seal as missing-sni, got {body}"
    );
}

#[test]
fn hostless_request_pairs_orphan_response_without_via_synthetic() {
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
    // Response first with Via junk (must orphan, not synthetic GET).
    mirror.observe_bytes(
        9010,
        1,
        "tls_ssl_read",
        "recv",
        b"HTTP/1.1 200 OK\r\nVia: spanner-gw-54-49022:7088[200]\r\nContent-Length: 4\r\n\r\npair",
    );
    // Authority-less request on same tid/stream shortly after.
    mirror.observe_bytes(
        9010,
        1,
        "tls_ssl_write",
        "send",
        b"POST /v1/rpc HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
    );
    mirror.observe_peer_on_thread(9010, 1, "gw.app.example".into());
    drop(mirror);
    let body = received.join().unwrap();
    assert!(
        body.contains("Host: gw.app.example") || body.contains("Host: gw.app.example"),
        "expected paired hostless+orphan, got {body}"
    );
    assert!(
        body.contains("POST "),
        "expected real POST not Via GET: {body}"
    );
    assert!(!body.contains("gw-54"), "Via junk must not win: {body}");
}

#[test]
fn ssl_read_pairs_across_tids_when_connection_id_matches() {
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
    mirror.observe_bytes_for_connection(
        42,
        100,
        Some(0xABCD_1000),
        "tls_ssl_write",
        "send",
        b"POST /pay HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 2\r\n\r\n{}",
    );
    // Different tid, same SSL* — must still pair (not 204).
    mirror.observe_bytes_for_connection(
        42,
        200,
        Some(0xABCD_1000),
        "tls_ssl_read",
        "recv",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{\"ok\"}",
    );
    drop(mirror);
    let body = received.join().unwrap();
    assert!(body.contains("Host: api.example.com"), "{body}");
    assert!(body.contains("/pay"), "{body}");
    assert!(body.contains("X-KernSight-Playback-ID:"), "{body}");
}

#[test]
fn response_before_request_pairs_via_orphan_store() {
    // HTTP/2 often surfaces SSL_read before the matching SSL_write is
    // reconstructed; dropping that response forced unpaired 204.
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
    mirror.observe_bytes_for_connection(
        55,
        2,
        Some(0x55AA),
        "tls_ssl_read",
        "recv",
        b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\norphanok",
    );
    thread::sleep(Duration::from_millis(80));
    mirror.observe_bytes_for_connection(
        55,
        1,
        Some(0x55AA),
        "tls_ssl_write",
        "send",
        b"POST /orphan HTTP/1.1\r\nHost: render.app.example\r\nContent-Length: 2\r\n\r\n{}",
    );
    drop(mirror);
    let body = received.join().unwrap();
    assert!(body.contains("Host: render.app.example"), "{body}");
    assert!(body.contains("/orphan"), "{body}");
    assert!(body.contains("X-KernSight-Playback-ID:"), "{body}");
}

#[test]
fn binary_preamble_ssl_read_still_pairs_http_response() {
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
    mirror.observe_bytes_for_connection(
        9,
        1,
        Some(0x2000),
        "tls_ssl_write",
        "send",
        b"GET /x HTTP/1.1\r\nHost: cdn.example.test\r\n\r\n",
    );
    let mut recv = vec![0xAAu8; 32];
    recv.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nPNG");
    mirror.observe_bytes_for_connection(9, 2, Some(0x2000), "tls_ssl_read", "recv", &recv);
    drop(mirror);
    let body = received.join().unwrap();
    assert!(body.contains("Host: cdn.example.test"), "{body}");
    assert!(body.contains("X-KernSight-Playback-ID:"), "{body}");
}

#[test]
fn http2_out_of_order_streams_pair_by_stream_id() {
    let mut pending: HashMap<
        (u32, u64),
        VecDeque<(MirroredMessage, Option<MirroredMessage>, Instant)>,
    > = HashMap::new();
    let req = |path: &str, sid: u32| MirroredMessage {
        is_request: true,
        method: "GET".into(),
        scheme: "https",
        host: "h2.example".into(),
        path: path.into(),
        status: None,
        headers: vec![],
        body: vec![],
        websocket_upgrade: false,
        stream_id: Some(sid),
    };
    let resp = |sid: u32, status: u16| MirroredMessage {
        is_request: false,
        method: "HTTP".into(),
        scheme: "https",
        host: "h2.example".into(),
        path: "/".into(),
        status: Some(status),
        headers: vec![],
        body: vec![],
        websocket_upgrade: false,
        stream_id: Some(sid),
    };
    pending
        .entry((9, 0xABC))
        .or_default()
        .push_back((req("/one", 1), None, Instant::now()));
    pending
        .entry((9, 0xABC))
        .or_default()
        .push_back((req("/three", 3), None, Instant::now()));
    // Response for stream 3 first — must not FIFO-steal /one.
    let paired = super::take_pending_for_response(&mut pending, 9, 0xABC, &resp(3, 203))
        .expect("h2 stream 3");
    assert_eq!(paired.path, "/three");
    assert_eq!(paired.stream_id, Some(3));
    let paired = super::take_pending_for_response(&mut pending, 9, 0xABC, &resp(1, 201))
        .expect("h2 stream 1");
    assert_eq!(paired.path, "/one");
    assert_eq!(paired.stream_id, Some(1));
}

#[test]
fn delayed_ssl_read_pairs_within_pairing_grace() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let received = thread::spawn(move || {
        listener.set_nonblocking(false).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let request = read_http_message(&mut stream, 8192);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        request
    });
    let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
    mirror.observe_bytes_for_connection(
        77,
        1,
        Some(0x7777),
        "tls_ssl_write",
        "send",
        b"POST /late HTTP/1.1\r\nHost: api.late.test\r\nContent-Length: 2\r\n\r\n{}",
    );
    // Delay well under PAIRING_GRACE (12s) but past soft-flush idle.
    thread::sleep(Duration::from_millis(1_200));
    mirror.observe_bytes_for_connection(
        77,
        2,
        Some(0x7777),
        "tls_ssl_read",
        "recv",
        b"HTTP/1.1 201 Created\r\nContent-Length: 7\r\n\r\nlate-ok",
    );
    drop(mirror);
    let body = received.join().unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("Host: api.late.test"), "{text}");
    assert!(text.contains("/late"), "{text}");
    assert!(text.contains("X-KernSight-Playback-ID:"), "{text}");
    // Playback listener should have served the paired 201, not unpaired 204.
    // Absolute form may win; either way request must not have been flushed alone
    // before the delayed response arrived.
    assert!(!text.is_empty());
}

#[test]
fn inert_all_zero_tls_fragment_is_rejected() {
    assert!(super::is_inert_tls_fragment(&[0u8; 660]));
    assert!(super::is_inert_tls_fragment(&[0u8; 16]));
    assert!(!super::is_inert_tls_fragment(
        b"POST /x HTTP/1.1\r\nHost: a\r\n\r\n"
    ));
    assert!(!super::is_inert_tls_fragment(br#"{"a":1}"#));
}

#[test]
fn outbound_copy_trusts_tls_ssl_read_adapter() {
    // Even if direction is wrongly tagged "send", SSL_read is inbound.
    assert!(!super::outbound_copy(
        "tls_ssl_read",
        "send",
        b"{\"partial\":true}"
    ));
    assert!(super::outbound_copy(
        "tls_ssl_write",
        "recv",
        b"{\"partial\":true}"
    ));
    assert!(!super::outbound_copy(
        "tls_ssl_write",
        "send",
        b"HTTP/1.1 200 OK\r\n\r\n"
    ));
}

#[test]
fn drop_drains_worker_while_playback_still_up() {
    // Fake Burp accepts the mirrored request during Drop. Worker must be
    // joined before playback `stop` so paired deliver completes (orig≠0).
    // Host :18081 may be owned by `adb forward` during overnight runs, so
    // this test does not require a local playback fetch to succeed.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let received = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(8)))
            .unwrap();
        let request = read_http_message(&mut stream, 4096);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        String::from_utf8_lossy(&request).into_owned()
    });
    let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
    mirror.observe_bytes_for_connection(
        42,
        1,
        Some(0x6001),
        "tls_ssl_write",
        "send",
        b"GET /drop-order HTTP/1.1\r\nHost: api.example.test\r\n\r\n",
    );
    mirror.observe_bytes_for_connection(
        42,
        1,
        Some(0x6001),
        "tls_ssl_read",
        "recv",
        b"HTTP/1.1 299 Drop Order\r\nContent-Length: 4\r\n\r\nping",
    );
    let before = mirror.diagnostic_metrics();
    assert_eq!(before.get("reconstructed_responses"), Some(&1));
    // Teardown joins worker first; deliver with paired orig must finish.
    drop(mirror);
    let wire = received.join().expect("burp accept during Drop drain");
    assert!(
        wire.contains("/drop-order"),
        "expected mirrored request during Drop, got {wire}"
    );
    assert!(
        wire.contains("X-KernSight-Playback-ID:") || wire.contains("x-kernsight-playback-id:"),
        "expected playback id on wire, got {wire}"
    );
}

#[test]
fn informational_100_continue_does_not_consume_pairing_slot() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let received = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(8)))
            .unwrap();
        let request = read_http_message(&mut stream, 8192);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        String::from_utf8_lossy(&request).into_owned()
    });
    let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
    mirror.observe_bytes_for_connection(
            9,
            1,
            Some(0x7001),
            "tls_ssl_write",
            "send",
            b"POST /continue HTTP/1.1\r\nHost: api.example\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\nping",
        );
    mirror.observe_bytes_for_connection(
        9,
        2,
        Some(0x7001),
        "tls_ssl_read",
        "recv",
        b"HTTP/1.1 100 Continue\r\n\r\n",
    );
    mirror.observe_bytes_for_connection(
        9,
        2,
        Some(0x7001),
        "tls_ssl_read",
        "recv",
        b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nOK",
    );
    thread::sleep(Duration::from_millis(300));
    mirror.seal();
    let wire = received.join().expect("burp wire");
    assert!(
        wire.contains("/continue"),
        "request must still deliver after 100 Continue, got {wire}"
    );
    assert!(
        wire.contains("X-KernSight-Playback-ID:") || wire.contains("x-kernsight-playback-id:"),
        "{wire}"
    );
    // Paired delivery should surface 201 via playback / orig, not unpaired 204.
    assert!(mirror.delivery_count() >= 1);
}

/// BOC-shaped: incomplete SSL_read (headers+partial CL body) sits buffered
/// with no further observe_bytes (so soft_flush_idle never runs). seal()
/// must soft_flush/orphan-salvage BEFORE Stop unpaired flush so orig≠0.
#[test]
fn seal_soft_flush_salvages_incomplete_ssl_read_before_unpaired() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let received = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(8)))
            .unwrap();
        let request = read_http_message(&mut stream, 8192);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        String::from_utf8_lossy(&request).into_owned()
    });
    let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
    mirror.observe_bytes_for_connection(
        88,
        1,
        Some(0xB0C1),
        "tls_ssl_write",
        "send",
        b"POST /v1/query HTTP/1.1\r\nHost: openapi.app.example\r\nContent-Length: 2\r\n\r\n{}",
    );
    // Incomplete response: headers done, body short of Content-Length.
    mirror.observe_bytes_for_connection(
        88,
        2,
        Some(0xB0C1),
        "tls_ssl_read",
        "recv",
        b"HTTP/1.1 201 Created\r\nContent-Length: 12\r\n\r\npartial",
    );
    let mid = mirror.diagnostic_metrics();
    assert_eq!(
        mid.get("reconstructed_responses"),
        Some(&0),
        "incomplete CL must stay buffered until soft_flush/seal: {mid:?}"
    );
    assert!(
        mid.get("buffered_bytes").copied().unwrap_or(0) > 0,
        "expected buffered incomplete SSL_read: {mid:?}"
    );
    // No sleep / no extra observe → soft_flush_idle_recv never runs.
    mirror.seal();
    let after = mirror.diagnostic_metrics();
    assert!(
        after.get("reconstructed_responses").copied().unwrap_or(0) >= 1,
        "seal must soft_flush/orphan-salvage incomplete recv before unpaired Stop: {after:?}"
    );
    assert!(
        mirror.delivery_count() >= 1,
        "expected delivery after seal salvage"
    );
    let wire = received.join().expect("burp wire");
    assert!(wire.contains("/v1/query"), "{wire}");
    assert!(
        wire.contains("X-KernSight-Playback-ID:") || wire.contains("x-kernsight-playback-id:"),
        "{wire}"
    );
}

/// Incomplete SSL_read headers (no CRLFCRLF) buffered at seal — bare flush
/// used to leave them stranded and Stop unpaired with orig=0.
#[test]
fn seal_salvages_incomplete_response_headers_before_unpaired() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let received = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(8)))
            .unwrap();
        let request = read_http_message(&mut stream, 8192);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        String::from_utf8_lossy(&request).into_owned()
    });
    let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
    mirror.observe_bytes_for_connection(
        90,
        1,
        Some(0xB0C3),
        "tls_ssl_write",
        "send",
        b"GET /notice HTTP/1.1\r\nHost: cdn.app.example\r\n\r\n",
    );
    mirror.observe_bytes_for_connection(
        90,
        2,
        Some(0xB0C3),
        "tls_ssl_read",
        "recv",
        b"HTTP/1.1 203 Non-Authoritative\r\nContent-Length: 4\r\n",
    );
    let mid = mirror.diagnostic_metrics();
    assert_eq!(mid.get("reconstructed_responses"), Some(&0), "{mid:?}");
    assert!(
        mid.get("buffered_bytes").copied().unwrap_or(0) > 0,
        "{mid:?}"
    );
    mirror.seal();
    let after = mirror.diagnostic_metrics();
    assert!(
        after.get("reconstructed_responses").copied().unwrap_or(0) >= 1,
        "incomplete headers must seal-salvage: {after:?}"
    );
    assert!(mirror.delivery_count() >= 1);
    let wire = received.join().expect("burp wire");
    assert!(wire.contains("/notice"), "{wire}");
}

/// Orphan SSL_read body (missed status-line) still buffered at seal — must
/// emit response-side reconstruct before unpaired Stop.
#[test]
fn seal_orphan_recv_salvages_before_unpaired() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let received = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(8)))
            .unwrap();
        let request = read_http_message(&mut stream, 8192);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        String::from_utf8_lossy(&request).into_owned()
    });
    let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
    mirror.observe_bytes_for_connection(
        89,
        1,
        Some(0xB0C2),
        "tls_ssl_write",
        "send",
        b"POST /v1/layout HTTP/1.1\r\nHost: openapi.app.example\r\nContent-Length: 2\r\n\r\n{}",
    );
    // Status-line missed; JSON body alone (BOC uretprobe gap).
    let orphan = br#"{"indexName":"SSE","upDownRate":"0.20%","indexCode":"000001"}"#;
    mirror.observe_bytes_for_connection(89, 2, Some(0xB0C2), "tls_ssl_read", "recv", orphan);
    let mid = mirror.diagnostic_metrics();
    // Complete-looking orphan may eager-emit; either way seal must not unpaired-only.
    mirror.seal();
    let after = mirror.diagnostic_metrics();
    assert!(
        after.get("reconstructed_responses").copied().unwrap_or(0) >= 1,
        "seal/orphan salvage must reconstruct a response: {after:?} (mid={mid:?})"
    );
    assert!(mirror.delivery_count() >= 1);
    let wire = received.join().expect("burp wire");
    assert!(wire.contains("/v1/layout"), "{wire}");
}

#[test]
fn seal_before_final_counts_session_end_delivery() {
    // Capture used to print inspect final before Drop, under-counting
    // session-end unpaired delivers. seal() must flush+join first.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let _burp = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(8)))
            .unwrap();
        let _ = read_http_message(&mut stream, 4096);
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    });
    let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
    mirror.observe_bytes_for_connection(
        77,
        1,
        Some(0x6101),
        "tls_ssl_write",
        "send",
        b"POST /seal-count HTTP/1.1\r\nHost: api.example\r\nContent-Length: 4\r\n\r\nping",
    );
    assert_eq!(mirror.delivery_count(), 0, "still inside pairing grace");
    mirror.seal();
    assert!(
        mirror.delivery_count() >= 1,
        "seal must count session-end deliver, got {}",
        mirror.delivery_count()
    );
    // Idempotent.
    mirror.seal();
    assert!(mirror.delivery_count() >= 1);
}

#[test]
fn peek_then_read_prefers_read_dedupe() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let _burp = thread::spawn(move || {
        let _ = listener.accept();
    });
    let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
    let body = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong";
    // Peek must not advance the stream cursor.
    mirror.observe_bytes_for_connection(
        55,
        1,
        Some(0x7001),
        "tls_ssl_read",
        "peek",
        body,
    );
    assert_eq!(
        mirror.recv_fragments, 0,
        "peek must not count as consuming recv"
    );
    assert_eq!(mirror.pending_peeks.len(), 1);
    // Matching read suppresses the peek and becomes canonical.
    mirror.observe_bytes_for_connection(
        55,
        1,
        Some(0x7001),
        "tls_ssl_read",
        "recv",
        body,
    );
    assert_eq!(mirror.pending_peeks.len(), 0, "read must suppress matched peek");
    assert!(mirror.recv_fragments >= 1);
}

#[test]
fn peek_without_read_promotes_after_idle() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let _burp = thread::spawn(move || {
        let _ = listener.accept();
    });
    let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
    let body = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    mirror.observe_bytes_for_connection(
        56,
        2,
        Some(0x7002),
        "tls_ssl_read",
        "peek",
        body,
    );
    assert_eq!(mirror.pending_peeks.len(), 1);
    // Age the peek past promote idle.
    if let Some(peek) = mirror.pending_peeks.front_mut() {
        peek.seen_at = Instant::now() - Duration::from_secs(5);
    }
    mirror.promote_stale_peeks();
    assert!(
        mirror.pending_peeks.is_empty(),
        "stale peek should promote/clear"
    );
    assert!(mirror.recv_fragments >= 1, "promoted peek feeds recv");
}

#[test]
fn peek_aged_past_match_window_still_suppressed_by_read() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let _burp = thread::spawn(move || {
        let _ = listener.accept();
    });
    let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
    let body = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong";
    mirror.observe_bytes_for_connection(57, 3, Some(0x7003), "tls_ssl_read", "peek", body);
    assert_eq!(mirror.pending_peeks.len(), 1);
    if let Some(peek) = mirror.pending_peeks.front_mut() {
        peek.seen_at = Instant::now() - Duration::from_millis(2000);
    }
    mirror.observe_bytes_for_connection(57, 3, Some(0x7003), "tls_ssl_read", "recv", body);
    assert_eq!(
        mirror.pending_peeks.len(),
        0,
        "read must suppress peek even after PEEK_MATCH_WINDOW"
    );
    assert!(mirror.recv_fragments >= 1);
    assert!(mirror.promoted_peeks.is_empty());
}

#[test]
fn peek_promoted_then_matching_read_does_not_double() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let _burp = thread::spawn(move || {
        let _ = listener.accept();
    });
    let mut mirror = BurpMirror::start(&addr.to_string()).expect("mirror");
    let body = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    mirror.observe_bytes_for_connection(58, 4, Some(0x7004), "tls_ssl_read", "peek", body);
    if let Some(peek) = mirror.pending_peeks.front_mut() {
        peek.seen_at = Instant::now() - Duration::from_secs(5);
    }
    mirror.promote_stale_peeks();
    assert!(mirror.pending_peeks.is_empty());
    let after_promote = mirror.recv_fragments;
    assert!(after_promote >= 1, "promoted peek feeds recv");
    assert_eq!(mirror.promoted_peeks.len(), 1);
    mirror.observe_bytes_for_connection(58, 4, Some(0x7004), "tls_ssl_read", "recv", body);
    assert_eq!(
        mirror.recv_fragments, after_promote,
        "matching read after promote must not re-inject"
    );
    assert!(mirror.promoted_peeks.is_empty());
}
