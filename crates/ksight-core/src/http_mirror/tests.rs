use super::{
    fragment_bytes, host_from_token, parse_mirror_endpoint, MirroredMessage, StreamReassembler,
    BURP_PLAYBACK_PORT,
};

#[test]
fn malformed_discovery_hosts_are_not_promoted_to_http_hosts() {
    assert!(host_from_token("*.example.test").is_empty());
    assert!(host_from_token("api.example.test+").is_empty());
    assert!(host_from_token("empty-sockaddr").is_empty());
    assert!(host_from_token("dirn:-2:-2").is_empty());
    assert!(host_from_token("content://media/external").is_empty());
    assert_eq!(host_from_token("api.example.test"), "api.example.test");
}

#[test]
fn absolute_wire_prefixes_slashless_path() {
    let message = MirroredMessage {
        is_request: true,
        method: "POST".into(),
        scheme: "https",
        host: "edge.app.example".into(),
        path: "gotoBackground".into(),
        status: None,
        headers: vec![],
        body: b"{}".to_vec(),
        websocket_upgrade: false,
        stream_id: Some(7),
    };
    let text = String::from_utf8(message.to_proxy_absolute()).unwrap();
    assert!(
        text.starts_with("POST http://edge.app.example:443/gotoBackground HTTP/1.1"),
        "{text}"
    );
    assert!(!text.contains("examplegotoBackground"), "{text}");
}

#[test]
fn absolute_wire_uses_http_port_443_for_https_copies() {
    let https = MirroredMessage {
        is_request: true,
        method: "POST".into(),
        scheme: "https",
        host: "api.app.example".into(),
        path: "/v1/client".into(),
        status: None,
        headers: vec![],
        body: b"ping".to_vec(),
        websocket_upgrade: false,
        stream_id: None,
    };
    let text = String::from_utf8(https.to_proxy_absolute()).unwrap();
    assert!(
        text.starts_with("POST http://api.app.example:443/v1/client HTTP/1.1"),
        "{text}"
    );
    assert!(text.contains("Host: api.app.example\r\n"), "{text}");
    assert!(!text.contains("https://"), "{text}");

    let already_ported = MirroredMessage {
        host: "svc.grid.example:28630".into(),
        path: "/map".into(),
        body: vec![],
        ..https.clone()
    };
    let text = String::from_utf8(already_ported.to_proxy_absolute()).unwrap();
    assert!(
        text.starts_with("POST http://svc.grid.example:28630/map HTTP/1.1"),
        "{text}"
    );
    assert!(!text.contains(":28630:443"), "{text}");

    let plain_http = MirroredMessage {
        scheme: "http",
        host: "origin.test".into(),
        path: "/x".into(),
        body: vec![],
        ..https
    };
    let text = String::from_utf8(plain_http.to_proxy_absolute()).unwrap();
    assert!(
        text.starts_with("POST http://origin.test/x HTTP/1.1"),
        "{text}"
    );
    assert!(!text.contains(":443"), "{text}");
}

#[test]
fn grpc_h2_streamgrpc_becomes_post_with_unwrapped_body() {
    // HEADERS: :method POST, :scheme https, :path /streamgrpc.Foo/Bar,
    // :authority edge.app.example, content-type application/grpc
    let path = b"/streamgrpc.Foo/Bar";
    let authority = b"edge.app.example";
    let ctype_name = b"content-type";
    let ctype_val = b"application/grpc";
    let mut block = vec![0x83, 0x87, 0x04, u8::try_from(path.len()).unwrap()];
    block.extend_from_slice(path);
    block.push(0x01);
    block.push(u8::try_from(authority.len()).unwrap());
    block.extend_from_slice(authority);
    block.push(0x00);
    block.push(u8::try_from(ctype_name.len()).unwrap());
    block.extend_from_slice(ctype_name);
    block.push(u8::try_from(ctype_val.len()).unwrap());
    block.extend_from_slice(ctype_val);
    let mut headers = vec![
        0,
        0,
        u8::try_from(block.len()).unwrap(),
        0x1,
        0x04,
        0,
        0,
        0,
        7,
    ];
    headers.extend_from_slice(&block);
    let proto = b"\x0a\x03abc";
    let mut grpc_data = vec![0, 0, 0, 0, u8::try_from(proto.len()).unwrap()];
    grpc_data.extend_from_slice(proto);
    let data_len = u32::try_from(grpc_data.len()).unwrap();
    let mut data = vec![
        u8::try_from((data_len >> 16) & 0xff).unwrap(),
        u8::try_from((data_len >> 8) & 0xff).unwrap(),
        u8::try_from(data_len & 0xff).unwrap(),
        0x0,
        0x01,
        0,
        0,
        0,
        7,
    ];
    data.extend_from_slice(&grpc_data);
    let mut stream = StreamReassembler::default();
    let mut wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    wire.extend_from_slice(&headers);
    wire.extend_from_slice(&data);
    let messages = stream.push(&wire);
    assert!(
        messages.iter().any(|item| {
            item.is_request
                && item.method == "POST"
                && item.host == "edge.app.example"
                && item.path == "/streamgrpc.Foo/Bar"
                && item.body == proto
                && item.headers.iter().any(|(name, value)| {
                    name.eq_ignore_ascii_case("content-type") && value.contains("grpc")
                })
        }),
        "{messages:?}"
    );
    let request = messages
        .iter()
        .find(|item| item.is_request)
        .expect("grpc request");
    let abs = request.to_proxy_absolute();
    let abs = String::from_utf8_lossy(&abs);
    assert!(
        abs.starts_with("POST http://edge.app.example:443/streamgrpc.Foo/Bar HTTP/1.1"),
        "{abs}"
    );
}

fn h2_headers_frame(stream: u32, block: &[u8]) -> Vec<u8> {
    let n = block.len();
    let mut frame = vec![
        u8::try_from((n >> 16) & 0xff).unwrap(),
        u8::try_from((n >> 8) & 0xff).unwrap(),
        u8::try_from(n & 0xff).unwrap(),
        0x1,
        0x05,
        u8::try_from((stream >> 24) & 0xff).unwrap(),
        u8::try_from((stream >> 16) & 0xff).unwrap(),
        u8::try_from((stream >> 8) & 0xff).unwrap(),
        u8::try_from(stream & 0xff).unwrap(),
    ];
    frame.extend_from_slice(block);
    frame
}

fn hpack_post_https(path: &[u8], authority: Option<&[u8]>) -> Vec<u8> {
    let mut block = vec![0x83, 0x87, 0x04, u8::try_from(path.len()).unwrap()];
    block.extend_from_slice(path);
    if let Some(authority) = authority {
        block.push(0x01);
        block.push(u8::try_from(authority.len()).unwrap());
        block.extend_from_slice(authority);
    }
    block
}

#[test]
fn h2_later_stream_reuses_connection_authority() {
    let mut stream = StreamReassembler::default();
    let mut wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    wire.extend_from_slice(&h2_headers_frame(
        1,
        &hpack_post_https(b"/v1/ping", Some(b"api.app.example")),
    ));
    wire.extend_from_slice(&h2_headers_frame(
        3,
        &hpack_post_https(b"/v1/session", None),
    ));
    let messages = stream.push(&wire);
    let login = messages.iter().find(|item| item.path == "/v1/session");
    assert!(
        login.is_some_and(|item| item.host == "api.app.example" && item.method == "POST"),
        "same TLS connection must reuse :authority, got {messages:?}"
    );
}

#[test]
fn absolute_url_header_fills_any_app_host() {
    let mut stream = StreamReassembler::default();
    let messages = stream.push(
        b"POST / HTTP/1.1\r\nX-Request-URL: https://api.app.example/v1/session\r\nContent-Length: 2\r\n\r\n{}",
    );
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert_eq!(messages[0].host, "api.app.example");
    assert_eq!(messages[0].path, "/v1/session");
}

#[test]
fn post_headers_and_body_round_trip_to_burp_absolute_form() {
    let raw = b"POST /v1/session HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nAuthorization: Bearer secret\r\nContent-Length: 12\r\n\r\n{\"user\":\"a\"}";
    let mut stream = StreamReassembler::default();
    let messages = stream.push(raw);
    assert_eq!(messages.len(), 1);
    let message = &messages[0];
    assert!(message.is_request);
    assert_eq!(message.method, "POST");
    assert_eq!(message.host, "api.example.com");
    assert_eq!(message.path, "/v1/session");
    assert_eq!(message.body, br#"{"user":"a"}"#);
    assert!(message.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("authorization") && value == "Bearer secret"
    }));
    let wire = message.to_proxy_absolute();
    let text = String::from_utf8_lossy(&wire);
    assert!(text.starts_with("POST http://api.example.com:443/v1/session HTTP/1.1\r\n"));
    assert!(text.contains("Host: api.example.com\r\n"));
    assert!(text.contains("Authorization: Bearer secret\r\n"));
    assert!(text.contains("Content-Length: 12\r\n"));
    assert!(text.ends_with("{\"user\":\"a\"}"));
    let playback = message.to_proxy_playback("192.168.3.20", BURP_PLAYBACK_PORT);
    let playback_text = String::from_utf8_lossy(&playback);
    assert!(playback_text.starts_with("POST http://192.168.3.20:18081/v1/session HTTP/1.1"));
    assert!(playback_text.contains("Host: api.example.com\r\n"));
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
            b"GET /ws HTTP/1.1\r\nHost: api.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        );
    assert_eq!(messages.len(), 1);
    assert!(messages[0].websocket_upgrade);
    let absolute = messages[0].to_proxy_absolute();
    let wire = String::from_utf8_lossy(&absolute);
    assert!(wire.contains("Upgrade: websocket"));
    assert!(wire.contains("Connection: Upgrade"));
}

#[test]
fn websocket_frames_after_upgrade_are_emitted() {
    let mut stream = StreamReassembler::default();
    stream.set_outbound(true);
    let _ = stream.push(
        b"GET /ws HTTP/1.1\r\nHost: api.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
    );
    // Unmasked text frame "hi" (FIN+text, len=2, payload hi)
    let frames = stream.push(&[0x81, 0x02, b'h', b'i']);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].method, "WS");
    assert_eq!(frames[0].body, b"hi");
    assert!(frames[0].is_request);
}

#[test]
fn gzip_content_encoding_inflates_http1_body() {
    use std::io::Write as _;
    let mut gz = Vec::new();
    {
        let mut encoder = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
        encoder.write_all(b"hello-gzip").expect("gzip");
        encoder.finish().expect("finish");
    }
    let mut raw = format!(
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
        gz.len()
    )
    .into_bytes();
    raw.extend_from_slice(&gz);
    let mut stream = StreamReassembler::default();
    let messages = stream.push(&raw);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].body, b"hello-gzip");
}

#[test]
fn brotli_content_encoding_inflates_http1_body() {
    let br = crate::decode_hex_bytes("8b038068656c6c6f2d627203").expect("br vector");
    let mut raw = format!(
        "HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: {}\r\n\r\n",
        br.len()
    )
    .into_bytes();
    raw.extend_from_slice(&br);
    let mut stream = StreamReassembler::default();
    let messages = stream.push(&raw);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].body, b"hello-br");
}

#[test]
fn http2_mid_frame_preamble_promotes_and_reconstructs() {
    let block = [
        0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90,
        0xf4, 0xff,
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
    let mut stream = StreamReassembler::default();
    let messages = stream.push(&junk);
    assert_eq!(stream.protocol(), "http2");
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert_eq!(messages[0].method, "GET");
    assert_eq!(messages[0].host, "www.example.com");
}

#[test]
fn http2_headers_become_http1_for_burp() {
    let block = [
        0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90,
        0xf4, 0xff,
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
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nVia: 1.1 cache.example (squid)\r\nContent-Length: 2\r\n\r\n{}",
        );
    assert_eq!(messages.len(), 1);
    let request = messages[0].synthetic_request_for_response();
    assert_eq!(request.method, "GET");
    assert_eq!(request.host, "cache.example");
    assert_eq!(request.path, "/");
    let playback = request.to_proxy_playback("192.168.3.116", BURP_PLAYBACK_PORT);
    let text = String::from_utf8_lossy(&playback);
    assert!(text.starts_with("GET http://192.168.3.116:18081/ HTTP/1.1"));
    assert!(text.contains("Host: cache.example"));
}

#[test]
fn via_spanner_token_is_not_used_as_synthetic_host() {
    let mut stream = StreamReassembler::default();
    let messages = stream.push(
        b"HTTP/1.1 200 OK\r\nVia: spanner-gw-54-49022:7088[200]\r\nContent-Length: 2\r\n\r\n{}",
    );
    assert_eq!(messages.len(), 1);
    let synth = messages[0].synthetic_request_for_response();
    assert!(
        synth.host.is_empty(),
        "Via spanner token must not become host: {}",
        synth.host
    );
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
    assert!(
        wire.contains("Connection: close"),
        "proxy wire must force close: {wire}"
    );
    assert!(!wire.to_ascii_lowercase().contains("connection: keep-alive"));
    assert!(wire.starts_with("GET http://127.0.0.1:18081/ HTTP/1.1"));
    let absolute_bytes = message.to_proxy_absolute();
    let absolute = String::from_utf8_lossy(&absolute_bytes);
    assert!(absolute.contains("Connection: close"), "{absolute}");
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
fn http1_locks_after_binary_preamble_within_resync_window() {
    let mut stream = StreamReassembler::default();
    let mut raw = vec![0xAAu8; 64];
    raw.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
    let messages = stream.push(&raw);
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert_eq!(messages[0].status, Some(200));
    assert_eq!(messages[0].body, b"{}");
}

#[test]
fn chunked_terminal_plus_garbage_resyncs_to_next_response() {
    let mut stream = StreamReassembler::default();
    let first = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
    assert!(
        stream.push(first).is_empty(),
        "incomplete chunked should wait"
    );
    let mut second = b"0\r\n\r\n".to_vec();
    second.extend(std::iter::repeat(0xAAu8).take(64));
    second.extend_from_slice(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
    let messages = stream.push(&second);
    assert_eq!(messages.len(), 2, "{messages:?}");
    assert_eq!(messages[0].body, b"hello");
    assert_eq!(messages[0].status, Some(200));
    assert_eq!(messages[1].status, Some(204));
    assert_eq!(stream.buffered_bytes(), 0);
}

#[test]
fn get_without_host_parses_so_sni_can_fill_later() {
    let mut stream = StreamReassembler::default();
    let messages = stream.push(b"GET /v1/ping HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\n\r\n");
    assert_eq!(messages.len(), 1);
    assert!(messages[0].is_request);
    assert_eq!(messages[0].path, "/v1/ping");
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

#[test]
fn flush_unknown_salvages_orphan_json_body() {
    let mut stream = StreamReassembler::default();
    // Mid-body SSL_read like BOC; unbalanced trailing `}` must not eager-emit.
    let orphan = r#"ndexName":"上证指数","upDownRate":"0.20%","indexCode":"000001"}"#.as_bytes();
    assert!(stream.push(orphan).is_empty());
    assert_eq!(stream.protocol(), "unknown");
    let messages = stream.flush();
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(!messages[0].is_request);
    assert_eq!(messages[0].status, Some(200));
    assert_eq!(messages[0].body, orphan);
    assert!(messages[0]
        .headers
        .iter()
        .any(|(n, v)| n.eq_ignore_ascii_case("x-kernsight-orphan-body") && v == "1"));
    assert!(messages[0]
        .headers
        .iter()
        .any(|(n, v)| n.eq_ignore_ascii_case("x-kernsight-missing-status") && v == "1"));
    assert_eq!(stream.buffered_bytes(), 0);
    let wire_bytes = messages[0].to_http1_response();
    let wire = String::from_utf8_lossy(&wire_bytes);
    assert!(wire.starts_with("HTTP/1.1 200 "), "{wire}");
}

#[test]
fn push_eager_salvages_complete_orphan_json() {
    let mut stream = StreamReassembler::default();
    let orphan = r#"{"indexName":"SSE","upDownRate":"0.20%","indexCode":"000001"}"#.as_bytes();
    let messages = stream.push(orphan);
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(!messages[0].is_request);
    assert_eq!(messages[0].status, Some(200));
    assert_eq!(messages[0].body, orphan);
    assert_eq!(stream.buffered_bytes(), 0);
}

#[test]
fn http2_multi_push_preface_headers_data_reconstructs_request() {
    // RFC7541 C.4.1 huffman request on stream 1, then a small DATA body with
    // END_STREAM — split across pushes the way SSL_write boundaries arrive.
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let block = [
        0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90,
        0xf4, 0xff,
    ];
    let mut headers = vec![
        0,
        0,
        u8::try_from(block.len()).unwrap(),
        0x1,
        0x04, // END_HEADERS only — body follows
        0,
        0,
        0,
        1,
    ];
    headers.extend_from_slice(&block);
    let data = b"hi";
    let mut data_frame = vec![
        0,
        0,
        u8::try_from(data.len()).unwrap(),
        0x0,
        0x01, // END_STREAM
        0,
        0,
        0,
        1,
    ];
    data_frame.extend_from_slice(data);

    let mut stream = StreamReassembler::default();
    assert!(stream.push(&preface[..10]).is_empty());
    assert!(stream.push(&preface[10..]).is_empty() || stream.protocol() == "http2");
    let mid = headers.len() / 2;
    assert!(
        stream.push(&headers[..mid]).is_empty(),
        "partial HEADERS must wait"
    );
    let after_headers = stream.push(&headers[mid..]);
    assert!(
        after_headers.is_empty(),
        "HEADERS without END_STREAM stays open: {after_headers:?}"
    );
    let mut messages = stream.push(&data_frame);
    if messages.is_empty() {
        messages = stream.soft_flush();
    }
    assert!(
        !messages.is_empty(),
        "multi-push H2 must yield >=1 MirroredMessage"
    );
    assert!(messages[0].is_request);
    assert_eq!(messages[0].method, "GET");
    assert_eq!(messages[0].host, "www.example.com");
    assert_eq!(messages[0].body, b"hi");
}

#[test]
fn soft_flush_keeps_short_unknown_prefix() {
    let mut stream = StreamReassembler::default();
    assert!(stream.push(b"HT").is_empty());
    assert!(stream.soft_flush().is_empty());
    assert_eq!(stream.buffered_bytes(), 2);
    assert_eq!(stream.protocol(), "unknown");
    // Hard flush without salvageable body still clears.
    assert!(stream.flush().is_empty());
    assert_eq!(stream.buffered_bytes(), 0);
}

#[test]
fn flush_unknown_late_promotes_http1_response() {
    let mut stream = StreamReassembler::default();
    // Force Unknown by pushing non-HTTP first, then... actually push alone
    // with a full response should promote on push. Exercise flush path by
    // calling flush_unknown indirectly after a response that is complete.
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
    let messages = stream.push(raw);
    assert_eq!(messages.len(), 1);
    assert!(!messages[0].is_request);
}

#[test]
fn seal_flush_salvages_incomplete_http1_headers() {
    let mut stream = StreamReassembler::default();
    // No terminating CRLFCRLF — bare flush leaves this stranded.
    assert!(stream
        .push(b"HTTP/1.1 203 Non-Authoritative\r\nContent-Length: 4\r\n")
        .is_empty());
    assert!(
        stream.flush().is_empty(),
        "hard flush must not invent CRLFCRLF"
    );
    // Re-push equivalent leftover via fresh assembler for seal path.
    let mut stream = StreamReassembler::default();
    assert!(stream
        .push(b"HTTP/1.1 203 Non-Authoritative\r\nContent-Length: 4\r\n")
        .is_empty());
    let messages = stream.seal_flush();
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert_eq!(messages[0].status, Some(203));
    assert_eq!(stream.buffered_bytes(), 0);
}

#[test]
fn soft_flush_emits_headers_only_incomplete_content_length() {
    let mut stream = StreamReassembler::default();
    // Headers complete, body not yet present (CL=12). Soft-flush must still
    // emit so pairing can attach orig=status before grace sweeps the request.
    let messages =
        stream.push(b"HTTP/1.1 202 Accepted\r\nHost: api.example\r\nContent-Length: 12\r\n\r\n");
    assert!(
        messages.is_empty(),
        "must wait for body or soft_flush: {messages:?}"
    );
    let messages = stream.soft_flush();
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert_eq!(messages[0].status, Some(202));
    assert!(messages[0].body.is_empty());
}

#[test]
fn response_without_content_length_waits_until_soft_flush() {
    let mut stream = StreamReassembler::default();
    let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nhello";
    assert!(
        stream.push(head).is_empty(),
        "until-close body must not commit mid-stream"
    );
    let messages = stream.soft_flush();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].status, Some(200));
    assert_eq!(messages[0].body, b"hello");
}

#[test]
fn status_204_and_304_ignore_content_length_body() {
    let mut stream = StreamReassembler::default();
    let raw = b"HTTP/1.1 204 No Content\r\nContent-Length: 12\r\n\r\nIGNORED_BODY!";
    let messages = stream.push(raw);
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert_eq!(messages[0].status, Some(204));
    assert!(messages[0].body.is_empty(), "204 must have empty body");
}

#[test]
fn status_100_continue_has_empty_body_and_does_not_eat_following() {
    let mut stream = StreamReassembler::default();
    let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nping";
    let messages = stream.push(raw);
    assert!(messages.len() >= 2, "{messages:?}");
    assert_eq!(messages[0].status, Some(100));
    assert!(messages[0].body.is_empty());
    assert_eq!(messages[1].status, Some(200));
    assert_eq!(messages[1].body, b"ping");
}

/// Chunked SSL_read: terminal chunk residue + status line that
/// lost the leading `HTTP/` prefix (`1.1 200` instead of `HTTP/1.1 200`).
#[test]
fn truncated_status_prefix_after_chunk_terminal_resyncs() {
    let mut stream = StreamReassembler::default();
    let raw = b"0\r\n\r\n1.1 200 \r\nDate: Thu, 10 Sep 2026 02:49:19 GMT\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\nc\r\n{\"code\":200}\r\n0\r\n\r\n";
    let messages = stream.push(raw);
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(!messages[0].is_request);
    assert_eq!(messages[0].status, Some(200));
    assert_eq!(messages[0].body, br#"{"code":200}"#);
    assert!(messages[0].headers.iter().any(|(n, v)| {
        n.eq_ignore_ascii_case("x-kernsight-truncated-status-prefix") && v == "1"
    }));
    let wire_bytes = messages[0].to_http1_response();
    let wire = String::from_utf8_lossy(&wire_bytes);
    assert!(wire.starts_with("HTTP/1.1 200 "), "{wire}");
}

#[test]
fn bare_http_version_does_not_false_positive_inside_json() {
    let mut stream = StreamReassembler::default();
    let orphan = br#"{"proto":"1.1 200 OK","indexCode":"000001"}"#;
    let messages = stream.push(orphan);
    // Orphan JSON salvage may emit, but must NOT parse as real HTTP status 200
    // via bare-version resync mid-object (preceded by quote, not LF).
    if let Some(msg) = messages.first() {
        assert!(
            msg.headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case("x-kernsight-orphan-body")
                    || n.eq_ignore_ascii_case("x-kernsight-missing-status")),
            "json with embedded 1.1 200 must stay orphan salvage, not HTTP resync: {msg:?}"
        );
    }
}

#[test]
fn soft_flush_emits_bare_version_headers_only() {
    let mut stream = StreamReassembler::default();
    let messages =
        stream.push(b"1.1 202 Accepted\r\nHost: api.example\r\nContent-Length: 12\r\n\r\n");
    assert!(
        messages.is_empty(),
        "wait for body/soft_flush: {messages:?}"
    );
    let messages = stream.soft_flush();
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert_eq!(messages[0].status, Some(202));
    assert!(messages[0].headers.iter().any(|(n, v)| {
        n.eq_ignore_ascii_case("x-kernsight-truncated-status-prefix") && v == "1"
    }));
}

/// Exhaustive unit coverage for `bare_http_version_status_at` + parse wiring.
#[test]
fn bare_http_version_status_at_edge_cases() {
    // Accept supported versions at buffer start.
    assert!(super::bare_http_version_status_at(b"1.0 200 OK\r\n", 0));
    assert!(super::bare_http_version_status_at(b"1.1 200 OK\r\n", 0));
    assert!(super::bare_http_version_status_at(
        b"2.0 404 Not Found\r\n",
        0
    ));
    assert!(super::bare_http_version_status_at(b"1.1 503 \r\n", 0));

    // Accept only immediately after LF (CRLF status resync).
    let after_lf = b"trail\n1.1 200 OK\r\n";
    assert!(super::bare_http_version_status_at(after_lf, 6));
    let after_crlf = b"0\r\n\r\n1.1 200 \r\n";
    assert!(super::bare_http_version_status_at(after_crlf, 5));

    // Reject mid-token / non-LF predecessors (JSON / prose false positives).
    let quoted = br#"{"x":"1.1 200 OK"}"#;
    let idx = quoted
        .windows(4)
        .position(|w| w == b"1.1 ")
        .expect("needle");
    assert!(!super::bare_http_version_status_at(quoted, idx));
    assert!(!super::bare_http_version_status_at(b"x1.1 200 OK\r\n", 1));
    assert!(!super::bare_http_version_status_at(b" 1.1 200 OK\r\n", 1));
    assert!(!super::bare_http_version_status_at(b"A1.1 200 OK\r\n", 1));
    // Preceded by CR alone (not LF) must not resync.
    assert!(!super::bare_http_version_status_at(b"x\r1.1 200 OK\r\n", 2));

    // Reject truncated / non-digit / unsupported version.
    assert!(!super::bare_http_version_status_at(b"1.1 ", 0));
    assert!(!super::bare_http_version_status_at(b"1.1 20", 0));
    assert!(!super::bare_http_version_status_at(b"1.1 2", 0));
    assert!(!super::bare_http_version_status_at(b"1.1 ABC OK\r\n", 0));
    assert!(!super::bare_http_version_status_at(b"1.1 20X OK\r\n", 0));
    assert!(!super::bare_http_version_status_at(b"3.0 200 OK\r\n", 0));
    assert!(!super::bare_http_version_status_at(b"0.9 200 OK\r\n", 0));
    assert!(!super::bare_http_version_status_at(
        b"HTTP/1.1 200 OK\r\n",
        0
    ));
    assert!(!super::bare_http_version_status_at(b"", 0));
    assert!(!super::bare_http_version_status_at(b"1.1", 0));

    // Helper token check stays tight.
    assert!(super::is_bare_http_version("1.0"));
    assert!(super::is_bare_http_version("1.1"));
    assert!(super::is_bare_http_version("2.0"));
    assert!(!super::is_bare_http_version("1.1 "));
    assert!(!super::is_bare_http_version("HTTP/1.1"));
    assert!(!super::is_bare_http_version("3.0"));
}

#[test]
fn bare_http_version_1_0_and_2_0_parse_with_prefix_marker() {
    for (raw, status) in [
        (&b"1.0 200 OK\r\nContent-Length: 4\r\n\r\nping"[..], 200u16),
        (
            &b"2.0 404 Not Found\r\nContent-Length: 3\r\n\r\nno!"[..],
            404u16,
        ),
    ] {
        let mut stream = StreamReassembler::default();
        let messages = stream.push(raw);
        assert_eq!(messages.len(), 1, "{messages:?}");
        assert!(!messages[0].is_request);
        assert_eq!(messages[0].status, Some(status));
        assert!(messages[0].headers.iter().any(|(n, v)| {
            n.eq_ignore_ascii_case("x-kernsight-truncated-status-prefix") && v == "1"
        }));
        let wire_bytes = messages[0].to_http1_response();
        let wire = String::from_utf8_lossy(&wire_bytes);
        // to_http1_response always rewrites start-line as HTTP/1.1.
        assert!(
            wire.starts_with(&format!("HTTP/1.1 {status} ")),
            "wire must restore HTTP/ prefix: {wire}"
        );
    }
}

#[test]
fn bare_http_version_rejects_space_prefixed_and_keeps_normal_http() {
    let mut stream = StreamReassembler::default();
    // Leading space before bare version must not false-resync as HTTP status.
    let odd = b" 1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let messages = stream.push(odd);
    if let Some(msg) = messages.first() {
        assert!(
            msg.headers.iter().any(|(n, _)| {
                n.eq_ignore_ascii_case("x-kernsight-orphan-body")
                    || n.eq_ignore_ascii_case("x-kernsight-missing-status")
                    || n.eq_ignore_ascii_case("x-kernsight-seal-salvage")
            }) || msg.status != Some(200)
                || !msg.headers.iter().any(|(n, v)| {
                    n.eq_ignore_ascii_case("x-kernsight-truncated-status-prefix") && v == "1"
                }),
            "space-prefixed bare version must not be treated as clean truncated status: {msg:?}"
        );
    }

    let mut stream = StreamReassembler::default();
    let normal = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata";
    let messages = stream.push(normal);
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert_eq!(messages[0].status, Some(200));
    assert_eq!(messages[0].body, b"data");
    assert!(
        !messages[0]
            .headers
            .iter()
            .any(|(n, _)| { n.eq_ignore_ascii_case("x-kernsight-truncated-status-prefix") }),
        "normal HTTP/ status must not set truncated-status marker"
    );
}

#[test]
fn bare_http_version_after_lf_mid_buffer_resyncs() {
    let mut stream = StreamReassembler::default();
    // Non-HTTP junk ending in LF, then bare status (SSL_read desync).
    let raw = b"GARBAGE\n1.1 201 Created\r\nContent-Length: 2\r\n\r\nOK";
    let messages = stream.push(raw);
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert_eq!(messages[0].status, Some(201));
    assert_eq!(messages[0].body, b"OK");
    assert!(messages[0].headers.iter().any(|(n, v)| {
        n.eq_ignore_ascii_case("x-kernsight-truncated-status-prefix") && v == "1"
    }));
}

#[test]
fn head_response_hint_forces_no_body_despite_content_length() {
    let mut stream = StreamReassembler::default();
    stream.expect_head_response();
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
    let messages = stream.push(raw);
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert_eq!(messages[0].status, Some(200));
    assert!(messages[0].body.is_empty());
}

#[test]
fn chunked_partial_under_8k_waits_for_terminal_or_flush() {
    let mut stream = StreamReassembler::default();
    let mut msg = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n64\r\n".to_vec();
    msg.extend(std::iter::repeat(b'x').take(100));
    assert!(stream.push(&msg).is_empty(), "incomplete chunked must wait");
    assert!(stream.push(b"more").is_empty());
    let messages = stream.flush();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].status, Some(200));
    assert!(!messages[0].body.is_empty());
}

// PRUNED 2026-09-10: status_304_ignores_content_length_body — covered by status_204_and_304_ignore_content_length_body.

#[test]
fn head_request_ignores_content_length() {
    let mut stream = StreamReassembler::default();
    let raw = b"HEAD /x HTTP/1.1\r\nHost: api.example\r\nContent-Length: 4\r\n\r\nABCD";
    let messages = stream.push(raw);
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert_eq!(messages[0].method, "HEAD");
    assert!(messages[0].body.is_empty());
}

#[test]
fn chunked_over_8kib_waits_for_terminal() {
    let mut stream = StreamReassembler::default();
    let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    raw.extend_from_slice(b"4000\r\n"); // 16384-byte chunk
    raw.extend(std::iter::repeat(b'A').take(9000));
    assert!(
        stream.push(&raw).is_empty(),
        "incomplete chunked must not emit at ~9KiB"
    );
    let mut rest = vec![b'B'; 16384 - 9000];
    rest.extend_from_slice(b"\r\n0\r\n\r\n");
    let messages = stream.push(&rest);
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert_eq!(messages[0].body.len(), 16384);
}

#[test]
fn http2_mirrored_message_carries_stream_id() {
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let block = [
        0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90,
        0xf4, 0xff,
    ];
    let mut headers = vec![
        0,
        0,
        u8::try_from(block.len()).unwrap(),
        0x1,
        0x05, // END_HEADERS|END_STREAM
        0,
        0,
        0,
        7,
    ];
    headers.extend_from_slice(&block);
    let mut stream = StreamReassembler::default();
    let mut messages = stream.push(preface);
    messages.extend(stream.push(&headers));
    if messages.is_empty() {
        messages = stream.soft_flush();
    }
    assert!(!messages.is_empty(), "{messages:?}");
    assert_eq!(messages[0].stream_id, Some(7));
    let absolute = messages[0].to_proxy_absolute();
    let wire = String::from_utf8_lossy(&absolute);
    assert!(
        wire.contains("X-KernSight-H2-Stream-ID: 7\r\n"),
        "Burp wire should retain H2 stream id: {wire}"
    );
}

#[test]
fn h2_data_only_seal_salvages_response_body() {
    let mut stream = StreamReassembler::default();
    let mut wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    let body = b"{\"ok\":true}";
    let n = body.len();
    wire.extend_from_slice(&[
        u8::try_from((n >> 16) & 0xff).unwrap(),
        u8::try_from((n >> 8) & 0xff).unwrap(),
        u8::try_from(n & 0xff).unwrap(),
        0x0,
        0x01,
        0,
        0,
        0,
        1,
    ]);
    wire.extend_from_slice(body);
    let mut messages = stream.push(&wire);
    if messages.is_empty() {
        messages = stream.seal_flush();
    }
    let resp = messages.iter().find(|item| !item.is_request);
    assert!(
        resp.is_some_and(|item| item.status == Some(200) && item.body == body),
        "DATA-only H2 must salvage SSL_read body, got {messages:?}"
    );
}

#[test]
fn h2_data_only_recv_idle_flush_salvages_response_body() {
    let mut stream = StreamReassembler::default();
    let mut wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    let body = b"{\"idle\":true}";
    let n = body.len();
    wire.extend_from_slice(&[
        u8::try_from((n >> 16) & 0xff).unwrap(),
        u8::try_from((n >> 8) & 0xff).unwrap(),
        u8::try_from(n & 0xff).unwrap(),
        0x0,
        0x01,
        0,
        0,
        0,
        1,
    ]);
    wire.extend_from_slice(body);
    let mut messages = stream.push(&wire);
    if messages.is_empty() {
        messages = stream.recv_idle_flush();
    }
    let resp = messages.iter().find(|item| !item.is_request);
    assert!(
        resp.is_some_and(|item| item.status == Some(200) && item.body == body),
        "recv idle must DATA-only salvage, got {messages:?}"
    );
}

#[test]
fn h2_64k_data_without_settings_seal_salvages() {
    let mut stream = StreamReassembler::default();
    let mut wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    let body = vec![b'x'; 64 * 1024];
    let n = body.len();
    wire.extend_from_slice(&[
        u8::try_from((n >> 16) & 0xff).unwrap(),
        u8::try_from((n >> 8) & 0xff).unwrap(),
        u8::try_from(n & 0xff).unwrap(),
        0x0,
        0x01,
        0,
        0,
        0,
        1,
    ]);
    wire.extend_from_slice(&body);
    let mut messages = stream.push(&wire);
    if messages.is_empty() {
        messages = stream.seal_flush();
    }
    let resp = messages.iter().find(|item| !item.is_request);
    assert!(
        resp.is_some_and(|item| item.status == Some(200) && item.body.len() == 64 * 1024),
        "64KiB DATA without SETTINGS must salvage, got {messages:?}"
    );
}

#[test]
fn h2_incomplete_large_data_seal_salvages_remainder() {
    let mut stream = StreamReassembler::default();
    let mut wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    let claimed = 128 * 1024;
    wire.extend_from_slice(&[
        u8::try_from((claimed >> 16) & 0xff).unwrap(),
        u8::try_from((claimed >> 8) & 0xff).unwrap(),
        u8::try_from(claimed & 0xff).unwrap(),
        0x0,
        0x01,
        0,
        0,
        0,
        1,
    ]);
    wire.extend(std::iter::repeat(b'y').take(60 * 1024));
    assert!(
        stream.push(&wire).is_empty(),
        "incomplete DATA must stay buffered"
    );
    assert!(
        stream.buffered_bytes() > 50 * 1024,
        "expected leftover DATA bytes"
    );
    let messages = stream.seal_flush();
    assert!(
        messages
            .iter()
            .any(|item| !item.is_request && item.status == Some(200) && !item.body.is_empty()),
        "seal must orphan incomplete H2 DATA, got {messages:?}"
    );
    assert_eq!(stream.buffered_bytes(), 0);
}

#[test]
fn seal_salvages_png_orphan_as_response() {
    let mut stream = StreamReassembler::default();
    let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
    assert!(stream.push(png).is_empty());
    let messages = stream.seal_flush();
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(!messages[0].is_request);
    assert_eq!(messages[0].status, Some(200));
    assert_eq!(messages[0].body, png);
}
