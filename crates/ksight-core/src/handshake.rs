//! Bounded first-write handshake metadata: TLS `ClientHello`, HTTP/1, QUIC long header.

/// Parsed first-send protocol metadata. Bodies stay ciphertext except cleartext HTTP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeMeta {
    /// `tls`, `http`, or `quic`.
    pub kind: &'static str,
    /// TLS SNI hostname, when present and not empty.
    pub sni: Option<String>,
    /// Comma-joined ALPN protocol list, when present.
    pub alpn: Option<String>,
    /// True when the `encrypted_client_hello` extension (`0xfe0d`) was present.
    pub ech: bool,
    /// HTTP/1 method or HTTP/2 preface `PRI`.
    pub http_method: Option<String>,
    /// HTTP request-target.
    pub http_path: Option<String>,
    /// HTTP `Host` header.
    pub http_host: Option<String>,
    /// QUIC version as `0x` plus eight hex digits.
    pub quic_version: Option<String>,
    /// QUIC long-header packet type: `initial`, `0rtt`, `handshake`, `retry`, or `long`.
    pub quic_packet: Option<String>,
}

/// Classify a bounded first-write payload copied from write/sendto/sendmsg.
#[must_use]
pub fn parse_handshake(payload: &[u8]) -> Option<HandshakeMeta> {
    parse_tls_client_hello(payload)
        .or_else(|| parse_http_request(payload))
        .or_else(|| parse_quic_long_header(payload))
}

fn parse_tls_client_hello(payload: &[u8]) -> Option<HandshakeMeta> {
    let mut offset = 0_usize;
    while offset.saturating_add(6) <= payload.len() {
        if payload[offset] != 0x16 || payload[offset + 1] != 0x03 {
            break;
        }
        let record_len = u16::from_be_bytes([payload[offset + 3], payload[offset + 4]]) as usize;
        let body = offset.saturating_add(5);
        if body >= payload.len() {
            break;
        }
        if payload[body] == 0x01 {
            return parse_client_hello_body(&payload[body..]);
        }
        offset = body.saturating_add(record_len);
    }
    None
}

fn parse_client_hello_body(handshake: &[u8]) -> Option<HandshakeMeta> {
    if handshake.len() < 4 || handshake[0] != 0x01 {
        return None;
    }
    let hello_len = u24(&handshake[1..4]);
    let hello = handshake.get(4..4 + hello_len.min(handshake.len().saturating_sub(4)))?;
    if hello.len() < 34 {
        return None;
    }
    let mut cursor = 34_usize;
    let session_id_len = usize::from(*hello.get(cursor)?);
    cursor = cursor.saturating_add(1).saturating_add(session_id_len);
    let cipher_len = usize::from(read_u16(hello, cursor)?);
    cursor = cursor.saturating_add(2).saturating_add(cipher_len);
    let compression_len = usize::from(*hello.get(cursor)?);
    cursor = cursor.saturating_add(1).saturating_add(compression_len);
    if cursor == hello.len() {
        return Some(HandshakeMeta {
            kind: "tls",
            sni: None,
            alpn: None,
            ech: false,
            http_method: None,
            http_path: None,
            http_host: None,
            quic_version: None,
            quic_packet: None,
        });
    }
    let ext_total = usize::from(read_u16(hello, cursor)?);
    cursor = cursor.saturating_add(2);
    let ext_end = cursor.saturating_add(ext_total).min(hello.len());
    let mut sni = None;
    let mut alpn = None;
    let mut ech = false;
    while cursor.saturating_add(4) <= ext_end {
        let ext_type = read_u16(hello, cursor)?;
        let ext_len = usize::from(read_u16(hello, cursor + 2)?);
        cursor = cursor.saturating_add(4);
        let Some(body) = hello.get(cursor..cursor.saturating_add(ext_len)) else {
            break;
        };
        match ext_type {
            0x0000 => sni = parse_sni(body),
            0x0010 => alpn = parse_alpn(body),
            0xfe0d => ech = true,
            _ => {}
        }
        cursor = cursor.saturating_add(ext_len);
    }
    Some(HandshakeMeta {
        kind: "tls",
        sni,
        alpn,
        ech,
        http_method: None,
        http_path: None,
        http_host: None,
        quic_version: None,
        quic_packet: None,
    })
}

fn parse_sni(body: &[u8]) -> Option<String> {
    if body.len() < 5 {
        return None;
    }
    let list_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
    let list = body.get(2..2 + list_len.min(body.len().saturating_sub(2)))?;
    let mut offset = 0_usize;
    while offset.saturating_add(3) <= list.len() {
        let name_type = list[offset];
        let name_len = usize::from(u16::from_be_bytes([list[offset + 1], list[offset + 2]]));
        offset = offset.saturating_add(3);
        let Some(name) = list.get(offset..offset.saturating_add(name_len)) else {
            break;
        };
        if name_type == 0 {
            return sanitize_hostname(name);
        }
        offset = offset.saturating_add(name_len);
    }
    None
}

fn parse_alpn(body: &[u8]) -> Option<String> {
    if body.len() < 2 {
        return None;
    }
    let list_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
    let list = body.get(2..2 + list_len.min(body.len().saturating_sub(2)))?;
    let mut offset = 0_usize;
    let mut protocols = Vec::new();
    while offset < list.len() {
        let len = usize::from(list[offset]);
        offset = offset.saturating_add(1);
        let Some(proto) = list.get(offset..offset.saturating_add(len)) else {
            break;
        };
        if let Some(name) = sanitize_alpn(proto) {
            protocols.push(name);
        }
        offset = offset.saturating_add(len);
        if protocols.len() >= 8 {
            break;
        }
    }
    (!protocols.is_empty()).then(|| protocols.join(","))
}

fn parse_http_request(payload: &[u8]) -> Option<HandshakeMeta> {
    let text = std::str::from_utf8(payload).ok()?;
    let line = text.split(['\r', '\n']).next()?;
    let mut parts = line.splitn(3, ' ');
    let method = parts.next()?;
    if !matches!(
        method,
        "GET" | "POST" | "HEAD" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "CONNECT" | "PRI"
    ) {
        return None;
    }
    let path = parts.next().unwrap_or("");
    let mut host = None;
    for header in text.split("\r\n").skip(1) {
        if header.is_empty() {
            break;
        }
        let Some((name, value)) = header.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("host") {
            host = sanitize_hostname(value.trim().as_bytes());
            break;
        }
    }
    Some(HandshakeMeta {
        kind: "http",
        sni: None,
        alpn: None,
        ech: false,
        http_method: Some(method.to_owned()),
        http_path: (!path.is_empty()).then(|| path.chars().take(256).collect()),
        http_host: host,
        quic_version: None,
        quic_packet: None,
    })
}

fn parse_quic_long_header(payload: &[u8]) -> Option<HandshakeMeta> {
    if payload.len() < 6 || payload[0] & 0xc0 != 0xc0 {
        return None;
    }
    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
    if version == 0 {
        return None;
    }
    let type_bits = (payload[0] & 0x30) >> 4;
    let packet = match version {
        1 => match type_bits {
            0 => "initial",
            1 => "0rtt",
            2 => "handshake",
            3 => "retry",
            _ => "long",
        },
        0x6b33_43cf => match type_bits {
            1 => "initial",
            2 => "0rtt",
            3 => "handshake",
            0 => "retry",
            _ => "long",
        },
        _ => "long",
    };
    Some(HandshakeMeta {
        kind: "quic",
        sni: None,
        alpn: None,
        ech: false,
        http_method: None,
        http_path: None,
        http_host: None,
        quic_version: Some(format!("{version:#010x}")),
        quic_packet: Some(packet.to_owned()),
    })
}

fn sanitize_hostname(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.len() > 253 {
        return None;
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
    {
        return None;
    }
    Some(String::from_utf8_lossy(bytes).to_ascii_lowercase())
}

fn sanitize_alpn(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.len() > 32 {
        return None;
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    {
        return None;
    }
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn u24(bytes: &[u8]) -> usize {
    ((usize::from(bytes[0])) << 16) | ((usize::from(bytes[1])) << 8) | usize::from(bytes[2])
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let slice = bytes.get(offset..offset + 2)?;
    Some(u16::from_be_bytes([slice[0], slice[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(sni: &str, alpn: &[&str], ech: bool) -> Vec<u8> {
        let mut extensions = Vec::new();
        let mut sni_list = Vec::new();
        sni_list.push(0_u8);
        sni_list.extend_from_slice(&(u16::try_from(sni.len()).expect("sni")).to_be_bytes());
        sni_list.extend_from_slice(sni.as_bytes());
        let mut sni_body = Vec::new();
        sni_body.extend_from_slice(&(u16::try_from(sni_list.len()).expect("list")).to_be_bytes());
        sni_body.extend_from_slice(&sni_list);
        extensions.extend_from_slice(&0_u16.to_be_bytes());
        extensions.extend_from_slice(&(u16::try_from(sni_body.len()).expect("body")).to_be_bytes());
        extensions.extend_from_slice(&sni_body);

        let mut alpn_list = Vec::new();
        for proto in alpn {
            alpn_list.push(u8::try_from(proto.len()).expect("alpn"));
            alpn_list.extend_from_slice(proto.as_bytes());
        }
        let mut alpn_body = Vec::new();
        alpn_body
            .extend_from_slice(&(u16::try_from(alpn_list.len()).expect("alpn list")).to_be_bytes());
        alpn_body.extend_from_slice(&alpn_list);
        extensions.extend_from_slice(&0x0010_u16.to_be_bytes());
        extensions
            .extend_from_slice(&(u16::try_from(alpn_body.len()).expect("alpn body")).to_be_bytes());
        extensions.extend_from_slice(&alpn_body);

        if ech {
            extensions.extend_from_slice(&0xfe0d_u16.to_be_bytes());
            extensions.extend_from_slice(&1_u16.to_be_bytes());
            extensions.push(0);
        }

        let mut hello = vec![0x03, 0x03];
        hello.extend_from_slice(&[0_u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&2_u16.to_be_bytes());
        hello.extend_from_slice(&[0x00, 0x2f]);
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&(u16::try_from(extensions.len()).expect("ext")).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut handshake = vec![0x01, 0, 0, 0];
        let hello_len = u32::try_from(hello.len()).expect("hello");
        handshake[1] = u8::try_from((hello_len >> 16) & 0xff).expect("b");
        handshake[2] = u8::try_from((hello_len >> 8) & 0xff).expect("b");
        handshake[3] = u8::try_from(hello_len & 0xff).expect("b");
        handshake.extend_from_slice(&hello);

        let record_len = u16::try_from(handshake.len()).expect("record");
        let mut record = vec![0x16, 0x03, 0x01, 0, 0];
        record[3] = u8::try_from(record_len >> 8).expect("b");
        record[4] = u8::try_from(record_len & 0xff).expect("b");
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn tls_client_hello_sni_alpn_ech() {
        let parsed =
            parse_handshake(&client_hello("bank.example", &["h2", "http/1.1"], true)).expect("tls");
        assert_eq!(parsed.kind, "tls");
        assert_eq!(parsed.sni.as_deref(), Some("bank.example"));
        assert_eq!(parsed.alpn.as_deref(), Some("h2,http/1.1"));
        assert!(parsed.ech);
    }

    #[test]
    fn http_request_line_and_host() {
        let parsed =
            parse_handshake(b"GET /login HTTP/1.1\r\nHost: pay.example\r\n\r\n").expect("http");
        assert_eq!(parsed.kind, "http");
        assert_eq!(parsed.http_method.as_deref(), Some("GET"));
        assert_eq!(parsed.http_path.as_deref(), Some("/login"));
        assert_eq!(parsed.http_host.as_deref(), Some("pay.example"));
    }

    #[test]
    fn quic_v1_initial_is_detected_without_sni() {
        let mut packet = vec![0xc0, 0x00, 0x00, 0x00, 0x01, 8];
        packet.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let parsed = parse_handshake(&packet).expect("quic");
        assert_eq!(parsed.kind, "quic");
        assert_eq!(parsed.quic_version.as_deref(), Some("0x00000001"));
        assert_eq!(parsed.quic_packet.as_deref(), Some("initial"));
        assert!(parsed.sni.is_none());
    }
}
