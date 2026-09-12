//! Offline TLS 1.3 decryption for session pcaps with keylog probe output.
//!
//! Input: a session `traffic.pcap` plus `sslkeylog.txt` lines. Keylog lines may
//! be standard Wireshark form (`LABEL random secret`) or the probe's debug form
//! (`# LABEL secret=HEX ...`, no client random). Connection/secret matching is
//! done by trial AEAD opening: a candidate secret "belongs" to the flow whose
//! record tag verifies, so the client random is not required up front; matched
//! flows are re-emitted as a standard keylog for tshark.

use std::collections::HashMap;

use crate::quic_initial::{hkdf_expand_label, Aes128};

const TLS_CONTENT_HANDSHAKE: u8 = 22;
const TLS_CONTENT_APP: u8 = 23;

/// One TCP direction's reassembled bytes with sequencing state.
#[derive(Default)]
struct DirStream {
    segments: Vec<(u32, Vec<u8>)>, // (relative seq, bytes)
    data: Vec<u8>,
}

impl DirStream {
    fn push(&mut self, seq: u32, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        self.segments.push((seq, payload.to_vec()));
    }

    /// Order segments by wrapping sequence distance from the first byte seen.
    fn finish(&mut self) {
        if self.segments.is_empty() {
            return;
        }
        let base = self.base_seq().unwrap_or(0);
        self.segments
            .sort_by_key(|(seq, _)| (*seq).wrapping_sub(base));
        let mut last_end: Option<u32> = None;
        for (seq, data) in &self.segments {
            let rel = seq.wrapping_sub(self.base_seq().unwrap_or(0));
            if let Some(end) = last_end {
                if rel.wrapping_sub(end) > 0x4000_0000 {
                    continue; // stale retransmission far behind
                }
            }
            let start = rel as usize;
            if start > self.data.len() + 1024 * 1024 {
                continue;
            }
            if start > self.data.len() {
                self.data.resize(start, 0);
            }
            let end = (start + data.len()).min(self.data.len().max(start) + data.len());
            if self.data.len() < end {
                self.data.resize(end, 0);
            }
            self.data[start..start + data.len()].copy_from_slice(data);
            last_end = Some(rel.wrapping_add(u32::try_from(data.len()).unwrap_or(u32::MAX)));
        }
        self.segments.clear();
    }

    fn base_seq(&self) -> Option<u32> {
        self.segments.first().map(|(seq, _)| *seq)
    }
}

/// A reassembled TCP conversation with both directions.
pub struct TcpFlow {
    /// `ip:port` of the connection initiator (client side).
    pub client: String,
    /// `ip:port` of the acceptor.
    pub server: String,
    client_data: DirStream,
    server_data: DirStream,
}

/// Parse a classic pcap (LE/BE; Ethernet, Linux cooked v1/v2, or raw IP) into
/// per-flow reassembled TCP streams. UDP is ignored. TLS is accepted on any
/// port because Android applications commonly use 8443 and private endpoints.
#[must_use]
/// Parse a classic pcap file.
///
/// # Panics
///
/// Panics never: malformed records are skipped, not unwrapped.
#[allow(clippy::too_many_lines)]
pub fn parse_pcap_tcp_flows(data: &[u8]) -> Vec<TcpFlow> {
    if data.len() < 24 {
        return Vec::new();
    }
    let magic = &data[0..4];
    let little = matches!(magic, [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1]);
    let read_u32 = |offset: usize| -> u32 {
        let raw: [u8; 4] = data[offset..offset + 4].try_into().expect("4 bytes");
        if little {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        }
    };
    let link_type = read_u32(20);
    let mut offset = 24usize;
    let mut flows: HashMap<String, TcpFlow> = HashMap::new();
    while offset + 16 <= data.len() {
        let caplen = read_u32(offset + 8) as usize;
        offset += 16;
        if caplen == 0 || offset + caplen > data.len() {
            break;
        }
        let pkt = &data[offset..offset + caplen];
        offset += caplen;
        let Some(ip) = link_ip_offset(link_type, pkt) else {
            continue;
        };
        if pkt.len() < ip + 20 {
            continue;
        }
        let version = pkt[ip] >> 4;
        let (proto, src, dst, tcp_start) = match version {
            4 => {
                let ihl = usize::from(pkt[ip] & 0x0f) * 4;
                if pkt.len() < ip + ihl + 20 {
                    continue;
                }
                let proto = pkt[ip + 9];
                let src = format!(
                    "{}.{}.{}.{}",
                    pkt[ip + 12],
                    pkt[ip + 13],
                    pkt[ip + 14],
                    pkt[ip + 15]
                );
                let dst = format!(
                    "{}.{}.{}.{}",
                    pkt[ip + 16],
                    pkt[ip + 17],
                    pkt[ip + 18],
                    pkt[ip + 19]
                );
                (proto, src, dst, ip + ihl)
            }
            6 => {
                if pkt.len() < ip + 40 + 20 {
                    continue;
                }
                let proto = pkt[ip + 6];
                let src = format_ipv6(&pkt[ip + 8..ip + 24]);
                let dst = format_ipv6(&pkt[ip + 24..ip + 40]);
                (proto, src, dst, ip + 40)
            }
            _ => continue,
        };
        if proto != 6 {
            continue;
        }
        if tcp_start + 20 > pkt.len() {
            continue;
        }
        let tcp = &pkt[tcp_start..];
        let sport = u16::from_be_bytes([tcp[0], tcp[1]]);
        let dport = u16::from_be_bytes([tcp[2], tcp[3]]);
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let data_offset = usize::from((tcp[12] >> 4) & 0x0f) * 4;
        if data_offset > tcp.len() {
            continue;
        }
        let payload = &tcp[data_offset.min(tcp.len())..];
        if payload.is_empty() {
            continue;
        }
        let source = format!("{src}:{sport}");
        let destination = format!("{dst}:{dport}");
        let client_to_server =
            looks_like_client_hello(payload) || is_likely_server_port(dport, sport);
        let (flow_key, is_from_client, client_addr, server_addr) = if client_to_server {
            (
                canonical_flow_key(&source, &destination),
                true,
                source,
                destination,
            )
        } else {
            (
                canonical_flow_key(&source, &destination),
                false,
                destination,
                source,
            )
        };
        #[cfg(test)]
        eprintln!(
            "pkt flow_key={flow_key} from_client={is_from_client} payload={}",
            payload.len()
        );
        let flow = flows.entry(flow_key).or_insert_with(|| TcpFlow {
            client: client_addr,
            server: server_addr,
            client_data: DirStream::default(),
            server_data: DirStream::default(),
        });
        if is_from_client {
            flow.client_data.push(seq, payload);
        } else {
            flow.server_data.push(seq, payload);
        }
    }
    let mut list: Vec<TcpFlow> = flows.into_values().collect();
    for flow in &mut list {
        flow.client_data.finish();
        flow.server_data.finish();
    }
    list.sort_by(|left, right| {
        left.client_data
            .data
            .len()
            .cmp(&right.client_data.data.len())
            .then(
                left.server_data
                    .data
                    .len()
                    .cmp(&right.server_data.data.len()),
            )
            .reverse()
    });
    list
}

fn link_ip_offset(link_type: u32, packet: &[u8]) -> Option<usize> {
    match link_type {
        1 => {
            if packet.len() < 14 {
                return None;
            }
            let mut cursor = 12usize;
            let mut protocol = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
            cursor += 2;
            while matches!(protocol, 0x8100 | 0x88a8 | 0x9100) {
                if packet.len() < cursor + 4 {
                    return None;
                }
                protocol = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]);
                cursor += 4;
            }
            matches!(protocol, 0x0800 | 0x86dd).then_some(cursor)
        }
        113 => {
            if packet.len() < 16 {
                return None;
            }
            let protocol = u16::from_be_bytes([packet[14], packet[15]]);
            matches!(protocol, 0x0800 | 0x86dd).then_some(16)
        }
        276 => {
            if packet.len() < 20 {
                return None;
            }
            let protocol = u16::from_be_bytes([packet[0], packet[1]]);
            matches!(protocol, 0x0800 | 0x86dd).then_some(20)
        }
        101 | 228 | 229 => Some(0),
        _ => None,
    }
}

fn looks_like_client_hello(payload: &[u8]) -> bool {
    payload.len() >= 6
        && payload[0] == TLS_CONTENT_HANDSHAKE
        && payload[1] == 0x03
        && payload[5] == 0x01
}

fn is_likely_server_port(destination: u16, source: u16) -> bool {
    matches!(destination, 443 | 8443 | 9443 | 10443) || destination < source
}

fn canonical_flow_key(left: &str, right: &str) -> String {
    if left <= right {
        format!("{left}<->{right}")
    } else {
        format!("{right}<->{left}")
    }
}

fn format_ipv6(bytes: &[u8]) -> String {
    let segments: Vec<String> = bytes
        .chunks(2)
        .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
        .collect();
    segments.join(":")
}

/// One keylog line in either supported form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeylogSecret {
    /// `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, ...
    pub label: String,
    /// Client random when the line carried one (standard form, hex).
    pub random: Option<String>,
    pub secret: Vec<u8>,
}

/// Parse standard and probe-debug keylog lines.
#[must_use]
pub fn parse_keylog(text: &str) -> Vec<KeylogSecret> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('#') {
            // Debug form: `LABEL secret=HEX ssl=0x...`
            let rest = rest.trim();
            let Some(secret_at) = rest.find("secret=") else {
                continue;
            };
            let after = &rest[secret_at + 7..];
            let mut parts = after.split_ascii_whitespace();
            let Some(secret_hex) = parts.next() else {
                continue;
            };
            let label = rest
                .split_ascii_whitespace()
                .next()
                .unwrap_or("")
                .to_owned();
            if let Some(secret) = decode_hex(secret_hex) {
                out.push(KeylogSecret {
                    label,
                    random: None,
                    secret,
                });
            }
            continue;
        }
        let parts: Vec<&str> = line.split_ascii_whitespace().collect();
        if parts.len() == 3 {
            if let Some(secret) = decode_hex(parts[2]) {
                let random = parts[1].to_ascii_lowercase();
                out.push(KeylogSecret {
                    label: parts[0].to_owned(),
                    random: Some(random),
                    secret,
                });
            }
        }
    }
    out
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.is_empty() || hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).ok())
        .collect()
}

/// TLS 1.3 record-decryption state for one direction of one flow.
struct DirectionDecryptor {
    /// Sticky working secret; retried candidates when it stops verifying.
    sticky: Option<Vec<u8>>,
    seq: u64,
    key_len: usize,
    decrypted: Vec<u8>,
}

impl DirectionDecryptor {
    fn new(key_len: usize) -> Self {
        Self {
            sticky: None,
            seq: 0,
            key_len,
            decrypted: Vec::new(),
        }
    }

    fn open_record(
        &mut self,
        header: [u8; 5],
        payload: &[u8],
        candidates: &[Vec<u8>],
    ) -> Option<u8> {
        if payload.len() < 17 {
            return None;
        }
        let mut ordered: Vec<Vec<u8>> = Vec::new();
        if let Some(sticky) = &self.sticky {
            ordered.push(sticky.clone());
        }
        for candidate in candidates {
            if Some(candidate) != self.sticky.as_ref() {
                ordered.push(candidate.clone());
            }
        }
        for secret in ordered {
            let secret32 = secret_key32(&secret);
            let key_vec = hkdf_expand_label(&secret32, b"key", self.key_len);
            if key_vec.len() != self.key_len {
                continue;
            }
            let key: [u8; 32] = pad_key(&key_vec, self.key_len);
            let iv_vec = hkdf_expand_label(&secret32, b"iv", 12);
            let mut iv = [0u8; 12];
            iv.copy_from_slice(&iv_vec[..12]);
            let mut nonce = iv;
            let seq_bytes = self.seq.to_be_bytes();
            for (index, byte) in seq_bytes.iter().enumerate() {
                nonce[4 + index] ^= byte;
            }
            let aes = Aes128::with_key_bytes(&key[..self.key_len]);
            if let Some(mut plaintext) = aes_gcm_decrypt_general(&aes, &nonce, &header, payload) {
                // Strip trailing padding zeros + content type.
                while plaintext.last().is_some_and(|byte| *byte == 0) {
                    plaintext.pop();
                }
                let content = plaintext.pop()?;
                if !matches!(
                    content,
                    TLS_CONTENT_HANDSHAKE | TLS_CONTENT_APP | 0x14..=0x18
                ) {
                    continue;
                }
                self.seq = self.seq.saturating_add(1);
                self.decrypted.extend_from_slice(&plaintext);
                return Some(content);
            }
        }
        None
    }
}

fn secret_key32(secret: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (index, byte) in secret.iter().take(32).enumerate() {
        out[index] = *byte;
    }
    out
}

fn pad_key(key: &[u8], key_len: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (index, byte) in key.iter().take(key_len).enumerate() {
        out[index] = *byte;
    }
    out
}

/// AES-GCM open for any AES key width supported by [`Aes128`].
fn aes_gcm_decrypt_general(
    aes: &Aes128,
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
) -> Option<Vec<u8>> {
    if ciphertext_with_tag.len() < 16 {
        return None;
    }
    let (ciphertext, tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);
    let mut h = [0u8; 16];
    aes.encrypt_block(&mut h);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1;
    let mut y = [0u8; 16];
    ghash_bytes(&h, aad, &mut y);
    ghash_bytes(&h, ciphertext, &mut y);
    let mut length_block = [0u8; 16];
    length_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    length_block[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    ghash_block(&h, &mut y, &length_block);
    let mut expected = j0;
    aes.encrypt_block(&mut expected);
    for (tag_byte, y_byte) in expected.iter_mut().zip(y.iter()) {
        *tag_byte ^= y_byte;
    }
    let mut difference = 0u8;
    for (expected, given) in expected.iter().zip(tag.iter()) {
        difference |= expected ^ given;
    }
    if difference != 0 {
        return None;
    }
    let mut counter = j0;
    let mut out = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(16) {
        for byte in counter.iter_mut().rev() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
        let mut keystream = counter;
        aes.encrypt_block(&mut keystream);
        for (cipher_byte, key_byte) in chunk.iter().zip(keystream.iter()) {
            out.push(cipher_byte ^ key_byte);
        }
    }
    Some(out)
}

fn ghash_block(h: &[u8; 16], y: &mut [u8; 16], block: &[u8; 16]) {
    for (y_byte, block_byte) in y.iter_mut().zip(block.iter()) {
        *y_byte ^= block_byte;
    }
    *y = gf128_mul(y, h);
}

fn ghash_bytes(h: &[u8; 16], data: &[u8], y: &mut [u8; 16]) {
    let mut chunks = data.chunks_exact(16);
    for chunk in &mut chunks {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        ghash_block(h, y, &block);
    }
    let remainder = chunks.remainder();
    if !remainder.is_empty() {
        let mut block = [0u8; 16];
        block[..remainder.len()].copy_from_slice(remainder);
        ghash_block(h, y, &block);
    }
}

fn gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;
    for byte in x {
        for bit in (0..8).rev() {
            if (byte >> bit) & 1 == 1 {
                for (z_byte, v_byte) in z.iter_mut().zip(v.iter()) {
                    *z_byte ^= v_byte;
                }
            }
            let lsb = v[15] & 1;
            for index in (1..16).rev() {
                v[index] = (v[index] >> 1) | (v[index - 1] << 7);
            }
            v[0] >>= 1;
            if lsb == 1 {
                v[0] ^= 0xe1;
            }
        }
    }
    z
}

#[allow(clippy::format_collect)]
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One decrypted flow plus the matched secrets, ready for HTTP analysis.
pub struct DecryptedFlow {
    /// `ip:port` of the connection initiator.
    pub client: String,
    /// `ip:port` of the acceptor.
    pub server: String,
    /// TLS 1.3 cipher suite from the `ServerHello` (`0x1301`, `0x1302`, ...).
    pub cipher: u16,
    /// Client-random from the `ClientHello` (hex).
    pub client_random: String,
    /// Decrypted client-to-server plaintext (handshake tail + app data).
    pub client_plain: Vec<u8>,
    /// Decrypted server-to-client plaintext.
    pub server_plain: Vec<u8>,
    /// Standard keylog lines for this flow (tshark-compatible).
    pub keylog_lines: Vec<String>,
}

/// Decrypt a TLS 1.3 record stream (Inspect `tls_record` copies) using keylog
/// secrets. Trial-opens with AES-128-GCM then AES-256-GCM. Empty when no
/// record tag verifies — never invents plaintext.
#[must_use]
pub fn decrypt_tls_application_data(stream: &[u8], secrets: &[KeylogSecret]) -> Option<Vec<u8>> {
    if stream.len() < 5 || stream.get(1).copied() != Some(0x03) {
        return None;
    }
    if secrets.is_empty() {
        return None;
    }
    let candidates: Vec<Vec<u8>> = secrets.iter().map(|line| line.secret.clone()).collect();
    for key_len in [16_usize, 32_usize] {
        let mut dir = DirectionDecryptor::new(key_len);
        walk_tls_records(stream, &mut dir, &candidates);
        if !dir.decrypted.is_empty() {
            return Some(dir.decrypted);
        }
    }
    None
}

/// Decrypt every flow that matches a keylog secret. `AES-GCM` suites only
/// (`0x1301`/`0x1302`); `ChaCha20` flows are reported and skipped.
#[must_use]
pub fn decrypt_flows(flows: &[TcpFlow], secrets: &[KeylogSecret]) -> Vec<DecryptedFlow> {
    let client_secrets: Vec<Vec<u8>> = secrets
        .iter()
        .filter(|line| line.label.starts_with("CLIENT"))
        .map(|line| line.secret.clone())
        .collect();
    let server_secrets: Vec<Vec<u8>> = secrets
        .iter()
        .filter(|line| line.label.starts_with("SERVER"))
        .map(|line| line.secret.clone())
        .collect();
    let mut out = Vec::new();
    for flow in flows {
        let Some(parsed) = parse_client_hello(&flow.client_data.data) else {
            continue;
        };
        if parsed.cipher != 0x1301 && parsed.cipher != 0x1302 {
            continue; // ChaCha or unsupported
        }
        let key_len = if parsed.cipher == 0x1301 { 16 } else { 32 };
        let mut client = DirectionDecryptor::new(key_len);
        let mut server = DirectionDecryptor::new(key_len);
        walk_tls_records(
            &flow.client_data.data[parsed.record_end..],
            &mut client,
            &client_secrets,
        );
        walk_tls_records(&flow.server_data.data, &mut server, &server_secrets);
        if client.decrypted.is_empty() && server.decrypted.is_empty() {
            continue;
        }
        let random_hex: String = to_hex(&parsed.client_random);
        let mut keylog_lines = Vec::new();
        for secret in secrets {
            let (label, value) = match secret.label.as_str() {
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
                | "CLIENT_TRAFFIC_SECRET_0"
                | "CLIENT_EARLY_TRAFFIC_SECRET" => ("c", &secret.secret),
                "SERVER_HANDSHAKE_TRAFFIC_SECRET" | "SERVER_TRAFFIC_SECRET_0" => {
                    ("s", &secret.secret)
                }
                _ => continue,
            };
            keylog_lines.push(format!("{label} {random_hex} {}", to_hex(value)));
        }
        out.push(DecryptedFlow {
            client: flow.client.clone(),
            server: flow.server.clone(),
            cipher: parsed.cipher,
            client_random: random_hex,
            client_plain: client.decrypted,
            server_plain: server.decrypted,
            keylog_lines,
        });
    }
    out
}

struct ClientHelloParsed {
    client_random: [u8; 32],
    cipher: u16,
    record_end: usize,
}

fn parse_client_hello(stream: &[u8]) -> Option<ClientHelloParsed> {
    if stream.len() < 11 || stream[0] != TLS_CONTENT_HANDSHAKE {
        return None;
    }
    let record_len = usize::from(u16::from_be_bytes([stream[3], stream[4]]));
    let record_end = 5 + record_len;
    if stream.len() < record_end || stream[5] != 0x01 {
        return None;
    }
    let hello = &stream[5..record_end];
    if hello.len() < 40 {
        return None;
    }
    let mut client_random = [0u8; 32];
    client_random.copy_from_slice(&hello[6..38]);
    let mut cursor = 38;
    let sid_len = usize::from(*hello.get(cursor)?);
    cursor += 1 + sid_len;
    if cursor + 2 > hello.len() {
        return None;
    }
    let cipher_len = usize::from(u16::from_be_bytes([hello[cursor], hello[cursor + 1]]));
    cursor += 2;
    let mut cipher = 0u16;
    for index in (0..cipher_len.saturating_sub(1)).step_by(2) {
        let Some(suite) = hello.get(cursor + index..cursor + index + 2) else {
            break;
        };
        let value = u16::from_be_bytes([suite[0], suite[1]]);
        if (0x1301..=0x1303).contains(&value) {
            cipher = value;
            break;
        }
    }
    Some(ClientHelloParsed {
        client_random,
        cipher,
        record_end,
    })
}

/// Walk framed TLS records and decrypt each with the direction's candidates.
fn walk_tls_records(stream: &[u8], dir: &mut DirectionDecryptor, candidates: &[Vec<u8>]) {
    let mut offset = 0usize;
    while offset + 5 <= stream.len() {
        let content = stream[offset];
        let length = usize::from(u16::from_be_bytes([stream[offset + 3], stream[offset + 4]]));
        let end = offset + 5 + length;
        if end > stream.len() {
            break;
        }
        let header: [u8; 5] = [
            stream[offset],
            stream[offset + 1],
            stream[offset + 2],
            stream[offset + 3],
            stream[offset + 4],
        ];
        let payload = &stream[offset + 5..end];
        // Unencrypted ServerHello (type 22 first record) passes through as-is.
        if content == TLS_CONTENT_HANDSHAKE && dir.decrypted.is_empty() && offset == 0 {
            dir.decrypted.extend_from_slice(payload);
            offset = end;
            continue;
        }
        dir.open_record(header, payload, candidates);
        offset = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn decrypt_tls_application_data_rejects_non_record() {
        assert!(decrypt_tls_application_data(b"GET / HTTP/1.1\r\n\r\n", &[]).is_none());
        assert!(decrypt_tls_application_data(&[0x17, 0x03, 0x03, 0x00, 0x01, 0xff], &[]).is_none());
    }

    #[test]
    fn recognizes_supported_link_headers() {
        let mut ethernet = vec![0_u8; 14];
        ethernet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        assert_eq!(link_ip_offset(1, &ethernet), Some(14));

        let mut sll = vec![0_u8; 16];
        sll[14..16].copy_from_slice(&0x86dd_u16.to_be_bytes());
        assert_eq!(link_ip_offset(113, &sll), Some(16));

        let mut sll2 = vec![0_u8; 20];
        sll2[0..2].copy_from_slice(&0x0800_u16.to_be_bytes());
        assert_eq!(link_ip_offset(276, &sll2), Some(20));
        assert_eq!(link_ip_offset(101, &[0x45]), Some(0));
        assert_eq!(link_ip_offset(999, &[0; 32]), None);
    }

    #[test]
    fn decrypts_synthetic_tls13_pcap_with_standard_keylog() {
        let pcap = hex_bytes("d4c3b2a1020004000000000000000000ffff000001000000e803000000000000ca000000ca0000000000000000001111111111110800450000bc00010000400600000a0000025db8d822138901bb000003e8000000005018200000000000160301002b0100002703038cb8976ba17b3731a40b2c126eaa36fbb487bb69759ac15674b10c8b882782e90000021301170303005f8da05b0f46b95ace461231485a24d93c1b95acf3a071ffee574b7876f25b32f3dfafb4a0d8bfd3c1f4f22743431573214d936a1984ad742a6f0ab5fd854ebd826c636e04fff26fa0e886e6192406a9e77d1b652aba5d1bc9e571565371dc84e903000000000000c5000000c50000000000000000001111111111110800450000b700010000400600005db8d8220a00000201bb1389000007d0000000005018200000000000160303004b020000270303aabbccddeeff00112233445566778899aabbccddeeff001122334455667788992000112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00130100170303003ab034620644d8b96c7ed9a72ece0c579938f480d692d766d88aa47479eaff4f3696679f892d82c9876ae90aa580ac4ea94cefd02d9477e2d5105e");
        let keylog_text = "CLIENT_HANDSHAKE_TRAFFIC_SECRET 8cb8976ba17b3731a40b2c126eaa36fbb487bb69759ac15674b10c8b882782e9 fc98a40a27592b084f874fc73d4eb2e3c6421c6de0092c2c0d028f6b7652560e
CLIENT_TRAFFIC_SECRET_0 8cb8976ba17b3731a40b2c126eaa36fbb487bb69759ac15674b10c8b882782e9 2ccf74feaecc588f0a542310279a7028dba5a616797290f0fb554bc7de884fdf
SERVER_HANDSHAKE_TRAFFIC_SECRET 8cb8976ba17b3731a40b2c126eaa36fbb487bb69759ac15674b10c8b882782e9 bb9607fc46ce5c0a332d12e9ee7fb9d73d578db2d448b789641c09618ce92d1b
SERVER_TRAFFIC_SECRET_0 8cb8976ba17b3731a40b2c126eaa36fbb487bb69759ac15674b10c8b882782e9 ababe52837b50fa7e18655536e84625bb536f6be49f52fad68936a830f4f0878\n";
        let flows = parse_pcap_tcp_flows(&pcap);
        assert_eq!(flows.len(), 1);
        let secrets = parse_keylog(keylog_text);
        assert_eq!(secrets.len(), 4);
        let decrypted = decrypt_flows(&flows, &secrets);
        assert_eq!(decrypted.len(), 1);
        let flow = &decrypted[0];
        let client_text = String::from_utf8_lossy(&flow.client_plain);
        assert!(
            client_text.contains("POST /api/v1/pay"),
            "client: {client_text}"
        );
        let server_text = String::from_utf8_lossy(&flow.server_plain);
        assert!(
            server_text.contains("HTTP/1.1 200 OK"),
            "server: {server_text}"
        );
    }

    #[test]
    fn decrypts_synthetic_pcap_with_debug_keylog_no_random() {
        let pcap = hex_bytes("d4c3b2a1020004000000000000000000ffff000001000000e803000000000000ca000000ca0000000000000000001111111111110800450000bc00010000400600000a0000025db8d822138901bb000003e8000000005018200000000000160301002b0100002703038cb8976ba17b3731a40b2c126eaa36fbb487bb69759ac15674b10c8b882782e90000021301170303005f8da05b0f46b95ace461231485a24d93c1b95acf3a071ffee574b7876f25b32f3dfafb4a0d8bfd3c1f4f22743431573214d936a1984ad742a6f0ab5fd854ebd826c636e04fff26fa0e886e6192406a9e77d1b652aba5d1bc9e571565371dc84e903000000000000c5000000c50000000000000000001111111111110800450000b700010000400600005db8d8220a00000201bb1389000007d0000000005018200000000000160303004b020000270303aabbccddeeff00112233445566778899aabbccddeeff001122334455667788992000112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00130100170303003ab034620644d8b96c7ed9a72ece0c579938f480d692d766d88aa47479eaff4f3696679f892d82c9876ae90aa580ac4ea94cefd02d9477e2d5105e");
        let keylog_text = "# CLIENT_TRAFFIC_SECRET_0 secret=2ccf74feaecc588f0a542310279a7028dba5a616797290f0fb554bc7de884fdf ssl=0x0
# SERVER_HANDSHAKE_TRAFFIC_SECRET secret=bb9607fc46ce5c0a332d12e9ee7fb9d73d578db2d448b789641c09618ce92d1b ssl=0x0
# SERVER_TRAFFIC_SECRET_0 secret=ababe52837b50fa7e18655536e84625bb536f6be49f52fad68936a830f4f0878 ssl=0x0
# CLIENT_HANDSHAKE_TRAFFIC_SECRET secret=fc98a40a27592b084f874fc73d4eb2e3c6421c6de0092c2c0d028f6b7652560e ssl=0x0\n";
        let flows = parse_pcap_tcp_flows(&pcap);
        let secrets = parse_keylog(keylog_text);
        let decrypted = decrypt_flows(&flows, &secrets);
        assert_eq!(decrypted.len(), 1);
        let flow = &decrypted[0];
        assert!(String::from_utf8_lossy(&flow.client_plain).contains("POST /api/v1/pay"));
        assert!(flow.keylog_lines.iter().all(|line| line
            .contains("8cb8976ba17b3731a40b2c126eaa36fbb487bb69759ac15674b10c8b882782e9")));
    }
    #[test]
    fn keylog_parsing_handles_both_forms() {
        let text = "CLIENT_HANDSHAKE_TRAFFIC_SECRET aabb 1122\n\
                    # CLIENT_TRAFFIC_SECRET_0 secret=99aa ssl=0x7f\n";
        let parsed = parse_keylog(text);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].label, "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
        assert_eq!(parsed[0].random.as_deref(), Some("aabb"));
        assert_eq!(parsed[1].label, "CLIENT_TRAFFIC_SECRET_0");
        assert!(parsed[1].random.is_none());
        assert_eq!(parsed[1].secret, vec![0x99, 0xaa]);
    }
}
