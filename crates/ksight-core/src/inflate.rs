//! Bounded gzip/zlib inflate of Inspect buffers.
//!
//! This is report/device-side analysis of bytes already copied at an authorized
//! TLS/JNI boundary. It is not MITM and does not invent HTTP/2 HPACK.

use std::io::Read as _;

const INFLATE_CAP: u64 = 16 * 1024;

/// RFC 1952 gzip magic plus deflate method.
#[must_use]
pub fn looks_like_gzip(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && bytes[0] == 0x1f && bytes[1] == 0x8b && bytes[2] == 8
}

/// zlib CMF/FLG (`78 01` / `78 9c` / `78 da`) with a valid FCHECK.
#[must_use]
pub fn looks_like_zlib(bytes: &[u8]) -> bool {
    if bytes.len() < 2 || bytes[0] != 0x78 {
        return false;
    }
    matches!(bytes[1], 0x01 | 0x9c | 0xda) && u16::from_be_bytes([bytes[0], bytes[1]]) % 31 == 0
}

/// Decode an even-length hex preview back into bytes.
#[must_use]
pub fn decode_hex_bytes(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();
    if hex.len() < 4 || hex.len() % 2 != 0 || hex.len() > 16 * 1024 {
        return None;
    }
    if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut index = 0_usize;
    while index + 1 < bytes.len() {
        let hi = hex_nibble(bytes[index])?;
        let lo = hex_nibble(bytes[index + 1])?;
        out.push((hi << 4) | lo);
        index += 2;
    }
    Some(out)
}

/// Inflate gzip or zlib when the buffer starts with those headers. Capped.
#[must_use]
pub fn inflate_gzip_bounded(bytes: &[u8]) -> Option<Vec<u8>> {
    if looks_like_gzip(bytes) {
        return read_bounded(flate2::read::GzDecoder::new(bytes));
    }
    if looks_like_zlib(bytes) {
        return read_bounded(flate2::read::ZlibDecoder::new(bytes));
    }
    None
}

/// Inflate gzip/zlib at the start, or after HTTP headers (`Content-Encoding: gzip`).
#[must_use]
pub fn inflate_inspect_buffer(bytes: &[u8]) -> Option<Vec<u8>> {
    if let Some(plain) = inflate_gzip_bounded(bytes) {
        return Some(plain);
    }
    let start = gzip_offset(bytes)?;
    let plain = inflate_gzip_bounded(&bytes[start..])?;
    if start == 0 {
        return Some(plain);
    }
    let mut out = Vec::with_capacity(start.saturating_add(plain.len()));
    out.extend_from_slice(&bytes[..start]);
    out.extend_from_slice(&plain);
    Some(out)
}

fn gzip_offset(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(3)
        .position(|window| window == [0x1f, 0x8b, 8])
}

fn read_bounded<R: std::io::Read>(decoder: R) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    decoder.take(INFLATE_CAP).read_to_end(&mut out).ok()?;
    (!out.is_empty()).then_some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn gzip_of(plain: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut encoder = flate2::write::GzEncoder::new(&mut out, flate2::Compression::default());
        encoder.write_all(plain).expect("gzip");
        encoder.finish().expect("gzip finish");
        out
    }

    #[test]
    fn inflates_gzip_json() {
        let plain = br#"{"host":"ebsnew.boc.cn","path":"/api"}"#;
        let gz = gzip_of(plain);
        assert!(looks_like_gzip(&gz));
        let inflated = inflate_gzip_bounded(&gz).expect("inflate");
        assert_eq!(inflated, plain);
    }

    #[test]
    fn inflates_gzip_after_http_headers() {
        let body = br#"{"list":[{"url":"https://ebsnew.boc.cn/api"}]} "#;
        let gz = gzip_of(body);
        let mut http = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
        http.extend_from_slice(&gz);
        let inflated = inflate_inspect_buffer(&http).expect("http gzip");
        let text = String::from_utf8_lossy(&inflated);
        assert!(text.contains("HTTP/1.1 200 OK"));
        assert!(text.contains("ebsnew.boc.cn"));
    }

    #[test]
    fn rejects_non_gzip() {
        assert!(inflate_gzip_bounded(b"HTTP/1.1 200 OK").is_none());
        assert!(inflate_gzip_bounded(&[0x17, 0x03, 0x03, 0x00, 0x10]).is_none());
    }

    #[test]
    fn decodes_hex_preview() {
        let bytes = decode_hex_bytes("1f8b08").expect("hex");
        assert_eq!(bytes, [0x1f, 0x8b, 0x08]);
        assert!(decode_hex_bytes("gg").is_none());
    }
}
