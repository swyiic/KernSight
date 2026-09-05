//! HTTP/1, JSON, embedded URLs, and HTTP/2 HPACK parse of Inspect/dump buffers.
//!
//! Values that look like tokens are replaced with `[REDACTED]`. This is
//! report-side analysis of existing Inspect buffers, not a new capture ABI.

const SENSITIVE_HEADER: &[&str] = &[
    "cookie",
    "set-cookie",
    "authorization",
    "proxy-authorization",
    "x-app-token",
    "x-app-device",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "token",
];

const SENSITIVE_KEY: &[&str] = &[
    "token",
    "password",
    "passwd",
    "secret",
    "cookie",
    "authorization",
    "access_token",
    "refresh_token",
    "id_token",
    "sms",
    "otp",
    "code",
    "message",
    "_v2_post_token",
    "x-app-token",
    "sessionid",
    "sid",
];

const THIRD_PARTY_HOST: &[&str] = &[
    "bytedance",
    "pangle",
    "snssdk",
    "toutiao",
    "umeng",
    "kuaishou",
    "kwai",
    "gifshow",
    "netease",
    "dun.163",
    "163yun",
    "google",
    "googleapis",
    "gvt1",
    "crashlytics",
    "firebase",
    "facebook",
    "fbcdn",
    "doubleclick",
    "appsflyer",
    "adjust.com",
    "flurry",
    "talkingdata",
    "amap.com",
    "alicdn",
    "alipayobjects",
    "taobao",
    "baidu.com",
    "bdimg.com",
    "bdstatic",
    "cnzz.com",
    "unpkg.com",
    "tiqcdn",
    "appdynamics",
    "ucweb.com",
    "uc.cn",
    "github.com",
    "githubusercontent",
    "cloudflare",
    "3g.qq.com",
    "jsdelivr",
    "bootstrapcdn",
    "medallia",
    "omtrdc",
    "adobedtm",
    "app-measurement",
    "map.qq.com",
    "demdex",
    "khms",
    "images.apple.com",
    "douyin",
    "zijieapi",
    "amemv.com",
    "volces.com",
    "cdn-static",
    "xiaojukeji",
];

/// One parsed HTTP/1 call, HTTP/2 HEADERS row, JSON object, or embedded URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHttpPlain {
    /// `http1_request`, `http1_response`, `http2_request`, `http2_response`, `http2_preface`, `json`, or `url`.
    pub kind: &'static str,
    /// `GET` / `POST` / `HTTP` (response) / `PRI`.
    pub method: String,
    /// Host header, lowercased.
    pub host: Option<String>,
    /// `http` / `https` when this row was parsed from a URL, not a Host header.
    pub scheme: Option<&'static str>,
    /// Path without query.
    pub path: String,
    /// Response status, when this is a response line.
    pub status: Option<u16>,
    /// Query parameter names, in first-seen order.
    pub query_keys: Vec<String>,
    /// Header names as they appeared.
    pub header_names: Vec<String>,
    /// Sensitive headers as `Name=[REDACTED]`.
    pub redacted_headers: Vec<String>,
    /// Form/JSON body keys.
    pub body_keys: Vec<String>,
    /// Sensitive body keys that were redacted.
    pub redacted_body_keys: Vec<String>,
    /// Content-Type, when present.
    pub content_type: Option<String>,
    /// True when the host looks like ads/risk/telemetry rather than app API.
    pub third_party: bool,
}

/// Parse an Inspect plaintext preview. `tls_record` / empty / binary hex is ignored.
#[must_use]
pub fn parse_http_plain(preview: &str, content_class: &str) -> Option<ParsedHttpPlain> {
    parse_http_plain_all(preview, content_class)
        .into_iter()
        .next()
}

/// HTTP/1, JSON keys, and `http(s)://` URLs from one Inspect preview.
///
/// Gzip/zlib hex previews are inflated first. Truncated JSON that does not start
/// with `{` still yields URL hosts. HTTP/2 HEADERS are HPACK-decoded.
#[must_use]
pub fn parse_http_plain_all(preview: &str, content_class: &str) -> Vec<ParsedHttpPlain> {
    if content_class == "tls_record" {
        return Vec::new();
    }
    let (bytes, class) = normalize_preview_bytes(preview, content_class);
    parse_http_plain_all_bytes(&bytes, &class)
}

/// Same as `parse_http_plain_all` on raw bytes (dump windows, HTTP/2 frames).
#[must_use]
pub fn parse_http_plain_all_bytes(bytes: &[u8], content_class: &str) -> Vec<ParsedHttpPlain> {
    if content_class == "tls_record" {
        return Vec::new();
    }
    let inflated = crate::inflate_inspect_buffer(bytes);
    let bytes = inflated.as_deref().unwrap_or(bytes);
    let mut out = Vec::new();
    if let Some(parsed) = parse_http_plain_bytes(bytes, content_class) {
        out.push(parsed);
    }
    if bytes.len() <= 16 * 1024 {
        for parsed in crate::http2::parse_http2(bytes) {
            if parsed.kind == "http2_preface" {
                continue;
            }
            if !out.iter().any(|seen| {
                seen.host == parsed.host && seen.path == parsed.path && seen.kind == parsed.kind
            }) {
                out.push(parsed);
            }
            if out.len() >= 48 {
                break;
            }
        }
    }
    for parsed in embedded_http_urls(bytes) {
        if !out.iter().any(|seen| {
            seen.host == parsed.host && seen.path == parsed.path && seen.kind == parsed.kind
        }) {
            out.push(parsed);
        }
        if out.len() >= 48 {
            break;
        }
    }
    if out.len() < 48 {
        for parsed in embedded_cookie_hosts(bytes) {
            if !out.iter().any(|seen| seen.host == parsed.host) {
                out.push(parsed);
            }
            if out.len() >= 48 {
                break;
            }
        }
    }
    drop_truncated_hosts(&mut out);
    out
}

fn normalize_preview_bytes(preview: &str, content_class: &str) -> (Vec<u8>, String) {
    let raw = if content_class == "binary" || preview_looks_hex(preview) {
        crate::decode_hex_bytes(preview).unwrap_or_else(|| preview.as_bytes().to_vec())
    } else {
        preview.as_bytes().to_vec()
    };
    if let Some(plain) = crate::inflate_inspect_buffer(&raw) {
        return (plain, "text".to_owned());
    }
    let class = if content_class.is_empty() && looks_mostly_text(&raw) {
        "text".to_owned()
    } else {
        content_class.to_owned()
    };
    (raw, class)
}

fn preview_looks_hex(preview: &str) -> bool {
    let trimmed = preview.trim();
    trimmed.len() >= 8
        && trimmed.len() % 2 == 0
        && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn looks_mostly_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let printable = bytes
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
        .count();
    printable.saturating_mul(4) >= bytes.len().saturating_mul(3)
}

/// Parse Inspect previews or dump heap windows. Leading object headers are skipped.
/// NUL-separated in-memory header tables are treated as HTTP/1 lines.
#[must_use]
pub fn parse_http_plain_bytes(bytes: &[u8], content_class: &str) -> Option<ParsedHttpPlain> {
    if content_class == "tls_record" {
        return None;
    }
    let start = skip_to_http(bytes).unwrap_or(0);
    let lossy = String::from_utf8_lossy(&bytes[start..]);
    let text = lossy
        .replace('\0', "\n")
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    if text.starts_with("PRI * HTTP/2.0") {
        return Some(ParsedHttpPlain {
            kind: "http2_preface",
            method: "PRI".to_owned(),
            host: None,
            scheme: None,
            path: String::new(),
            status: None,
            query_keys: Vec::new(),
            header_names: Vec::new(),
            redacted_headers: Vec::new(),
            body_keys: Vec::new(),
            redacted_body_keys: Vec::new(),
            content_type: None,
            third_party: false,
        });
    }
    parse_http1(text).or_else(|| parse_json_only(text))
}

fn skip_to_http(bytes: &[u8]) -> Option<usize> {
    let mut json = None;
    let mut index = 0_usize;
    while index < bytes.len() {
        if is_token_boundary(bytes, index) {
            if http_starts_at(bytes, index) {
                return Some(index);
            }
            if json.is_none() && bytes[index] == b'{' {
                json = Some(index);
            }
        }
        index += 1;
    }
    json
}

fn is_token_boundary(bytes: &[u8], index: usize) -> bool {
    index == 0 || {
        let previous = bytes[index - 1];
        previous == 0 || previous.is_ascii_whitespace() || !previous.is_ascii_graphic()
    }
}

fn http_starts_at(bytes: &[u8], index: usize) -> bool {
    const STARTS: [&[u8]; 10] = [
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"PATCH ",
        b"OPTIONS ",
        b"CONNECT ",
        b"HTTP/1.",
        b"PRI * HTTP/2.0",
    ];
    let rest = &bytes[index..];
    STARTS.iter().any(|needle| rest.starts_with(needle))
}

fn parse_http1(text: &str) -> Option<ParsedHttpPlain> {
    let (head, body) = text.split_once("\n\n").unwrap_or((text, ""));
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("");
    let (method, path_and_query, status) = parse_start_line(request_line)?;
    let (path, query_keys) = split_path_query(path_and_query);
    let mut host = None;
    let mut content_type = None;
    let mut header_names = Vec::new();
    let mut redacted_headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name_trim = name.trim();
        if name_trim.is_empty() || header_names.len() >= 24 {
            continue;
        }
        header_names.push(name_trim.to_owned());
        if name_trim.eq_ignore_ascii_case("host") {
            host = sanitize_host(value.trim());
        }
        if name_trim.eq_ignore_ascii_case("content-type") {
            content_type = Some(value.trim().chars().take(96).collect());
        }
        if sensitive_header(name_trim) {
            redacted_headers.push(format!("{name_trim}=[REDACTED]"));
        }
    }
    let (body_keys, redacted_body_keys) = parse_body_keys(body, content_type.as_deref());
    let third_party = host.as_deref().is_some_and(is_third_party_host);
    let kind = if status.is_some() {
        "http1_response"
    } else {
        "http1_request"
    };
    let path = if kind == "http1_response" {
        String::new()
    } else {
        path
    };
    Some(ParsedHttpPlain {
        kind,
        method,
        host,
        scheme: None,
        path,
        status,
        query_keys,
        header_names,
        redacted_headers,
        body_keys,
        redacted_body_keys,
        content_type,
        third_party,
    })
}

fn parse_start_line(line: &str) -> Option<(String, &str, Option<u16>)> {
    let mut parts = line.splitn(3, ' ');
    let first = parts.next()?;
    if first.starts_with("HTTP/") {
        let status = parts.next()?.parse::<u16>().ok();
        return Some(("HTTP".to_owned(), "", status));
    }
    if !matches!(
        first,
        "GET" | "POST" | "HEAD" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "CONNECT"
    ) {
        return None;
    }
    let target = parts.next().unwrap_or("/");
    Some((first.to_owned(), target, None))
}

fn split_path_query(target: &str) -> (String, Vec<String>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let path = path.chars().take(256).collect();
    let mut keys = Vec::new();
    for pair in query.split('&') {
        if keys.len() >= 24 {
            break;
        }
        let key = pair.split('=').next().unwrap_or("").trim();
        if key.is_empty() || keys.iter().any(|seen| seen == key) {
            continue;
        }
        keys.push(key.chars().take(64).collect());
    }
    (path, keys)
}

fn parse_body_keys(body: &str, content_type: Option<&str>) -> (Vec<String>, Vec<String>) {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return (Vec::new(), Vec::new());
    }
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return json_keys(trimmed);
    }
    let formish = content_type
        .is_some_and(|value| value.to_ascii_lowercase().contains("x-www-form-urlencoded"))
        || (trimmed.contains('=') && !trimmed.contains(' '));
    if formish {
        return form_keys(trimmed);
    }
    (Vec::new(), Vec::new())
}

fn form_keys(body: &str) -> (Vec<String>, Vec<String>) {
    let mut keys = Vec::new();
    let mut redacted = Vec::new();
    for pair in body.split('&') {
        if keys.len() >= 24 {
            break;
        }
        let key = pair.split('=').next().unwrap_or("").trim();
        if key.is_empty() || keys.iter().any(|seen| seen == key) {
            continue;
        }
        let owned = key.chars().take(64).collect::<String>();
        if sensitive_key(&owned) {
            redacted.push(owned.clone());
        }
        keys.push(owned);
    }
    (keys, redacted)
}

fn json_keys(body: &str) -> (Vec<String>, Vec<String>) {
    let mut keys = Vec::new();
    let mut redacted = Vec::new();
    let bytes = body.as_bytes();
    let mut i = 0_usize;
    while i + 1 < bytes.len() && keys.len() < 24 {
        if bytes[i] == b'"' {
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' {
                    i = i.saturating_add(2);
                    continue;
                }
                i += 1;
            }
            let key = String::from_utf8_lossy(&bytes[start..i.min(bytes.len())]).into_owned();
            i = i.saturating_add(1);
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len()
                && bytes[i] == b':'
                && !key.is_empty()
                && !keys.iter().any(|seen| seen == &key)
            {
                if sensitive_key(&key) {
                    redacted.push(key.clone());
                }
                keys.push(key.chars().take(64).collect());
            }
            continue;
        }
        i += 1;
    }
    (keys, redacted)
}

fn parse_json_only(text: &str) -> Option<ParsedHttpPlain> {
    let trimmed = text.trim();
    let json = if trimmed.starts_with('{') || trimmed.starts_with('[') {
        trimmed
    } else {
        let bytes = trimmed.as_bytes();
        let start = bytes
            .iter()
            .position(|byte| *byte == b'{' || *byte == b'[')?;
        std::str::from_utf8(&bytes[start..]).ok()?.trim()
    };
    if !(json.starts_with('{') || json.starts_with('[')) {
        return None;
    }
    let (body_keys, redacted_body_keys) = json_keys(json);
    if body_keys.is_empty() {
        return None;
    }
    Some(ParsedHttpPlain {
        kind: "json",
        method: "JSON".to_owned(),
        host: None,
        scheme: None,
        path: String::new(),
        status: None,
        query_keys: Vec::new(),
        header_names: Vec::new(),
        redacted_headers: Vec::new(),
        body_keys,
        redacted_body_keys,
        content_type: Some("application/json".to_owned()),
        third_party: false,
    })
}

pub(crate) fn embedded_http_urls(bytes: &[u8]) -> Vec<ParsedHttpPlain> {
    let mut out: Vec<ParsedHttpPlain> = Vec::new();
    let mut index = 0_usize;
    while index + 8 < bytes.len() && out.len() < 48 {
        let rest = &bytes[index..];
        let scheme = if rest.starts_with(b"https://") {
            8_usize
        } else if rest.starts_with(b"http://") {
            7_usize
        } else {
            index += 1;
            continue;
        };
        if index > 0 {
            let previous = bytes[index - 1];
            // SQLite/XML packs `https://` after letters. Only skip if this is a path continuation.
            if previous == b'/' || previous == b':' || previous == b'.' {
                index += 1;
                continue;
            }
        }
        let host_start = index + scheme;
        let host_end = bytes[host_start..]
            .iter()
            .position(|byte| !matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'_'))
            .map_or(bytes.len(), |rel| host_start + rel);
        if host_end <= host_start {
            index += 1;
            continue;
        }
        let host_raw = String::from_utf8_lossy(&bytes[host_start..host_end]).to_ascii_lowercase();
        let Some(host) = sanitize_host(&host_raw) else {
            index = host_end.max(index + 1);
            continue;
        };
        let path_end = bytes[host_end..]
            .iter()
            .position(|byte| {
                *byte <= 0x20
                    || matches!(
                        byte,
                        b'"' | b'\'' | b'<' | b'>' | b'\\' | b')' | b']' | b'}' | b','
                    )
            })
            .map_or(bytes.len(), |rel| host_end + rel);
        let path_and_query = if host_end < path_end && bytes[host_end] == b'/' {
            String::from_utf8_lossy(&bytes[host_end..path_end]).into_owned()
        } else {
            String::new()
        };
        let (path, query_keys) = split_path_query(path_and_query.split('#').next().unwrap_or(""));
        if !out
            .iter()
            .any(|seen| seen.host.as_deref() == Some(host.as_str()) && seen.path == path)
        {
            out.push(ParsedHttpPlain {
                kind: "url",
                method: "URL".to_owned(),
                host: Some(host.clone()),
                scheme: Some(if scheme == 8 { "https" } else { "http" }),
                path,
                status: None,
                query_keys,
                header_names: Vec::new(),
                redacted_headers: Vec::new(),
                body_keys: Vec::new(),
                redacted_body_keys: Vec::new(),
                content_type: None,
                third_party: is_third_party_host(&host),
            });
        }
        index = path_end.max(index + 1);
    }
    out
}

/// Packed Chromium `host_key` values (`mywap2.icbc.com.cnCK_...`) without `https://`.
pub(crate) fn embedded_cookie_hosts(bytes: &[u8]) -> Vec<ParsedHttpPlain> {
    const TLDS: [&[u8]; 8] = [
        b".com.cn",
        b".com.hk",
        b".co.uk",
        b".com",
        b".net",
        b".org",
        b".cn",
        b".hk",
    ];
    let mut out = Vec::new();
    let lower: Vec<u8> = bytes.iter().map(u8::to_ascii_lowercase).collect();
    for tld in TLDS {
        let mut from = 0_usize;
        while from + tld.len() < lower.len() && out.len() < 48 {
            let Some(rel) = lower[from..]
                .windows(tld.len())
                .position(|window| window == tld)
            else {
                break;
            };
            let mut end = from.saturating_add(rel).saturating_add(tld.len());
            if tld == b".com"
                && lower
                    .get(end..)
                    .is_some_and(|rest| rest.starts_with(b".cn") || rest.starts_with(b".hk"))
            {
                end = end.saturating_add(3);
            }
            let mut start = from.saturating_add(rel);
            while start > 0 {
                let previous = bytes[start - 1];
                if previous.is_ascii_alphanumeric() || previous == b'-' || previous == b'.' {
                    start -= 1;
                    continue;
                }
                break;
            }
            if start < end {
                if let Some(host) = sanitize_host(
                    &String::from_utf8_lossy(&bytes[start..end]).replace(['[', ']'], ""),
                ) {
                    if !out
                        .iter()
                        .any(|seen: &ParsedHttpPlain| seen.host.as_deref() == Some(host.as_str()))
                    {
                        let third_party = is_third_party_host(&host);
                        out.push(ParsedHttpPlain {
                            kind: "url",
                            method: "URL".to_owned(),
                            host: Some(host),
                            scheme: Some("https"),
                            path: String::new(),
                            status: None,
                            query_keys: Vec::new(),
                            header_names: Vec::new(),
                            redacted_headers: Vec::new(),
                            body_keys: Vec::new(),
                            redacted_body_keys: Vec::new(),
                            content_type: None,
                            third_party,
                        });
                    }
                }
            }
            from = end;
        }
    }
    drop_prefixed_cookie_hosts(&mut out);
    drop_truncated_hosts(&mut out);
    out
}

fn drop_prefixed_cookie_hosts(out: &mut Vec<ParsedHttpPlain>) {
    let hosts: Vec<String> = out
        .iter()
        .filter_map(|row| row.host.clone())
        .collect();
    out.retain(|row| {
        let Some(host) = row.host.as_deref() else {
            return true;
        };
        let first = host.split('.').next().unwrap_or("");
        if first
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_digit())
            && first.bytes().any(|byte| byte.is_ascii_alphabetic())
        {
            return false;
        }
        !hosts.iter().any(|other| {
            other != host
                && host.ends_with(other)
                && host.len() > other.len()
                && host.len() - other.len() <= 3
                && host
                    .as_bytes()
                    .get(host.len() - other.len() - 1)
                    .is_none_or(|byte| *byte != b'.')
        })
    });
}

fn drop_truncated_hosts(out: &mut Vec<ParsedHttpPlain>) {
    let hosts: Vec<String> = out.iter().filter_map(|row| row.host.clone()).collect();
    out.retain(|row| {
        let Some(host) = row.host.as_deref() else {
            return true;
        };
        !hosts.iter().any(|other| is_truncated_host(host, other))
    });
}

pub(crate) fn is_truncated_host(host: &str, other: &str) -> bool {
    other.len() > host.len()
        && other.starts_with(host)
        && other.as_bytes().get(host.len()).is_some_and(|byte| {
            byte.is_ascii_alphanumeric() || *byte == b'.'
        })
}

pub(crate) fn parse_host_token(value: &str) -> Option<String> {
    sanitize_host(value)
}

pub(crate) fn header_is_sensitive(name: &str) -> bool {
    sensitive_header(name)
}

fn sanitize_host(value: &str) -> Option<String> {
    let host = value
        .trim()
        .trim_matches(|ch: char| ch == '[' || ch == ']')
        .trim_matches('.');
    if host.len() < 4 || host.len() > 253 || !host.contains('.') {
        return None;
    }
    if !host.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
    }) {
        return None;
    }
    let host_no_port = host.split(':').next().unwrap_or(host);
    let tld = host_no_port.rsplit('.').next().unwrap_or("");
    if tld.len() < 2 || tld.len() > 10 || !tld.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return None;
    }
    if matches!(tld, "invalid" | "local" | "localhost") {
        return None;
    }
    let labels: Vec<&str> = host_no_port.split('.').collect();
    if matches!(host_no_port, "com.cn" | "com.hk" | "co.uk") || labels.len() < 2 {
        return None;
    }
    if labels.len() == 2 && labels[0].len() < 2 {
        return None;
    }
    if labels.len() > 5 {
        return None;
    }
    if labels
        .get(labels.len().saturating_sub(2))
        .copied()
        .is_some_and(|label| {
            matches!(label, "constructor" | "prototype" | "vuemodel" | "jquery")
        })
    {
        return None;
    }
    let lower = host.to_ascii_lowercase();
    if lower == "schemas.android.com"
        || lower.ends_with(".w3.org")
        || lower.starts_with("ns.google.")
        || lower.starts_with("ns.adobe.")
        || lower.starts_with("android.hardware.")
        || lower.contains("xmlsoap")
    {
        return None;
    }
    Some(lower)
}

fn sensitive_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_HEADER
        .iter()
        .any(|needle| lower == *needle || lower.contains("token"))
}

fn sensitive_key(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_KEY
        .iter()
        .any(|needle| lower == *needle || lower.ends_with("_token"))
}

/// Reconstruct a URL with scheme. Image paths are dropped; `.txt` / `.json` / `.html` stay.
#[must_use]
pub fn format_inspect_url(scheme: Option<&str>, host: &str, path: &str) -> Option<String> {
    let host = sanitize_host(host)?;
    if path.chars().any(|ch| ch == '\u{FFFD}' || ch.is_control()) {
        return None;
    }
    let scheme = scheme.unwrap_or("https");
    let url = if path.is_empty() {
        format!("{scheme}://{host}")
    } else if path.starts_with('/') {
        format!("{scheme}://{host}{path}")
    } else {
        format!("{scheme}://{host}/{path}")
    };
    is_kept_inspect_url(&url).then_some(url)
}

/// PNG/JPEG and PKI URLs are not app interface catalog rows. `.txt` is kept.
#[must_use]
pub fn is_kept_inspect_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    let path = lower.split(['?', '#']).next().unwrap_or(lower.as_str());
    let ext = path.rsplit_once('.').map_or("", |(_, ext)| ext);
    if matches!(
        ext,
        "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "webp"
            | "ico"
            | "bmp"
            | "svg"
            | "crl"
            | "cer"
            | "crt"
            | "der"
            | "pem"
            | "mp4"
            | "mp3"
            | "pdf"
    ) {
        return false;
    }
    if path.ends_with(".min.js") || path.ends_with("vue.min.js") {
        return false;
    }
    if path.contains('*')
        || path.ends_with('{')
        || path.contains("{*")
        || path.contains("&quot;")
        || path.contains(".*")
        || path.contains('|')
    {
        return false;
    }
    if path.contains("digicert")
        || path.contains("/ocsp")
        || path.contains("pki.goog")
        || path.contains("amazontrust")
        || path.contains(".crl")
        || path.contains("/crl")
        || path.contains("globalsign.com/repository")
        || path.contains("/data/user/0/")
        || path.contains("apache.org/licenses")
    {
        return false;
    }
    let host = lower
        .split("://")
        .nth(1)
        .unwrap_or(lower.as_str())
        .split('/')
        .next()
        .unwrap_or("");
    if path.contains(".crt") {
        return false;
    }
    if matches!(
        host,
        "jquery.com"
            | "sizzlejs.com"
            | "getbootstrap.com"
            | "swiperjs.com"
            | "github.com"
            | "www.apache.org"
            | "www.unicode.org"
            | "goo.gl"
            | "bit.ly"
            | "t.co"
            | "flutter.dev"
            | "pub.dev"
            | "dart.dev"
            | "api.flutter.dev"
    ) {
        return false;
    }
    true
}

/// Host is ads/risk/telemetry rather than first-party API.
#[must_use]
pub fn is_third_party_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    THIRD_PARTY_HOST.iter().any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_coolapk_create_feed() {
        let preview = concat!(
            "POST /v6/feed/createFeed HTTP/1.1\r\n",
            "Host: api.coolapk.com\r\n",
            "Cookie: session=secret\r\n",
            "X-App-Token: abc\r\n",
            "Content-Type: application/x-www-form-urlencoded\r\n",
            "\r\n",
            "message=hello&status=1&_v2_post_token=xyz&disallow_reply=0"
        );
        let parsed = parse_http_plain(preview, "text").expect("http");
        assert_eq!(parsed.kind, "http1_request");
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.host.as_deref(), Some("api.coolapk.com"));
        assert_eq!(parsed.path, "/v6/feed/createFeed");
        assert!(parsed
            .redacted_headers
            .iter()
            .any(|row| row.starts_with("Cookie=")));
        assert!(parsed
            .redacted_headers
            .iter()
            .any(|row| row.starts_with("X-App-Token=")));
        assert!(parsed.body_keys.contains(&"message".to_owned()));
        assert!(parsed.redacted_body_keys.contains(&"message".to_owned()));
        assert!(parsed
            .redacted_body_keys
            .contains(&"_v2_post_token".to_owned()));
        assert!(!parsed.third_party);
    }

    #[test]
    fn parses_get_query_and_flags_tracker_host() {
        let preview = concat!(
            "GET /v6/main/indexV8?page=1&installTime=1 HTTP/1.1\r\n",
            "Host: log-api.pangle.io\r\n",
            "\r\n"
        );
        let parsed = parse_http_plain(preview, "text").expect("http");
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.path, "/v6/main/indexV8");
        assert_eq!(parsed.query_keys, vec!["page", "installTime"]);
        assert!(parsed.third_party);
    }

    #[test]
    fn skips_tls_record_and_parses_http2_preface() {
        assert!(parse_http_plain("TLS application_data", "tls_record").is_none());
        let parsed = parse_http_plain("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "text").expect("h2");
        assert_eq!(parsed.kind, "http2_preface");
        let mut frame = vec![0, 0, 20, 0x1, 0x04, 0, 0, 0, 1];
        frame.extend_from_slice(&[
            0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
        ]);
        let parsed = parse_http_plain_all_bytes(&frame, "binary");
        assert!(
            parsed.iter().any(|row| {
                row.kind == "http2_request"
                    && row.host.as_deref() == Some("www.example.com")
                    && row.path == "/"
            }),
            "{parsed:?}"
        );
    }

    #[test]
    fn drops_png_keeps_txt_with_scheme() {
        let preview = r#"{"img":"https://s.thsi.cn/a.png","cfg":"https://hxapp.10jqka.com.cn/config/sc_public_android.v2.txt"}"#;
        let parsed = parse_http_plain_all(preview, "text");
        let urls: Vec<String> = parsed
            .iter()
            .filter(|row| row.kind == "url")
            .filter_map(|row| format_inspect_url(row.scheme, row.host.as_deref()?, &row.path))
            .collect();
        assert!(
            urls.iter()
                .any(|url| url == "https://hxapp.10jqka.com.cn/config/sc_public_android.v2.txt"),
            "{urls:?}"
        );
        assert!(!urls.iter().any(|url| url.contains(".png")), "{urls:?}");
        assert!(is_kept_inspect_url("https://ecs.abchina.com.cn/mbfront/"));
        assert!(!is_kept_inspect_url("https://i.pki.goog/we1.crt0"));
        assert!(!is_kept_inspect_url("https://c.pki.goog/r/gsr1.crl0"));
    }

    #[test]
    fn packed_cookie_host_keys_are_split_from_names() {
        let bytes =
            b"\0mywap2.icbc.com.cnCK_ISW_WAPB-PORTAL\0cmywap2.icbc.com.cnCK_\0.b2c.icbc.com.cnCK_ISW_EPAY";
        let parsed = parse_http_plain_all_bytes(bytes, "binary");
        assert!(
            parsed
                .iter()
                .any(|row| row.host.as_deref() == Some("mywap2.icbc.com.cn")),
            "{parsed:?}"
        );
        assert!(
            parsed
                .iter()
                .any(|row| row.host.as_deref() == Some("b2c.icbc.com.cn")),
            "{parsed:?}"
        );
        assert!(!parsed.iter().any(|row| row.host.as_deref() == Some("com.cn")));
        assert!(!parsed
            .iter()
            .any(|row| row.host.as_deref() == Some("cmywap2.icbc.com.cn")));
    }

    #[test]
    fn drops_truncated_host_prefix_of_a_longer_host() {
        let bytes = b"https://data.10jqka.co\0https://data.10jqka.com.cn/api/quote";
        let parsed = parse_http_plain_all_bytes(bytes, "text");
        assert!(
            parsed
                .iter()
                .any(|row| row.host.as_deref() == Some("data.10jqka.com.cn")),
            "{parsed:?}"
        );
        assert!(
            !parsed
                .iter()
                .any(|row| row.host.as_deref() == Some("data.10jqka.co")),
            "{parsed:?}"
        );
        assert!(sanitize_host("t.com").is_none());
        assert!(sanitize_host("this.constructor.com").is_none());
        assert!(!is_kept_inspect_url(
            "https://www.citibank.com.hk/english/insurance/pdf/terms.pdf"
        ));
        assert!(!is_kept_inspect_url("https://khms0.google.com/*"));
        assert!(sanitize_host("alipay.kylinbridge").is_none());
    }

    #[test]
    fn json_top_level_keys() {
        let parsed = parse_http_plain("{\"feed_id\":\"1\",\"token\":\"x\"}", "text").expect("json");
        assert_eq!(parsed.kind, "json");
        assert!(parsed.body_keys.contains(&"feed_id".to_owned()));
        assert!(parsed.redacted_body_keys.contains(&"token".to_owned()));
    }

    #[test]
    fn extracts_urls_from_truncated_json() {
        let preview = concat!(
            r#"9fa5b256894d4a31","esType":-1,"url":"https://s.thsi.cn/cd/acrossBar_v1.8.zip","status":1}"#,
            r#",{"url":"https://sp.thsi.cn/staticS3/pkg/e5db.zip"}"#
        );
        let parsed = parse_http_plain_all(preview, "mixed");
        assert!(
            parsed.iter().any(|row| {
                row.host.as_deref() == Some("s.thsi.cn") && row.path == "/cd/acrossBar_v1.8.zip"
            }),
            "{parsed:?}"
        );
        assert!(parsed
            .iter()
            .any(|row| row.host.as_deref() == Some("sp.thsi.cn")));
    }

    #[test]
    fn inflates_gzip_hex_preview_to_json() {
        use std::io::Write as _;
        let plain = br#"{"url":"https://ebsnew.boc.cn/api/login"}"#;
        let mut gz = Vec::new();
        {
            let mut encoder =
                flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
            encoder.write_all(plain).expect("gzip");
            encoder.finish().expect("gzip finish");
        }
        let mut hex = String::new();
        for byte in &gz {
            let _ = std::fmt::Write::write_fmt(&mut hex, format_args!("{byte:02x}"));
        }
        let parsed = parse_http_plain_all(&hex, "binary");
        assert!(
            parsed
                .iter()
                .any(|row| row.host.as_deref() == Some("ebsnew.boc.cn")),
            "{parsed:?}"
        );
    }

    #[test]
    fn skips_heap_object_header_and_parses_nul_response() {
        let mut bytes = vec![0_u8; 0x40];
        bytes[0x28..0x2c].copy_from_slice(&[0x9d, 0xb8, 0x2f, 0x00]);
        bytes[0x3c..0x40].copy_from_slice(&[0xea, 0x03, 0x00, 0x00]);
        bytes.extend_from_slice(b"HTTP/1.1 200 OK\0");
        bytes.extend_from_slice(b"Date: Thu, 27 Aug 2026 13:35:57 GMT\0");
        bytes.extend_from_slice(b"Content-Type: image/jpeg\0");
        bytes.extend_from_slice(b"Content-Length: 73045\0");
        bytes.extend_from_slice(b"Server: unknown\0");
        let parsed = parse_http_plain_bytes(&bytes, "text").expect("http");
        assert_eq!(parsed.kind, "http1_response");
        assert_eq!(parsed.status, Some(200));
        assert!(
            parsed.path.is_empty(),
            "responses have no URL path: {:?}",
            parsed.path
        );
        assert_eq!(parsed.content_type.as_deref(), Some("image/jpeg"));
        assert!(!parsed
            .header_names
            .iter()
            .any(|name| name.contains('\u{fffd}')));
    }

    #[test]
    fn parses_lf_only_headers_and_json_body() {
        let preview = concat!(
            "POST /v1/login HTTP/1.1\n",
            "Host: pay.example\n",
            "Authorization: Bearer secret\n",
            "Content-Type: application/json\n",
            "\n",
            "{\"phone\":\"1\",\"password\":\"x\"}"
        );
        let parsed = parse_http_plain(preview, "text").expect("http");
        assert_eq!(parsed.path, "/v1/login");
        assert_eq!(parsed.host.as_deref(), Some("pay.example"));
        assert!(parsed
            .redacted_headers
            .iter()
            .any(|row| row.starts_with("Authorization=")));
        assert!(parsed.body_keys.contains(&"phone".to_owned()));
        assert!(parsed.redacted_body_keys.contains(&"password".to_owned()));
    }
}
