//! HTTP/1 (and HTTP/2 preface) parse of Inspect TLS plaintext previews.
//!
//! Values that look like tokens are replaced with `[REDACTED]`. HTTP/2 frames
//! after the preface are not decoded. This is report-side analysis of existing
//! Inspect buffers, not a new capture ABI.

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
    "taobao",
];

/// One parsed HTTP/1 call or HTTP/2 preface from an Inspect preview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHttpPlain {
    /// `http1_request`, `http1_response`, `http2_preface`, or `json`.
    pub kind: &'static str,
    /// `GET` / `POST` / `HTTP` (response) / `PRI`.
    pub method: String,
    /// Host header, lowercased.
    pub host: Option<String>,
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
    if content_class == "tls_record" {
        return None;
    }
    let text = preview.trim();
    if text.is_empty() {
        return None;
    }
    if text.starts_with("PRI * HTTP/2.0") {
        return Some(ParsedHttpPlain {
            kind: "http2_preface",
            method: "PRI".to_owned(),
            host: None,
            path: "*".to_owned(),
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

fn parse_http1(text: &str) -> Option<ParsedHttpPlain> {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let (head, body) = text.split_once("\n\n").unwrap_or((text.as_str(), ""));
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
    Some(ParsedHttpPlain {
        kind: if status.is_some() {
            "http1_response"
        } else {
            "http1_request"
        },
        method,
        host,
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
        return Some(("HTTP".to_owned(), "/", status));
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
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return None;
    }
    let (body_keys, redacted_body_keys) = json_keys(trimmed);
    if body_keys.is_empty() {
        return None;
    }
    Some(ParsedHttpPlain {
        kind: "json",
        method: "JSON".to_owned(),
        host: None,
        path: "/".to_owned(),
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

fn sanitize_host(value: &str) -> Option<String> {
    let host = value.trim().trim_matches(|ch: char| ch == '[' || ch == ']');
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    if !host.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'[' | b']')
    }) {
        return None;
    }
    Some(host.to_ascii_lowercase())
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
    }

    #[test]
    fn json_top_level_keys() {
        let parsed = parse_http_plain("{\"feed_id\":\"1\",\"token\":\"x\"}", "text").expect("json");
        assert_eq!(parsed.kind, "json");
        assert!(parsed.body_keys.contains(&"feed_id".to_owned()));
        assert!(parsed.redacted_body_keys.contains(&"token".to_owned()));
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
