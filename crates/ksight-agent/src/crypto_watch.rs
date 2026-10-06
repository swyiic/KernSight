//! Live heap scan for app-layer crypto / signing markers during capture.
//!
//! Findings stay local by default (`crypto-watch.log` + durable JSONL).
//! Burp never receives raw windows — only optional correlation fingerprints
//! (sha256 of the scanned window) via InspectObservation metrics/detail so an
//! operator can align timestamps with Burp history offline.
//!
//! Versioned needle hints are written under
//! `/data/local/tmp/ksight/crypto-watch-rules.json` (package → family counts).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const LOG: &str = "/data/local/tmp/ksight/crypto-watch.log";
const EVENTS: &str = "/data/local/tmp/ksight/crypto-watch-events.jsonl";
const RULES: &str = "/data/local/tmp/ksight/crypto-watch-rules.json";
const WINDOW: usize = 512;
const CAP: usize = 24;
const MAP_CAP: u64 = 4 * 1024 * 1024;
const PREVIEW_CHARS: usize = 160;
const RULES_SCHEMA_VERSION: u32 = 1;

/// One heap needle and its metric family (histogram only — not a Burp channel).
struct Needle {
    bytes: &'static [u8],
    family: &'static str,
}

/// Signing / header-encrypt markers. Expand carefully: more needles raise scan
/// cost but still hit the same CAP / 400 ms budget.
const NEEDLES: &[Needle] = &[
    // Sign / gateway headers
    Needle {
        bytes: b"X-Qen",
        family: "sign_header",
    },
    Needle {
        bytes: b"X-Sign",
        family: "sign_header",
    },
    Needle {
        bytes: b"X-Sign:",
        family: "sign_header",
    },
    Needle {
        bytes: b"X-Signature",
        family: "sign_header",
    },
    Needle {
        bytes: b"X-Nonce",
        family: "sign_header",
    },
    Needle {
        bytes: b"X-Token",
        family: "sign_header",
    },
    // JSON / form signing fields
    Needle {
        bytes: b"\"sign\":",
        family: "sign_field",
    },
    Needle {
        bytes: b"\"signature\":",
        family: "sign_field",
    },
    Needle {
        bytes: b"sign=",
        family: "sign_field",
    },
    Needle {
        bytes: b"\"enc\":",
        family: "enc_field",
    },
    Needle {
        bytes: b"\"key\":",
        family: "enc_field",
    },
    // App / platform crypto APIs (string presence only)
    Needle {
        bytes: b"OpenPlatformEncrypt",
        family: "platform_api",
    },
    Needle {
        bytes: b"MessageDigest",
        family: "platform_api",
    },
    Needle {
        bytes: b"SecretKeySpec",
        family: "platform_api",
    },
    Needle {
        bytes: b"Mac.getInstance",
        family: "platform_api",
    },
    Needle {
        bytes: b"HMAC",
        family: "platform_api",
    },
    // Key material labels (preview only — never Burp)
    Needle {
        bytes: b"appSecret",
        family: "key_label",
    },
    Needle {
        bytes: b"appKey",
        family: "key_label",
    },
    Needle {
        bytes: b"secretKey",
        family: "key_label",
    },
    // Cipher transforms
    Needle {
        bytes: b"AES/CBC",
        family: "cipher",
    },
    Needle {
        bytes: b"AES/ECB",
        family: "cipher",
    },
    Needle {
        bytes: b"AES/GCM",
        family: "cipher",
    },
    Needle {
        bytes: b"SM4/",
        family: "cipher",
    },
    Needle {
        bytes: b"SM4/ECB",
        family: "cipher",
    },
    Needle {
        bytes: b"SM4/CBC",
        family: "cipher",
    },
    Needle {
        bytes: b"SM4_decrypt",
        family: "cipher",
    },
    Needle {
        bytes: b"encryptSM4",
        family: "cipher",
    },
    Needle {
        bytes: b"getSM4SecretKey",
        family: "cipher",
    },
    Needle {
        bytes: b"getSM4IV",
        family: "cipher",
    },
    Needle {
        bytes: b"NativeManager",
        family: "cipher",
    },
    Needle {
        bytes: b"bocsafe",
        family: "platform_api",
    },
    Needle {
        bytes: b"EncryptionAesUtils",
        family: "cipher",
    },
    Needle {
        bytes: b"sm4 encrypt keyString",
        family: "cipher",
    },
    // App-layer cipher / sign markers (string presence only; no offsets).
    Needle {
        bytes: b"Cipher.getInstance",
        family: "platform_api",
    },
    Needle {
        bytes: b"javax.crypto.Cipher",
        family: "platform_api",
    },
    Needle {
        bytes: b"doFinal",
        family: "platform_api",
    },
    Needle {
        bytes: b"\"signValue\"",
        family: "sign_field",
    },
    Needle {
        bytes: b"\"signData\"",
        family: "sign_field",
    },
    Needle {
        bytes: b"encryptByPublicKey",
        family: "platform_api",
    },
    Needle {
        bytes: b"InfosecTcp",
        family: "platform_api",
    },
    Needle {
        bytes: b"Infosec4",
        family: "platform_api",
    },
    Needle {
        bytes: b"Mac.init",
        family: "platform_api",
    },
    Needle {
        bytes: b"javax.crypto.Mac",
        family: "platform_api",
    },
    Needle {
        bytes: b"writeSSLDataNative",
        family: "platform_api",
    },
    // InfosecTcp JNI read-side entry name — string only.
    Needle {
        bytes: b"readSSLDataNative",
        family: "platform_api",
    },
    // BOC GmSSL JNI crypto SDK (libgmssl.so build_id a89971d3… size=783320).
    // String presence only — correlates --inspect-jni / boundary dump with
    // pre-encrypt buffers; no invented register offsets.
    Needle {
        bytes: b"org.gmssl.GmSSL",
        family: "platform_api",
    },
    Needle {
        bytes: b"Java_org_gmssl_GmSSL_symmetricEncrypt",
        family: "platform_api",
    },
    Needle {
        bytes: b"symmetricEncrypt",
        family: "platform_api",
    },
    Needle {
        bytes: b"sm4_cbc_encrypt",
        family: "cipher",
    },
    Needle {
        bytes: b"sm4_encrypt",
        family: "cipher",
    },
    // JNI registration corridor (string presence): helps correlate --inspect-jni
    // RegisterNatives previews into versioned rules before encrypt seals headers.
    Needle {
        bytes: b"RegisterNatives",
        family: "jni_registration",
    },
    Needle {
        bytes: b"JNI_OnLoad",
        family: "jni_registration",
    },
    // JNIEnv byte[] corridor (string presence): correlates --inspect-jni
    // Get/SetByteArrayRegion / GetPrimitiveArrayCritical previews with
    // plaintext-before-encrypt buffers into versioned rules (no offsets).
    Needle {
        bytes: b"GetByteArrayRegion",
        family: "jni_registration",
    },
    Needle {
        bytes: b"SetByteArrayRegion",
        family: "jni_registration",
    },
    Needle {
        bytes: b"GetPrimitiveArrayCritical",
        family: "jni_registration",
    },
    // Java Cipher.init sits on the pre-encrypt path.
    Needle {
        bytes: b"JavascriptInterface",
        family: "webview_js",
    },
    Needle {
        bytes: b"evaluateJavascript",
        family: "webview_js",
    },
    Needle {
        bytes: b"Cipher.init",
        family: "platform_api",
    },
];

/// Redacted durable finding for spool / Burp correlation (fingerprint only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoWatchFinding {
    /// `pid`.
    pub pid: u32,
    /// `package`.
    pub package: String,
    /// `family`.
    pub family: &'static str,
    /// `needle`.
    pub needle: String,
    /// `va`.
    pub va: u64,
    /// SHA-256 hex of the raw window bytes (correlation id — not a secret dump).
    pub window_sha256: String,
    /// Scrubbed printable preview (value-like tokens replaced).
    pub preview_redacted: String,
    /// `unix_ms`.
    pub unix_ms: u64,
}

/// Summary returned to the capture loop for `InspectObservation` emission.
#[derive(Debug, Clone, Default)]
pub struct CryptoWatchScanResult {
    /// `added`.
    pub added: usize,
    /// `family_hits`.
    pub family_hits: BTreeMap<&'static str, usize>,
    /// `findings`.
    pub findings: Vec<CryptoWatchFinding>,
}

/// Scan one process and append new findings (log + durable JSONL + rules).
#[must_use]
pub fn scan_pid(pid: u32, package: &str) -> usize {
    scan_pid_ex(pid, package, &Paths::device()).added
}

/// Scan with explicit paths (unit tests / offline fixtures).
#[must_use]
pub fn scan_pid_ex(pid: u32, package: &str, paths: &Paths) -> CryptoWatchScanResult {
    let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return CryptoWatchScanResult::default();
    };
    let Ok(mut mem) = File::open(format!("/proc/{pid}/mem")) else {
        return CryptoWatchScanResult::default();
    };
    scan_maps(pid, package, &maps, &mut mem, paths)
}

/// Pure scan over provided maps text + memory reader (fixtures / tests).
pub fn scan_maps(
    pid: u32,
    package: &str,
    maps: &str,
    mem: &mut dyn MemSource,
    paths: &Paths,
) -> CryptoWatchScanResult {
    let mut seen = load_seen(&paths.log);
    let mut result = CryptoWatchScanResult::default();
    let started = Instant::now();
    for line in maps.lines() {
        if result.added >= CAP || started.elapsed().as_millis() > 400 {
            break;
        }
        let Some((start, end, perms, path)) = parse_map(line) else {
            continue;
        };
        if !perms.contains('r') || perms.contains('x') {
            continue;
        }
        if path.starts_with("/system/")
            || path.starts_with("/apex/")
            || path.starts_with("/vendor/")
        {
            continue;
        }
        let heap = path.is_empty()
            || path.starts_with('[')
            || path.contains("scudo")
            || path.contains("dalvik");
        if !heap {
            continue;
        }
        let len = end.saturating_sub(start).min(MAP_CAP);
        if len < 4096 {
            continue;
        }
        let Some(bytes) = mem.read_region(start, len as usize) else {
            continue;
        };
        for needle in NEEDLES {
            let mut from = 0;
            while result.added < CAP {
                let Some(rel) = bytes[from..]
                    .windows(needle.bytes.len())
                    .position(|w| w == needle.bytes)
                else {
                    break;
                };
                let at = from + rel;
                let begin = at.saturating_sub(32);
                let end_i = (at + WINDOW).min(bytes.len());
                let slice = &bytes[begin..end_i];
                let printable = lossy_printable(slice);
                let redacted = redact_preview(&printable);
                let digest = sha256_hex(slice);
                let va = start + at as u64;
                let line = format!(
                    "pid={pid} pkg={package} family={} needle={} va={:#x} sha256={} {}",
                    needle.family,
                    String::from_utf8_lossy(needle.bytes),
                    va,
                    &digest[..16],
                    redacted.chars().take(PREVIEW_CHARS).collect::<String>()
                );
                if seen.insert(line.clone()) {
                    append_log(&paths.log, &line);
                    let finding = CryptoWatchFinding {
                        pid,
                        package: package.to_owned(),
                        family: needle.family,
                        needle: String::from_utf8_lossy(needle.bytes).into_owned(),
                        va,
                        window_sha256: digest,
                        preview_redacted: redacted.chars().take(PREVIEW_CHARS).collect(),
                        unix_ms: now_unix_ms(),
                    };
                    append_event_jsonl(&paths.events, &finding);
                    result.findings.push(finding);
                    result.added += 1;
                    *result.family_hits.entry(needle.family).or_default() += 1;
                    eprintln!("crypto-watch {line}");
                }
                from = at + needle.bytes.len().max(1);
            }
        }
    }
    if !result.family_hits.is_empty() {
        let summary: Vec<String> = result
            .family_hits
            .iter()
            .map(|(family, count)| format!("{family}={count}"))
            .collect();
        let metrics = format!(
            "pid={pid} pkg={package} metrics hits={} {}",
            result.added,
            summary.join(" ")
        );
        append_log(&paths.log, &metrics);
        eprintln!("crypto-watch {metrics}");
        merge_versioned_rules(&paths.rules, package, &result.family_hits);
    }
    result
}

/// Classify a JNI / Inspect plaintext preview as pre-encrypt crypto-related.
///
/// Returns `(family, needle)` when a known marker is present. Used by the JNI
/// inspect path to stamp correlation metadata without inventing offsets.
#[must_use]
pub fn classify_plaintext_preview(preview: &str) -> Option<(&'static str, &'static str)> {
    classify_plaintext_bytes(preview.as_bytes())
}

/// Classify raw buffer bytes the same way as a lossy preview string.
#[must_use]
pub fn classify_plaintext_bytes(bytes: &[u8]) -> Option<(&'static str, &'static str)> {
    for needle in NEEDLES {
        if needle.bytes.is_empty() {
            continue;
        }
        if bytes.windows(needle.bytes.len()).any(|w| w == needle.bytes) {
            return Some((
                needle.family,
                std::str::from_utf8(needle.bytes).unwrap_or(needle.family),
            ));
        }
    }
    // Phone-number field in a short buffer (pre-encrypt, not full HTTP).
    // Covers CN mobile/landline and common international forms — not only 11-digit CN mobile.
    if looks_like_phone_field(bytes) {
        return Some(("critical_field", "phone"));
    }
    None
}

/// True when `bytes` is (or tightly wraps) a phone number field value.
///
/// Accepts more than mainland 11-digit mobiles: landlines, `+CC…`, and numbers with
/// common separators. Kept tight to short field buffers to avoid HTTP-body false positives.
pub(crate) fn looks_like_phone_field(bytes: &[u8]) -> bool {
    let text = std::str::from_utf8(bytes).unwrap_or("");
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.len() > 48 {
        return false;
    }
    // Bare / quoted sole value.
    if is_phone_number_token(trimmed) {
        return true;
    }
    if trimmed.len() >= 3
        && trimmed.starts_with('"')
        && trimmed.ends_with('"')
        && is_phone_number_token(&trimmed[1..trimmed.len() - 1])
    {
        return true;
    }
    // Tiny JSON naming a phone-ish key: {"mobile":"…"} / {"phone":"…"} / {"tel":"…"}.
    if trimmed.starts_with('{') && trimmed.ends_with('}') && phone_field_key_present(trimmed) {
        if let Some(token) = json_string_value_near_phone_key(trimmed) {
            return is_phone_number_token(token);
        }
        // Fallback: single digit-run in a tiny phone-keyed object.
        let digits: String = trimmed.chars().filter(char::is_ascii_digit).collect();
        return is_phone_digit_run(&digits);
    }
    false
}

fn phone_field_key_present(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "mobile",
        "phone",
        "tel",
        "cellphone",
        "telephone",
        "msisdn",
        "phonenumber",
        "phone_number",
        "mobilephone",
        "手机",
        "电话",
    ]
    .iter()
    .any(|k| lower.contains(k) || text.contains(k))
}

/// Best-effort extract of a JSON string value next to a phone-ish key in a tiny object.
fn json_string_value_near_phone_key(text: &str) -> Option<&str> {
    let lower = text.to_ascii_lowercase();
    for key in [
        "mobile",
        "phone",
        "tel",
        "cellphone",
        "telephone",
        "msisdn",
        "phonenumber",
        "phone_number",
        "mobilephone",
    ] {
        if let Some(pos) = lower.find(key) {
            let after = &text[pos + key.len()..];
            if let Some(colon) = after.find(':') {
                let v = after[colon + 1..].trim_start();
                if let Some(rest) = v.strip_prefix('"') {
                    if let Some(end) = rest.find('"') {
                        return Some(&rest[..end]);
                    }
                }
            }
        }
    }
    None
}

/// A single phone token: optional `+`, digits, and common separators only.
fn is_phone_number_token(token: &str) -> bool {
    let t = token.trim();
    if t.is_empty() || t.len() > 24 {
        return false;
    }
    // Must look like a phone glyph set: digits, spaces, dashes, dots, parens, leading +.
    let mut chars = t.chars().peekable();
    if chars.peek() == Some(&'+') {
        chars.next();
    }
    let mut digit_count = 0usize;
    let mut saw_separator = false;
    for c in chars {
        if c.is_ascii_digit() {
            digit_count += 1;
        } else if matches!(c, ' ' | '-' | '.' | '(' | ')') {
            saw_separator = true;
        } else {
            return false;
        }
    }
    if !is_phone_digit_run_len(digit_count) {
        return false;
    }
    // Pure digit run, or separator-formatted with enough digits.
    // Bare short runs (7–9) are too ambiguous (IDs / truncated JNI); require phone-keyed JSON for those.
    if !saw_separator {
        let digits = t.trim_start_matches('+');
        if !(10..=15).contains(&digits.len()) {
            return false;
        }
        // Mainland-shaped 11-digit mobiles start with 1; other 10–15 still ok (intl without '+').
        if digits.len() == 11 && !digits.starts_with('1') {
            return false;
        }
        return is_phone_digit_run(digits);
    }
    true
}

/// Digit-only (no `+`) phone run: 7–15 digits (E.164 national/international span).
fn is_phone_digit_run(digits: &str) -> bool {
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    is_phone_digit_run_len(digits.len())
}

fn is_phone_digit_run_len(len: usize) -> bool {
    // ITU E.164 max 15; local shorts rarely <7. Reject 13-digit unix-ms-shaped alone? still allow 7–15.
    (7..=15).contains(&len)
}

/// Path hint stamped on `InspectObservation` / logs for Burp correlation only.
#[must_use]
pub fn path_hint_for(family: &str, needle: &str) -> String {
    format!("crypto_pre_encrypt:{family}:{needle}")
}

/// True when the inspect adapter is a `JNIEnv` / jni_* corridor (opt-in `--inspect-jni`).
#[must_use]
pub fn adapter_is_jni(adapter: &str) -> bool {
    adapter == "jni_plaintext" || adapter.starts_with("jni_") || adapter.contains("JNIEnv")
}

/// True when adapter is a vendor TLS/JNI boundary (`InfosecTcp` etc.).
#[must_use]
pub fn adapter_is_vendor_boundary(adapter: &str) -> bool {
    adapter.starts_with("vendor_boundary")
}

/// Source label written into durable events / versioned rules.
#[must_use]
pub fn source_for_adapter(adapter: &str) -> &'static str {
    if adapter_is_jni(adapter) {
        "inspect_jni"
    } else if adapter_is_vendor_boundary(adapter) {
        "inspect_vendor"
    } else {
        "inspect_plaintext"
    }
}

/// Result of ingesting an `InspectPlaintext` preview into crypto-watch rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectIngestHit {
    /// `family`.
    pub family: &'static str,
    /// `needle`.
    pub needle: &'static str,
    /// `source`.
    pub source: &'static str,
    /// `path_hint`.
    pub path_hint: String,
    /// `preview_redacted`.
    pub preview_redacted: String,
    /// `window_sha256`.
    pub window_sha256: String,
    /// Observation-friendly detail (no raw secrets).
    pub detail: String,
}

/// Classify an `InspectPlaintext` preview and, on hit, persist into versioned rules
/// + durable JSONL (`source=inspect_jni|inspect_plaintext|inspect_vendor`).
///
/// Never forwards raw secret bytes — only redacted preview + sha256 fingerprint.
/// Intended splice site: `capture.rs` `emit_inspect_output` Plaintext branch
/// (after fragment is built, before/while emitting `InspectPlaintext`).
pub fn ingest_inspect_plaintext(
    package: &str,
    adapter: &str,
    preview: &str,
    content_sha256: Option<&str>,
    paths: &Paths,
) -> Option<InspectIngestHit> {
    let (family, needle) = classify_plaintext_preview(preview)?;
    let source = source_for_adapter(adapter);
    let redacted = redact_preview(preview)
        .chars()
        .take(PREVIEW_CHARS)
        .collect::<String>();
    let digest = content_sha256
        .filter(|s| !s.is_empty())
        .map_or_else(|| sha256_hex(preview.as_bytes()), str::to_owned);
    let path_hint = path_hint_for(family, needle);
    let finding = CryptoWatchFinding {
        pid: 0,
        package: package.to_owned(),
        family,
        needle: needle.to_owned(),
        va: 0,
        window_sha256: digest.clone(),
        preview_redacted: redacted.clone(),
        unix_ms: now_unix_ms(),
    };
    // Tag source in the JSONL by extending the manual line (schema stays v1).
    append_ingest_event_jsonl(&paths.events, &finding, source, adapter);
    if family == "critical_field" {
        eprintln!(
            "critical-field kind={needle} pkg={package} adapter={adapter} preview={}",
            redacted.chars().take(48).collect::<String>()
        );
    }
    let mut family_hits = BTreeMap::new();
    family_hits.insert(family, 1usize);
    merge_versioned_rules_ex(&paths.rules, package, &family_hits, source, needle, &digest);
    let line = format!(
        "pkg={package} source={source} adapter={adapter} family={family} needle={needle} sha256={} {}",
        &digest[..digest.len().min(16)],
        redacted
    );
    append_log(&paths.log, &format!("ingest {line}"));
    let detail = format!(
        "crypto_watch_ingest source={source} family={family} needle={needle} path_hint={path_hint} fingerprint={digest}"
    );
    Some(InspectIngestHit {
        family,
        needle,
        source,
        path_hint,
        preview_redacted: redacted,
        window_sha256: digest,
        detail,
    })
}

/// Build an InspectObservation-friendly detail line (no raw secrets).
#[must_use]
pub fn observation_detail(result: &CryptoWatchScanResult) -> String {
    let mut parts: Vec<String> = result
        .family_hits
        .iter()
        .map(|(f, n)| format!("{f}={n}"))
        .collect();
    parts.sort();
    let fps: Vec<&str> = result
        .findings
        .iter()
        .take(8)
        .map(|f| f.window_sha256.as_str())
        .collect();
    format!(
        "crypto_watch hits={} families=[{}] fingerprints=[{}]",
        result.added,
        parts.join(","),
        fps.join(",")
    )
}

/// Paths for durable crypto-watch artifacts (overridable in tests).
#[derive(Debug, Clone)]
pub struct Paths {
    /// `log`.
    pub log: PathBuf,
    /// `events`.
    pub events: PathBuf,
    /// `rules`.
    pub rules: PathBuf,
}

impl Paths {
    /// `device`.
    #[must_use]
    pub fn device() -> Self {
        Self {
            log: PathBuf::from(LOG),
            events: PathBuf::from(EVENTS),
            rules: PathBuf::from(RULES),
        }
    }

    /// `under`.
    pub fn under(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        Self {
            log: root.join("crypto-watch.log"),
            events: root.join("crypto-watch-events.jsonl"),
            rules: root.join("crypto-watch-rules.json"),
        }
    }
}

/// Abstraction over `/proc/pid/mem` for fixture tests.
pub trait MemSource {
    /// `read_region`.
    fn read_region(&mut self, start: u64, len: usize) -> Option<Vec<u8>>;
}

impl MemSource for File {
    fn read_region(&mut self, start: u64, len: usize) -> Option<Vec<u8>> {
        self.seek(SeekFrom::Start(start)).ok()?;
        let mut buf = vec![0_u8; len];
        let n = self.read(&mut buf).ok()?;
        buf.truncate(n);
        Some(buf)
    }
}

/// In-memory region map for unit tests (no /proc).
pub struct FixtureMem {
    /// `regions`.
    pub regions: BTreeMap<u64, Vec<u8>>,
}

impl MemSource for FixtureMem {
    fn read_region(&mut self, start: u64, len: usize) -> Option<Vec<u8>> {
        let bytes = self.regions.get(&start)?;
        let end = len.min(bytes.len());
        Some(bytes[..end].to_vec())
    }
}

fn parse_map(line: &str) -> Option<(u64, u64, &str, &str)> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let (start, end) = range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    let perms = parts.next()?;
    let path = line.splitn(6, char::is_whitespace).last().unwrap_or("");
    Some((start, end, perms, path))
}

fn load_seen(log: &Path) -> BTreeSet<String> {
    let Ok(text) = std::fs::read_to_string(log) else {
        return BTreeSet::new();
    };
    text.lines().map(str::to_owned).collect()
}

fn append_log(log: &Path, line: &str) {
    if let Some(parent) = log.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log) else {
        return;
    };
    let _ = writeln!(file, "{line}");
}

fn append_event_jsonl(events: &Path, finding: &CryptoWatchFinding) {
    if let Some(parent) = events.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(events) else {
        return;
    };
    // Manual JSON to avoid pulling serde into agent host-test cfg surprises.
    let line = format!(
        "{{\"schema\":\"crypto_watch_event/v1\",\"unix_ms\":{},\"pid\":{},\"package\":{},\"family\":{},\"needle\":{},\"va\":\"{:#x}\",\"window_sha256\":{},\"preview_redacted\":{}}}",
        finding.unix_ms,
        finding.pid,
        json_str(&finding.package),
        json_str(finding.family),
        json_str(&finding.needle),
        finding.va,
        json_str(&finding.window_sha256),
        json_str(&finding.preview_redacted),
    );
    let _ = writeln!(file, "{line}");
}

fn merge_versioned_rules(
    rules_path: &Path,
    package: &str,
    family_hits: &BTreeMap<&'static str, usize>,
) {
    merge_versioned_rules_ex(rules_path, package, family_hits, "heap_scan", "", "");
}

/// Merge family counts plus optional source / needle / fingerprint into schema v1 rules.
///
/// Additive fields under each package (still `schema_version=1`):
/// - `sources`: { `heap_scan|inspect_jni|inspect_plaintext|inspect_vendor`: count }
/// - `needles`: { `needle_string`: count }
/// - `fingerprints`: capped array of recent window sha256 (correlation only)
fn merge_versioned_rules_ex(
    rules_path: &Path,
    package: &str,
    family_hits: &BTreeMap<&'static str, usize>,
    source: &str,
    needle: &str,
    fingerprint: &str,
) {
    if let Some(parent) = rules_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut root: serde_json::Value = std::fs::read_to_string(rules_path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_else(|| {
            serde_json::json!({
                "schema_version": RULES_SCHEMA_VERSION,
                "packages": {}
            })
        });
    if root
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(u64::from(RULES_SCHEMA_VERSION))
    {
        root = serde_json::json!({
            "schema_version": RULES_SCHEMA_VERSION,
            "packages": {}
        });
    }
    let packages = root
        .as_object_mut()
        .unwrap()
        .entry("packages")
        .or_insert_with(|| serde_json::json!({}));
    let pkg = packages
        .as_object_mut()
        .unwrap()
        .entry(package.to_owned())
        .or_insert_with(|| {
            serde_json::json!({
                "families": {},
                "sources": {},
                "needles": {},
                "fingerprints": [],
                "updated_unix_ms": 0u64
            })
        });
    let pkg_obj = pkg.as_object_mut().unwrap();
    let families = pkg_obj
        .entry("families")
        .or_insert_with(|| serde_json::json!({}));
    for (family, count) in family_hits {
        let entry = families
            .as_object_mut()
            .unwrap()
            .entry((*family).to_owned())
            .or_insert(serde_json::json!(0));
        let prev = entry.as_u64().unwrap_or(0);
        *entry = serde_json::json!(prev.saturating_add(*count as u64));
    }
    if !source.is_empty() {
        let sources = pkg_obj
            .entry("sources")
            .or_insert_with(|| serde_json::json!({}));
        let entry = sources
            .as_object_mut()
            .unwrap()
            .entry(source.to_owned())
            .or_insert(serde_json::json!(0));
        let prev = entry.as_u64().unwrap_or(0);
        *entry = serde_json::json!(prev.saturating_add(1));
    }
    if !needle.is_empty() {
        let needles = pkg_obj
            .entry("needles")
            .or_insert_with(|| serde_json::json!({}));
        let entry = needles
            .as_object_mut()
            .unwrap()
            .entry(needle.to_owned())
            .or_insert(serde_json::json!(0));
        let prev = entry.as_u64().unwrap_or(0);
        *entry = serde_json::json!(prev.saturating_add(1));
    }
    if !fingerprint.is_empty() {
        let fps = pkg_obj
            .entry("fingerprints")
            .or_insert_with(|| serde_json::json!([]));
        if let Some(arr) = fps.as_array_mut() {
            let fp = serde_json::Value::String(fingerprint.to_owned());
            if !arr.contains(&fp) {
                arr.push(fp);
            }
            if arr.len() > 32 {
                let drain = arr.len() - 32;
                arr.drain(0..drain);
            }
        }
    }
    pkg_obj.insert("updated_unix_ms".into(), serde_json::json!(now_unix_ms()));
    if let Ok(text) = serde_json::to_string_pretty(&root) {
        let _ = std::fs::write(rules_path, text);
    }
}

fn append_ingest_event_jsonl(
    events: &Path,
    finding: &CryptoWatchFinding,
    source: &str,
    adapter: &str,
) {
    if let Some(parent) = events.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(events) else {
        return;
    };
    let line = format!(
        "{{\"schema\":\"crypto_watch_event/v1\",\"unix_ms\":{},\"pid\":{},\"package\":{},\"family\":{},\"needle\":{},\"va\":\"{:#x}\",\"window_sha256\":{},\"preview_redacted\":{},\"source\":{},\"adapter\":{}}}",
        finding.unix_ms,
        finding.pid,
        json_str(&finding.package),
        json_str(finding.family),
        json_str(&finding.needle),
        finding.va,
        json_str(&finding.window_sha256),
        json_str(&finding.preview_redacted),
        json_str(source),
        json_str(adapter),
    );
    let _ = writeln!(file, "{line}");
}

fn lossy_printable(slice: &[u8]) -> String {
    slice
        .iter()
        .map(|b| {
            if (32..127).contains(b) || *b == b'\n' || *b == b'\r' {
                *b as char
            } else {
                '.'
            }
        })
        .collect()
}

/// Replace value-ish tokens after known labels so durable events stay non-secret.
#[must_use]
pub fn redact_preview(preview: &str) -> String {
    let mut out = preview.to_owned();
    // Quote-bounded JSON values after sensitive keys.
    for key in [
        "\"sign\"",
        "\"signature\"",
        "\"signValue\"",
        "\"signData\"",
        "\"enc\"",
        "\"key\"",
        "\"appSecret\"",
        "\"appKey\"",
        "\"secretKey\"",
        "\"password\"",
        "\"token\"",
    ] {
        out = redact_json_value(&out, key);
    }
    // Header-style `X-Sign: <value>`
    for hdr in ["X-Sign:", "X-Signature:", "X-Nonce:", "X-Token:", "X-Qen:"] {
        out = redact_header_value(&out, hdr);
    }
    // Form `sign=<value>`
    out = redact_form_value(&out, "sign=");
    out = redact_form_value(&out, "appSecret=");
    out = redact_form_value(&out, "appKey=");
    out = redact_form_value(&out, "secretKey=");
    // Windows often start mid-value (needle at "key": leaves prior "sign" value
    // without its key). Scrub remaining long quoted / alnum tokens.
    out = redact_long_quoted(&out);
    out = redact_long_tokens(&out);
    out
}

/// Replace `"…"` literals whose content is longer than 8 chars (keeps short enums).
fn redact_long_quoted(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let mut j = i + 1;
            while j < bytes.len() && bytes[j] != b'"' {
                j += 1;
            }
            if j < bytes.len() {
                let inner = &input[i + 1..j];
                if inner.len() > 8 && inner != "[REDACTED]" {
                    out.push_str("\"[REDACTED]\"");
                } else {
                    out.push_str(&input[i..=j]);
                }
                i = j + 1;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Replace unbroken alnum/_/- tokens of length >= 8 (hex/base64-ish leftovers).
fn redact_long_tokens(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while !rest.is_empty() {
        let split = rest
            .char_indices()
            .find(|(_, c)| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .map(|(idx, _)| idx);
        let Some(start) = split else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        let end = rest
            .char_indices()
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_' || *c == '-'))
            .map_or(rest.len(), |(idx, _)| idx);
        let token = &rest[..end];
        let keep = token.len() < 8
            || matches!(
                token,
                "OpenPlatformEncrypt"
                    | "MessageDigest"
                    | "SecretKeySpec"
                    | "EncryptionAesUtils"
                    | "SM4_decrypt"
                    | "encryptSM4"
                    | "Cipher.getInstance"
                    | "encryptByPublicKey"
                    | "InfosecTcp"
                    | "Infosec4"
                    | "javax.crypto.Cipher"
                    | "javax.crypto.Mac"
                    | "writeSSLDataNative"
                    | "readSSLDataNative"
                    | "RegisterNatives"
                    | "JNI_OnLoad"
                    | "GetByteArrayRegion"
                    | "SetByteArrayRegion"
                    | "GetPrimitiveArrayCritical"
                    | "Cipher.init"
            );
        if keep {
            out.push_str(token);
        } else {
            out.push_str("[REDACTED]");
        }
        rest = &rest[end..];
    }
    out
}

fn redact_json_value(input: &str, key: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(idx) = rest.find(key) {
        out.push_str(&rest[..idx + key.len()]);
        rest = &rest[idx + key.len()..];
        // skip whitespace and colon
        let trimmed = rest.trim_start_matches([' ', '\t']);
        let skipped = rest.len() - trimmed.len();
        out.push_str(&rest[..skipped]);
        rest = trimmed;
        if rest.starts_with(':') {
            out.push(':');
            rest = rest[1..].trim_start();
        }
        if let Some(stripped) = rest.strip_prefix('"') {
            out.push_str("\"[REDACTED]\"");
            if let Some(end) = stripped.find('"') {
                rest = &stripped[end + 1..];
            } else {
                rest = "";
            }
        } else {
            // bare token until delimiter
            out.push_str("[REDACTED]");
            let end = rest.find([',', '}', ' ', '&', '\n']).unwrap_or(rest.len());
            rest = &rest[end..];
        }
    }
    out.push_str(rest);
    out
}

fn redact_header_value(input: &str, header: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(idx) = rest.find(header) {
        out.push_str(&rest[..idx + header.len()]);
        rest = &rest[idx + header.len()..];
        let trimmed = rest.trim_start();
        out.push_str(&rest[..rest.len() - trimmed.len()]);
        out.push_str("[REDACTED]");
        let end = trimmed.find(['\n', '\r', ' ']).unwrap_or(trimmed.len());
        // if space-delimited mid-line, keep remainder after first token
        rest = &trimmed[end..];
    }
    out.push_str(rest);
    out
}

fn redact_form_value(input: &str, key: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(idx) = rest.find(key) {
        out.push_str(&rest[..idx + key.len()]);
        rest = &rest[idx + key.len()..];
        out.push_str("[REDACTED]");
        let end = rest.find(['&', ' ', '\n', '"', '\'']).unwrap_or(rest.len());
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let dig = hasher.finalize();
    let mut hex = String::with_capacity(dig.len().saturating_mul(2));
    for byte in dig {
        hex.push(char::from(HEX[usize::from(byte >> 4)]));
        hex.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    hex
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_owned())
}
