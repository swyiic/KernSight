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
        bytes: b"SM4_decrypt",
        family: "cipher",
    },
    Needle {
        bytes: b"encryptSM4",
        family: "cipher",
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
        bytes: b"Cipher.init",
        family: "platform_api",
    },
    // App-specific markers retained from prior captures
    Needle {
        bytes: b"getScanItWhiteList",
        family: "app_marker",
    },
    Needle {
        bytes: b"sysLogin",
        family: "app_marker",
    },
    Needle {
        bytes: b"BHtQRepXEBWle7CJ",
        family: "app_marker",
    },
];

/// Redacted durable finding for spool / Burp correlation (fingerprint only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoWatchFinding {
    pub pid: u32,
    pub package: String,
    pub family: &'static str,
    pub needle: String,
    pub va: u64,
    /// SHA-256 hex of the raw window bytes (correlation id — not a secret dump).
    pub window_sha256: String,
    /// Scrubbed printable preview (value-like tokens replaced).
    pub preview_redacted: String,
    pub unix_ms: u64,
}

/// Summary returned to the capture loop for InspectObservation emission.
#[derive(Debug, Clone, Default)]
pub struct CryptoWatchScanResult {
    pub added: usize,
    pub family_hits: BTreeMap<&'static str, usize>,
    pub findings: Vec<CryptoWatchFinding>,
}

/// Scan one process and append new findings (log + durable JSONL + rules).
pub fn scan_pid(pid: u32, package: &str) -> usize {
    scan_pid_ex(pid, package, Paths::device()).added
}

/// Scan with explicit paths (unit tests / offline fixtures).
pub fn scan_pid_ex(pid: u32, package: &str, paths: Paths) -> CryptoWatchScanResult {
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
    paths: Paths,
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
pub fn classify_plaintext_preview(preview: &str) -> Option<(&'static str, &'static str)> {
    classify_plaintext_bytes(preview.as_bytes())
}

/// Classify raw buffer bytes the same way as a lossy preview string.
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
    None
}

/// Path hint stamped on InspectObservation / logs for Burp correlation only.
pub fn path_hint_for(family: &str, needle: &str) -> String {
    format!("crypto_pre_encrypt:{family}:{needle}")
}

/// True when the inspect adapter is a JNIEnv / jni_* corridor (opt-in `--inspect-jni`).
pub fn adapter_is_jni(adapter: &str) -> bool {
    adapter == "jni_plaintext" || adapter.starts_with("jni_") || adapter.contains("JNIEnv")
}

/// True when adapter is a vendor TLS/JNI boundary (InfosecTcp etc.).
pub fn adapter_is_vendor_boundary(adapter: &str) -> bool {
    adapter.starts_with("vendor_boundary")
}

/// Source label written into durable events / versioned rules.
pub fn source_for_adapter(adapter: &str) -> &'static str {
    if adapter_is_jni(adapter) {
        "inspect_jni"
    } else if adapter_is_vendor_boundary(adapter) {
        "inspect_vendor"
    } else {
        "inspect_plaintext"
    }
}

/// Result of ingesting an InspectPlaintext preview into crypto-watch rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectIngestHit {
    pub family: &'static str,
    pub needle: &'static str,
    pub source: &'static str,
    pub path_hint: String,
    pub preview_redacted: String,
    pub window_sha256: String,
    /// Observation-friendly detail (no raw secrets).
    pub detail: String,
}

/// Classify an InspectPlaintext preview and, on hit, persist into versioned rules
/// + durable JSONL (`source=inspect_jni|inspect_plaintext|inspect_vendor`).
///
/// Never forwards raw secret bytes — only redacted preview + sha256 fingerprint.
/// Intended splice site: `capture.rs` `emit_inspect_output` Plaintext branch
/// (after fragment is built, before/while emitting InspectPlaintext).
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
        .map(str::to_owned)
        .unwrap_or_else(|| sha256_hex(preview.as_bytes()));
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
    pub log: PathBuf,
    pub events: PathBuf,
    pub rules: PathBuf,
}

impl Paths {
    pub fn device() -> Self {
        Self {
            log: PathBuf::from(LOG),
            events: PathBuf::from(EVENTS),
            rules: PathBuf::from(RULES),
        }
    }

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
/// - `sources`: { heap_scan|inspect_jni|inspect_plaintext|inspect_vendor: count }
/// - `needles`: { needle_string: count }
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
    if root.get("schema_version").and_then(|v| v.as_u64()) != Some(RULES_SCHEMA_VERSION as u64) {
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
            const FP_CAP: usize = 32;
            if arr.len() > FP_CAP {
                let drain = arr.len() - FP_CAP;
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
            .map(|(idx, _)| idx)
            .unwrap_or(rest.len());
        let token = &rest[..end];
        let keep = token.len() < 8
            || matches!(
                token,
                "OpenPlatformEncrypt"
                    | "MessageDigest"
                    | "SecretKeySpec"
                    | "EncryptionAesUtils"
                    | "getScanItWhiteList"
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
        let trimmed = rest.trim_start_matches(|c: char| c == ' ' || c == '\t');
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
            let end = rest
                .find(|c: char| c == ',' || c == '}' || c == ' ' || c == '&' || c == '\n')
                .unwrap_or(rest.len());
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
        let end = trimmed
            .find(|c: char| c == '\n' || c == '\r' || c == ' ')
            .unwrap_or(trimmed.len());
        // if space-delimited mid-line, keep remainder after first token
        if end < trimmed.len() && trimmed.as_bytes().get(end) == Some(&b' ') {
            rest = &trimmed[end..];
        } else {
            rest = &trimmed[end..];
        }
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
        let end = rest
            .find(|c: char| c == '&' || c == ' ' || c == '\n' || c == '"' || c == '\'')
            .unwrap_or(rest.len());
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let dig = hasher.finalize();
    dig.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE_SEQ: AtomicU64 = AtomicU64::new(1);

    fn vendor_gm_label() -> &'static str {
        "Infosec4"
    }

    fn tmp_paths() -> (PathBuf, Paths) {
        let seq = FIXTURE_SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("ksight-crypto-watch-test-{seq}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let paths = Paths::under(&dir);
        (dir, paths)
    }

    #[test]
    fn needles_cover_signing_and_cipher_families() {
        let families: BTreeSet<&str> = NEEDLES.iter().map(|n| n.family).collect();
        for required in [
            "sign_header",
            "sign_field",
            "enc_field",
            "platform_api",
            "key_label",
            "cipher",
            "app_marker",
            "jni_registration",
        ] {
            assert!(families.contains(required), "missing family {required}");
        }
        assert!(NEEDLES.iter().any(|n| n.bytes == b"OpenPlatformEncrypt"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"appKey"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"secretKey"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"sign="));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"X-Sign:"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"AES/GCM"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"X-Sign"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"Cipher.getInstance"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"doFinal"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"\"signValue\""));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"InfosecTcp"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"Infosec4"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"Mac.init"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"Mac.getInstance"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"javax.crypto.Mac"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"writeSSLDataNative"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"readSSLDataNative"));
        assert!(NEEDLES
            .iter()
            .any(|n| n.family == "jni_registration" && n.bytes == b"RegisterNatives"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"JNI_OnLoad"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"GetByteArrayRegion"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"SetByteArrayRegion"));
        assert!(NEEDLES
            .iter()
            .any(|n| n.bytes == b"GetPrimitiveArrayCritical"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"Cipher.init"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"SecretKeySpec"));
        assert!(NEEDLES.iter().any(|n| n.bytes == b"\"signature\":"));
    }

    #[test]
    fn needle_bytes_are_nonempty_and_unique() {
        let mut seen = BTreeSet::new();
        for needle in NEEDLES {
            assert!(!needle.bytes.is_empty());
            assert!(
                seen.insert(needle.bytes),
                "duplicate needle {}",
                String::from_utf8_lossy(needle.bytes)
            );
        }
    }

    #[test]
    fn redact_preview_strips_json_and_header_values() {
        let raw = r#"{"sign":"SUPERSECRET","key":"abc123"} X-Sign: deadbeef sign=leakme&ok=1"#;
        let red = redact_preview(raw);
        assert!(!red.contains("SUPERSECRET"), "{red}");
        assert!(!red.contains("abc123"), "{red}");
        assert!(!red.contains("deadbeef"), "{red}");
        assert!(!red.contains("leakme"), "{red}");
        assert!(red.contains("[REDACTED]"), "{red}");
        assert!(red.contains("\"sign\""), "{red}");
        assert!(red.contains("X-Sign:"), "{red}");
        // Mid-window: key label truncated, prior value still present as raw text.
        let mid = r#"CRET_DO_NOT_SHIP","key":"FIXTURE_KEY"} X-Sign: FIXTURE_HDR"#;
        let mid_red = redact_preview(mid);
        assert!(!mid_red.contains("CRET_DO_NOT_SHIP"), "{mid_red}");
        assert!(!mid_red.contains("FIXTURE_KEY"), "{mid_red}");
        assert!(!mid_red.contains("FIXTURE_HDR"), "{mid_red}");
    }

    #[test]
    fn classify_plaintext_preview_finds_openplatform() {
        let hit = classify_plaintext_preview("call OpenPlatformEncrypt(buf) before TLS");
        assert_eq!(hit, Some(("platform_api", "OpenPlatformEncrypt")));
        assert!(classify_plaintext_preview("hello world").is_none());
    }

    #[test]
    fn fixture_scan_emits_durable_event_and_rules() {
        let (dir, paths) = tmp_paths();
        let _cleanup = DirGuard(dir);
        let base = 0x1000_0000u64;
        // 8 KiB heap fixture with cipher-like markers (fake secrets only).
        let mut heap = vec![b'.'; 8192];
        let payload = b"preamble OpenPlatformEncrypt {\"sign\":\"FIXTURE_SECRET_DO_NOT_SHIP\",\"key\":\"FIXTURE_KEY\"} X-Sign: FIXTURE_HDR AES/GCM";
        heap[100..100 + payload.len()].copy_from_slice(payload);
        let maps = format!(
            "{base:x}-{:x} rw-p 00000000 00:00 0  [anon:scudo]",
            base + 8192
        );
        let mut mem = FixtureMem {
            regions: BTreeMap::from([(base, heap)]),
        };
        let pkg = format!(
            "com.example.fixture{}",
            FIXTURE_SEQ.fetch_add(1, Ordering::SeqCst)
        );
        let result = scan_maps(4242, &pkg, &maps, &mut mem, paths.clone());
        assert!(result.added >= 1, "expected hits, got {}", result.added);
        assert!(result.family_hits.contains_key("platform_api"));
        let events = std::fs::read_to_string(&paths.events).expect("events");
        assert!(events.contains("crypto_watch_event/v1"));
        assert!(events.contains("window_sha256"));
        assert!(
            !events.contains("FIXTURE_SECRET_DO_NOT_SHIP"),
            "raw secret leaked into durable events: {events}"
        );
        assert!(
            !events.contains("FIXTURE_KEY"),
            "raw key leaked into durable events: {events}"
        );
        assert!(events.contains("[REDACTED]"));
        let rules: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.rules).unwrap()).unwrap();
        assert_eq!(rules["schema_version"], 1);
        assert!(
            rules["packages"][&pkg]["families"]["platform_api"]
                .as_u64()
                .unwrap()
                >= 1
        );
        let detail = observation_detail(&result);
        assert!(detail.contains("crypto_watch hits="));
        assert!(detail.contains("fingerprints="));
    }

    #[test]
    fn observation_detail_lists_families_sorted() {
        let mut result = CryptoWatchScanResult::default();
        result.added = 2;
        result.family_hits.insert("cipher", 1);
        result.family_hits.insert("sign_header", 1);
        result.findings.push(CryptoWatchFinding {
            pid: 1,
            package: "p".into(),
            family: "cipher",
            needle: "AES/GCM".into(),
            va: 0,
            window_sha256: "abcd".repeat(8),
            preview_redacted: "x".into(),
            unix_ms: 0,
        });
        let d = observation_detail(&result);
        assert!(d.contains("cipher=1"));
        assert!(d.contains("sign_header=1"));
    }

    #[test]
    fn classify_plaintext_bytes_matches_preview() {
        let raw = br#"before doFinal({"signValue":"AAAA"}) InfosecTcp"#;
        let hit = classify_plaintext_bytes(raw).expect("hit");
        assert!(
            hit == ("platform_api", "doFinal")
                || hit == ("sign_field", "\"signValue\"")
                || hit == ("platform_api", "InfosecTcp"),
            "unexpected {hit:?}"
        );
        assert_eq!(
            classify_plaintext_preview(std::str::from_utf8(raw).unwrap()),
            classify_plaintext_bytes(raw)
        );
    }

    #[test]
    fn ingest_inspect_plaintext_feeds_versioned_rules() {
        let (dir, paths) = tmp_paths();
        let _cleanup = DirGuard(dir);
        let pkg = format!(
            "com.example.app.fixture{}",
            FIXTURE_SEQ.fetch_add(1, Ordering::SeqCst)
        );
        // Preview avoids earlier NEEDLES (e.g. "sign":) so classify hits OpenPlatformEncrypt.
        let preview =
            r#"JNI byte[] call OpenPlatformEncrypt(buf) keyLabel=FIXTURE_SECRET_DO_NOT_SHIP"#;
        let sha = "ab".repeat(32);
        let hit =
            ingest_inspect_plaintext(&pkg, "jni_GetByteArrayRegion", preview, Some(&sha), &paths)
                .expect("ingest hit");
        assert_eq!(hit.family, "platform_api");
        assert_eq!(hit.needle, "OpenPlatformEncrypt");
        assert_eq!(hit.source, "inspect_jni");
        assert_eq!(
            hit.path_hint,
            "crypto_pre_encrypt:platform_api:OpenPlatformEncrypt"
        );
        assert!(!hit.preview_redacted.contains("FIXTURE_SECRET_DO_NOT_SHIP"));
        assert!(hit.detail.contains("crypto_watch_ingest"));
        assert!(hit.detail.contains(&sha));

        let events = std::fs::read_to_string(&paths.events).expect("events");
        assert!(events.contains("crypto_watch_event/v1"));
        assert!(events.contains("\"source\":\"inspect_jni\""));
        assert!(events.contains("jni_GetByteArrayRegion"));
        assert!(!events.contains("FIXTURE_SECRET_DO_NOT_SHIP"));

        let rules: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.rules).unwrap()).unwrap();
        assert_eq!(rules["schema_version"], 1);
        assert!(
            rules["packages"][&pkg]["families"]["platform_api"]
                .as_u64()
                .unwrap()
                >= 1
        );
        assert_eq!(
            rules["packages"][&pkg]["sources"]["inspect_jni"]
                .as_u64()
                .unwrap(),
            1
        );
        assert!(
            rules["packages"][&pkg]["needles"]["OpenPlatformEncrypt"]
                .as_u64()
                .unwrap()
                >= 1
        );
        let fps = rules["packages"][&pkg]["fingerprints"].as_array().unwrap();
        assert!(fps.iter().any(|v| v.as_str() == Some(sha.as_str())));

        // Non-JNI adapter → inspect_plaintext source
        let hit2 = ingest_inspect_plaintext(
            &pkg,
            "tls_ssl_write",
            "header X-Sign: FIXTURE_HDR AES/GCM",
            None,
            &paths,
        )
        .expect("tls-side classify still useful for correlation");
        assert_eq!(hit2.source, "inspect_plaintext");
        assert!(hit2.family == "sign_header" || hit2.family == "cipher");

        assert!(ingest_inspect_plaintext(&pkg, "jni_plaintext", "hello", None, &paths).is_none());
    }

    #[test]
    fn source_for_adapter_labels_jni_and_vendor() {
        assert_eq!(source_for_adapter("jni_plaintext"), "inspect_jni");
        assert_eq!(source_for_adapter("jni_GetByteArrayRegion"), "inspect_jni");
        assert_eq!(
            source_for_adapter("vendor_boundary:Java_InfosecTcp_writeSSLDataNative"),
            "inspect_vendor"
        );
        assert_eq!(source_for_adapter("tls_ssl_write"), "inspect_plaintext");
        assert_eq!(
            path_hint_for("sign_field", "sign="),
            "crypto_pre_encrypt:sign_field:sign="
        );
    }

    #[test]
    fn redact_preview_strips_sign_value_and_sign_data() {
        // Values must never land in durable events. Key labels may be partially
        // rewritten when a shorter key (e.g. "sign") is a prefix of "signValue".
        let raw = r#"{"signValue":"BANK_SIGN_SECRET_FIXTURE","signData":"BANK_DATA_SECRET_FIXTURE","ok":1}"#;
        let red = redact_preview(raw);
        assert!(!red.contains("BANK_SIGN_SECRET_FIXTURE"), "{red}");
        assert!(!red.contains("BANK_DATA_SECRET_FIXTURE"), "{red}");
        assert!(red.contains("[REDACTED]"), "{red}");
        assert!(red.contains("\"ok\""), "{red}");
        // Classify still sees the keys on the *raw* preview (needle presence).
        let hit = classify_plaintext_preview(raw).expect("sign field");
        assert_eq!(hit.0, "sign_field");
        assert!(
            hit.1 == "\"signValue\"" || hit.1 == "\"signData\"",
            "{hit:?}"
        );
        // Ingest path must keep secrets out of events while still labeling source.
        let (dir, paths) = tmp_paths();
        let _cleanup = DirGuard(dir);
        let pkg = format!(
            "com.example.app.sign{}",
            FIXTURE_SEQ.fetch_add(1, Ordering::SeqCst)
        );
        let hit = ingest_inspect_plaintext(&pkg, "jni_plaintext", raw, None, &paths)
            .expect("ingest sign field");
        assert_eq!(hit.source, "inspect_jni");
        assert!(!hit.preview_redacted.contains("BANK_SIGN_SECRET_FIXTURE"));
        assert!(!hit.preview_redacted.contains("BANK_DATA_SECRET_FIXTURE"));
        let events = std::fs::read_to_string(&paths.events).unwrap();
        assert!(!events.contains("BANK_SIGN_SECRET_FIXTURE"));
        assert!(!events.contains("BANK_DATA_SECRET_FIXTURE"));
        assert!(events.contains("\"source\":\"inspect_jni\""));
    }

    #[test]
    fn source_for_adapter_inspect_jni_labeling() {
        // JNI corridor → inspect_jni (opt-in --inspect-jni only at attach time).
        for adapter in [
            "jni_plaintext",
            "jni_GetByteArrayRegion",
            "jni_NewStringUTF",
            "jni_GetStringUTFChars",
            "art::JNIEnvExt::GetByteArrayRegion",
        ] {
            assert_eq!(source_for_adapter(adapter), "inspect_jni", "{adapter}");
            assert!(adapter_is_jni(adapter), "{adapter}");
        }
        assert!(!adapter_is_jni("tls_ssl_write"));
        assert!(!adapter_is_jni("vendor_boundary:InfosecTcp"));
        assert_eq!(
            source_for_adapter("vendor_boundary:Java_InfosecTcp_writeSSLDataNative"),
            "inspect_vendor"
        );
    }

    #[test]
    fn merge_versioned_rules_ex_additive_sources() {
        let (dir, paths) = tmp_paths();
        let _cleanup = DirGuard(dir);
        let pkg = format!(
            "com.bank.additive{}",
            FIXTURE_SEQ.fetch_add(1, Ordering::SeqCst)
        );
        let mut fam = BTreeMap::new();
        fam.insert("platform_api", 2usize);
        merge_versioned_rules_ex(
            &paths.rules,
            &pkg,
            &fam,
            "heap_scan",
            "doFinal",
            &"aa".repeat(32),
        );
        fam.clear();
        fam.insert("sign_field", 1usize);
        merge_versioned_rules_ex(
            &paths.rules,
            &pkg,
            &fam,
            "inspect_jni",
            "\"signValue\"",
            &"bb".repeat(32),
        );
        fam.clear();
        fam.insert("platform_api", 1usize);
        merge_versioned_rules_ex(
            &paths.rules,
            &pkg,
            &fam,
            "inspect_vendor",
            "InfosecTcp",
            &"cc".repeat(32),
        );
        // Second heap_scan bump must accumulate, not replace.
        fam.clear();
        fam.insert("cipher", 1usize);
        merge_versioned_rules_ex(&paths.rules, &pkg, &fam, "heap_scan", "AES/GCM", "");

        let rules: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.rules).unwrap()).unwrap();
        assert_eq!(rules["schema_version"], 1);
        let pkg_rules = &rules["packages"][&pkg];
        assert_eq!(pkg_rules["sources"]["heap_scan"].as_u64().unwrap(), 2);
        assert_eq!(pkg_rules["sources"]["inspect_jni"].as_u64().unwrap(), 1);
        assert_eq!(pkg_rules["sources"]["inspect_vendor"].as_u64().unwrap(), 1);
        assert_eq!(pkg_rules["families"]["platform_api"].as_u64().unwrap(), 3);
        assert_eq!(pkg_rules["families"]["sign_field"].as_u64().unwrap(), 1);
        assert_eq!(pkg_rules["families"]["cipher"].as_u64().unwrap(), 1);
        assert!(
            pkg_rules["needles"]["doFinal"].as_u64().unwrap() >= 1
                && pkg_rules["needles"]["\"signValue\""].as_u64().unwrap() >= 1
                && pkg_rules["needles"]["InfosecTcp"].as_u64().unwrap() >= 1
        );
        let fps = pkg_rules["fingerprints"].as_array().unwrap();
        assert!(fps.iter().any(|v| v.as_str() == Some(&"aa".repeat(32))));
        assert!(fps.iter().any(|v| v.as_str() == Some(&"bb".repeat(32))));
        assert!(fps.iter().any(|v| v.as_str() == Some(&"cc".repeat(32))));
        // Empty fingerprint must not push a blank entry.
        assert!(!fps.iter().any(|v| v.as_str() == Some("")));
    }

    #[test]
    fn classify_and_ingest_platform_api_path_hint() {
        let (dir, paths) = tmp_paths();
        let _cleanup = DirGuard(dir);
        let hit = classify_plaintext_preview(&format!(
            "JNI RegisterNatives {} before writeSSLDataNative",
            vendor_gm_label()
        ));
        assert_eq!(hit, Some(("platform_api", vendor_gm_label())));
        let pkg = format!(
            "com.example.app.fixture{}",
            FIXTURE_SEQ.fetch_add(1, Ordering::SeqCst)
        );
        let ingest = ingest_inspect_plaintext(
            &pkg,
            "jni_GetByteArrayRegion",
            &format!("corridor Mac.init then {} seal", vendor_gm_label()),
            Some(&"dd".repeat(32)),
            &paths,
        )
        .expect("ingest");
        assert_eq!(ingest.source, "inspect_jni");
        assert_eq!(ingest.family, "platform_api");
        assert_eq!(ingest.needle, vendor_gm_label());
        assert_eq!(
            ingest.path_hint,
            format!("crypto_pre_encrypt:platform_api:{}", vendor_gm_label())
        );
        assert!(!ingest.detail.contains("secret"));
        let rules: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.rules).unwrap()).unwrap();
        assert_eq!(rules["schema_version"], 1);
        assert_eq!(
            rules["packages"][&pkg]["sources"]["inspect_jni"]
                .as_u64()
                .unwrap(),
            1
        );
        assert!(
            rules["packages"][&pkg]["needles"][vendor_gm_label()]
                .as_u64()
                .unwrap()
                >= 1
        );
    }

    #[test]
    fn redact_preview_keeps_new_platform_api_labels() {
        let raw = format!(
            "call {} via writeSSLDataNative + javax.crypto.Mac.init",
            vendor_gm_label()
        );
        let red = redact_preview(&raw);
        assert!(red.contains(vendor_gm_label()), "{red}");
        assert!(red.contains("writeSSLDataNative"), "{red}");
        assert!(red.contains("javax.crypto.Mac"), "{red}");
    }

    /// Plaintext-before-encrypt corridor: JNI preview → versioned rules with
    /// `crypto_pre_encrypt:*` path_hint only (no offsets; Burp gets fingerprint).
    #[test]
    fn plaintext_before_encrypt_versioned_rule_path_hint() {
        let (dir, paths) = tmp_paths();
        let _cleanup = DirGuard(dir);
        let pkg = format!(
            "com.example.app.preencrypt{}",
            FIXTURE_SEQ.fetch_add(1, Ordering::SeqCst)
        );
        // Prefer SecretKeySpec / readSSLDataNative over earlier NEEDLES in the
        // same window by using a preview that hits readSSLDataNative first only
        // after OpenPlatformEncrypt is intentionally omitted.
        let preview = "JNI GetByteArrayRegion before TLS: SecretKeySpec then readSSLDataNative";
        let sha = "ee".repeat(32);
        let hit =
            ingest_inspect_plaintext(&pkg, "jni_GetByteArrayRegion", preview, Some(&sha), &paths)
                .expect("pre-encrypt ingest");
        assert_eq!(hit.source, "inspect_jni");
        assert_eq!(hit.family, "platform_api");
        assert!(
            hit.needle == "SecretKeySpec" || hit.needle == "readSSLDataNative",
            "unexpected needle {}",
            hit.needle
        );
        assert!(hit
            .path_hint
            .starts_with("crypto_pre_encrypt:platform_api:"));
        assert_eq!(hit.path_hint, path_hint_for(hit.family, &hit.needle));
        let rules: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.rules).unwrap()).unwrap();
        assert_eq!(rules["schema_version"], 1);
        assert_eq!(
            rules["packages"][&pkg]["sources"]["inspect_jni"]
                .as_u64()
                .unwrap(),
            1
        );
        assert!(
            rules["packages"][&pkg]["needles"][&hit.needle]
                .as_u64()
                .unwrap()
                >= 1
        );
        let fps = rules["packages"][&pkg]["fingerprints"].as_array().unwrap();
        assert!(fps.iter().any(|v| v.as_str() == Some(sha.as_str())));
        // Labels survive redaction; no invented offsets in path_hint.
        let red = redact_preview(preview);
        assert!(red.contains("SecretKeySpec"), "{red}");
        assert!(red.contains("readSSLDataNative"), "{red}");
        assert!(!hit.path_hint.contains("0x"));
    }

    #[test]
    fn jni_bytearray_cipher_init_corridor_feeds_versioned_rules() {
        let (dir, paths) = tmp_paths();
        let _cleanup = DirGuard(dir);
        let pkg = format!(
            "com.example.app.jni_ba{}",
            FIXTURE_SEQ.fetch_add(1, Ordering::SeqCst)
        );
        let preview_ba = "JNIEnv GetByteArrayRegion plaintext buffer ahead of AES seal";
        let hit_ba =
            ingest_inspect_plaintext(&pkg, "jni_GetByteArrayRegion", preview_ba, None, &paths)
                .expect("bytearray corridor");
        assert_eq!(hit_ba.source, "inspect_jni");
        assert_eq!(hit_ba.family, "jni_registration");
        assert_eq!(hit_ba.needle, "GetByteArrayRegion");
        assert_eq!(
            hit_ba.path_hint,
            "crypto_pre_encrypt:jni_registration:GetByteArrayRegion"
        );
        assert!(!hit_ba.path_hint.contains("0x"));
        let red = redact_preview(preview_ba);
        assert!(red.contains("GetByteArrayRegion"), "{red}");

        let pkg2 = format!(
            "com.example.app.cipher_init{}",
            FIXTURE_SEQ.fetch_add(1, Ordering::SeqCst)
        );
        let preview_ci = "Java Cipher.init(key, IvParameterSpec) before header seal";
        let hit_ci = ingest_inspect_plaintext(&pkg2, "jni_plaintext", preview_ci, None, &paths)
            .expect("Cipher.init corridor");
        assert_eq!(hit_ci.source, "inspect_jni");
        assert_eq!(hit_ci.family, "platform_api");
        assert_eq!(hit_ci.needle, "Cipher.init");
        assert!(hit_ci
            .path_hint
            .starts_with("crypto_pre_encrypt:platform_api:"));
        let rules: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.rules).unwrap()).unwrap();
        assert_eq!(
            rules["packages"][&pkg]["sources"]["inspect_jni"]
                .as_u64()
                .unwrap(),
            1
        );
        assert_eq!(
            rules["packages"][&pkg2]["needles"]["Cipher.init"]
                .as_u64()
                .unwrap(),
            1
        );
    }

    #[test]
    fn register_natives_jni_corridor_feeds_versioned_rules() {
        let (dir, paths) = tmp_paths();
        let _cleanup = DirGuard(dir);
        let pkg = format!(
            "com.example.app.jni_reg{}",
            FIXTURE_SEQ.fetch_add(1, Ordering::SeqCst)
        );
        let preview = "ART JNI RegisterNatives OpenPlatformEncrypt before Cipher.doFinal";
        let hit = ingest_inspect_plaintext(&pkg, "jni_RegisterNatives", preview, None, &paths)
            .expect("jni registration corridor");
        assert_eq!(hit.source, "inspect_jni");
        assert!(
            hit.family == "jni_registration" || hit.family == "platform_api",
            "family {}",
            hit.family
        );
        assert!(hit.path_hint.starts_with("crypto_pre_encrypt:"));
        assert!(!hit.path_hint.contains("0x"));
        let rules: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&paths.rules).unwrap()).unwrap();
        assert_eq!(
            rules["packages"][&pkg]["sources"]["inspect_jni"]
                .as_u64()
                .unwrap(),
            1
        );
    }

    struct DirGuard(PathBuf);
    impl Drop for DirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
