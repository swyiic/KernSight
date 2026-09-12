//! Data-driven TLS-stack recognition rules: one file describing every known
//! stack (generic / vendor-fork / framework), its symbols, keylog anchors and
//! offsets, JNI boundary functions, and per-device capability quirks.
//!
//! The table ships embedded (so the agent works standalone) and can be
//! overridden on-device at `/data/local/tmp/ksight/tls_stacks.json` without a
//! rebuild. Everything learned about a target app family lands here instead of
//! scattering across code paths.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::tls_abi::{CapturePhase, TlsAbiKind, TlsDirection};

pub const DEVICE_TABLE_PATH: &str = "/data/local/tmp/ksight/tls_stacks.json";
pub const SCHEMA_VERSION: &str = "1.3";

/// Root of the rules document.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StackRulesFile {
    #[serde(default)]
    pub schema_version: String,
    /// SHA-256 of the stacks array (hex). Used to detect stale on-device copies.
    #[serde(default)]
    pub content_hash: String,
    /// Agent version that last wrote this file.
    #[serde(default)]
    pub agent_version: String,
    /// Per-device/kernel capability quirks.
    #[serde(default)]
    pub device_profiles: HashMap<String, DeviceProfile>,
    #[serde(default)]
    pub stacks: Vec<StackRule>,
}

/// Kernel/device-level facts that change what the probes can do.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceProfile {
    #[serde(default)]
    pub kernel: String,
    #[serde(default)]
    pub sdk: u32,
    /// Capability flags such as `aarch32_uprobe`, `kallsyms_ksu_visible`,
    /// `tcpdump_sll2`, `bpf_loop`.
    #[serde(default)]
    pub capabilities: HashMap<String, bool>,
    #[serde(default)]
    pub notes: String,
}

/// How a library is recognized on disk / in maps.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatchRules {
    #[serde(default)]
    pub basename: Option<String>,
    #[serde(default)]
    pub basename_contains: Vec<String>,
    #[serde(default)]
    pub path_contains: Vec<String>,
    /// Exact file size, for vendor ELFs without a build-id.
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub build_id: Option<String>,
    /// `arm64` / `arm` when the pin is architecture-specific.
    #[serde(default)]
    pub architecture: Option<String>,
}

impl MatchRules {
    /// Whether a mapped path satisfies this rule set. `actual_build_id` comes
    /// from the caller's ELF inspection (agent side); `None` fails a build-id
    /// rule.
    #[must_use]
    pub fn matches(
        &self,
        path: &str,
        file_size: Option<u64>,
        actual_build_id: Option<&str>,
    ) -> bool {
        let lower = path.to_ascii_lowercase();
        let basename = std::path::Path::new(&lower)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if let Some(wanted) = &self.basename {
            if basename != wanted.to_ascii_lowercase() {
                return false;
            }
        }
        if self
            .basename_contains
            .iter()
            .all(|needle| !basename.contains(&needle.to_ascii_lowercase()))
            && !self.basename_contains.is_empty()
        {
            return false;
        }
        for needle in &self.path_contains {
            if !lower.contains(&needle.to_ascii_lowercase()) {
                return false;
            }
        }
        if let Some(wanted) = self.build_id.as_deref() {
            if actual_build_id != Some(wanted) {
                return false;
            }
        }
        if let Some(wanted) = self.size {
            match file_size {
                Some(actual) if actual == wanted => {}
                _ => return false,
            }
        }
        if let Some(wanted) = self.architecture.as_deref() {
            if !path_matches_architecture(path, wanted) {
                return false;
            }
        }
        true
    }

    /// Rank matching rules so an exact build-specific rule always wins over
    /// a generic basename fallback, regardless of JSON declaration order.
    ///
    /// Order: build-id+arch → build-id → size+basename+arch → exact export
    /// (attach time) → generic basename → classify-only.
    #[must_use]
    pub fn specificity(&self) -> u32 {
        let bid = self.build_id.is_some();
        let arch = self.architecture.is_some();
        let size = self.size.is_some();
        let base = self.basename.is_some() || !self.basename_contains.is_empty();
        let mut score = 0_u32;
        if bid && arch {
            score = 10_000;
        } else if bid {
            score = 1_000;
        } else if size && base && arch {
            score = 400;
        } else if size {
            score = 200;
        }
        score
            .saturating_add(u32::from(self.basename.is_some()).saturating_mul(100))
            .saturating_add(
                u32::try_from(self.path_contains.len())
                    .unwrap_or(u32::MAX)
                    .saturating_mul(20),
            )
            .saturating_add(
                u32::try_from(self.basename_contains.len())
                    .unwrap_or(u32::MAX)
                    .saturating_mul(10),
            )
    }

    fn is_empty(&self) -> bool {
        self.basename.is_none()
            && self.basename_contains.is_empty()
            && self.path_contains.is_empty()
            && self.size.is_none()
            && self.build_id.is_none()
            && self.architecture.is_none()
    }
}

fn path_matches_architecture(path: &str, architecture: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    match architecture.to_ascii_lowercase().as_str() {
        "arm64" | "aarch64" => {
            lower.contains("arm64") || lower.contains("/lib64/") || lower.contains("lib64/")
        }
        "arm" | "arm32" | "aarch32" => {
            (lower.contains("/lib/") || lower.contains("armeabi") || lower.contains("/arm/"))
                && !lower.contains("arm64")
                && !lower.contains("/lib64/")
        }
        other => lower.contains(other),
    }
}

/// Exported-symbol sets the sweeps and probes should target.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SymbolSets {
    #[serde(default)]
    pub write: Vec<String>,
    #[serde(default)]
    pub read: Vec<String>,
    /// Functions that receive keylog material (label, secret) in registers.
    #[serde(default)]
    pub keylog: Vec<String>,
}

/// One exported-symbol attach description. When omitted, the runtime
/// synthesizes this from `symbols.write` / `symbols.read` via [`TlsAbiKind::from_exported_symbol`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProbeSpec {
    #[serde(default)]
    pub symbol: String,
    #[serde(default)]
    pub file_offset: Option<u64>,
    #[serde(default)]
    pub direction: Option<TlsDirection>,
    #[serde(default)]
    pub abi: Option<TlsAbiKind>,
    #[serde(default)]
    pub capture_phase: Option<CapturePhase>,
    #[serde(default)]
    pub buffer_arg: Option<u8>,
    #[serde(default)]
    pub requested_length_arg: Option<u8>,
    #[serde(default)]
    pub actual_length_source: Option<String>,
    #[serde(default)]
    pub connection_arg: Option<u8>,
    #[serde(default)]
    pub build_id: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub architecture: Option<String>,
    /// `enabled` | `experimental` | `disabled`. Numeric offsets without
    /// build-id/size must not be `enabled`.
    #[serde(default)]
    pub validation_state: String,
}

/// Local / stripped plaintext boundary (not an exported SSL_* name, not keylog).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlaintextProbe {
    #[serde(default)]
    pub build_id: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub file_offset: Option<u64>,
    #[serde(default)]
    pub direction: TlsDirection,
    #[serde(default)]
    pub abi: TlsAbiKind,
    #[serde(default)]
    pub capture_phase: Option<CapturePhase>,
    #[serde(default)]
    pub buffer_arg: Option<u8>,
    #[serde(default)]
    pub requested_length_arg: Option<u8>,
    #[serde(default)]
    pub actual_length_source: Option<String>,
    #[serde(default)]
    pub max_bytes: Option<u32>,
    #[serde(default)]
    pub verified_at: Option<String>,
    #[serde(default)]
    pub sample_sha256: Option<String>,
    /// `enabled` | `experimental` | `disabled`. Default disabled.
    #[serde(default)]
    pub validation_state: String,
}

/// Per-function vendor JNI/TLS boundary. Shared layout on a stack is not assumed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BoundaryFunction {
    #[serde(default)]
    pub symbol: String,
    #[serde(default)]
    pub direction: Option<TlsDirection>,
    #[serde(default)]
    pub abi: Option<TlsAbiKind>,
    #[serde(default)]
    pub capture_phase: Option<CapturePhase>,
    #[serde(default)]
    pub return_semantics: Option<String>,
    #[serde(default)]
    pub buffer_arg: Option<u8>,
    #[serde(default)]
    pub length_arg: Option<u8>,
    #[serde(default)]
    pub output_length_arg: Option<u8>,
    #[serde(default)]
    pub connection_arg: Option<u8>,
    #[serde(default)]
    pub stream_arg: Option<u8>,
    #[serde(default)]
    pub is_header: Option<bool>,
    #[serde(default)]
    pub is_body: Option<bool>,
    /// `empirical` | `pinned`.
    #[serde(default)]
    pub layout: String,
    #[serde(default)]
    pub confidence: Option<String>,
    #[serde(default)]
    pub build_id: Option<String>,
    #[serde(default)]
    pub max_bytes: Option<u32>,
    /// `enabled` | `experimental` | `disabled`.
    #[serde(default)]
    pub validation_state: String,
}

/// JNI-boundary functions of a vendor stack (B-route targets).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BoundaryRules {
    #[serde(default)]
    pub write: Vec<String>,
    #[serde(default)]
    pub read: Vec<String>,
    /// Per-function rows. When empty, `write`/`read` plus the shared layout apply.
    #[serde(default)]
    pub functions: Vec<BoundaryFunction>,
    /// `empirical` while the register layout is unknown, `pinned` when decoded.
    #[serde(default)]
    pub layout: String,
    /// ARM64 register containing the plaintext pointer (x0..x7).
    #[serde(default)]
    pub buffer_arg: Option<u8>,
    /// ARM64 register containing the plaintext byte length.
    #[serde(default)]
    pub length_arg: Option<u8>,
    /// Optional register containing a stable connection/session pointer.
    #[serde(default)]
    pub connection_arg: Option<u8>,
    /// Per-hit read ceiling; the capture policy applies an additional ceiling.
    #[serde(default)]
    pub max_bytes: Option<u32>,
}

/// Keylog probe definition for one stack build.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeylogRule {
    /// Function offset to probe (`ssl_log_secret`-equivalent entry). Absent
    /// when only anchors are known (runtime writer not yet pinned).
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub build_id: Option<String>,
    #[serde(default)]
    pub lib_name: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    /// Offset of the 32-byte client random within the SSL struct; absent means
    /// the probe emits debug-form lines and the decryptor trial-matches.
    #[serde(default)]
    pub client_random_offset: Option<u64>,
    #[serde(default)]
    pub anchors: Vec<String>,
    #[serde(default)]
    pub note: String,
}

/// What this stack yields today.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageFlags {
    #[serde(default)]
    pub plaintext_copy: bool,
    /// `None` means "pending" (stack recognized, capability not decided).
    #[serde(default)]
    pub keylog: Option<bool>,
    #[serde(default)]
    pub boundary_dump: bool,
}

/// Upgrade-tracking metadata for one stack row (pins, gaps, and stable export attach).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StackVersion {
    /// `stable` | `pinned` | `gap` | `rolling`
    #[serde(default)]
    pub kind: String,
    /// Human product/engine label e.g. "Flutter 3.24.5", "OpenSSL 3.x", "Pixel6a apex Cronet"
    #[serde(default)]
    pub product: String,
    /// Engine/openssl/cronet/flutter version string when known
    #[serde(default)]
    pub engine_version: Option<String>,
    /// Android API / apex when relevant
    #[serde(default)]
    pub api_level: Option<u32>,
    /// Canonical build-id (may mirror match_rules)
    #[serde(default)]
    pub build_id: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    /// ISO date last verified on device/disk
    #[serde(default)]
    pub verified_at: Option<String>,
    /// What breaks on upgrade / how to re-pin
    #[serde(default)]
    pub upgrade_note: String,
}

/// One recognized stack.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StackRule {
    pub id: String,
    /// `generic` | `vendor-fork` | `framework` | `framework-vendor`.
    #[serde(default)]
    pub class: String,
    /// Attach priority; lower attaches first.
    #[serde(default)]
    pub tier: u32,
    #[serde(default)]
    pub match_rules: MatchRules,
    #[serde(default)]
    pub symbols: SymbolSets,
    /// Per-symbol attach specs. Empty → synthesized from `symbols.write`/`read`.
    #[serde(default)]
    pub probes: Vec<ProbeSpec>,
    /// Local/stripped plaintext boundaries. Never reuse `keylog.offset`.
    #[serde(default)]
    pub plaintext_probes: Vec<PlaintextProbe>,
    #[serde(default)]
    pub boundary: Option<BoundaryRules>,
    #[serde(default)]
    pub keylog: Option<KeylogRule>,
    #[serde(default)]
    pub coverage: CoverageFlags,
    /// Optional upgrade-tracking version tag (empty default keeps old JSON loadable).
    #[serde(default)]
    pub version: StackVersion,
    #[serde(default)]
    pub notes: String,
    /// `embedded` | `local`. Local rows survive an embedded-rules refresh.
    #[serde(default)]
    pub source: String,
}

impl StackRule {
    /// Whether a mapped path satisfies this stack's match rules.
    #[must_use]
    pub fn matches(
        &self,
        path: &str,
        file_size: Option<u64>,
        actual_build_id: Option<&str>,
    ) -> bool {
        self.match_rules.matches(path, file_size, actual_build_id)
    }
}

/// The embedded knowledge base (mirrors the on-device JSON).
pub const EMBEDDED_RULES: &str = include_str!("stack_rules_default.json");

static LOADED: OnceLock<StackRulesFile> = OnceLock::new();

/// Load the rules: on-device file wins, otherwise the embedded defaults.
#[must_use]
pub fn load() -> &'static StackRulesFile {
    LOADED.get_or_init(|| {
        if let Ok(text) = std::fs::read_to_string(DEVICE_TABLE_PATH) {
            if let Ok(parsed) = serde_json::from_str::<StackRulesFile>(&text) {
                let issues = validation_issues(&parsed);
                if issues.is_empty() {
                    return parsed;
                }
                eprintln!(
                    "ignoring invalid TLS stack override {}: {}",
                    DEVICE_TABLE_PATH,
                    issues.join("; ")
                );
            }
        }
        let embedded = serde_json::from_str::<StackRulesFile>(EMBEDDED_RULES).unwrap_or_default();
        for issue in validation_issues(&embedded) {
            eprintln!("embedded TLS stack rule issue: {issue}");
        }
        embedded
    })
}

/// The stack rule matching a mapped path, if any. `actual_build_id` comes
/// from the caller's ELF inspection when available.
#[must_use]
pub fn stack_for_path(
    path: &str,
    file_size: Option<u64>,
    actual_build_id: Option<&str>,
) -> Option<&'static StackRule> {
    matching_stacks(path, file_size, actual_build_id)
        .into_iter()
        .next()
}

/// Every matching stack in deterministic precedence order. Exact build/file
/// rules win, then lower attach tier, then id. Callers can retain the complete
/// candidate list for coverage diagnostics instead of losing it to first-match.
#[must_use]
pub fn matching_stacks(
    path: &str,
    file_size: Option<u64>,
    actual_build_id: Option<&str>,
) -> Vec<&'static StackRule> {
    let mut matches = load()
        .stacks
        .iter()
        .filter(|stack| stack.matches(path, file_size, actual_build_id))
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| {
        right
            .match_rules
            .specificity()
            .cmp(&left.match_rules.specificity())
            .then_with(|| left.tier.cmp(&right.tier))
            .then_with(|| left.id.cmp(&right.id))
    });
    matches
}

/// Validate an override before operators rely on it. Invalid entries remain
/// visible as diagnostics; they must never silently broaden to every ELF.
#[must_use]
pub fn validation_issues(rules: &StackRulesFile) -> Vec<String> {
    let mut issues = Vec::new();
    if rules.schema_version.trim().is_empty() {
        issues.push("stack rules schema_version is empty".to_owned());
    } else if !rules.schema_version.starts_with("1.") {
        issues.push(format!(
            "unsupported stack rules schema_version={}",
            rules.schema_version
        ));
    }
    let mut ids = std::collections::HashSet::new();
    for stack in &rules.stacks {
        if stack.id.trim().is_empty() {
            issues.push("stack rule has an empty id".to_owned());
        } else if !ids.insert(stack.id.as_str()) {
            issues.push(format!("duplicate stack rule id={}", stack.id));
        }
        if stack.match_rules.is_empty() {
            issues.push(format!(
                "stack rule id={} has no match constraints",
                stack.id
            ));
        }
        if let Some(keylog) = &stack.keylog {
            if keylog.offset.is_some()
                && keylog.build_id.is_none()
                && keylog.lib_name.is_none()
                && stack.match_rules.build_id.is_none()
                && stack.match_rules.size.is_none()
            {
                issues.push(format!(
                    "stack rule id={} has an unpinned keylog offset",
                    stack.id
                ));
            }
        }
        for probe in &stack.plaintext_probes {
            if probe.file_offset.is_some()
                && probe.build_id.is_none()
                && probe.size.is_none()
                && stack.match_rules.build_id.is_none()
                && stack.match_rules.size.is_none()
                && probe.validation_state.eq_ignore_ascii_case("enabled")
            {
                issues.push(format!(
                    "stack rule id={} plaintext_probe offset without build-id/size cannot be enabled",
                    stack.id
                ));
            }
        }
    }
    issues
}

fn probe_name_attachable(probe: &ProbeSpec) -> bool {
    if probe.symbol.is_empty() {
        return false;
    }
    matches!(
        probe.validation_state.to_ascii_lowercase().as_str(),
        "enabled" | "experimental"
    )
}

/// Union of exported write/read symbol names across all stacks.
///
/// Disabled probes are skipped. `BIO_*` and `SSL_quic_*_level` never enter
/// this list even if a row names them — those are not TLS application-data copies.
#[must_use]
pub fn tls_symbol_names() -> Vec<String> {
    let mut out = Vec::new();
    for stack in &load().stacks {
        out.extend(
            stack
                .symbols
                .write
                .iter()
                .chain(stack.symbols.read.iter())
                .filter(|name| crate::tls_abi::is_tls_application_data_export(name))
                .cloned(),
        );
        out.extend(
            stack
                .probes
                .iter()
                .filter(|probe| probe_name_attachable(probe))
                .map(|probe| probe.symbol.clone())
                .filter(|name| crate::tls_abi::is_tls_application_data_export(name)),
        );
    }
    out.sort();
    out.dedup();
    out
}

/// Plaintext probes that may attach (enabled + pinned by build-id or size).
#[must_use]
pub fn enabled_plaintext_probes() -> Vec<(String, PlaintextProbe)> {
    let mut out = Vec::new();
    for stack in &load().stacks {
        for probe in &stack.plaintext_probes {
            if !probe.validation_state.eq_ignore_ascii_case("enabled") {
                continue;
            }
            let pinned = probe.build_id.is_some()
                || probe.size.is_some()
                || stack.match_rules.build_id.is_some()
                || stack.match_rules.size.is_some();
            if !pinned || probe.file_offset.is_none() {
                continue;
            }
            out.push((stack.id.clone(), probe.clone()));
        }
    }
    out
}

/// ProbeSpec rows for the concrete ELF matched by path/size/build-id.
///
/// Returns attachable (`enabled` / `experimental`) probes from the winning
/// stack (and any equally specific co-matches). Callers build InspectPlans
/// from these rows — file_offset / abi / buffer_arg / capture_phase are the
/// source of truth over Rust fixed-name arrays + name→ABI re-inference.
#[must_use]
pub fn probe_specs_for_path(
    path: &str,
    file_size: Option<u64>,
    actual_build_id: Option<&str>,
) -> Vec<(String, ProbeSpec)> {
    let matches = matching_stacks(path, file_size, actual_build_id);
    let Some(best) = matches.first() else {
        return Vec::new();
    };
    let best_score = best.match_rules.specificity();
    let mut out = Vec::new();
    // Winning stack + equally specific co-matches only (not generic basename
    // fallbacks), so pinned ProbeSpecs do not double-attach with a broader twin.
    for stack in matches
        .into_iter()
        .filter(|stack| stack.match_rules.specificity() == best_score)
    {
        for probe in &stack.probes {
            if !probe_name_attachable(probe) {
                continue;
            }
            if let Some(wanted) = probe.build_id.as_deref() {
                if actual_build_id != Some(wanted) {
                    continue;
                }
            }
            if let Some(wanted) = probe.size {
                if file_size != Some(wanted) {
                    continue;
                }
            }
            out.push((stack.id.clone(), probe.clone()));
        }
    }
    out
}

/// Flattened per-function vendor boundary rows (explicit `functions` plus
/// legacy write/read name lists).
#[must_use]
pub fn boundary_functions() -> Vec<(String, BoundaryFunction)> {
    let mut out = Vec::new();
    for stack in &load().stacks {
        let Some(boundary) = stack.boundary.as_ref() else {
            continue;
        };
        if !boundary.functions.is_empty() {
            for function in &boundary.functions {
                out.push((stack.id.clone(), function.clone()));
            }
            continue;
        }
        for symbol in boundary.write.iter().chain(boundary.read.iter()) {
            let direction = if boundary.write.iter().any(|item| item == symbol) {
                TlsDirection::Send
            } else {
                TlsDirection::Recv
            };
            out.push((
                stack.id.clone(),
                BoundaryFunction {
                    symbol: symbol.clone(),
                    direction: Some(direction),
                    layout: boundary.layout.clone(),
                    buffer_arg: boundary.buffer_arg,
                    length_arg: boundary.length_arg,
                    connection_arg: boundary.connection_arg,
                    max_bytes: boundary.max_bytes,
                    validation_state: if boundary.layout.eq_ignore_ascii_case("pinned") {
                        "enabled".to_owned()
                    } else {
                        "experimental".to_owned()
                    },
                    ..BoundaryFunction::default()
                },
            ));
        }
    }
    out
}

/// All keylog probe entries from the table (build-id or name matched).
///
/// Only stacks with `coverage.keylog == true` and a pinned `keylog.offset` are
/// returned. Soft-demoting a pin (`coverage.keylog=false`) keeps the verified
/// offset documented in JSON but prevents live uprobe attach — prefer no app
/// break over an aggressive pin when hit-safety is unproven.
#[must_use]
pub fn keylog_entries() -> Vec<KeylogRule> {
    load()
        .stacks
        .iter()
        .filter(|stack| stack.coverage.keylog == Some(true))
        .filter_map(|stack| stack.keylog.as_ref())
        .filter(|rule| rule.offset.is_some())
        .cloned()
        .collect()
}

/// Whether `--inspect-tls` may try `SSL_write` on this mapped ELF.
///
/// Unknown paths stay eligible (symbol proof happens at attach). Recognized
/// stacks with `plaintext_copy=false` are skipped so stripped size-pins
/// (`libssl` 405664, Flutter generic, XQUIC) do not claim a write
/// surface. `plaintext_copy=true` still requires a defined `SSL_write` in
/// dynsym or LOCAL `.symtab` of *that* file — offsets are never invented.
#[must_use]
pub fn ssl_write_attach_allowed(
    path: &str,
    file_size: Option<u64>,
    actual_build_id: Option<&str>,
) -> bool {
    match stack_for_path(path, file_size, actual_build_id) {
        Some(stack) => stack.coverage.plaintext_copy,
        None => true,
    }
}

/// True when this mapping is a live-APK-sized keylog pin (`coverage.keylog`
/// plus a writer offset, and not a 100MiB+ unstripped `flutter.jar` artifact).
#[must_use]
pub fn live_apk_keylog_pin(
    path: &str,
    file_size: Option<u64>,
    actual_build_id: Option<&str>,
) -> bool {
    const JAR_SO_FLOOR: u64 = 20 * 1024 * 1024;
    let Some(stack) = stack_for_path(path, file_size, actual_build_id) else {
        return false;
    };
    if stack.coverage.keylog != Some(true) {
        return false;
    }
    if stack.keylog.as_ref().and_then(|rule| rule.offset).is_none() {
        return false;
    }
    !matches!(
        file_size.or(stack.match_rules.size),
        Some(size) if size >= JAR_SO_FLOOR
    )
}

/// All JNI boundary symbol names (write/read) across stacks.
#[must_use]
pub fn boundary_symbols() -> Vec<String> {
    let mut out = Vec::new();
    for stack in &load().stacks {
        if let Some(boundary) = &stack.boundary {
            out.extend(boundary.write.iter().cloned());
            out.extend(boundary.read.iter().cloned());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Configured ABI for an exported vendor boundary symbol.
#[must_use]
pub fn boundary_rule_for_symbol(
    symbol: &str,
) -> Option<(&'static StackRule, &'static BoundaryRules, &'static str)> {
    for stack in &load().stacks {
        let Some(boundary) = stack.boundary.as_ref() else {
            continue;
        };
        if boundary.write.iter().any(|item| item == symbol) {
            return Some((stack, boundary, "send"));
        }
        if boundary.read.iter().any(|item| item == symbol) {
            return Some((stack, boundary, "recv"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_table_parses_and_classifies() {
        let rules = load();
        assert!(!rules.stacks.is_empty(), "embedded table must ship stacks");
        let conscrypt = stack_for_path("/apex/com.android.conscrypt/lib64/libssl.so", None, None)
            .expect("conscrypt classified");
        assert_eq!(conscrypt.id, "conscrypt_system");
        let ttboring = stack_for_path(
            "/data/app/~~x/com.example.app-y/lib/arm64/libttboringssl.so",
            Some(369_256),
            None,
        )
        .expect("ttboringssl classified");
        assert_eq!(ttboring.id, "ttboringssl");
        assert!(
            ttboring.keylog.is_some(),
            "ttboringssl ships a keylog offset"
        );
        assert!(stack_for_path(
            "/apex/com.android.webview/lib64/libwebviewchromium.so",
            None,
            None
        )
        .is_some());
    }

    #[test]
    fn keylog_and_boundary_extract() {
        let entries = keylog_entries();
        assert!(entries.iter().any(|entry| entry.offset == Some(305_616)));
        assert!(entries.iter().any(|entry| entry.offset == Some(359_252)));
        let boundary = boundary_symbols();
        assert!(boundary.iter().any(|name| name.contains("writeSSLData")));
        assert!(tls_symbol_names().iter().any(|name| name == "SSL_write"));
        assert!(
            tls_symbol_names().iter().any(|name| name == "SSL_peek"),
            "rules must declare SSL_peek so runtime can attach it"
        );
        assert!(tls_symbol_names()
            .iter()
            .any(|name| name == "SSL_write_ex2"));
        assert!(tls_symbol_names().iter().any(|name| name == "SSL_read_ex2"));
    }

    #[test]
    fn size_mismatch_does_not_match() {
        assert!(
            stack_for_path("/data/app/x/lib/arm64/libttboringssl.so", Some(999), None)
                .is_none_or(|stack| stack.match_rules.size.is_none())
        );
    }

    #[test]
    fn ttboringssl_size_gap_twins_do_not_collide() {
        let vendor_tt = stack_for_path(
            "/data/app/~~x/com.example.app-y/lib/arm64/libttboringssl.so",
            Some(369_256),
            None,
        )
        .expect("vendor ttboringssl");
        assert_eq!(vendor_tt.id, "ttboringssl");
        assert_eq!(
            vendor_tt.keylog.as_ref().and_then(|k| k.offset),
            Some(359_252)
        );

        let twin_a = stack_for_path(
            "/data/app/~~x/com.example.video-y/lib/arm64/libttboringssl.so",
            Some(367_512),
            None,
        )
        .expect("ttboringssl size pin");
        assert_eq!(twin_a.id, "ttboringssl_367512");
        assert_eq!(twin_a.keylog.as_ref().and_then(|k| k.offset), Some(357_600));
        assert_eq!(twin_a.coverage.keylog, Some(true));
        assert!(twin_a.coverage.plaintext_copy);

        let twin_b = stack_for_path(
            "/data/app/~~x/com.example.chat-y/lib/arm64/libttboringssl.so",
            Some(341_976),
            Some("b854276cc5debb7f195dae237d51cef88f5ce793"),
        )
        .expect("ttboringssl build-id pin");
        assert_eq!(twin_b.id, "ttboringssl_b854276c");
        assert_eq!(twin_b.keylog.as_ref().and_then(|k| k.offset), Some(318_348));
        assert_eq!(twin_b.coverage.keylog, Some(true));

        // Offsets must stay distinct — never retarget one RVA onto size-gap twins.
        let offsets: Vec<u64> = keylog_entries()
            .into_iter()
            .filter_map(|e| e.offset)
            .filter(|o| matches!(o, 359_252 | 357_600 | 318_348))
            .collect();
        assert!(offsets.contains(&359_252));
        assert!(offsets.contains(&357_600));
        assert!(offsets.contains(&318_348));
    }

    #[test]
    fn exact_path_rule_beats_generic_basename() {
        let matches = matching_stacks("/apex/com.android.conscrypt/lib64/libssl.so", None, None);
        assert_eq!(
            matches.first().map(|item| item.id.as_str()),
            Some("conscrypt_system")
        );
        assert!(matches.iter().any(|item| item.id == "app_libssl_generic"));
    }

    #[test]
    fn embedded_rules_are_structurally_valid() {
        assert_eq!(validation_issues(load()), Vec::<String>::new());
    }

    #[test]
    fn official_build_id_pins_conscrypt_system_cronet_babassl_hssl() {
        let c = stack_for_path(
            "/apex/com.android.conscrypt/lib64/libssl.so",
            Some(489_400),
            Some("268ad40478040d405ef16199f46f137f"),
        )
        .expect("conscrypt pin");
        assert_eq!(c.id, "conscrypt_268ad404");
        assert!(c.coverage.plaintext_copy);
        assert_eq!(c.coverage.keylog, Some(true));

        let sys = stack_for_path(
            "/system/lib64/libssl.so",
            Some(513_920),
            Some("5bb7c9f8533f57612a6d8ac7c90d48f8"),
        )
        .expect("system libssl pin");
        assert_eq!(sys.id, "system_libssl_5bb7c9f8");

        let c32 = stack_for_path(
            "/apex/com.android.conscrypt/lib/libssl.so",
            Some(326_604),
            Some("5f60f4e3725320a87f66156cf343cadb"),
        )
        .expect("conscrypt32 pin");
        assert_eq!(c32.id, "conscrypt_5f60f4e3");

        let cronet32 = stack_for_path(
            "/apex/com.android.tethering/lib/stable_cronet_libssl.so",
            Some(299_240),
            Some("ccdddb35581c6dc25e90ed791d7d9f40"),
        )
        .expect("cronet32 pin");
        assert_eq!(cronet32.id, "cronet_ccdddb35");
        assert!(cronet32.coverage.plaintext_copy);

        let baba = stack_for_path(
            "/data/app/~~x/com.example.app-y/lib/arm64/libopenssl.so",
            Some(2_444_056),
            Some("40f1ff861a60f7c72def7ee1edf98a21322a6ca9"),
        )
        .expect("babassl pin");
        assert_eq!(baba.id, "babassl_40f1ff86");
        assert!(baba.symbols.write.iter().any(|s| s == "SSL_write_ex"));

        let hssl = stack_for_path(
            "/data/app/~~x/com.example.app-y/lib/arm64/libhssl-2.1.so",
            Some(130_384),
            Some("c81d34ed7227eb81366e5d8c3bf6db0965cfbf75"),
        )
        .expect("hssl pin");
        assert_eq!(hssl.id, "libhssl_c81d34ed");
        assert!(hssl.symbols.write.iter().any(|s| s == "sslWrite"));

        let hssl_small = stack_for_path(
            "/data/app/~~x/com.example.app-y/lib/arm64/libhssl-2.1.so",
            Some(109_912),
            Some("0f47c907e5b8dc7706c0154f3943cc71a0ca1c0b"),
        )
        .expect("hssl small twin pin");
        assert_eq!(hssl_small.id, "libhssl_0f47c907");

        let vendor = stack_for_path(
            "/vendor/lib64/libssl.so",
            Some(513_920),
            Some("aebd44138c05defb60ce8e74b235121b"),
        )
        .expect("vendor libssl pin");
        assert_eq!(vendor.id, "vendor_libssl_aebd4413");
        assert!(vendor.coverage.plaintext_copy);
        assert_eq!(vendor.coverage.keylog, Some(true));

        // Same size as system twin must NOT collapse to system pin when bid differs.
        let sys_same_size = stack_for_path(
            "/system/lib64/libssl.so",
            Some(513_920),
            Some("5bb7c9f8533f57612a6d8ac7c90d48f8"),
        )
        .expect("system twin");
        assert_eq!(sys_same_size.id, "system_libssl_5bb7c9f8");
        assert_ne!(vendor.id, sys_same_size.id);

        let xquic_gap = stack_for_path(
            "/data/app/~~x/com.example.maps-y/lib/arm64/libxquic.so",
            Some(563_768),
            Some("ff5f8bff320f94bb1e04358cd63f2f86040d4687"),
        )
        .expect("xquic size/build-id gap pin");
        assert_eq!(xquic_gap.id, "xquic_ff5f8bff");
        assert!(!xquic_gap.coverage.plaintext_copy);
        assert_eq!(xquic_gap.coverage.keylog, Some(false));
        assert!(
            xquic_gap.keylog.as_ref().and_then(|k| k.offset).is_none(),
            "xquic size=563768 pin must not invent keylog offset"
        );
        assert_eq!(xquic_gap.version.kind, "gap");
        assert!(!ssl_write_attach_allowed(
            "/data/app/~~x/com.example.maps-y/lib/arm64/libxquic.so",
            Some(563_768),
            Some("ff5f8bff320f94bb1e04358cd63f2f86040d4687"),
        ));
    }

    #[test]
    fn unpinned_ttboringssl_size_is_generic_gap_not_pinned_offset() {
        let path = "/data/app/~~x/com.example.video-y/lib/arm64/libttboringssl.so";
        let unknown = stack_for_path(path, Some(999), None).expect("generic twin");
        assert_eq!(unknown.id, "ttboringssl_generic");
        assert_eq!(unknown.coverage.keylog, Some(false));
        assert!(unknown.keylog.as_ref().and_then(|k| k.offset).is_none());
        assert!(
            !keylog_entries()
                .iter()
                .any(
                    |entry| entry.lib_name.as_deref() == Some("libttboringssl.so")
                        && entry.size == Some(999)
                ),
            "unknown ttboringssl must not inherit a pinned keylog offset"
        );
        assert!(ssl_write_attach_allowed(path, Some(999), None));
    }

    #[test]
    fn flutter_jar_size_is_not_a_live_apk_keylog_pin() {
        let path = "/data/app/~~x/com.example-y/lib/arm64/libflutter.so";
        let jar_bid = "dbac22aadb80e480bb438af805083393e8a064e7";
        assert!(
            !live_apk_keylog_pin(path, Some(163_761_776), Some(jar_bid)),
            "unstripped flutter.jar SO is not a live APK pin"
        );
        assert!(live_apk_keylog_pin(
            path,
            Some(11_107_920),
            Some("0a7fde9baaf490ad50a8480ebc422ea4ee862a2e"),
        ));
        assert!(!live_apk_keylog_pin(
            path,
            Some(10_268_216),
            Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
        ));
    }

    #[test]
    fn babassl_libopenssl_classifies_without_unpinned_offsets() {
        let stack = stack_for_path(
            "/data/app/~~x/com.example.app-y/lib/arm64/libopenssl.so",
            Some(2_444_056),
            Some("40f1ff861a60f7c72def7ee1edf98a21322a6ca9"),
        )
        .expect("babassl libopenssl classified");
        // Build-id+size pin wins over basename-only babassl_openssl.
        assert_eq!(stack.id, "babassl_40f1ff86");
        assert!(stack.coverage.plaintext_copy);
        assert_eq!(stack.coverage.keylog, Some(true));
        assert!(
            stack.keylog.as_ref().and_then(|k| k.offset).is_none(),
            "crash-safe: no guessed keylog offset without pin"
        );
        assert!(stack.symbols.write.iter().any(|s| s == "SSL_write"));
        // Another BABASSL build still matches by basename alone.
        let other_openssl = stack_for_path(
            "/data/app/~~x/com.example.wallet-y/lib/arm64/libopenssl.so",
            Some(2_857_704),
            None,
        )
        .expect("libopenssl classified");
        assert_eq!(other_openssl.id, "babassl_openssl");
        // Size pin openssl3_libssl_908888 beats basename-only app_libssl_generic.
        assert_eq!(
            stack_for_path(
                "/data/app/~~x/com.example.app-y/lib/arm64/libssl.so",
                Some(908_888),
                None,
            )
            .map(|s| s.id.as_str()),
            Some("openssl3_libssl_908888")
        );
    }

    #[test]
    fn tquic_pinned_by_build_id_soft_demote_retains_offset_skips_attach() {
        let vendor_tquic = "/data/app/~~x/com.example.app-y/lib/arm64/libtquic.so";
        let pinned = stack_for_path(
            vendor_tquic,
            Some(1_833_968),
            Some("2916c4a0a606c37082127aacf169a9ff26fbd20e"),
        )
        .expect("vendor libtquic pinned");
        assert_eq!(pinned.id, "tquic_dlxx");
        assert!(!pinned.coverage.plaintext_copy);
        // Soft-demote policy: coverage.keylog=false gates live attach, but the
        // verified xref candidate offset stays documented in JSON (do not strip).
        assert_eq!(pinned.coverage.keylog, Some(false));
        assert_eq!(
            pinned.keylog.as_ref().and_then(|k| k.offset),
            Some(0x19bf70),
            "soft-demote retains documented keylog offset 0x19bf70"
        );
        assert!(
            pinned
                .keylog
                .as_ref()
                .map(|k| k.anchors.iter().any(|a| a == "CLIENT_RANDOM"))
                .unwrap_or(false),
            "anchors recorded for future on-device derivation"
        );
        assert!(pinned.symbols.write.is_empty());
        // Attach gate: keylog_entries() must skip demoted pins even when offset present.
        assert!(
            !keylog_entries().iter().any(|e| {
                e.offset == Some(0x19bf70)
                    || e.build_id.as_deref() == Some("2916c4a0a606c37082127aacf169a9ff26fbd20e")
            }),
            "soft-demoted tquic_dlxx must not appear in keylog_entries()"
        );

        let twin = stack_for_path(
            "/data/app/~~x/com.example.app-y/lib/arm64/libtquic.so",
            Some(1_993_864),
            Some("51c6aa5c8968df399ed2752f43b956d7c45f393e"),
        )
        .expect("vendor libtquic twin pinned");
        assert_eq!(twin.id, "tquic_51c6aa5c");
        assert!(!twin.coverage.plaintext_copy);

        // Wrong / unknown build-id must NOT match either pin (coverage gap → quic_generic).
        let unknown = stack_for_path(
            vendor_tquic,
            Some(1_833_968),
            Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
        )
        .expect("unpinned tquic falls through");
        assert_eq!(unknown.id, "quic_generic");
        assert!(!unknown.coverage.plaintext_copy);
        assert!(
            unknown.keylog.as_ref().and_then(|k| k.offset).is_none(),
            "unknown tquic: gap only, no offsets"
        );

        // Size mismatch with correct build-id must fail the pin.
        assert_eq!(
            stack_for_path(
                vendor_tquic,
                Some(999),
                Some("2916c4a0a606c37082127aacf169a9ff26fbd20e"),
            )
            .map(|s| s.id.as_str()),
            Some("quic_generic"),
            "size pin must not silently broaden"
        );

        // Without build-id, pin cannot fire (agent ELF inspect required).
        assert_eq!(
            stack_for_path(vendor_tquic, Some(1_833_968), None).map(|s| s.id.as_str()),
            Some("quic_generic")
        );

        // Pinned row beats quic_generic when build-id present.
        let matches = matching_stacks(
            vendor_tquic,
            Some(1_833_968),
            Some("2916c4a0a606c37082127aacf169a9ff26fbd20e"),
        );
        assert_eq!(matches.first().map(|s| s.id.as_str()), Some("tquic_dlxx"));
        assert!(matches.iter().any(|s| s.id == "quic_generic"));
    }

    #[test]
    fn flutter_pinned_build_id_keylog_beats_generic_unknown_is_gap() {
        let path = "/data/app/~~x/com.example-y/lib/arm64/libflutter.so";
        let bid = "0a7fde9baaf490ad50a8480ebc422ea4ee862a2e";
        let pinned = stack_for_path(path, Some(11_107_920), Some(bid)).expect("pinned flutter");
        assert_eq!(pinned.id, "flutter_0a7fde9b");
        assert_eq!(pinned.coverage.keylog, Some(true));
        assert_eq!(
            pinned.keylog.as_ref().and_then(|k| k.offset),
            Some(0x716dbc)
        );
        // Unknown build-id → generic flutter; crash-safe gap (no offset / keylog false)
        let generic = stack_for_path(
            path,
            Some(11_107_920),
            Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
        )
        .expect("generic flutter");
        assert_eq!(generic.id, "flutter");
        assert_eq!(generic.coverage.keylog, Some(false));
        assert!(generic.keylog.as_ref().and_then(|k| k.offset).is_none());
        // Specificity: pinned wins when both would match
        let ranked = matching_stacks(path, Some(11_107_920), Some(bid));
        assert_eq!(ranked[0].id, "flutter_0a7fde9b");
    }

    #[test]
    fn every_embedded_stack_has_version_kind_and_product() {
        let rules: StackRulesFile =
            serde_json::from_str(EMBEDDED_RULES).expect("embedded JSON must deserialize");
        assert_eq!(rules.schema_version, SCHEMA_VERSION);
        assert!(!rules.stacks.is_empty());
        for stack in &rules.stacks {
            assert!(
                !stack.version.kind.trim().is_empty(),
                "stack {} missing version.kind",
                stack.id
            );
            let kind = stack.version.kind.as_str();
            assert!(
                matches!(kind, "stable" | "pinned" | "gap" | "rolling"),
                "stack {} unexpected version.kind={}",
                stack.id,
                kind
            );
            // Placeholder rows may keep an empty product; everything else must label.
            if stack.id != "quic_generic" {
                assert!(
                    !stack.version.product.trim().is_empty(),
                    "stack {} missing version.product",
                    stack.id
                );
            }
            assert!(
                !stack.version.upgrade_note.trim().is_empty(),
                "stack {} missing version.upgrade_note",
                stack.id
            );
        }
        // Spot-check a few shapes
        let flutter = rules
            .stacks
            .iter()
            .find(|s| s.id == "flutter_67d6564b")
            .expect("flutter_67d6564b");
        assert_eq!(flutter.version.kind, "pinned");
        assert!(flutter.version.product.contains("3.24.5"));
        assert_eq!(
            flutter.version.engine_version.as_deref(),
            Some("a18df97ca57a249df5d8d68cd0820600223ce262")
        );
        let cronet = rules
            .stacks
            .iter()
            .find(|s| s.id == "cronet_0dceef13")
            .expect("cronet_0dceef13");
        assert_eq!(cronet.version.kind, "pinned");
        assert_eq!(cronet.version.verified_at.as_deref(), Some("2026-09-12"));
        let gap = rules
            .stacks
            .iter()
            .find(|s| s.id == "webview_chromium")
            .expect("webview_chromium");
        assert_eq!(gap.version.kind, "gap");
        let stable = rules
            .stacks
            .iter()
            .find(|s| s.id == "conscrypt_system")
            .expect("conscrypt_system");
        assert_eq!(stable.version.kind, "stable");
    }

    #[test]
    #[test]
    fn libhssl_probespecs_pin_ex_abi_and_offsets() {
        // Basename-only match: name attach, openssl_ex_* for Ex (pre-P0 pazq ABI).
        let generic = probe_specs_for_path(
            "/data/app/~~x/com.example.app-y/lib/arm64/libhssl-2.1.so",
            None,
            None,
        );
        assert!(
            generic.iter().any(|(id, _)| id == "libhssl"),
            "basename-only should surface generic libhssl ProbeSpecs"
        );
        let ex_write = generic
            .iter()
            .find(|(_, p)| p.symbol == "sslWriteEx")
            .map(|(_, p)| p)
            .expect("sslWriteEx ProbeSpec");
        assert_eq!(ex_write.abi, Some(crate::TlsAbiKind::OpensslExWrite));
        assert!(ex_write.file_offset.is_none());
        assert_eq!(
            generic
                .iter()
                .find(|(_, p)| p.symbol == "sslWrite")
                .and_then(|(_, p)| p.abi),
            Some(crate::TlsAbiKind::VendorWrite)
        );

        // Pinned twin: verified offsets; must not also emit generic libhssl rows.
        let pinned = probe_specs_for_path(
            "/data/app/~~x/com.example.app-y/lib/arm64/libhssl-2.1.so",
            Some(109_912),
            Some("0f47c907e5b8dc7706c0154f3943cc71a0ca1c0b"),
        );
        assert!(
            pinned.iter().all(|(id, _)| id == "libhssl_0f47c907"),
            "winning build-id pin must not co-emit generic libhssl ProbeSpecs: {pinned:?}"
        );
        let by_sym: std::collections::BTreeMap<_, _> = pinned
            .iter()
            .map(|(_, p)| (p.symbol.as_str(), p))
            .collect();
        assert_eq!(by_sym["sslWrite"].file_offset, Some(0x1248c));
        assert_eq!(by_sym["sslWriteEx"].file_offset, Some(0x12a6c));
        assert_eq!(by_sym["sslRead"].file_offset, Some(0x12cb4));
        assert_eq!(by_sym["sslReadEx"].file_offset, Some(0x130fc));
        assert_eq!(by_sym["sslWriteEx"].abi, Some(crate::TlsAbiKind::OpensslExWrite));
        assert_eq!(by_sym["sslReadEx"].abi, Some(crate::TlsAbiKind::OpensslExRead));
        assert_eq!(by_sym["sslWrite"].abi, Some(crate::TlsAbiKind::VendorWrite));
        assert_eq!(by_sym["sslRead"].abi, Some(crate::TlsAbiKind::VendorRead));

        let twin = probe_specs_for_path(
            "/data/app/~~x/com.example.app-y/lib/arm64/libhssl-2.1.so",
            Some(130_384),
            Some("c81d34ed7227eb81366e5d8c3bf6db0965cfbf75"),
        );
        assert!(twin.iter().all(|(id, _)| id == "libhssl_c81d34ed"));
        assert_eq!(
            twin.iter()
                .find(|(_, p)| p.symbol == "sslWriteEx")
                .and_then(|(_, p)| p.file_offset),
            Some(0x12b30)
        );
    }

    fn pixel6a_elfs_do_not_invent_local_write_or_bio_or_quic_level() {
        let names = tls_symbol_names();
        assert!(names.iter().any(|name| name == "SSL_write"));
        assert!(names.iter().any(|name| name == "SSL_peek"));
        for banned in [
            "BIO_write",
            "BIO_read",
            "BIO_write_all",
            "SSL_quic_read_level",
            "SSL_quic_write_level",
            "SSL_provide_quic_data",
            "SSL_set_quic_method",
        ] {
            assert!(
                !names.iter().any(|name| name == banned),
                "{banned} must not enter tls_symbol_names"
            );
        }
        assert!(
            enabled_plaintext_probes().is_empty(),
            "no enabled plaintext_probes until an ELF-pinned row exists"
        );
        // No JSON pins today — probe_specs_for_path stays empty without inventing rows.
        assert!(probe_specs_for_path(
            "/apex/com.android.tethering/lib64/stable_cronet_libssl.so",
            Some(456_088),
            Some("0dceef1315310b5520aa046f7119d879"),
        )
        .is_empty());

        let cronet = stack_for_path(
            "/apex/com.android.tethering/lib64/stable_cronet_libssl.so",
            Some(456_088),
            Some("0dceef1315310b5520aa046f7119d879"),
        )
        .expect("cronet pin");
        assert_eq!(cronet.id, "cronet_0dceef13");
        assert!(cronet.coverage.plaintext_copy);
        assert!(cronet.symbols.write.iter().any(|name| name == "SSL_write"));
        assert!(cronet.plaintext_probes.is_empty());
        assert!(ssl_write_attach_allowed(
            "/apex/com.android.tethering/lib64/stable_cronet_libssl.so",
            Some(456_088),
            Some("0dceef1315310b5520aa046f7119d879"),
        ));

        let flutter = stack_for_path(
            "/data/app/~~x/com.example-y/lib/arm64/libflutter.so",
            Some(10_554_680),
            Some("e263a16aaa8bf3e0d2b45e1cc4e6207615829b32"),
        )
        .expect("flutter e263");
        assert_eq!(flutter.id, "flutter_e263a16a");
        assert!(!flutter.coverage.plaintext_copy);
        assert!(flutter.symbols.write.is_empty());
        assert!(flutter.plaintext_probes.is_empty());
        assert_eq!(
            flutter.keylog.as_ref().and_then(|rule| rule.offset),
            Some(7_081_800),
            "ssl_log_secret 0x6c0f48 — not the 0x9ac63c wrapper"
        );
        assert!(!ssl_write_attach_allowed(
            "/data/app/~~x/com.example-y/lib/arm64/libflutter.so",
            Some(10_554_680),
            Some("e263a16aaa8bf3e0d2b45e1cc4e6207615829b32"),
        ));

        let webview = stack_for_path(
            "/data/app/~~x/com.google.android.webview-y/lib/arm64/libmonochrome.so",
            Some(124_193_136),
            Some("e784a0ac4a27d41670fff83eb0aa3c8a631385c8"),
        )
        .expect("webview");
        assert_eq!(webview.id, "webview_chromium");
        assert!(!webview.coverage.plaintext_copy);
        assert!(webview.symbols.write.is_empty());
        assert!(webview.plaintext_probes.is_empty());
        assert!(!ssl_write_attach_allowed(
            "/data/app/~~x/com.google.android.webview-y/lib/arm64/libmonochrome.so",
            Some(124_193_136),
            Some("e784a0ac4a27d41670fff83eb0aa3c8a631385c8"),
        ));

        let xquic = stack_for_path(
            "/data/app/~~x/com.example.maps-y/lib/arm64/libxquic.so",
            Some(563_768),
            Some("ff5f8bff320f94bb1e04358cd63f2f86040d4687"),
        )
        .expect("xquic");
        assert_eq!(xquic.id, "xquic_ff5f8bff");
        assert!(!xquic.coverage.plaintext_copy);
        assert!(xquic.plaintext_probes.is_empty());

        let tquic = stack_for_path(
            "/data/app/~~x/com.example.app-y/lib/arm64/libtquic.so",
            Some(1_833_968),
            Some("2916c4a0a606c37082127aacf169a9ff26fbd20e"),
        )
        .expect("tquic");
        assert_eq!(tquic.id, "tquic_dlxx");
        assert!(!tquic.coverage.plaintext_copy);
        assert!(tquic.plaintext_probes.is_empty());
    }
}
