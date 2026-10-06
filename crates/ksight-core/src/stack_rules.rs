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

/// Default on-device rule override; diagnostics must not silently hide read errors.
pub const DEVICE_TABLE_PATH: &str = "/data/local/tmp/ksight/tls_stacks.json";
/// Schema string stored in embedded and on-device rules files.
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
        if self.is_empty()
            || self
                .basename
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            || self
                .basename_contains
                .iter()
                .chain(&self.path_contains)
                .any(|value| value.trim().is_empty())
            || self
                .build_id
                .as_deref()
                .is_some_and(|value| !valid_build_id(value))
            || self
                .architecture
                .as_deref()
                .is_some_and(|value| !known_architecture(value))
        {
            return false;
        }
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
        "x86_64" => lower.contains("/x86_64/"),
        "x86" => lower.contains("/x86/"),
        _ => false,
    }
}

/// Exported-symbol sets the sweeps and probes should target.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SymbolSets {
    /// Outbound plaintext-copy symbols.
    #[serde(default)]
    pub write: Vec<String>,
    /// Inbound plaintext-copy symbols.
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
    /// Exported symbol this probe attaches to.
    #[serde(default)]
    pub symbol: String,
    /// File offset when the symbol name is stripped.
    #[serde(default)]
    pub file_offset: Option<u64>,
    /// Send or recv override for the ABI default.
    #[serde(default)]
    pub direction: Option<TlsDirection>,
    /// Calling-convention override; omitted means the symbol name selects it.
    #[serde(default)]
    pub abi: Option<TlsAbiKind>,
    /// When the probe copies bytes.
    #[serde(default)]
    pub capture_phase: Option<CapturePhase>,
    /// Register index of the plaintext buffer.
    #[serde(default)]
    pub buffer_arg: Option<u8>,
    /// Register index of the requested length.
    #[serde(default)]
    pub requested_length_arg: Option<u8>,
    /// Where the copied length is read from.
    #[serde(default)]
    pub actual_length_source: Option<String>,
    /// Register index of the TLS connection or stream.
    #[serde(default)]
    pub connection_arg: Option<u8>,
    /// ELF build-id this row is pinned to.
    #[serde(default)]
    pub build_id: Option<String>,
    /// ELF file size this row is pinned to.
    #[serde(default)]
    pub size: Option<u64>,
    /// ABI architecture this row applies to.
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
    /// ELF build-id this probe is pinned to.
    #[serde(default)]
    pub build_id: Option<String>,
    /// ELF file size this probe is pinned to.
    #[serde(default)]
    pub size: Option<u64>,
    /// ABI architecture this probe applies to.
    #[serde(default)]
    pub architecture: Option<String>,
    /// File offset of the stripped plaintext boundary.
    #[serde(default)]
    pub file_offset: Option<u64>,
    /// Send or recv for this boundary.
    #[serde(default)]
    pub direction: TlsDirection,
    /// Calling convention used at this boundary.
    #[serde(default)]
    pub abi: TlsAbiKind,
    /// When the probe copies bytes.
    #[serde(default)]
    pub capture_phase: Option<CapturePhase>,
    /// Register index of the plaintext buffer.
    #[serde(default)]
    pub buffer_arg: Option<u8>,
    /// Register index of the requested length.
    #[serde(default)]
    pub requested_length_arg: Option<u8>,
    /// Where the copied length is read from.
    #[serde(default)]
    pub actual_length_source: Option<String>,
    /// Maximum plaintext bytes to copy.
    #[serde(default)]
    pub max_bytes: Option<u32>,
    /// When this row was verified.
    #[serde(default)]
    pub verified_at: Option<String>,
    /// SHA-256 of the sample used to verify the row.
    #[serde(default)]
    pub sample_sha256: Option<String>,
    /// `enabled` | `experimental` | `disabled`. Default disabled.
    #[serde(default)]
    pub validation_state: String,
}

/// Per-function vendor JNI/TLS boundary. Shared layout on a stack is not assumed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BoundaryFunction {
    /// JNI or vendor function name.
    #[serde(default)]
    pub symbol: String,
    /// Send or recv when known.
    #[serde(default)]
    pub direction: Option<TlsDirection>,
    /// Calling convention when known.
    #[serde(default)]
    pub abi: Option<TlsAbiKind>,
    /// When the probe copies bytes.
    #[serde(default)]
    pub capture_phase: Option<CapturePhase>,
    /// How the function return value is interpreted.
    #[serde(default)]
    pub return_semantics: Option<String>,
    /// Register index of the plaintext buffer.
    #[serde(default)]
    pub buffer_arg: Option<u8>,
    /// Register index of the length argument.
    #[serde(default)]
    pub length_arg: Option<u8>,
    /// Register index of the out-length pointer.
    #[serde(default)]
    pub output_length_arg: Option<u8>,
    /// Register index of the connection.
    #[serde(default)]
    pub connection_arg: Option<u8>,
    /// Register index of the stream.
    #[serde(default)]
    pub stream_arg: Option<u8>,
    /// True when this function copies header bytes.
    #[serde(default)]
    pub is_header: Option<bool>,
    /// True when this function copies body bytes.
    #[serde(default)]
    pub is_body: Option<bool>,
    /// `empirical` | `pinned`.
    #[serde(default)]
    pub layout: String,
    /// How strongly this layout was confirmed.
    #[serde(default)]
    pub confidence: Option<String>,
    /// ELF build-id this row is pinned to.
    #[serde(default)]
    pub build_id: Option<String>,
    /// Maximum plaintext bytes to copy.
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
    /// Canonical build-id (may mirror `match_rules`)
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
        rule_constraint_issues(self).is_empty()
            && self.match_rules.matches(path, file_size, actual_build_id)
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
    } else if !matches!(rules.schema_version.as_str(), "1.0" | "1.1" | "1.2" | "1.3") {
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
        issues.extend(
            rule_constraint_issues(stack)
                .into_iter()
                .map(|issue| format!("stack rule id={}: {issue}", stack.id)),
        );
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

pub(crate) fn valid_build_id(value: &str) -> bool {
    !value.is_empty() && value.len() % 2 == 0 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn known_architecture(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "arm64" | "aarch64" | "arm" | "arm32" | "aarch32" | "x86" | "x86_64"
    )
}

pub(crate) fn rule_constraint_issues(stack: &StackRule) -> Vec<String> {
    let mut issues = Vec::new();
    let rule = &stack.match_rules;
    if rule
        .basename
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
        || rule
            .basename_contains
            .iter()
            .chain(&rule.path_contains)
            .any(|value| value.trim().is_empty())
    {
        issues.push("empty path/basename match constraint".into());
    }
    if rule
        .architecture
        .as_deref()
        .is_some_and(|value| !known_architecture(value))
    {
        issues.push("unknown architecture constraint".into());
    }
    let keylog = stack.keylog.as_ref();
    let ids: Vec<_> = [
        rule.build_id.as_deref(),
        stack.version.build_id.as_deref(),
        keylog.and_then(|value| value.build_id.as_deref()),
    ]
    .into_iter()
    .flatten()
    .collect();
    if ids.iter().any(|id| !valid_build_id(id)) {
        issues.push("invalid build ID (expected nonempty hex bytes)".into());
    }
    if ids
        .first()
        .is_some_and(|first| ids.iter().any(|id| !id.eq_ignore_ascii_case(first)))
    {
        issues.push("match/version/keylog build IDs disagree".into());
    }
    let sizes: Vec<_> = [
        rule.size,
        stack.version.size,
        keylog.and_then(|value| value.size),
    ]
    .into_iter()
    .flatten()
    .collect();
    if sizes.contains(&0)
        || sizes
            .first()
            .is_some_and(|first| sizes.iter().any(|size| size != first))
    {
        issues.push("match/version/keylog sizes are zero or disagree".into());
    }
    if let Some(keylog) = keylog {
        if keylog
            .lib_name
            .as_deref()
            .is_some_and(|name| name.trim().is_empty())
        {
            issues.push("empty keylog library name".into());
        }
        if let (Some(expected), Some(actual)) =
            (rule.basename.as_deref(), keylog.lib_name.as_deref())
        {
            if expected != actual {
                issues.push("match/keylog library names disagree".into());
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
    out.extend(
        crate::tls_abi::QUIC_STREAM_SEND_EXPORTS
            .iter()
            .chain(crate::tls_abi::QUIC_STREAM_RECV_EXPORTS)
            .map(|name| (*name).to_owned()),
    );
    out.sort();
    out.dedup();
    out
}

/// Plaintext probes that may attach (enabled + pinned by build-id or size).
#[must_use]
pub fn enabled_plaintext_probes() -> Vec<(String, PlaintextProbe)> {
    let mut out = Vec::new();
    for stack in &load().stacks {
        if !rule_constraint_issues(stack).is_empty() {
            continue;
        }
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

/// `ProbeSpec` rows for the concrete ELF matched by path/size/build-id.
///
/// Returns attachable (`enabled` / `experimental`) probes from the winning
/// stack (and any equally specific co-matches). Callers build `InspectPlans`
/// from these rows — `file_offset` / abi / `buffer_arg` / `capture_phase` are the
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
        .filter(|stack| rule_constraint_issues(stack).is_empty())
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
