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

pub const DEVICE_TABLE_PATH: &str = "/data/local/tmp/ksight/tls_stacks.json";

/// Root of the rules document.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StackRulesFile {
    #[serde(default)]
    pub schema_version: String,
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
        true
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

/// JNI-boundary functions of a vendor stack (B-route targets).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BoundaryRules {
    #[serde(default)]
    pub write: Vec<String>,
    #[serde(default)]
    pub read: Vec<String>,
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
    #[serde(default)]
    pub boundary: Option<BoundaryRules>,
    #[serde(default)]
    pub keylog: Option<KeylogRule>,
    #[serde(default)]
    pub coverage: CoverageFlags,
    #[serde(default)]
    pub notes: String,
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
                return parsed;
            }
        }
        serde_json::from_str::<StackRulesFile>(EMBEDDED_RULES).unwrap_or_default()
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
    load()
        .stacks
        .iter()
        .find(|stack| stack.matches(path, file_size, actual_build_id))
}

/// Union of exported write/read symbol names across all stacks.
#[must_use]
pub fn tls_symbol_names() -> Vec<String> {
    let mut out = Vec::new();
    for stack in &load().stacks {
        out.extend(stack.symbols.write.iter().cloned());
        out.extend(stack.symbols.read.iter().cloned());
    }
    out.sort();
    out.dedup();
    out
}

/// All keylog probe entries from the table (build-id or name matched).
#[must_use]
pub fn keylog_entries() -> Vec<KeylogRule> {
    load()
        .stacks
        .iter()
        .filter_map(|stack| stack.keylog.as_ref())
        .filter(|rule| rule.offset.is_some())
        .cloned()
        .collect()
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
            "/data/app/~~x/com.hundsun.winner.pazq-y/lib/arm64/libttboringssl.so",
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
    }

    #[test]
    fn size_mismatch_does_not_match() {
        assert!(
            stack_for_path("/data/app/x/lib/arm64/libttboringssl.so", Some(999), None)
                .is_none_or(|stack| stack.match_rules.size.is_none())
        );
    }
}
