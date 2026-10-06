//! Embedded native-library framework rules used by package-dump analysis.

use std::{collections::BTreeMap, path::Path};

use serde::{Deserialize, Serialize};

use crate::DumpArtifact;

const RULES_JSON: &str = include_str!("../../../rules/native_frameworks.json");

#[derive(Debug, Deserialize)]
struct NativeRuleDocument {
    schema_version: String,
    rules: Vec<NativeRule>,
}

#[derive(Debug, Deserialize)]
struct NativeRule {
    id: String,
    name: String,
    category: String,
    confidence: String,
    exact_basenames: Vec<String>,
    path_markers: Vec<String>,
    description: String,
}

/// One native artifact supporting a framework classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeFrameworkEvidence {
    /// Retained path below the package dump root.
    pub relative_path: String,
    /// Acquisition source such as `install-lib` or `runtime-so`.
    pub source: String,
    /// Content digest when the file was readable.
    pub sha256: Option<String>,
    /// Process that loaded or exposed the library, when known.
    pub pid: Option<u32>,
}

/// One rule-library match. A match is a candidate identification, not proof of behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeFrameworkMatch {
    /// Stable rule identifier.
    pub rule_id: String,
    /// Human-readable framework name.
    pub name: String,
    /// `packer_shell` or `crypto_framework`.
    pub category: String,
    /// Rule confidence (`high` or `medium`), before behavioral validation.
    pub confidence: String,
    /// Interpretation guidance.
    pub description: String,
    /// All distinct matching SO observations.
    pub evidence: Vec<NativeFrameworkEvidence>,
}

/// Mapped TLS/crypto library class. Used to say whether `--inspect-tls` can attach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsLibraryKind {
    /// System/Apex Conscrypt `libssl.so`. `--inspect-tls` attaches here.
    ConscryptSystem,
    /// Conscrypt JNI helper, not the `SSL_write` boundary.
    ConscryptJni,
    /// App-private `libssl.so` / `libboringssl.so` / `libopenssl.so` (BABASSL) / `libhssl`. Inspect attaches only if `SSL_write` is exported.
    AppLibssl,
    /// Chromium Cronet. Inspect attaches only if that ELF exports `SSL_write`.
    Cronet,
    /// Flutter engine. Dart TLS is not Conscrypt `SSL_write`.
    FlutterEngine,
    /// Mbed TLS.
    MbedTls,
    /// wolfSSL.
    WolfSsl,
    /// `GmSSL` / 国密.
    Gmssl,
    /// Tencent TASSL.
    Tassl,
}

impl TlsLibraryKind {
    /// Stable identifier for reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConscryptSystem => "conscrypt_system",
            Self::ConscryptJni => "conscrypt_jni",
            Self::AppLibssl => "app_libssl",
            Self::Cronet => "cronet",
            Self::FlutterEngine => "flutter",
            Self::MbedTls => "mbedtls",
            Self::WolfSsl => "wolfssl",
            Self::Gmssl => "gmssl",
            Self::Tassl => "tassl",
        }
    }

    /// Whether `--inspect-tls` will try exported `SSL_write` on this mapping.
    #[must_use]
    pub const fn inspect_tries_ssl_write(self) -> bool {
        matches!(self, Self::ConscryptSystem | Self::AppLibssl | Self::Cronet)
    }
}

/// Classify a mapped or dumped ELF path as a TLS stack, if it looks like one.
#[must_use]
pub fn classify_tls_library_path(path: &str) -> Option<TlsLibraryKind> {
    let lower = path.to_ascii_lowercase();
    let basename = Path::new(&lower)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if basename.contains("cronet")
        || basename == "libchrome.so"
        || basename.starts_with("libmonochrome")
        || lower.contains("/cronet")
    {
        return Some(TlsLibraryKind::Cronet);
    }
    if basename == "libflutter.so" || lower.contains("libflutter") {
        return Some(TlsLibraryKind::FlutterEngine);
    }
    if basename.contains("mbedtls") || basename.contains("mbedcrypto") {
        return Some(TlsLibraryKind::MbedTls);
    }
    if basename.contains("wolfssl") {
        return Some(TlsLibraryKind::WolfSsl);
    }
    if basename.contains("gmssl") || basename.contains("smcrypto") {
        return Some(TlsLibraryKind::Gmssl);
    }
    if basename.contains("tassl") {
        return Some(TlsLibraryKind::Tassl);
    }
    if basename == "libconscrypt_jni.so" || basename == "libjavacrypto.so" {
        return Some(TlsLibraryKind::ConscryptJni);
    }
    if basename.contains("mssl") || basename.contains("infosec") {
        // Vendor Infosec GMSSL stacks: JNI-boundary TLS (writeSSLDataNative).
        return Some(TlsLibraryKind::AppLibssl);
    }
    if basename.contains("hssl") || basename.contains("boringssl") {
        // `libhssl*` and vendor boringssl forks such as
        // `libttboringssl.so` export standard `SSL_write` symbols.
        return Some(TlsLibraryKind::AppLibssl);
    }
    if basename == "libssl.so"
        || basename == "libboringssl.so"
        || basename == "libopenssl.so"
        || basename == "libcrypto.so"
    {
        if lower.contains("conscrypt")
            || lower.contains("/apex/com.android.conscrypt/")
            || lower.starts_with("/system/lib/libssl.so")
            || lower.starts_with("/system/lib64/libssl.so")
        {
            return Some(TlsLibraryKind::ConscryptSystem);
        }
        if lower.starts_with("/system/") || lower.starts_with("/apex/") {
            return Some(TlsLibraryKind::ConscryptSystem);
        }
        return Some(TlsLibraryKind::AppLibssl);
    }
    None
}

/// Version of the embedded native framework rule document.
#[must_use]
pub fn native_framework_rule_version() -> String {
    parse_rules().map_or_else(|| "invalid".to_owned(), |document| document.schema_version)
}

/// Classify ELF/SO artifacts with the embedded, versioned rule library.
#[must_use]
pub fn classify_native_frameworks(artifacts: &[DumpArtifact]) -> Vec<NativeFrameworkMatch> {
    let Some(document) = parse_rules() else {
        return Vec::new();
    };
    let mut matches = BTreeMap::<String, NativeFrameworkMatch>::new();
    for artifact in artifacts.iter().filter(|artifact| artifact.kind == "elf") {
        let path = artifact.relative_path.to_ascii_lowercase();
        let basename = Path::new(&path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        for rule in &document.rules {
            let exact = rule.exact_basenames.iter().any(|candidate| {
                let candidate = candidate.to_ascii_lowercase();
                basename == candidate || basename.ends_with(&format!("_{candidate}"))
            });
            let marker = rule
                .path_markers
                .iter()
                .any(|candidate| path.contains(&candidate.to_ascii_lowercase()));
            if !exact && !marker {
                continue;
            }
            let entry = matches
                .entry(rule.id.clone())
                .or_insert_with(|| NativeFrameworkMatch {
                    rule_id: rule.id.clone(),
                    name: rule.name.clone(),
                    category: rule.category.clone(),
                    confidence: rule.confidence.clone(),
                    description: rule.description.clone(),
                    evidence: Vec::new(),
                });
            if !entry
                .evidence
                .iter()
                .any(|existing| existing.relative_path == artifact.relative_path)
            {
                entry.evidence.push(NativeFrameworkEvidence {
                    relative_path: artifact.relative_path.clone(),
                    source: artifact.source.clone(),
                    sha256: artifact.sha256.clone(),
                    pid: artifact.pid,
                });
            }
        }
    }
    let mut result = matches.into_values().collect::<Vec<_>>();
    result.sort_by(|left, right| {
        left.category
            .cmp(&right.category)
            .then(left.name.cmp(&right.name))
    });
    result
}

fn parse_rules() -> Option<NativeRuleDocument> {
    serde_json::from_str(RULES_JSON).ok()
}

