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

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(path: &str) -> DumpArtifact {
        DumpArtifact {
            kind: "elf".to_owned(),
            source: "runtime-so".to_owned(),
            relative_path: path.to_owned(),
            bytes: 100,
            magic: "elf".to_owned(),
            pid: Some(42),
            vma_start: None,
            vma_end: None,
            map_path: None,
            dex_offset: None,
            sha256: Some("abc".to_owned()),
        }
    }

    #[test]
    fn embedded_rules_parse_and_identify_shell_and_crypto_frameworks() {
        assert_eq!(
            native_framework_rule_version(),
            "kernsight.native-framework-rules/v1"
        );
        let matches = classify_native_frameworks(&[
            artifact("apk-assets/assets_ijm_lib_arm64-v8a_libexec.so"),
            artifact("lib/arm64/libsqlcipher.so"),
        ]);
        assert!(matches.iter().any(|item| item.rule_id == "shell.ijiami"));
        assert!(matches
            .iter()
            .any(|item| item.rule_id == "crypto.sqlcipher"));
    }
}
