//! Read-only rule diagnostics. Configuration is not runtime attestation.
use crate::stack_rules::{
    rule_constraint_issues, valid_build_id, validation_issues, StackRulesFile,
};
use serde::Serialize;

/// Bounded input for local/device rule diagnostics.
pub const STACK_AUDIT_MAX_BYTES: usize = 4 * 1024 * 1024;

/// Machine-readable audit; never contains offsets or captured payloads.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StackRulesAudit {
    /// Version of this diagnostic result, independent of the input rule schema.
    pub schema_version: &'static str,
    /// Whether structural and identity checks passed.
    pub valid: bool,
    /// Number of configured rules, not number of supported libraries.
    pub rule_count: usize,
    /// Whole-table validation errors.
    pub errors: Vec<String>,
    /// Per-rule configuration and gaps.
    pub rules: Vec<StackAuditRow>,
    /// Limits that must accompany any GUI presentation.
    pub limitations: Vec<&'static str>,
}

/// One declared rule; no live process was inspected to produce it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StackAuditRow {
    /// Stable rule ID.
    pub id: String,
    /// Human-readable product hint from the configuration.
    pub product: String,
    /// Declared maintenance state; not verification status.
    pub declared_kind: String,
    /// Strong build identity / size hint / name hint.
    pub identity_basis: &'static str,
    /// True only means the rule requests this feature.
    pub plaintext_configured: bool,
    /// True only means the rule requests this feature.
    pub keylog_configured: bool,
    /// A read-only audit cannot attest runtime correctness.
    pub runtime_verification: &'static str,
    /// Rejections and verification gaps, with no inferred success.
    pub diagnostics: Vec<String>,
}

/// Audit a bounded JSON rules document without loading ELF files or attaching.
///
/// # Errors
/// Returns an error for oversized/malformed input; invalid rules are returned
/// as a report with `valid=false`, so the operator sees every diagnostic.
pub fn audit_stack_rules_json(input: &str) -> Result<StackRulesAudit, String> {
    if input.len() > STACK_AUDIT_MAX_BYTES {
        return Err("rules document exceeds 4 MiB".into());
    }
    let table: StackRulesFile = serde_json::from_str(input).map_err(|error| error.to_string())?;
    let mut errors = validation_issues(&table);
    if table.stacks.is_empty() {
        errors.push("rules table is empty".into());
    }
    let mut pins = std::collections::BTreeMap::new();
    for stack in &table.stacks {
        if let Some(rule) = &stack.keylog {
            if let (Some(id), Some(offset)) = (rule.build_id.as_deref(), rule.offset) {
                if valid_build_id(id) && stack.coverage.keylog == Some(true) {
                    let identity = id.to_ascii_lowercase();
                    let value = (offset, rule.client_random_offset);
                    if let Some(previous) = pins.insert(identity.clone(), value) {
                        if previous != value {
                            errors.push(format!(
                                "conflicting active pins for build identity {identity}"
                            ));
                        }
                    }
                }
            }
        }
    }
    let rows = table.stacks.iter().map(|stack| {
        let mut diagnostics = rule_constraint_issues(stack);
        let keylog_configured = stack.coverage.keylog == Some(true);
        if keylog_configured {
            match &stack.keylog {
                Some(rule) => {
                    if rule.offset.is_none() { diagnostics.push("keylog requested without a configured offset".into()); }
                    if !rule.build_id.as_deref().is_some_and(valid_build_id) {
                        diagnostics.push("keylog blocked by agent strict identity: name/size or parent-only build ID is insufficient".into());
                    }
                }
                None => diagnostics.push("keylog requested without a keylog rule".into()),
            }
        }
        if stack.coverage.plaintext_copy {
            diagnostics.push("plaintext configured; concrete ELF symbols, ABI and runtime results still require verification".into());
        }
        if stack.version.kind == "pinned" {
            diagnostics.push("pinned describes configuration, not current-build runtime acceptance".into());
        }
        if !stack.coverage.plaintext_copy && !keylog_configured && !stack.coverage.boundary_dump {
            diagnostics.push("classification only; no collection capability declared".into());
        }
        let identity_basis = if stack.match_rules.build_id.as_deref().is_some_and(valid_build_id) {
            "build_id"
        } else if stack.match_rules.size.is_some() {
            "size_hint_only"
        } else { "name_or_path_hint_only" };
        StackAuditRow {
            id: stack.id.clone(), product: stack.version.product.clone(),
            declared_kind: stack.version.kind.clone(), identity_basis,
            plaintext_configured: stack.coverage.plaintext_copy, keylog_configured,
            runtime_verification: "not_assessed", diagnostics,
        }
    }).collect();
    Ok(StackRulesAudit {
        schema_version: "kernsight.stack-rules-audit/v1", valid: errors.is_empty(),
        rule_count: table.stacks.len(), errors, rules: rows,
        limitations: vec![
            "Rule count is not library coverage or runtime success.",
            "A file name, size, stable/pinned tag or verified_at date is not current ELF attestation.",
            "This audit does not validate private offsets, architecture/ABI on a real ELF, TLS secrets, or App-to-Burp delivery.",
            "QUIC Initial SNI/ALPN parsing is not QUIC 1-RTT or HTTP/3 body support.",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> serde_json::Value {
        json!({"schema_version":"1.3","stacks":[{
            "id":"fixture", "match_rules":{"basename":"libfixture.so","build_id":"aabb"},
            "version":{"kind":"pinned","build_id":"aabb","verified_at":"2026-01-01"},
            "coverage":{"plaintext_copy":true,"keylog":true},
            "keylog":{"build_id":"aabb","offset":32}
        }]})
    }

    #[test]
    fn configured_and_dated_does_not_mean_runtime_verified() {
        let report = audit_stack_rules_json(&fixture().to_string()).unwrap();
        assert!(report.valid);
        assert_eq!(report.rules[0].runtime_verification, "not_assessed");
        assert!(report.rules[0]
            .diagnostics
            .iter()
            .any(|item| item.contains("runtime acceptance")));
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("\"offset\""));
    }

    #[test]
    fn conflicting_identity_fields_are_rejected() {
        for field in ["keylog", "version"] {
            let mut rules = fixture();
            rules["stacks"][0][field]["build_id"] = json!("ccdd");
            assert!(!audit_stack_rules_json(&rules.to_string()).unwrap().valid);
        }
    }

    #[test]
    fn parent_identity_does_not_hide_agent_rejection() {
        let mut rules = fixture();
        rules["stacks"][0]["keylog"]
            .as_object_mut()
            .unwrap()
            .remove("build_id");
        let report = audit_stack_rules_json(&rules.to_string()).unwrap();
        assert!(report.rules[0]
            .diagnostics
            .iter()
            .any(|item| item.contains("blocked")));
    }

    #[test]
    fn conflicting_pins_are_visible() {
        let mut rules = fixture();
        let mut second = rules["stacks"][0].clone();
        second["id"] = json!("second");
        second["keylog"]["offset"] = json!(64);
        rules["stacks"].as_array_mut().unwrap().push(second);
        let report = audit_stack_rules_json(&rules.to_string()).unwrap();
        assert!(!report.valid);
        assert!(report
            .errors
            .iter()
            .any(|item| item.contains("conflicting active pins")));
    }

    #[test]
    fn bad_schema_empty_constraints_and_oversize_are_rejected() {
        for version in ["1.foo", "1.99", "2.0"] {
            let mut rules = fixture();
            rules["schema_version"] = json!(version);
            assert!(!audit_stack_rules_json(&rules.to_string()).unwrap().valid);
        }
        let mut rules = fixture();
        rules["stacks"][0]["match_rules"] = json!({"basename_contains":[""]});
        assert!(!audit_stack_rules_json(&rules.to_string()).unwrap().valid);
        assert!(audit_stack_rules_json("{").is_err());
        assert!(audit_stack_rules_json(&" ".repeat(STACK_AUDIT_MAX_BYTES + 1)).is_err());
    }

    #[test]
    fn embedded_table_reports_all_rules_without_attesting_any() {
        let report = audit_stack_rules_json(crate::stack_rules::EMBEDDED_RULES).unwrap();
        assert!(report.valid, "{:?}", report.errors);
        assert!(report.rule_count > 0);
        assert_eq!(report.rule_count, report.rules.len());
        assert!(report
            .rules
            .iter()
            .all(|row| row.runtime_verification == "not_assessed"));
    }
}
