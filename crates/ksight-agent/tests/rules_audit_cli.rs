//! Read-only diagnostic CLI integration tests; never attach to a process.
use std::process::Command;

#[test]
fn explicit_table_reports_configuration_not_runtime_support() {
    let table = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../ksight-core/src/stack_rules_default.json");
    let output = Command::new(env!("CARGO_BIN_EXE_ksightd"))
        .args(["rules-audit", "--json", "--rules"])
        .arg(&table)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["source"], table.display().to_string());
    assert_eq!(json["report"]["valid"], true);
    let rows = json["report"]["rules"].as_array().unwrap();
    assert!(!rows.is_empty());
    assert!(rows
        .iter()
        .all(|row| row["runtimeVerification"] == "not_assessed"));
}

#[test]
fn explicitly_missing_table_does_not_fall_back_to_embedded() {
    let path = std::env::temp_dir().join(format!(
        "ksight-missing-rules-{}.json",
        uuid::Uuid::new_v4()
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_ksightd"))
        .args(["rules-audit", "--json", "--rules"])
        .arg(path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot read rules"));
    assert!(output.stdout.is_empty());
}
