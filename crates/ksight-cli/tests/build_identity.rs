//! End-to-end version and capability compatibility checks.
use std::process::Command;

#[test]
fn human_version_includes_source_identity() {
    let output = Command::new(env!("CARGO_BIN_EXE_ksightctl"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        format!("ksightctl {}", ksight_core::build_info::VERSION)
    );
}

#[test]
fn compatibility_versions_are_unchanged() {
    let output = Command::new(env!("CARGO_BIN_EXE_ksightctl"))
        .arg("versions")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        format!(
            "wire={}.{} schema={}.{} raw_abi=1",
            ksight_protocol::CURRENT_PROTOCOL.major,
            ksight_protocol::CURRENT_PROTOCOL.minor,
            ksight_model::CURRENT_SCHEMA.major,
            ksight_model::CURRENT_SCHEMA.minor
        )
    );
}
