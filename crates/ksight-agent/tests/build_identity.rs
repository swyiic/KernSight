//! End-to-end version and capability compatibility checks.
use std::process::Command;

#[test]
fn human_version_includes_source_identity() {
    let output = Command::new(env!("CARGO_BIN_EXE_ksightd"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        format!("ksightd {}", ksight_core::build_info::VERSION)
    );
    let version = ksight_core::build_info::VERSION;
    let prefix = concat!(env!("CARGO_PKG_VERSION"), "_");
    assert!(version.starts_with(prefix), "{version}");
    let suffix = &version[prefix.len()..];
    assert_eq!(suffix.len(), 8, "{version}");
    assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()), "{version}");
}

#[test]
fn capabilities_preserve_base_version_and_add_compiled_provenance() {
    let output = Command::new(env!("CARGO_BIN_EXE_ksightd"))
        .arg("code-capabilities")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "kernsight.code-capabilities/v1");
    assert_eq!(report["agent_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        report["agent_build_version"],
        ksight_core::build_info::VERSION
    );
    assert_eq!(
        report["agent_git_commit"],
        serde_json::json!(ksight_core::build_info::git_commit())
    );
    assert_eq!(
        report["agent_git_dirty"],
        serde_json::json!(ksight_core::build_info::git_dirty())
    );
    assert_eq!(
        report["agent_build_identity_source"],
        ksight_core::build_info::SOURCE
    );
    let hash = report["agent_sha256"].as_str().unwrap();
    assert_eq!(hash.len(), 64);
    assert!(hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
}
