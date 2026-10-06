//! Native execution of the actual C producers; no target, probe or networking.
use std::path::Path;
use std::process::Command;

#[test]
fn production_c_instance_gate_rejects_reuse_read_failures_and_update_aba() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let binary = std::env::temp_dir().join(format!("ksight-instance-gate-{}", std::process::id()));
    let compiler = std::env::var_os("KSIGHT_TEST_CLANG").unwrap_or_else(|| "cc".into());
    let built = Command::new(compiler)
        .args(["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(root.join("bpf/include"))
        .arg(root.join("native/instance_scope_test.c"))
        .arg("-o")
        .arg(&binary)
        .output()
        .expect("existing host C compiler required");
    assert!(
        built.status.success(),
        "C compilation: {}",
        String::from_utf8_lossy(&built.stderr)
    );
    let ran = Command::new(&binary)
        .output()
        .expect("run native production C fixture");
    let _ = std::fs::remove_file(&binary);
    assert!(
        ran.status.success(),
        "C fixture failed: {} {}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(String::from_utf8_lossy(&ran.stdout).contains("denied samples read zero payload"));
}
