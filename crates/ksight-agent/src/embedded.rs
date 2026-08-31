//! Embedded device assets for the single-file Android distribution.

#[cfg(feature = "embedded-assets")]
use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};

#[cfg(feature = "embedded-assets")]
use anyhow::Context as _;
use anyhow::Result;
#[cfg(feature = "embedded-assets")]
use sha2::{Digest as _, Sha256};

/// Stable directory used by the host CLI and service configuration.
pub const DEVICE_ROOT: &str = "/data/local/tmp/ksight";

#[cfg(feature = "embedded-assets")]
const ASSETS: &[(&str, &[u8], u32)] = &[
    (
        "process_lifecycle.bpf.o",
        include_bytes!("../../../build/bpf/process_lifecycle.bpf.o"),
        0o644,
    ),
    (
        "file_open.bpf.o",
        include_bytes!("../../../build/bpf/file_open.bpf.o"),
        0o644,
    ),
    (
        "network_connect.bpf.o",
        include_bytes!("../../../build/bpf/network_connect.bpf.o"),
        0o644,
    ),
    (
        "memory_regions.bpf.o",
        include_bytes!("../../../build/bpf/memory_regions.bpf.o"),
        0o644,
    ),
    (
        "binder_transaction.bpf.o",
        include_bytes!("../../../build/bpf/binder_transaction.bpf.o"),
        0o644,
    ),
    (
        "sched_wakeup.bpf.o",
        include_bytes!("../../../build/bpf/sched_wakeup.bpf.o"),
        0o644,
    ),
    (
        "uprobe_regs.bpf.o",
        include_bytes!("../../../build/bpf/uprobe_regs.bpf.o"),
        0o644,
    ),
    (
        "ksightd.json",
        include_bytes!("../../../android/config/ksightd.json.example"),
        0o644,
    ),
    (
        "ksight-hide-debug.sh",
        include_bytes!("../../../android/scripts/ksight-hide-debug.sh"),
        0o755,
    ),
];

/// Materialize the assets compiled into the device release.
///
/// Existing custom `ksightd.json` is preserved. Immutable generated objects and
/// the helper script are replaced atomically only when their content differs.
///
/// # Errors
///
/// Returns when the device root cannot be created or an embedded asset cannot be
/// installed with its expected content and permissions.
#[cfg(feature = "embedded-assets")]
pub fn prepare_default_layout() -> Result<()> {
    let root = Path::new(DEVICE_ROOT);
    fs::create_dir_all(root).with_context(|| format!("create {}", root.display()))?;
    set_mode(root, 0o755)?;
    for (name, bytes, mode) in ASSETS {
        let destination = root.join(name);
        if *name == "ksightd.json" && destination.is_file() {
            continue;
        }
        write_if_changed(&destination, bytes, *mode)?;
    }
    Ok(())
}

/// No-op in ordinary host/test builds.
///
/// # Errors
///
/// This build variant performs no I/O and therefore always succeeds.
#[cfg(not(feature = "embedded-assets"))]
pub fn prepare_default_layout() -> Result<()> {
    Ok(())
}

#[cfg(feature = "embedded-assets")]
fn write_if_changed(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    if fs::read(path).is_ok_and(|current| digest(&current) == digest(bytes)) {
        set_mode(path, mode)?;
        return Ok(());
    }
    let temporary = temporary_path(path);
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)
            .with_context(|| format!("create {}", temporary.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("sync {}", temporary.display()))?;
        set_mode(&temporary, mode)?;
        fs::rename(&temporary, path)
            .with_context(|| format!("install embedded asset {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[cfg(feature = "embedded-assets")]
fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(feature = "embedded-assets")]
fn temporary_path(path: &Path) -> PathBuf {
    path.with_extension(format!("tmp-{}", std::process::id()))
}

#[cfg(all(feature = "embedded-assets", unix))]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {mode:o} {}", path.display()))
}

#[cfg(all(feature = "embedded-assets", not(unix)))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(all(test, feature = "embedded-assets"))]
mod tests {
    use super::ASSETS;

    #[test]
    fn single_file_distribution_contains_every_runtime_asset() {
        assert_eq!(ASSETS.len(), 9);
        for (name, bytes, _) in ASSETS
            .iter()
            .filter(|(name, _, _)| name.ends_with(".bpf.o"))
        {
            assert!(bytes.starts_with(b"\x7fELF"), "{name} is not an ELF object");
        }
        let (_, config, _) = ASSETS
            .iter()
            .find(|(name, _, _)| *name == "ksightd.json")
            .expect("embedded service config");
        let document: serde_json::Value =
            serde_json::from_slice(config).expect("valid config JSON");
        assert_eq!(document["schema_version"], 3);
    }
}
