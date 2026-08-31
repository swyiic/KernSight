//! Best-effort file path semantic enrichment.

use std::{
    fs::File,
    io::{Read as _, Write as _},
    path::{Component, Path, PathBuf},
};

use ksight_model::FileOpen;
use sha2::{Digest as _, Sha256};

const AT_FDCWD: i32 = -100;
const MAX_HASH_BYTES: u64 = 1024 * 1024;

/// Resolve a submitted `openat` path without opening the target file.
pub fn resolve_open_path(process_id: u32, open: &mut FileOpen) {
    if open.path.is_empty() {
        return;
    }
    let submitted = Path::new(&open.path);
    if submitted.is_absolute() {
        open.resolved_path = Some(
            normalize_lexically(submitted)
                .to_string_lossy()
                .into_owned(),
        );
        hash_code_candidate(process_id, open);
        return;
    }

    let base_link = if open.directory_fd == AT_FDCWD {
        format!("/proc/{process_id}/cwd")
    } else {
        format!("/proc/{process_id}/fd/{}", open.directory_fd)
    };
    let Ok(base) = std::fs::read_link(base_link) else {
        return;
    };
    open.resolved_path = Some(
        normalize_lexically(&base.join(submitted))
            .to_string_lossy()
            .into_owned(),
    );
    hash_code_candidate(process_id, open);
}

fn hash_code_candidate(process_id: u32, open: &mut FileOpen) {
    let Some(fd) = open.file_descriptor.filter(|_| open.result >= 0) else {
        return;
    };
    let path = open.resolved_path.as_deref().unwrap_or(open.path.as_str());
    if is_forensic_snapshot(path) {
        return;
    }
    if !is_hashable_artifact(path) {
        return;
    }
    let proc_fd = format!("/proc/{process_id}/fd/{fd}");
    let Ok(mut file) = File::open(&proc_fd).or_else(|_| File::open(path)) else {
        return;
    };
    let Ok(metadata) = file.metadata() else {
        return;
    };
    if metadata.len() == 0 || metadata.len() > MAX_HASH_BYTES {
        return;
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    let mut total_bytes = 0_u64;
    loop {
        let Ok(read) = file.read(&mut buffer) else {
            return;
        };
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total_bytes = total_bytes.saturating_add(u64::try_from(read).unwrap_or(0));
        if total_bytes > MAX_HASH_BYTES {
            return;
        }
    }
    open.content_bytes = Some(total_bytes);
    open.content_sha256 = Some(format!("{:x}", hasher.finalize()));
}

fn is_hashable_artifact(path: &str) -> bool {
    is_code_artifact(path) || is_forensic_artifact(path)
}

fn is_code_artifact(path: &str) -> bool {
    let extension = Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default();
    extension.eq_ignore_ascii_case("so")
        || extension.eq_ignore_ascii_case("dex")
        || extension.eq_ignore_ascii_case("apk")
        || extension.eq_ignore_ascii_case("oat")
        || extension.eq_ignore_ascii_case("vdex")
        || extension.eq_ignore_ascii_case("art")
}

fn is_forensic_artifact(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let extension = Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default();
    lower.contains("/connlogs/")
        || extension.eq_ignore_ascii_case("dve")
        || lower.ends_with("/envc.push")
        || lower.ends_with("/info.y")
        || lower.contains("jssdk")
        || is_ephemeral_dex(path)
        || is_packer_so(path)
}

fn is_ephemeral_dex(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let extension = Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default();
    (extension.eq_ignore_ascii_case("dex") || extension.eq_ignore_ascii_case("vdex"))
        && (lower.contains("/code_cache/")
            || lower.contains("/data/user/")
            || lower.contains("/data/data/")
            || lower.contains("dalvik"))
}

/// True when a mapped/opened native library is a packer, VMP, or gadget.
#[must_use]
pub fn is_interesting_native(path: &str) -> bool {
    let path = path
        .strip_suffix(" (deleted)")
        .or_else(|| path.strip_suffix("(deleted)"))
        .unwrap_or(path)
        .trim();
    let name = Path::new(path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name == "libencrypt.so"
        || [
            "dexhelper",
            "dexjni",
            "dexvmp",
            "dexloader",
            "loaddex",
            "dumpdex",
            "flipped",
            "ssduck",
            "scylla",
            "fridagadget",
            "frida-gadget",
            "libgadget",
            "xposed",
            "substrate",
            "bangcle",
            "nllvm",
            "iprotect",
            "secneo",
            "secexe",
            "secmain",
            "datajar",
            "apkwrapper",
            "apkprotect",
            "nprotect",
            "jiagu",
            "legu",
            "ijiami",
            "libexec",
            "execmain",
            "qihoo",
            "qvm",
            "naga",
            "baiduprotect",
            "sgmain",
            "sgsecuritybody",
            "mobisec",
            "shella",
            "shellx",
        ]
        .iter()
        .any(|needle| name.contains(needle))
}

fn is_packer_so(path: &str) -> bool {
    is_interesting_native(path)
}

fn is_forensic_snapshot(path: &str) -> bool {
    is_forensic_artifact(path)
}

/// Copy a forensic file into the session spool so later analysis is not
/// blocked when the app deletes the original (common for packed DEX).
///
/// Copies through `/proc/<pid>/fd/<n>` first so an unlink still yields the
/// live inode. Does not require a prior SHA-256 (payload DEX is often > 1 MiB).
pub fn snapshot_forensic(process_id: u32, open: &mut FileOpen, dest_dir: &Path) {
    let Some(fd) = open.file_descriptor.filter(|_| open.result >= 0) else {
        return;
    };
    let Some(path) = open.resolved_path.as_deref().or(Some(open.path.as_str())) else {
        return;
    };
    if !is_forensic_snapshot(path) {
        return;
    }
    let name = Path::new(path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("blob");
    if std::fs::create_dir_all(dest_dir).is_err() {
        return;
    }
    let staging = dest_dir.join(format!(".partial-{process_id}-{fd}-{name}"));
    let proc_fd = format!("/proc/{process_id}/fd/{fd}");
    let cap = snapshot_cap(path);
    let copied = copy_capped(Path::new(&proc_fd), &staging, cap)
        .or_else(|_| copy_capped(Path::new(path), &staging, cap));
    let Ok((copied, digest, prefix)) = copied else {
        let _ = std::fs::remove_file(&staging);
        return;
    };
    if copied == 0 || !prefix_matches_name(name, &prefix) {
        let _ = std::fs::remove_file(&staging);
        return;
    }
    open.content_bytes = Some(copied);
    open.content_sha256 = Some(digest.clone());
    let dest = dest_dir.join(format!("{digest}_{name}"));
    if dest.exists() {
        let _ = std::fs::remove_file(&staging);
        return;
    }
    if std::fs::rename(&staging, &dest).is_err() {
        let _ = std::fs::copy(&staging, &dest);
        let _ = std::fs::remove_file(&staging);
    }
    if ksight_core::is_dex_magic(&prefix) {
        if let Ok(bytes) = std::fs::read(&dest) {
            if let Some(repaired) = ksight_core::repair_dex(&bytes) {
                let repaired_dir = dest_dir.join("repaired");
                let _ = std::fs::create_dir_all(&repaired_dir);
                let _ = std::fs::write(
                    repaired_dir.join(format!("{digest}_{name}")),
                    repaired.bytes,
                );
            }
        }
    }
}

fn snapshot_cap(path: &str) -> u64 {
    if is_ephemeral_dex(path) {
        48 * 1024 * 1024
    } else if is_packer_so(path) {
        12 * 1024 * 1024
    } else if path.to_ascii_lowercase().ends_with(".dve") {
        4096
    } else {
        2 * 1024 * 1024
    }
}

fn prefix_matches_name(name: &str, prefix: &[u8]) -> bool {
    let ext = Path::new(name)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if ext.eq_ignore_ascii_case("so") {
        prefix.starts_with(b"\x7fELF")
    } else if ext.eq_ignore_ascii_case("dex") || ext.eq_ignore_ascii_case("cdex") {
        ksight_core::is_dex_magic(prefix)
    } else if ext.eq_ignore_ascii_case("vdex") {
        ksight_core::is_vdex_magic(prefix)
    } else if ext.eq_ignore_ascii_case("dve") {
        !prefix.starts_with(b"PK")
    } else {
        true
    }
}

fn copy_capped(src: &Path, dest: &Path, max_bytes: u64) -> std::io::Result<(u64, String, Vec<u8>)> {
    let mut input = File::open(src)?;
    if let Ok(meta) = input.metadata() {
        if meta.len() > max_bytes.saturating_mul(2) && max_bytes <= 12 * 1024 * 1024 {
            return Err(std::io::Error::other("source larger than forensic cap"));
        }
    }
    let mut output = File::create(dest)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    let mut total = 0_u64;
    let mut prefix = Vec::new();
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = max_bytes.saturating_sub(total);
        if remaining == 0 {
            break;
        }
        let take = read.min(usize::try_from(remaining).unwrap_or(read));
        let chunk = &buffer[..take];
        if prefix.len() < 16 {
            let need = 16_usize.saturating_sub(prefix.len());
            prefix.extend_from_slice(&chunk[..need.min(chunk.len())]);
        }
        output.write_all(chunk)?;
        hasher.update(chunk);
        total = total.saturating_add(u64::try_from(take).unwrap_or(0));
        if take < read {
            break;
        }
    }
    Ok((total, format!("{:x}", hasher.finalize()), prefix))
}

fn normalize_lexically(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_paths_are_normalized_without_io() {
        let mut open = FileOpen {
            directory_fd: AT_FDCWD,
            file_descriptor: Some(3),
            result: 3,
            flags: 0,
            mode: 0,
            path: "/data/user/0/app/../app/config".to_owned(),
            resolved_path: None,
            content_sha256: None,
            content_bytes: None,
        };
        resolve_open_path(1, &mut open);
        assert_eq!(
            open.resolved_path.as_deref(),
            Some("/data/user/0/app/config")
        );
    }

    #[test]
    fn missing_relative_base_stays_unresolved() {
        let mut open = FileOpen {
            directory_fd: 99,
            file_descriptor: None,
            result: -9,
            flags: 0,
            mode: 0,
            path: "relative.txt".to_owned(),
            resolved_path: None,
            content_sha256: None,
            content_bytes: None,
        };
        resolve_open_path(u32::MAX, &mut open);
        assert!(open.resolved_path.is_none());
    }

    #[test]
    fn hashes_and_snapshots_connlog_files() {
        let dir = std::env::temp_dir().join(format!("ksight-forensic-{}", std::process::id()));
        let logs = dir.join("connlogs");
        std::fs::create_dir_all(&logs).expect("temp connlogs");
        let src = logs.join("icbcim_test.txt");
        std::fs::write(&src, b"CinClient : connect host:example\n").expect("write connlog");
        let mut open = FileOpen {
            directory_fd: AT_FDCWD,
            file_descriptor: Some(3),
            result: 3,
            flags: 0,
            mode: 0,
            path: src.to_string_lossy().into_owned(),
            resolved_path: None,
            content_sha256: None,
            content_bytes: None,
        };
        resolve_open_path(1, &mut open);
        let snap = dir.join("snap");
        snapshot_forensic(1, &mut open, &snap);
        assert!(open.content_sha256.is_some());
        let count = std::fs::read_dir(&snap).expect("snapshot dir").count();
        assert_eq!(count, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn packer_and_gadget_names_are_interesting() {
        assert!(is_interesting_native("/data/app/x/libdexvmp.so"));
        assert!(is_interesting_native("/data/app/x/libiProtectSGCC.so"));
        assert!(is_interesting_native("/data/app/x/libFridaGadget.so"));
        assert!(is_interesting_native("/data/app/x/libbangcle_risk.so"));
        assert!(is_interesting_native("/data/app/x/libjiagu.so"));
        assert!(is_interesting_native(
            "/data/data/pkg/files/libexec.so (deleted)"
        ));
        assert!(is_interesting_native("/data/app/x/libshella.so"));
        assert!(!is_interesting_native("/system/lib64/libc.so"));
        assert!(!is_interesting_native("/data/app/x/libcrypto.so"));
    }
}
