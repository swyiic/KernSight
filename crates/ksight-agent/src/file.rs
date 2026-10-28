//! Best-effort file path semantic enrichment.

use std::{
    fs::File,
    io::{Read as _, Write as _},
    path::{Component, Path, PathBuf},
    time::Instant,
};

use ksight_model::FileOpen;
use sha2::{Digest as _, Sha256};

const AT_FDCWD: i32 = -100;
const MAX_HASH_BYTES: u64 = 1024 * 1024;

/// Resolve a submitted `openat` path without opening the target file.
pub fn resolve_open_path(process_id: u32, open: &mut FileOpen) {
    resolve_open_path_until(process_id, open, None);
}

/// Bound optional content hashing by the caller's observation deadline.
pub fn resolve_open_path_until(process_id: u32, open: &mut FileOpen, deadline: Option<Instant>) {
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
        hash_code_candidate(process_id, open, deadline);
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
    hash_code_candidate(process_id, open, deadline);
}

fn hash_code_candidate(process_id: u32, open: &mut FileOpen, deadline: Option<Instant>) {
    if check_deadline(deadline).is_err() {
        return;
    }
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
    let Ok(mut file) = open_regular(Path::new(&proc_fd)).or_else(|_| open_regular(Path::new(path)))
    else {
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
        if check_deadline(deadline).is_err() {
            return;
        }
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
    let _ = snapshot_forensic_until(process_id, open, dest_dir, None);
}

/// Preserve raw files within a live window; derived DEX repair is offline work.
/// A timeout never publishes a partial file hash as a complete snapshot.
/// # Errors
/// Returns the optional enrichment failure, including an expired window.
pub fn snapshot_forensic_until(
    process_id: u32,
    open: &mut FileOpen,
    dest_dir: &Path,
    deadline: Option<Instant>,
) -> std::io::Result<()> {
    let Some(fd) = open.file_descriptor.filter(|_| open.result >= 0) else {
        return Ok(());
    };
    let Some(path) = open.resolved_path.as_deref().or(Some(open.path.as_str())) else {
        return Ok(());
    };
    if !is_forensic_snapshot(path) {
        return Ok(());
    }
    let name = Path::new(path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("blob");
    check_deadline(deadline)?;
    std::fs::create_dir_all(dest_dir)?;
    let staging = dest_dir.join(format!(".partial-{process_id}-{fd}-{name}"));
    let proc_fd = format!("/proc/{process_id}/fd/{fd}");
    let cap = snapshot_cap(path);
    let copied = copy_capped(Path::new(&proc_fd), &staging, cap, deadline).or_else(|error| {
        if error.kind() == std::io::ErrorKind::TimedOut {
            return Err(error);
        }
        copy_capped(Path::new(path), &staging, cap, deadline)
    });
    let (copied, digest, prefix) = match copied {
        Ok(value) => value,
        Err(error) => {
            let _ = std::fs::remove_file(&staging);
            return Err(error);
        }
    };
    if copied == 0 || !prefix_matches_name(name, &prefix) {
        let _ = std::fs::remove_file(&staging);
        return Ok(());
    }
    open.content_bytes = Some(copied);
    open.content_sha256 = Some(digest.clone());
    let dest = dest_dir.join(format!("{digest}_{name}"));
    if dest.exists() {
        let _ = std::fs::remove_file(&staging);
        return Ok(());
    }
    if let Err(error) = std::fs::rename(&staging, &dest) {
        let _ = std::fs::remove_file(&staging);
        open.content_bytes = None;
        open.content_sha256 = None;
        return Err(error);
    }
    if deadline.is_none() && ksight_core::is_dex_magic(&prefix) {
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
    Ok(())
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

fn copy_capped(
    src: &Path,
    dest: &Path,
    max_bytes: u64,
    deadline: Option<Instant>,
) -> std::io::Result<(u64, String, Vec<u8>)> {
    check_deadline(deadline)?;
    let mut input = open_regular(src)?;
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
        check_deadline(deadline)?;
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

fn check_deadline(deadline: Option<Instant>) -> std::io::Result<()> {
    if deadline.is_some_and(|end| Instant::now() >= end) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "file enrichment window expired",
        ));
    }
    Ok(())
}

// File extensions are untrusted. Opening a FIFO named *.dex in blocking mode
// can stall the entire collector indefinitely, even before metadata is checked.
pub(crate) fn open_regular(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOCTTY)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular evidence file",
        ));
    }
    Ok(file)
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
mod deadline_tests {
    use super::*;

    #[test]
    fn expired_copy_does_not_create_output() {
        let root = std::env::temp_dir().join(format!("ks-file-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("source"), b"bytes").unwrap();
        let result = copy_capped(
            &root.join("source"),
            &root.join("output"),
            100,
            Some(Instant::now()),
        );
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert!(!root.join("output").exists());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fifo_named_dex_cannot_block_capture() {
        let root = std::env::temp_dir().join(format!("ks-fifo-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let fifo = root.join("payload.dex");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        let start = Instant::now();
        assert_eq!(
            open_regular(&fifo).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn regular_copy_still_has_exact_bytes_and_digest() {
        let root = std::env::temp_dir().join(format!("ks-copy-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let input = vec![b'x'; 16384];
        std::fs::write(root.join("source"), &input).unwrap();
        let (bytes, hash, _) = copy_capped(
            &root.join("source"),
            &root.join("output"),
            32768,
            Some(Instant::now() + std::time::Duration::from_secs(1)),
        )
        .unwrap();
        assert_eq!(bytes, input.len() as u64);
        assert_eq!(hash, format!("{:x}", Sha256::digest(&input)));
        assert_eq!(std::fs::read(root.join("output")).unwrap(), input);
        std::fs::remove_dir_all(root).unwrap();
    }
}
