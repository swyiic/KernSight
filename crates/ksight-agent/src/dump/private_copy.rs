//! Bounded copy of app private CE/DE trees into a package dump.

use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use anyhow::Result;

use super::{has_ext, APP_PRIVATE_DIRS, MAX_PRIVATE_FILES, MAX_PRIVATE_FILE_BYTES};

pub(super) fn copy_app_private(package: &str, dest: &Path) -> Result<usize> {
    let mut copied = 0_usize;
    let mut seen = BTreeSet::new();
    for (label, root) in [
        ("ce", format!("/data/user/0/{package}")),
        ("de", format!("/data/user_de/0/{package}")),
        ("ce", format!("/data/data/{package}")),
    ] {
        for dir in APP_PRIVATE_DIRS {
            copied = copied.saturating_add(copy_private_tree(
                &PathBuf::from(&root).join(dir),
                &dest.join(label).join(dir),
                dest,
                &mut seen,
                0,
            )?);
            if copied >= MAX_PRIVATE_FILES {
                return Ok(copied);
            }
        }
    }
    Ok(copied)
}

pub(super) fn copy_private_tree(
    src: &Path,
    dest: &Path,
    dest_root: &Path,
    seen: &mut BTreeSet<String>,
    depth: u32,
) -> Result<usize> {
    if depth > 6 || !src.is_dir() {
        return Ok(0);
    }
    let mut copied = 0_usize;
    let Ok(entries) = std::fs::read_dir(src) else {
        return Ok(0);
    };
    for entry in entries.flatten() {
        if seen.len() >= MAX_PRIVATE_FILES {
            break;
        }
        let path = entry.path();
        if path.is_dir() {
            if skip_private_dir(&entry.file_name().to_string_lossy()) {
                continue;
            }
            copied = copied.saturating_add(copy_private_tree(
                &path,
                &dest.join(entry.file_name()),
                dest_root,
                seen,
                depth.saturating_add(1),
            )?);
            continue;
        }
        if !path.is_file() {
            continue;
        }
        if skip_private_file(&path) {
            continue;
        }
        let target = dest.join(entry.file_name());
        let Ok(rel) = target.strip_prefix(dest_root) else {
            continue;
        };
        let key = rel.to_string_lossy().replace('\\', "/");
        if !seen.insert(key) {
            continue;
        }
        if copy_capped_path(&path, &target, MAX_PRIVATE_FILE_BYTES).is_ok() && target.is_file() {
            copied = copied.saturating_add(1);
        }
    }
    Ok(copied)
}

pub(super) fn skip_private_dir(name: &str) -> bool {
    matches!(
        name,
        "fresco_disk_cache"
            | "image_manager_disk_cache"
            | "Crash Reports"
            | "HTTP Cache"
            | "Code Cache"
            | "Cache_Data"
            | "oat_primary"
            | "shaders_cache"
            | "com.android.opengl.shaders_cache.multifile"
            | "com.android.skia.shaders_cache"
    )
}

pub(super) fn skip_private_file(path: &Path) -> bool {
    if has_ext(path, "cnt") || has_ext(path, "baj") || has_ext(path, "baf") {
        return true;
    }
    [
        "jpg", "jpeg", "png", "webp", "mp4", "webm", "gif", "so", "apk", "dex", "jar", "oat",
        "vdex", "odex", "mp3", "aac", "wav",
    ]
    .iter()
    .any(|ext| has_ext(path, ext))
}

pub(super) fn copy_capped_path(src: &Path, dest: &Path, cap: u64) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let meta = src.metadata()?;
    if meta.len() > cap {
        return Ok(());
    }
    if reuse_static_object(src, dest, cap)? {
        return Ok(());
    }
    if dest.exists() {
        if files_equal(src, dest)? {
            return Ok(());
        }
        anyhow::bail!("static target content conflict");
    }
    let temporary = dest.with_extension(format!("pending-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut input = File::open(src)?;
        let before = input.metadata()?;
        let mut output = ksight_core::output_budget::BudgetFile::create(&temporary)?;
        let mut buffer = [0_u8; 8192];
        let mut total = 0_u64;
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            total = total.saturating_add(read as u64);
            if total > cap || total > before.len() {
                anyhow::bail!("static source changed or exceeds bound");
            }
            output.write_all(&buffer[..read])?;
        }
        let after = input.metadata()?;
        if total != before.len() || !same_identity(&before, &after) {
            anyhow::bail!("static source changed");
        }
        output.sync_all()?;
        if !files_equal(src, &temporary)? {
            anyhow::bail!("static completed copy mismatch");
        }
        // Atomic publication never overwrites existing evidence.
        std::fs::hard_link(&temporary, dest)?;
        if !files_equal(&temporary, dest)? {
            anyhow::bail!("static published copy mismatch");
        }
        Ok(())
    })();
    // Only this invocation's own temporary file is removed.
    let _ = std::fs::remove_file(&temporary);
    result
}

fn same_identity(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    let same = before.len() == after.len() && before.modified().ok() == after.modified().ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        same && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        same
    }
}

fn files_equal(first: &Path, second: &Path) -> Result<bool> {
    let check_first = first;
    let check_second = second;
    let mut first = File::open(first)?;
    let mut second = File::open(second)?;
    let first_before = first.metadata()?;
    let second_before = second.metadata()?;
    if first_before.len() != second_before.len() {
        return Ok(false);
    }
    let mut first_block = [0_u8; 8192];
    let mut second_block = [0_u8; 8192];
    let mut total = 0_u64;
    loop {
        if ksight_core::output_budget::should_stop(check_first)
            || ksight_core::output_budget::should_stop(check_second)
        {
            anyhow::bail!("static comparison budget interrupted");
        }
        let read = first.read(&mut first_block)?;
        if read == 0 {
            return Ok(second.read(&mut second_block)? == 0
                && total == first_before.len()
                && same_identity(&first_before, &first.metadata()?)
                && same_identity(&second_before, &second.metadata()?));
        }
        total = total.saturating_add(read as u64);
        if total > first_before.len() {
            return Ok(false);
        }
        second.read_exact(&mut second_block[..read])?;
        if first_block[..read] != second_block[..read] {
            return Ok(false);
        }
    }
}

// Reuse only complete, byte-verified content; never truncate an existing hard link.
fn reuse_static_object(src: &Path, dest: &Path, cap: u64) -> Result<bool> {
    use sha2::{Digest, Sha256};
    let Some(root) = dest.ancestors().find(|p| p.join("code-objects").is_dir()) else {
        return Ok(false);
    };
    let mut input = File::open(src)?;
    let before = input.metadata()?;
    if !before.is_file() || before.len() > cap {
        return Ok(false);
    }
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 8192];
    let mut total = 0_u64;
    loop {
        if ksight_core::output_budget::should_stop(dest) {
            anyhow::bail!("static source budget interrupted");
        }
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > before.len() || total > cap {
            anyhow::bail!("static source changed");
        }
        hash.update(&buffer[..n]);
    }
    let after = input.metadata()?;
    if total != before.len() || !same_identity(&before, &after) {
        anyhow::bail!("static source changed");
    }
    let object = root
        .join("code-objects")
        .join(format!("{:x}.bin", hash.finalize()));
    if !object.is_file() {
        return Ok(false);
    }
    // Do not trust an object name alone.
    if !files_equal(src, &object)? {
        anyhow::bail!("static content object conflict");
    }
    ksight_core::output_budget::charge(dest, 0)?;
    if dest.exists() {
        if !files_equal(dest, &object)? {
            anyhow::bail!("static target content conflict");
        }
    } else {
        std::fs::hard_link(&object, dest)?;
    }
    if !files_equal(src, dest)? || !files_equal(&object, dest)? {
        anyhow::bail!("static object changed during publication");
    }
    // Verify the published bytes against the content-addressed name, not merely equality.
    let mut published = File::open(dest)?;
    let before = published.metadata()?;
    let mut published_hash = Sha256::new();
    let mut published_bytes = 0_u64;
    loop {
        if ksight_core::output_budget::should_stop(dest) {
            anyhow::bail!("static published digest budget interrupted");
        }
        let read = published.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        published_bytes = published_bytes.saturating_add(read as u64);
        if published_bytes > before.len() || published_bytes > cap {
            anyhow::bail!("static published file changed or exceeds bound");
        }
        published_hash.update(&buffer[..read]);
    }
    let expected = object.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    if published_bytes != before.len()
        || format!("{:x}", published_hash.finalize()) != expected
        || !same_identity(&before, &published.metadata()?)
    {
        anyhow::bail!("static published digest mismatch");
    }
    Ok(true)
}

#[cfg(test)]
mod installed_apk_bound_tests {
    use super::*;
    #[test]
    fn static_comparison_obeys_parent_cancellation() {
        let root = std::env::temp_dir().join(format!("ksight-compare-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let first = root.join("first");
        let second = root.join("second");
        std::fs::write(&first, b"abc").unwrap();
        std::fs::write(&second, b"abc").unwrap();
        let guard =
            ksight_core::output_budget::Guard::install(vec![root.clone()], 1024, 30000).unwrap();
        ksight_core::output_budget::interrupt(&root, "parent_cancelled");
        assert!(files_equal(&first, &second)
            .unwrap_err()
            .to_string()
            .contains("interrupted"));
        assert_eq!(guard.receipt().admitted_write_bytes, 0);
        drop(guard);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn static_quota_interruption_never_publishes_a_prefix() {
        let root = std::env::temp_dir().join(format!("ksight-atomic-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let source = root.join("source.so");
        std::fs::write(&source, vec![1_u8; 16384]).unwrap();
        let dest = root.join("lib/fixture.so");
        let guard =
            ksight_core::output_budget::Guard::install(vec![root.clone()], 32768, 30000).unwrap();
        let child =
            ksight_core::output_budget::StaticScope::install(root.clone(), 8192, 0).unwrap();
        assert!(copy_capped_path(&source, &dest, 32768)
            .unwrap_err()
            .to_string()
            .contains("static_output_budget_exhausted"));
        assert!(!dest.exists());
        assert_eq!(
            std::fs::read_dir(dest.parent().unwrap()).unwrap().count(),
            0
        );
        assert_eq!(guard.receipt().admitted_write_bytes, 8192);
        drop(child);
        ksight_core::output_budget::write(root.join("dump-report.json"), b"partial").unwrap();
        drop(guard);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn installed_so_reuses_verified_object_without_payload_charge() {
        let root = std::env::temp_dir().join(format!("ksight-reuse-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("code-objects")).unwrap();
        let source = root.join("source.so");
        std::fs::write(&source, b"abc").unwrap();
        let object = root.join(
            "code-objects/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.bin",
        );
        std::fs::write(&object, b"abc").unwrap();
        let dest = root.join("lib/fixture.so");
        let guard =
            ksight_core::output_budget::Guard::install(vec![root.clone()], 1024, 30000).unwrap();
        copy_capped_path(&source, &dest, 128 * 1024 * 1024).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"abc");
        assert_eq!(guard.receipt().admitted_write_bytes, 0);
        std::fs::write(&source, b"xyz").unwrap();
        // A conflicting existing evidence target is never overwritten.
        assert!(copy_capped_path(&source, &dest, 1024).is_err());
        assert_eq!(std::fs::read(&dest).unwrap(), b"abc");
        drop(guard);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn observed_large_apk_raw_copy_is_skipped_without_failing_or_spending_budget() {
        let root = std::env::temp_dir().join(format!("ksight-raw-apk-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let source = root.join("base.apk");
        File::create(&source).unwrap().set_len(653_556_074).unwrap();
        let dest = root.join("evidence/apk/base.apk");
        let guard =
            ksight_core::output_budget::Guard::install(vec![root.join("evidence")], 1024, 30000)
                .unwrap();
        copy_capped_path(&source, &dest, super::super::MAX_APK_BYTES).unwrap();
        assert!(!dest.exists());
        assert_eq!(guard.receipt().admitted_write_bytes, 0);
        assert!(!guard.receipt().partial);
        drop(guard);
        std::fs::remove_dir_all(root).unwrap();
    }
}
