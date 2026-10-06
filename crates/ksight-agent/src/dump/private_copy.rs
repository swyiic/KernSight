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

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn copy_app_private_from(roots: &[PathBuf], dest: &Path) -> Result<usize> {
    let mut copied = 0_usize;
    let mut seen = BTreeSet::new();
    for root in roots {
        for dir in APP_PRIVATE_DIRS {
            copied = copied.saturating_add(copy_private_tree(
                &root.join(dir),
                &dest.join(dir),
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
    let mut input = File::open(src)?;
    let mut output = ksight_core::output_budget::BudgetFile::create(dest)?;
    let mut buffer = [0_u8; 8192];
    let mut total = 0_u64;
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if total.saturating_add(u64::try_from(read).unwrap_or(0)) > cap {
            break;
        }
        output.write_all(&buffer[..read])?;
        total = total.saturating_add(u64::try_from(read).unwrap_or(0));
    }
    Ok(())
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    #[test]
    fn installed_apk_copy_stops_and_preserves_partial() {
        let root = std::env::temp_dir().join(format!("copy-budget-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let src = root.join("installed.apk");
        std::fs::write(&src, vec![7; 10000]).unwrap();
        let dest = root.join("evidence");
        std::fs::create_dir(&dest).unwrap();
        let g = ksight_core::output_budget::Guard::install(vec![dest.clone()], 8192, 1000).unwrap();
        assert!(copy_capped_path(&src, &dest.join("base.apk"), 20000).is_err());
        assert_eq!(
            std::fs::metadata(dest.join("base.apk")).unwrap().len(),
            8192
        );
        assert_eq!(std::fs::metadata(src).unwrap().len(), 10000);
        assert!(g.receipt().partial);
        drop(g);
        std::fs::remove_dir_all(root).unwrap();
    }
}
