//! Read-only, bounded full-path inventory for streamed transport.
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};
///
/// # Errors
/// Returns the validation or required operation error; no successful result is fabricated.
/// Inventory retained by this evidence operation.
#[allow(
    clippy::many_single_char_names,
    reason = "Local fixture or owned callback keeps its explicit scope and fallible signature."
)]
pub fn inventory(root: &Path) -> Result<serde_json::Value> {
    if !root.is_absolute() || std::fs::symlink_metadata(root)?.file_type().is_symlink() {
        bail!("invalid evidence root");
    }
    let canonical = root.canonicalize()?;
    let mut queue = vec![canonical.clone()];
    let mut rows = vec![];
    let mut total = 0u64;
    while let Some(dir) = queue.pop() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                bail!("evidence symlink refused");
            }
            let path = entry.path();
            if kind.is_dir() {
                queue.push(path);
                continue;
            }
            if !kind.is_file() {
                bail!("nonregular evidence refused");
            }
            let declared_bytes = entry.metadata()?.len();
            total = total
                .checked_add(declared_bytes)
                .ok_or_else(|| anyhow::anyhow!("inventory overflow"))?;
            if total > 8 * 1024 * 1024 * 1024 || rows.len() >= 100_000 {
                bail!("inventory cap exceeded");
            }
            let mut file = File::open(&path)?;
            let mut hash = Sha256::new();
            let mut count = 0u64;
            let mut buffer = vec![0_u8; 65_536];
            loop {
                let read_count = file.read(&mut buffer)?;
                if read_count == 0 {
                    break;
                }
                count += read_count as u64;
                if count > declared_bytes {
                    bail!("source grew during inventory");
                }
                hash.update(&buffer[..read_count]);
            }
            if count != declared_bytes {
                bail!("source short read during inventory");
            }
            let rel = path
                .strip_prefix(&canonical)?
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("non UTF8 source path"))?;
            rows.push(
                serde_json::json!({"path":rel,"bytes":declared_bytes,"sha256":format!("{:x}",hash.finalize())}),
            );
        }
    }
    Ok(
        serde_json::json!({"schema":"kernsight.evidence-inventory/v1","logical_bytes":total,"files":rows}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inventory_keeps_identical_paths_and_full_tail() {
        let root = std::env::temp_dir().join(format!("inventory-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let a = vec![7u8; 100];
        let mut buffer = a.clone();
        buffer[99] = 8;
        std::fs::write(root.join("a"), &a).unwrap();
        std::fs::write(root.join("buffer"), &buffer).unwrap();
        std::fs::hard_link(root.join("a"), root.join("same")).unwrap();
        let v = inventory(&root).unwrap();
        assert_eq!(v["logical_bytes"], 300);
        assert_eq!(v["files"].as_array().unwrap().len(), 3);
        let hs = v["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["sha256"].as_str().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(hs.len(), 2);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("a"), root.join("escape")).unwrap();
            assert!(inventory(&root).is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
