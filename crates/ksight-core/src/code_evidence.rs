//! Exact complete-byte APK member reuse. Raw APKs and existing evidence stay untouched.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

pub(crate) fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(crate) fn apk_hash(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    if file.metadata()?.len() > 512 * 1024 * 1024 {
        return Err(io::Error::other("APK fingerprint budget exceeded"));
    }
    let mut hash = Sha256::new();
    let mut block = vec![0_u8; 65_536];
    loop {
        let n = file.read(&mut block)?;
        if n == 0 {
            break;
        }
        hash.update(&block[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn same_file(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    let mut file = fs::File::open(path)?;
    if file.metadata()?.len() != bytes.len() as u64 {
        return Ok(false);
    }
    let mut buffer = vec![0_u8; 65_536];
    let mut offset = 0;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            return Ok(offset == bytes.len());
        }
        if offset + n > bytes.len() || bytes[offset..offset + n] != buffer[..n] {
            return Ok(false);
        }
        offset += n;
    }
}

// Never unlink an old target. A collision must be byte-identical, including its tail.
fn exclusive(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if path.exists() {
        return if same_file(path, bytes)? {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "evidence content conflict",
            ))
        };
    }
    let temporary = path.with_extension(format!("pending-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        crate::output_budget::charge(&temporary, bytes.len() as u64)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        match fs::hard_link(&temporary, path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && same_file(path, bytes)? => Ok(()),
            Err(e) => Err(e),
        }
    })();
    if result.is_err() {
        crate::output_budget::record_failure(&temporary, "code_evidence_output_failed");
    }
    let _ = fs::remove_file(temporary);
    result
}

pub(crate) fn retain(
    root: &Path,
    target: &Path,
    bytes: &[u8],
    source: &Value,
    raw_hash: &str,
    transform: &str,
) -> io::Result<()> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| io::Error::other("target outside evidence root"))?;
    fs::create_dir_all(root.join("code-objects"))?;
    fs::create_dir_all(root.join("code-evidence"))?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let digest = hash(bytes);
    let object_relative = format!("code-objects/{digest}.bin");
    let object = root.join(&object_relative);
    let reused = object.exists();
    exclusive(&object, bytes)?;
    let result = if target.exists() {
        if same_file(target, bytes)? {
            Ok("existing_verified")
        } else {
            Err(io::Error::other("existing evidence content conflict"))
        }
    } else {
        fs::hard_link(&object, target).map(|()| "hard_link")
    };
    let status = result.as_ref().copied().unwrap_or("write_failed");
    let observation = json!({"schema":"kernsight.apk-member-evidence/v1", "source":source,
        "source_complete":true, "raw_member_sha256":raw_hash, "sha256":digest,
        "bytes":bytes.len(), "relative_path":relative.to_string_lossy(), "object_path":object_relative,
        "transformation":transform, "object_reused":reused, "write_status":status,
        "ownership":{"category":"unknown","confidence":0,"reasons":["APK member identity is content provenance, not business ownership"]}});
    exclusive(
        &root
            .join("code-evidence")
            .join(format!("member-{}.json", uuid::Uuid::new_v4())),
        &serde_json::to_vec_pretty(&observation)?,
    )?;
    result.map(|_| ())
}

