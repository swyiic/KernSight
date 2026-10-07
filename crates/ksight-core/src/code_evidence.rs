//! Exact complete-byte APK member reuse. Raw APKs and existing evidence stay untouched.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Seek, Write},
    path::Path,
};

pub(crate) fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
const MAX_APK_FINGERPRINT_BYTES: u64 = 1024 * 1024 * 1024;

pub(crate) fn apk_hash(
    path: &Path,
    evidence_root: &Path,
) -> io::Result<(String, fs::File, fs::Metadata)> {
    use std::time::{Duration, Instant};
    let mut file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::other("APK fingerprint requires a regular file"));
    }
    let length = metadata.len();
    if length > MAX_APK_FINGERPRINT_BYTES {
        return Err(io::Error::other("APK fingerprint input exceeds 1GiB bound"));
    }
    let deadline =
        crate::output_budget::deadline(evidence_root, Instant::now() + Duration::from_secs(60));
    let mut hash = Sha256::new();
    let mut block = vec![0_u8; 65_536];
    let mut read_bytes = 0_u64;
    loop {
        if crate::output_budget::should_stop(evidence_root) || Instant::now() >= deadline {
            crate::output_budget::record_failure(evidence_root, "apk_fingerprint_interrupted");
            return Err(io::Error::other(
                "APK fingerprint deadline or parent budget interrupted",
            ));
        }
        let n = file.read(&mut block)?;
        if n == 0 {
            break;
        }
        read_bytes = read_bytes
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::other("APK fingerprint byte overflow"))?;
        if read_bytes > length || read_bytes > MAX_APK_FINGERPRINT_BYTES {
            return Err(io::Error::other("APK changed while fingerprinting"));
        }
        hash.update(&block[..n]);
    }
    if read_bytes != length {
        return Err(io::Error::other("APK changed while fingerprinting"));
    }
    verify_apk_identity(&file, &metadata)?;
    file.rewind()?;
    Ok((format!("{:x}", hash.finalize()), file, metadata))
}

/// Verify the retained handle after extraction; a changed APK never returns success.
pub(crate) fn verify_apk_identity(file: &fs::File, before: &fs::Metadata) -> io::Result<()> {
    let after = file.metadata()?;
    let mut changed = after.len() != before.len() || after.modified()? != before.modified()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        changed |= after.dev() != before.dev()
            || after.ino() != before.ino()
            || after.ctime() != before.ctime()
            || after.ctime_nsec() != before.ctime_nsec();
    }
    if changed {
        return Err(io::Error::other(
            "APK changed while fingerprinting or extracting",
        ));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("ksight-apk-hash-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn apk(&self, len: u64) -> std::path::PathBuf {
            let p = self.0.join("fixture.apk");
            fs::File::create(&p).unwrap().set_len(len).unwrap();
            p
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn apk_hash_includes_the_byte_beyond_old_512mib_limit() {
        use std::io::{Seek, SeekFrom};
        let f = Fixture::new();
        let p = f.apk(512 * 1024 * 1024 + 1);
        let mut file = OpenOptions::new().write(true).open(&p).unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&[1]).unwrap();
        file.sync_all().unwrap();
        // Independently computed complete SHA256 of 512MiB zeroes followed by 0x01.
        assert_eq!(
            apk_hash(&p, &f.0).unwrap().0,
            "bae94e27df354fea71f36769de3a4a563d4e86a285bdec9e94b765c55a20ab95"
        );
    }
    #[test]
    fn apk_hash_still_rejects_input_over_finite_limit() {
        let f = Fixture::new();
        let p = f.apk(MAX_APK_FINGERPRINT_BYTES + 1);
        assert!(apk_hash(&p, &f.0)
            .unwrap_err()
            .to_string()
            .contains("1GiB bound"));
    }
    #[test]
    fn apk_hash_obeys_parent_cancellation_without_releasing_or_spending_quota() {
        let f = Fixture::new();
        let p = f.apk(1024);
        let guard =
            crate::output_budget::Guard::install(vec![f.0.clone()], 1_048_576, 30000).unwrap();
        crate::output_budget::interrupt(&f.0, "parent_cancelled");
        assert!(apk_hash(&p, &f.0)
            .unwrap_err()
            .to_string()
            .contains("interrupted"));
        let receipt = guard.receipt();
        assert!(receipt.partial);
        assert_eq!(receipt.reason.as_deref(), Some("parent_cancelled"));
        assert_eq!(receipt.admitted_write_bytes, 0);
        assert_eq!(receipt.limit_bytes, 1_048_576);
    }
    #[test]
    fn apk_hash_small_complete_input_is_unchanged() {
        let f = Fixture::new();
        let p = f.apk(0);
        fs::write(&p, b"abc").unwrap();
        assert_eq!(
            apk_hash(&p, &f.0).unwrap().0,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
    #[test]
    fn apk_hash_obeys_expired_parent_deadline() {
        let f = Fixture::new();
        let p = f.apk(1024);
        let guard = crate::output_budget::Guard::install(vec![f.0.clone()], 1024, 1).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(3));
        assert!(apk_hash(&p, &f.0).is_err());
        assert_eq!(
            guard.receipt().reason.as_deref(),
            Some("time_budget_exhausted")
        );
    }
    #[test]
    fn apk_hash_obeys_exhausted_parent_quota() {
        let f = Fixture::new();
        let p = f.apk(1024);
        let guard = crate::output_budget::Guard::install(vec![f.0.clone()], 0, 30000).unwrap();
        assert!(apk_hash(&p, &f.0).is_err());
        let receipt = guard.receipt();
        assert_eq!(receipt.reason.as_deref(), Some("output_budget_exhausted"));
        assert_eq!(receipt.admitted_write_bytes, 0);
    }
    #[test]
    fn apk_hash_reuses_original_handle_after_path_replacement() {
        let f = Fixture::new();
        let p = f.apk(0);
        fs::write(&p, b"abc").unwrap();
        let (sha, mut file, metadata) = apk_hash(&p, &f.0).unwrap();
        fs::rename(&p, f.0.join("original.apk")).unwrap();
        fs::write(&p, b"replacement").unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"abc");
        assert_eq!(sha, hash(&bytes));
        // Rename can update ctime: conservatively reject it rather than claim success.
        let _ = verify_apk_identity(&file, &metadata);
    }
    #[test]
    fn apk_identity_rejects_mutation_during_extraction() {
        let f = Fixture::new();
        let p = f.apk(0);
        fs::write(&p, b"abc").unwrap();
        let (_, file, metadata) = apk_hash(&p, &f.0).unwrap();
        fs::write(&p, b"xyz").unwrap();
        assert!(verify_apk_identity(&file, &metadata).is_err());
    }
}
