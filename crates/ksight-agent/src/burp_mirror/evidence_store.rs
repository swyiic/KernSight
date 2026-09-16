//! Bounded, append-only reconstructed-message evidence, independent of Burp delivery.
//! A final .json file commits a record. Entity bytes are not raw TLS/frame bytes.

use ksight_core::MirroredMessage;
use sha2::{Digest, Sha256};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const SESSION_BUDGET: u64 = 256 * 1024 * 1024;

pub(super) struct EvidenceStore {
    directory: PathBuf,
    used: u64,
    budget: u64,
    initialized: bool,
}

impl EvidenceStore {
    pub(super) fn new(root: &Path, session: &str) -> Self {
        let key = format!("{:x}", Sha256::digest(session.as_bytes()));
        Self {
            directory: root.join(key),
            used: 0,
            budget: SESSION_BUDGET,
            initialized: false,
        }
    }

    fn initialize(&mut self) -> io::Result<()> {
        if self.initialized {
            return Ok(());
        }
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.directory)?;
        if fs::symlink_metadata(&self.directory)?
            .file_type()
            .is_symlink()
        {
            return Err(io::Error::other("evidence_directory_symlink"));
        }
        for item in fs::read_dir(&self.directory)? {
            self.used = self.used.saturating_add(item?.metadata()?.len());
        }
        self.initialized = true;
        Ok(())
    }

    fn write_new(&mut self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.directory.join(name))?;
        // Reserve conservatively even on partial I/O failure. Never evict prior evidence.
        self.used = self.used.saturating_add(bytes.len() as u64);
        file.write_all(bytes)?;
        file.sync_all()
    }

    pub(super) fn save(
        &mut self,
        request: &MirroredMessage,
        response: Option<&MirroredMessage>,
    ) -> io::Result<PathBuf> {
        self.initialize()?;
        let id = uuid::Uuid::new_v4().to_string();
        let mut entries = Vec::new();
        let mut files = Vec::new();
        for (side, message) in [("request", Some(request)), ("response", response)] {
            let Some(message) = message else {
                continue;
            };
            let original = message
                .evidence
                .original_entity
                .as_deref()
                .unwrap_or(&message.body);
            let original_name = format!("{id}-{side}.entity");
            files.push((original_name.clone(), original));
            let display_name = if original != message.body {
                let name = format!("{id}-{side}.display");
                files.push((name.clone(), message.body.as_slice()));
                name
            } else {
                original_name.clone()
            };
            entries.push(serde_json::json!({
                "side": side, "evidence": message.evidence,
                "observed_status": message.status, "headers": message.headers,
                "display_host": message.host, "display_path": message.path,
                "original_entity": original_name, "display_entity": display_name,
                "original_entity_bytes": original.len(),
                "original_entity_sha256": format!("{:x}", Sha256::digest(original)),
                "display_entity_sha256": format!("{:x}", Sha256::digest(&message.body)),
            }));
        }
        let metadata = serde_json::to_vec(&serde_json::json!({
            "schema_version": "kernsight.mirror-artifact/v1",
            "stage": "reconstructed_entity_not_raw_transport",
            "delivery_state": "not_recorded_here", "messages": entries,
        }))?;
        let required = files.iter().fold(metadata.len() as u64, |n, (_, data)| {
            n.saturating_add(data.len() as u64)
        });
        if self.used.saturating_add(required) > self.budget {
            return Err(io::Error::other(
                "evidence_budget_exceeded: existing evidence retained",
            ));
        }
        for (name, data) in files {
            self.write_new(&name, data)?;
        }
        let pending = format!("{id}.pending");
        self.write_new(&pending, &metadata)?;
        let final_path = self.directory.join(format!("{id}.json"));
        fs::rename(self.directory.join(pending), &final_path)?;
        fs::File::open(&self.directory)?.sync_all()?;
        Ok(final_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_entity_is_durable_and_budget_never_evicts() {
        let root =
            std::env::temp_dir().join(format!("ksight-evidence-test-{}", uuid::Uuid::new_v4()));
        let mut store = EvidenceStore::new(&root, "../untrusted-session");
        let mut request = ksight_core::StreamReassembler::default()
            .push(b"POST /test HTTP/1.1\r\nHost: fixture.example\r\nContent-Length: 2\r\n\r\nok")
            .remove(0);
        request.evidence.original_entity = Some(vec![0, 1, 2]);
        let path = store.save(&request, None).unwrap();
        let metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let entry = &metadata["messages"][0];
        let original = path
            .parent()
            .unwrap()
            .join(entry["original_entity"].as_str().unwrap());
        assert_eq!(fs::read(&original).unwrap(), [0, 1, 2]);
        store.budget = store.used;
        assert!(store
            .save(&request, None)
            .unwrap_err()
            .to_string()
            .contains("budget_exceeded"));
        assert!(path.exists() && original.exists());
        // Only this test's UUID-owned temporary directory is removed.
        fs::remove_dir_all(root).unwrap();
    }
}
