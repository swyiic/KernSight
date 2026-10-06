//! Bounded window evidence; no device operations in tests.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) struct RegionRead {
    pub bytes: Vec<u8>,
    pub evidence: Value,
}
pub(crate) fn read<R: Read + Seek>(input: &mut R, start: u64, want: u64) -> RegionRead {
    let Ok(len) = usize::try_from(want) else {
        return RegionRead {
            bytes: Vec::new(),
            evidence: json!({"schema":"kernsight.memory-read/v1", "requested_start":start, "requested_bytes":want, "actual_start":start, "actual_bytes":0, "read_status":"read_failed", "read_error":"InvalidInput"}),
        };
    };
    let mut bytes = vec![0; len];
    let mut actual = 0;
    let mut error = input.seek(SeekFrom::Start(start)).err();
    if error.is_none() {
        while actual < bytes.len() {
            match input.read(&mut bytes[actual..]) {
                Ok(0) => break,
                Ok(n) => actual += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    error = Some(e);
                    break;
                }
            }
        }
    }
    bytes.truncate(actual);
    let status = if error.is_some() {
        "read_failed"
    } else if actual as u64 != want {
        "short_read"
    } else {
        "complete"
    };
    RegionRead {
        bytes,
        evidence: json!({"schema":"kernsight.memory-read/v1", "requested_start":start, "requested_bytes":want, "actual_start":start, "actual_bytes":actual, "read_status":status, "read_error":error.map(|e| format!("{:?}",e.kind()))}),
    }
}

// Write to a new scratch inode, then exclusively link the complete file. A failed
// write cannot leave a partial file at a content-addressed evidence path.
fn retain(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let scratch = path.with_extension(format!("pending-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&scratch)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        match fs::hard_link(&scratch, path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if fs::read(path)? == bytes {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "evidence content conflict",
                    ))
                }
            }
            Err(error) => Err(error),
        }
    })();
    let _ = fs::remove_file(&scratch); // Only the scratch inode created by this call.
    result
}
pub(crate) fn note(dir: &Path, name: &str, value: &Value) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    // Unique observation identity: a repeated scan must not replace an earlier observation.
    let path = dir.join(format!("{name}-{}.json", uuid::Uuid::new_v4()));
    retain(&path, &serde_json::to_vec_pretty(value)?)
}

#[derive(Clone, Copy)]
pub(crate) struct Window<'a> {
    pub pid: u32,
    pub read: &'a Value,
    pub begin: usize,
    pub requested_bytes: usize,
    pub raw: &'a [u8],
    pub selected: &'a [u8],
}
pub(crate) type WindowKey = (String, String, usize, Vec<u8>, Vec<u8>);

pub(crate) fn save(
    dir: &Path,
    window: Window<'_>,
    seen: &mut BTreeSet<WindowKey>,
) -> io::Result<bool> {
    save_with_note(dir, window, seen, note)
}
fn save_with_note<F>(
    dir: &Path,
    window: Window<'_>,
    seen: &mut BTreeSet<WindowKey>,
    mut write_note: F,
) -> io::Result<bool>
where
    F: FnMut(&Path, &str, &Value) -> io::Result<()>,
{
    let Window {
        pid,
        read,
        begin,
        requested_bytes,
        raw,
        selected,
    } = window;
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "window outside actual read");
    let offset = (selected.as_ptr() as usize)
        .checked_sub(raw.as_ptr() as usize)
        .ok_or_else(invalid)?;
    if raw.get(offset..offset.checked_add(selected.len()).ok_or_else(invalid)?) != Some(selected)
        || raw.len() > requested_bytes
        || begin.checked_add(raw.len()).ok_or_else(invalid)? as u64
            > read["actual_bytes"].as_u64().ok_or_else(invalid)?
    {
        return Err(invalid());
    }
    let start = read["actual_start"]
        .as_u64()
        .ok_or_else(invalid)?
        .checked_add(begin as u64)
        .ok_or_else(invalid)?;
    fs::create_dir_all(dir)?;
    let source_hash = digest(raw);
    let hash = digest(selected);
    let read_status = match read["read_status"].as_str() {
        Some("complete") => "complete",
        Some("short_read") => "short_read",
        Some("read_failed") => "read_failed",
        _ => "unknown",
    };
    let window_status = if raw.len() < requested_bytes {
        "short_read"
    } else {
        "complete"
    };
    let key = (
        read_status.to_owned(),
        window_status.to_owned(),
        requested_bytes,
        raw.to_vec(),
        selected.to_vec(),
    );
    let raw_name = format!("raw-{source_hash}.bin");
    let analysis_name = format!(
        "mem-{pid}-{hash}-{source_hash}-{read_status}-{window_status}-{requested_bytes}.txt"
    );
    // Existing bytes alone do not prove a previous successful evidence commit.
    let committed = fs::read_dir(dir)?.flatten().any(|entry| {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json")
            || entry
                .metadata()
                .map(|m| m.len() > 256 * 1024)
                .unwrap_or(true)
        {
            return false;
        }
        let Some(value) = fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        else {
            return false;
        };
        value["schema"] == "kernsight.memory-window/v1"
            && value["write_status"] == "retained"
            && value["relative_path"] == analysis_name
            && value["sha256"] == hash
            && value["read"]["read_status"] == read_status
            && value["window_status"] == window_status
            && value["requested_bytes"] == requested_bytes
    });
    let duplicate = seen.contains(&key)
        || (committed
            && fs::read(dir.join(&analysis_name))
                .map(|bytes| bytes == selected)
                .unwrap_or(false));
    let mut record = json!({"schema":"kernsight.memory-window/v1", "pid":pid, "read":read, "window_status":window_status, "source_start":start, "source_bytes":raw.len(), "requested_start":start, "requested_bytes":requested_bytes, "actual_bytes":raw.len(), "source_relative_path":raw_name, "source_sha256":source_hash, "relative_path":analysis_name, "sha256":hash, "derived_offset":offset, "derived_bytes":selected.len(), "transformation":"trim_nul_padding/v1", "parse_status":"unparsed", "duplicate":duplicate, "write_status":"retained"});
    let result = retain(&dir.join(&raw_name), raw)
        .and_then(|()| retain(&dir.join(&analysis_name), selected));
    if let Err(error) = result {
        record["write_status"] = json!("write_failed");
        record["write_error"] = json!(format!("{:?}", error.kind()));
        write_note(dir, "window", &record)?;
        return Err(error);
    }
    write_note(dir, "window", &record)?;
    seen.insert(key);
    Ok(!duplicate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    macro_rules! save {
        ($dir:expr, $pid:expr, $read:expr, $begin:expr, $requested:expr, $raw:expr, $selected:expr, $seen:expr) => {
            super::save(
                $dir,
                Window {
                    pid: $pid,
                    read: $read,
                    begin: $begin,
                    requested_bytes: $requested,
                    raw: $raw,
                    selected: $selected,
                },
                $seen,
            )
        };
    }
    #[test]
    fn memory_window_production_tail_and_duplicate() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let a = vec![b'a'; 128];
        let mut b = a.clone();
        b[127] = b'b';
        let r = read(&mut Cursor::new(a.clone()), 0, 128);
        let mut seen = BTreeSet::new();
        assert!(save!(&dir, 1, &r.evidence, 0, a.len(), &a, &a, &mut seen).unwrap());
        assert!(save!(&dir, 1, &r.evidence, 0, b.len(), &b, &b, &mut seen).unwrap());
        assert!(!save!(&dir, 1, &r.evidence, 0, a.len(), &a, &a, &mut seen).unwrap());
        seen.clear();
        assert!(!save!(&dir, 1, &r.evidence, 0, a.len(), &a, &a, &mut seen).unwrap());
        assert_eq!(
            fs::read(dir.join(format!("raw-{}.bin", digest(&a)))).unwrap(),
            a
        );
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn memory_window_production_parser_keeps_pid_and_ignores_notes() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let raw = b"GET /fixture HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let r = read(&mut Cursor::new(raw), 0, raw.len() as u64);
        let mut seen = BTreeSet::new();
        assert!(save!(&dir, 73, &r.evidence, 0, raw.len(), raw, raw, &mut seen).unwrap());
        for i in 0..300 {
            fs::write(dir.join(format!("window-{i}.json")), b"{}").unwrap();
        }
        let calls = ksight_core::http_calls_from_plaintext_dir(&dir, "fixture");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].process_id, 73);
        fs::remove_dir_all(dir).unwrap();
    }

    fn records(dir: &Path) -> Vec<Value> {
        fs::read_dir(dir)
            .unwrap()
            .flatten()
            .filter_map(|entry| {
                let path = entry.path();
                if path.extension()?.to_str()? != "json" {
                    return None;
                }
                serde_json::from_slice(&fs::read(path).ok()?).ok()
            })
            .collect()
    }
    #[test]
    fn memory_window_partial_complete_and_source_ranges() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let raw = b"abc\0\0";
        let partial = read(&mut Cursor::new(raw), 0, 12);
        let complete = read(&mut Cursor::new(raw), 0, 5);
        let mut seen = BTreeSet::new();
        assert!(save!(&dir, 1, &partial.evidence, 0, 12, raw, &raw[..3], &mut seen).unwrap());
        // Identical saved bytes and window request, differing mapping completeness.
        assert!(save!(&dir, 1, &partial.evidence, 0, 5, raw, &raw[..3], &mut seen).unwrap());
        assert!(save!(&dir, 1, &complete.evidence, 0, 5, raw, &raw[..3], &mut seen).unwrap());
        let mut other = complete.evidence.clone();
        other["actual_start"] = json!(4096);
        other["requested_start"] = json!(4096);
        assert!(!save!(&dir, 1, &other, 0, 5, raw, &raw[..3], &mut seen).unwrap());
        let notes = records(&dir);
        assert_eq!(notes.len(), 4);
        assert!(notes
            .iter()
            .any(|note| note["source_start"] == 4096 && note["duplicate"] == true));
        assert!(notes
            .iter()
            .any(|note| note["window_status"] == "short_read" && note["requested_bytes"] == 12));
        for note in notes {
            let saved_raw =
                fs::read(dir.join(note["source_relative_path"].as_str().unwrap())).unwrap();
            let saved_derived =
                fs::read(dir.join(note["relative_path"].as_str().unwrap())).unwrap();
            assert_eq!(note["actual_bytes"], saved_raw.len());
            assert_eq!(note["source_bytes"], saved_raw.len());
            assert_eq!(note["source_sha256"], digest(&saved_raw));
            assert_eq!(note["sha256"], digest(&saved_derived));
            let offset = usize::try_from(note["derived_offset"].as_u64().unwrap()).unwrap();
            assert_eq!(
                &saved_raw[offset..offset + saved_derived.len()],
                saved_derived
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn memory_window_metadata_failure_retry_does_not_pollute_dedup() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let raw = b"abc";
        let r = read(&mut Cursor::new(raw), 0, 3);
        let mut seen = BTreeSet::new();
        let window = || Window {
            pid: 1,
            read: &r.evidence,
            begin: 0,
            requested_bytes: 3,
            raw,
            selected: raw,
        };
        assert!(
            save_with_note(&dir, window(), &mut seen, |_, _, _| Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected metadata failure"
            )))
            .is_err()
        );
        assert!(seen.is_empty());
        assert!(records(&dir).is_empty());
        assert!(super::save(&dir, window(), &mut seen).unwrap());
        assert!(!super::save(&dir, window(), &mut BTreeSet::new()).unwrap());
        fs::remove_dir_all(dir).unwrap();
    }
    pub(super) struct FailingRead {
        pub inner: Cursor<Vec<u8>>,
        pub failed: bool,
    }
    impl Seek for FailingRead {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }
    impl Read for FailingRead {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.failed {
                return Err(io::Error::other("injected read failure"));
            }
            self.failed = true;
            self.inner.read(bytes)
        }
    }
    #[test]
    fn memory_window_error_after_prefix_is_separate_from_short_and_complete() {
        let mut input = FailingRead {
            inner: Cursor::new(b"abc".to_vec()),
            failed: false,
        };
        let failed = read(&mut input, 0, 8);
        assert_eq!(failed.bytes, b"abc");
        assert_eq!(failed.evidence["read_status"], "read_failed");
        assert_eq!(failed.evidence["actual_bytes"], 3);
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        let mut seen = BTreeSet::new();
        assert!(save!(
            &dir,
            1,
            &failed.evidence,
            0,
            8,
            &failed.bytes,
            &failed.bytes,
            &mut seen
        )
        .unwrap());
        let short = read(&mut Cursor::new(b"abc"), 0, 8);
        assert!(save!(
            &dir,
            1,
            &short.evidence,
            0,
            8,
            &short.bytes,
            &short.bytes,
            &mut seen
        )
        .unwrap());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn memory_window_short_read_and_failure() {
        let r = read(&mut Cursor::new(vec![1; 7]), 0, 12);
        assert_eq!(r.bytes.len(), 7);
        assert_eq!(r.evidence["requested_bytes"], 12);
        assert_eq!(r.evidence["read_status"], "short_read");
        let mut file = std::fs::File::open(std::env::temp_dir()).unwrap();
        let r = read(&mut file, 0, 12);
        assert_eq!(r.evidence["read_status"], "read_failed");
        assert_eq!(r.evidence["actual_bytes"], 0);
    }
    #[test]
    fn memory_window_write_failure_and_raw_derivation() {
        let dir = std::env::temp_dir().join(uuid::Uuid::new_v4().to_string());
        fs::create_dir(&dir).unwrap();
        let raw = b"abc\0\0";
        let selected = &raw[..3];
        let r = read(&mut Cursor::new(raw), 0, 5);
        let mut seen = BTreeSet::new();
        fs::create_dir(dir.join(format!(
            "mem-1-{}-{}-complete-complete-5.txt",
            digest(selected),
            digest(raw)
        )))
        .unwrap();
        assert!(save!(&dir, 1, &r.evidence, 0, raw.len(), raw, selected, &mut seen).is_err());
        assert!(seen.is_empty());
        let records: Vec<Value> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| {
                let p = e.ok()?.path();
                if p.extension()?.to_str()? != "json" {
                    return None;
                }
                serde_json::from_slice(&fs::read(p).ok()?).ok()
            })
            .collect();
        assert_eq!(records[0]["write_status"], "write_failed");
        fs::remove_dir_all(dir.join(format!(
            "mem-1-{}-{}-complete-complete-5.txt",
            digest(selected),
            digest(raw)
        )))
        .unwrap();
        assert!(save!(&dir, 1, &r.evidence, 0, raw.len(), raw, selected, &mut seen).unwrap());
        assert_eq!(
            fs::read(dir.join(format!("raw-{}.bin", digest(raw)))).unwrap(),
            raw
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
