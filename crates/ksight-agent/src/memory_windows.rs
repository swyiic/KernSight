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
