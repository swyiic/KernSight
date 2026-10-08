//! Conservative positive proof. Legacy or ambiguous partials remain blocked.
use anyhow::{bail, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufReader, Read},
    path::Path,
};

fn check_note(
    note: &Value,
    package: &str,
    expected: &[crate::qualified_code::SourceIdentity],
) -> Result<usize> {
    let rows = note["records"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("missing ranges"))?;
    let source: crate::qualified_code::SourceIdentity =
        serde_json::from_value(note["source"].clone())?;
    source.validate()?;
    if !expected.contains(&source)
        || source.package != package
        || note["schema"] != "kernsight.bound-code-copy/v1"
        || note["paused"] != false
        || note["candidate_result"]["budget_stop"] != false
        || rows.is_empty()
        || rows.len() > 65536
        || note["candidate_result"]["attempted"].as_u64() != Some(rows.len() as u64)
    {
        bail!("unknown bound coverage");
    }
    let gap = &note["candidate_result"]["unattempted_state"];
    if gap != "none"
        && !(gap == "not_attempted_parent_deadline"
            && note["candidate_result"]["stop_scope"] == "local_copy_window")
    {
        bail!("parent or unknown stop");
    }
    for row in rows {
        let read = &row["read"];
        let selected = row["selection_limit_bytes"].as_u64().unwrap_or(0);
        if row["source"] != note["source"]
            || row["admitted"] != true
            || read["admission"] != "qualified_live_copy"
            || read["read_status"] != "complete"
            || read["write_status"] != "complete"
            || !read["read_error"].is_null()
            || !read["write_error"].is_null()
            || selected == 0
            || read["actual_length"].as_u64() != Some(selected)
            || read["requested_length"].as_u64() != Some(selected)
            || !matches!(
                row["selection_limit_reason"].as_str(),
                Some(
                    "full_mapping_selected"
                        | "per_range_cap"
                        | "runtime_payload_budget_metadata_reserve"
                )
            )
        {
            bail!("unverified range or IO/identity failure");
        }
    }
    Ok(rows.len())
}

#[derive(Deserialize)]
struct CatalogHeader {
    schema_version: String,
    package: String,
    dump_id: uuid::Uuid,
    agent_version: String,
    artifacts: Vec<serde::de::IgnoredAny>,
    mapped_code: serde::de::IgnoredAny,
    warnings: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    collection_status: Option<String>,
}

/// Validate the completed catalog and bounded original producer receipts.
/// # Errors
/// Missing, malformed, foreign, IO, parent-stop and legacy receipts fail closed.
pub fn proof(
    root: &Path,
    package: &str,
    expected: &[crate::qualified_code::SourceIdentity],
) -> Result<Value> {
    if !ksight_core::output_budget::bound_coverage_only(root) {
        bail!("not coverage-only");
    }
    if expected.is_empty() {
        bail!("missing source grants");
    }
    let path = root.join("dump-report.json");
    let mut file = fs::File::open(&path)?;
    let before = file.metadata()?;
    let size = before.len();
    if !(1..=64 * 1024 * 1024).contains(&size) {
        bail!("catalog bound");
    }
    let mut reader = CheckedReader {
        file: &mut file,
        root,
        remaining: size + 1,
        count: 0,
        hash: Sha256::new(),
    };
    let mut de = serde_json::Deserializer::from_reader(BufReader::new(&mut reader));
    let header = CatalogHeader::deserialize(&mut de)?;
    de.end()?;
    drop(de);
    if reader.count != size {
        bail!("catalog length changed");
    }
    let catalog_hash = reader.hash.clone();
    let after = file.metadata()?;
    if before.len() != after.len()
        || before.modified()? != after.modified()?
        || !same_file(&before, &after)
        || !same_file(&before, &fs::metadata(&path)?)
    {
        bail!("catalog changed");
    }
    if header.schema_version != crate::dump::PACKAGE_DUMP_SCHEMA
        || header.package != package
        || header.dump_id.is_nil()
        || header.agent_version.is_empty()
        || header.collection_status.is_some()
        || header.artifacts.is_empty()
    {
        bail!("foreign or fallback catalog");
    }
    let _ = (header.mapped_code, header.warnings);
    let mut notes = Vec::new();
    for entry in fs::read_dir(root.join("runtime"))? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("bound-source-") && name.ends_with(".json") {
            notes.push(entry.path());
        }
        if notes.len() > 16 {
            bail!("bound note count");
        }
    }
    notes.sort();
    if notes.is_empty() {
        bail!("missing bound proof");
    }
    let mut notes_hash = Sha256::new();
    let mut ranges = 0usize;
    for path in &notes {
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(256 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 256 * 1024 {
            bail!("bound note size");
        }
        let note: Value = serde_json::from_slice(&bytes)?;
        ranges += check_note(&note, package, expected)?;
        notes_hash.update((bytes.len() as u64).to_le_bytes());
        notes_hash.update(&bytes);
    }
    if !ksight_core::output_budget::bound_coverage_only(root) {
        bail!("deadline or subsequent failure");
    }
    Ok(
        json!({"schema":"kernsight.dump-coverage/v1","classification":"coverage_only","package":package,
        "catalog_complete":true,"catalog_bytes":size,"catalog_sha256":format!("{:x}",catalog_hash.finalize()),
        "bound_notes":notes.len(),"bound_notes_sha256":format!("{:x}",notes_hash.finalize()),"admitted_ranges":ranges}),
    )
}
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    #[cfg(not(unix))]
    {
        a.len() == b.len()
    }
}
struct CheckedReader<'a> {
    file: &'a mut fs::File,
    root: &'a Path,
    remaining: u64,
    count: u64,
    hash: Sha256,
}
impl Read for CheckedReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !ksight_core::output_budget::bound_coverage_only(self.root) {
            return Err(std::io::Error::other("parent deadline or unsafe failure"));
        }
        if self.remaining == 0 {
            return Ok(0);
        }
        let limit = buf
            .len()
            .min(64 * 1024)
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let n = self.file.read(&mut buf[..limit])?;
        self.remaining -= n as u64;
        self.count += n as u64;
        self.hash.update(&buf[..n]);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn note() -> Value {
        json!({"schema":"kernsight.bound-code-copy/v1","source":{"package":"test.app","pid":1,"uid":10001,"birth_ns":1,"exec_id":1,"boot_id":"test-boot"},"paused":false,"candidate_result":{"budget_stop":false,"attempted":1,"unattempted_state":"not_attempted_parent_deadline","stop_scope":"local_copy_window"},"records":[]})
    }
    #[test]
    fn incomplete_or_ambiguous_receipts_fail_closed() {
        let mut n = note();
        let expected = vec![serde_json::from_value(n["source"].clone()).unwrap()];
        assert!(check_note(&n, "test.app", &expected).is_err());
        let source = n["source"].clone();
        n["records"] = json!([{"source":source,"admitted":true,"selection_limit_bytes":1,"selection_limit_reason":"per_range_cap","read":{"admission":"qualified_live_copy","read_status":"complete","write_status":"complete","read_error":null,"write_error":null,"actual_length":1,"requested_length":1}}]);
        assert!(check_note(&n, "test.app", &expected).is_ok());
        for (field, value) in [
            ("admission", json!("rejected_generation_after_read")),
            ("read_status", json!("read_failed")),
            ("write_status", json!("write_failed")),
            ("actual_length", json!(0)),
            ("write_error", json!("IO")),
        ] {
            let mut bad = n.clone();
            bad["records"][0]["read"][field] = value;
            assert!(check_note(&bad, "test.app", &expected).is_err());
        }
        n["candidate_result"]["stop_scope"] = Value::Null;
        assert!(check_note(&n, "test.app", &expected).is_err());
    }

    #[test]
    fn complete_catalog_and_original_source_required_and_later_io_revokes_proof() {
        let root = std::env::temp_dir().join(format!("dump-proof-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(root.join("runtime")).unwrap();
        let _guard =
            ksight_core::output_budget::Guard::install(vec![root.clone()], 1024 * 1024, 10000)
                .unwrap();
        let mut n = note();
        let source = n["source"].clone();
        n["records"] = json!([{"source":source,"admitted":true,"selection_limit_bytes":1,"selection_limit_reason":"per_range_cap","read":{"admission":"qualified_live_copy","read_status":"complete","write_status":"complete","read_error":null,"write_error":null,"actual_length":1,"requested_length":1}}]);
        let expected = vec![serde_json::from_value(n["source"].clone()).unwrap()];
        fs::write(
            root.join("runtime/bound-source-test.json"),
            serde_json::to_vec(&n).unwrap(),
        )
        .unwrap();
        let catalog = json!({"schema_version":crate::dump::PACKAGE_DUMP_SCHEMA,"package":"test.app","dump_id":uuid::Uuid::new_v4(),"agent_version":"test","artifacts":[{}],"mapped_code":[],"warnings":[]});
        fs::write(
            root.join("dump-report.json"),
            serde_json::to_vec(&catalog).unwrap(),
        )
        .unwrap();
        ksight_core::output_budget::record_failure(&root, "bound_code_copy_partial");
        assert!(proof(&root, "test.app", &expected).is_ok());
        assert!(proof(&root, "test.app", &[]).is_err());
        let mut foreign = expected.clone();
        foreign[0].birth_ns += 1;
        assert!(proof(&root, "test.app", &foreign).is_err());
        let mut fallback = catalog.clone();
        fallback["collection_status"] = json!("partial");
        fs::write(
            root.join("dump-report.json"),
            serde_json::to_vec(&fallback).unwrap(),
        )
        .unwrap();
        assert!(proof(&root, "test.app", &expected).is_err());
        fs::write(root.join("dump-report.json"), b"{\"package\":").unwrap();
        assert!(proof(&root, "test.app", &expected).is_err());
        fs::write(
            root.join("dump-report.json"),
            serde_json::to_vec(&catalog).unwrap(),
        )
        .unwrap();
        ksight_core::output_budget::record_failure(&root, "output_io_failed");
        assert_eq!(
            ksight_core::output_budget::stop_reason(&root).as_deref(),
            Some("bound_code_copy_partial")
        );
        assert!(proof(&root, "test.app", &expected).is_err());
        // Only disposable synthetic fixtures, never captured evidence.
        fs::remove_dir_all(root).unwrap();
    }
}
