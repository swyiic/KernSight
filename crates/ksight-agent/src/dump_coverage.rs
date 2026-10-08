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
) -> Result<(usize, usize, u64)> {
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
    let mut admitted = 0;
    let mut excluded = 0;
    let mut excluded_bytes = 0;
    for (index, row) in rows.iter().enumerate() {
        let read = &row["read"];
        let selected = row["selection_limit_bytes"].as_u64().unwrap_or(0);
        if row["source"] != note["source"]
            || selected == 0
            || read["requested_length"].as_u64() != Some(selected)
            || read["write_status"] != "complete"
            || !read["write_error"].is_null()
            || !matches!(
                row["selection_limit_reason"].as_str(),
                Some(
                    "full_mapping_selected"
                        | "per_range_cap"
                        | "runtime_payload_budget_metadata_reserve"
                )
            )
        {
            bail!("unverified source/range or write failure");
        }
        if row["admitted"] == true
            && read["admission"] == "qualified_live_copy"
            && read["read_status"] == "complete"
            && read["read_error"].is_null()
            && read["actual_length"].as_u64() == Some(selected)
        {
            admitted += 1;
        } else if index + 1 == rows.len()
            && excluded == 0
            && row["admitted"] == false
            && row["excluded_local_window"] == true
            && row["post_copy_source_verified"] == true
            && row["mapping_revalidated"] == true
            && read["admission"] == "rejected_identity_or_deadline"
            && read["read_error"] == "local_copy_window_exhausted"
            && matches!(
                read["read_status"].as_str(),
                Some("interrupted" | "complete")
            )
            && read["actual_length"]
                .as_u64()
                .is_some_and(|n| n <= selected)
            && row["raw_evidence"]
                .as_str()
                .is_some_and(|name| name.ends_with(".pending") && !name.contains('/'))
            && note["candidate_result"]["stop_scope"] == "local_copy_window"
        {
            excluded = 1;
            excluded_bytes = read["actual_length"].as_u64().unwrap_or(0);
        } else {
            bail!("unverified range or IO/identity failure");
        }
    }
    Ok((admitted, excluded, excluded_bytes))
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
    let mut excluded = 0usize;
    let mut excluded_bytes = 0u64;
    for path in &notes {
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(256 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 256 * 1024 {
            bail!("bound note size");
        }
        let note: Value = serde_json::from_slice(&bytes)?;
        let counts = check_note(&note, package, expected)?;
        ranges += counts.0;
        excluded += counts.1;
        excluded_bytes += counts.2;
        if excluded > 1 {
            bail!("multiple excluded local ranges");
        }
        notes_hash.update((bytes.len() as u64).to_le_bytes());
        notes_hash.update(&bytes);
    }
    if ranges == 0 || !ksight_core::output_budget::bound_coverage_only(root) {
        bail!("no admitted range, deadline or subsequent failure");
    }
    Ok(
        json!({"schema":"kernsight.dump-coverage/v1","classification":"coverage_only","package":package,
        "catalog_complete":true,"catalog_bytes":size,"catalog_sha256":format!("{:x}",catalog_hash.finalize()),
        "bound_notes":notes.len(),"bound_notes_sha256":format!("{:x}",notes_hash.finalize()),"admitted_ranges":ranges,"excluded_local_window_ranges":excluded,"excluded_local_window_bytes":excluded_bytes,"excluded_scope":"local_copy_window_only; not admitted code coverage"}),
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

    #[test]
    fn only_last_explicit_positive_local_window_gap_is_excluded_not_admitted() {
        let mut n = note();
        let source = n["source"].clone();
        let complete = json!({"source":source,"admitted":true,"selection_limit_bytes":16,"selection_limit_reason":"per_range_cap","read":{"admission":"qualified_live_copy","read_status":"complete","write_status":"complete","read_error":null,"write_error":null,"actual_length":16,"requested_length":16}});
        let excluded = json!({"source":source,"admitted":false,"excluded_local_window":true,"post_copy_source_verified":true,"mapping_revalidated":true,"raw_evidence":"original.pending","selection_limit_bytes":16,"selection_limit_reason":"per_range_cap","read":{"admission":"rejected_identity_or_deadline","read_status":"interrupted","write_status":"complete","read_error":"local_copy_window_exhausted","write_error":null,"actual_length":8,"requested_length":16}});
        n["records"] = json!([complete.clone(), excluded.clone()]);
        n["candidate_result"]["attempted"] = json!(2);
        let expected = vec![serde_json::from_value(n["source"].clone()).unwrap()];
        assert_eq!(check_note(&n, "test.app", &expected).unwrap(), (1, 1, 8));
        assert_eq!(n["records"][1]["admitted"], false);
        assert_eq!(n["records"][1]["raw_evidence"], "original.pending");
        for (field, value) in [
            ("excluded_local_window", Value::Null),
            ("post_copy_source_verified", json!(false)),
            ("mapping_revalidated", json!(false)),
            ("raw_evidence", json!("unexpected.code")),
            ("admitted", json!(true)),
        ] {
            let mut bad = n.clone();
            bad["records"][1][field] = value;
            assert!(check_note(&bad, "test.app", &expected).is_err(), "{field}");
        }
        for (field, value) in [
            ("read_error", json!("parent_deadline_or_output_exhausted")),
            ("read_error", json!("IO")),
            ("admission", json!("rejected_generation_after_read")),
            ("admission", json!("rejected_mapping_changed_or_unknown")),
            ("write_status", json!("write_failed")),
            ("write_error", json!("sync failed")),
        ] {
            let mut bad = n.clone();
            bad["records"][1]["read"][field] = value;
            assert!(check_note(&bad, "test.app", &expected).is_err(), "{field}");
        }
        let mut bad = n.clone();
        bad["candidate_result"]["budget_stop"] = json!(true);
        assert!(check_note(&bad, "test.app", &expected).is_err());
        let mut bad = n.clone();
        bad["records"][1]["source"]["exec_id"] = json!(2);
        assert!(check_note(&bad, "test.app", &expected).is_err());
        let mut bad = n.clone();
        bad["records"][1]["source"]["birth_ns"] = json!(2);
        assert!(check_note(&bad, "test.app", &expected).is_err());
        let mut bad = n.clone();
        bad["records"] = json!([excluded.clone(), complete]);
        assert!(check_note(&bad, "test.app", &expected).is_err());
        let mut bad = n.clone();
        bad["records"] = json!([excluded.clone(), excluded]);
        assert!(check_note(&bad, "test.app", &expected).is_err());
    }
}
