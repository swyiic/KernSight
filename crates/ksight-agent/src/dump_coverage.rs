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

const BOUND_NOTE_LIMIT: usize = 2 * 1024 * 1024;
const BOUND_NOTES_TOTAL_LIMIT: usize = 8 * 1024 * 1024;

fn read_bound_note(reader: impl Read, total: &mut usize) -> Result<Vec<u8>> {
    let remaining = BOUND_NOTES_TOTAL_LIMIT
        .checked_sub(*total)
        .ok_or_else(|| anyhow::anyhow!("bound notes total size"))?;
    let read_limit = BOUND_NOTE_LIMIT.min(remaining);
    let mut bytes = Vec::new();
    reader
        .take((read_limit as u64) + 1)
        .read_to_end(&mut bytes)?;
    let next = total
        .checked_add(bytes.len())
        .ok_or_else(|| anyhow::anyhow!("bound notes length overflow"))?;
    if bytes.len() > BOUND_NOTE_LIMIT || next > BOUND_NOTES_TOTAL_LIMIT {
        bail!("bound note size or total size");
    }
    *total = next;
    Ok(bytes)
}

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
            && read["read_error"] == "local_copy_window_exhausted"
            && ((read["admission"] == "rejected_identity_or_deadline"
                    && matches!(read["read_status"].as_str(), Some("interrupted" | "complete")))
                // copy_range's initial current() check uses these generic states
                // even for a local-window stop before the first read. The exact
                // reason and positive post-copy checks above still gate exclusion.
                || (read["admission"] == "rejected_identity"
                    && read["read_status"] == "not_attempted"
                    && read["actual_length"].as_u64() == Some(0)
                    && read.get("sha256").is_some_and(Value::is_null)))
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
    let mut note_bytes = 0usize;
    for path in &notes {
        let bytes = read_bound_note(fs::File::open(path)?, &mut note_bytes)?;
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

#[cfg(test)]
mod zero_window_tests {
    use super::*;
    fn fixture() -> Value {
        let source = json!({"package":"test.app","pid":1,"uid":10001,"birth_ns":1,"exec_id":1,"boot_id":"test-boot"});
        json!({"schema":"kernsight.bound-code-copy/v1","source":source,"paused":false,"candidate_result":{"budget_stop":false,"attempted":2,"unattempted_state":"not_attempted_parent_deadline","stop_scope":"local_copy_window"},"records":[{"source":source,"admitted":true,"selection_limit_bytes":16,"selection_limit_reason":"per_range_cap","read":{"admission":"qualified_live_copy","read_status":"complete","write_status":"complete","read_error":null,"write_error":null,"actual_length":16,"requested_length":16}},{"source":source,"admitted":false,"excluded_local_window":true,"post_copy_source_verified":true,"mapping_revalidated":true,"raw_evidence":"original.pending","selection_limit_bytes":16,"selection_limit_reason":"per_range_cap","read":{"admission":"rejected_identity","read_status":"not_attempted","write_status":"complete","read_error":"local_copy_window_exhausted","write_error":null,"actual_length":0,"requested_length":16,"sha256":null}}]})
    }
    #[test]
    fn zero_local_window_is_excluded_only_with_all_positive_checks() {
        let note = fixture();
        let expected = vec![serde_json::from_value(note["source"].clone()).unwrap()];
        assert_eq!(check_note(&note, "test.app", &expected).unwrap(), (1, 1, 0));
        for (field, value) in [
            ("actual_length", json!(1)),
            ("read_status", json!("interrupted")),
            ("admission", json!("rejected_generation_after_read")),
            ("read_error", json!("parent_deadline_or_output_exhausted")),
            ("read_error", json!("identity changed")),
            ("read_error", json!("IO")),
            ("write_status", json!("write_failed")),
            ("write_error", json!("sync failed")),
            ("sha256", json!("claimedhash")),
        ] {
            let mut bad = note.clone();
            bad["records"][1]["read"][field] = value;
            assert!(check_note(&bad, "test.app", &expected).is_err(), "{field}");
        }
        for field in [
            "excluded_local_window",
            "post_copy_source_verified",
            "mapping_revalidated",
        ] {
            let mut bad = note.clone();
            bad["records"][1][field] = json!(false);
            assert!(check_note(&bad, "test.app", &expected).is_err(), "{field}");
        }
        let mut bad = note.clone();
        bad["candidate_result"]["budget_stop"] = json!(true);
        assert!(check_note(&bad, "test.app", &expected).is_err());
        let mut bad = note.clone();
        bad["candidate_result"]["stop_scope"] = json!("none_or_parent_budget");
        assert!(check_note(&bad, "test.app", &expected).is_err());
        let mut bad = note.clone();
        bad["records"][1]["source"]["exec_id"] = json!(2);
        assert!(check_note(&bad, "test.app", &expected).is_err());
        let mut bad = note.clone();
        bad["records"].as_array_mut().unwrap().swap(0, 1);
        assert!(check_note(&bad, "test.app", &expected).is_err());
    }
    #[test]
    #[ignore = "explicit retained local note; read-only, no device"]
    fn retained_zero_tail_uses_production_check_without_mutating_note() {
        let path = std::env::var_os("KSIGHT_RETAINED_ZERO_NOTE").unwrap();
        let before = fs::read(&path).unwrap();
        let note: Value = serde_json::from_slice(&before).unwrap();
        let expected = vec![serde_json::from_value(note["source"].clone()).unwrap()];
        assert_eq!(
            check_note(&note, "com.dlxx.mam.Internal", &expected).unwrap(),
            (166, 1, 0)
        );
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[cfg(test)]
mod note_cap_tests {
    use super::*;
    #[test]
    fn per_note_and_aggregate_bounds_are_inclusive_and_fail_closed() {
        let bytes = vec![b' '; BOUND_NOTE_LIMIT + 1];
        let mut total = 0;
        for _ in 0..4 {
            assert_eq!(
                read_bound_note(&bytes[..BOUND_NOTE_LIMIT], &mut total)
                    .unwrap()
                    .len(),
                BOUND_NOTE_LIMIT
            );
        }
        assert_eq!(total, BOUND_NOTES_TOTAL_LIMIT);
        assert!(read_bound_note(&bytes[..1], &mut total).is_err());
        assert_eq!(total, BOUND_NOTES_TOTAL_LIMIT);
        total = 0;
        assert!(read_bound_note(bytes.as_slice(), &mut total).is_err());
        assert_eq!(total, 0);
        total = BOUND_NOTES_TOTAL_LIMIT - 10;
        assert!(read_bound_note(&bytes[..11], &mut total).is_err());
        assert_eq!(total, BOUND_NOTES_TOTAL_LIMIT - 10);
        total = usize::MAX;
        assert!(read_bound_note(&bytes[..1], &mut total).is_err());
        assert_eq!(total, usize::MAX);
    }
    #[test]
    fn input_io_failure_is_not_a_valid_note() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("fixture IO failure"))
            }
        }
        let mut total = 123;
        assert!(read_bound_note(Broken, &mut total).is_err());
        assert_eq!(total, 123);
    }
    #[test]
    #[ignore = "explicit retained local zero-tail note; no device"]
    fn retained_175_ranges_note_uses_bounded_production_reader_and_predicates() {
        let path = std::env::var_os("KSIGHT_RETAINED_175_NOTE").unwrap();
        let before = fs::read(&path).unwrap();
        assert_eq!(before.len(), 268776);
        let mut total = 0;
        let bytes = read_bound_note(fs::File::open(&path).unwrap(), &mut total).unwrap();
        assert_eq!(total, before.len());
        let note: Value = serde_json::from_slice(&bytes).unwrap();
        let expected = vec![serde_json::from_value(note["source"].clone()).unwrap()];
        assert_eq!(
            check_note(&note, "com.dlxx.mam.Internal", &expected).unwrap(),
            (175, 1, 0)
        );
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}

#[cfg(test)]
mod retained_full_proof_test {
    use super::*;
    #[test]
    #[ignore = "explicit preserved metadata and enrollment paths; offline validator only, no device"]
    fn preserved_catalog_and_175_ranges_use_full_production_proof() {
        let root = std::path::PathBuf::from(std::env::var_os("KSIGHT_OFFLINE_PROOF_ROOT").unwrap());
        let sources =
            std::path::PathBuf::from(std::env::var_os("KSIGHT_OFFLINE_PROOF_SOURCES").unwrap());
        let expected: Vec<crate::qualified_code::SourceIdentity> =
            serde_json::from_slice(&fs::read(&sources).unwrap()).unwrap();
        let mut inputs = vec![root.join("dump-report.json"), sources];
        for e in fs::read_dir(root.join("runtime")).unwrap() {
            let path = e.unwrap().path();
            if path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("bound-source-")
            {
                inputs.push(path);
            }
        }
        let before: Vec<_> = inputs
            .iter()
            .map(|path| {
                let bytes = fs::read(path).unwrap();
                (bytes.len(), format!("{:x}", Sha256::digest(&bytes)))
            })
            .collect();
        // Guard/failure live only in host process memory. No input or receipt writes.
        // This models the recorded coverage-only reason; it never renews capture.
        let guard =
            ksight_core::output_budget::Guard::install(vec![root.clone()], 8 * 1024 * 1024, 60000)
                .unwrap();
        ksight_core::output_budget::record_failure(&root, "bound_code_copy_partial");
        let result = proof(&root, "com.dlxx.mam.Internal", &expected).unwrap();
        assert_eq!(result["admitted_ranges"], 175);
        assert_eq!(result["excluded_local_window_ranges"], 1);
        assert_eq!(result["excluded_local_window_bytes"], 0);
        assert_eq!(guard.receipt().admitted_write_bytes, 0);
        for (path, expected_hash) in inputs.iter().zip(before) {
            let bytes = fs::read(path).unwrap();
            assert_eq!(
                (bytes.len(), format!("{:x}", Sha256::digest(bytes))),
                expected_hash
            );
        }
        println!("OFFLINE_FULL_PROOF {}",serde_json::to_string(&json!({"scope":"independent offline validator; does not upgrade historical physical result or renew parent","proof":result,"input_hashes_unchanged":true,"written_bytes":0})).unwrap());
    }
}
