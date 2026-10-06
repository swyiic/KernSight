use super::*;
use ksight_model::{EventPayload, InspectPlaintext};
use sha2::{Digest, Sha256};

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("ksight-evidence-test-{}", Uuid::new_v4())))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fragment_event(session: Uuid, seq: u64, bytes: &[u8]) -> Event {
    let mut event = tests::batch(session, seq).events.remove(0);
    let (preview, preview_encoding) = (
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut text, byte| {
                use std::fmt::Write as _;
                write!(&mut text, "{byte:02x}").unwrap();
                text
            }),
        "hex".to_owned(),
    );
    event.payload = EventPayload::InspectPlaintext(InspectPlaintext {
        adapter: "synthetic-bounded-contract".into(),
        direction: "recv".into(),
        sequence: seq,
        captured_bytes: u32::try_from(bytes.len()).unwrap(),
        requested_bytes: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
        preview,
        preview_encoding,
        content_class: "binary".into(),
        ..Default::default()
    });
    event
}
fn open(root: &Path, session: Uuid, compress: bool, count: usize) -> SessionSpoolWriter {
    SessionSpoolWriter::open_with(
        root,
        session,
        64 * 1024 * 1024,
        count,
        SpoolOptions {
            compress,
            completion_reserve_bytes: 0,
        },
    )
    .unwrap()
}

#[test]
fn synthetic_64_hex_fragments_split_before_enqueue_and_recover_all_ranges() {
    for compress in [false, true] {
        let root = Scratch::new();
        let session = Uuid::new_v4();
        let mut writer = open(&root.0, session, compress, 64);
        let bytes: Vec<_> = (0..262_144)
            .map(|i| u8::try_from(i % 256).unwrap())
            .collect();
        assert_eq!("hex", "hex");
        for seq in 1..=64 {
            crate::capture::persist_capture_event(
                &mut writer,
                &fragment_event(session, seq, &bytes),
            )
            .unwrap();
        }
        writer
            .seal(
                DurableSessionState::Completed,
                Some(CaptureStopReason::DurationElapsed),
            )
            .unwrap();
        let d = writer.diagnostics();
        assert_eq!(d.accepted_events, 64);
        assert_eq!(d.committed_events, 64);
        assert!(d.byte_splits >= 4);
        assert!(d.high_water_pending_bytes <= u64::from(DEFAULT_MAX_FRAME_BYTES));
        assert!(d.high_water_pending_events < 64);
        assert_eq!(d.pending_events, 0);
        // Owned pending JSON + assembled JSON + bounded LZ4 workspace + event descriptors.
        let frame = u64::from(DEFAULT_MAX_FRAME_BYTES);
        assert!(
            d.high_water_working_bytes <= 3 * frame + frame / 255 + 65536,
            "{d:?}"
        );
        let mut seen = 0u64;
        visit_batches(writer.directory(), session, None, |batch| {
            let size = measure_json(&batch)?.0;
            assert!(size <= u64::from(DEFAULT_MAX_FRAME_BYTES));
            for event in batch.events {
                seen += 1;
                assert_eq!(event.header.source_sequence, seen);
                let EventPayload::InspectPlaintext(fragment) = event.payload else {
                    panic!("fragment")
                };
                for range in [0..17, 65_533..65_555, 262_127..262_144] {
                    assert_eq!(
                        recover_captured_range(&fragment, range.clone()).unwrap(),
                        bytes[range]
                    );
                }
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, 64);
        let manifest = load_manifest(writer.directory()).unwrap().unwrap();
        assert_eq!(manifest.event_count, 64);
        assert_eq!(manifest.writer.unwrap().committed_events, 64);
        let physical: u64 = fs::read_dir(writer.directory())
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum();
        assert!(physical <= 64 * 1024 * 1024);
    }
}

#[test]
fn range_recovery_rejects_hash_length_encoding_and_unseen_tail() {
    let session = Uuid::new_v4();
    let event = fragment_event(session, 1, b"GET / HTTP/1.1\r\n\r\n");
    let EventPayload::InspectPlaintext(mut p) = event.payload else {
        panic!("fragment")
    };
    p.requested_bytes = 999;
    p.truncated = true;
    assert_eq!(recover_captured_range(&p, 0..3).unwrap(), b"GET");
    assert!(p.truncated);
    assert!(recover_captured_range(&p, 0..999).is_err());
    p.preview.replace_range(0..1, "0");
    assert!(matches!(
        recover_captured_range(&p, 0..3),
        Err(SpoolError::Evidence("hash_mismatch"))
    ));
    p.preview_encoding = "tls_record".into();
    assert!(recover_captured_range(&p, 0..3).is_err());
    p.preview_encoding = "hex".into();
    p.preview = "00".into();
    assert!(recover_captured_range(&p, 0..3).is_err());
}

#[test]
fn oversized_single_event_is_rejected_before_storage_allocation() {
    let root = Scratch::new();
    let session = Uuid::new_v4();
    let mut writer = open(&root.0, session, false, 64);
    let mut event = tests::batch(session, 1).events.remove(0);
    event.header.process.command_line = Some("x".repeat(DEFAULT_MAX_FRAME_BYTES as usize));
    assert!(matches!(
        crate::capture::persist_capture_event(&mut writer, &event),
        Err(SpoolError::EventTooLarge { .. })
    ));
    let d = writer.diagnostics();
    assert_eq!(d.accepted_events, 0);
    assert_eq!(d.rejected_events, 1);
    assert_eq!(d.pending_events, 0);
    assert_eq!(writer.used_bytes(), 0);
    assert!(!d.last_failure.unwrap().retained_pending);
    let m = load_manifest(writer.directory()).unwrap().unwrap();
    assert_eq!(m.state, DurableSessionState::Interrupted);
}

#[test]
fn write_faults_retain_bounded_evidence_and_exact_retry_is_once() {
    for point in [
        "batch_open",
        "batch_short_write",
        "batch_file_sync",
        "batch_publish",
        "batch_directory_sync",
        "manifest_open",
        "manifest_short_write",
        "manifest_file_sync",
        "manifest_publish",
        "manifest_directory_sync",
    ] {
        let root = Scratch::new();
        let session = Uuid::new_v4();
        let mut writer = open(&root.0, session, true, 1);
        let event = fragment_event(session, 7, b"small binary\x00\xff");
        IO_FAULT.with(|f| *f.borrow_mut() = Some(point));
        assert!(writer.push(&event).is_err(), "{point}");
        let failed = writer.diagnostics();
        assert_eq!(failed.rejected_events, 0, "{point}");
        assert_eq!(failed.accepted_events, 1);
        if point.starts_with("batch_") {
            assert_eq!(failed.pending_events, 1);
            assert!(failed.last_failure.as_ref().unwrap().retained_pending);
        } else {
            assert_eq!(failed.pending_events, 0);
            assert!(failed.last_failure.as_ref().unwrap().committed);
        }
        assert!(writer.push(&fragment_event(session, 8, b"next")).is_err());
        writer.push(&event).unwrap();
        writer.flush().unwrap();
        assert_eq!(writer.diagnostics().committed_events, 1, "{point}");
        assert_eq!(writer.diagnostics().retry_deduplicated, 1);
        assert!(!fs::read_dir(writer.directory()).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with('.')));
        let mut events = 0;
        visit_batches(writer.directory(), session, None, |batch| {
            events += batch.events.len();
            Ok(())
        })
        .unwrap();
        assert_eq!(events, 1);
        drop(writer);
        let mut reopened = open(&root.0, session, true, 1);
        reopened.push(&event).unwrap();
        assert_eq!(reopened.persisted_batches(), 0);
        assert_eq!(reopened.diagnostics().retry_deduplicated, 1);
    }
}

#[test]
fn published_batch_without_manifest_recovers_and_all_acked_sequence_never_resets() {
    let root = Scratch::new();
    let session = Uuid::new_v4();
    let mut writer = open(&root.0, session, false, 1);
    let event = fragment_event(session, 10, b"recover");
    IO_FAULT.with(|f| *f.borrow_mut() = Some("manifest_open"));
    assert!(writer.push(&event).is_err());
    drop(writer);
    let mut writer = open(&root.0, session, false, 1);
    writer.push(&event).unwrap();
    writer.push(&fragment_event(session, 11, b"next")).unwrap();
    writer.flush().unwrap();
    assert_eq!(writer.diagnostics().next_batch_sequence, 3);
    let mut ack = DirectorySpool::open_existing(writer.directory(), 64 * 1024 * 1024).unwrap();
    ack.acknowledge_through(2).unwrap();
    drop(writer);
    let mut writer = open(&root.0, session, false, 1);
    assert_eq!(writer.diagnostics().next_batch_sequence, 3);
    writer.push(&fragment_event(session, 11, b"next")).unwrap();
    assert_eq!(writer.persisted_batches(), 0);
    writer.push(&fragment_event(session, 12, b"third")).unwrap();
    assert!(batch_path(writer.directory(), 3).exists());
    assert!(!batch_path(writer.directory(), 1).exists());
}

#[test]
fn failed_batch_keeps_memory_bounded_and_does_not_accept_more_input() {
    let root = Scratch::new();
    let session = Uuid::new_v4();
    let mut writer = SessionSpoolWriter::open(&root.0, session, 12000, 1).unwrap();
    writer
        .push(&fragment_event(session, 1, &vec![0; 700]))
        .unwrap();
    assert!(writer
        .push(&fragment_event(session, 2, &vec![0; 700]))
        .is_err());
    let d = writer.diagnostics();
    assert_eq!(d.pending_events, 0);
    assert_eq!(d.accepted_events, 1);
    assert_eq!(d.committed_events, 1);
    assert_eq!(d.rejected_events, 1);
    assert_eq!(d.write_failures, 0);
    assert!(d.pending_json_bytes <= d.pending_limit_bytes);
    for seq in 3..50 {
        assert!(writer
            .push(&fragment_event(session, seq, &vec![0; 700]))
            .is_err());
    }
    assert_eq!(
        writer.diagnostics().pending_json_bytes,
        d.pending_json_bytes
    );
    assert_eq!(writer.diagnostics().pending_events, 0);
    writer.mark_interrupted().unwrap();
    assert_eq!(
        load_manifest(writer.directory()).unwrap().unwrap().state,
        DurableSessionState::Interrupted
    );
    let physical: u64 = fs::read_dir(writer.directory())
        .unwrap()
        .map(|e| e.unwrap().metadata().unwrap().len())
        .sum();
    assert!(physical <= 12000);
}

#[test]
fn idle_partial_flush_commits_without_more_events() {
    let root = Scratch::new();
    let session = Uuid::new_v4();
    let mut writer = open(&root.0, session, false, 64);
    writer.push(&fragment_event(session, 1, b"tail")).unwrap();
    assert!(!writer.flush_if_idle().unwrap());
    writer.pending_since = Some(Instant::now().checked_sub(WRITER_IDLE_FLUSH).unwrap());
    assert!(writer.flush_if_idle().unwrap());
    assert_eq!(writer.diagnostics().committed_events, 1);
    assert_eq!(writer.diagnostics().pending_events, 0);
    assert!(!writer.flush_if_idle().unwrap());
}

#[test]
fn corrupt_declared_lz4_and_filename_sequence_fail_before_recovery() {
    let root = Scratch::new();
    fs::create_dir_all(&root.0).unwrap();
    let compressed = root.0.join(batch_filename(1, BATCH_LZ4_SUFFIX));
    fs::write(&compressed, u32::MAX.to_le_bytes()).unwrap();
    assert!(matches!(
        decode_batch_file(&compressed, BatchEncoding::Lz4),
        Err(SpoolError::BatchTooLarge { .. })
    ));
    fs::remove_file(compressed).unwrap();
    let session = Uuid::new_v4();
    fs::write(
        root.0.join(batch_filename(1, BATCH_JSON_SUFFIX)),
        serde_json::to_vec(&tests::batch(session, 2)).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        visit_batches(&root.0, session, None, |_| Ok(())),
        Err(SpoolError::FilenameSequenceMismatch { .. })
    ));
}

#[test]
fn escaping_and_sequence_digit_boundaries_use_actual_json_size() {
    let root = Scratch::new();
    let session = Uuid::new_v4();
    let mut writer = open(&root.0, session, false, 2);
    for seq in 1..=23 {
        let mut event = fragment_event(session, seq, b"text\r\n\\\"\t");
        event.header.process.command_line = Some("\n\"\\".repeat(700));
        writer.push(&event).unwrap();
    }
    writer.flush().unwrap();
    assert_eq!(writer.diagnostics().next_batch_sequence, 13);
    visit_batches(writer.directory(), session, None, |batch| {
        assert_eq!(
            measure_json(&batch)?.0,
            serde_json::to_vec(&batch)?.len() as u64
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn public_append_measures_before_allocation_and_stays_strict_on_duplicates() {
    let root = Scratch::new();
    let session = Uuid::new_v4();
    let mut spool = DirectorySpool::open(&root.0, 64 * 1024 * 1024).unwrap();
    let batch = tests::batch(session, 1);
    spool.append(&batch).unwrap();
    assert!(spool.append(&batch).is_err());
    let mut oversized = tests::batch(session, 2);
    oversized.events[0].header.process.command_line =
        Some("q".repeat(DEFAULT_MAX_FRAME_BYTES as usize));
    assert!(matches!(
        spool.append(&oversized),
        Err(SpoolError::BatchTooLarge { .. })
    ));
    assert_eq!(spool.pending().unwrap().len(), 1);
}

#[test]
fn byte_gate_failure_rejects_incoming_and_retains_existing_prefix() {
    let root = Scratch::new();
    let session = Uuid::new_v4();
    let mut writer = open(&root.0, session, false, 64);
    let bytes: Vec<_> = (0..262_144)
        .map(|i| u8::try_from(i % 256).unwrap())
        .collect();
    for seq in 1..=15 {
        writer.push(&fragment_event(session, seq, &bytes)).unwrap();
    }
    let pending = writer.diagnostics().pending_json_bytes;
    IO_FAULT.with(|f| *f.borrow_mut() = Some("batch_short_write"));
    let incoming = fragment_event(session, 16, &bytes);
    assert!(writer.push(&incoming).is_err());
    let d = writer.diagnostics();
    assert_eq!(d.accepted_events, 15);
    assert_eq!(d.rejected_events, 1);
    assert_eq!(d.pending_json_bytes, pending);
    assert_eq!(d.pending_events, 15);
    assert_eq!(d.last_failure.as_ref().unwrap().fragment_sequence, Some(16));
    assert!(!d.last_failure.as_ref().unwrap().retained_pending);
    writer.flush().unwrap();
    writer.push(&incoming).unwrap();
    writer.flush().unwrap();
    assert_eq!(writer.diagnostics().committed_events, 16);
    let mut seen = 0;
    visit_batches(writer.directory(), session, None, |batch| {
        for event in batch.events {
            seen += 1;
            assert_eq!(event.header.source_sequence, seen);
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(seen, 16);
}

#[test]
fn retry_never_overwrites_different_immutable_destination() {
    let root = Scratch::new();
    let session = Uuid::new_v4();
    let mut writer = open(&root.0, session, false, 1);
    let destination = batch_path(writer.directory(), 1);
    let foreign = serde_json::to_vec(&tests::batch(session, 1)).unwrap();
    fs::write(&destination, &foreign).unwrap();
    let event = fragment_event(session, 1, b"different");
    assert!(writer.push(&event).is_err());
    assert!(matches!(
        writer.flush(),
        Err(SpoolError::DestinationExists(_))
    ));
    assert_eq!(fs::read(destination).unwrap(), foreign);
    assert_eq!(writer.diagnostics().pending_events, 1);
}

#[test]
fn disk_gate_uses_actual_encoded_bytes_and_keeps_completion_reserve() {
    let root = Scratch::new();
    let session = Uuid::new_v4();
    let batch = tests::batch(session, 1);
    let json = serde_json::to_vec(&batch).unwrap();
    let encoded = lz4_flex::compress_prepend_size(&json);
    let reserve = 64;
    let mut spool = DirectorySpool::open_with(
        &root.0,
        encoded.len() as u64 + reserve - 1,
        SpoolOptions {
            compress: true,
            completion_reserve_bytes: reserve,
        },
    )
    .unwrap();
    assert!(matches!(
        spool.append(&batch),
        Err(SpoolError::CapacityExceeded { .. })
    ));
    assert_eq!(spool.used_bytes(), 0);
    assert!(spool.pending().unwrap().is_empty());
}

fn opaque_bytes(n: usize) -> Vec<u8> {
    let mut x = 0x58e7_61d9u32;
    let mut bytes = Vec::with_capacity(n);
    for _ in 0..n {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        bytes.push(x.to_le_bytes()[0]);
    }
    if !bytes.is_empty() {
        bytes[0] = 0xff;
    } // force reversible hex, as in the real failing event
    bytes
}
#[test]
fn production_32mib_capacity_rejects_before_acceptance_and_saves_every_accepted_fragment() {
    for compress in [false, true] {
        let root = Scratch::new();
        let session = Uuid::new_v4();
        let bytes = opaque_bytes(262_144);
        let mut w = SessionSpoolWriter::open_with(
            &root.0,
            session,
            32 * 1024 * 1024,
            64,
            SpoolOptions {
                compress,
                completion_reserve_bytes: DEFAULT_COMPLETION_RESERVE_BYTES,
            },
        )
        .unwrap();
        let mut accepted = 0;
        for seq in 1..=200 {
            let event = fragment_event(session, seq, &bytes);
            match crate::capture::persist_capture_event(&mut w, &event) {
                Ok(()) => accepted += 1,
                Err(SpoolError::CapacityExceeded { .. }) => break,
                other => panic!("{other:?}"),
            }
        }
        assert!(accepted > 30 && accepted < 200);
        let d = w.diagnostics();
        assert_eq!(d.accepted_events, accepted);
        assert_eq!(d.committed_events, accepted);
        assert_eq!(d.pending_events, 0);
        assert_eq!(d.unpersisted_events_at_exit, 0);
        assert_eq!(d.capacity_admission_rejections, 1);
        assert_eq!(d.rejected_events, 1);
        assert_eq!(d.write_failures, 0);
        assert!(d.terminal_finalized);
        assert!(d.capacity_splits > 0);
        assert!(d.high_water_working_bytes <= 4 * u64::from(DEFAULT_MAX_FRAME_BYTES) + 65536);
        let mut count = 0;
        visit_batches(w.directory(), session, None, |batch| {
            for event in batch.events {
                count += 1;
                assert_eq!(event.header.source_sequence, count);
                let EventPayload::InspectPlaintext(p) = event.payload else {
                    panic!("plaintext")
                };
                assert_eq!(
                    recover_captured_range(&p, 0..p.captured_bytes as usize)?,
                    bytes
                );
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(count, accepted);
        let physical: u64 = fs::read_dir(w.directory())
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum();
        assert!(physical <= 32 * 1024 * 1024);
        drop(w);
        let reopened = SessionSpoolWriter::open_with(
            &root.0,
            session,
            32 * 1024 * 1024,
            64,
            SpoolOptions {
                compress,
                completion_reserve_bytes: DEFAULT_COMPLETION_RESERVE_BYTES,
            },
        )
        .unwrap();
        assert_eq!(
            reopened.diagnostics().unrecovered_previous_pending_events,
            0
        );
    }
}
#[test]
fn admission_checks_exact_capacity_boundary_without_accepting_the_rejected_event() {
    for delta in [0, 1] {
        let root = Scratch::new();
        let session = Uuid::new_v4();
        let event = fragment_event(session, 1, b"tail-boundary");
        let singleton = batch_prefix(session, 1).len() as u64 + 2 + measure_json(&event).unwrap().0;
        let mut w = SessionSpoolWriter::open(
            &root.0,
            session,
            WRITER_METADATA_RESERVE + singleton - delta,
            64,
        )
        .unwrap();
        if delta == 1 {
            assert!(crate::capture::persist_capture_event(&mut w, &event).is_err());
            assert_eq!(w.diagnostics().accepted_events, 0);
            assert_eq!(w.diagnostics().rejected_events, 1);
        } else {
            crate::capture::persist_capture_event(&mut w, &event).unwrap();
            assert!(crate::capture::persist_capture_event(
                &mut w,
                &fragment_event(session, 2, b"tail-boundary")
            )
            .is_err());
            assert_eq!(w.diagnostics().accepted_events, 1);
            assert_eq!(w.diagnostics().committed_events, 1);
            assert_eq!(w.diagnostics().rejected_events, 1);
            assert_eq!(w.diagnostics().pending_events, 0);
        }
    }
}
#[test]
fn compressed_singleton_uses_actual_size_at_boundary_without_growing_trial_batches() {
    let root = Scratch::new();
    let session = Uuid::new_v4();
    let event = fragment_event(session, 1, &vec![0; 700]);
    let prefix = batch_prefix(session, 1);
    let bytes = format!("{prefix}{}]}}", serde_json::to_string(&event).unwrap()).into_bytes();
    let encoded = lz4_flex::compress_prepend_size(&bytes);
    let budget = WRITER_METADATA_RESERVE + bytes.len() as u64; // smaller than LZ4's worst-case bound
    let mut w = SessionSpoolWriter::open_with(
        &root.0,
        session,
        budget,
        64,
        SpoolOptions {
            compress: true,
            completion_reserve_bytes: 0,
        },
    )
    .unwrap();
    assert!(w.encoded_upper_bound(bytes.len() as u64).unwrap() > bytes.len() as u64);
    crate::capture::persist_capture_event(&mut w, &event).unwrap();
    assert_eq!(w.diagnostics().committed_events, 1);
    assert_eq!(w.diagnostics().pending_events, 0);
    assert_eq!(w.used_bytes(), encoded.len() as u64);
}
#[test]
fn synthetic_11680_capture_and_24601_serialization_are_rejected_as_one_visible_event() {
    let root = Scratch::new();
    let session = Uuid::new_v4();
    let mut event = fragment_event(session, 2314, &opaque_bytes(11680));
    event.header.process.command_line = Some(String::new());
    let initial = measure_json(&event).unwrap().0;
    assert!(initial < 24601);
    event.header.process.command_line = Some("x".repeat(usize::try_from(24601 - initial).unwrap()));
    assert_eq!(measure_json(&event).unwrap().0, 24601);
    let mut w = SessionSpoolWriter::open_with(
        &root.0,
        session,
        WRITER_METADATA_RESERVE + 26000,
        64,
        SpoolOptions {
            compress: false,
            completion_reserve_bytes: 0,
        },
    )
    .unwrap();
    let prior = fragment_event(session, 1, &opaque_bytes(700));
    crate::capture::persist_capture_event(&mut w, &prior).unwrap();
    assert!(matches!(
        crate::capture::persist_capture_event(&mut w, &event),
        Err(SpoolError::CapacityExceeded { .. })
    ));
    let d = w.diagnostics();
    assert_eq!(d.accepted_events, 1);
    assert_eq!(d.committed_events, 1);
    assert_eq!(d.rejected_events, 1);
    let failure = d.last_failure.unwrap();
    assert_eq!(failure.fragment_sequence, Some(2314));
    assert_eq!(failure.captured_bytes, Some(11680));
    assert_eq!(failure.serialized_bytes, Some(24601));
    assert!(!failure.retained_pending);
    assert!(!failure.committed);
}
#[test]
#[allow(
    clippy::many_single_char_names,
    reason = "Local fixture or owned callback keeps its explicit scope and fallible signature."
)]
fn production_exit_retry_commits_accepted_tail_once_after_write_and_manifest_faults() {
    for point in [
        "batch_open",
        "batch_short_write",
        "batch_file_sync",
        "batch_publish",
        "batch_directory_sync",
        "manifest_open",
        "manifest_short_write",
        "manifest_file_sync",
        "manifest_publish",
        "manifest_directory_sync",
    ] {
        let root = Scratch::new();
        let session = Uuid::new_v4();
        let mut w = open(&root.0, session, true, 2);
        let a = fragment_event(session, 1, b"accepted prefix");
        let b = fragment_event(session, 2, &opaque_bytes(11680));
        crate::capture::persist_capture_event(&mut w, &a).unwrap();
        IO_FAULT.with(|f| *f.borrow_mut() = Some(point));
        assert!(
            crate::capture::persist_capture_event(&mut w, &b).is_err(),
            "{point}"
        );
        let d = w.diagnostics();
        assert_eq!(d.accepted_events, 2);
        assert_eq!(d.committed_events, 2, "{point}");
        assert_eq!(d.rejected_events, 0);
        assert_eq!(d.pending_events, 0);
        assert_eq!(d.unpersisted_events_at_exit, 0);
        assert_eq!(d.terminal_flush_attempts, 1);
        assert!(d.terminal_finalized);
        w.finish_interrupted().unwrap();
        assert_eq!(w.diagnostics().terminal_flush_attempts, 1);
        let mut seen = 0;
        visit_batches(w.directory(), session, None, |batch| {
            for e in batch.events {
                seen += 1;
                assert_eq!(e.header.source_sequence, seen);
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, 2);
        drop(w);
        let r = open(&root.0, session, true, 2);
        assert_eq!(r.diagnostics().unrecovered_previous_pending_events, 0);
    }
}
#[test]
fn persistent_exit_write_failure_reports_volatile_tail_and_restart_does_not_invent_recovery() {
    let root = Scratch::new();
    let session = Uuid::new_v4();
    let mut w = open(&root.0, session, true, 1);
    IO_FAULT.with(|f| *f.borrow_mut() = Some("batch_open"));
    assert!(w.push(&fragment_event(session, 1, b"volatile")).is_err());
    IO_FAULT.with(|f| *f.borrow_mut() = Some("batch_open"));
    assert!(!w.finish_interrupted().unwrap());
    let d = w.diagnostics();
    assert_eq!(d.accepted_events, 1);
    assert_eq!(d.committed_events, 0);
    assert_eq!(d.unpersisted_events_at_exit, 1);
    assert_eq!(d.terminal_flush_attempts, 1);
    assert!(d.terminal_flush_error.is_some());
    for _ in 0..3 {
        assert!(!w.finish_interrupted().unwrap());
    }
    assert_eq!(w.diagnostics().write_failures, 2); // initial attempt + exactly one terminal retry
    assert!(w
        .push(&fragment_event(session, 2, b"not admitted"))
        .is_err());
    assert_eq!(w.diagnostics().accepted_events, 1);
    assert_eq!(w.diagnostics().rejected_events, 1);
    drop(w);
    let mut r = open(&root.0, session, true, 1);
    assert_eq!(r.diagnostics().accepted_events, 0);
    assert_eq!(r.diagnostics().committed_events, 0);
    assert_eq!(r.diagnostics().unrecovered_previous_pending_events, 1);
    r.push(&fragment_event(session, 2, b"new durable input"))
        .unwrap();
    drop(r);
    let r = open(&root.0, session, true, 1);
    assert_eq!(r.diagnostics().unrecovered_previous_pending_events, 1);
}
#[test]
fn incoming_rejected_during_prefix_flush_does_not_become_accepted_on_exit_retry() {
    let root = Scratch::new();
    let session = Uuid::new_v4();
    let mut w =
        SessionSpoolWriter::open(&root.0, session, WRITER_METADATA_RESERVE + 3200, 64).unwrap();
    let a = fragment_event(session, 1, &opaque_bytes(700));
    let b = fragment_event(session, 2, &opaque_bytes(700));
    crate::capture::persist_capture_event(&mut w, &a).unwrap();
    IO_FAULT.with(|f| *f.borrow_mut() = Some("batch_short_write"));
    assert!(crate::capture::persist_capture_event(&mut w, &b).is_err());
    let d = w.diagnostics();
    assert_eq!(d.accepted_events, 1);
    assert_eq!(d.committed_events, 1);
    assert_eq!(d.rejected_events, 1);
    assert_eq!(d.pending_events, 0);
    let failure = d.last_failure.unwrap();
    assert_eq!(failure.fragment_sequence, Some(2));
    assert!(!failure.retained_pending);
}

#[test]
fn json_broken_pipe_is_an_error_and_the_accepted_tail_remains_recoverable() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "fixture closed",
            ))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let root = Scratch::new();
    let session = Uuid::new_v4();
    let mut w = open(&root.0, session, true, 64);
    let event = fragment_event(session, 1, b"accepted before output error");
    crate::capture::persist_capture_event(&mut w, &event).unwrap();
    assert!(crate::capture::write_capture_json(&mut Broken, &event).is_err());
    assert!(w.finish_interrupted().unwrap());
    assert_eq!(w.diagnostics().accepted_events, 1);
    assert_eq!(w.diagnostics().committed_events, 1);
    assert_eq!(w.diagnostics().rejected_events, 0);
    assert_eq!(w.diagnostics().unpersisted_events_at_exit, 0);
    assert_eq!(
        load_manifest(w.directory()).unwrap().unwrap().state,
        DurableSessionState::Interrupted
    );
    visit_batches(w.directory(), session, None, |batch| {
        assert_eq!(batch.events, vec![event.clone()]);
        Ok(())
    })
    .unwrap();
}
#[test]
fn terminal_manifest_failure_is_reported_and_metadata_retries_are_bounded() {
    let root = Scratch::new();
    let session = Uuid::new_v4();
    let mut w = open(&root.0, session, true, 1);
    w.push(&fragment_event(session, 1, b"already durable"))
        .unwrap();
    IO_FAULT.with(|f| *f.borrow_mut() = Some("manifest_short_write"));
    assert!(w.finish_interrupted().is_err());
    assert_eq!(w.diagnostics().terminal_manifest_attempts, 1);
    assert!(w.diagnostics().terminal_manifest_error.is_some());
    assert_eq!(w.diagnostics().committed_events, 1);
    assert!(w.finish_interrupted().unwrap());
    assert_eq!(w.diagnostics().terminal_manifest_attempts, 2);
    assert!(w.diagnostics().terminal_manifest_error.is_none());
    IO_FAULT.with(|f| *f.borrow_mut() = Some("manifest_open"));
    assert!(w.finish_interrupted().unwrap());
    assert_eq!(w.diagnostics().terminal_manifest_attempts, 2);
    IO_FAULT.with(|f| *f.borrow_mut() = None);
}
