//! Automatic capture must never silently discard unexported sessions.
use ksight_agent::{retention::SpoolRetention, spool::SessionSpoolWriter};
use ksight_protocol::DurableSessionState;
use uuid::Uuid;

#[test]
fn admission_preserves_more_than_four_sessions_and_refuses_full_storage() {
    let root = std::env::temp_dir().join(format!("ksight-retention-{}", Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let retention = SpoolRetention {
        root: root.clone(),
        max_total_bytes: 1024 * 1024,
        keep_completed: 4,
    };
    let mut ids = Vec::new();
    for index in 0..9 {
        retention.prepare_session(65536).unwrap();
        let id = Uuid::new_v4();
        let mut writer = SessionSpoolWriter::open(&root, id, 65536, 64).unwrap();
        writer
            .seal(
                if index % 2 == 0 {
                    DurableSessionState::Completed
                } else {
                    DurableSessionState::Interrupted
                },
                None,
            )
            .unwrap();
        std::fs::write(
            root.join(id.to_string()).join("evidence.txt"),
            b"retain unexported evidence",
        )
        .unwrap();
        ids.push(id);
    }
    let full = SpoolRetention {
        max_total_bytes: 1,
        ..retention
    };
    let error = full.prepare_session(65536).unwrap_err().to_string();
    assert!(error.contains("existing sessions preserved"), "{error}");
    for id in ids {
        assert_eq!(
            std::fs::read(root.join(id.to_string()).join("evidence.txt")).unwrap(),
            b"retain unexported evidence"
        );
    }
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 9);
    std::fs::remove_dir_all(root).unwrap();
}
