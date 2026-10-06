//! Exercises the production revocation/publication boundary without a device.
use super::*;

fn runtime() -> InspectRuntime {
    let policy = InspectPolicy {
        package: Some("org.example.fixture".into()),
        ..InspectPolicy::default()
    };
    InspectRuntime::prepare_all(
        &policy,
        &[InspectAdapterKind::ArtDexLoad],
        Path::new("not-loaded"),
    )
}

#[test]
fn reuse_exit_and_unreadable_identity_drop_pending_payload_and_preserve_deny() {
    for observation in [
        ProcStartRead::Running(101),
        ProcStartRead::Gone,
        ProcStartRead::Unreadable,
    ] {
        let mut runtime = runtime();
        runtime.process_starts.insert(7, 100);
        runtime.bound_instance_targets = Some(Vec::new());
        runtime.tls_pending.push(
            ProbeCallKey {
                pid: 7,
                tid: 8,
                lib_token: 1,
                offset: 2,
                abi: 1,
            },
            PendingSslRead {
                pid: 7,
                buf: 4096,
                requested: 4,
                written_ptr: None,
                connection_id: None,
            },
        );
        assert_eq!(verify_process_read(&mut runtime, 7, observation), 0);
        assert_eq!(runtime.pending_depth(), (0, 1));
        assert_eq!(runtime.bound_instance_targets.as_ref().unwrap().len(), 0);
        let outputs = finish_scope_poll(
            &mut runtime,
            vec![InspectOutput::Plaintext {
                pid: 7,
                tid: 8,
                connection_id: None,
                fragment: InspectPlaintext::default(),
                raw: vec![1, 2, 3],
            }],
        );
        assert!(outputs
            .iter()
            .all(|output| matches!(output, InspectOutput::Observation { .. })));
        assert!(outputs.iter().any(|output| matches!(output, InspectOutput::Observation { observation, .. } if observation.adapter == "scope_fail_closed")));
    }
}

#[test]
fn revocation_clears_pending_payload_even_before_a_process_start_is_cached() {
    let mut runtime = runtime();
    runtime.tls_pending.push(
        ProbeCallKey {
            pid: 7,
            tid: 8,
            lib_token: 1,
            offset: 2,
            abi: 1,
        },
        PendingSslRead {
            pid: 7,
            buf: 4096,
            requested: 4,
            written_ptr: None,
            connection_id: None,
        },
    );
    revoke_scope(&mut runtime, None, "read-failed");
    assert_eq!(runtime.pending_depth(), (0, 1));
}
