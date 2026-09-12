use ksight_model::{
    BinderTransaction, BinderTransactionDirection, BinderTransactionStage, CaptureMode, Confidence,
    DataQuality, EventHeader, InspectObservation, PackageCandidate, ProcessIdentity, ProcessKey,
    SchemaVersion,
};

use super::*;

#[test]
fn groups_binder_and_artifact_activity_without_claiming_semantics() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    builder.record(&binder_event(session, 10, Some(20), false, 7));
    builder.record(&binder_event(session, 20, Some(10), true, 0));
    builder.record(&file_event(session, "/data/app/com.example/base.apk"));

    let report = builder.finish();
    assert_eq!(report.total_events, 3);
    assert_eq!(report.binder_relations.len(), 2);
    assert_eq!(report.artifacts[0].category, "android_package");
    assert!(report
        .limitations
        .iter()
        .any(|value| value.contains("AIDL")));
    assert!(report
        .graph
        .edges
        .iter()
        .any(|edge| edge.relation == "binder"));
    let binder_graph = report.graph.query(&crate::GraphQuery {
        relation: Some("binder".to_owned()),
        limit: 8,
        ..crate::GraphQuery::default()
    });
    assert!(!binder_graph.edges.is_empty());
    assert!(report.graph.edges.iter().any(|edge| {
        edge.relation == "binder" && edge.from.contains(":10") && edge.to.contains(":20")
    }));
    assert!(report
        .graph
        .edges
        .iter()
        .any(|edge| edge.relation == "contains"));
    assert!(report.processes.iter().any(|process| process
        .instances
        .iter()
        .any(|instance| instance.pid == 10 && instance.process_instance_id.contains(":10:"))));
    assert!(report
        .graph
        .entities
        .iter()
        .any(|entity| entity.key.starts_with("procinst:") && entity.process_instance_id.is_some()));
}

#[test]
fn infers_tls_record_from_legacy_preview_and_keeps_file_digest() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    let mut hashed = file_event(session, "/data/user/0/com.example/code_cache/1.dex");
    if let EventPayload::FileOpen(open) = &mut hashed.payload {
        open.content_sha256 = Some("abc123".to_owned());
        open.content_bytes = Some(32);
    }
    builder.record(&hashed);
    builder.record(&Event {
        header: header(session, 10, SensorKind::Integrity),
        payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
            adapter: "tls_ssl_write".to_owned(),
            direction: "send".to_owned(),
            library: "libssl.so".to_owned(),
            build_id: None,
            offset: None,
            requested_bytes: 64,
            captured_bytes: 16,
            truncated: false,
            sha256: "deadbeef".to_owned(),
            preview: "17030307a4000000".to_owned(),
            preview_encoding: "hex".to_owned(),
            content_class: String::new(),

            ..Default::default()
        }),
    });

    let report = builder.finish();
    assert_eq!(
        report.artifacts[0].content_sha256.as_deref(),
        Some("abc123")
    );
    assert_eq!(report.plaintext[0].content_class, "tls_record");
    assert!(report
        .graph
        .edges
        .iter()
        .any(|edge| { edge.relation == "tls_send" && edge.from == "process:com.example:10" }));
}

#[test]
fn separates_failed_opens_and_attributes_truncation() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    builder.record(&file_event(session, "/data/app/com.example/base.apk"));
    let mut failed = file_event(session, "/data/app/com.example/base.apk");
    let EventPayload::FileOpen(open) = &mut failed.payload else {
        unreachable!("file_event must produce FileOpen");
    };
    open.result = -2;
    open.file_descriptor = None;
    failed.header.quality.truncated = true;
    failed.header.quality.source = "syscalls/sys_exit_openat".to_owned();
    builder.record(&failed);

    let report = builder.finish();
    assert_eq!(report.artifacts[0].open_attempts, 2);
    assert_eq!(report.artifacts[0].successful_opens, 1);
    assert_eq!(report.artifacts[0].failed_opens, 1);
    assert_eq!(
        report.quality.truncated_by_source["syscalls/sys_exit_openat"],
        1
    );
}

#[test]
fn correlates_fd_and_binder_lifecycles() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    builder.record(&file_event(session, "/data/local/tmp/demo.so"));
    builder.record(&fd_event(session, FileDescriptorOperation::Duplicate, 3, 4));
    builder.record(&fd_event(session, FileDescriptorOperation::Close, 3, 0));
    builder.record(&socket_event(session, 4, -115));
    builder.record(&socket_io_event(session, 4, SocketIoOperation::Send, 120));
    builder.record(&fd_event(session, FileDescriptorOperation::Close, 4, 0));
    builder.record(&socket_accept_event(session, 7, 5));
    builder.record(&socket_io_event(session, 5, SocketIoOperation::Receive, 80));
    builder.record(&fd_event(session, FileDescriptorOperation::Close, 5, 0));
    builder.record(&memory_event(session, MemoryOperation::Map, 0x1000, 0x2000));
    builder.record(&memory_event(
        session,
        MemoryOperation::Unmap,
        0x1800,
        0x800,
    ));

    let mut submitted = binder_event(session, 10, Some(20), false, 7);
    submitted.header.monotonic_ns = 100;
    builder.record(&submitted);
    let mut received = binder_event(session, 20, None, false, 0);
    received.header.monotonic_ns = 160;
    if let EventPayload::BinderTransaction(transaction) = &mut received.payload {
        transaction.stage = BinderTransactionStage::Received;
        transaction.transaction_id = 10;
    }
    builder.record(&received);

    let report = builder.finish();
    assert_eq!(report.fd_lifecycle.successful_opens, 1);
    assert_eq!(report.fd_lifecycle.successful_duplicates, 1);
    assert_eq!(report.fd_lifecycle.successful_closes, 3);
    assert_eq!(report.fd_lifecycle.active_at_end, 0);
    assert!(report.fd_lifecycle.lineage_complete);
    assert_eq!(report.socket_lifecycle.connected_or_in_progress, 1);
    assert_eq!(report.socket_lifecycle.accept_attempts, 1);
    assert_eq!(report.socket_lifecycle.accepted_descriptors, 1);
    assert_eq!(report.socket_lifecycle.sent_bytes, 120);
    assert_eq!(report.socket_lifecycle.received_bytes, 80);
    assert_eq!(report.socket_lifecycle.io_without_observed_lifecycle, 0);
    assert_eq!(report.socket_lifecycle.closed_descriptors, 2);
    assert_eq!(report.socket_lifecycle.active_at_end, 0);
    assert_eq!(report.memory_lifecycle.unmaps_with_observed_mapping, 1);
    assert_eq!(report.memory_lifecycle.unmaps_without_observed_mapping, 0);
    assert_eq!(report.memory_lifecycle.active_regions_at_end, 2);
    assert!(report.observed_mappings.iter().any(|mapping| {
        mapping.process_id == 10
            && mapping.start == 0x1000
            && mapping.end == 0x3000
            && mapping.source == MappingSource::Mmap
    }));
    assert!(report.graph.edges.iter().any(|edge| {
        edge.relation == "maps"
            && edge.strength == crate::EdgeStrength::Confirmed
            && edge.to.starts_with("mmap:10:1000-3000")
    }));
    assert_eq!(report.binder_lifecycle.submitted, 1);
    assert_eq!(report.binder_lifecycle.delivered, 1);
    assert_eq!(report.binder_lifecycle.average_delivery_ns, Some(60));
    assert_eq!(report.binder_lifecycle.two_way_submitted, 1);
    assert_eq!(report.binder_lifecycle.paired_replies, 0);
}

#[test]
fn pairs_two_way_binder_request_and_reply() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    let mut request = binder_event(session, 10, Some(20), false, 7);
    request.header.monotonic_ns = 100;
    if let EventPayload::BinderTransaction(transaction) = &mut request.payload {
        transaction.transaction_id = 42;
    }
    builder.record(&request);
    let mut reply = binder_event(session, 20, Some(10), true, 7);
    reply.header.monotonic_ns = 5_100;
    if let EventPayload::BinderTransaction(transaction) = &mut reply.payload {
        transaction.transaction_id = 99;
        transaction.reply = true;
        transaction.direction = BinderTransactionDirection::Reply;
        transaction.reply_to_request_id = Some(42);
        transaction.reply_latency_ns = Some(5_000);
    }
    builder.record(&reply);
    let report = builder.finish();
    assert_eq!(report.binder_lifecycle.two_way_submitted, 1);
    assert_eq!(report.binder_lifecycle.reply_submitted, 1);
    assert_eq!(report.binder_lifecycle.paired_replies, 1);
    assert_eq!(report.binder_lifecycle.average_reply_ns, Some(5_000));
    assert_eq!(report.binder_reply_pairs.len(), 1);
    assert_eq!(report.binder_reply_pairs[0].request_transaction_id, 42);
    assert_eq!(report.binder_reply_pairs[0].client_process_id, 10);
    assert_eq!(report.binder_reply_pairs[0].server_process_id, 20);
    assert!(report.graph.edges.iter().any(
        |edge| edge.relation == "replies_to" && edge.strength == crate::EdgeStrength::Confirmed
    ));
    assert!(report
        .graph
        .edges
        .iter()
        .any(|edge| edge.relation == "binder_reply"
            && edge.strength == crate::EdgeStrength::Confirmed));
}

#[test]
fn one_way_binder_is_not_a_reply_pair() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    let mut request = binder_event(session, 10, Some(20), false, 7);
    if let EventPayload::BinderTransaction(transaction) = &mut request.payload {
        transaction.transaction_id = 42;
        transaction.flags = 0x1;
        transaction.decoded_flags = vec![ksight_model::BinderTransactionFlag::OneWay];
    }
    builder.record(&request);
    let report = builder.finish();
    assert_eq!(report.binder_lifecycle.one_way_submitted, 1);
    assert_eq!(report.binder_lifecycle.two_way_submitted, 0);
    assert_eq!(report.binder_lifecycle.paired_replies, 0);
    assert!(report.binder_reply_pairs.is_empty());
}

#[test]
fn kernel_parcel_token_is_counted_on_binder_relation() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    let mut request = binder_event(session, 10, Some(20), false, 1);
    if let EventPayload::BinderTransaction(transaction) = &mut request.payload {
        transaction.transaction_id = 42;
        transaction.interface_token = Some("android.os.IServiceManager".to_owned());
        transaction.binder_method = Some("getService".to_owned());
        transaction.binder_method_source = Some("aosp_stub".to_owned());
    }
    builder.record(&request);
    let report = builder.finish();
    assert_eq!(
        report.binder_relations[0]
            .interfaces
            .get("android.os.IServiceManager"),
        Some(&1)
    );
    assert!(report.graph.entities.iter().any(|entity| {
        entity.key == "binder:req:42"
            && entity
                .label
                .contains("android.os.IServiceManager::getService")
    }));
}

#[test]
fn inspect_transact_joins_two_way_binder_by_tid_and_code() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    builder.record(&inspect_transact_event(session, 10, 11, 7));
    let mut request = binder_event(session, 10, Some(20), false, 7);
    request.header.process.tid = 11;
    request.header.monotonic_ns = 100;
    if let EventPayload::BinderTransaction(transaction) = &mut request.payload {
        transaction.transaction_id = 42;
    }
    builder.record(&request);
    let mut reply = binder_event(session, 20, Some(10), true, 7);
    reply.header.monotonic_ns = 5_100;
    if let EventPayload::BinderTransaction(transaction) = &mut reply.payload {
        transaction.transaction_id = 99;
        transaction.reply = true;
        transaction.direction = BinderTransactionDirection::Reply;
        transaction.reply_to_request_id = Some(42);
        transaction.reply_latency_ns = Some(5_000);
    }
    builder.record(&reply);
    let report = builder.finish();
    let hit = report
        .inspect_hits
        .iter()
        .find(|row| row.adapter == "binder_userspace")
        .expect("inspect hit");
    assert_eq!(hit.binder_transaction_id, Some(42));
    assert_eq!(hit.reply_latency_ns, Some(5_000));
    assert!(report.graph.edges.iter().any(|edge| {
        edge.relation == "joined_transact"
            && edge.strength == crate::EdgeStrength::Correlated
            && edge.to == "binder:req:42"
    }));
    assert!(report
        .graph
        .edges
        .iter()
        .any(|edge| edge.relation == "replies_to"));
}

#[test]
fn inspect_transact_does_not_join_mismatched_tid() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    builder.record(&inspect_transact_event(session, 10, 11, 7));
    let mut request = binder_event(session, 10, Some(20), false, 7);
    request.header.process.tid = 99;
    if let EventPayload::BinderTransaction(transaction) = &mut request.payload {
        transaction.transaction_id = 42;
    }
    builder.record(&request);
    let report = builder.finish();
    let hit = report
        .inspect_hits
        .iter()
        .find(|row| row.adapter == "binder_userspace")
        .expect("inspect hit");
    assert_eq!(hit.binder_transaction_id, None);
    assert!(report
        .graph
        .edges
        .iter()
        .all(|edge| edge.relation != "joined_transact"));
}

#[test]
fn inspect_transact_joins_one_way_request_without_reply_latency() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    builder.record(&inspect_transact_event(session, 10, 11, 7));
    let mut request = binder_event(session, 10, Some(20), false, 7);
    request.header.process.tid = 11;
    if let EventPayload::BinderTransaction(transaction) = &mut request.payload {
        transaction.transaction_id = 42;
        transaction.flags = 0x1;
        transaction.decoded_flags = vec![ksight_model::BinderTransactionFlag::OneWay];
    }
    builder.record(&request);
    let report = builder.finish();
    let hit = report
        .inspect_hits
        .iter()
        .find(|row| row.adapter == "binder_userspace")
        .expect("inspect hit");
    assert_eq!(hit.binder_transaction_id, Some(42));
    assert_eq!(hit.reply_latency_ns, None);
    assert!(report
        .graph
        .edges
        .iter()
        .any(|edge| { edge.relation == "joined_transact" && edge.to == "binder:req:42" }));
}

#[test]
fn baselines_seed_fd_socket_and_memory_state() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    builder.record(&Event {
        header: header(session, 10, SensorKind::File),
        payload: EventPayload::SessionFdBaseline(ksight_model::SessionFdBaseline {
            process_id: 10,
            fds: vec![ksight_model::BaselineFd {
                fd: 7,
                kind: BaselineFdKind::Socket,
                target: "socket:[123]".to_owned(),
            }],
            chunk_index: 0,
            chunk_count: 1,
        }),
    });
    builder.record(&Event {
        header: header(session, 10, SensorKind::Memory),
        payload: EventPayload::SessionVmaBaseline(ksight_model::SessionVmaBaseline {
            process_id: 10,
            vmas: vec![ksight_model::BaselineVma {
                start: 0x1000,
                end: 0x3000,
                protection: 5,
                path: Some("/system/lib64/libc.so".to_owned()),
            }],
            chunk_index: 0,
            chunk_count: 1,
        }),
    });

    let report = builder.finish();
    assert_eq!(report.fd_lifecycle.active_at_end, 1);
    assert_eq!(report.socket_lifecycle.active_at_end, 1);
    assert_eq!(report.memory_lifecycle.active_regions_at_end, 1);
    assert_eq!(report.artifacts[0].mappings, 1);
    assert_eq!(report.observed_mappings.len(), 1);
    assert_eq!(
        report.observed_mappings[0].source,
        MappingSource::VmaBaseline
    );
    assert!(report.graph.edges.iter().any(|edge| {
        edge.relation == "maps" && edge.strength == crate::EdgeStrength::Correlated
    }));
}

#[test]
fn observed_mappings_keep_large_mmap_ahead_of_tiny_baselines() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    builder.record(&Event {
        header: header(session, 10, SensorKind::Memory),
        payload: EventPayload::SessionVmaBaseline(ksight_model::SessionVmaBaseline {
            process_id: 10,
            vmas: (0_u32..80)
                .map(|index| ksight_model::BaselineVma {
                    start: u64::from(index) * 0x1000,
                    end: u64::from(index) * 0x1000 + 0x1000,
                    protection: 3,
                    path: None,
                })
                .collect(),
            chunk_index: 0,
            chunk_count: 1,
        }),
    });
    builder.record(&memory_event(
        session,
        MemoryOperation::Map,
        0x006e_5f3f_1000,
        53_604_352,
    ));
    builder.record(&memory_event(session, MemoryOperation::Map, 0, 1 << 50));

    let report = builder.finish();
    assert_eq!(report.observed_mappings[0].source, MappingSource::Mmap);
    assert_eq!(report.observed_mappings[0].start, 0x006e_5f3f_1000);
    assert!(report.observed_mappings.iter().all(|mapping| {
        mapping.start >= 0x1000 && mapping.end.saturating_sub(mapping.start) <= 1024 * 1024 * 1024
    }));
    assert_eq!(report.memory_lifecycle.mapped_bytes, 53_604_352);
    assert!(report.graph.edges.iter().any(|edge| {
        edge.relation == "maps"
            && edge.strength == crate::EdgeStrength::Confirmed
            && edge.to.contains("mmap:10:6e5f3f1000-")
    }));
}

#[test]
fn mmsg_results_are_messages_not_bytes() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    builder.record(&socket_event(session, 4, 0));
    let mut send = socket_io_event(session, 4, SocketIoOperation::Send, 3);
    let EventPayload::SocketIo(io) = &mut send.payload else {
        panic!("expected socket I/O");
    };
    io.syscall = 269;
    io.requested_bytes = None;
    builder.record(&send);

    let report = builder.finish();
    assert_eq!(report.socket_lifecycle.sent_messages, 3);
    assert_eq!(report.socket_lifecycle.sent_bytes, 0);
    assert_eq!(report.network_peers[0].sent_messages, 3);
    assert_eq!(report.network_peers[0].sent_bytes, 0);
}

#[test]
fn dns_answer_stamps_connect_at_finish() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    builder.record(&socket_event(session, 5, 0));
    builder.record(&Event {
        header: header(session, 10, SensorKind::Network),
        payload: EventPayload::DnsDatagram(ksight_model::DnsDatagram {
            file_descriptor: 4,
            result: 32,
            address_family: 2,
            peer_port: 53,
            peer_address: Some("8.8.8.8".to_owned()),
            direction: "response".to_owned(),
            truncated: false,
            qname: Some("example.com".to_owned()),
            addresses: vec!["127.0.0.1".to_owned()],
        }),
    });
    let report = builder.finish();
    assert_eq!(report.dns_datagrams, 1);
    assert_eq!(report.dns_names[0].qname, "example.com");
    assert_eq!(
        report.network_peers[0].resolved_name.as_deref(),
        Some("example.com")
    );
    assert!(
        report
            .graph
            .edges
            .iter()
            .any(|edge| edge.relation == "answers"
                && edge.strength == crate::EdgeStrength::Correlated)
    );
}

#[test]
fn unique_sni_stamps_empty_inspect_http_host() {
    let mut calls = vec![HttpCallActivity {
        source: "us.hsbc.hsbcus".to_owned(),
        process_id: 7554,
        direction: "recv".to_owned(),
        kind: "http1_response".to_owned(),
        method: "HTTP".to_owned(),
        host: None,
        path: String::new(),
        status: Some(200),
        query_keys: Vec::new(),
        header_names: vec!["Content-Type".to_owned()],
        redacted_headers: Vec::new(),
        body_keys: Vec::new(),
        redacted_body_keys: Vec::new(),
        content_type: Some("application/json".to_owned()),
        third_party: false,
        count: 1,
        origin: "inspect".to_owned(),
    }];
    let handshakes = vec![HandshakeNameActivity {
        process_id: 7554,
        kind: "tls".to_owned(),
        sni: Some("www.us.hsbc.com".to_owned()),
        alpn: Some("h2".to_owned()),
        http_host: None,
        http_method: None,
        peer: None,
        port: None,
    }];
    stamp_empty_hosts_from_sni(&mut calls, &handshakes);
    assert_eq!(calls[0].host.as_deref(), Some("www.us.hsbc.com"));
}

#[test]
fn handshake_sni_stamps_connect_at_finish() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    builder.record(&socket_event(session, 5, 0));
    builder.record(&Event {
        header: header(session, 10, SensorKind::Network),
        payload: EventPayload::NetworkHandshake(ksight_model::NetworkHandshake {
            file_descriptor: 5,
            result: 120,
            address_family: 2,
            peer_port: 0,
            peer_address: None,
            truncated: false,
            kind: "tls".to_owned(),
            sni: Some("app.example".to_owned()),
            alpn: Some("h2".to_owned()),
            ech: false,
            http_method: None,
            http_path: None,
            http_host: None,
            request_prefix: None,
            quic_version: None,
            quic_packet: None,
            quic_dcid: None,
        }),
    });
    let report = builder.finish();
    assert_eq!(report.handshake_events, 1);
    assert_eq!(
        report.handshake_names[0].sni.as_deref(),
        Some("app.example")
    );
    assert_eq!(report.network_peers[0].sni.as_deref(), Some("app.example"));
    assert_eq!(report.network_peers[0].alpn.as_deref(), Some("h2"));
    assert!(report.graph.edges.iter().any(|edge| {
        edge.relation == "sni" && edge.strength == crate::EdgeStrength::Correlated
    }));
}

#[test]
fn binder_fd_receive_emits_transfers_fd() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    let mut received = binder_event(session, 20, Some(10), false, 1);
    received.payload = EventPayload::BinderTransaction(BinderTransaction {
        stage: BinderTransactionStage::FdReceived,
        transaction_id: 7,
        target_node: None,
        target_process_id: Some(20),
        target_thread_id: None,
        target_kind: None,
        reply: false,
        direction: BinderTransactionDirection::Request,
        reply_to_request_id: None,
        reply_latency_ns: None,
        code: 1,
        code_kind: None,
        flags: 0,
        decoded_flags: Vec::new(),
        data_size: None,
        offsets_size: None,
        extra_buffers_size: None,
        file_descriptor: Some(9),
        object_offset: Some(0x10),
        transferred_fd_origin: Some("/data/app/base.apk".to_owned()),
        transferred_fd_source_pid: Some(10),
        transferred_fd_source_fd: Some(7),
        interface_token: None,
        binder_method: None,
        binder_method_source: None,
        parcel_prefix_hex: None,
    });
    builder.record(&received);
    let report = builder.finish();
    assert_eq!(report.binder_fd_transfers.len(), 1);
    assert_eq!(report.binder_fd_transfers[0].origin, "/data/app/base.apk");
    assert!(report.graph.edges.iter().any(|edge| {
        edge.relation == "transfers_fd"
            && edge.strength == crate::EdgeStrength::Confirmed
            && edge.from == "fd:10:7"
            && edge.to == "fd:20:9"
    }));
}

#[test]
fn ssl_read_plaintext_graphs_tls_recv() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    builder.record(&file_event(
        session,
        "/data/user/0/com.example/code_cache/1.dex",
    ));
    builder.record(&Event {
        header: header(session, 10, SensorKind::Integrity),
        payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
            adapter: "tls_ssl_read".to_owned(),
            direction: "recv".to_owned(),
            library: "libssl.so".to_owned(),
            build_id: None,
            offset: None,
            requested_bytes: 64,
            captured_bytes: 16,
            truncated: false,
            sha256: "cafebabe".to_owned(),
            preview: "17030307a4000000".to_owned(),
            preview_encoding: "hex".to_owned(),
            content_class: String::new(),

            ..Default::default()
        }),
    });
    let report = builder.finish();
    assert_eq!(report.plaintext[0].direction, "recv");
    assert!(report
        .graph
        .edges
        .iter()
        .any(|edge| edge.relation == "tls_recv"));
}

#[test]
fn stitches_ssl_read_text_and_extracts_split_urls() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    builder.record(&Event {
        header: header(session, 22, SensorKind::Integrity),
        payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
            adapter: "tls_ssl_read".to_owned(),
            direction: "recv".to_owned(),
            library: "libssl.so".to_owned(),
            build_id: None,
            offset: None,
            requested_bytes: 64,
            captured_bytes: 64,
            truncated: true,
            sha256: "aa".to_owned(),
            preview: r#"{"type":"hummer","url":"https://cdn.example/cd/acrossBar.zip""#.to_owned(),
            preview_encoding: "utf8_lossy".to_owned(),
            content_class: "text".to_owned(),
            ..Default::default()
        }),
    });
    builder.record(&Event {
        header: header(session, 22, SensorKind::Integrity),
        payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
            adapter: "tls_ssl_read".to_owned(),
            direction: "recv".to_owned(),
            library: "libssl.so".to_owned(),
            build_id: None,
            offset: None,
            requested_bytes: 40,
            captured_bytes: 40,
            truncated: true,
            sha256: "bb".to_owned(),
            preview: r#","md5":"abc","url":"https://static.example/pkg/e5.zip","#.to_owned(),
            preview_encoding: "utf8_lossy".to_owned(),
            content_class: "text".to_owned(),

            ..Default::default()
        }),
    });
    let report = builder.finish();
    let preview = report.plaintext[0].preview.as_deref().unwrap_or("");
    assert!(preview.contains("cdn.example"));
    assert!(preview.contains("static.example"));
    assert!(report.http_calls.iter().any(|call| {
        call.host.as_deref() == Some("cdn.example") && call.path.contains("acrossBar.zip")
    }));
    assert!(report
        .http_calls
        .iter()
        .any(|call| call.host.as_deref() == Some("static.example")));
}

#[test]
fn utf8_inspect_preview_does_not_panic_on_content_class() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    builder.record(&Event {
        header: header(session, 11, SensorKind::Integrity),
        payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
            adapter: "tls_ssl_read".to_owned(),
            direction: "recv".to_owned(),
            library: "libssl.so".to_owned(),
            build_id: None,
            offset: None,
            requested_bytes: 32,
            captured_bytes: 32,
            truncated: false,
            sha256: "cc".to_owned(),
            preview: "证指数".to_owned(),
            preview_encoding: "utf8_lossy".to_owned(),
            content_class: String::new(),

            ..Default::default()
        }),
    });
    let report = builder.finish();
    assert_eq!(report.plaintext[0].preview.as_deref(), Some("证指数"));
}

#[test]
fn keeps_url_json_over_longer_jni_javascript() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    let urls = r#"{"type":"hummer","url":"https://cdn.example/cd/acrossBar_v1.8.zip"}"#;
    builder.record(&Event {
        header: header(session, 30, SensorKind::Integrity),
        payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
            adapter: "jni_get_string_utf_chars".to_owned(),
            direction: "java_to_native".to_owned(),
            library: "libart.so".to_owned(),
            build_id: None,
            offset: None,
            requested_bytes: urls.len() as u64,
            captured_bytes: u32::try_from(urls.len()).unwrap_or(u32::MAX),
            truncated: false,
            sha256: "urljson".to_owned(),
            preview: urls.to_owned(),
            preview_encoding: "utf8_lossy".to_owned(),
            content_class: "text".to_owned(),

            ..Default::default()
        }),
    });
    let long_js = "dth\",\"height\",\"render\"];".repeat(80);
    builder.record(&Event {
        header: header(session, 30, SensorKind::Integrity),
        payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
            adapter: "jni_get_string_utf_chars".to_owned(),
            direction: "java_to_native".to_owned(),
            library: "libart.so".to_owned(),
            build_id: None,
            offset: None,
            requested_bytes: long_js.len() as u64,
            captured_bytes: u32::try_from(long_js.len()).unwrap_or(u32::MAX),
            truncated: false,
            sha256: "webpack".to_owned(),
            preview: long_js,
            preview_encoding: "utf8_lossy".to_owned(),
            content_class: "text".to_owned(),

            ..Default::default()
        }),
    });
    let report = builder.finish();
    let preview = report.plaintext[0].preview.as_deref().unwrap_or("");
    assert!(
        preview.contains("cdn.example/cd/acrossBar_v1.8.zip"),
        "longer JS must not replace URL JSON: {preview}"
    );
    assert!(report.plaintext[0]
        .urls
        .iter()
        .any(|url| url.contains("cdn.example")));
}

#[test]
fn tls_hex_does_not_hide_later_zip_urls() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    builder.record(&Event {
        header: header(session, 31, SensorKind::Integrity),
        payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
            adapter: "tls_ssl_read".to_owned(),
            direction: "recv".to_owned(),
            library: "libssl.so".to_owned(),
            build_id: None,
            offset: None,
            requested_bytes: 32,
            captured_bytes: 32,
            truncated: false,
            sha256: "h2".to_owned(),
            preview: "000000000100000005886196dc34fd28".to_owned(),
            preview_encoding: "hex".to_owned(),
            content_class: "binary".to_owned(),

            ..Default::default()
        }),
    });
    let json = r#"{"url":"https://cdn.example/cd/mobileweb-eq-homepage-v2-front-container/acrossBar_v1.8.zip"}"#;
    builder.record(&Event {
        header: header(session, 31, SensorKind::Integrity),
        payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
            adapter: "tls_ssl_read".to_owned(),
            direction: "recv".to_owned(),
            library: "libssl.so".to_owned(),
            build_id: None,
            offset: None,
            requested_bytes: json.len() as u64,
            captured_bytes: u32::try_from(json.len()).unwrap_or(u32::MAX),
            truncated: false,
            sha256: "zip".to_owned(),
            preview: json.to_owned(),
            preview_encoding: "utf8_lossy".to_owned(),
            content_class: "text".to_owned(),

            ..Default::default()
        }),
    });
    let report = builder.finish();
    let preview = report.plaintext[0].preview.as_deref().unwrap_or("");
    assert!(
        preview.contains("acrossBar_v1.8.zip"),
        "HTTP/2 hex must not hide zip URL JSON: {preview}"
    );
    assert!(!preview.starts_with("00000000"), "{preview}");
}

#[test]
fn http2_hpack_hex_preview_becomes_http_calls_and_urls() {
    let session = Uuid::new_v4();
    let block = [
        0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90,
        0xf4, 0xff,
    ];
    let mut frame = vec![
        0,
        0,
        u8::try_from(block.len()).unwrap(),
        0x1,
        0x04,
        0,
        0,
        0,
        1,
    ];
    frame.extend_from_slice(&block);
    let mut hex = String::new();
    for byte in &frame {
        let _ = std::fmt::Write::write_fmt(&mut hex, format_args!("{byte:02x}"));
    }
    let mut builder = SessionReportBuilder::default();
    builder.record(&Event {
        header: header(session, 31, SensorKind::Integrity),
        payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
            adapter: "tls_ssl_read".to_owned(),
            direction: "recv".to_owned(),
            library: "libssl.so".to_owned(),
            build_id: None,
            offset: None,
            requested_bytes: u64::try_from(frame.len()).unwrap_or(0),
            captured_bytes: u32::try_from(frame.len()).unwrap_or(u32::MAX),
            truncated: false,
            sha256: "hpack".to_owned(),
            preview: hex,
            preview_encoding: "hex".to_owned(),
            content_class: "binary".to_owned(),

            ..Default::default()
        }),
    });
    let report = builder.finish();
    assert!(
        report.http_calls.iter().any(|call| {
            call.kind == "http2_request"
                && call.method == "GET"
                && call.host.as_deref() == Some("www.example.com")
                && call.path == "/"
        }),
        "{:?}",
        report.http_calls
    );
    assert!(
        report.plaintext[0]
            .urls
            .iter()
            .any(|url| url == "http://www.example.com/" || url == "https://www.example.com/"),
        "{:?}",
        report.plaintext[0].urls
    );
}

#[test]
fn http2_hpack_dynamic_table_survives_split_ssl_reads() {
    let session = Uuid::new_v4();
    let first = [
        0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90,
        0xf4, 0xff,
    ];
    let mut frame1 = vec![
        0,
        0,
        u8::try_from(first.len()).unwrap(),
        0x1,
        0x04,
        0,
        0,
        0,
        1,
    ];
    frame1.extend_from_slice(&first);
    let second = [
        0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65,
    ];
    let mut frame2 = vec![
        0,
        0,
        u8::try_from(second.len()).unwrap(),
        0x1,
        0x04,
        0,
        0,
        0,
        3,
    ];
    frame2.extend_from_slice(&second);
    let mut hex1 = String::new();
    for byte in &frame1 {
        let _ = std::fmt::Write::write_fmt(&mut hex1, format_args!("{byte:02x}"));
    }
    let mut hex2 = String::new();
    for byte in &frame2 {
        let _ = std::fmt::Write::write_fmt(&mut hex2, format_args!("{byte:02x}"));
    }
    let mut builder = SessionReportBuilder::default();
    builder.record(&Event {
        header: header(session, 31, SensorKind::Integrity),
        payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
            adapter: "tls_ssl_read".to_owned(),
            direction: "recv".to_owned(),
            library: "libssl.so".to_owned(),
            build_id: None,
            offset: None,
            requested_bytes: u64::try_from(frame1.len()).unwrap_or(0),
            captured_bytes: u32::try_from(frame1.len()).unwrap_or(u32::MAX),
            truncated: false,
            sha256: "h1".to_owned(),
            preview: hex1,
            preview_encoding: "hex".to_owned(),
            content_class: "binary".to_owned(),

            ..Default::default()
        }),
    });
    builder.record(&Event {
        header: header(session, 31, SensorKind::Integrity),
        payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
            adapter: "tls_ssl_read".to_owned(),
            direction: "recv".to_owned(),
            library: "libssl.so".to_owned(),
            build_id: None,
            offset: None,
            requested_bytes: u64::try_from(frame2.len()).unwrap_or(0),
            captured_bytes: u32::try_from(frame2.len()).unwrap_or(u32::MAX),
            truncated: false,
            sha256: "h2".to_owned(),
            preview: hex2,
            preview_encoding: "hex".to_owned(),
            content_class: "binary".to_owned(),

            ..Default::default()
        }),
    });
    let report = builder.finish();
    let call = report
        .http_calls
        .iter()
        .find(|call| {
            call.kind == "http2_request" && call.host.as_deref() == Some("www.example.com")
        })
        .expect("h2 request");
    assert!(
        call.count >= 2 && call.header_names.iter().any(|name| name == "cache-control"),
        "dynamic :authority must survive the second SSL_read: {:?}",
        report.http_calls
    );
}

#[test]
fn private_store_sqlite_bytes_become_http_calls() {
    let dir = std::env::temp_dir().join(format!("ksight-ce-{}", Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("ce/databases")).expect("db dir");
    let mut bytes = b"COL".to_vec();
    bytes.extend_from_slice(b"https://ebs.app.example/api/session");
    bytes.push(0);
    bytes.extend_from_slice(b"https://mbs.app.example/phone/");
    std::fs::write(dir.join("ce/databases/app_mobile_database.db"), &bytes).expect("db");
    std::fs::write(
            dir.join("ce/shared_prefs.xml"),
            br#"<?xml version='1.0'?><map><string name="host">https://wap.app.example/cs/fd5/index.html</string></map>"#,
        )
        .expect("xml");
    let calls = http_calls_from_private_dir(&dir, "com.example.app");
    assert!(
        calls.iter().any(|call| {
            call.origin == "private" && call.host.as_deref() == Some("ebs.app.example")
        }),
        "{calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|call| call.host.as_deref() == Some("wap.app.example")),
        "{calls:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn catalog_keeps_first_party_paths_ahead_of_cdn() {
    let mut calls = vec![
        HttpCallActivity {
            source: "app".to_owned(),
            process_id: 1,
            direction: "private".to_owned(),
            kind: "url".to_owned(),
            method: "URL".to_owned(),
            host: Some("cdn.objects.example".to_owned()),
            path: "/img/x".to_owned(),
            status: None,
            query_keys: Vec::new(),
            header_names: Vec::new(),
            redacted_headers: Vec::new(),
            body_keys: Vec::new(),
            redacted_body_keys: Vec::new(),
            content_type: None,
            third_party: true,
            count: 99,
            origin: "private".to_owned(),
        },
        HttpCallActivity {
            source: "app".to_owned(),
            process_id: 1,
            direction: "private".to_owned(),
            kind: "url".to_owned(),
            method: "URL".to_owned(),
            host: Some("render.app.example".to_owned()),
            path: "/api/pay".to_owned(),
            status: None,
            query_keys: Vec::new(),
            header_names: Vec::new(),
            redacted_headers: Vec::new(),
            body_keys: Vec::new(),
            redacted_body_keys: Vec::new(),
            content_type: None,
            third_party: false,
            count: 1,
            origin: "private".to_owned(),
        },
    ];
    sort_http_catalog(&mut calls);
    assert_eq!(calls[0].host.as_deref(), Some("render.app.example"));
    calls[1].source = "com.example.wallet".to_owned();
    calls[1].host = Some("clients.app.example".to_owned());
    calls[1].path = "/account/gateway.htm".to_owned();
    calls[1].third_party = false;
    calls.push(HttpCallActivity {
        source: "com.example.wallet".to_owned(),
        process_id: 1,
        direction: "private".to_owned(),
        kind: "url".to_owned(),
        method: "URL".to_owned(),
        host: Some("account.chsi.com.cn".to_owned()),
        path: "/passport/session".to_owned(),
        status: None,
        query_keys: Vec::new(),
        header_names: Vec::new(),
        redacted_headers: Vec::new(),
        body_keys: Vec::new(),
        redacted_body_keys: Vec::new(),
        content_type: None,
        third_party: false,
        count: 9,
        origin: "private".to_owned(),
    });
    sort_http_catalog(&mut calls);
    assert_eq!(calls[0].host.as_deref(), Some("clients.app.example"));
}

#[test]
fn catalog_keeps_few_rows_per_path_family() {
    let mut calls = (0..12)
        .map(|index| HttpCallActivity {
            source: "us.hsbc.hsbcus".to_owned(),
            process_id: 1,
            direction: "heap".to_owned(),
            kind: "url".to_owned(),
            method: "URL".to_owned(),
            host: Some("www.us.hsbc.com".to_owned()),
            path: format!("/api/wpb-dsvc-zz-content-entity-prod-proxy/v1/entities/us/page{index}"),
            status: None,
            query_keys: Vec::new(),
            header_names: Vec::new(),
            redacted_headers: Vec::new(),
            body_keys: Vec::new(),
            redacted_body_keys: Vec::new(),
            content_type: None,
            third_party: false,
            count: 10,
            origin: "heap".to_owned(),
        })
        .collect::<Vec<_>>();
    calls.push(HttpCallActivity {
        source: "us.hsbc.hsbcus".to_owned(),
        process_id: 1,
        direction: "heap".to_owned(),
        kind: "url".to_owned(),
        method: "URL".to_owned(),
        host: Some("www.us.hsbc.com".to_owned()),
        path: "/api/session".to_owned(),
        status: None,
        query_keys: Vec::new(),
        header_names: Vec::new(),
        redacted_headers: Vec::new(),
        body_keys: Vec::new(),
        redacted_body_keys: Vec::new(),
        content_type: None,
        third_party: false,
        count: 2,
        origin: "heap".to_owned(),
    });
    sort_http_catalog(&mut calls);
    let cms = calls
        .iter()
        .filter(|row| {
            row.path
                .contains("/api/wpb-dsvc-zz-content-entity-prod-proxy/v1")
        })
        .count();
    assert!(cms <= 3, "{calls:?}");
    assert!(
        calls.iter().any(|row| row.path == "/api/session"),
        "{calls:?}"
    );
}

#[test]
fn catalog_drops_empty_host_and_truncated_prefix() {
    let mut calls = vec![
        HttpCallActivity {
            source: "app".to_owned(),
            process_id: 1,
            direction: "heap".to_owned(),
            kind: "url".to_owned(),
            method: "URL".to_owned(),
            host: None,
            path: String::new(),
            status: None,
            query_keys: Vec::new(),
            header_names: Vec::new(),
            redacted_headers: Vec::new(),
            body_keys: Vec::new(),
            redacted_body_keys: Vec::new(),
            content_type: None,
            third_party: false,
            count: 9,
            origin: "heap".to_owned(),
        },
        HttpCallActivity {
            source: "app".to_owned(),
            process_id: 1,
            direction: "heap".to_owned(),
            kind: "url".to_owned(),
            method: "URL".to_owned(),
            host: Some("data.example.co".to_owned()),
            path: String::new(),
            status: None,
            query_keys: Vec::new(),
            header_names: Vec::new(),
            redacted_headers: Vec::new(),
            body_keys: Vec::new(),
            redacted_body_keys: Vec::new(),
            content_type: None,
            third_party: false,
            count: 3,
            origin: "heap".to_owned(),
        },
        HttpCallActivity {
            source: "app".to_owned(),
            process_id: 1,
            direction: "heap".to_owned(),
            kind: "url".to_owned(),
            method: "URL".to_owned(),
            host: Some("data.example.com".to_owned()),
            path: "/api/quote".to_owned(),
            status: None,
            query_keys: Vec::new(),
            header_names: Vec::new(),
            redacted_headers: Vec::new(),
            body_keys: Vec::new(),
            redacted_body_keys: Vec::new(),
            content_type: None,
            third_party: false,
            count: 1,
            origin: "heap".to_owned(),
        },
    ];
    sort_http_catalog(&mut calls);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].host.as_deref(), Some("data.example.com"));
    calls.push(HttpCallActivity {
        source: "app".to_owned(),
        process_id: 1,
        direction: "heap".to_owned(),
        kind: "url".to_owned(),
        method: "URL".to_owned(),
        host: Some("data.example.com".to_owned()),
        path: "/api".to_owned(),
        status: None,
        query_keys: Vec::new(),
        header_names: Vec::new(),
        redacted_headers: Vec::new(),
        body_keys: Vec::new(),
        redacted_body_keys: Vec::new(),
        content_type: None,
        third_party: false,
        count: 4,
        origin: "heap".to_owned(),
    });
    sort_http_catalog(&mut calls);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].path, "/api/quote");
}

#[test]
fn jni_plaintext_graphs_jni_from_java() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    builder.record(&Event {
        header: header(session, 10, SensorKind::Integrity),
        payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
            adapter: "jni_get_string_utf_chars".to_owned(),
            direction: "java_to_native".to_owned(),
            library: "/apex/com.android.art/lib64/libart.so".to_owned(),
            build_id: None,
            offset: Some(0x0080_d02c),
            requested_bytes: 12,
            captured_bytes: 11,
            truncated: false,
            sha256: "aabbccdd".to_owned(),
            preview: "hello world".to_owned(),
            preview_encoding: "utf8_lossy".to_owned(),
            content_class: "text".to_owned(),

            ..Default::default()
        }),
    });
    let report = builder.finish();
    assert_eq!(report.plaintext[0].adapter, "jni_get_string_utf_chars");
    assert!(report
        .graph
        .edges
        .iter()
        .any(|edge| edge.relation == "jni_from_java"));
    assert!(report
        .inspect_hits
        .iter()
        .any(|hit| hit.adapter == "jni_get_string_utf_chars" && hit.hits >= 1));
}

#[test]
fn parses_http_calls_from_inspect_plaintext_and_redacts_tokens() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    let preview = concat!(
        "POST /v6/feed/createFeed HTTP/1.1\r\n",
        "Host: api.coolapk.com\r\n",
        "Cookie: session=secret\r\n",
        "X-App-Token: abc\r\n",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "\r\n",
        "message=hello&status=1&_v2_post_token=xyz"
    );
    builder.record(&Event {
        header: header(session, 10, SensorKind::Integrity),
        payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
            adapter: "tls_ssl_write".to_owned(),
            direction: "send".to_owned(),
            library: "libssl.so".to_owned(),
            build_id: None,
            offset: None,
            requested_bytes: preview.len() as u64,
            captured_bytes: u32::try_from(preview.len()).unwrap_or(u32::MAX),
            truncated: false,
            sha256: "feed1".to_owned(),
            preview: preview.to_owned(),
            preview_encoding: "utf8_lossy".to_owned(),
            content_class: "text".to_owned(),

            ..Default::default()
        }),
    });
    builder.record(&Event {
        header: header(session, 10, SensorKind::Integrity),
        payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
            adapter: "tls_ssl_write".to_owned(),
            direction: "send".to_owned(),
            library: "libssl.so".to_owned(),
            build_id: None,
            offset: None,
            requested_bytes: 80,
            captured_bytes: 80,
            truncated: false,
            sha256: "tracker1".to_owned(),
            preview: "GET /v6/main/indexV8?page=1 HTTP/1.1\r\nHost: log-api.pangle.io\r\n\r\n"
                .to_owned(),
            preview_encoding: "utf8_lossy".to_owned(),
            content_class: "text".to_owned(),

            ..Default::default()
        }),
    });
    let report = builder.finish();
    assert_eq!(report.http_calls.len(), 2);
    let create = report
        .http_calls
        .iter()
        .find(|row| row.path == "/v6/feed/createFeed")
        .expect("createFeed");
    assert_eq!(create.method, "POST");
    assert_eq!(create.host.as_deref(), Some("api.coolapk.com"));
    assert_eq!(create.count, 1);
    assert!(!create.third_party);
    assert!(create
        .redacted_headers
        .iter()
        .any(|row| row.starts_with("Cookie=")));
    assert!(create
        .redacted_body_keys
        .contains(&"_v2_post_token".to_owned()));
    assert!(!create.body_keys.iter().any(|key| key.contains("xyz")));
    let tracker = report
        .http_calls
        .iter()
        .find(|row| row.third_party)
        .expect("tracker");
    assert_eq!(tracker.host.as_deref(), Some("log-api.pangle.io"));
    assert!(report
        .graph
        .edges
        .iter()
        .any(|edge| edge.relation == "http_call"));
    assert!(report
        .limitations
        .iter()
        .any(|line| line.contains("http_calls")));
    assert_eq!(
        report
            .http_calls
            .iter()
            .find(|row| row.path == "/v6/feed/createFeed")
            .map(|row| row.origin.as_str()),
        Some("inspect")
    );
}

#[test]
fn ingest_heap_http_calls_are_correlated_and_pair_by_host() {
    let session = Uuid::new_v4();
    let mut builder = SessionReportBuilder::default();
    builder.record(&Event {
        header: header(session, 10, SensorKind::Integrity),
        payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
            adapter: "tls_ssl_write".to_owned(),
            direction: "send".to_owned(),
            library: "libssl.so".to_owned(),
            build_id: None,
            offset: None,
            requested_bytes: 40,
            captured_bytes: 40,
            truncated: false,
            sha256: "req".to_owned(),
            preview: "POST /v1/session HTTP/1.1\r\nHost: pay.example\r\n\r\n".to_owned(),
            preview_encoding: "utf8_lossy".to_owned(),
            content_class: "text".to_owned(),

            ..Default::default()
        }),
    });
    builder.record(&Event {
        header: header(session, 10, SensorKind::Integrity),
        payload: EventPayload::InspectPlaintext(ksight_model::InspectPlaintext {
            adapter: "tls_ssl_read".to_owned(),
            direction: "recv".to_owned(),
            library: "libssl.so".to_owned(),
            build_id: None,
            offset: None,
            requested_bytes: 40,
            captured_bytes: 40,
            truncated: false,
            sha256: "resp".to_owned(),
            preview:
                "HTTP/1.1 200 OK\r\nHost: pay.example\r\nContent-Type: application/json\r\n\r\n{}"
                    .to_owned(),
            preview_encoding: "utf8_lossy".to_owned(),
            content_class: "text".to_owned(),
            ..Default::default()
        }),
    });
    let mut report = builder.finish();
    report.ingest_dump_http_calls(vec![HttpCallActivity {
        source: "com.example".to_owned(),
        process_id: 10,
        direction: "heap".to_owned(),
        kind: "http1_response".to_owned(),
        method: "HTTP".to_owned(),
        host: None,
        path: String::new(),
        status: Some(200),
        query_keys: Vec::new(),
        header_names: vec!["Content-Type".to_owned()],
        redacted_headers: Vec::new(),
        body_keys: Vec::new(),
        redacted_body_keys: Vec::new(),
        content_type: Some("image/jpeg".to_owned()),
        third_party: false,
        count: 1,
        origin: "heap".to_owned(),
    }]);
    assert!(report
        .http_calls
        .iter()
        .any(|row| row.origin == "heap" && row.status == Some(200) && row.path.is_empty()));
    assert!(report
        .graph
        .edges
        .iter()
        .any(|edge| edge.relation == "http_reply"
            && edge.strength == crate::EdgeStrength::Correlated));
    assert!(report.graph.edges.iter().any(|edge| {
        edge.relation == "http_call" && edge.strength == crate::EdgeStrength::Correlated
    }));
}

#[test]
fn correlates_http_path_to_dex_string_and_method() {
    let calls = vec![HttpCallActivity {
        source: "com.example".to_owned(),
        process_id: 1,
        direction: "send".to_owned(),
        kind: "http1_request".to_owned(),
        method: "POST".to_owned(),
        host: Some("api.coolapk.com".to_owned()),
        path: "/v6/feed/createFeed".to_owned(),
        status: None,
        query_keys: Vec::new(),
        header_names: Vec::new(),
        redacted_headers: Vec::new(),
        body_keys: Vec::new(),
        redacted_body_keys: Vec::new(),
        content_type: None,
        third_party: false,
        count: 1,
        origin: "inspect".to_owned(),
    }];
    let semantic = crate::DexSemanticSummary {
        api_strings: vec!["https://api.coolapk.com/v6/feed/createFeed".to_owned()],
        method_names: vec!["Lcom/coolapk/Market;->createFeed".to_owned()],
        ..crate::DexSemanticSummary::default()
    };
    let set = crate::DexArtifactSet {
        sha256: "abc".to_owned(),
        bytes: 10,
        canonical_relative_path: "readable-dex/x.dex".to_owned(),
        sources: vec!["heap-blob".to_owned()],
        observations: Vec::new(),
        semantic: Some(semantic),
    };
    let refs = correlate_http_calls_to_dex(&calls, &[set]);
    assert_eq!(refs.len(), 1);
    assert!(refs[0].matches.iter().any(|row| row.contains("createFeed")));
    assert_eq!(refs[0].relative_path.as_deref(), Some("readable-dex/x.dex"));
}

fn inspect_transact_event(session_id: Uuid, pid: u32, tid: u32, code: u32) -> Event {
    let mut event = Event {
        header: header(session_id, pid, SensorKind::Integrity),
        payload: EventPayload::InspectObservation(InspectObservation {
            adapter: "binder_userspace".to_owned(),
            attached: true,
            hit: true,
            library: "/system/lib64/libbinder.so".to_owned(),
            binder_handle: Some(3),
            binder_code: Some(code),
            binder_interface: Some("android.os.IServiceManager".to_owned()),
            binder_method: Some("getService".to_owned()),
            binder_method_source: Some("aosp_stub".to_owned()),
            detail: format!("binder transact hit pid={pid} code={code:#x}"),
            ..InspectObservation::default()
        }),
    };
    event.header.process.tid = tid;
    event.header.mode = CaptureMode::Inspect;
    event
}

fn binder_event(session_id: Uuid, pid: u32, target: Option<u32>, reply: bool, code: u32) -> Event {
    Event {
        header: header(session_id, pid, SensorKind::Binder),
        payload: EventPayload::BinderTransaction(BinderTransaction {
            stage: BinderTransactionStage::Submitted,
            transaction_id: i32::try_from(pid).unwrap_or_default(),
            target_node: None,
            target_process_id: target,
            target_thread_id: None,
            target_kind: None,
            reply,
            direction: BinderTransactionDirection::Request,
            reply_to_request_id: None,
            reply_latency_ns: None,
            code,
            code_kind: None,
            flags: 0,
            decoded_flags: Vec::new(),
            data_size: None,
            offsets_size: None,
            extra_buffers_size: None,
            file_descriptor: None,
            object_offset: None,
            transferred_fd_origin: None,
            transferred_fd_source_pid: None,
            transferred_fd_source_fd: None,
            interface_token: None,
            binder_method: None,
            binder_method_source: None,
            parcel_prefix_hex: None,
        }),
    }
}

fn file_event(session_id: Uuid, path: &str) -> Event {
    Event {
        header: header(session_id, 10, SensorKind::File),
        payload: EventPayload::FileOpen(ksight_model::FileOpen {
            directory_fd: -100,
            file_descriptor: Some(3),
            result: 3,
            flags: 0,
            mode: 0,
            path: path.to_owned(),
            resolved_path: None,
            content_sha256: None,
            content_bytes: None,
        }),
    }
}

fn fd_event(session_id: Uuid, operation: FileDescriptorOperation, fd: i32, result: i32) -> Event {
    Event {
        header: header(session_id, 10, SensorKind::File),
        payload: EventPayload::FileDescriptorChange(ksight_model::FileDescriptorChange {
            operation,
            file_descriptor: fd,
            requested_file_descriptor: None,
            resulting_file_descriptor: (operation == FileDescriptorOperation::Duplicate)
                .then_some(result),
            result,
            command: 0,
            flags: 0,
            last_file_descriptor: None,
        }),
    }
}

fn socket_event(session_id: Uuid, fd: i32, result: i32) -> Event {
    Event {
        header: header(session_id, 10, SensorKind::Network),
        payload: EventPayload::SocketConnect(ksight_model::SocketConnect {
            file_descriptor: fd,
            result,
            address_family: 2,
            submitted_address_length: 16,
            captured_address_length: 16,
            peer_address: Some("127.0.0.1".to_owned()),
            peer_port: Some(443),
            scope_id: None,
            resolved_name: None,
        }),
    }
}

fn socket_accept_event(session_id: Uuid, listening_fd: i32, accepted_fd: i32) -> Event {
    Event {
        header: header(session_id, 10, SensorKind::Network),
        payload: EventPayload::SocketAccept(ksight_model::SocketAccept {
            listening_file_descriptor: listening_fd,
            accepted_file_descriptor: Some(accepted_fd),
            result: accepted_fd,
            address_family: 2,
            returned_address_length: 16,
            captured_address_length: 16,
            peer_address: Some("127.0.0.2".to_owned()),
            peer_port: Some(8443),
            scope_id: None,
        }),
    }
}

fn socket_io_event(session_id: Uuid, fd: i32, operation: SocketIoOperation, result: i64) -> Event {
    Event {
        header: header(session_id, 10, SensorKind::Network),
        payload: EventPayload::SocketIo(ksight_model::SocketIo {
            file_descriptor: fd,
            operation,
            result,
            requested_bytes: Some(u64::try_from(result).expect("positive test result")),
            syscall: if operation == SocketIoOperation::Send {
                206
            } else {
                207
            },
        }),
    }
}

fn memory_event(session_id: Uuid, operation: MemoryOperation, address: u64, length: u64) -> Event {
    Event {
        header: header(session_id, 10, SensorKind::Memory),
        payload: EventPayload::MemoryRegionChange(ksight_model::MemoryRegionChange {
            operation,
            address,
            length,
            result: if operation == MemoryOperation::Map {
                i64::try_from(address).expect("test address")
            } else {
                0
            },
            protection: 5,
            mapping_flags: (operation == MemoryOperation::Map).then_some(2),
            file_descriptor: None,
            backing_path: None,
            offset: None,
        }),
    }
}

fn header(session_id: Uuid, pid: u32, sensor: SensorKind) -> EventHeader {
    EventHeader {
        schema: SchemaVersion {
            major: 1,
            minor: 10,
        },
        session_id,
        source_sequence: u64::from(pid),
        monotonic_ns: u64::from(pid),
        cpu: Some(0),
        process: ProcessIdentity {
            key: ProcessKey {
                boot_id: Uuid::nil(),
                pid,
                start_time_ns: 1,
            },
            tid: pid,
            tgid: pid,
            uid: 10_000,
            gid: 10_000,
            comm: format!("proc-{pid}"),
            command_line: None,
            selinux_context: None,
            packages: vec![PackageCandidate {
                package_name: "com.example".to_owned(),
                source: "test".to_owned(),
                confidence_percent: 100,
            }],
        },
        sensor,
        mode: CaptureMode::Observe,
        quality: DataQuality {
            confidence: Confidence::Confirmed,
            truncated: false,
            lost_before: 0,
            sample_one_in: 1,
            source: "test".to_owned(),
        },
    }
}
