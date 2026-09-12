use std::collections::HashSet;

use ksight_model::{
    BinderTransaction, BinderTransactionDirection, BinderTransactionStage, EventPayload,
};

use super::{
    apply_pending_parcel, binder_event_matches_scope, insert_capped, push_capped_deque,
    PendingParcel,
};

#[test]
fn binder_follow_on_stages_keep_the_originating_process_scope() {
    let mut tracked = HashSet::new();
    assert!(binder_event_matches_scope(
        true,
        &binder(BinderTransactionStage::Submitted, 42),
        &mut tracked,
    ));
    assert!(binder_event_matches_scope(
        false,
        &binder(BinderTransactionStage::BufferAllocated, 42),
        &mut tracked,
    ));
    assert!(binder_event_matches_scope(
        false,
        &binder(BinderTransactionStage::Received, 42),
        &mut tracked,
    ));
    assert!(tracked.is_empty());
    assert!(!binder_event_matches_scope(
        false,
        &binder(BinderTransactionStage::Received, 43),
        &mut tracked,
    ));
}

#[test]
fn pending_parcel_fills_submit_token_and_hex() {
    let EventPayload::BinderTransaction(mut transaction) =
        binder(BinderTransactionStage::Submitted, 42)
    else {
        panic!("binder");
    };
    apply_pending_parcel(
        &mut transaction,
        PendingParcel {
            interface_token: Some("android.os.IServiceManager".to_owned()),
            binder_method: Some("getService".to_owned()),
            binder_method_source: Some("aosp_stub".to_owned()),
            parcel_prefix_hex: Some("04000000".to_owned()),
        },
    );
    assert_eq!(
        transaction.interface_token.as_deref(),
        Some("android.os.IServiceManager")
    );
    assert_eq!(transaction.binder_method.as_deref(), Some("getService"));
    assert_eq!(transaction.parcel_prefix_hex.as_deref(), Some("04000000"));
    let mut map = std::collections::HashMap::new();
    insert_capped(&mut map, 1_i32, 1_u8);
    assert_eq!(map.get(&1), Some(&1));
    let mut queues = std::collections::HashMap::new();
    push_capped_deque(&mut queues, 7_u32, "a", 2);
    push_capped_deque(&mut queues, 7_u32, "b", 2);
    push_capped_deque(&mut queues, 7_u32, "c", 2);
    assert_eq!(
        queues
            .get_mut(&7)
            .and_then(std::collections::VecDeque::pop_front),
        Some("b")
    );
}

fn binder(stage: BinderTransactionStage, transaction_id: i32) -> EventPayload {
    EventPayload::BinderTransaction(BinderTransaction {
        stage,
        transaction_id,
        target_node: None,
        target_process_id: None,
        target_thread_id: None,
        target_kind: None,
        reply: false,
        direction: BinderTransactionDirection::Request,
        reply_to_request_id: None,
        reply_latency_ns: None,
        code: 0,
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
    })
}
