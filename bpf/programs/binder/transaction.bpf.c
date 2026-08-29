/* SPDX-License-Identifier: GPL-2.0-only */
#include "ksight_binder_event.h"
#include "ksight_bpf_helpers.h"
#include "ksight_sensor_runtime.h"

struct ksight_trace_entry {
    ksight_u16 type;
    ksight_u8 flags;
    ksight_u8 preempt_count;
    ksight_s32 pid;
};

struct ksight_binder_transaction_trace {
    struct ksight_trace_entry common;
    ksight_s32 debug_id;
    ksight_s32 target_node;
    ksight_s32 to_proc;
    ksight_s32 to_thread;
    ksight_s32 reply;
    ksight_u32 code;
    ksight_u32 flags;
};

struct ksight_binder_transaction_received_trace {
    struct ksight_trace_entry common;
    ksight_s32 debug_id;
};

struct ksight_binder_transaction_alloc_trace {
    struct ksight_trace_entry common;
    ksight_s32 debug_id;
    ksight_u32 padding;
    ksight_u64 data_size;
    ksight_u64 offsets_size;
    ksight_u64 extra_buffers_size;
};

struct ksight_binder_transaction_fd_trace {
    struct ksight_trace_entry common;
    ksight_s32 debug_id;
    ksight_s32 fd;
    ksight_u64 offset;
};

/* 等待回复的请求：key = 客户端线程 tid，value = 请求 debug_id + 提交时间 */
struct ksight_pending_request {
    ksight_s32 request_id;
    ksight_u64 submitted_ns;
};

#define KSIGHT_BINDER_TF_ONE_WAY 0x01U

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} binder_events SEC(".maps");

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, ksight_s32);
    __type(value, ksight_u8);
} tracked_transactions SEC(".maps");

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, ksight_u64);
    __type(value, struct ksight_pending_request);
} pending_requests SEC(".maps");

static __always_inline void
ksight_fill_binder_header(struct ksight_raw_event_header *header,
                          ksight_u16 event_type,
                          ksight_u32 total_size,
                          ksight_u64 pid_tgid,
                          ksight_u64 uid_gid)
{
    header->abi_version = KSIGHT_RAW_ABI_VERSION;
    header->header_size = sizeof(*header);
    header->sensor_id = KSIGHT_SENSOR_BINDER;
    header->event_type = event_type;
    header->total_size = total_size;
    header->flags = KSIGHT_EVENT_F_IDENTITY_PARTIAL;
    header->source_sequence = ksight_next_sequence();
    header->monotonic_ns = ksight_bpf_ktime_get_ns();
    header->cpu = ksight_bpf_get_smp_processor_id();
    header->uid = (ksight_u32)uid_gid;
    header->gid = (ksight_u32)(uid_gid >> 32);
    header->tid = (ksight_u32)pid_tgid;
    header->tgid = (ksight_u32)(pid_tgid >> 32);
    header->pid = header->tgid;
    ksight_bpf_get_current_comm(header->comm, sizeof(header->comm));
}

SEC("tracepoint/binder/binder_transaction")
int ksight_binder_transaction(struct ksight_binder_transaction_trace *context)
{
    struct ksight_binder_event *event;
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;
    ksight_u8 tracked = 1;
    ksight_s32 transaction_key;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    uid_gid = ksight_bpf_get_current_uid_gid();
    transaction_key = context->debug_id;
    if (!ksight_should_capture(pid_tgid, uid_gid))
        return 0;

    event = ksight_bpf_ringbuf_reserve(&binder_events, sizeof(*event), 0);
    if (!event) {
        ksight_record_drop();
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    ksight_fill_binder_header(&event->header,
                              KSIGHT_EVENT_BINDER_TRANSACTION,
                              sizeof(*event), pid_tgid, uid_gid);

    event->transaction_id = context->debug_id;
    event->target_node = context->target_node;
    event->target_tgid = context->to_proc;
    event->target_tid = context->to_thread;
    event->reply = (ksight_u32)context->reply;
    event->code = context->code;
    event->transaction_flags = context->flags;

    if (context->reply != 0) {
        /* 回复方向：reply 的 to_thread/to_proc 即原请求的发起线程（客户端线程）。
         * 用客户端线程 (tgid,tid) 复合键查回提交时记录的请求 id。 */
        struct ksight_pending_request *pending;
        ksight_u64 key = ((ksight_u64)(ksight_u32)context->to_proc << 32) |
                         (ksight_u64)(ksight_u32)context->to_thread;

        pending = ksight_bpf_map_lookup_elem(&pending_requests, &key);
        if (pending) {
            event->request_transaction_id = pending->request_id;
            ksight_bpf_map_delete_elem(&pending_requests, &key);
        }
    } else if ((context->flags & KSIGHT_BINDER_TF_ONE_WAY) == 0) {
        /* 请求方向：用当前线程 pid_tgid（客户端线程）记录请求 id + 提交时间。
         * 后续该线程收到的 reply 会以相同 (tgid,tid) 复合键回查。 */
        struct ksight_pending_request pending = {
            .request_id = context->debug_id,
            .submitted_ns = event->header.monotonic_ns,
        };
        ksight_u64 key = pid_tgid;

        if (ksight_bpf_map_update_elem(&pending_requests, &key,
                                       &pending, 0) != 0)
            ksight_record_drop();
    }

    ksight_bpf_ringbuf_submit(event, 0);
    if (ksight_bpf_map_update_elem(&tracked_transactions,
                                   &transaction_key, &tracked, 0) != 0)
        ksight_record_drop();
    return 0;
}

SEC("tracepoint/binder/binder_transaction_received")
int ksight_binder_transaction_received(
    struct ksight_binder_transaction_received_trace *context)
{
    struct ksight_binder_event *event;
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;
    ksight_s32 transaction_key = context->debug_id;

    if (!ksight_bpf_map_lookup_elem(&tracked_transactions,
                                    &transaction_key))
        return 0;
    event = ksight_bpf_ringbuf_reserve(&binder_events, sizeof(*event), 0);
    if (!event) {
        ksight_record_drop();
        return 0;
    }
    pid_tgid = ksight_bpf_get_current_pid_tgid();
    uid_gid = ksight_bpf_get_current_uid_gid();
    __builtin_memset(event, 0, sizeof(*event));
    ksight_fill_binder_header(&event->header,
                              KSIGHT_EVENT_BINDER_TRANSACTION_RECEIVED,
                              sizeof(*event), pid_tgid, uid_gid);
    event->transaction_id = context->debug_id;
    ksight_bpf_ringbuf_submit(event, 0);
    ksight_bpf_map_delete_elem(&tracked_transactions, &transaction_key);
    return 0;
}

SEC("tracepoint/binder/binder_transaction_alloc_buf")
int ksight_binder_buffer_allocated(
    struct ksight_binder_transaction_alloc_trace *context)
{
    struct ksight_binder_buffer_event *event;
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;
    ksight_s32 transaction_key = context->debug_id;

    if (!ksight_bpf_map_lookup_elem(&tracked_transactions,
                                    &transaction_key))
        return 0;
    event = ksight_bpf_ringbuf_reserve(&binder_events, sizeof(*event), 0);
    if (!event) {
        ksight_record_drop();
        return 0;
    }
    pid_tgid = ksight_bpf_get_current_pid_tgid();
    uid_gid = ksight_bpf_get_current_uid_gid();
    __builtin_memset(event, 0, sizeof(*event));
    ksight_fill_binder_header(&event->header,
                              KSIGHT_EVENT_BINDER_BUFFER_ALLOCATED,
                              sizeof(*event), pid_tgid, uid_gid);
    event->transaction_id = context->debug_id;
    event->data_size = context->data_size;
    event->offsets_size = context->offsets_size;
    event->extra_buffers_size = context->extra_buffers_size;
    ksight_bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int
ksight_emit_binder_fd(struct ksight_binder_transaction_fd_trace *context,
                      ksight_u16 event_type)
{
    struct ksight_binder_fd_event *event;
    ksight_s32 transaction_key = context->debug_id;
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;

    if (!ksight_bpf_map_lookup_elem(&tracked_transactions, &transaction_key))
        return 0;
    event = ksight_bpf_ringbuf_reserve(&binder_events, sizeof(*event), 0);
    if (!event) {
        ksight_record_drop();
        return 0;
    }
    pid_tgid = ksight_bpf_get_current_pid_tgid();
    uid_gid = ksight_bpf_get_current_uid_gid();
    __builtin_memset(event, 0, sizeof(*event));
    ksight_fill_binder_header(&event->header, event_type,
                              sizeof(*event), pid_tgid, uid_gid);
    event->transaction_id = context->debug_id;
    event->fd = context->fd;
    event->object_offset = context->offset;
    ksight_bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/binder/binder_transaction_fd_send")
int ksight_binder_fd_sent(struct ksight_binder_transaction_fd_trace *context)
{
    return ksight_emit_binder_fd(context, KSIGHT_EVENT_BINDER_FD_SENT);
}

SEC("tracepoint/binder/binder_transaction_fd_recv")
int ksight_binder_fd_received(struct ksight_binder_transaction_fd_trace *context)
{
    return ksight_emit_binder_fd(context, KSIGHT_EVENT_BINDER_FD_RECEIVED);
}

char LICENSE[] SEC("license") = "GPL";
