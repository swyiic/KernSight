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
    __uint(max_entries, 1 << 22);
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

/* Native 64-bit UAPI binder_transaction_data. 32-bit clients are converted
 * by the driver before binder_transaction(), so one kprobe covers both ABIs. */
#define KSIGHT_BINDER_TR_CODE 16
#define KSIGHT_BINDER_TR_DATA_SIZE 32
#define KSIGHT_BINDER_TR_BUFFER 48

struct ksight_pt_regs {
    ksight_u64 regs[31];
    ksight_u64 sp;
    ksight_u64 pc;
    ksight_u64 pstate;
};

struct ksight_parcel_stash {
    ksight_u32 code;
    ksight_u32 copied;
    ksight_u32 truncated;
    ksight_u8 data[KSIGHT_BINDER_PARCEL_BYTES];
};

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, ksight_u32);
    __type(value, struct ksight_parcel_stash);
} parcel_stash SEC(".maps");

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

static __always_inline void
ksight_copy_parcel_prefix(struct ksight_parcel_stash *stash, const void *buffer,
                          ksight_u64 data_size)
{
    stash->truncated = data_size > KSIGHT_BINDER_PARCEL_BYTES ? 1U : 0U;
    if (ksight_bpf_probe_read_user(stash->data, 128, buffer) == 0 ||
        ksight_bpf_probe_read_kernel(stash->data, 128, buffer) == 0) {
        stash->copied = data_size > 128 ? 128 : (ksight_u32)data_size;
        return;
    }
    if (ksight_bpf_probe_read_user(stash->data, 64, buffer) == 0 ||
        ksight_bpf_probe_read_kernel(stash->data, 64, buffer) == 0) {
        stash->copied = data_size > 64 ? 64 : (ksight_u32)data_size;
        if (data_size > 64)
            stash->truncated = 1;
        return;
    }
    if (ksight_bpf_probe_read_user(stash->data, 32, buffer) == 0 ||
        ksight_bpf_probe_read_kernel(stash->data, 32, buffer) == 0) {
        stash->copied = data_size > 32 ? 32 : (ksight_u32)data_size;
        if (data_size > 32)
            stash->truncated = 1;
        return;
    }
    stash->copied = 0;
}

static __always_inline void
ksight_emit_parcel(const struct ksight_parcel_stash *stash, ksight_s32 transaction_id,
                   ksight_u64 pid_tgid, ksight_u64 uid_gid)
{
    struct ksight_binder_parcel_event *event;

    if (!stash || stash->copied == 0)
        return;
    event = ksight_bpf_ringbuf_reserve(&binder_events, sizeof(*event), 0);
    if (!event) {
        ksight_record_drop();
        return;
    }
    __builtin_memset(event, 0, sizeof(*event));
    ksight_fill_binder_header(&event->header, KSIGHT_EVENT_BINDER_PARCEL,
                              sizeof(*event), pid_tgid, uid_gid);
    event->transaction_id = transaction_id;
    event->code = stash->code;
    event->copied = stash->copied;
    event->truncated = stash->truncated;
    __builtin_memcpy(event->data, stash->data, KSIGHT_BINDER_PARCEL_BYTES);
    ksight_bpf_ringbuf_submit(event, 0);
}

static __always_inline void
ksight_emit_stashed_parcel(ksight_s32 transaction_id, ksight_u32 tid,
                           ksight_u64 pid_tgid, ksight_u64 uid_gid)
{
    struct ksight_parcel_stash *stash;

    stash = ksight_bpf_map_lookup_elem(&parcel_stash, &tid);
    if (!stash)
        return;
    ksight_emit_parcel(stash, transaction_id, pid_tgid, uid_gid);
    ksight_bpf_map_delete_elem(&parcel_stash, &tid);
}

SEC("kprobe/binder_transaction")
int ksight_binder_parcel_enter(struct ksight_pt_regs *ctx)
{
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;
    ksight_u32 tid;
    ksight_u64 tr;
    ksight_u64 reply;
    ksight_u64 data_size = 0;
    ksight_u64 buffer = 0;
    ksight_u32 code = 0;
    struct ksight_parcel_stash stash;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    uid_gid = ksight_bpf_get_current_uid_gid();
    if (!ksight_identity_allowed(pid_tgid, uid_gid))
        return 0;

    tr = ctx->regs[2];
    reply = ctx->regs[3];
    if (tr == 0 || (reply & 0xffffffffULL) != 0)
        return 0;
    if (ksight_bpf_probe_read_kernel(&code, sizeof(code),
                                     (const void *)(tr + KSIGHT_BINDER_TR_CODE)) != 0)
        return 0;
    if (ksight_bpf_probe_read_kernel(&data_size, sizeof(data_size),
                                     (const void *)(tr + KSIGHT_BINDER_TR_DATA_SIZE)) != 0)
        return 0;
    if (ksight_bpf_probe_read_kernel(&buffer, sizeof(buffer),
                                     (const void *)(tr + KSIGHT_BINDER_TR_BUFFER)) != 0)
        return 0;
    if (buffer == 0 || data_size < 8)
        return 0;

    __builtin_memset(&stash, 0, sizeof(stash));
    stash.code = code;
    ksight_copy_parcel_prefix(&stash, (const void *)buffer, data_size);
    if (stash.copied == 0)
        return 0;
    tid = (ksight_u32)pid_tgid;
    ksight_emit_parcel(&stash, 0, pid_tgid, uid_gid);
    if (ksight_bpf_map_update_elem(&parcel_stash, &tid, &stash, 0) != 0)
        ksight_record_drop();
    return 0;
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

    if (context->reply == 0)
        ksight_emit_stashed_parcel(context->debug_id, (ksight_u32)pid_tgid,
                                   pid_tgid, uid_gid);

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
