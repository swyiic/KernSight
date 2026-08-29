/* SPDX-License-Identifier: GPL-2.0-only */
#include "ksight_bpf_helpers.h"
#include "ksight_memory_event.h"
#include "ksight_sensor_runtime.h"
#include "ksight_syscall_compat.h"

struct ksight_trace_entry {
    ksight_u16 type;
    ksight_u8 flags;
    ksight_u8 preempt_count;
    ksight_s32 pid;
};

struct ksight_raw_sys_enter {
    struct ksight_trace_entry common;
    ksight_s64 id;
    ksight_u64 arguments[6];
};

struct ksight_raw_sys_exit {
    struct ksight_trace_entry common;
    ksight_s64 id;
    ksight_s64 result;
};



#define KSIGHT_PROT_EXEC 4U
#define KSIGHT_MEMORY_KEEP_BYTES (256ULL * 1024ULL)
#define KSIGHT_MEMORY_LARGE_BYTES (1024ULL * 1024ULL)

static __always_inline int ksight_capture_all_memory(void)
{
    ksight_u32 key = 3;
    ksight_u32 *enabled = ksight_bpf_map_lookup_elem(&control, &key);

    return enabled && *enabled != 0;
}

/* Packed-app heaps are multi-megabyte anonymous maps. Page-permission storms are not. */
static __always_inline int ksight_memory_keep(ksight_s64 syscall_id, const ksight_u64 *arguments,
                                             int capture_all)
{
    ksight_u64 length = arguments[1];
    ksight_u32 protection = (ksight_u32)arguments[2];

    if (ksight_syscall_is_mmap(syscall_id)) {
        if ((protection & KSIGHT_PROT_EXEC) != 0)
            return 1;
        return capture_all && length >= KSIGHT_MEMORY_KEEP_BYTES;
    }
    if (ksight_syscall_is_mprotect(syscall_id)) {
        if ((protection & KSIGHT_PROT_EXEC) != 0)
            return 1;
        return capture_all && length >= KSIGHT_MEMORY_LARGE_BYTES;
    }
    if (ksight_syscall_is_munmap(syscall_id))
        return capture_all && length >= KSIGHT_MEMORY_KEEP_BYTES;
    if (ksight_syscall_is_mremap(syscall_id))
        return capture_all && arguments[2] >= KSIGHT_MEMORY_KEEP_BYTES;
    if (ksight_syscall_is_brk(syscall_id))
        return capture_all;
    return 0;
}

struct ksight_pending_memory {
    ksight_u64 address;
    ksight_u64 length;
    ksight_u64 offset;
    ksight_s32 fd;
    ksight_u32 protection;
    ksight_u32 map_flags;
    ksight_u16 event_type;
    ksight_u16 reserved;
};

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23);
} memory_events SEC(".maps");

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, ksight_u64);
    __type(value, struct ksight_pending_memory);
} pending_memory SEC(".maps");

static __always_inline int ksight_is_memory_syscall(ksight_s64 syscall_id)
{
    return ksight_syscall_is_mmap(syscall_id) ||
           ksight_syscall_is_mprotect(syscall_id) ||
           ksight_syscall_is_munmap(syscall_id) ||
           ksight_syscall_is_mremap(syscall_id) ||
           ksight_syscall_is_brk(syscall_id);
}

SEC("tracepoint/raw_syscalls/sys_enter")
int ksight_memory_enter(struct ksight_raw_sys_enter *context)
{
    struct ksight_pending_memory pending = {};
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;
    int capture_all;

    if (!ksight_is_memory_syscall(context->id))
        return 0;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    uid_gid = ksight_bpf_get_current_uid_gid();
    if (!ksight_identity_allowed(pid_tgid, uid_gid))
        return 0;
    capture_all = ksight_capture_all_memory();
    if (!ksight_memory_keep(context->id, context->arguments, capture_all))
        return 0;

    pending.address = context->arguments[0];
    pending.length = context->arguments[1];
    pending.protection = 0;
    pending.fd = -1;
    if (ksight_syscall_is_mmap(context->id)) {
        pending.event_type = KSIGHT_EVENT_MEMORY_MAP;
        pending.protection = (ksight_u32)context->arguments[2];
        pending.map_flags = (ksight_u32)context->arguments[3];
        pending.fd = (ksight_s32)context->arguments[4];
        pending.offset = context->arguments[5];
    } else if (ksight_syscall_is_mprotect(context->id)) {
        pending.event_type = KSIGHT_EVENT_MEMORY_PROTECT;
        pending.protection = (ksight_u32)context->arguments[2];
    } else if (ksight_syscall_is_mremap(context->id)) {
        pending.event_type = KSIGHT_EVENT_MEMORY_REMAP;
        pending.offset = context->arguments[2];
        pending.map_flags = (ksight_u32)context->arguments[3];
    } else if (ksight_syscall_is_brk(context->id)) {
        pending.event_type = KSIGHT_EVENT_MEMORY_BRK;
        pending.length = 0;
    } else {
        pending.event_type = KSIGHT_EVENT_MEMORY_UNMAP;
    }

    if (ksight_bpf_map_update_elem(&pending_memory, &pid_tgid, &pending, 0) != 0)
        ksight_record_drop();
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int ksight_memory_exit(struct ksight_raw_sys_exit *context)
{
    struct ksight_pending_memory *pending;
    struct ksight_memory_event *event;
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;

    if (!ksight_is_memory_syscall(context->id))
        return 0;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    pending = ksight_bpf_map_lookup_elem(&pending_memory, &pid_tgid);
    if (!pending)
        return 0;

    event = ksight_bpf_ringbuf_reserve(&memory_events, sizeof(*event), 0);
    if (!event) {
        ksight_record_drop();
        ksight_bpf_map_delete_elem(&pending_memory, &pid_tgid);
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    uid_gid = ksight_bpf_get_current_uid_gid();
    event->header.abi_version = KSIGHT_RAW_ABI_VERSION;
    event->header.header_size = sizeof(event->header);
    event->header.sensor_id = KSIGHT_SENSOR_MEMORY;
    event->header.event_type = pending->event_type;
    event->header.total_size = sizeof(*event);
    event->header.flags = KSIGHT_EVENT_F_IDENTITY_PARTIAL;
    event->header.source_sequence = ksight_next_sequence();
    event->header.monotonic_ns = ksight_bpf_ktime_get_ns();
    event->header.cpu = ksight_bpf_get_smp_processor_id();
    event->header.uid = (ksight_u32)uid_gid;
    event->header.gid = (ksight_u32)(uid_gid >> 32);
    event->header.tid = (ksight_u32)pid_tgid;
    event->header.tgid = (ksight_u32)(pid_tgid >> 32);
    event->header.pid = event->header.tgid;
    ksight_bpf_get_current_comm(event->header.comm,
                                sizeof(event->header.comm));

    event->address = pending->address;
    event->length = pending->length;
    event->result = context->result;
    event->offset = pending->offset;
    event->fd = pending->fd;
    event->protection = pending->protection;
    event->map_flags = pending->map_flags;

    ksight_bpf_ringbuf_submit(event, 0);
    ksight_bpf_map_delete_elem(&pending_memory, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
