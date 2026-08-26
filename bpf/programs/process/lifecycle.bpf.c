/* SPDX-License-Identifier: GPL-2.0-only */
#include "ksight_bpf_helpers.h"
#include "ksight_process_event.h"

struct ksight_trace_entry {
    ksight_u16 type;
    ksight_u8 flags;
    ksight_u8 preempt_count;
    ksight_s32 pid;
};

struct ksight_sched_process_fork {
    struct ksight_trace_entry common;
    char parent_comm[KSIGHT_TASK_COMM_LEN];
    ksight_s32 parent_pid;
    char child_comm[KSIGHT_TASK_COMM_LEN];
    ksight_s32 child_pid;
};

struct ksight_sched_process_exec {
    struct ksight_trace_entry common;
    ksight_u32 filename_location;
    ksight_s32 pid;
    ksight_s32 old_pid;
};

struct ksight_sched_process_exit {
    struct ksight_trace_entry common;
    char comm[KSIGHT_TASK_COMM_LEN];
    ksight_s32 pid;
    ksight_s32 priority;
};

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} process_events SEC(".maps");

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, ksight_u32);
    __type(value, ksight_u64);
} source_sequence SEC(".maps");

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, ksight_u32);
    __type(value, ksight_u64);
} dropped_events SEC(".maps");

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, ksight_u32);
    __type(value, ksight_u64);
} process_start_times SEC(".maps");

static __always_inline ksight_u64 ksight_next_sequence(void)
{
    ksight_u32 key = 0;
    ksight_u64 *sequence = ksight_bpf_map_lookup_elem(&source_sequence, &key);

    if (!sequence)
        return 0;
    return __sync_fetch_and_add(sequence, 1) + 1;
}

static __always_inline void ksight_record_drop(void)
{
    ksight_u32 key = 0;
    ksight_u64 *dropped = ksight_bpf_map_lookup_elem(&dropped_events, &key);

    if (dropped)
        __sync_fetch_and_add(dropped, 1);
}

static __always_inline struct ksight_process_event *
ksight_reserve_process_event(ksight_u16 event_type)
{
    struct ksight_process_event *event;
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;

    event = ksight_bpf_ringbuf_reserve(&process_events, sizeof(*event), 0);
    if (!event) {
        ksight_record_drop();
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    pid_tgid = ksight_bpf_get_current_pid_tgid();
    uid_gid = ksight_bpf_get_current_uid_gid();

    event->header.abi_version = KSIGHT_RAW_ABI_VERSION;
    event->header.header_size = sizeof(event->header);
    event->header.sensor_id = KSIGHT_SENSOR_PROCESS;
    event->header.event_type = event_type;
    event->header.total_size = sizeof(*event);
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
    return event;
}

SEC("tracepoint/sched/sched_process_fork")
int ksight_process_fork(struct ksight_sched_process_fork *context)
{
    struct ksight_process_event *event;
    ksight_u64 started_at;
    ksight_u32 child_pid;
    int index;

    if (context->child_pid <= 0)
        return 0;

    child_pid = (ksight_u32)context->child_pid;
    event = ksight_reserve_process_event(KSIGHT_EVENT_PROCESS_FORK);
    if (!event)
        return 0;

    started_at = event->header.monotonic_ns;
    event->header.process_start_time = started_at;
    event->header.pid = child_pid;
    event->header.tid = child_pid;
    event->header.tgid = child_pid;
    event->header.ppid = (ksight_u32)context->parent_pid;
    /* sched_process_fork does not expose child TGID, so thread identity is provisional. */
    event->header.flags |= KSIGHT_EVENT_F_IDENTITY_PARTIAL;

#pragma unroll
    for (index = 0; index < KSIGHT_TASK_COMM_LEN; index++)
        event->header.comm[index] = context->child_comm[index];

    ksight_bpf_map_update_elem(&process_start_times, &child_pid, &started_at, 0);
    ksight_bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int ksight_process_exec(struct ksight_sched_process_exec *context)
{
    struct ksight_process_event *event;
    const char *filename;
    ksight_u64 *started_at;
    ksight_u32 process_id;
    ksight_u32 filename_offset;
    long copied;

    event = ksight_reserve_process_event(KSIGHT_EVENT_PROCESS_EXEC);
    if (!event)
        return 0;

    process_id = event->header.tgid;
    started_at = ksight_bpf_map_lookup_elem(&process_start_times, &process_id);
    if (started_at) {
        event->header.process_start_time = *started_at;
    } else {
        event->header.flags |= KSIGHT_EVENT_F_IDENTITY_PARTIAL;
    }

    filename_offset = context->filename_location & 0xffff;
    filename = (const char *)context + filename_offset;
    copied = ksight_bpf_probe_read_kernel_str(event->filename,
                                              sizeof(event->filename),
                                              filename);
    if (copied > 0) {
        event->filename_length = (ksight_u32)copied - 1;
        if (copied == sizeof(event->filename))
            event->header.flags |= KSIGHT_EVENT_F_TRUNCATED;
    } else {
        event->header.flags |= KSIGHT_EVENT_F_IDENTITY_PARTIAL;
    }

    ksight_bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int ksight_process_exit(struct ksight_sched_process_exit *context)
{
    struct ksight_process_event *event;
    ksight_u64 *started_at;
    ksight_u32 process_id;

    event = ksight_reserve_process_event(KSIGHT_EVENT_PROCESS_EXIT);
    if (!event)
        return 0;

    process_id = event->header.tgid;
    started_at = ksight_bpf_map_lookup_elem(&process_start_times, &process_id);
    if (started_at) {
        event->header.process_start_time = *started_at;
    } else {
        event->header.flags |= KSIGHT_EVENT_F_IDENTITY_PARTIAL;
    }

    if (event->header.tid == process_id)
        ksight_bpf_map_delete_elem(&process_start_times, &process_id);

    event->header.flags |= KSIGHT_EVENT_F_IDENTITY_PARTIAL;
    ksight_bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
