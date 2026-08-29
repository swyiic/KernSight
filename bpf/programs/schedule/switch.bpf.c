/* SPDX-License-Identifier: GPL-2.0-only */
#include "ksight_bpf_helpers.h"
#include "ksight_schedule_event.h"
#include "ksight_sensor_runtime.h"

/* Compile-checked prototype. It is intentionally not loaded until aggregation replaces streaming. */

struct ksight_trace_entry {
    ksight_u16 type;
    ksight_u8 flags;
    ksight_u8 preempt_count;
    ksight_s32 pid;
};

struct ksight_sched_switch_trace {
    struct ksight_trace_entry common;
    char prev_comm[16];
    ksight_s32 prev_pid;
    ksight_s32 prev_prio;
    ksight_s64 prev_state;
    char next_comm[16];
    ksight_s32 next_pid;
    ksight_s32 next_prio;
};

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} schedule_events SEC(".maps");

static __always_inline void
ksight_fill_schedule_header(struct ksight_raw_event_header *header,
                            ksight_u32 total_size,
                            ksight_u64 pid_tgid,
                            ksight_u64 uid_gid)
{
    header->abi_version = KSIGHT_RAW_ABI_VERSION;
    header->header_size = sizeof(*header);
    header->sensor_id = KSIGHT_SENSOR_SCHED;
    header->event_type = KSIGHT_EVENT_SCHED_SWITCH;
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

SEC("tracepoint/sched/sched_switch")
int ksight_sched_switch(struct ksight_sched_switch_trace *context)
{
    struct ksight_schedule_event *event;
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;
    ksight_u32 key = 1;
    ksight_u32 *target_tgid;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    uid_gid = ksight_bpf_get_current_uid_gid();
    target_tgid = ksight_bpf_map_lookup_elem(&control, &key);
    if (!target_tgid || *target_tgid == KSIGHT_FILTER_DISABLED)
        return 0;

    /* Prototype is PID-scoped; whole-device sched_switch streaming is forbidden. */
    if ((ksight_u32)context->next_pid != *target_tgid &&
        (ksight_u32)context->prev_pid != *target_tgid)
        return 0;

    event = ksight_bpf_ringbuf_reserve(&schedule_events, sizeof(*event), 0);
    if (!event) {
        ksight_record_drop();
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    ksight_fill_schedule_header(&event->header, sizeof(*event), pid_tgid, uid_gid);
    event->prev_pid = context->prev_pid;
    event->next_pid = context->next_pid;
    event->prev_prio = context->prev_prio;
    event->next_prio = context->next_prio;
    event->prev_state = (ksight_u64)context->prev_state;
    __builtin_memcpy(event->prev_comm, context->prev_comm, sizeof(event->prev_comm));
    __builtin_memcpy(event->next_comm, context->next_comm, sizeof(event->next_comm));
    ksight_bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
