/* SPDX-License-Identifier: GPL-2.0-only */
#include "ksight_bpf_helpers.h"
#include "ksight_sched_event.h"
#include "ksight_sensor_runtime.h"

struct ksight_trace_entry {
    ksight_u16 type;
    ksight_u8 flags;
    ksight_u8 preempt_count;
    ksight_s32 pid;
};

/* Android 6.1 GKI tracefs format: comm, pid, prio, target_cpu. */
struct ksight_sched_wakeup {
    struct ksight_trace_entry common;
    char comm[KSIGHT_TASK_COMM_LEN];
    ksight_s32 pid;
    ksight_s32 prio;
    ksight_s32 target_cpu;
};

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} sched_events SEC(".maps");

static __always_inline int ksight_has_target_scope(void)
{
    ksight_u32 key = 1;
    ksight_u32 *target = ksight_bpf_map_lookup_elem(&control, &key);
    ksight_u32 *uid;

    if (target && *target != KSIGHT_FILTER_DISABLED)
        return 1;
    key = 2;
    uid = ksight_bpf_map_lookup_elem(&control, &key);
    return uid && *uid != KSIGHT_FILTER_DISABLED;
}

static __always_inline int ksight_wakee_is_target(ksight_s32 wakee_tid)
{
    ksight_u32 key = 1;
    ksight_u32 *target = ksight_bpf_map_lookup_elem(&control, &key);

    return target && *target != KSIGHT_FILTER_DISABLED &&
           (ksight_u32)wakee_tid == *target;
}

SEC("tracepoint/sched/sched_wakeup")
int ksight_sched_wakeup_prog(struct ksight_sched_wakeup *context)
{
    struct ksight_sched_event *event;
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;
    int waker_captured;

    /* 调度事件高频：仅在有明确 target 时采集，且要求 waker 在 scope 或 wakee 是 target。 */
    if (!ksight_has_target_scope())
        return 0;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    uid_gid = ksight_bpf_get_current_uid_gid();
    waker_captured = ksight_should_capture(pid_tgid, uid_gid);
    if (!waker_captured && !ksight_wakee_is_target(context->pid))
        return 0;

    event = ksight_bpf_ringbuf_reserve(&sched_events, sizeof(*event), 0);
    if (!event) {
        ksight_record_drop();
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->header.abi_version = KSIGHT_RAW_ABI_VERSION;
    event->header.header_size = sizeof(event->header);
    event->header.sensor_id = KSIGHT_SENSOR_SCHED;
    event->header.event_type = KSIGHT_EVENT_SCHED_WAKEUP;
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

    event->wakee_tid = context->pid;
    event->wakee_prio = context->prio;
    event->target_cpu = context->target_cpu;

    ksight_bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
