/* SPDX-License-Identifier: GPL-2.0-only */
#include "ksight_bpf_helpers.h"
#include "ksight_hwbp.h"

/* uprobe 命中时 ctx 即用户态 pt_regs 现场（ARM64 前 34 个字段）。 */
struct ksight_user_regs {
    ksight_u64 regs[31]; /* x0 - x30 */
    ksight_u64 sp;
    ksight_u64 pc;
    ksight_u64 pstate;
};

static void *(*const ksight_bpf_perf_event_output)(const void *ctx,
                                                   const void *map,
                                                   ksight_u64 flags,
                                                   const void *data,
                                                   ksight_u64 size) = (void *)25;

/* per-cpu 临时缓冲。 */
struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, ksight_u32);
    __type(value, struct ksight_hwbp_context);
} hwbp_ctx SEC(".maps");

/* 事件出口：用户态打开此 perf event array 读取寄存器现场。 */
struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 128);
    __type(key, ksight_u32);
    __type(value, ksight_u32);
} hwbp_events SEC(".maps");

SEC("uprobe/ksight_regs")
int ksight_uprobe_regs(struct ksight_user_regs *ctx)
{
    ksight_u32 zero = 0;
    struct ksight_hwbp_context *out = ksight_bpf_map_lookup_elem(&hwbp_ctx, &zero);
    ksight_u64 pid_tgid;
    int i;

    if (!out)
        return 0;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    out->pid = (ksight_u32)(pid_tgid >> 32);
    out->tid = (ksight_u32)pid_tgid;
#pragma unroll
    for (i = 0; i < 31; i++)
        ksight_bpf_probe_read_kernel(&out->regs[i], sizeof(out->regs[i]),
                                     &ctx->regs[i]);
    ksight_bpf_probe_read_kernel(&out->sp, sizeof(out->sp), &ctx->sp);
    ksight_bpf_probe_read_kernel(&out->pc, sizeof(out->pc), &ctx->pc);
    ksight_bpf_probe_read_kernel(&out->pstate, sizeof(out->pstate), &ctx->pstate);

    ksight_bpf_perf_event_output(ctx, &hwbp_events, 0, out, sizeof(*out));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
