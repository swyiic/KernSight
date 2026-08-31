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

/* 1 = only emit when tgid is in tgid_allow. Kernel uprobe pid is a thread, so
 * scoped Inspect still attaches globally and filters TGID here. */
struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, ksight_u32);
    __type(value, ksight_u32);
} tgid_filter SEC(".maps");

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, ksight_u32);
    __type(value, ksight_u32);
} tgid_allow SEC(".maps");

static __always_inline int ksight_emit_user_regs(struct ksight_user_regs *ctx)
{
    ksight_u32 zero = 0;
    struct ksight_hwbp_context *out = ksight_bpf_map_lookup_elem(&hwbp_ctx, &zero);
    ksight_u64 pid_tgid;
    ksight_u32 tgid;
    ksight_u32 *mode;
    int i;

    if (!out)
        return 0;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    tgid = (ksight_u32)(pid_tgid >> 32);
    mode = ksight_bpf_map_lookup_elem(&tgid_filter, &zero);
    if (mode && *mode != 0) {
        if (!ksight_bpf_map_lookup_elem(&tgid_allow, &tgid))
            return 0;
    }
    out->pid = tgid;
    out->tid = (ksight_u32)pid_tgid;
#pragma unroll
    for (i = 0; i < 31; i++)
        ksight_bpf_probe_read_kernel(&out->regs[i], sizeof(out->regs[i]),
                                     &ctx->regs[i]);
    ksight_bpf_probe_read_kernel(&out->sp, sizeof(out->sp), &ctx->sp);
    ksight_bpf_probe_read_kernel(&out->pc, sizeof(out->pc), &ctx->pc);
    ksight_bpf_probe_read_kernel(&out->pstate, sizeof(out->pstate), &ctx->pstate);
    out->time_ns = ksight_bpf_ktime_get_ns();
    out->aux_bytes = 0;
    out->aux_pad = 0;
    /* x1 is a user pointer for Parcel UTF-16 / TLS buffers; transact x1 is a handle.
     * Strip ARM TBI/MTE tags so probe_read_user can follow ART heap pointers. */
    {
        ksight_u64 src1 = out->regs[1] & 0x00ffffffffffffffULL;
        ksight_u64 src2 = out->regs[2] & 0x00ffffffffffffffULL;
        ksight_u64 len1 = out->regs[1] & 0xffffffffULL;
        ksight_u64 len2 = out->regs[2] & 0xffffffffULL;

        if (src1 >= 0x10000ULL) {
            ksight_u64 n = len2;
            if (n == 0 || n > 192)
                n = 192;
            ksight_bpf_probe_read_user(out->aux, sizeof(out->aux),
                                       (const void *)src1);
            out->aux_bytes = (ksight_u32)n;
        } else if (src2 >= 0x10000ULL && len1 > 0 && len1 <= 4096) {
            ksight_u64 n = len1;
            if (n > 192)
                n = 192;
            ksight_bpf_probe_read_user(out->aux, sizeof(out->aux),
                                       (const void *)src2);
            out->aux_bytes = (ksight_u32)n;
        }
    }

    ksight_bpf_perf_event_output(ctx, &hwbp_events, 0, out, sizeof(*out));
    return 0;
}

SEC("uprobe/ksight_regs")
int ksight_uprobe_regs(struct ksight_user_regs *ctx)
{
    return ksight_emit_user_regs(ctx);
}

/* Return probe: ARM64 x0 is the function result; argument registers are not preserved. */
SEC("uretprobe/ksight_ret")
int ksight_uretprobe_regs(struct ksight_user_regs *ctx)
{
    return ksight_emit_user_regs(ctx);
}

char LICENSE[] SEC("license") = "GPL";
