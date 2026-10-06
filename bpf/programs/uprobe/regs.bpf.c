#ifndef KSIGHT_INSTANCE_GATE
#define KSIGHT_INSTANCE_GATE 0
#endif
/* SPDX-License-Identifier: GPL-2.0-only */
#include "ksight_bpf_helpers.h"
#include "ksight_hwbp.h"

/* BPF_F_CURRENT_CPU: a perf event belongs to the CPU that opened it.
 * Index 0 only works on CPU 0; other CPUs reject that output (-EOPNOTSUPP).
 * Apply this to both entry and return events, independently of TGID scope. */
#define KSIGHT_BPF_F_CURRENT_CPU 0xffffffffULL

/* uprobe 命中时 ctx 即用户态 pt_regs 现场（ARM64 前 34 个字段）。 */
struct ksight_user_regs {
    ksight_u64 regs[31]; /* x0 - x30 */
    ksight_u64 sp;
    ksight_u64 pc;
    ksight_u64 pstate;
};

#ifdef KSIGHT_SCOPE_HOST_TEST
long ksight_bpf_perf_event_output(const void *, const void *, ksight_u64, const void *, ksight_u64);
#else
static long (*const ksight_bpf_perf_event_output)(const void *ctx,
                                                   const void *map,
                                                   ksight_u64 flags,
                                                   const void *data,
                                                   ksight_u64 size) = (void *)25;
#endif

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
} tgid_filter_v2 SEC(".maps");

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, ksight_u32);
    __type(value, ksight_u32);
} tgid_allow SEC(".maps");

#if KSIGHT_INSTANCE_GATE
#include "ksight_instance_scope.h"
#endif

/* Entry-time buffer pointer + length ceiling per tid. Entry and uretprobe MUST
 * share one BPF object so this map is visible on return (SSL_read snapshot). */
struct entry_info {
    ksight_u64 ptr;
    ksight_u64 num;
    ksight_u64 call_id;
#if KSIGHT_INSTANCE_GATE
    struct ksight_scope_stamp scope;
#endif
};

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, ksight_u32);
    __type(value, struct entry_info);
} entry_ptr SEC(".maps");

static __always_inline int ksight_emit_user_regs(struct ksight_user_regs *ctx,
                                                 ksight_u32 at_return)
{
    ksight_u32 zero = 0;
    struct ksight_hwbp_context *out = ksight_bpf_map_lookup_elem(&hwbp_ctx, &zero);
    ksight_u64 pid_tgid;
    ksight_u32 tgid;
#if KSIGHT_INSTANCE_GATE
    struct ksight_scope_stamp scope = {};
#else
    ksight_u32 *mode;
#endif
    int i;

    if (!out)
        return 0;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    tgid = (ksight_u32)(pid_tgid >> 32);
#if KSIGHT_INSTANCE_GATE
    if (!ksight_scope_context(out, &scope, &entry_ptr, pid_tgid))
        return 0;
#else
    mode = ksight_bpf_map_lookup_elem(&tgid_filter_v2, &zero);
    if (!mode || *mode > 1)
        return 0;
    if (*mode == 1 && !ksight_bpf_map_lookup_elem(&tgid_allow, &tgid))
        return 0;
#endif
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
    out->actual_len = 0;
    out->call_id = at_return ? 0 : out->time_ns;
    out->aux_bytes = 0;
    /* aux_pad / snapshot_at_return: 1 on EVERY uretprobe event so a paired
     * entry+return session can classify hits without separate LiveProbe rows. */
    out->aux_pad = at_return ? 1 : 0;
    if (at_return) {
        /* Return probe: argument registers are gone. The entry program saved
         * x1 (buffer) + x2 (num); x0 is retval. Snapshot NOW while bytes exist.
         * Plain SSL_read: x0 = byte count. SSL_read_ex: x0 = 0/1 success — use
         * saved num as ceiling when x0==1. */
        ksight_u32 tid = (ksight_u32)pid_tgid;
        struct entry_info *saved = ksight_bpf_map_lookup_elem(&entry_ptr, &tid);
#if KSIGHT_INSTANCE_GATE
        if (!saved || !ksight_scope_same(&saved->scope, &scope)) {
            ksight_bpf_map_delete_elem(&entry_ptr, &tid);
            return 0;
        }
#endif
        if (saved) out->call_id = saved->call_id;
        /* regs[0] is a signed return (SSL_read byte count or SSL_read_ex 0/1).
         * Treating it as u64 made WANT_READ (-1) look like a huge success and
         * produced 4096-zero false recv fragments on Alipay BABASSL. */
        ksight_s64 ret = (ksight_s64)out->regs[0];
        if (saved && (saved->ptr & 0x00ffffffffffffffULL) >= 0x10000ULL &&
            ret > 0) {
            ksight_u64 src = saved->ptr & 0x00ffffffffffffffULL;
            ksight_u64 snap = (ksight_u64)ret;
            /* SSL_read_ex success is x0==1; use entry num as snapshot ceiling. */
            if (snap <= 1 && saved->num > 1)
                snap = saved->num;
            if (snap > sizeof(out->aux))
                snap = sizeof(out->aux);
            /* Size must be compile-time constant for bpf_probe_read_user.
             * Only publish aux_bytes when the user read succeeds — failed reads
             * leave stale percpu aux and produced all-zero false SSL_read hits. */
            if (ksight_bpf_probe_read_user(out->aux, sizeof(out->aux),
                                           (const void *)src) == 0) {
                out->aux_bytes = (ksight_u32)snap;
            }
        }
        ksight_bpf_map_delete_elem(&entry_ptr, &tid);
        ksight_bpf_perf_event_output(ctx, &hwbp_events,
                                     KSIGHT_BPF_F_CURRENT_CPU, out, sizeof(*out));
        return 0;
    }
    /* Entry probe: x1 is a user pointer for Parcel UTF-16 / TLS buffers;
     * transact x1 is a handle. Strip ARM TBI/MTE tags so probe_read_user can
     * follow ART heap pointers. */
    ksight_u32 tid = (ksight_u32)pid_tgid;
    ksight_u64 x1 = out->regs[1] & 0x00ffffffffffffffULL;
    if (x1 >= 0x10000ULL) {
        struct entry_info info = {};
        info.ptr = out->regs[1];
        info.num = out->regs[2];
        info.call_id = out->call_id;
#if KSIGHT_INSTANCE_GATE
        info.scope = scope;
#endif
        ksight_bpf_map_update_elem(&entry_ptr, &tid, &info, 0);
    }
    {
        ksight_u64 src1 = out->regs[1] & 0x00ffffffffffffffULL;
        ksight_u64 src2 = out->regs[2] & 0x00ffffffffffffffULL;
        ksight_u64 len1 = out->regs[1] & 0xffffffffULL;
        ksight_u64 len2 = out->regs[2] & 0xffffffffULL;

        if (src1 >= 0x10000ULL) {
            ksight_u64 n = len2;
            if (n == 0 || n > 4096)
                n = 4096;
            if (ksight_bpf_probe_read_user(out->aux, sizeof(out->aux),
                                       (const void *)src1) == 0)
                out->aux_bytes = (ksight_u32)n;
        } else if (src2 >= 0x10000ULL && len1 > 0 && len1 <= 4096) {
            ksight_u64 n = len1;
            if (n > 4096)
                n = 4096;
            if (ksight_bpf_probe_read_user(out->aux, sizeof(out->aux),
                                       (const void *)src2) == 0)
                out->aux_bytes = (ksight_u32)n;
        }
    }

    ksight_bpf_perf_event_output(ctx, &hwbp_events,
                                 KSIGHT_BPF_F_CURRENT_CPU, out, sizeof(*out));
    return 0;
}

SEC("uprobe/ksight_regs")
int ksight_uprobe_regs(struct ksight_user_regs *ctx)
{
    return ksight_emit_user_regs(ctx, 0);
}

/* Return probe: ARM64 x0 is the function result; argument registers are not preserved. */
SEC("uretprobe/ksight_ret")
int ksight_uretprobe_regs(struct ksight_user_regs *ctx)
{
    return ksight_emit_user_regs(ctx, 1);
}

/* Independent registers-only pairing, no payload or TLS entry_ptr access. */
struct regs_entry_info {
    ksight_u64 calls[4];
    ksight_u32 depth, overflow;
#if KSIGHT_INSTANCE_GATE
    struct ksight_scope_stamp scope;
#endif
};
struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, ksight_u32);
    __type(value, struct regs_entry_info);
} regs_entry_ptr SEC(".maps");

/* Registers only. Used for pointer-returning getters such as
 * xqc_get_conn_user_data_by_stream. Does not read x1/x2 and does not touch
 * entry_ptr, so an SSL_read already stashed on this tid keeps its buffer. */
static __always_inline int ksight_emit_regs_only(struct ksight_user_regs *ctx,
                                                 ksight_u32 at_return)
{
    ksight_u32 zero = 0;
    struct ksight_hwbp_context *out = ksight_bpf_map_lookup_elem(&hwbp_ctx, &zero);
    ksight_u64 pid_tgid;
    ksight_u32 tgid;
#if KSIGHT_INSTANCE_GATE
    struct ksight_scope_stamp scope = {};
#else
    ksight_u32 *mode;
#endif
    int i;

    if (!out)
        return 0;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    tgid = (ksight_u32)(pid_tgid >> 32);
#if KSIGHT_INSTANCE_GATE
    if (!ksight_scope_context(out, &scope, &regs_entry_ptr, pid_tgid))
        return 0;
#else
    mode = ksight_bpf_map_lookup_elem(&tgid_filter_v2, &zero);
    /* 2 is the update transaction gate. Missing/unknown mode also denies. */
    if (!mode || *mode > 1)
        return 0;
    if (*mode == 1 && !ksight_bpf_map_lookup_elem(&tgid_allow, &tgid))
        return 0;
#endif
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
    out->aux_pad = at_return ? 1 : 0;
    out->actual_len = 0;
    out->call_id = 0;
    ksight_u32 tid = (ksight_u32)pid_tgid;
    struct regs_entry_info *stack = ksight_bpf_map_lookup_elem(&regs_entry_ptr, &tid);
#if KSIGHT_INSTANCE_GATE
    if (stack && !ksight_scope_same(&stack->scope, &scope)) {
        ksight_bpf_map_delete_elem(&regs_entry_ptr, &tid);
        stack = 0;
    }
    if (at_return && !stack) return 0;
#endif
    if (!at_return) {
        out->call_id = out->time_ns;
        if (!stack) {
            struct regs_entry_info empty = {};
#if KSIGHT_INSTANCE_GATE
            empty.scope = scope;
#endif
            ksight_bpf_map_update_elem(&regs_entry_ptr, &tid, &empty, 0);
            stack = ksight_bpf_map_lookup_elem(&regs_entry_ptr, &tid);
        }
        if (stack) {
            if (stack->depth < 4 && !stack->overflow) {
                if (stack->depth == 0) stack->calls[0] = out->call_id;
                else if (stack->depth == 1) stack->calls[1] = out->call_id;
                else if (stack->depth == 2) stack->calls[2] = out->call_id;
                else stack->calls[3] = out->call_id;
            } else stack->overflow = 1;
            if (stack->depth < 65535) stack->depth++;
            else stack->overflow = 1;
        }
    } else if (stack && stack->depth > 0) {
        stack->depth--;
        if (!(stack->overflow && stack->depth >= 4)) {
            if (stack->depth == 0) out->call_id = stack->calls[0];
            else if (stack->depth == 1) out->call_id = stack->calls[1];
            else if (stack->depth == 2) out->call_id = stack->calls[2];
            else if (stack->depth == 3) out->call_id = stack->calls[3];
        }
        if (stack->depth == 0) ksight_bpf_map_delete_elem(&regs_entry_ptr, &tid);
    }
    ksight_bpf_perf_event_output(ctx, &hwbp_events,
                                 KSIGHT_BPF_F_CURRENT_CPU, out, sizeof(*out));
    return 0;
}

SEC("uprobe/ksight_regs_nocopy")
int ksight_uprobe_regs_nocopy(struct ksight_user_regs *ctx)
{
    return ksight_emit_regs_only(ctx, 0);
}

SEC("uretprobe/ksight_ret_nocopy")
int ksight_uretprobe_regs_nocopy(struct ksight_user_regs *ctx)
{
    return ksight_emit_regs_only(ctx, 1);
}

char LICENSE[] SEC("license") = "GPL";
