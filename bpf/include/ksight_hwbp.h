/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSIGHT_HWBP_H
#define KSIGHT_HWBP_H

#include "ksight_types.h"

/* 硬件断点命中时捕获的用户态寄存器现场。
 * 由 kprobe/perf_output_sample 旁路填充，经 perf event 传给用户态。
 * aux 是 x1 指向的用户缓冲在命中瞬间的有界副本（writeString16 / token），
 * 不是 Parcel C++ 对象字段。 */
struct ksight_hwbp_context {
    ksight_u32 pid;
    ksight_u32 tid;
    ksight_u64 regs[31]; /* x0 - x30 */
    ksight_u64 sp;
    ksight_u64 pc;
    ksight_u64 pstate;
    ksight_u64 time_ns;
    ksight_u32 aux_bytes;
    ksight_u32 aux_pad;
    ksight_u8 aux[384];
};

_Static_assert(sizeof(struct ksight_hwbp_context) == 680,
               "ksight hwbp context ABI changed");

#endif /* KSIGHT_HWBP_H */
