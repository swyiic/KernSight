/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSIGHT_SCHED_EVENT_H
#define KSIGHT_SCHED_EVENT_H

#include "ksight_abi.h"

/* 调度唤醒关系：header 记录唤醒者（waker，当前进程），负载记录被唤醒者（wakee）。 */
struct ksight_sched_event {
    struct ksight_raw_event_header header;
    ksight_s32 wakee_tid;
    ksight_s32 wakee_prio;
    ksight_s32 target_cpu;
    ksight_u32 reserved;
};

_Static_assert(sizeof(struct ksight_sched_event) == 112,
               "ksight sched event ABI changed");

#endif /* KSIGHT_SCHED_EVENT_H */
