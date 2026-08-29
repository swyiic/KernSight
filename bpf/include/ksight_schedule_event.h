/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSIGHT_SCHEDULE_EVENT_H
#define KSIGHT_SCHEDULE_EVENT_H

#include "ksight_abi.h"

struct ksight_schedule_event {
    struct ksight_raw_event_header header;
    ksight_s32 prev_pid;
    ksight_s32 next_pid;
    ksight_s32 prev_prio;
    ksight_s32 next_prio;
    ksight_u64 prev_state;
    char prev_comm[KSIGHT_TASK_COMM_LEN];
    char next_comm[KSIGHT_TASK_COMM_LEN];
};

_Static_assert(sizeof(struct ksight_schedule_event) == 152,
               "ksight schedule event ABI changed");

#endif /* KSIGHT_SCHEDULE_EVENT_H */
