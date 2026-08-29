/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSIGHT_PROCESS_EVENT_H
#define KSIGHT_PROCESS_EVENT_H

#include "ksight_abi.h"

#define KSIGHT_PROCESS_FILENAME_LEN 256

struct ksight_process_event {
    struct ksight_raw_event_header header;
    ksight_s32 exit_code;
    ksight_u32 detail_length;
    char detail[KSIGHT_PROCESS_FILENAME_LEN];
};

_Static_assert(sizeof(struct ksight_process_event) == 360,
               "ksight process event ABI changed");

#endif /* KSIGHT_PROCESS_EVENT_H */
