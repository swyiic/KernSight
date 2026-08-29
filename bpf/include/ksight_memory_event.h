/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSIGHT_MEMORY_EVENT_H
#define KSIGHT_MEMORY_EVENT_H

#include "ksight_abi.h"

struct ksight_memory_event {
    struct ksight_raw_event_header header;
    ksight_u64 address;
    ksight_u64 length;
    ksight_s64 result;
    ksight_u64 offset;
    ksight_s32 fd;
    ksight_u32 protection;
    ksight_u32 map_flags;
    ksight_u32 reserved;
};

_Static_assert(sizeof(struct ksight_memory_event) == 144,
               "ksight memory event ABI changed");

#endif /* KSIGHT_MEMORY_EVENT_H */
