/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSIGHT_BINDER_EVENT_H
#define KSIGHT_BINDER_EVENT_H

#include "ksight_abi.h"

struct ksight_binder_event {
    struct ksight_raw_event_header header;
    ksight_s32 transaction_id;
    ksight_s32 target_node;
    ksight_s32 target_tgid;
    ksight_s32 target_tid;
    ksight_u32 reply;
    ksight_u32 code;
    ksight_u32 transaction_flags;
    /* 回复方向: 关联的请求事务 debug_id（请求方向恒为 0） */
    ksight_u32 request_transaction_id;
};

_Static_assert(sizeof(struct ksight_binder_event) == 128,
               "ksight binder event ABI changed");

struct ksight_binder_buffer_event {
    struct ksight_raw_event_header header;
    ksight_s32 transaction_id;
    ksight_u32 reserved;
    ksight_u64 data_size;
    ksight_u64 offsets_size;
    ksight_u64 extra_buffers_size;
};

_Static_assert(sizeof(struct ksight_binder_buffer_event) == 128,
               "ksight Binder buffer event ABI changed");

struct ksight_binder_fd_event {
    struct ksight_raw_event_header header;
    ksight_s32 transaction_id;
    ksight_s32 fd;
    ksight_u64 object_offset;
};

_Static_assert(sizeof(struct ksight_binder_fd_event) == 112,
               "ksight Binder FD event ABI changed");

/* Bounded parcel prefix copied at kernel binder_transaction().
 * Works for 32-bit and 64-bit clients: the kernel struct is native-width. */
#define KSIGHT_BINDER_PARCEL_BYTES 128

struct ksight_binder_parcel_event {
    struct ksight_raw_event_header header;
    ksight_s32 transaction_id;
    ksight_u32 code;
    ksight_u32 copied;
    ksight_u32 truncated;
    ksight_u8 data[KSIGHT_BINDER_PARCEL_BYTES];
};

_Static_assert(sizeof(struct ksight_binder_parcel_event) == 240,
               "ksight Binder parcel event ABI changed");

#endif /* KSIGHT_BINDER_EVENT_H */
