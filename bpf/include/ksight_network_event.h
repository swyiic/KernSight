/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSIGHT_NETWORK_EVENT_H
#define KSIGHT_NETWORK_EVENT_H

#include "ksight_abi.h"

#define KSIGHT_SOCKET_ADDRESS_LEN 128

struct ksight_network_event {
    struct ksight_raw_event_header header;
    ksight_s32 fd;
    ksight_s32 result;
    ksight_u32 address_length;
    ksight_u16 address_family;
    ksight_u16 submitted_address_length;
    ksight_u8 address[KSIGHT_SOCKET_ADDRESS_LEN];
};

struct ksight_network_io_event {
    struct ksight_raw_event_header header;
    ksight_s32 fd;
    ksight_u32 syscall_id;
    ksight_s64 result;
    ksight_u64 requested_length;
    ksight_u8 reserved[8];
};

_Static_assert(sizeof(struct ksight_network_event) == 240,
               "ksight network event ABI changed");
_Static_assert(sizeof(struct ksight_network_io_event) == 128,
               "ksight network I/O event ABI changed");

#endif /* KSIGHT_NETWORK_EVENT_H */
