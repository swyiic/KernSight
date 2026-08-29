/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSIGHT_FILE_EVENT_H
#define KSIGHT_FILE_EVENT_H

#include "ksight_abi.h"

#define KSIGHT_FILE_PATH_LEN 256

struct ksight_file_event {
    struct ksight_raw_event_header header;
    ksight_s32 dirfd;
    ksight_s32 fd;
    ksight_s32 result;
    ksight_u32 open_flags;
    ksight_u32 mode;
    ksight_u32 path_length;
    char path[KSIGHT_FILE_PATH_LEN];
};

_Static_assert(sizeof(struct ksight_file_event) == 376,
               "ksight file event ABI changed");

struct ksight_fd_event {
    struct ksight_raw_event_header header;
    ksight_s32 fd;
    ksight_s32 requested_fd;
    ksight_s32 result;
    ksight_u32 command;
    ksight_u32 operation_flags;
    ksight_u32 reserved;
};

_Static_assert(sizeof(struct ksight_fd_event) == 120,
               "ksight fd event ABI changed");

#endif /* KSIGHT_FILE_EVENT_H */
