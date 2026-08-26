/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSIGHT_ABI_H
#define KSIGHT_ABI_H

#include "ksight_types.h"

#define KSIGHT_RAW_ABI_VERSION 1
#define KSIGHT_TASK_COMM_LEN 16

enum ksight_sensor_id {
    KSIGHT_SENSOR_PROCESS = 1,
    KSIGHT_SENSOR_FILE = 2,
    KSIGHT_SENSOR_MEMORY = 3,
    KSIGHT_SENSOR_NETWORK = 4,
    KSIGHT_SENSOR_BINDER = 5,
    KSIGHT_SENSOR_INTEGRITY = 6,
    KSIGHT_SENSOR_SYSCALL = 7,
};

enum ksight_raw_event_type {
    KSIGHT_EVENT_PROCESS_FORK = 0x0101,
    KSIGHT_EVENT_PROCESS_EXEC = 0x0102,
    KSIGHT_EVENT_PROCESS_EXIT = 0x0103,
};

enum ksight_raw_event_flags {
    KSIGHT_EVENT_F_TRUNCATED = 1U << 0,
    KSIGHT_EVENT_F_SAMPLED = 1U << 1,
    KSIGHT_EVENT_F_IDENTITY_PARTIAL = 1U << 2,
};

/*
 * Fixed prefix for every ring/perf-buffer record. Variable payload bytes follow
 * total_size and are decoded according to (abi_version, event_type).
 *
 * The agent supplies boot_id and session_id during normalization. BPF supplies
 * only kernel-local identity and monotonic time.
 */
struct ksight_raw_event_header {
    ksight_u16 abi_version;
    ksight_u16 header_size;
    ksight_u16 sensor_id;
    ksight_u16 event_type;
    ksight_u32 total_size;
    ksight_u32 flags;
    ksight_u64 source_sequence;
    ksight_u64 monotonic_ns;
    ksight_u64 process_start_time;
    ksight_u32 cpu;
    ksight_u32 uid;
    ksight_u32 gid;
    ksight_u32 pid;
    ksight_u32 tid;
    ksight_u32 tgid;
    ksight_u32 ppid;
    char comm[KSIGHT_TASK_COMM_LEN];
    ksight_u32 reserved[3];
};

_Static_assert(sizeof(struct ksight_raw_event_header) == 96,
               "ksight raw event header ABI changed");

#endif /* KSIGHT_ABI_H */
