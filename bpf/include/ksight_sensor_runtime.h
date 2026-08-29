/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSIGHT_SENSOR_RUNTIME_H
#define KSIGHT_SENSOR_RUNTIME_H

#include "ksight_bpf_helpers.h"

#define KSIGHT_FILTER_DISABLED 0xffffffffU

/* Each sensor object owns these maps; identical names form a stable loader ABI. */
struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, ksight_u32);
    __type(value, ksight_u64);
} source_sequence SEC(".maps");

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, ksight_u32);
    __type(value, ksight_u64);
} dropped_events SEC(".maps");

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, ksight_u32);
    __type(value, ksight_u32);
} control SEC(".maps");

static __always_inline int
ksight_identity_allowed(ksight_u64 pid_tgid, ksight_u64 uid_gid)
{
    ksight_u32 key = 0;
    ksight_u32 *configured;
    ksight_u32 tgid = (ksight_u32)(pid_tgid >> 32);
    ksight_u32 uid = (ksight_u32)uid_gid;

    configured = ksight_bpf_map_lookup_elem(&control, &key);
    if (configured && tgid == *configured)
        return 0;
    key = 1;
    configured = ksight_bpf_map_lookup_elem(&control, &key);
    if (configured && *configured != KSIGHT_FILTER_DISABLED &&
        tgid != *configured)
        return 0;
    key = 2;
    configured = ksight_bpf_map_lookup_elem(&control, &key);
    if (configured && *configured != KSIGHT_FILTER_DISABLED &&
        uid != *configured)
        return 0;
    return 1;
}

static __always_inline int ksight_take_sample(void)
{
    ksight_u32 key = 4;
    ksight_u32 *configured = ksight_bpf_map_lookup_elem(&control, &key);
    ksight_u32 *counter;
    ksight_u32 ticket;
    ksight_u32 sample_one_in;

    if (!configured || *configured <= 1)
        return 1;
    sample_one_in = *configured;
    key = 5;
    counter = ksight_bpf_map_lookup_elem(&control, &key);
    if (!counter)
        return 0;
    ticket = __sync_fetch_and_add(counter, 1);
    return ticket % sample_one_in == 0;
}

static __always_inline int
ksight_should_capture(ksight_u64 pid_tgid, ksight_u64 uid_gid)
{
    return ksight_identity_allowed(pid_tgid, uid_gid) && ksight_take_sample();
}

static __always_inline ksight_u64 ksight_next_sequence(void)
{
    ksight_u32 key = 0;
    ksight_u64 *sequence = ksight_bpf_map_lookup_elem(&source_sequence, &key);

    if (!sequence)
        return 0;
    return __sync_fetch_and_add(sequence, 1) + 1;
}

static __always_inline void ksight_record_drop(void)
{
    ksight_u32 key = 0;
    ksight_u64 *dropped = ksight_bpf_map_lookup_elem(&dropped_events, &key);

    if (dropped)
        __sync_fetch_and_add(dropped, 1);
}

#endif /* KSIGHT_SENSOR_RUNTIME_H */
