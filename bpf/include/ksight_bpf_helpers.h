/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSIGHT_BPF_HELPERS_H
#define KSIGHT_BPF_HELPERS_H

#include "ksight_types.h"

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name

#define KSIGHT_BPF_MAP_TYPE_HASH 1
#define KSIGHT_BPF_MAP_TYPE_ARRAY 2
#define KSIGHT_BPF_MAP_TYPE_RINGBUF 27

static void *(*const ksight_bpf_map_lookup_elem)(const void *map,
                                                 const void *key) = (void *)1;
static long (*const ksight_bpf_map_update_elem)(const void *map,
                                                const void *key,
                                                const void *value,
                                                ksight_u64 flags) = (void *)2;
static long (*const ksight_bpf_map_delete_elem)(const void *map,
                                                const void *key) = (void *)3;
static ksight_u64 (*const ksight_bpf_ktime_get_ns)(void) = (void *)5;
static ksight_u32 (*const ksight_bpf_get_smp_processor_id)(void) = (void *)8;
static ksight_u64 (*const ksight_bpf_get_current_pid_tgid)(void) = (void *)14;
static ksight_u64 (*const ksight_bpf_get_current_uid_gid)(void) = (void *)15;
static long (*const ksight_bpf_get_current_comm)(void *buffer,
                                                 ksight_u32 size) = (void *)16;
static long (*const ksight_bpf_probe_read_kernel_str)(void *destination,
                                                      ksight_u32 size,
                                                      const void *source) = (void *)115;
static void *(*const ksight_bpf_ringbuf_reserve)(void *ringbuf,
                                                 ksight_u64 size,
                                                 ksight_u64 flags) = (void *)131;
static void (*const ksight_bpf_ringbuf_submit)(void *data,
                                               ksight_u64 flags) = (void *)132;

#endif /* KSIGHT_BPF_HELPERS_H */
