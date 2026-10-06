/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSIGHT_INSTANCE_SCOPE_H
#define KSIGHT_INSTANCE_SCOPE_H
#include "ksight_types.h"

/* Minimal CO-RE declarations: these are field names/types, never target offsets.
 * Linux v6.1/v6.1.124 sched.h, fork.c and exec.c establish their semantics.
 * Actual target BTF and relocation are mandatory before loading this backend. */
struct task_struct {
    int tgid;
    struct task_struct *group_leader;
    ksight_u64 start_boottime;
    ksight_u64 self_exec_id;
}
#ifndef KSIGHT_SCOPE_HOST_TEST
__attribute__((preserve_access_index))
#endif
;

struct ksight_scope_key { ksight_u32 tgid, epoch; };
struct ksight_scope_allow {
    ksight_u32 uid, epoch;
    ksight_u64 birth_ns, exec_id;
};
#define KSIGHT_SCOPE_ABI_V1 0x4b534931U
struct ksight_scope_stamp {
    ksight_u32 tgid, uid, epoch, abi;
    ksight_u64 birth_ns, exec_id, thread_birth_ns;
};
_Static_assert(sizeof(struct ksight_scope_key) == 8, "scope key ABI");
_Static_assert(sizeof(struct ksight_scope_allow) == 24, "scope value ABI");
_Static_assert(sizeof(struct ksight_scope_stamp) == 40, "scope stamp ABI");

#ifdef KSIGHT_SCOPE_HOST_TEST
#define KSIGHT_SCOPE_INLINE static inline
#define KSIGHT_SCOPE_FIELD(address) (address)
#define KSIGHT_SCOPE_SIZE(field) sizeof(field)
ksight_u32 ksight_scope_gate(void);
ksight_u32 ksight_scope_epoch(void);
ksight_u64 ksight_scope_pid_tgid(void);
ksight_u32 ksight_scope_uid(void);
struct task_struct *ksight_scope_task(void);
const struct ksight_scope_allow *ksight_scope_lookup(struct ksight_scope_key key);
const struct ksight_scope_allow *ksight_scope_bound(struct task_struct *leader);
long ksight_scope_read(void *dst, unsigned size, const void *src);
#else
#include "ksight_bpf_helpers.h"
#define KSIGHT_SCOPE_INLINE static __always_inline
#define KSIGHT_SCOPE_FIELD(address) __builtin_preserve_access_index(address)
/* BPF_FIELD_BYTE_SIZE = 1; clang emits target CO-RE size relocations. */
#define KSIGHT_SCOPE_SIZE(field) __builtin_preserve_field_info(field, 1)
struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, ksight_u32);
    __type(value, ksight_u32);
} scope_epoch_v1 SEC(".maps");
struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct ksight_scope_key);
    __type(value, struct ksight_scope_allow);
} scope_allow_v1 SEC(".maps");
/* Linux UAPI type 29, pidfd key; NO_PREALLOC, never CLONE. Authorization
 * belongs to the exact task object and is not inherited by a new process. */
struct {
    __uint(type, 29);
    __uint(map_flags, 1);
    __uint(max_entries, 0);
    __type(key, int);
    __type(value, struct ksight_scope_allow);
} scope_task_v1 SEC(".maps");
static void *(*const ksight_task_storage_get)(void *, struct task_struct *, void *, ksight_u64) = (void *)156;
KSIGHT_SCOPE_INLINE const struct ksight_scope_allow *ksight_scope_bound(struct task_struct *leader) {
    /* Lookup only: the probe can NEVER grant authorization to an unseen task. */
    return ksight_task_storage_get(&scope_task_v1, leader, 0, 0);
}
/* Helper ID from Linux UAPI __BPF_FUNC_MAPPER, GPL tracing helper. */
static struct task_struct *(*const ksight_get_current_task_btf)(void) = (void *)158;
KSIGHT_SCOPE_INLINE ksight_u32 ksight_scope_gate(void) {
    ksight_u32 zero = 0;
    volatile ksight_u32 *value = ksight_bpf_map_lookup_elem(&tgid_filter_v2, &zero);
    return value ? *value : 0;
}
KSIGHT_SCOPE_INLINE ksight_u32 ksight_scope_epoch(void) {
    ksight_u32 zero = 0;
    volatile ksight_u32 *value = ksight_bpf_map_lookup_elem(&scope_epoch_v1, &zero);
    return value ? *value : 0;
}
KSIGHT_SCOPE_INLINE ksight_u64 ksight_scope_pid_tgid(void) { return ksight_bpf_get_current_pid_tgid(); }
KSIGHT_SCOPE_INLINE ksight_u32 ksight_scope_uid(void) { return (ksight_u32)ksight_bpf_get_current_uid_gid(); }
KSIGHT_SCOPE_INLINE struct task_struct *ksight_scope_task(void) { return ksight_get_current_task_btf(); }
KSIGHT_SCOPE_INLINE const struct ksight_scope_allow *ksight_scope_lookup(struct ksight_scope_key key) {
    return ksight_bpf_map_lookup_elem(&scope_allow_v1, &key);
}
KSIGHT_SCOPE_INLINE long ksight_scope_read(void *dst, unsigned size, const void *src) {
    return ksight_bpf_probe_read_kernel(dst, size, src);
}
#endif

KSIGHT_SCOPE_INLINE int ksight_scope_same(const struct ksight_scope_stamp *a,
                                         const struct ksight_scope_stamp *b) {
    return a->abi == KSIGHT_SCOPE_ABI_V1 && b->abi == KSIGHT_SCOPE_ABI_V1 &&
        a->tgid == b->tgid && a->uid == b->uid && a->epoch == b->epoch &&
        a->birth_ns == b->birth_ns && a->exec_id == b->exec_id &&
        a->thread_birth_ns == b->thread_birth_ns;
}

/* Called before register/aux/payload reads in both entry and return producers.
 * Only immutable (epoch,TGID) rows may be used; epochs never wrap or roll back.
 * This decision does not synchronously cancel an invocation already admitted. */
KSIGHT_SCOPE_INLINE int ksight_scope_admit(struct ksight_scope_stamp *stamp) {
    struct ksight_scope_key key = {};
    struct ksight_scope_allow allowed = {};
    struct task_struct *task, *leader = 0;
    ksight_u64 birth = 0, exec_id = 0, thread_birth = 0;
    int task_tgid = 0, leader_tgid = 0;
    ksight_u32 uid;
    if (ksight_scope_gate() != 3)
        return 0;
    key.epoch = ksight_scope_epoch();
    key.tgid = (ksight_u32)(ksight_scope_pid_tgid() >> 32);
    if (!key.epoch || !key.tgid)
        return 0;
    const struct ksight_scope_allow *row = ksight_scope_lookup(key);
    if (!row)
        return 0;
    allowed = *row;
    uid = ksight_scope_uid();
    if (allowed.epoch != key.epoch || allowed.uid != uid || !allowed.birth_ns)
        return 0;
    task = ksight_scope_task();
    if (!task)
        return 0;
    if (KSIGHT_SCOPE_SIZE(task->tgid) != 4 ||
        KSIGHT_SCOPE_SIZE(task->group_leader) != 8 ||
        KSIGHT_SCOPE_SIZE(task->start_boottime) != 8 ||
        KSIGHT_SCOPE_SIZE(task->self_exec_id) != 8)
        return 0;
    /* Direct CO-RE access preserves PTR_TO_BTF_ID for task_storage_get.
     * A pointer obtained by probe_read_kernel alone is not a typed task. */
    struct task_struct *typed_leader = KSIGHT_SCOPE_FIELD(task->group_leader);
    if (!typed_leader)
        return 0;
    const struct ksight_scope_allow *bound = ksight_scope_bound(typed_leader);
    if (!bound || bound->uid != allowed.uid || bound->epoch != allowed.epoch ||
        bound->birth_ns != allowed.birth_ns || bound->exec_id != allowed.exec_id)
        return 0;
    if (ksight_scope_read(&task_tgid, sizeof(task_tgid), KSIGHT_SCOPE_FIELD(&task->tgid)) ||
        task_tgid <= 0 || (ksight_u32)task_tgid != key.tgid ||
        ksight_scope_read(&leader, sizeof(leader), KSIGHT_SCOPE_FIELD(&task->group_leader)) ||
        !leader || leader != typed_leader ||
        ksight_scope_read(&leader_tgid, sizeof(leader_tgid), KSIGHT_SCOPE_FIELD(&leader->tgid)) ||
        leader_tgid != task_tgid ||
        ksight_scope_read(&birth, sizeof(birth), KSIGHT_SCOPE_FIELD(&leader->start_boottime)) ||
        !birth || birth != allowed.birth_ns ||
        ksight_scope_read(&exec_id, sizeof(exec_id), KSIGHT_SCOPE_FIELD(&leader->self_exec_id)) ||
        exec_id != allowed.exec_id ||
        ksight_scope_read(&thread_birth, sizeof(thread_birth), KSIGHT_SCOPE_FIELD(&task->start_boottime)) ||
        !thread_birth)
        return 0;
    if (ksight_scope_gate() != 3 || ksight_scope_epoch() != key.epoch)
        return 0;
    stamp->tgid = key.tgid;
    stamp->uid = uid;
    stamp->epoch = key.epoch;
    stamp->abi = KSIGHT_SCOPE_ABI_V1;
    stamp->birth_ns = birth;
    stamp->exec_id = exec_id;
    stamp->thread_birth_ns = thread_birth;
    return 1;
}
/* Shared producer admission/stamp; map key is explicitly the 32-bit TID.
 * Denied events clear a saved call without reading its user buffer. */
KSIGHT_SCOPE_INLINE int ksight_scope_context(struct ksight_hwbp_context *out,
        struct ksight_scope_stamp *stamp, const void *pending_map, ksight_u64 pid_tgid) {
    if (!ksight_scope_admit(stamp)) {
        ksight_u32 tid = (ksight_u32)pid_tgid;
        ksight_bpf_map_delete_elem(pending_map, &tid);
        return 0;
    }
    out->scope_tgid = stamp->tgid;
    out->scope_uid = stamp->uid;
    out->scope_epoch = stamp->epoch;
    out->scope_abi = stamp->abi;
    out->scope_birth_ns = stamp->birth_ns;
    out->scope_exec_id = stamp->exec_id;
    out->scope_thread_birth_ns = stamp->thread_birth_ns;
    return 1;
}
#endif
