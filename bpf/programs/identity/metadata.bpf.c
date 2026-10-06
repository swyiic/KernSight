/* SPDX-License-Identifier: GPL-2.0-only
 * Metadata-only task iterator. Never reads registers, user memory, mm, buffers,
 * argv, files or keys. Only the exact task bearing this map's pidfd grant may
 * emit a fixed 48-byte raw identity. pid_fd iteration is not the object proof. */
#include "ksight_types.h"
#ifndef KSIGHT_METADATA_HOST_TEST
#include "ksight_bpf_helpers.h"
#define META_INLINE static __always_inline
#define META_CORE __attribute__((preserve_access_index))
#define META_FIELD(x) __builtin_preserve_access_index(x)
#define META_SIZE(x) __builtin_preserve_field_info(x, 1)
#else
#define META_INLINE static inline
#define META_CORE
#define META_FIELD(x) (x)
#define META_SIZE(x) sizeof(x)
#endif
struct meta_uid { ksight_u32 val; } META_CORE;
struct cred { struct meta_uid uid; } META_CORE;
struct task_struct {
    int tgid;
    struct task_struct *group_leader;
    ksight_u64 start_boottime, self_exec_id;
    const struct cred *cred;
    ksight_u32 flags;
    int exit_state;
    unsigned in_execve:1;
} META_CORE;
struct seq_file;
struct bpf_iter_meta { struct seq_file *seq; } META_CORE;
struct bpf_iter__task { struct bpf_iter_meta *meta; struct task_struct *task; } META_CORE;
struct metadata_token { ksight_u64 nonce, round; };
#define KSIGHT_METADATA_ABI 0x4b534d31U
struct metadata_record {
    ksight_u32 abi, bytes;
    ksight_u64 nonce, round;
    ksight_u32 tgid, uid;
    ksight_u64 birth_ns, exec_id;
};
_Static_assert(sizeof(struct metadata_token)==16, "metadata token ABI");
_Static_assert(sizeof(struct metadata_record)==48, "metadata record ABI");
#ifdef KSIGHT_METADATA_HOST_TEST
const struct metadata_token *meta_lookup(struct task_struct *task);
long meta_read(void *dst, unsigned size, const void *src);
int meta_inexec(struct task_struct *task, ksight_u64 *value);
long meta_emit(struct seq_file *seq, const struct metadata_record *record);
#else
struct {
    __uint(type, 29); /* BPF_MAP_TYPE_TASK_STORAGE, pidfd key */
    __uint(map_flags, 1); /* NO_PREALLOC; no inherited/cloned authorization */
    __uint(max_entries, 0);
    __type(key, int);
    __type(value, struct metadata_token);
} metadata_task_v1 SEC(".maps");
static void *(*const task_storage_get)(void *, struct task_struct *, void *, ksight_u64) = (void *)156;
static long (*const seq_write)(struct seq_file *, const void *, ksight_u32) = (void *)127;
META_INLINE const struct metadata_token *meta_lookup(struct task_struct *task) {
    return task_storage_get(&metadata_task_v1, task, 0, 0); /* lookup only */
}
META_INLINE long meta_read(void *dst, unsigned size, const void *src) {
    return ksight_bpf_probe_read_kernel(dst,size,src);
}
/* Named CO-RE bitfield extraction, matching libbpf's probed algorithm; never
 * encode the target byte offset, mask or shift from a guessed task layout. */
META_INLINE int meta_inexec(struct task_struct *task, ksight_u64 *value) {
    ksight_u32 size=__builtin_preserve_field_info(task->in_execve,1);
    ksight_u32 left=__builtin_preserve_field_info(task->in_execve,4);
    ksight_u32 right=__builtin_preserve_field_info(task->in_execve,5);
    ksight_u64 bits=0;
    if (!__builtin_preserve_field_info(task->in_execve,2) || !size || size>8 || left>63 || right>63)
        return 0;
    const void *src=(const unsigned char *)task+__builtin_preserve_field_info(task->in_execve,0);
    if (meta_read(&bits,size,src)) return 0;
    *value=(bits<<left)>>right;
    return 1;
}
META_INLINE long meta_emit(struct seq_file *seq, const struct metadata_record *record) {
    return seq_write(seq,record,sizeof(*record));
}
#endif
META_INLINE int metadata_snapshot(struct task_struct *task, struct metadata_record *out) {
    struct task_struct *leader=0;
    const struct cred *cred=0,*after_cred=0;
    ksight_u32 flags=0;
    int exit_state=0,after_tgid=0;
    ksight_u64 inexec=0,after_birth=0,after_exec=0;
    const struct metadata_token *row=meta_lookup(task);
    if (!row) return 0; /* No task fields read on an ungranted object. */
    struct metadata_token token=*row;
    if (!token.nonce || !token.round) return 0;
    if (META_SIZE(task->tgid)!=4 || META_SIZE(task->group_leader)!=8 ||
        META_SIZE(task->start_boottime)!=8 || META_SIZE(task->self_exec_id)!=8 ||
        META_SIZE(task->cred)!=8 || META_SIZE(task->flags)!=4 ||
        META_SIZE(task->exit_state)!=4) return 0;
    if (!meta_inexec(task,&inexec) || inexec ||
        meta_read(&exit_state,4,META_FIELD(&task->exit_state)) || exit_state ||
        meta_read(&flags,4,META_FIELD(&task->flags)) || (flags&4U) || /* PF_EXITING */
        meta_read(&leader,8,META_FIELD(&task->group_leader)) || leader!=task ||
        meta_read(&out->tgid,4,META_FIELD(&task->tgid)) || !out->tgid ||
        meta_read(&out->birth_ns,8,META_FIELD(&task->start_boottime)) || !out->birth_ns ||
        meta_read(&out->exec_id,8,META_FIELD(&task->self_exec_id)) || out->exec_id==~0ULL ||
        meta_read(&cred,8,META_FIELD(&task->cred)) || !cred ||
        META_SIZE(cred->uid.val)!=4 || meta_read(&out->uid,4,META_FIELD(&cred->uid.val))) return 0;
    /* Credential objects are immutable; compare pointer as well as raw exec.
     * in_execve excludes mm/cred transition before self_exec_id increments. */
    if (meta_read(&after_cred,8,META_FIELD(&task->cred)) || cred!=after_cred ||
        meta_read(&after_tgid,4,META_FIELD(&task->tgid)) || (ksight_u32)after_tgid!=out->tgid ||
        meta_read(&after_birth,8,META_FIELD(&task->start_boottime)) || after_birth!=out->birth_ns ||
        meta_read(&after_exec,8,META_FIELD(&task->self_exec_id)) || after_exec!=out->exec_id ||
        !meta_inexec(task,&inexec) || inexec ||
        meta_read(&exit_state,4,META_FIELD(&task->exit_state)) || exit_state ||
        meta_read(&flags,4,META_FIELD(&task->flags)) || (flags&4U)) return 0;
    row=meta_lookup(task);
    if (!row || row->nonce!=token.nonce || row->round!=token.round) return 0;
    out->abi=KSIGHT_METADATA_ABI;out->bytes=sizeof(*out);
    out->nonce=token.nonce;out->round=token.round;
    return 1;
}
#ifndef KSIGHT_METADATA_HOST_TEST
SEC("iter/task")
#endif
int ksight_task_metadata(struct bpf_iter__task *ctx) {
    if (!ctx) return 0;
    /* Keep the very pointers checked below. Reloading a nullable context field
     * loses the verifier's non-null proof before TASK_STORAGE/seq_write. */
    struct task_struct *task=ctx->task;
    if (!task) return 0;
    struct bpf_iter_meta *meta=ctx->meta;
    if (!meta) return 0;
    struct seq_file *seq=meta->seq;
    if (!seq) return 0;
    struct metadata_record record={};
    if (metadata_snapshot(task,&record)) meta_emit(seq,&record);
    return 0;
}
#ifndef KSIGHT_METADATA_HOST_TEST
char LICENSE[] SEC("license")="GPL";
#endif
