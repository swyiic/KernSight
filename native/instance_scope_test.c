/* Execute the actual production entry/return C producers with host helpers.
 * This tests read ordering and counterexamples, not kernel verifier acceptance. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "ksight_types.h"
#define KSIGHT_SCOPE_HOST_TEST 1
#define KSIGHT_BPF_HELPERS_H 1
#define SEC(name)
#ifdef __always_inline
#undef __always_inline
#endif
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name
#define KSIGHT_BPF_MAP_TYPE_HASH 1
#define KSIGHT_BPF_MAP_TYPE_ARRAY 2
#define KSIGHT_BPF_MAP_TYPE_PERF_EVENT_ARRAY 4
#define KSIGHT_BPF_MAP_TYPE_PERCPU_ARRAY 6
#define KSIGHT_BPF_MAP_TYPE_LRU_HASH 9
void *ksight_bpf_map_lookup_elem(const void *, const void *);
long ksight_bpf_map_update_elem(const void *, const void *, const void *, ksight_u64);
long ksight_bpf_map_delete_elem(const void *, const void *);
ksight_u64 ksight_bpf_get_current_pid_tgid(void);
ksight_u64 ksight_bpf_ktime_get_ns(void);
long ksight_bpf_probe_read_kernel(void *, ksight_u32, const void *);
long ksight_bpf_probe_read_user(void *, ksight_u32, const void *);
#include "../bpf/programs/uprobe/instances.bpf.c"

static struct task_struct leader, worker, replacement;
static struct task_struct *current_task, *bound_task;
static int missing_binding, bad_binding;
static struct ksight_scope_allow forged_binding;
static struct ksight_scope_allow row;
static struct ksight_hwbp_context output, emitted;
static struct entry_info saved;
static struct regs_entry_info saved_regs;
static struct ksight_user_regs ctx;
static unsigned mode, epoch, uid, meta_reads, register_reads, payload_reads, outputs;
static unsigned fail_read, mutate_at, gate_reads, cases;
static int have_row, have_entry, have_regs, mutation;
static ksight_u64 pid_tgid, now;
static unsigned char payload[4096] = "fixture-only";

ksight_u32 ksight_scope_gate(void) { gate_reads++; return mode; }
ksight_u32 ksight_scope_epoch(void) { return epoch; }
ksight_u64 ksight_scope_pid_tgid(void) { return pid_tgid; }
ksight_u32 ksight_scope_uid(void) { return uid; }
struct task_struct *ksight_scope_task(void) { return current_task; }
const struct ksight_scope_allow *ksight_scope_lookup(struct ksight_scope_key key) {
    return have_row && key.tgid == 7 && key.epoch == row.epoch ? &row : NULL;
}
const struct ksight_scope_allow *ksight_scope_bound(struct task_struct *task) {
    return !missing_binding && task == bound_task ? (bad_binding ? &forged_binding : &row) : NULL;
}
long ksight_scope_read(void *dst, unsigned size, const void *src) {
    meta_reads++;
    if (meta_reads == fail_read) return -1;
    memcpy(dst, src, size);
    if (meta_reads == mutate_at) {
        if (mutation == 1) mode = 2;
        if (mutation == 2) { mode = 2; epoch++; mode = 3; }
    }
    return 0;
}
ksight_u64 ksight_bpf_get_current_pid_tgid(void) { return pid_tgid; }
ksight_u64 ksight_bpf_ktime_get_ns(void) { return ++now; }
void *ksight_bpf_map_lookup_elem(const void *map, const void *key) {
    (void)key;
    if (map == &hwbp_ctx) return &output;
    if (map == &entry_ptr) return have_entry ? &saved : NULL;
    if (map == &regs_entry_ptr) return have_regs ? &saved_regs : NULL;
    assert(0 && "unexpected production map lookup"); return NULL;
}
long ksight_bpf_map_update_elem(const void *map, const void *key,
                               const void *value, ksight_u64 flags) {
    (void)key; (void)flags;
    if (map == &entry_ptr) { memcpy(&saved, value, sizeof(saved)); have_entry=1; }
    else if (map == &regs_entry_ptr) { memcpy(&saved_regs, value, sizeof(saved_regs)); have_regs=1; }
    else assert(0 && "unexpected map update");
    return 0;
}
long ksight_bpf_map_delete_elem(const void *map, const void *key) {
    (void)key;
    if (map == &entry_ptr) have_entry=0;
    else if (map == &regs_entry_ptr) have_regs=0;
    else assert(0 && "unexpected map delete");
    return 0;
}
long ksight_bpf_probe_read_kernel(void *dst, ksight_u32 size, const void *src) {
    register_reads++; memcpy(dst,src,size); return 0;
}
long ksight_bpf_probe_read_user(void *dst, ksight_u32 size, const void *src) {
    payload_reads++;
    assert(src == payload && size <= sizeof(payload));
    memcpy(dst, src, size); return 0;
}
long ksight_bpf_perf_event_output(const void *context, const void *map,
        ksight_u64 flags, const void *data, ksight_u64 size) {
    (void)context; assert(map == &hwbp_events);
    assert(flags == KSIGHT_BPF_F_CURRENT_CPU && size == sizeof(emitted));
    memcpy(&emitted,data,size); outputs++; return 0;
}
static void counters(void) {
    meta_reads=register_reads=payload_reads=outputs=gate_reads=0;
}
static void reset(void) {
    memset(&output,0,sizeof(output)); memset(&emitted,0,sizeof(emitted));
    memset(&saved,0,sizeof(saved)); memset(&saved_regs,0,sizeof(saved_regs));
    leader=(struct task_struct){.tgid=7,.start_boottime=12345678901ULL,.self_exec_id=2};
    leader.group_leader=&leader;
    worker=(struct task_struct){.tgid=7,.group_leader=&leader,
        .start_boottime=22345678901ULL,.self_exec_id=99};
    current_task=&leader; bound_task=&leader; missing_binding=bad_binding=0;
    row=(struct ksight_scope_allow){.uid=10001,.epoch=1,
        .birth_ns=leader.start_boottime,.exec_id=2};
    mode=3; epoch=1; uid=10001; have_row=1; have_entry=have_regs=0;
    fail_read=mutate_at=mutation=0; pid_tgid=(7ULL<<32)|7; now=100;
    ctx=(struct ksight_user_regs){0};
    ctx.regs[1]=(ksight_u64)(unsigned long)payload; ctx.regs[2]=4;
    counters();
}
static void denied(void) {
    ksight_uprobe_regs(&ctx);
    assert(payload_reads==0 && register_reads==0 && outputs==0 && !have_entry);
    ksight_uprobe_regs_nocopy(&ctx);
    assert(payload_reads==0 && register_reads==0 && outputs==0 && !have_regs);
    ksight_uretprobe_regs(&ctx); ksight_uretprobe_regs_nocopy(&ctx);
    assert(payload_reads==0 && register_reads==0 && outputs==0);
    cases++;
}
static void valid_pair(int thread) {
    reset();
    if (thread) { current_task=&worker; pid_tgid=(7ULL<<32)|8; }
    ksight_uprobe_regs(&ctx);
    assert(payload_reads==1 && register_reads==34 && outputs==1 && have_entry);
    assert(emitted.scope_abi==KSIGHT_SCOPE_ABI_V1 && emitted.scope_tgid==7 &&
        emitted.scope_uid==10001 && emitted.scope_epoch==1 &&
        emitted.scope_birth_ns==row.birth_ns && emitted.scope_exec_id==2 &&
        emitted.scope_thread_birth_ns==current_task->start_boottime);
    assert(gate_reads==2);
    ksight_u64 call=emitted.call_id;
    counters(); ctx.regs[0]=4; ksight_uretprobe_regs(&ctx);
    assert(payload_reads==1 && outputs==1 && !have_entry && emitted.call_id==call);
    assert(emitted.actual_len==0 && emitted.aux_bytes==4);
    cases++;
}
static void stale_return(int change) {
    reset();
    if (change==4) { current_task=&worker; pid_tgid=(7ULL<<32)|8; }
    ksight_uprobe_regs(&ctx); ksight_uprobe_regs_nocopy(&ctx);
    assert(have_entry && have_regs);
    if (change==1) { leader.start_boottime++; row.birth_ns++; }
    if (change==2) { leader.self_exec_id++; row.exec_id++; }
    if (change==3) { epoch++; row.epoch++; }
    if (change==4) {
        // Same process, reused worker TID. Process birth alone cannot pair it.
        replacement=worker; replacement.start_boottime++;
        current_task=&replacement; // helper TID deliberately remains identical
    }
    counters(); ctx.regs[0]=4;
    ksight_uretprobe_regs(&ctx); ksight_uretprobe_regs_nocopy(&ctx);
    assert(payload_reads==0 && outputs==0 && !have_entry && !have_regs);
    // New entry must discard stale state and use the current raw stamp.
    ksight_uprobe_regs(&ctx); assert(have_entry && saved.call_id!=0 && outputs==1);
    assert(saved.scope.thread_birth_ns==current_task->start_boottime);
    cases++;
}
int main(void) {
    valid_pair(0); valid_pair(1);
    // Exact tuple collision does not authorize a different task object.
    reset(); replacement=leader; replacement.group_leader=&replacement;
    current_task=&replacement; denied();
    reset(); missing_binding=1; denied();
    for (int field=0; field<4; field++) {
        reset(); bad_binding=1; forged_binding=row;
        if (field==0) forged_binding.uid++;
        if (field==1) forged_binding.epoch++;
        if (field==2) forged_binding.birth_ns++;
        if (field==3) forged_binding.exec_id++;
        denied();
    }
    // A return after same-tuple replacement must clear the saved call.
    reset(); ksight_uprobe_regs(&ctx); ksight_uprobe_regs_nocopy(&ctx);
    replacement=leader; replacement.group_leader=&replacement; current_task=&replacement;
    counters(); ksight_uretprobe_regs(&ctx); ksight_uretprobe_regs_nocopy(&ctx);
    assert(!have_entry && !have_regs && !payload_reads && !outputs); cases++;
    // Raw +1ns PID reuse remains in the same proc tick, yet must be denied.
    reset(); leader.start_boottime++; denied();
    reset(); current_task=&replacement; replacement=leader;
    replacement.start_boottime++; replacement.group_leader=&replacement; denied();
    reset(); uid++; denied();
    reset(); pid_tgid=(9ULL<<32)|9; denied();
    reset(); leader.tgid=9; denied();
    reset(); current_task=NULL; denied();
    reset(); leader.group_leader=NULL; denied();
    reset(); current_task=&worker; worker.tgid=9; denied();
    reset(); leader.start_boottime=0; denied();
    reset(); row.birth_ns=0; denied();
    reset(); current_task=&worker; worker.start_boottime=0; denied();
    reset(); leader.self_exec_id++; denied();
    reset(); have_row=0; denied();
    reset(); row.epoch++; denied();
    reset(); epoch=0; denied();
    for (unsigned bad=0; bad<=5; bad++) {
        if (bad==3) continue;
        reset(); mode=bad; denied();
    }
    for (unsigned read=1; read<=6; read++) {
        // Reset between each producer so the same metadata helper failure repeats.
        reset(); fail_read=read; ksight_uprobe_regs(&ctx);
        assert(register_reads==0 && payload_reads==0 && outputs==0);
        counters(); ksight_uprobe_regs_nocopy(&ctx);
        assert(register_reads==0 && payload_reads==0 && outputs==0); cases++;
    }
    for (int kind=1; kind<=2; kind++) {
        reset(); mutation=kind; mutate_at=6; ksight_uprobe_regs(&ctx);
        assert(register_reads==0 && payload_reads==0 && outputs==0); cases++;
    }
    // After exit, a stale row never authorizes the new process at the same TGID.
    reset(); ksight_uprobe_regs(&ctx); leader.start_boottime++;
    counters(); ctx.regs[0]=4; ksight_uretprobe_regs(&ctx);
    assert(register_reads==0 && payload_reads==0 && outputs==0); cases++;
    for (int change=1; change<=4; change++) stale_return(change);
    reset(); ksight_uretprobe_regs(&ctx); ksight_uretprobe_regs_nocopy(&ctx);
    assert(outputs==0 && payload_reads==0); cases++;
    printf("production C instance gate: %u cases passed; denied samples read zero payload\n", cases);
    return 0;
}
