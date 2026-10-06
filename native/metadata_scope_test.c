/* Actual metadata producer, native execution only. No BPF calls or devices. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define KSIGHT_METADATA_HOST_TEST
#include "../bpf/programs/identity/metadata.bpf.c"
static struct task_struct task, other;
static struct cred credential, changed_credential;
static struct metadata_token token;
static struct seq_file *seq = (struct seq_file *)0x100;
static int reads, lookups, inexec_calls, emits, fail_read, fail_inexec, mutation, change_at;
static struct metadata_record emitted;
static struct bpf_iter__task *mutate_context;
const struct metadata_token *meta_lookup(struct task_struct *p) {
    lookups++;
    if (mutate_context) { mutate_context->task=0; mutate_context->meta=0; mutate_context=0; }
    if(p!=&task) return 0;
    if(lookups==2) {
        if(mutation==1)return 0;
        if(mutation==2)token.nonce++;
        if(mutation==3)token.round++;
    }
    return &token;
}
long meta_read(void *dst,unsigned size,const void *src) {
    reads++;
    if(reads==change_at) {
        if(mutation==4)task.cred=&changed_credential;
        if(mutation==5)task.tgid++;
        if(mutation==6)task.start_boottime++;
        if(mutation==7)task.self_exec_id++;
        if(mutation==8)task.exit_state=1;
        if(mutation==9)task.flags|=4;
    }
    if(reads==fail_read)return -1;
    memcpy(dst,src,size);return 0;
}
int meta_inexec(struct task_struct *p,ksight_u64 *value) {
    inexec_calls++;
    if(inexec_calls==fail_inexec)return 0;
    if(mutation==10 && inexec_calls==2)p->in_execve=1;
    *value=p->in_execve;return 1;
}
long meta_emit(struct seq_file *s,const struct metadata_record *r) {
    assert(s==seq);emits++;emitted=*r;return 0;
}
static void reset(void) {
    memset(&task,0,sizeof(task));memset(&credential,0,sizeof(credential));
    credential.uid.val=10001;changed_credential=credential;changed_credential.uid.val++;
    task.tgid=7;task.group_leader=&task;task.start_boottime=12345678901ULL;
    task.self_exec_id=2;task.cred=&credential;other=task;other.group_leader=&other;
    token=(struct metadata_token){19,1};reads=lookups=inexec_calls=emits=0;
    fail_read=fail_inexec=mutation=change_at=0;mutate_context=0;memset(&emitted,0,sizeof(emitted));
}
static int cases;
static void run(struct task_struct *p,int expected) {
    struct bpf_iter_meta meta={seq};struct bpf_iter__task ctx={&meta,p};
    assert(ksight_task_metadata(&ctx)==0);
    if(emits!=expected) fprintf(stderr,"case=%d mutation=%d reads=%d expected=%d emits=%d\n",cases,mutation,reads,expected,emits);
    assert(emits==expected);cases++;
}
int main(void) {
    reset();run(&task,1);
    assert(emitted.abi==KSIGHT_METADATA_ABI && emitted.bytes==48);
    assert(emitted.nonce==19 && emitted.round==1 && emitted.tgid==7 && emitted.uid==10001);
    assert(emitted.birth_ns==12345678901ULL && emitted.exec_id==2);
    int total_reads=reads;assert(total_reads>10);
    reset();run(&other,0);assert(reads==0 && inexec_calls==0);
    reset();task.group_leader=&other;run(&task,0);
    for(int i=1;i<=total_reads;i++){reset();fail_read=i;run(&task,0);}
    for(int i=1;i<=2;i++){reset();fail_inexec=i;run(&task,0);}
    for(int i=1;i<=3;i++){reset();mutation=i;run(&task,0);}
    // Mutation after the first UID read, before the second credential check.
    for(int i=4;i<=9;i++){reset();mutation=i;change_at=9;run(&task,0);}
    reset();mutation=10;run(&task,0); /* exec starts after initial observation */
    reset();task.in_execve=1;run(&task,0); /* mm swapped, exec id not advanced */
    reset();task.flags=4;run(&task,0);
    reset();task.exit_state=1;run(&task,0);
    reset();task.cred=0;run(&task,0);
    reset();task.start_boottime=0;run(&task,0);
    reset();task.tgid=0;run(&task,0);
    reset();task.self_exec_id=~0ULL;run(&task,0);
    reset();token.nonce=0;run(&task,0);assert(reads==0);
    reset();token.round=0;run(&task,0);assert(reads==0);
    reset();run(0,0);assert(reads==0);
    reset();struct bpf_iter__task ctx={0,&task};ksight_task_metadata(&ctx);assert(emits==0);cases++;
    reset();struct bpf_iter_meta meta={0};ctx=(struct bpf_iter__task){&meta,&task};ksight_task_metadata(&ctx);assert(emits==0);cases++;
    reset();struct bpf_iter_meta kept_meta={seq};ctx=(struct bpf_iter__task){&kept_meta,&task};
    mutate_context=&ctx;ksight_task_metadata(&ctx);assert(emits==1 && ctx.task==0 && ctx.meta==0);cases++;
    reset();ksight_task_metadata(0);assert(emits==0);cases++;
    printf("metadata production C: %d cases; ungranted same-tuple task reads zero fields; exec/exit refuse\n",cases);
    return 0;
}
