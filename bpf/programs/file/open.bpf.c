/* SPDX-License-Identifier: GPL-2.0-only */
#include "ksight_bpf_helpers.h"
#include "ksight_file_event.h"
#include "ksight_sensor_runtime.h"
#include "ksight_syscall_compat.h"

struct ksight_trace_entry {
    ksight_u16 type;
    ksight_u8 flags;
    ksight_u8 preempt_count;
    ksight_s32 pid;
};

struct ksight_raw_sys_enter {
    struct ksight_trace_entry common;
    ksight_s64 id;
    ksight_u64 arguments[6];
};

struct ksight_raw_sys_exit {
    struct ksight_trace_entry common;
    ksight_s64 id;
    ksight_s64 result;
};

struct ksight_open_how {
    ksight_u64 flags;
    ksight_u64 mode;
    ksight_u64 resolve;
};

struct ksight_pending_open {
    ksight_s32 dirfd;
    ksight_u32 open_flags;
    ksight_u32 mode;
    ksight_u32 path_length;
    char path[KSIGHT_FILE_PATH_LEN];
};

#define KSIGHT_F_DUPFD 0U
#define KSIGHT_F_DUPFD_CLOEXEC 1030U
#define KSIGHT_SOL_SOCKET 1
#define KSIGHT_SCM_RIGHTS 1

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} file_events SEC(".maps");

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, ksight_u64);
    __type(value, struct ksight_pending_open);
} pending_open SEC(".maps");

struct ksight_pending_fd {
    ksight_s32 fd;
    ksight_s32 requested_fd;
    ksight_u32 command;
    ksight_u32 operation_flags;
    ksight_u16 event_type;
    ksight_u16 reserved;
    ksight_u32 last_fd;
};

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, ksight_u64);
    __type(value, struct ksight_pending_fd);
} pending_fd SEC(".maps");

struct ksight_user_msghdr {
    ksight_u64 msg_name;
    ksight_u32 msg_namelen;
    ksight_u32 pad0;
    ksight_u64 msg_iov;
    ksight_u64 msg_iovlen;
    ksight_u64 msg_control;
    ksight_u64 msg_controllen;
    ksight_u32 msg_flags;
    ksight_u32 pad1;
};

struct ksight_cmsghdr {
    ksight_u64 cmsg_len;
    ksight_s32 cmsg_level;
    ksight_s32 cmsg_type;
};

struct ksight_pending_rights {
    ksight_s32 socket_fd;
    ksight_s32 first_fd;
    ksight_u32 fd_count;
    ksight_u16 event_type;
    ksight_u16 reserved;
    ksight_u64 control;
    ksight_u64 control_len;
};

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, ksight_u64);
    __type(value, struct ksight_pending_rights);
} pending_rights SEC(".maps");

static __always_inline int
ksight_parse_rights(ksight_u64 control, ksight_u64 control_len,
                    struct ksight_pending_rights *pending)
{
    struct ksight_cmsghdr cmsg = {};
    ksight_s32 first_fd = -1;

    if (control == 0 || control_len < sizeof(cmsg))
        return 0;
    if (ksight_bpf_probe_read_user(&cmsg, sizeof(cmsg), (const void *)control) != 0)
        return 0;
    if (cmsg.cmsg_level != KSIGHT_SOL_SOCKET || cmsg.cmsg_type != KSIGHT_SCM_RIGHTS)
        return 0;
    if (cmsg.cmsg_len < sizeof(cmsg) + sizeof(ksight_s32))
        return 0;
    if (ksight_bpf_probe_read_user(&first_fd, sizeof(first_fd),
                                   (const void *)(control + sizeof(cmsg))) != 0)
        return 0;
    pending->first_fd = first_fd;
    pending->fd_count = (ksight_u32)((cmsg.cmsg_len - sizeof(cmsg)) / sizeof(ksight_s32));
    if (pending->fd_count > 64)
        pending->fd_count = 64;
    return 1;
}

static __always_inline int
ksight_prepare_rights(struct ksight_raw_sys_enter *context, ksight_u64 pid_tgid)
{
    struct ksight_user_msghdr msg = {};
    struct ksight_pending_rights pending = {};

    if (ksight_bpf_probe_read_user(&msg, sizeof(msg),
                                   (const void *)context->arguments[1]) != 0)
        return 0;
    pending.socket_fd = (ksight_s32)context->arguments[0];
    pending.control = msg.msg_control;
    pending.control_len = msg.msg_controllen;
    pending.event_type = ksight_syscall_is_sendmsg(context->id) ?
                         KSIGHT_EVENT_FILE_DESCRIPTOR_RIGHTS_SEND :
                         KSIGHT_EVENT_FILE_DESCRIPTOR_RIGHTS_RECEIVE;
    if (ksight_syscall_is_sendmsg(context->id) &&
        !ksight_parse_rights(msg.msg_control, msg.msg_controllen, &pending))
        return 0;
    if (ksight_bpf_map_update_elem(&pending_rights, &pid_tgid, &pending, 0) != 0)
        ksight_record_drop();
    return 0;
}

static __always_inline int
ksight_emit_rights(struct ksight_raw_sys_exit *context, ksight_u64 pid_tgid)
{
    struct ksight_pending_rights *pending;
    struct ksight_fd_event *event;
    ksight_u64 uid_gid;

    pending = ksight_bpf_map_lookup_elem(&pending_rights, &pid_tgid);
    if (!pending)
        return 0;
    if (pending->event_type == KSIGHT_EVENT_FILE_DESCRIPTOR_RIGHTS_RECEIVE &&
        context->result >= 0)
        ksight_parse_rights(pending->control, pending->control_len, pending);
    if (pending->fd_count == 0) {
        ksight_bpf_map_delete_elem(&pending_rights, &pid_tgid);
        return 0;
    }
    event = ksight_bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) {
        ksight_record_drop();
        ksight_bpf_map_delete_elem(&pending_rights, &pid_tgid);
        return 0;
    }
    __builtin_memset(event, 0, sizeof(*event));
    uid_gid = ksight_bpf_get_current_uid_gid();
    event->header.abi_version = KSIGHT_RAW_ABI_VERSION;
    event->header.header_size = sizeof(event->header);
    event->header.sensor_id = KSIGHT_SENSOR_FILE;
    event->header.event_type = pending->event_type;
    event->header.total_size = sizeof(*event);
    event->header.flags = KSIGHT_EVENT_F_IDENTITY_PARTIAL;
    event->header.source_sequence = ksight_next_sequence();
    event->header.monotonic_ns = ksight_bpf_ktime_get_ns();
    event->header.cpu = ksight_bpf_get_smp_processor_id();
    event->header.uid = (ksight_u32)uid_gid;
    event->header.gid = (ksight_u32)(uid_gid >> 32);
    event->header.tid = (ksight_u32)pid_tgid;
    event->header.tgid = (ksight_u32)(pid_tgid >> 32);
    event->header.pid = event->header.tgid;
    ksight_bpf_get_current_comm(event->header.comm, sizeof(event->header.comm));
    event->fd = pending->socket_fd;
    event->requested_fd = pending->first_fd;
    event->result = (ksight_s32)context->result;
    event->command = (ksight_u32)context->id;
    event->operation_flags = pending->fd_count;
    event->reserved = pending->fd_count;
    ksight_bpf_ringbuf_submit(event, 0);
    ksight_bpf_map_delete_elem(&pending_rights, &pid_tgid);
    return 0;
}

static __always_inline int ksight_file_fd_enabled(void)
{
    ksight_u32 key = 7;
    ksight_u32 *configured = ksight_bpf_map_lookup_elem(&control, &key);

    return configured && *configured != 0;
}

static __always_inline int ksight_is_open_syscall(ksight_s64 syscall_id)
{
    return ksight_syscall_is_open(syscall_id);
}

static __always_inline int ksight_is_fd_syscall(ksight_s64 syscall_id)
{
    return ksight_syscall_is_close(syscall_id) ||
           ksight_syscall_is_close_range(syscall_id) ||
           ksight_syscall_is_dup(syscall_id) ||
           ksight_syscall_is_dup3(syscall_id) ||
           ksight_syscall_is_fcntl(syscall_id);
}

static __always_inline int ksight_is_rights_syscall(ksight_s64 syscall_id)
{
    return ksight_syscall_is_sendmsg(syscall_id) ||
           ksight_syscall_is_recvmsg(syscall_id);
}

static __always_inline int
ksight_prepare_fd(struct ksight_raw_sys_enter *context, ksight_u64 pid_tgid)
{
    struct ksight_pending_fd pending = {};
    ksight_u32 fcntl_command;

    if (!ksight_is_fd_syscall(context->id))
        return 0;
    pending.fd = (ksight_s32)context->arguments[0];
    pending.requested_fd = -1;
    pending.last_fd = 0;
    pending.command = (ksight_u32)context->id;
    if (ksight_syscall_is_close(context->id)) {
        pending.event_type = KSIGHT_EVENT_FILE_DESCRIPTOR_CLOSE;
    } else if (ksight_syscall_is_close_range(context->id)) {
        pending.event_type = KSIGHT_EVENT_FILE_DESCRIPTOR_CLOSE_RANGE;
        pending.last_fd = (ksight_u32)context->arguments[1];
        pending.operation_flags = (ksight_u32)context->arguments[2];
        if (pending.last_fd <= 0x7fffffffU)
            pending.requested_fd = (ksight_s32)pending.last_fd;
    } else if (ksight_syscall_is_dup(context->id)) {
        pending.event_type = KSIGHT_EVENT_FILE_DESCRIPTOR_DUPLICATE;
    } else if (ksight_syscall_is_dup3(context->id)) {
        pending.event_type = KSIGHT_EVENT_FILE_DESCRIPTOR_DUPLICATE;
        pending.requested_fd = (ksight_s32)context->arguments[1];
        pending.operation_flags = (ksight_u32)context->arguments[2];
    } else {
        fcntl_command = (ksight_u32)context->arguments[1];
        if (fcntl_command != KSIGHT_F_DUPFD &&
            fcntl_command != KSIGHT_F_DUPFD_CLOEXEC)
            return 0;
        pending.event_type = KSIGHT_EVENT_FILE_DESCRIPTOR_DUPLICATE;
        pending.requested_fd = (ksight_s32)context->arguments[2];
        pending.operation_flags = fcntl_command;
    }
    if (ksight_bpf_map_update_elem(&pending_fd, &pid_tgid, &pending, 0) != 0)
        ksight_record_drop();
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int ksight_file_open_enter(struct ksight_raw_sys_enter *context)
{
    struct ksight_pending_open pending = {};
    struct ksight_open_how how = {};
    const char *path;
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;
    long copied;

    if (!ksight_is_open_syscall(context->id) &&
        !ksight_is_fd_syscall(context->id) &&
        !ksight_is_rights_syscall(context->id))
        return 0;
    if ((ksight_is_fd_syscall(context->id) || ksight_is_rights_syscall(context->id))
        && !ksight_file_fd_enabled())
        return 0;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    uid_gid = ksight_bpf_get_current_uid_gid();
    if (!ksight_should_capture(pid_tgid, uid_gid))
        return 0;
    if (ksight_is_rights_syscall(context->id))
        return ksight_prepare_rights(context, pid_tgid);
    if (!ksight_is_open_syscall(context->id))
        return ksight_prepare_fd(context, pid_tgid);
    pending.dirfd = (ksight_s32)context->arguments[0];
    path = (const char *)context->arguments[1];
    if (context->id == KSIGHT_A64_OPENAT || context->id == KSIGHT_A32_OPENAT) {
        pending.open_flags = (ksight_u32)context->arguments[2];
        pending.mode = (ksight_u32)context->arguments[3];
    } else if (ksight_bpf_probe_read_user(&how, sizeof(how),
                                          (const void *)context->arguments[2]) == 0) {
        pending.open_flags = (ksight_u32)how.flags;
        pending.mode = (ksight_u32)how.mode;
    }

    copied = ksight_bpf_probe_read_user_str(pending.path,
                                            sizeof(pending.path), path);
    if (copied > 0)
        pending.path_length = (ksight_u32)copied - 1;

    if (ksight_bpf_map_update_elem(&pending_open, &pid_tgid, &pending, 0) != 0)
        ksight_record_drop();
    return 0;
}

static __always_inline int
ksight_emit_fd(struct ksight_raw_sys_exit *context, ksight_u64 pid_tgid)
{
    struct ksight_pending_fd *pending;
    struct ksight_fd_event *event;
    ksight_u64 uid_gid;

    pending = ksight_bpf_map_lookup_elem(&pending_fd, &pid_tgid);
    if (!pending)
        return 0;
    event = ksight_bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) {
        ksight_record_drop();
        ksight_bpf_map_delete_elem(&pending_fd, &pid_tgid);
        return 0;
    }
    __builtin_memset(event, 0, sizeof(*event));
    uid_gid = ksight_bpf_get_current_uid_gid();
    event->header.abi_version = KSIGHT_RAW_ABI_VERSION;
    event->header.header_size = sizeof(event->header);
    event->header.sensor_id = KSIGHT_SENSOR_FILE;
    event->header.event_type = pending->event_type;
    event->header.total_size = sizeof(*event);
    event->header.flags = KSIGHT_EVENT_F_IDENTITY_PARTIAL;
    event->header.source_sequence = ksight_next_sequence();
    event->header.monotonic_ns = ksight_bpf_ktime_get_ns();
    event->header.cpu = ksight_bpf_get_smp_processor_id();
    event->header.uid = (ksight_u32)uid_gid;
    event->header.gid = (ksight_u32)(uid_gid >> 32);
    event->header.tid = (ksight_u32)pid_tgid;
    event->header.tgid = (ksight_u32)(pid_tgid >> 32);
    event->header.pid = event->header.tgid;
    ksight_bpf_get_current_comm(event->header.comm,
                                sizeof(event->header.comm));
    event->fd = pending->fd;
    event->requested_fd = pending->requested_fd;
    event->result = (ksight_s32)context->result;
    event->command = pending->command;
    event->operation_flags = pending->operation_flags;
    event->reserved = pending->last_fd;
    ksight_bpf_ringbuf_submit(event, 0);
    ksight_bpf_map_delete_elem(&pending_fd, &pid_tgid);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int ksight_file_open_exit(struct ksight_raw_sys_exit *context)
{
    struct ksight_pending_open *pending;
    struct ksight_file_event *event;
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;

    if (!ksight_is_open_syscall(context->id) &&
        !ksight_is_fd_syscall(context->id) &&
        !ksight_is_rights_syscall(context->id))
        return 0;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    if (ksight_is_rights_syscall(context->id))
        return ksight_emit_rights(context, pid_tgid);
    if (!ksight_is_open_syscall(context->id))
        return ksight_emit_fd(context, pid_tgid);
    pending = ksight_bpf_map_lookup_elem(&pending_open, &pid_tgid);
    if (!pending)
        return 0;

    event = ksight_bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) {
        ksight_record_drop();
        ksight_bpf_map_delete_elem(&pending_open, &pid_tgid);
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    uid_gid = ksight_bpf_get_current_uid_gid();
    event->header.abi_version = KSIGHT_RAW_ABI_VERSION;
    event->header.header_size = sizeof(event->header);
    event->header.sensor_id = KSIGHT_SENSOR_FILE;
    event->header.event_type = KSIGHT_EVENT_FILE_OPEN;
    event->header.total_size = sizeof(*event);
    event->header.flags = KSIGHT_EVENT_F_IDENTITY_PARTIAL;
    event->header.source_sequence = ksight_next_sequence();
    event->header.monotonic_ns = ksight_bpf_ktime_get_ns();
    event->header.cpu = ksight_bpf_get_smp_processor_id();
    event->header.uid = (ksight_u32)uid_gid;
    event->header.gid = (ksight_u32)(uid_gid >> 32);
    event->header.tid = (ksight_u32)pid_tgid;
    event->header.tgid = (ksight_u32)(pid_tgid >> 32);
    event->header.pid = event->header.tgid;
    ksight_bpf_get_current_comm(event->header.comm,
                                sizeof(event->header.comm));

    event->dirfd = pending->dirfd;
    event->fd = context->result >= 0 ? (ksight_s32)context->result : -1;
    event->result = (ksight_s32)context->result;
    event->open_flags = pending->open_flags;
    event->mode = pending->mode;
    event->path_length = pending->path_length;
    __builtin_memcpy(event->path, pending->path, sizeof(event->path));
    if (pending->path_length == sizeof(pending->path) - 1)
        event->header.flags |= KSIGHT_EVENT_F_TRUNCATED;

    ksight_bpf_ringbuf_submit(event, 0);
    ksight_bpf_map_delete_elem(&pending_open, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
