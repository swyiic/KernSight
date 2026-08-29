/* SPDX-License-Identifier: GPL-2.0-only */
#include "ksight_bpf_helpers.h"
#include "ksight_network_event.h"
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

struct ksight_pending_connect {
    ksight_s32 fd;
    ksight_u32 address_length;
    ksight_u16 address_family;
    ksight_u16 submitted_address_length;
    ksight_u8 address[KSIGHT_SOCKET_ADDRESS_LEN];
};

struct ksight_pending_accept {
    ksight_s32 listening_fd;
    ksight_u32 address_length;
    ksight_u64 address_pointer;
    ksight_u64 length_pointer;
    ksight_u16 address_family;
    ksight_u16 returned_address_length;
    ksight_u8 address[KSIGHT_SOCKET_ADDRESS_LEN];
};

struct ksight_pending_io {
    ksight_s32 fd;
    ksight_u32 syscall_id;
    ksight_u64 requested_length;
    ksight_u16 event_type;
    ksight_u16 reserved;
};

#include "ksight_network_fd_tracker.h"

#define KSIGHT_ARM64_ACCEPT 202
#define KSIGHT_ARM64_CONNECT 203
#define KSIGHT_ARM64_SENDTO 206
#define KSIGHT_ARM64_RECVFROM 207
#define KSIGHT_ARM64_SENDMSG 211
#define KSIGHT_ARM64_RECVMSG 212
#define KSIGHT_ARM64_READ 63
#define KSIGHT_ARM64_WRITE 64
#define KSIGHT_ARM64_RECVMMSG 243
#define KSIGHT_ARM64_SENDMMSG 269
#define KSIGHT_ARM64_ACCEPT4 242
#define KSIGHT_AF_UNIX 1
#define KSIGHT_AF_INET 2
#define KSIGHT_AF_INET6 10
#define KSIGHT_SOCKADDR_INET_LEN 16
#define KSIGHT_SOCKADDR_INET6_LEN 28
#define KSIGHT_SOCKADDR_UNIX_LEN 110
#define KSIGHT_SOCKADDR_GENERIC_LEN 16
#define KSIGHT_SOCKADDR_FAMILY_LEN 2
#define KSIGHT_ARM64_USER_POINTER_MASK 0x00ffffffffffffffULL
struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} network_events SEC(".maps");

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, ksight_u64);
    __type(value, struct ksight_pending_connect);
} pending_connect SEC(".maps");

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, ksight_u64);
    __type(value, struct ksight_pending_accept);
} pending_accept SEC(".maps");

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, ksight_u64);
    __type(value, struct ksight_pending_io);
} pending_io SEC(".maps");

static __always_inline int ksight_network_io_enabled(void)
{
    ksight_u32 key = 6;
    ksight_u32 *enabled = ksight_bpf_map_lookup_elem(&control, &key);

    return enabled && *enabled != 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int ksight_network_connect_enter(struct ksight_raw_sys_enter *context)
{
    struct ksight_pending_connect pending = {};
    const void *address;
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;

    if (!ksight_syscall_is_connect(context->id))
        return 0;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    uid_gid = ksight_bpf_get_current_uid_gid();
    if (!ksight_should_capture(pid_tgid, uid_gid))
        return 0;

    pending.fd = (ksight_s32)context->arguments[0];
    pending.submitted_address_length =
        context->arguments[2] > 0xffffU ? 0xffffU :
        (ksight_u16)context->arguments[2];
    address = (const void *)(context->arguments[1] &
                             KSIGHT_ARM64_USER_POINTER_MASK);
    if (context->arguments[2] < KSIGHT_SOCKADDR_FAMILY_LEN ||
        ksight_bpf_probe_read_user(&pending.address_family,
                                   sizeof(pending.address_family),
                                   address) != 0) {
        pending.address_length = 0;
    } else {
        pending.address_length = KSIGHT_SOCKADDR_FAMILY_LEN;
        pending.address[0] = (ksight_u8)pending.address_family;
        pending.address[1] = (ksight_u8)(pending.address_family >> 8);
        if (pending.address_family == KSIGHT_AF_INET &&
            context->arguments[2] >= KSIGHT_SOCKADDR_INET_LEN &&
            ksight_bpf_probe_read_user(pending.address,
                                       KSIGHT_SOCKADDR_INET_LEN,
                                       address) == 0) {
            pending.address_length = KSIGHT_SOCKADDR_INET_LEN;
        } else if (pending.address_family == KSIGHT_AF_INET6 &&
                   context->arguments[2] >= KSIGHT_SOCKADDR_INET6_LEN &&
                   ksight_bpf_probe_read_user(pending.address,
                                              KSIGHT_SOCKADDR_INET6_LEN,
                                              address) == 0) {
            pending.address_length = KSIGHT_SOCKADDR_INET6_LEN;
        } else if (pending.address_family == KSIGHT_AF_UNIX &&
                   context->arguments[2] > KSIGHT_SOCKADDR_FAMILY_LEN) {
            /* Abstract Unix names start with NUL; do not use probe_read_str. */
            if (ksight_bpf_probe_read_user(pending.address,
                                           KSIGHT_SOCKADDR_UNIX_LEN,
                                           address) == 0) {
                pending.address_length = context->arguments[2] >
                                         KSIGHT_SOCKADDR_UNIX_LEN
                    ? KSIGHT_SOCKADDR_UNIX_LEN
                    : (ksight_u32)context->arguments[2];
            }
        } else if (context->arguments[2] >= 12 &&
                   ksight_bpf_probe_read_user(pending.address,
                                              KSIGHT_SOCKADDR_GENERIC_LEN,
                                              address) == 0) {
            pending.address_length = context->arguments[2] >
                                     KSIGHT_SOCKADDR_GENERIC_LEN
                ? KSIGHT_SOCKADDR_GENERIC_LEN
                : (ksight_u32)context->arguments[2];
        }
    }

    if (ksight_bpf_map_update_elem(&pending_connect, &pid_tgid, &pending, 0) != 0)
        ksight_record_drop();
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int ksight_network_connect_exit(struct ksight_raw_sys_exit *context)
{
    struct ksight_pending_connect *pending;
    struct ksight_network_event *event;
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;

    if (!ksight_syscall_is_connect(context->id))
        return 0;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    pending = ksight_bpf_map_lookup_elem(&pending_connect, &pid_tgid);
    if (!pending)
        return 0;

    event = ksight_bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event) {
        ksight_record_drop();
        ksight_bpf_map_delete_elem(&pending_connect, &pid_tgid);
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    uid_gid = ksight_bpf_get_current_uid_gid();
    event->header.abi_version = KSIGHT_RAW_ABI_VERSION;
    event->header.header_size = sizeof(event->header);
    event->header.sensor_id = KSIGHT_SENSOR_NETWORK;
    event->header.event_type = KSIGHT_EVENT_NETWORK_CONNECT;
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
    event->result = (ksight_s32)context->result;
    event->address_length = pending->address_length;
    event->address_family = pending->address_family;
    event->submitted_address_length = pending->submitted_address_length;
    __builtin_memcpy(event->address, pending->address, sizeof(event->address));

    ksight_bpf_ringbuf_submit(event, 0);
    ksight_bpf_map_delete_elem(&pending_connect, &pid_tgid);
    if (context->result >= 0 || context->result == -115) {
        ksight_u64 key = ksight_socket_key((ksight_u32)(pid_tgid >> 32),
                                           pending->fd);
        ksight_u8 tracked = 1;

        if (ksight_bpf_map_update_elem(&socket_fds, &key, &tracked, 0) != 0)
            ksight_record_drop();
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int ksight_network_accept_enter(struct ksight_raw_sys_enter *context)
{
    struct ksight_pending_accept pending = {};
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;

    if (!ksight_syscall_is_accept(context->id))
        return 0;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    uid_gid = ksight_bpf_get_current_uid_gid();
    if (!ksight_should_capture(pid_tgid, uid_gid))
        return 0;

    pending.listening_fd = (ksight_s32)context->arguments[0];
    pending.address_pointer = context->arguments[1] &
                              KSIGHT_ARM64_USER_POINTER_MASK;
    pending.length_pointer = context->arguments[2] &
                             KSIGHT_ARM64_USER_POINTER_MASK;
    if (ksight_bpf_map_update_elem(&pending_accept, &pid_tgid,
                                   &pending, 0) != 0)
        ksight_record_drop();
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int ksight_network_accept_exit(struct ksight_raw_sys_exit *context)
{
    struct ksight_pending_accept *pending;
    struct ksight_network_event *event;
    const void *address;
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;
    ksight_u32 returned_length = 0;

    if (!ksight_syscall_is_accept(context->id))
        return 0;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    pending = ksight_bpf_map_lookup_elem(&pending_accept, &pid_tgid);
    if (!pending)
        return 0;

    address = (const void *)pending->address_pointer;
    if (context->result >= 0 && pending->address_pointer != 0 &&
        pending->length_pointer != 0 &&
        ksight_bpf_probe_read_user(&returned_length, sizeof(returned_length),
                                   (const void *)pending->length_pointer) == 0) {
        pending->returned_address_length =
            returned_length > 0xffffU ? 0xffffU : (ksight_u16)returned_length;
        if (returned_length >= KSIGHT_SOCKADDR_FAMILY_LEN &&
            ksight_bpf_probe_read_user(&pending->address_family,
                                       sizeof(pending->address_family),
                                       address) == 0) {
            pending->address_length = KSIGHT_SOCKADDR_FAMILY_LEN;
            pending->address[0] = (ksight_u8)pending->address_family;
            pending->address[1] = (ksight_u8)(pending->address_family >> 8);
            if (pending->address_family == KSIGHT_AF_INET &&
                returned_length >= KSIGHT_SOCKADDR_INET_LEN &&
                ksight_bpf_probe_read_user(pending->address,
                                           KSIGHT_SOCKADDR_INET_LEN,
                                           address) == 0) {
                pending->address_length = KSIGHT_SOCKADDR_INET_LEN;
            } else if (pending->address_family == KSIGHT_AF_INET6 &&
                       returned_length >= KSIGHT_SOCKADDR_INET6_LEN &&
                       ksight_bpf_probe_read_user(pending->address,
                                                  KSIGHT_SOCKADDR_INET6_LEN,
                                                  address) == 0) {
                pending->address_length = KSIGHT_SOCKADDR_INET6_LEN;
            } else if (pending->address_family == KSIGHT_AF_UNIX &&
                       returned_length > KSIGHT_SOCKADDR_FAMILY_LEN) {
                if (ksight_bpf_probe_read_user(pending->address,
                                               KSIGHT_SOCKADDR_UNIX_LEN,
                                               address) == 0) {
                    pending->address_length = returned_length >
                                              KSIGHT_SOCKADDR_UNIX_LEN
                        ? KSIGHT_SOCKADDR_UNIX_LEN
                        : returned_length;
                }
            } else if (returned_length >= 12 &&
                       ksight_bpf_probe_read_user(pending->address,
                                                  KSIGHT_SOCKADDR_GENERIC_LEN,
                                                  address) == 0) {
                pending->address_length = returned_length >
                                          KSIGHT_SOCKADDR_GENERIC_LEN
                    ? KSIGHT_SOCKADDR_GENERIC_LEN
                    : returned_length;
            }
        }
    }

    event = ksight_bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event) {
        ksight_record_drop();
        ksight_bpf_map_delete_elem(&pending_accept, &pid_tgid);
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    uid_gid = ksight_bpf_get_current_uid_gid();
    event->header.abi_version = KSIGHT_RAW_ABI_VERSION;
    event->header.header_size = sizeof(event->header);
    event->header.sensor_id = KSIGHT_SENSOR_NETWORK;
    event->header.event_type = KSIGHT_EVENT_NETWORK_ACCEPT;
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

    event->fd = pending->listening_fd;
    event->result = (ksight_s32)context->result;
    event->address_length = pending->address_length;
    event->address_family = pending->address_family;
    event->submitted_address_length = pending->returned_address_length;
    __builtin_memcpy(event->address, pending->address, sizeof(event->address));

    ksight_bpf_ringbuf_submit(event, 0);
    ksight_bpf_map_delete_elem(&pending_accept, &pid_tgid);
    if (context->result >= 0) {
        ksight_u64 key = ksight_socket_key((ksight_u32)(pid_tgid >> 32),
                                           context->result);
        ksight_u8 tracked = 1;

        if (ksight_bpf_map_update_elem(&socket_fds, &key, &tracked, 0) != 0)
            ksight_record_drop();
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int ksight_network_io_enter(struct ksight_raw_sys_enter *context)
{
    struct ksight_pending_io pending = {};
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;

    if (!ksight_syscall_is_network_io(context->id) &&
        !ksight_is_socket_fd_lifecycle(context->id))
        return 0;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    uid_gid = ksight_bpf_get_current_uid_gid();
    if (!ksight_should_capture(pid_tgid, uid_gid))
        return 0;
    if (ksight_track_socket_fd_enter(context, pid_tgid))
        return 0;
    if (!ksight_network_io_enabled())
        return 0;

    /* read/write 是通用 syscall：仅统计已识别为 socket 的 fd */
    if (context->id == KSIGHT_ARM64_READ ||
        context->id == KSIGHT_ARM64_WRITE ||
        context->id == KSIGHT_A32_READ ||
        context->id == KSIGHT_A32_WRITE) {
        ksight_u64 key = ksight_socket_key((ksight_u32)(pid_tgid >> 32),
                                           (ksight_s32)context->arguments[0]);

        if (!ksight_bpf_map_lookup_elem(&socket_fds, &key))
            return 0;
    }

    pending.fd = (ksight_s32)context->arguments[0];
    pending.syscall_id = (ksight_u32)context->id;
    /* sendto/recvfrom: 字节数; read/write: 字节数; sendmmsg/recvmmsg: 批量条数 */
    if (context->id == KSIGHT_ARM64_SENDTO ||
        context->id == KSIGHT_ARM64_RECVFROM ||
        context->id == KSIGHT_ARM64_READ ||
        context->id == KSIGHT_ARM64_WRITE ||
        context->id == KSIGHT_ARM64_SENDMMSG ||
        context->id == KSIGHT_ARM64_RECVMMSG ||
        context->id == KSIGHT_A32_SENDTO ||
        context->id == KSIGHT_A32_RECVFROM ||
        context->id == KSIGHT_A32_READ ||
        context->id == KSIGHT_A32_WRITE ||
        context->id == KSIGHT_A32_SENDMMSG ||
        context->id == KSIGHT_A32_RECVMMSG)
        pending.requested_length = context->arguments[2];
    pending.event_type =
        context->id == KSIGHT_ARM64_SENDTO ||
        context->id == KSIGHT_ARM64_SENDMSG ||
        context->id == KSIGHT_ARM64_WRITE ||
        context->id == KSIGHT_ARM64_SENDMMSG ||
        context->id == KSIGHT_A32_SENDTO ||
        context->id == KSIGHT_A32_SENDMSG ||
        context->id == KSIGHT_A32_WRITE ||
        context->id == KSIGHT_A32_SENDMMSG ?
        KSIGHT_EVENT_NETWORK_SEND : KSIGHT_EVENT_NETWORK_RECEIVE;
    if (ksight_bpf_map_update_elem(&pending_io, &pid_tgid,
                                   &pending, 0) != 0)
        ksight_record_drop();
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int ksight_network_io_exit(struct ksight_raw_sys_exit *context)
{
    struct ksight_pending_io *pending;
    struct ksight_network_io_event *event;
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;

    if (!ksight_syscall_is_network_io(context->id) &&
        !ksight_is_socket_fd_lifecycle(context->id))
        return 0;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    if (ksight_track_socket_fd_exit(context, pid_tgid))
        return 0;
    pending = ksight_bpf_map_lookup_elem(&pending_io, &pid_tgid);
    if (!pending)
        return 0;
    event = ksight_bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event) {
        ksight_record_drop();
        ksight_bpf_map_delete_elem(&pending_io, &pid_tgid);
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    uid_gid = ksight_bpf_get_current_uid_gid();
    event->header.abi_version = KSIGHT_RAW_ABI_VERSION;
    event->header.header_size = sizeof(event->header);
    event->header.sensor_id = KSIGHT_SENSOR_NETWORK;
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
    event->syscall_id = pending->syscall_id;
    event->result = context->result;
    event->requested_length = pending->requested_length;
    ksight_bpf_ringbuf_submit(event, 0);
    ksight_bpf_map_delete_elem(&pending_io, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
