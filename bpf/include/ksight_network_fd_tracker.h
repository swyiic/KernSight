/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSIGHT_NETWORK_FD_TRACKER_H
#define KSIGHT_NETWORK_FD_TRACKER_H

#define KSIGHT_ARM64_DUP 23
#define KSIGHT_ARM64_DUP3 24
#define KSIGHT_ARM64_FCNTL 25
#define KSIGHT_ARM64_CLOSE 57
#define KSIGHT_F_DUPFD 0U
#define KSIGHT_F_DUPFD_CLOEXEC 1030U

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, ksight_u64);
    __type(value, ksight_u8);
} socket_fds SEC(".maps");

struct ksight_pending_socket_fd {
    ksight_s32 fd;
};

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, ksight_u64);
    __type(value, struct ksight_pending_socket_fd);
} pending_socket_fd SEC(".maps");

static __always_inline ksight_u64 ksight_socket_key(ksight_u32 tgid,
                                                      ksight_s32 fd)
{
    return ((ksight_u64)tgid << 32) | (ksight_u32)fd;
}

static __always_inline int ksight_is_socket_fd_lifecycle(ksight_s64 syscall_id)
{
    return syscall_id == KSIGHT_ARM64_CLOSE ||
           syscall_id == KSIGHT_ARM64_DUP ||
           syscall_id == KSIGHT_ARM64_DUP3 ||
           syscall_id == KSIGHT_ARM64_FCNTL;
}

static __always_inline int
ksight_track_socket_fd_enter(struct ksight_raw_sys_enter *context,
                             ksight_u64 pid_tgid)
{
    struct ksight_pending_socket_fd pending = {};
    ksight_u32 command;

    if (!ksight_is_socket_fd_lifecycle(context->id))
        return 0;
    if (context->id == KSIGHT_ARM64_FCNTL) {
        command = (ksight_u32)context->arguments[1];
        if (command != KSIGHT_F_DUPFD && command != KSIGHT_F_DUPFD_CLOEXEC)
            return 0;
    }
    pending.fd = (ksight_s32)context->arguments[0];
    if (ksight_bpf_map_update_elem(&pending_socket_fd, &pid_tgid,
                                   &pending, 0) != 0)
        ksight_record_drop();
    return 1;
}

static __always_inline int
ksight_track_socket_fd_exit(struct ksight_raw_sys_exit *context,
                            ksight_u64 pid_tgid)
{
    struct ksight_pending_socket_fd *pending;
    ksight_u64 old_key;

    if (!ksight_is_socket_fd_lifecycle(context->id))
        return 0;
    pending = ksight_bpf_map_lookup_elem(&pending_socket_fd, &pid_tgid);
    if (!pending)
        return 1;
    old_key = ksight_socket_key((ksight_u32)(pid_tgid >> 32), pending->fd);
    if (context->result >= 0) {
        if (context->id == KSIGHT_ARM64_CLOSE) {
            ksight_bpf_map_delete_elem(&socket_fds, &old_key);
        } else {
            ksight_u64 new_key = ksight_socket_key(
                (ksight_u32)(pid_tgid >> 32), (ksight_s32)context->result);

            if (ksight_bpf_map_lookup_elem(&socket_fds, &old_key)) {
                ksight_u8 tracked = 1;

                if (ksight_bpf_map_update_elem(&socket_fds, &new_key,
                                               &tracked, 0) != 0)
                    ksight_record_drop();
            } else {
                /* dup3 may replace a previously tracked socket with a non-socket. */
                ksight_bpf_map_delete_elem(&socket_fds, &new_key);
            }
        }
    }
    ksight_bpf_map_delete_elem(&pending_socket_fd, &pid_tgid);
    return 1;
}

#endif /* KSIGHT_NETWORK_FD_TRACKER_H */
