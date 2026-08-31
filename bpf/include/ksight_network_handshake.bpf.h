/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSIGHT_NETWORK_HANDSHAKE_BPF_H
#define KSIGHT_NETWORK_HANDSHAKE_BPF_H

struct ksight_pending_handshake {
    ksight_s32 fd;
    ksight_u8 is_sendmsg;
    ksight_u8 is_a32;
    ksight_u8 reserved[2];
    ksight_u64 buf;
    ksight_u64 addr;
    ksight_u32 addr_len;
};

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, ksight_u64);
    __type(value, struct ksight_pending_handshake);
} pending_handshake SEC(".maps");

static __always_inline ksight_u8 ksight_handshake_classify(const ksight_u8 *p,
                                                           ksight_u32 n)
{
    ksight_u32 word;
    ksight_u32 version;

    if (n >= 6 && p[0] == 0x16 && p[1] == 0x03)
        return KSIGHT_HANDSHAKE_KIND_TLS;
    if (n >= 5 && (p[0] & 0xc0) == 0xc0) {
        version = ((ksight_u32)p[1] << 24) | ((ksight_u32)p[2] << 16) |
                  ((ksight_u32)p[3] << 8) | (ksight_u32)p[4];
        if (version != 0)
            return KSIGHT_HANDSHAKE_KIND_QUIC;
    }
    if (n < 4)
        return 0;
    word = ((ksight_u32)p[0] << 24) | ((ksight_u32)p[1] << 16) |
           ((ksight_u32)p[2] << 8) | (ksight_u32)p[3];
    if (word == 0x47455420 || word == 0x50555420 || word == 0x50524920 ||
        word == 0x504f5354 || word == 0x48454144 || word == 0x44454c45 ||
        word == 0x50415443 || word == 0x4f505449 || word == 0x434f4e4e)
        return KSIGHT_HANDSHAKE_KIND_HTTP;
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int ksight_handshake_enter(struct ksight_raw_sys_enter *context)
{
    struct ksight_pending_handshake pending = {};
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;

    if (ksight_is_socket_fd_lifecycle(context->id)) {
        pid_tgid = ksight_bpf_get_current_pid_tgid();
        uid_gid = ksight_bpf_get_current_uid_gid();
        if (!ksight_should_capture(pid_tgid, uid_gid))
            return 0;
        ksight_track_socket_fd_enter(context, pid_tgid);
        return 0;
    }
    if (!ksight_syscall_is_handshake_send(context->id))
        return 0;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    uid_gid = ksight_bpf_get_current_uid_gid();
    if (!ksight_should_capture(pid_tgid, uid_gid))
        return 0;

    if (ksight_syscall_is_write(context->id)) {
        ksight_u64 key = ksight_socket_key((ksight_u32)(pid_tgid >> 32),
                                           (ksight_s32)context->arguments[0]);

        if (!ksight_bpf_map_lookup_elem(&socket_fds, &key))
            return 0;
    }

    pending.fd = (ksight_s32)context->arguments[0];
    pending.is_sendmsg = ksight_syscall_is_sendmsg(context->id) ? 1 : 0;
    pending.is_a32 = (context->id == KSIGHT_A32_WRITE ||
                      context->id == KSIGHT_A32_SENDTO ||
                      context->id == KSIGHT_A32_SENDMSG) ?
                         1 :
                         0;
    pending.buf = context->arguments[1] & KSIGHT_ARM64_USER_POINTER_MASK;
    if (context->id == KSIGHT_A64_SENDTO || context->id == KSIGHT_A32_SENDTO) {
        pending.addr = context->arguments[4] & KSIGHT_ARM64_USER_POINTER_MASK;
        pending.addr_len = (ksight_u32)context->arguments[5];
    }
    if (ksight_bpf_map_update_elem(&pending_handshake, &pid_tgid, &pending,
                                   0) != 0)
        ksight_record_drop();
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int ksight_handshake_exit(struct ksight_raw_sys_exit *context)
{
    struct ksight_pending_handshake *pending;
    struct ksight_handshake_event *event;
    ksight_u8 preview[8] = {};
    ksight_u8 sockaddr[28] = {};
    ksight_u8 kind;
    ksight_u8 truncated = 0;
    ksight_u8 flags = 0;
    ksight_u8 *seen;
    ksight_u16 family = 0;
    ksight_u16 port = 0;
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;
    ksight_u64 sock_key;
    ksight_u64 buf;
    ksight_s64 result;
    ksight_u32 copy_len;
    ksight_u32 preview_len;

    if (ksight_is_socket_fd_lifecycle(context->id)) {
        pid_tgid = ksight_bpf_get_current_pid_tgid();
        ksight_track_socket_fd_exit(context, pid_tgid);
        return 0;
    }
    if (!ksight_syscall_is_handshake_send(context->id))
        return 0;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    pending = ksight_bpf_map_lookup_elem(&pending_handshake, &pid_tgid);
    if (!pending)
        return 0;
    result = context->result;
    if (result <= 0)
        goto out;
    buf = pending->buf;
    if (pending->is_sendmsg && buf != 0) {
        ksight_u8 msg[32] = {};
        ksight_u64 iov_ptr = 0;
        ksight_u64 name_ptr = 0;
        ksight_u32 name_len = 0;
        ksight_u8 iov[16] = {};

        if (ksight_bpf_probe_read_user(msg, sizeof(msg), (const void *)buf) !=
            0)
            goto out;
        if (pending->is_a32) {
            name_ptr = (ksight_u64)(
                (ksight_u32)msg[0] | ((ksight_u32)msg[1] << 8) |
                ((ksight_u32)msg[2] << 16) | ((ksight_u32)msg[3] << 24));
            name_len = (ksight_u32)msg[4] | ((ksight_u32)msg[5] << 8) |
                       ((ksight_u32)msg[6] << 16) | ((ksight_u32)msg[7] << 24);
            iov_ptr = (ksight_u64)(
                (ksight_u32)msg[8] | ((ksight_u32)msg[9] << 8) |
                ((ksight_u32)msg[10] << 16) | ((ksight_u32)msg[11] << 24));
        } else {
            name_ptr = 0;
            iov_ptr = 0;
            __builtin_memcpy(&name_ptr, msg, 8);
            __builtin_memcpy(&name_len, msg + 8, 4);
            __builtin_memcpy(&iov_ptr, msg + 16, 8);
            name_ptr &= KSIGHT_ARM64_USER_POINTER_MASK;
            iov_ptr &= KSIGHT_ARM64_USER_POINTER_MASK;
        }
        if (iov_ptr == 0)
            goto out;
        if (ksight_bpf_probe_read_user(iov, sizeof(iov),
                                       (const void *)iov_ptr) != 0)
            goto out;
        if (pending->is_a32) {
            buf = (ksight_u64)((ksight_u32)iov[0] | ((ksight_u32)iov[1] << 8) |
                               ((ksight_u32)iov[2] << 16) |
                               ((ksight_u32)iov[3] << 24));
        } else {
            buf = 0;
            __builtin_memcpy(&buf, iov, 8);
            buf &= KSIGHT_ARM64_USER_POINTER_MASK;
        }
        if (name_ptr != 0 && name_len >= KSIGHT_SOCKADDR_FAMILY_LEN) {
            pending->addr = name_ptr;
            pending->addr_len = name_len;
        }
    }
    if (buf == 0)
        goto out;
    if (pending->addr != 0 && pending->addr_len >= KSIGHT_SOCKADDR_FAMILY_LEN &&
        ksight_bpf_probe_read_user(sockaddr, sizeof(sockaddr),
                                   (const void *)pending->addr) == 0) {
        family = (ksight_u16)sockaddr[0] | ((ksight_u16)sockaddr[1] << 8);
        port = ksight_port_from_sockaddr(sockaddr, family);
    }
    sock_key = ksight_socket_key((ksight_u32)(pid_tgid >> 32), pending->fd);
    if (port == 53 || ksight_bpf_map_lookup_elem(&dns_sockets, &sock_key))
        goto out;

    if (ksight_bpf_probe_read_user(preview, sizeof(preview),
                                   (const void *)buf) != 0)
        goto out;
    preview_len = result >= (ksight_s64)sizeof(preview) ?
                      (ksight_u32)sizeof(preview) :
                      (ksight_u32)result;
    kind = ksight_handshake_classify(preview, preview_len);
    if (kind == 0)
        goto out;
    {
        ksight_u8 bit = kind == KSIGHT_HANDSHAKE_KIND_QUIC ? 4 : kind;

        seen = ksight_bpf_map_lookup_elem(&handshake_seen, &sock_key);
        if (seen)
            flags = *seen;
        if (flags & bit)
            goto out;
        flags |= bit;
    }

    copy_len = (ksight_u32)result;
    if (copy_len > KSIGHT_HANDSHAKE_PAYLOAD_LEN) {
        copy_len = KSIGHT_HANDSHAKE_PAYLOAD_LEN;
        truncated = 1;
    }
    event = ksight_bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
    if (!event) {
        ksight_record_drop();
        goto out;
    }
    __builtin_memset(event, 0, sizeof(*event));
    uid_gid = ksight_bpf_get_current_uid_gid();
    event->header.abi_version = KSIGHT_RAW_ABI_VERSION;
    event->header.header_size = sizeof(event->header);
    event->header.sensor_id = KSIGHT_SENSOR_NETWORK;
    event->header.event_type = KSIGHT_EVENT_NETWORK_HANDSHAKE;
    event->header.total_size = sizeof(*event);
    event->header.flags = KSIGHT_EVENT_F_IDENTITY_PARTIAL;
    if (truncated)
        event->header.flags |= KSIGHT_EVENT_F_TRUNCATED;
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
    event->result = (ksight_s32)result;
    event->address_family = family;
    event->peer_port = port;
    event->captured_len = (ksight_u16)copy_len;
    event->kind = kind;
    event->truncated = truncated;
    if (family == KSIGHT_AF_INET)
        __builtin_memcpy(event->address, sockaddr + 4, 4);
    else if (family == KSIGHT_AF_INET6)
        __builtin_memcpy(event->address, sockaddr + 8, 16);
    ksight_bpf_probe_read_user(event->payload, KSIGHT_HANDSHAKE_PAYLOAD_LEN,
                               (const void *)buf);
    ksight_bpf_ringbuf_submit(event, 0);
    if (ksight_bpf_map_update_elem(&handshake_seen, &sock_key, &flags, 0) != 0)
        ksight_record_drop();
out:
    ksight_bpf_map_delete_elem(&pending_handshake, &pid_tgid);
    return 0;
}

#endif /* KSIGHT_NETWORK_HANDSHAKE_BPF_H */
