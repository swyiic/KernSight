/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSIGHT_NETWORK_DNS_BPF_H
#define KSIGHT_NETWORK_DNS_BPF_H

struct ksight_pending_dns {
    ksight_s32 fd;
    ksight_u8 is_send;
    ksight_u8 reserved[3];
    ksight_u64 buf;
    ksight_u64 addr;
    ksight_u32 addr_len;
};

struct {
    __uint(type, KSIGHT_BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, ksight_u64);
    __type(value, struct ksight_pending_dns);
} pending_dns SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int ksight_dns_enter(struct ksight_raw_sys_enter *context)
{
    struct ksight_pending_dns pending = {};
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;

    if (context->id != KSIGHT_ARM64_SENDTO &&
        context->id != KSIGHT_ARM64_RECVFROM &&
        context->id != KSIGHT_A32_SENDTO &&
        context->id != KSIGHT_A32_RECVFROM)
        return 0;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    uid_gid = ksight_bpf_get_current_uid_gid();
    if (!ksight_should_capture(pid_tgid, uid_gid))
        return 0;

    pending.fd = (ksight_s32)context->arguments[0];
    pending.buf = context->arguments[1] & KSIGHT_ARM64_USER_POINTER_MASK;
    pending.addr = context->arguments[4] & KSIGHT_ARM64_USER_POINTER_MASK;
    pending.addr_len = (ksight_u32)context->arguments[5];
    pending.is_send = context->id == KSIGHT_ARM64_SENDTO ||
                      context->id == KSIGHT_A32_SENDTO;
    if (ksight_bpf_map_update_elem(&pending_dns, &pid_tgid, &pending, 0) != 0)
        ksight_record_drop();
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int ksight_dns_exit(struct ksight_raw_sys_exit *context)
{
    struct ksight_pending_dns *pending;
    struct ksight_dns_event *event;
    ksight_u8 sockaddr[28] = {};
    ksight_u16 family = 0;
    ksight_u16 port = 0;
    ksight_u64 pid_tgid;
    ksight_u64 uid_gid;
    ksight_u64 sock_key;
    ksight_s64 result;
    ksight_u32 copy_len;
    ksight_u8 truncated = 0;

    if (context->id != KSIGHT_ARM64_SENDTO &&
        context->id != KSIGHT_ARM64_RECVFROM &&
        context->id != KSIGHT_A32_SENDTO &&
        context->id != KSIGHT_A32_RECVFROM)
        return 0;

    pid_tgid = ksight_bpf_get_current_pid_tgid();
    pending = ksight_bpf_map_lookup_elem(&pending_dns, &pid_tgid);
    if (!pending)
        return 0;
    result = context->result;
    if (result <= 0)
        goto out;
    if (pending->addr != 0 && pending->addr_len >= KSIGHT_SOCKADDR_FAMILY_LEN) {
        ksight_u32 take = pending->addr_len > sizeof(sockaddr)
                              ? sizeof(sockaddr)
                              : pending->addr_len;
        if (ksight_bpf_probe_read_user(sockaddr, take,
                                       (const void *)pending->addr) == 0) {
            family = (ksight_u16)sockaddr[0] | ((ksight_u16)sockaddr[1] << 8);
            port = ksight_port_from_sockaddr(sockaddr, family);
        }
    }
    sock_key = ksight_socket_key((ksight_u32)(pid_tgid >> 32), pending->fd);
    if (port == 0 && ksight_bpf_map_lookup_elem(&dns_sockets, &sock_key))
        port = 53;
    if (port != 53)
        goto out;
    if (port == 53)
        ksight_note_dns_socket((ksight_u32)(pid_tgid >> 32), pending->fd,
                               family, sockaddr);

    copy_len = (ksight_u32)result;
    if (copy_len > KSIGHT_DNS_PAYLOAD_LEN) {
        copy_len = KSIGHT_DNS_PAYLOAD_LEN;
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
    event->header.event_type = KSIGHT_EVENT_NETWORK_DNS;
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
    event->direction = pending->is_send ? 0 : 1;
    event->truncated = truncated;
    if (family == KSIGHT_AF_INET)
        __builtin_memcpy(event->address, sockaddr + 4, 4);
    else if (family == KSIGHT_AF_INET6)
        __builtin_memcpy(event->address, sockaddr + 8, 16);
    if (pending->buf != 0)
        ksight_bpf_probe_read_user(event->payload, copy_len,
                                   (const void *)pending->buf);
    ksight_bpf_ringbuf_submit(event, 0);
out:
    ksight_bpf_map_delete_elem(&pending_dns, &pid_tgid);
    return 0;
}

#endif /* KSIGHT_NETWORK_DNS_BPF_H */
