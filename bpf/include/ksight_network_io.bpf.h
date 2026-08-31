/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSIGHT_NETWORK_IO_BPF_H
#define KSIGHT_NETWORK_IO_BPF_H

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

#endif /* KSIGHT_NETWORK_IO_BPF_H */
