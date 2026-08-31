/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSIGHT_SYSCALL_COMPAT_H
#define KSIGHT_SYSCALL_COMPAT_H

#include "ksight_types.h"

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#define KSIGHT_A64_DUP 23
#define KSIGHT_A64_DUP3 24
#define KSIGHT_A64_FCNTL 25
#define KSIGHT_A64_OPENAT 56
#define KSIGHT_A64_CLOSE 57
#define KSIGHT_A64_READ 63
#define KSIGHT_A64_WRITE 64
#define KSIGHT_A64_SENDTO 206
#define KSIGHT_A64_RECVFROM 207
#define KSIGHT_A64_SENDMSG 211
#define KSIGHT_A64_RECVMSG 212
#define KSIGHT_A64_BRK 214
#define KSIGHT_A64_MUNMAP 215
#define KSIGHT_A64_MREMAP 216
#define KSIGHT_A64_MMAP 222
#define KSIGHT_A64_MPROTECT 226
#define KSIGHT_A64_ACCEPT 202
#define KSIGHT_A64_CONNECT 203
#define KSIGHT_A64_ACCEPT4 242
#define KSIGHT_A64_RECVMMSG 243
#define KSIGHT_A64_SENDMMSG 269
#define KSIGHT_A64_CLOSE_RANGE 436
#define KSIGHT_A64_OPENAT2 437

#define KSIGHT_A32_CLOSE 6
#define KSIGHT_A32_DUP 41
#define KSIGHT_A32_BRK 45
#define KSIGHT_A32_FCNTL 55
#define KSIGHT_A32_DUP2 63
#define KSIGHT_A32_MUNMAP 91
#define KSIGHT_A32_MPROTECT 125
#define KSIGHT_A32_MREMAP 163
#define KSIGHT_A32_MMAP2 192
#define KSIGHT_A32_FCNTL64 221
#define KSIGHT_A32_CONNECT 283
#define KSIGHT_A32_SENDTO 290
#define KSIGHT_A32_RECVFROM 292
#define KSIGHT_A32_SENDMSG 296
#define KSIGHT_A32_RECVMSG 297
#define KSIGHT_A32_OPENAT 322
#define KSIGHT_A32_DUP3 358
#define KSIGHT_A32_ACCEPT4 366
#define KSIGHT_A32_CLOSE_RANGE 436
#define KSIGHT_A32_OPENAT2 437
#define KSIGHT_A32_READ 3
#define KSIGHT_A32_WRITE 4
#define KSIGHT_A32_ACCEPT 285
#define KSIGHT_A32_RECVMMSG 365
#define KSIGHT_A32_SENDMMSG 374

static __always_inline int ksight_syscall_is_open(ksight_s64 id)
{
    return id == KSIGHT_A64_OPENAT || id == KSIGHT_A64_OPENAT2 ||
           id == KSIGHT_A32_OPENAT || id == KSIGHT_A32_OPENAT2;
}

static __always_inline int ksight_syscall_is_close(ksight_s64 id)
{
    return id == KSIGHT_A64_CLOSE || id == KSIGHT_A32_CLOSE;
}

static __always_inline int ksight_syscall_is_close_range(ksight_s64 id)
{
    return id == KSIGHT_A64_CLOSE_RANGE || id == KSIGHT_A32_CLOSE_RANGE;
}

static __always_inline int ksight_syscall_is_dup(ksight_s64 id)
{
    return id == KSIGHT_A64_DUP || id == KSIGHT_A32_DUP || id == KSIGHT_A32_DUP2;
}

static __always_inline int ksight_syscall_is_dup3(ksight_s64 id)
{
    return id == KSIGHT_A64_DUP3 || id == KSIGHT_A32_DUP3;
}

static __always_inline int ksight_syscall_is_fcntl(ksight_s64 id)
{
    return id == KSIGHT_A64_FCNTL || id == KSIGHT_A32_FCNTL ||
           id == KSIGHT_A32_FCNTL64;
}

static __always_inline int ksight_syscall_is_mmap(ksight_s64 id)
{
    return id == KSIGHT_A64_MMAP || id == KSIGHT_A32_MMAP2;
}

static __always_inline int ksight_syscall_is_mprotect(ksight_s64 id)
{
    return id == KSIGHT_A64_MPROTECT || id == KSIGHT_A32_MPROTECT;
}

static __always_inline int ksight_syscall_is_munmap(ksight_s64 id)
{
    return id == KSIGHT_A64_MUNMAP || id == KSIGHT_A32_MUNMAP;
}

static __always_inline int ksight_syscall_is_mremap(ksight_s64 id)
{
    return id == KSIGHT_A64_MREMAP || id == KSIGHT_A32_MREMAP;
}

static __always_inline int ksight_syscall_is_brk(ksight_s64 id)
{
    return id == KSIGHT_A64_BRK || id == KSIGHT_A32_BRK;
}

static __always_inline int ksight_syscall_is_connect(ksight_s64 id)
{
    return id == KSIGHT_A64_CONNECT || id == KSIGHT_A32_CONNECT;
}

static __always_inline int ksight_syscall_is_accept(ksight_s64 id)
{
    return id == KSIGHT_A64_ACCEPT || id == KSIGHT_A64_ACCEPT4 ||
           id == KSIGHT_A32_ACCEPT || id == KSIGHT_A32_ACCEPT4;
}

static __always_inline int ksight_syscall_is_sendmsg(ksight_s64 id)
{
    return id == KSIGHT_A64_SENDMSG || id == KSIGHT_A32_SENDMSG;
}

static __always_inline int ksight_syscall_is_recvmsg(ksight_s64 id)
{
    return id == KSIGHT_A64_RECVMSG || id == KSIGHT_A32_RECVMSG;
}

static __always_inline int ksight_syscall_is_network_io(ksight_s64 id)
{
    return id == KSIGHT_A64_SENDTO || id == KSIGHT_A64_RECVFROM ||
           id == KSIGHT_A64_SENDMSG || id == KSIGHT_A64_RECVMSG ||
           id == KSIGHT_A64_READ || id == KSIGHT_A64_WRITE ||
           id == KSIGHT_A64_SENDMMSG || id == KSIGHT_A64_RECVMMSG ||
           id == KSIGHT_A32_SENDTO || id == KSIGHT_A32_RECVFROM ||
           id == KSIGHT_A32_SENDMSG || id == KSIGHT_A32_RECVMSG ||
           id == KSIGHT_A32_READ || id == KSIGHT_A32_WRITE ||
           id == KSIGHT_A32_SENDMMSG || id == KSIGHT_A32_RECVMMSG;
}

static __always_inline int ksight_syscall_is_handshake_send(ksight_s64 id)
{
    return id == KSIGHT_A64_WRITE || id == KSIGHT_A64_SENDTO ||
           id == KSIGHT_A64_SENDMSG || id == KSIGHT_A32_WRITE ||
           id == KSIGHT_A32_SENDTO || id == KSIGHT_A32_SENDMSG;
}

static __always_inline int ksight_syscall_is_write(ksight_s64 id)
{
    return id == KSIGHT_A64_WRITE || id == KSIGHT_A32_WRITE;
}

#endif /* KSIGHT_SYSCALL_COMPAT_H */
