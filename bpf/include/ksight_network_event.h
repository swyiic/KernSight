/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSIGHT_NETWORK_EVENT_H
#define KSIGHT_NETWORK_EVENT_H

#include "ksight_abi.h"

#define KSIGHT_SOCKET_ADDRESS_LEN 128

struct ksight_network_event {
    struct ksight_raw_event_header header;
    ksight_s32 fd;
    ksight_s32 result;
    ksight_u32 address_length;
    ksight_u16 address_family;
    ksight_u16 submitted_address_length;
    ksight_u8 address[KSIGHT_SOCKET_ADDRESS_LEN];
};

struct ksight_network_io_event {
    struct ksight_raw_event_header header;
    ksight_s32 fd;
    ksight_u32 syscall_id;
    ksight_s64 result;
    ksight_u64 requested_length;
    ksight_u8 reserved[8];
};

_Static_assert(sizeof(struct ksight_network_event) == 240,
               "ksight network event ABI changed");
_Static_assert(sizeof(struct ksight_network_io_event) == 128,
               "ksight network I/O event ABI changed");

#define KSIGHT_DNS_PAYLOAD_LEN 512

struct ksight_dns_event {
    struct ksight_raw_event_header header;
    ksight_s32 fd;
    ksight_s32 result;
    ksight_u16 address_family;
    ksight_u16 peer_port;
    ksight_u16 captured_len;
    ksight_u8 direction;
    ksight_u8 truncated;
    ksight_u8 address[16];
    ksight_u8 payload[KSIGHT_DNS_PAYLOAD_LEN];
};

_Static_assert(sizeof(struct ksight_dns_event) == 640,
               "ksight DNS event ABI changed");

#define KSIGHT_HANDSHAKE_PAYLOAD_LEN 512
#define KSIGHT_HANDSHAKE_KIND_TLS 1
#define KSIGHT_HANDSHAKE_KIND_HTTP 2
#define KSIGHT_HANDSHAKE_KIND_QUIC 3

/*
 * Same 640-byte layout as ksight_dns_event. `direction` carries the protocol
 * kind (KSIGHT_HANDSHAKE_KIND_*) rather than DNS query/response.
 */
struct ksight_handshake_event {
    struct ksight_raw_event_header header;
    ksight_s32 fd;
    ksight_s32 result;
    ksight_u16 address_family;
    ksight_u16 peer_port;
    ksight_u16 captured_len;
    ksight_u8 kind;
    ksight_u8 truncated;
    ksight_u8 address[16];
    ksight_u8 payload[KSIGHT_HANDSHAKE_PAYLOAD_LEN];
};

_Static_assert(sizeof(struct ksight_handshake_event) == 640,
               "ksight handshake event ABI changed");

#endif /* KSIGHT_NETWORK_EVENT_H */
