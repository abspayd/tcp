#ifndef TCP_H_INCLUDED
#define TCP_H_INCLUDED

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>

#define TCP_PROTOCOL 6
#define MSS 536

enum TCP_State {
    TCP_STATE_CLOSED,
    TCP_STATE_LISTEN,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RECEIEVED,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_CLOSING,
    TCP_STATE_LAST_ACK,
    TCP_STATE_TIME_WAIT,
};

struct TCB {
    in_addr_t s_addr;
    in_addr_t d_addr;

    uint32_t iss;
    uint32_t irs;
    uint32_t send_unacknowledged;
    uint32_t send_next;
    uint32_t rcv_next;
    uint32_t send_wl1;
    uint32_t send_wl2;

    uint16_t send_window;
    uint16_t rcv_window;
    uint16_t send_urgent_ptr;
    uint16_t rcv_urgent_ptr;

    uint16_t s_port;
    uint16_t d_port;
    enum TCP_State state;
};

#define SET_BIT(BF, N) ((BF) |= (1 << (N)))
#define UNSET_BIT(BF, N) ((BF) &= ~(1 << (N)))
#define TOGGLE_BIT(BF, N) ((BF) ^= (1 << (N)))
#define READ_BIT(BF, N) (((BF) >> (N)) & 1)

#define TCP_OFFSET(flags) ((0xF000 & (flags)) >> 12)
#define TCP_RESERVED(flags) ((0x0F00 & (flags)) >> 8)

#define TCP_CWR(BF) READ_BIT(BF, 7)
#define TCP_ECE(BF) READ_BIT(BF, 6)
#define TCP_URG(BF) READ_BIT(BF, 5)
#define TCP_ACK(BF) READ_BIT(BF, 4)
#define TCP_PSH(BF) READ_BIT(BF, 3)
#define TCP_RST(BF) READ_BIT(BF, 2)
#define TCP_SYN(BF) READ_BIT(BF, 1)
#define TCP_FIN(BF) READ_BIT(BF, 0)

#define TCP_SET_OFFSET(flags, offset) ((flags) |= (((offset) & 0x000F) << 12))
#define TCP_SET_RESERVED(flags, reserved) ((flags) |= (((reserved) & 0x00F0) << 8))
#define TCP_SET_CWR(BF) SET_BIT(BF, 7)
#define TCP_SET_ECE(BF) SET_BIT(BF, 6)
#define TCP_SET_URG(BF) SET_BIT(BF, 5)
#define TCP_SET_ACK(BF) SET_BIT(BF, 4)
#define TCP_SET_PSH(BF) SET_BIT(BF, 3)
#define TCP_SET_RST(BF) SET_BIT(BF, 2)
#define TCP_SET_SYN(BF) SET_BIT(BF, 1)
#define TCP_SET_FIN(BF) SET_BIT(BF, 0)

struct TCP_Header {
    uint16_t s_port;
    uint16_t d_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

// pseudo ip header for checksum
struct Pseudo_IP_Header {
    uint32_t source_ipaddr;
    uint32_t dest_ipaddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_length;
};

struct TCP_IP_Packet {
    struct iphdr ip_header;
    struct TCP_Header tcp_header;
    size_t ip_options_len;
    size_t tcp_options_len;
    size_t data_len;
    char *ip_options;
    char *tcp_options;
    char *data;
};

#endif
