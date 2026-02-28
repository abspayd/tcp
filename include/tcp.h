#ifndef TCP_H_INCLUDED
#define TCP_H_INCLUDED

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>

#define TCP_PROTOCOL 6
#define MSS 536

enum tcp_state {
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

struct tcb {
    in_addr_t s_addr;
    in_addr_t d_addr;
    uint16_t s_port;
    uint16_t d_port;
    enum tcp_state state;
};

#define SET_BIT(BF, N) ((BF) |= (1 << (N)))
#define UNSET_BIT(BF, N) ((BF) &= ~(1 << (N)))
#define TOGGLE_BIT(BF, N) ((BF) ^= (1 << (N)))
#define READ_BIT(BF, N) (((BF) >> (N)) & 1)

#define TCP_OFFSET(flags) (0xF000 & (flags) >> 12)
#define TCP_RESERVED(flags) (0x0F00 & (flags) >> 8)
#define TCP_CWR(BF) READ_BIT(BF, 7)
#define TCP_ECE(BF) READ_BIT(BF, 6)
#define TCP_URG(BF) READ_BIT(BF, 5)
#define TCP_ACK(BF) READ_BIT(BF, 4)
#define TCP_PSH(BF) READ_BIT(BF, 3)
#define TCP_RST(BF) READ_BIT(BF, 2)
#define TCP_SYN(BF) READ_BIT(BF, 1)
#define TCP_FIN(BF) READ_BIT(BF, 0)

struct tcp_hdr {
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
struct pseudo_hdr {
    uint32_t source_ipaddr;
    uint32_t dest_ipaddr;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_length;
};

struct tcp_ip_packet {
    struct iphdr ip_header;
    struct tcp_hdr tcp_header;
    size_t ip_options_len;
    size_t tcp_options_len;
    size_t data_len;
    char *ip_options;
    char *tcp_options;
    char *data;
};

#endif
