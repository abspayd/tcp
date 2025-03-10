#ifndef __TCP_H
#define __TCP_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>

#define TCP_PROTOCOL 6
#define MSS 536

enum tcp_state {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RECEIEVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT,
};

struct tcb {
    in_addr_t s_addr;
    uint16_t s_port;
    in_addr_t d_addr;
    uint16_t d_port;
    enum tcp_state state;
};

struct tcp_hdr {
    uint16_t s_port;
    uint16_t d_port;
    uint32_t seq;
    uint32_t ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t reserved : 4;
    uint8_t data_offset : 4;
    uint8_t flag_fin : 1;
    uint8_t flag_syn : 1;
    uint8_t flag_rst : 1;
    uint8_t flag_psh : 1;
    uint8_t flag_ack : 1;
    uint8_t flag_urg : 1;
    uint8_t flag_ece : 1;
    uint8_t flag_cwr : 1;
#else
    uint8_t data_offset : 4;
    uint8_t reserved : 4;
    uint8_t flag_cwr : 1;
    uint8_t flag_ece : 1;
    uint8_t flag_urg : 1;
    uint8_t flag_ack : 1;
    uint8_t flag_psh : 1;
    uint8_t flag_rst : 1;
    uint8_t flag_syn : 1;
    uint8_t flag_fin : 1;
#endif
    // uint8_t flags;
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
    struct iphdr *ip_header;
    char *ip_options;
    size_t ip_options_len;
    struct tcp_hdr *tcp_header;
    char *tcp_options;
    size_t tcp_options_len;
    char *data;
    size_t data_len;
};

#endif
