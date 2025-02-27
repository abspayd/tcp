#ifndef __TCP_H
#define __TCP_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>

struct tcp_hdr {
    uint16_t s_port;
    uint16_t d_port;
    uint32_t seq;
    uint32_t ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t reserved : 4;
    uint8_t data_offset : 4;
#else
    uint8_t data_offset : 4;
    uint8_t reserved : 4;
#endif
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

struct cksm_hdr {
    in_addr_t source_ipaddr;
    in_addr_t dest_ipaddr;
    uint8_t protocol;
    uint16_t total_length;
};

#define CWR_MASK 0x80
#define ECE_MASK 0x40
#define URG_MASK 0x20
#define ACK_MASK 0x10
#define PSH_MASK 0x08
#define RST_MASK 0x04
#define SYN_MASK 0x02
#define FIN_MASK 0x01

// Extract TCP flags
#define CWR_FLG(FLAGS) ((FLAGS & CWR_MASK) >> 7)
#define ECE_FLG(FLAGS) ((FLAGS & ECE_MASK) >> 6)
#define URG_FLG(FLAGS) ((FLAGS & URG_MASK) >> 5)
#define ACK_FLG(FLAGS) ((FLAGS & ACK_MASK) >> 4)
#define PSH_FLG(FLAGS) ((FLAGS & PSH_MASK) >> 3)
#define RST_FLG(FLAGS) ((FLAGS & RST_MASK) >> 2)
#define SYN_FLG(FLAGS) ((FLAGS & SYN_MASK) >> 1)
#define FIN_FLG(FLAGS) (FLAGS & FIN_MASK)

#endif
