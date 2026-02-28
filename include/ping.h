#ifndef PING_H_INCLUDED
#define PING_H_INCLUDED

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ICMP_PROTOCOL 1
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t data;
};

extern uint16_t icmp_checksum(struct icmp_hdr *icmp_header, char *data, size_t data_len);
extern bool icmp_respond(int tun_fd, char *buffer, size_t buffer_len);

#endif
