#include "ping.h"
#include <errno.h>
#include <ip.h>
#include <stdio.h>
#include <string.h>

uint16_t icmp_checksum(struct icmp_hdr *icmp_header, char *data, size_t data_len) {
    size_t buffer_len = sizeof(struct icmp_hdr) + data_len;
    char buf[buffer_len];
    memset(buf, 0, buffer_len);

    memcpy(buf, icmp_header, sizeof(struct icmp_hdr));
    memcpy(buf + sizeof(struct icmp_hdr), data, data_len);

    ((struct icmp_hdr *)buf)->checksum = 0;

    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)buf;
    for (int i = 0; i < (int)buffer_len / 2; i++) {
        sum += ptr[i];
    }
    if (buffer_len % 2) {
        sum += (uint16_t)(buf[buffer_len - 1] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0x0000FFFF) + (sum >> 16);
    }

    return (uint16_t)~sum;
}

bool icmp_respond(int tun_fd, char *buffer, size_t buffer_len) {
    if (buffer_len < sizeof(struct iphdr) + sizeof(struct icmp_hdr)) {
        return false;
    }

    size_t offset = 0;
    struct iphdr ip_header;
    memcpy(&ip_header, buffer, sizeof(ip_header));
    offset += sizeof(struct iphdr);

    size_t ip_options_len = (ip_header.ihl * 4) - sizeof(struct iphdr);
    char ip_options[ip_options_len];
    memcpy(&ip_options, buffer + offset, ip_options_len);
    offset += ip_options_len;

    uint16_t sum = ip_checksum(&ip_header, ip_options, ip_options_len);
    if (ip_header.check != sum) {
        printf("[WARN] --- IP checksum expected %u, got %u instead.\n", ip_header.check, sum);
        return false;
    }

    printf("[INFO] --- Verified IP checksum.\n");

    struct icmp_hdr icmp_header;
    memcpy(&icmp_header, buffer + offset, sizeof(icmp_header));
    offset += sizeof(icmp_header);

    size_t data_len = buffer_len - (sizeof(struct iphdr) + ip_options_len + sizeof(struct icmp_hdr));
    char data[data_len];
    memcpy(&data, buffer + offset, data_len);

    printf("[DEBUG] --- == ICMP ==\n");
    printf("[DEBUG] ---  Type: %u\n", icmp_header.type);
    printf("[DEBUG] ---  Code: %u\n", icmp_header.code);
    printf("[DEBUG] ---  Checksum: %u\n", ntohs(icmp_header.checksum));
    printf("[DEBUG] ---  Data: %u\n", ntohl(icmp_header.data));
    printf("[DEBUG] ---  Payload: [");
    for (int i = 0; i < data_len; i++) {
        printf("0x%02X", data[i]);
        // printf("%c", data[i]);
        if (i < data_len - 1) {
            printf(" ");
        }
    }
    printf("]\n");

    sum = icmp_checksum(&icmp_header, data, data_len);
    if (sum != icmp_header.checksum) {
        printf("[WARN] --- ICMP checksum expected %u, got %u instead.\n", icmp_header.checksum, sum);
        return false;
    }

    printf("[INFO] --- Verified ICMP checksum.\n");

    if (icmp_header.type != ICMP_ECHO_REQUEST) {
        printf("[WARN] --- Unsupported ICMP type: %u.\n", icmp_header.type);
        return false;
    }

    struct icmp_hdr icmp_reply;
    memcpy(&icmp_reply, &icmp_header, sizeof(icmp_header));
    icmp_reply.type = ICMP_ECHO_REPLY;
    icmp_reply.code = 0;
    icmp_reply.checksum = icmp_checksum(&icmp_reply, data, data_len);

    struct iphdr ip_reply = {
        .version = 4,
        .ihl = (sizeof(struct iphdr) / 4),
        .tos = 0,
        .id = 0,
        .frag_off = 0,
        .ttl = ip_header.ttl,
        .protocol = ICMP_PROTOCOL,
        .check = 0,
        .saddr = ip_header.daddr,
        .daddr = ip_header.saddr,
    };
    ip_reply.tot_len = htons(sizeof(icmp_header) + sizeof(ip_reply) + data_len);
    ip_reply.check = ip_checksum(&ip_reply, NULL, 0);

    size_t reply_len = sizeof(struct iphdr) + sizeof(struct icmp_hdr) + data_len;
    char reply[reply_len];
    memcpy(reply, &ip_reply, sizeof(ip_reply));
    memcpy(reply + sizeof(ip_reply), &icmp_reply, sizeof(icmp_reply));
    memcpy(reply + sizeof(ip_reply) + sizeof(icmp_reply), data, data_len);

    printf("[DEBUG] --- tun_fd: %d\n", tun_fd);
    printf("[DEBUG] --- reply len: %zu\n", reply_len);
    printf("[DEBUG] --- ");
    for (int i = 0; i < reply_len; i++) {
        printf("0x%02X", reply[i]);
        if (i < reply_len - 1) {
            printf(" ");
        }
    }
    printf("\n");

    // TODO: configure routing tables
    if (write(tun_fd, reply, reply_len) <= 0) {
        printf("[WARN] --- (Error %d: %s) Unable to send PING reply.\n", errno, strerror(errno));
        return false;
    }

    printf("[INFO] --- Sent PING reply.\n");
    return true;
}
