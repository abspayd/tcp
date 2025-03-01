#include "include/tcp.h"
#include "include/tun.h"
#include <arpa/inet.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TUN_DEVICE "tun0"
#define TUN_IP_ADDRESS "192.168.100.1"
#define TUN_IP_PREFIX_LENGTH 24

int get_ip_header(const char *buf, size_t buf_len, struct iphdr **ip_header) {
    if (buf_len < sizeof(struct iphdr)) {
        printf("Buffer size %zu too small for IP header\n", buf_len);
        return -1;
    }
    *ip_header = (struct iphdr *)buf;
    return 0;
}

int get_tcp_header(struct iphdr *ip_header, const char *buf, size_t buf_len, struct tcp_hdr **tcp_header) {
    if (buf_len < sizeof(struct iphdr) + sizeof(struct tcp_hdr)) {
        printf("Buffer size %zu too small for TCP header\n", buf_len);
        return -1;
    }
    *tcp_header = (struct tcp_hdr *)(buf + (ip_header->ihl * 4));
    return 0;
}

static void tcp_dump(struct tcp_hdr *tcp_header) {
    printf("== TCP header ==\n");
    printf("  source port: %u, dest port: %u\n", ntohs(tcp_header->s_port), ntohs(tcp_header->d_port));
    printf("  seq: %u\n", ntohl(tcp_header->seq));
    printf("  ack: %u\n", ntohl(tcp_header->ack));
    printf("  data offset: %u, reserved: %u, flags: %u, window: %u\n", tcp_header->data_offset, tcp_header->reserved,
           tcp_header->flags, ntohs(tcp_header->window));
    printf("  checksum: %u, urg ptr: %u\n", ntohs(tcp_header->checksum), ntohs(tcp_header->urgent_ptr));
}

void pseudo_header_dump(struct pseudo_hdr *pseudo_header) {
    printf("== Pseudo header ==\n");
    printf("  s_addr: %u\n", ntohl(pseudo_header->source_ipaddr));
    printf("  d_addr: %u\n", ntohl(pseudo_header->dest_ipaddr));
    printf("  protocol: %u (0x%02X)\n", pseudo_header->protocol, pseudo_header->protocol);
    printf("  tcp length: %u\n", ntohs(pseudo_header->tcp_length));
}

uint16_t checksum(struct pseudo_hdr *pseudo_header, struct tcp_hdr *tcp_header, const char *payload,
                  size_t payload_len) {

    size_t buf_len = sizeof(struct pseudo_hdr) + sizeof(struct tcp_hdr) + payload_len;
    unsigned char buf[buf_len];
    memset(&buf, 0, buf_len);
    memcpy(buf, pseudo_header, sizeof(struct pseudo_hdr));
    memcpy(buf + sizeof(struct pseudo_hdr), tcp_header, sizeof(struct tcp_hdr));
    if (payload_len > 0) {
        memcpy(buf + sizeof(struct pseudo_hdr) + sizeof(struct tcp_hdr), payload, payload_len);
    }

    ((struct tcp_hdr *)(buf + sizeof(struct pseudo_hdr)))->checksum = 0;

    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)buf;
    for (int i = 0; i < buf_len / 2; ++i) {
        sum += ptr[i];
    }
    if (buf_len % 2) {
        sum += (uint16_t)(buf[buf_len - 1] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    uint16_t checksum = (uint16_t)~sum;

    printf("Expect: %u (0x%04X)\n", ntohs(tcp_header->checksum), ntohs(tcp_header->checksum));
    printf("Actual: %u (0x%04X)\n", ntohs(checksum), ntohs(checksum));
    return checksum;
}

void handle_packet(const char *buf, size_t buf_len) {
    struct iphdr *ip_header;
    if (get_ip_header(buf, buf_len, &ip_header) < 0) {
        printf("Unable to get IP header\n");
        return;
    }
    if (ip_header->version != 4) {
        printf("IP version %d, ignoring...\n", ip_header->version);
        return;
    }

    if (ip_header->protocol != TCP_PROTOCOL) {
        printf("Non-TCP packet, ignoring...\n");
        return;
    }

    struct tcp_hdr *tcp_header;
    if (get_tcp_header(ip_header, buf, buf_len, &tcp_header) < 0) {
        printf("Unable to get TCP header\n");
        return;
    }

    struct pseudo_hdr pseudo_header = {
        .source_ipaddr = ip_header->saddr,
        .dest_ipaddr = ip_header->daddr,
        .zero = 0,
        .protocol = (uint8_t)ip_header->protocol,
        .tcp_length = htons(ntohs(ip_header->tot_len) - ((uint16_t)ip_header->ihl * 4)),
    };
    size_t payload_offset = (ip_header->ihl * 4) + sizeof(struct tcp_hdr);
    checksum(&pseudo_header, tcp_header, (char *)(buf + payload_offset), buf_len - payload_offset);
}

int main(void) {
    char dev[IFNAMSIZ] = TUN_DEVICE;
    int tun_fd = tun_alloc(dev);
    if (tun_fd < 0) {
        perror("tun_alloc");
        return 1;
    }

    printf("Listening to device %s\n", dev);
    const int BUFFER_LENGTH = 1024 * 4;
    char buffer[BUFFER_LENGTH];
    while (1) {
        ssize_t count = read(tun_fd, &buffer, BUFFER_LENGTH);
        if (count < 0) {
            perror("read(tun_fd)");
            close(tun_fd);
            return 1;
        }

        printf("== Received %zu bytes ==\n", count);
        handle_packet(buffer, count);
        printf("\n");
    }

    close(tun_fd);
    return 0;
}
