#include "../include/tcp.h"
#include "../include/ip.h"
#include "../include/tun.h"
#include "../include/util.h"
#include <arpa/inet.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TUN_DEVICE "tun0"
#define TUN_IP_ADDRESS "192.168.100.1"
#define TUN_IP_PREFIX_LENGTH 24

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
           tcp_header->flag_cwr, ntohs(tcp_header->window));
    printf("  checksum: %u, urg ptr: %u\n", ntohs(tcp_header->checksum), ntohs(tcp_header->urgent_ptr));
}

void pseudo_header_dump(struct pseudo_hdr *pseudo_header) {
    printf("== Pseudo header ==\n");
    printf("  s_addr: %u\n", ntohl(pseudo_header->source_ipaddr));
    printf("  d_addr: %u\n", ntohl(pseudo_header->dest_ipaddr));
    printf("  protocol: %u (0x%02X)\n", pseudo_header->protocol, pseudo_header->protocol);
    printf("  tcp length: %u\n", ntohs(pseudo_header->tcp_length));
}

uint16_t tcp_checksum(struct pseudo_hdr *pseudo_header, struct tcp_hdr *tcp_header, const char *payload,
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
    for (int i = 0; i < (int)buf_len / 2; ++i) {
        sum += ptr[i];
    }
    if (buf_len % 2) {
        sum += (uint16_t)(buf[buf_len - 1] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

struct iphdr new_ip_header(in_addr_t source_ipaddr, in_addr_t dest_ipaddr) {
    struct iphdr returnIP = {
        .version = 4,
        .ihl = (uint8_t)(sizeof(struct iphdr) & 0xF),
        .tos = 0,
        .tot_len = 0, // TODO: need _everything_ before this can be determined
        .id = htons(1),
        .frag_off = 0,
        .ttl = 64,
        .protocol = 6,
        .check = 0,
        .saddr = htonl(source_ipaddr),
        .daddr = htonl(dest_ipaddr),
    };

    return returnIP;
}

/**
 * Construct a SYN-ACK packet into a buffer buf
 *
 * @return the size of the packet, or -1 if an error occurred
 */
ssize_t syn_ack(struct iphdr *ip_header, char *buf, size_t buf_len) {
    // TODO: take some time to make a diagram of how the TCP/IP protocol works
    return -1;
}

// Unwrap a byte stream into a TCP/IP packet. Returns true if the byte stream contains
// a valid TCP/IP packet and was unwrapped, and false otherwise.
bool unwrap_packet(const char *buf, size_t buf_len, struct tcp_ip_packet **packet) {
    if (buf_len < sizeof(struct iphdr) + sizeof(struct tcp_hdr)) {
        return false;
    }

    memset(*packet, 0, sizeof(struct tcp_ip_packet));

    memcpy((*packet)->ip_header, buf, sizeof(struct iphdr));
    if ((*packet)->ip_header->version != 4) {
        printf("Packet is not IPv4, skipping...\n");
        return false;
    }

    if ((*packet)->ip_header->ihl * 4 > sizeof(struct iphdr)) {
        size_t options_len = ((*packet)->ip_header->ihl * 4) - sizeof(struct iphdr);
        char *ip_options = malloc(options_len);
        (*packet)->ip_options_len = options_len;
        memcpy(ip_options, buf + sizeof(struct iphdr), options_len);
    }

    uint16_t ip_sum = ip_checksum((*packet)->ip_header, (*packet)->ip_options, (*packet)->ip_options_len);
    if (ip_sum != (*packet)->ip_header->check) {
        free((*packet)->ip_options);
        return false;
    }

    // TODO:
    // 1. Get tcp header options and length
    // 2. Get packet data and length
    // 3. Checksum TCP segment

    // (*packet)->tcp_header =
    memcpy((*packet)->tcp_header, buf + ((*packet)->ip_header->ihl * 4), sizeof(struct tcp_hdr));
    if ((*packet)->tcp_header->data_offset > sizeof(struct tcp_hdr)) {
    }

    return true;
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

    char *opts = NULL;
    size_t opts_len = 0;
    if ((ip_header->ihl * 4) > sizeof(struct iphdr)) {
        opts = (char *)(buf + sizeof(struct iphdr));
        opts_len = (ip_header->ihl * 4) - sizeof(struct iphdr);
    }

    uint16_t ip_sum = ip_checksum(ip_header, opts, opts_len);
    if (ip_sum != ip_header->check) {
        printf("IP checksum validation failed\n");
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
    uint16_t sum = tcp_checksum(&pseudo_header, tcp_header, (char *)(buf + payload_offset), buf_len - payload_offset);
    if (sum != tcp_header->checksum) {
        printf("Checksum validation failed\n");
        return;
    }

    if (tcp_header->flag_syn) {
        // Send SYN-ACK
        char resp_buf[MSS];
        ssize_t resp_len = syn_ack(ip_header, resp_buf, buf_len);
        if (resp_len > 0) {
            printf("created packet, now I just need to send it...\n");
        }
    }
}

int main(void) {
    char dev[IFNAMSIZ] = TUN_DEVICE;
    int tun_fd = tun_alloc(dev);
    if (tun_fd < 0) {
        perror("tun_alloc");
        return 1;
    }

    ArrayList *tcb_table = arraylist_create(DEFAULT_CAPACITY);

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
        // handle_packet(buffer, count);
        printf("\n");

        struct tcp_ip_packet *packet;
        unwrap_packet(buffer, count, &packet);

        // TODO:
        // unwrap_packet(...)
        // tcb_add_or_update
        // respond

        if (packet->ip_options_len > 0) {
            free(packet->ip_options);
        }
        if (packet->data_len > 0) {
            free(packet->data);
        }
    }

    for (int i = 0; i < tcb_table->len; i++) {
        free(tcb_table->values[i]);
    }
    arraylist_destroy(tcb_table);

    close(tun_fd);
    return 0;
}
