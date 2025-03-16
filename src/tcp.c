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

bool send_packet(int tun_fd, struct tcp_ip_packet *packet) {
    if (packet == NULL) {
        printf("Attempted to send a packet with value of NULL\n");
        return false;
    }

    size_t buf_len = sizeof(struct iphdr) + sizeof(struct tcp_hdr) + packet->ip_options_len + packet->tcp_options_len +
                     packet->data_len;
    char buf[buf_len];
    memset(buf, 0, buf_len);

    size_t offset = 0;
    if (memcpy(buf, &packet->ip_header, sizeof(struct iphdr)) == NULL) {
        printf("Unable to write IP header!\n");
        return false;
    }
    offset += sizeof(struct iphdr);
    if (memcpy(buf + offset, &packet->ip_options, packet->ip_options_len) == NULL) {
        printf("Unable to write IP header options!\n");
        return false;
    }
    offset += packet->ip_options_len;
    if (memcpy(buf + offset, &packet->tcp_header, sizeof(struct tcp_hdr)) == NULL) {
        printf("Unable to write TCP header!\n");
        return false;
    }
    offset += sizeof(struct tcp_hdr);
    if (memcpy(buf + offset, &packet->tcp_options, packet->tcp_options_len) == NULL) {
        printf("Unable to write TCP header options!\n");
        return false;
    }
    offset += packet->tcp_options_len;
    if (memcpy(buf + offset, &packet->data, packet->data_len) == NULL) {
        printf("Unable to write payload!\n");
        return false;
    }

    if (write(tun_fd, buf, buf_len) <= 0) {
        printf("Failed to send packet!\n");
        return false;
    }

    return true;
}

void handle_packet(int tun_fd, tcb_table_t *tcb_table, struct tcp_ip_packet *packet) {

    tcb_key_t key = {
        .s_addr = ntohl(packet->ip_header.saddr),
        .s_port = ntohs(packet->tcp_header.s_port),
        .d_addr = ntohl(packet->ip_header.daddr),
        .d_port = ntohs(packet->tcp_header.d_port),
    };

    enum tcp_state current_state = tcb_table_get(tcb_table, &key);
    if (true || packet->tcp_header.flag_syn && current_state == TCP_STATE_CLOSED) {
        // Send syn-ack
        struct tcp_ip_packet packet_out;
        memset(&packet_out, 0, sizeof(packet_out));
        packet_out.tcp_header = (struct tcp_hdr){
            .s_port = packet->tcp_header.d_port,
            .d_port = packet->tcp_header.s_port,
            .seq = htonl((uint32_t)rand()),
            .ack = htonl(ntohl(packet->tcp_header.seq) + 1),
            .data_offset = (uint8_t)(sizeof(struct tcp_hdr)) / 4,
            .flag_ack = 1,
            .flag_syn = 1,
            .window = htons(64240),
            .checksum = 0,
        };
        packet_out.ip_header = (struct iphdr){
            .ihl = (uint8_t)(sizeof(struct iphdr) / 4),
            .version = 4,
            .tos = 0,
            .tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcp_hdr)),
            .id = 0,
            .frag_off = 0,
            .ttl = 255,
            .protocol = 6,
            .check = 0,
            .saddr = packet->ip_header.daddr,
            .daddr = packet->ip_header.saddr,
        };
        struct pseudo_hdr pseudo_header = {
            .source_ipaddr = packet_out.ip_header.saddr,
            .dest_ipaddr = packet_out.ip_header.daddr,
            .zero = 0,
            .protocol = packet_out.ip_header.protocol,
            .tcp_length = htons(sizeof(struct tcp_hdr)),

        };
        uint16_t sum = tcp_checksum(&pseudo_header, &packet_out.tcp_header, NULL, 0);
        packet_out.tcp_header.checksum = htons(sum);
        sum = ip_checksum(&packet_out.ip_header, NULL, 0);
        packet_out.ip_header.check = htons(sum);

        tcp_dump(&(packet->tcp_header));
        tcp_dump(&(packet_out.tcp_header));

        if (send_packet(tun_fd, &packet_out)) {
            printf("Packet sent!\n");
            tcb_table_set(tcb_table, &key, TCP_STATE_SYN_RECEIEVED);
        } else {
            printf("Failed to send packet.\n");
        }
    }
    //
    //
}

// Unwrap a byte stream into a TCP/IP packet. Returns true if the byte stream contains
// a valid TCP/IP packet and was unwrapped, and false otherwise.
bool unwrap_packet(const char *buf, size_t buf_len, struct tcp_ip_packet **packet) {
    if (buf_len < sizeof(struct iphdr) + sizeof(struct tcp_hdr)) {
        return false;
    }

    memset(*packet, 0, sizeof(struct tcp_ip_packet));

    memcpy(&(*packet)->ip_header, buf, sizeof(struct iphdr));
    if ((*packet)->ip_header.version != 4) {
        printf("Packet is not IPv4, skipping...\n");
        return false;
    }
    if ((*packet)->ip_header.protocol != TCP_PROTOCOL) {
        printf("Packet is not a TCP segment, skipping...\n");
        return false;
    }

    if ((*packet)->ip_header.ihl * 4 > sizeof(struct iphdr)) {
        size_t options_len = ((*packet)->ip_header.ihl * 4) - sizeof(struct iphdr);
        char *ip_options = malloc(options_len);
        memcpy(ip_options, buf + sizeof(struct iphdr), options_len);

        (*packet)->ip_options_len = options_len;
        (*packet)->ip_options = ip_options;
    }

    uint16_t ip_sum = ip_checksum(&((*packet)->ip_header), (*packet)->ip_options, (*packet)->ip_options_len);
    if (ip_sum != (*packet)->ip_header.check) {
        return false;
    }

    memcpy(&(*packet)->tcp_header, buf + ((*packet)->ip_header.ihl * 4), sizeof(struct tcp_hdr));
    if ((*packet)->tcp_header.data_offset > sizeof(struct tcp_hdr)) {
        size_t tcp_options_len = ((*packet)->tcp_header.data_offset * 4) - sizeof(struct tcp_hdr);
        char *tcp_options = malloc(tcp_options_len);
        memcpy(tcp_options, buf + sizeof(struct iphdr) + sizeof(struct tcp_hdr), tcp_options_len);

        (*packet)->tcp_options_len = tcp_options_len;
        (*packet)->tcp_options = tcp_options;
    }

    size_t headers_length =
        sizeof(struct iphdr) + (*packet)->ip_options_len + sizeof(struct tcp_hdr) + (*packet)->tcp_options_len;
    if (buf_len > headers_length) {
        size_t data_len = buf_len - headers_length;
        char *data = malloc(data_len);
        memcpy(data, buf + headers_length, data_len);

        (*packet)->data_len = data_len;
        (*packet)->data = data;
    }

    struct pseudo_hdr pseudo_header = {
        .source_ipaddr = (*packet)->ip_header.saddr,
        .dest_ipaddr = (*packet)->ip_header.daddr,
        .zero = 0,
        .protocol = (*packet)->ip_header.protocol,
        .tcp_length = htons(sizeof(struct tcp_hdr) + (*packet)->tcp_options_len + (*packet)->data_len),
    };

    size_t payload_offset = ((*packet)->ip_header.ihl * 4) + sizeof(struct tcp_hdr);
    if (payload_offset >= buf_len) {
        printf("Packet too small to fit TCP/IP headers!\n");
        return false;
    }
    uint16_t tcp_sum =
        tcp_checksum(&pseudo_header, &(*packet)->tcp_header, buf + payload_offset, buf_len - payload_offset);
    if (tcp_sum != (*packet)->tcp_header.checksum) {
        printf("Incorrect TCP checksum.\n");
        return false;
    }

    return true;
}

int main(void) {
    char dev[IFNAMSIZ] = TUN_DEVICE;
    int tun_fd = tun_alloc(dev);
    if (tun_fd < 0) {
        perror("tun_alloc");
        return 1;
    }

    tcb_table_t *tcb_table = tcb_table_create(256);

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

        struct tcp_ip_packet *packet = malloc(sizeof(struct tcp_ip_packet));
        if (!unwrap_packet(buffer, count, &packet)) {
            printf("Unable to validate packet\n");
        } else {
            printf("Obtained valid packet!\n");
        }

        handle_packet(tun_fd, tcb_table, packet);

        tcb_key_t key = {
            .s_addr = ntohl(packet->ip_header.saddr),
            .s_port = ntohs(packet->tcp_header.s_port),
            .d_addr = ntohl(packet->ip_header.daddr),
            .d_port = ntohs(packet->tcp_header.d_port),
        };
        // if (!tcb_table_set(tcb_table, &key, TCP_STATE_ESTABLISHED)) {
        //     printf("Unable to set record in TCB table\n");
        //     exit(1);
        // }
        printf("STATE: %d\n", tcb_table_get(tcb_table, &key));
        tcb_table_print(tcb_table);

        if (packet->ip_options_len > 0) {
            free(packet->ip_options);
        }
        if (packet->tcp_options_len > 0) {
            free(packet->tcp_options);
        }
        if (packet->data_len > 0) {
            free(packet->data);
        }
        free(packet);
    }

    tcb_table_destroy(tcb_table);

    close(tun_fd);
    return 0;
}
