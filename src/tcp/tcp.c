#define _GNU_SOURCE
#include "tcp/tcp.h"
#include "ip.h"
#include "tcp/tcb_table.h"
#include <arpa/inet.h>
#include <bits/endian.h>
#include <bits/time.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sha2.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

int TCP_Get_Header(struct iphdr *ip_header, const char *buf, size_t buf_len, TCP_Header **tcp_header);
static void TCP_Debug(TCP_Header *tcp_header);
void TCP_Pseudo_Header_Debug(Pseudo_IP_Header *pseudo_header);
uint16_t TCP_Checksum(Pseudo_IP_Header *pseudo_header, TCP_Header *tcp_header, const char *payload, size_t payload_len);
bool TCP_Send_Packet(int tun_fd, TCP_IP_Packet *packet);

void TCP_Init() {
    if (tcb_table == NULL) {
        tcb_table = TCB_Table_Create();
    }
}

void TCP_Close() {
    if (tcb_table != NULL) {
        TCB_Table_Free(tcb_table);
    }
}

int TCP_Get_Header(struct iphdr *ip_header, const char *buf, size_t buf_len, TCP_Header **tcp_header) {
    if (buf_len < sizeof(struct iphdr) + sizeof(TCP_Header)) {
        printf("Buffer size %zu too small for TCP header\n", buf_len);
        return -1;
    }

    *tcp_header = (TCP_Header *)(buf + (ip_header->ihl * 4));
    return 0;
}

static void TCP_Debug(TCP_Header *tcp_header) {
    printf("== TCP header ==\n");
    printf("  source port: %u, dest port: %u\n", tcp_header->s_port, tcp_header->d_port);
    printf("  seq: %u\n", tcp_header->seq);
    printf("  ack: %u\n", tcp_header->ack);
    printf("  data offset: %u, reserved: %u, flags: %u, window: %u\n", TCP_OFFSET(tcp_header->flags),
           TCP_RESERVED(tcp_header->flags), TCP_CWR(tcp_header->flags), tcp_header->window);
    printf("  checksum: %u, urg ptr: %u\n", tcp_header->checksum, tcp_header->urgent_ptr);
}

void TCP_Pseudo_Header_Debug(Pseudo_IP_Header *pseudo_header) {
    printf("== Pseudo header ==\n");
    printf("  s_addr: %u\n", ntohl(pseudo_header->source_ipaddr));
    printf("  d_addr: %u\n", ntohl(pseudo_header->dest_ipaddr));
    printf("  protocol: %u (0x%02X)\n", pseudo_header->protocol, pseudo_header->protocol);
    printf("  tcp length: %u\n", ntohs(pseudo_header->tcp_length));
}

uint16_t TCP_Checksum(Pseudo_IP_Header *pseudo_header, TCP_Header *tcp_header, const char *payload,
                      size_t payload_len) {
    size_t buf_len = sizeof(Pseudo_IP_Header) + sizeof(TCP_Header) + payload_len;
    unsigned char buf[buf_len];
    memset(&buf, 0, buf_len);
    memcpy(buf, pseudo_header, sizeof(Pseudo_IP_Header));
    memcpy(buf + sizeof(Pseudo_IP_Header), tcp_header, sizeof(TCP_Header));
    if (payload_len > 0) {
        memcpy(buf + sizeof(Pseudo_IP_Header) + sizeof(TCP_Header), payload, payload_len);
    }

    ((TCP_Header *)(buf + sizeof(Pseudo_IP_Header)))->checksum = 0;

    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)buf;
    for (int i = 0; i < (int)buf_len / 2; ++i) {
        sum += ptr[i];
    }
    if (buf_len % 2) {
        sum += (uint16_t)(buf[buf_len - 1] << 8);
    }

    // end-around carry to add remainder back to least-significant bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

bool TCP_Send_Packet(int tun_fd, TCP_IP_Packet *packet) {
    if (packet == NULL) {
        printf("Attempted to send a packet with value of NULL\n");
        return false;
    }

    size_t buf_len =
        sizeof(struct iphdr) + sizeof(TCP_Header) + packet->ip_options_len + packet->tcp_options_len + packet->data_len;
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
    if (memcpy(buf + offset, &packet->tcp_header, sizeof(TCP_Header)) == NULL) {
        printf("Unable to write TCP header!\n");
        return false;
    }
    offset += sizeof(TCP_Header);
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

void TCP_Handle_Packet(int tun_fd, TCB_Table *tcb_table, TCP_IP_Packet *packet) {
    TCB_Key key = {
        .s_addr = packet->ip_header.saddr,
        .s_port = packet->tcp_header.s_port,
        .d_addr = packet->ip_header.daddr,
        .d_port = packet->tcp_header.d_port,
    };

    TCB *tcb = TCB_Table_Get(tcb_table, &key);
    enum TCP_State current_state = tcb->state;

    if (TCP_SYN(packet->tcp_header.flags)) {
        tcb->state = TCP_STATE_SYN_RECEIVED;
        TCB_Table_Set(tcb_table, &key, tcb);

        // Send syn-ack
        TCP_IP_Packet packet_out;

        uint16_t tcp_flags = 0;
        TCP_SET_OFFSET(tcp_flags, (uint8_t)sizeof(TCP_Header) / 4);
        TCP_SET_ACK(tcp_flags);
        TCP_SET_SYN(tcp_flags);

        memset(&packet_out, 0, sizeof(packet_out));
        packet_out.tcp_header = (TCP_Header){
            .s_port = htons(packet->tcp_header.d_port),
            .d_port = htons(packet->tcp_header.s_port),
            .ack = htonl(ntohl(packet->tcp_header.seq) + 1),
            .flags = htons(tcp_flags),
            .window = htons(65535),
            .checksum = 0,
            .urgent_ptr = 0,
        };

        // set initial sequence number
        struct timespec tp;
        clock_gettime(CLOCK_REALTIME, &tp);
        uint64_t time = tp.tv_sec + (tp.tv_nsec / 1000);
        uint64_t secret = (uint32_t)rand();

        SHA2_CTX ctx;
        SHA256Init(&ctx);
        SHA256Update(&ctx, (uint8_t *)&time, sizeof(time));
        SHA256Update(&ctx, (uint8_t *)&secret, sizeof(secret));
        SHA256Update(&ctx, (uint8_t *)&(packet->ip_header.saddr), sizeof(packet->ip_header.saddr));
        SHA256Update(&ctx, (uint8_t *)&(packet->ip_header.daddr), sizeof(packet->ip_header.daddr));
        SHA256Update(&ctx, (uint8_t *)&(packet->tcp_header.s_port), sizeof(packet->tcp_header.s_port));
        SHA256Update(&ctx, (uint8_t *)&(packet->tcp_header.d_port), sizeof(packet->tcp_header.d_port));

        uint8_t seq_buf[SHA256_DIGEST_LENGTH];
        SHA256Final(seq_buf, &ctx);

        packet_out.tcp_header.seq = htonl(*(uint32_t *)&seq_buf);

        packet_out.ip_header = (struct iphdr){
            .ihl = (uint8_t)(sizeof(struct iphdr) / 4),
            .version = 4,
            .tos = 0,
            .tot_len = htons(sizeof(struct iphdr) + sizeof(TCP_Header)),
            .id = htons((uint16_t)rand()),
            .frag_off = 0,
            .ttl = 64,
            .protocol = 6,
            .check = 0,
            .saddr = htonl(packet->ip_header.daddr),
            .daddr = htonl(packet->ip_header.saddr),
        };
        Pseudo_IP_Header pseudo_header = {
            .source_ipaddr = htonl(packet_out.ip_header.saddr),
            .dest_ipaddr = htonl(packet_out.ip_header.daddr),
            .zero = 0,
            .protocol = packet_out.ip_header.protocol,
            .tcp_length = htons(sizeof(TCP_Header)),

        };
        uint16_t sum = TCP_Checksum(&pseudo_header, &packet_out.tcp_header, NULL, 0);
        packet_out.tcp_header.checksum = sum;
        sum = IP_Checksum(&packet_out.ip_header, NULL, 0);
        packet_out.ip_header.check = sum;

        if (TCP_Send_Packet(tun_fd, &packet_out)) {
            printf("Packet sent!\n");
            IP_Debug(&packet_out.ip_header);
            TCP_Debug(&packet_out.tcp_header);
        } else {
            printf("Failed to send packet.\n");
        }
    }
}

// Unwrap a byte stream into a TCP/IP packet. Returns true if the byte stream contains
// a valid TCP/IP packet and was unwrapped, and false otherwise.
bool TCP_Unwrap_Packet(const char *buf, size_t buf_len, TCP_IP_Packet **packet) {
    if (buf_len < sizeof(struct iphdr) + sizeof(TCP_Header)) {
        return false;
    }

    memset(*packet, 0, sizeof(TCP_IP_Packet));

    memcpy(&(*packet)->ip_header, buf, sizeof(struct iphdr));
    if ((*packet)->ip_header.version != 4) {
        // printf("Packet is not IPv4, skipping...\n");
        return false;
    }

    if ((*packet)->ip_header.protocol != TCP_PROTOCOL) {
        // printf("Packet is not a TCP segment, skipping...\n");
        return false;
    }

    if ((*packet)->ip_header.ihl * 4 > sizeof(struct iphdr)) {
        size_t options_len = ((*packet)->ip_header.ihl * 4) - sizeof(struct iphdr);
        char *ip_options = malloc(options_len);
        memcpy(ip_options, buf + sizeof(struct iphdr), options_len);

        (*packet)->ip_options_len = options_len;
        (*packet)->ip_options = ip_options;
    }

    uint16_t ip_sum = IP_Checksum(&((*packet)->ip_header), (*packet)->ip_options, (*packet)->ip_options_len);
    if (ip_sum != (*packet)->ip_header.check) {
        printf("Invalid IP checksum\n");
        return false;
    }

    memcpy(&(*packet)->tcp_header, buf + ((*packet)->ip_header.ihl * 4), sizeof(TCP_Header));
    if (TCP_OFFSET((*packet)->tcp_header.flags) > sizeof(TCP_Header)) {
        size_t tcp_options_len = (TCP_OFFSET((*packet)->tcp_header.flags) * 4) - sizeof(TCP_Header);
        char *tcp_options = malloc(tcp_options_len);
        memcpy(tcp_options, buf + sizeof(struct iphdr) + sizeof(TCP_Header), tcp_options_len);

        (*packet)->tcp_options_len = tcp_options_len;
        (*packet)->tcp_options = tcp_options;
    }

    size_t headers_length =
        sizeof(struct iphdr) + (*packet)->ip_options_len + sizeof(TCP_Header) + (*packet)->tcp_options_len;
    if (buf_len > headers_length) {
        size_t data_len = buf_len - headers_length;
        char *data = malloc(data_len);
        memcpy(data, buf + headers_length, data_len);

        (*packet)->data_len = data_len;
        (*packet)->data = data;
    }

    Pseudo_IP_Header pseudo_header = {
        .source_ipaddr = (*packet)->ip_header.saddr,
        .dest_ipaddr = (*packet)->ip_header.daddr,
        .zero = 0,
        .protocol = (*packet)->ip_header.protocol,
        .tcp_length = htons(sizeof(TCP_Header) + (*packet)->tcp_options_len + (*packet)->data_len),
    };

    size_t payload_offset = ((*packet)->ip_header.ihl * 4) + sizeof(TCP_Header);
    if (payload_offset >= buf_len) {
        printf("Packet too small to fit TCP/IP headers!\n");
        return false;
    }
    uint16_t tcp_sum =
        TCP_Checksum(&pseudo_header, &(*packet)->tcp_header, buf + payload_offset, buf_len - payload_offset);
    if (tcp_sum != (*packet)->tcp_header.checksum) {
        printf("Incorrect TCP checksum.\n");
        return false;
    }

    // convert IP header to host byte order
    (*packet)->ip_header.tot_len = ntohs((*packet)->ip_header.tot_len);
    (*packet)->ip_header.id = ntohs((*packet)->ip_header.id);
    (*packet)->ip_header.frag_off = ntohs((*packet)->ip_header.frag_off);
    (*packet)->ip_header.check = ntohs((*packet)->ip_header.check);
    (*packet)->ip_header.saddr = ntohl((*packet)->ip_header.saddr);
    (*packet)->ip_header.daddr = ntohl((*packet)->ip_header.daddr);
    if ((*packet)->ip_options_len > 0) {
        printf("TODO: byte swap IP options\n");
    }

    IP_Debug(&(*packet)->ip_header);

    // convert TCP header to host byte order
    (*packet)->tcp_header.s_port = ntohs((*packet)->tcp_header.s_port);
    (*packet)->tcp_header.d_port = ntohs((*packet)->tcp_header.d_port);
    (*packet)->tcp_header.seq = ntohl((*packet)->tcp_header.seq);
    (*packet)->tcp_header.ack = ntohl((*packet)->tcp_header.ack);
    (*packet)->tcp_header.flags = ntohs((*packet)->tcp_header.flags);
    (*packet)->tcp_header.window = ntohs((*packet)->tcp_header.window);
    (*packet)->tcp_header.checksum = ntohs((*packet)->tcp_header.checksum);
    (*packet)->tcp_header.urgent_ptr = ntohs((*packet)->tcp_header.urgent_ptr);
    if ((*packet)->tcp_options_len > 0) {
        printf("TODO: byte swap TCP options\n");
    }

    return true;
}
