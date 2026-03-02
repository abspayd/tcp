#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int IP_Get_Header(const char *buf, size_t buf_len, struct iphdr **ip_header) {
    if (buf_len < sizeof(struct iphdr)) {
        printf("Buffer size %zu too small for IP header\n", buf_len);
        return -1;
    }
    *ip_header = (struct iphdr *)buf;
    return 0;
}

uint16_t IP_Checksum(struct iphdr *ip_header, char *options, size_t options_len) {
    size_t buf_len = (ip_header->ihl * 4);
    char buf[buf_len];
    memset(buf, 0, buf_len);

    memcpy(buf, (char *)ip_header, sizeof(struct iphdr));
    if (options_len > 0) {
        memcpy(buf + sizeof(struct iphdr), options, options_len);
    }
    ((struct iphdr *)buf)->check = 0;

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

struct iphdr IP_Header_Create(in_addr_t source_ipaddr, in_addr_t dest_ipaddr) {
    struct iphdr returnIP = {
        .version = 4,
        .ihl = (uint8_t)(sizeof(struct iphdr) & 0x0F),
        .tos = 0,
        .tot_len = 0,
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

void IP_Debug(struct iphdr *ip_header) {
    printf("== IP header ==\n");
    printf("  version: %u, ihl: %u, tos: %u, tot_len: %u\n", ip_header->version, ip_header->ihl, ip_header->tos,
           ip_header->tot_len);
    printf("  id: %u, frag_offset: %u\n", ip_header->id, ip_header->frag_off);
    printf("  ttl: %u, protocol: %u, checksum: %u\n", ip_header->ttl, ip_header->protocol, ip_header->check);

    char s_addr_str[INET_ADDRSTRLEN];
    char d_addr_str[INET_ADDRSTRLEN];

    snprintf(s_addr_str, INET_ADDRSTRLEN, "%u.%u.%u.%u", (ip_header->saddr & 0xFF000000) >> 24,
             (ip_header->saddr & 0x00FF0000) >> 16, (ip_header->saddr & 0x0000FF00) >> 8,
             (ip_header->saddr & 0x000000FF));
    snprintf(d_addr_str, INET_ADDRSTRLEN, "%u.%u.%u.%u", (ip_header->daddr & 0xFF000000) >> 24,
             (ip_header->daddr & 0x00FF0000) >> 16, (ip_header->daddr & 0x0000FF00) >> 8,
             (ip_header->daddr & 0x000000FF));

    printf("  source addr: %s\n", s_addr_str);
    printf("  destination addr: %s\n", d_addr_str);
}
