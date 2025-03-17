#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int get_ip_header(const char *buf, size_t buf_len, struct iphdr **ip_header) {
    if (buf_len < sizeof(struct iphdr)) {
        printf("Buffer size %zu too small for IP header\n", buf_len);
        return -1;
    }
    *ip_header = (struct iphdr *)buf;
    return 0;
}

uint16_t ip_checksum(struct iphdr *ip_header, char *options, size_t options_len) {
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

void ip_dump(struct iphdr *ip_header) {
    printf("== IP header ==\n");
    printf("  version: %u, ihl: %u, tos: %u, tot_len: %u\n", ip_header->version, ip_header->ihl, ip_header->tos,
           ntohs(ip_header->tot_len));
    printf("  id: %u, frag_offset: %u\n", ntohs(ip_header->id), ntohs(ip_header->frag_off));
    printf("  ttl: %u, protocol: %u, checksum: %u\n", ip_header->ttl, ip_header->protocol, ntohs(ip_header->check));

    char s_addr_str[INET_ADDRSTRLEN];
    char d_addr_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_header->saddr, s_addr_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_header->daddr, d_addr_str, INET_ADDRSTRLEN);
    printf("  source addr: %s\n", s_addr_str);
    printf("  destination addr: %s\n", d_addr_str);
}
