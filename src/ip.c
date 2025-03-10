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
