#include "include/tcp.h"
#include "include/tun.h"
#include <linux/if.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TUN_DEVICE "tun0"
#define TUN_IP_ADDRESS "192.168.100.1"
#define TUN_IP_PREFIX_LENGTH 24

int get_ip_header(const char *buf, size_t buf_len, struct iphdr **ip_header) {
    if (buf_len < sizeof(struct iphdr)) {
        printf("Buffer too small for IP header\n");
        return -1;
    }
    *ip_header = (struct iphdr *)buf;
    return 0;
}

int get_tcp_header(const char *buf, size_t buf_len, struct tcp_hdr **tcp_header) {
    if (buf_len < sizeof(struct iphdr) + sizeof(struct tcp_hdr)) {
        printf("Buffer too small for TCP header\n");
        return -1;
    }

    struct iphdr *ip_header;
    if (get_ip_header(buf, buf_len, &ip_header) < 0) {
        printf("Unable to get IP header\n");
        return -1;
    }

    *tcp_header = (struct tcp_hdr *)buf + ip_header->ihl * 4;
    return 0;
}

uint16_t checksum(struct tcp_hdr *tcp_header) {

    printf("TODO: verify this checksum: 0x%04X", ntohs(tcp_header->checksum));
    return 0;
}

void handle_packet(const char *buf, size_t buf_len) {
    struct iphdr *ip_header;
    if (get_ip_header(buf, buf_len, &ip_header) < 0) {
        printf("Uh-oh\n");
    }
    if (ip_header->version != 4) {
        printf("IP version %d, ignoring...\n", ip_header->version);
        return;
    }

    struct tcp_hdr *tcp_header;
    get_tcp_header(buf, buf_len, &tcp_header);
    checksum(tcp_header);
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

        // printf("=== Received %zu bytes ===\n", count);
        // dump_packet(buffer, count);
        // printf("\n");
    }

    close(tun_fd);
    return 0;
}
