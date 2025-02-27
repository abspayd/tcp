#include "tcp.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <features.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int tun_alloc(char *dev) {
    // ip tuntap add dev 'dev' mode tun
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("open");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}

void dump_ipv4(unsigned char *buf, size_t buf_len) {
    if (buf_len < sizeof(struct iphdr)) {
        printf("Buffer too small for IP packet\n");
        return;
    }

    struct iphdr *ip_header = (struct iphdr *)buf;
    printf("version: %u, ihl: %u\n", ip_header->version, ip_header->ihl);
    printf("tos: 0x%02X (DSCP: %u, ECN: %u)\n", ip_header->tos, IPTOS_DSCP(ip_header->tos) >> 2,
           IPTOS_ECN(ip_header->tos));
    printf("total len: %u\n", ip_header->tot_len);

    struct in_addr source_addr = {.s_addr = ip_header->saddr};
    char source_addr_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &source_addr, source_addr_str, INET_ADDRSTRLEN) < 0) {
        printf("Unable to stringify address\n");
        return;
    }
    printf("source: %s\n", source_addr_str);
    struct in_addr destination_addr = {.s_addr = ip_header->daddr};
    char destination_addr_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &destination_addr, destination_addr_str, INET_ADDRSTRLEN) < 0) {
        printf("Unable to stringify address\n");
        return;
    }
    printf("dest: %s\n", destination_addr_str);

    if (ip_header->ihl > 5) {
        printf("Need to consider options section for this.\n");
    }
}

void dump_tcp(unsigned char *buf, size_t buf_len) {
    struct iphdr *ip_header = (struct iphdr *)buf;

    if (ip_header->ihl > 5) {
        printf("Handle options!!!\n");
        return;
    }

    struct tcp_hdr *tcp_header = (struct tcp_hdr *)&buf[ip_header->ihl * 4];
    printf("== TCP header (%u bytes) ==\n", tcp_header->data_offset * 4);
    printf("source port: %u, dest port: %u\n", ntohs(tcp_header->s_port), ntohs(tcp_header->d_port));
    printf("seq: %u\n", ntohl(tcp_header->seq));
    printf("ack: %u\n", ntohl(tcp_header->ack));
    printf("data offset: %u, reserved: 0x%0X\n", tcp_header->data_offset, ntohs(tcp_header->reserved));
    printf("flags (0x%02X):\n", tcp_header->flags);
    printf("  CWR: %u\n", CWR_FLG(tcp_header->flags));
    printf("  ECE: %u\n", ECE_FLG(tcp_header->flags));
    printf("  URG: %u\n", URG_FLG(tcp_header->flags));
    printf("  ACK: %u\n", ACK_FLG(tcp_header->flags));
    printf("  PSH: %u\n", PSH_FLG(tcp_header->flags));
    printf("  RST: %u\n", RST_FLG(tcp_header->flags));
    printf("  SYN: %u\n", SYN_FLG(tcp_header->flags));
    printf("  FIN: %u\n", FIN_FLG(tcp_header->flags));
    printf("window: %u\n", ntohs(tcp_header->window));
    printf("checksum: 0x%04X, urgent pointer: 0x%04X\n", ntohs(tcp_header->checksum), ntohs(tcp_header->urgent_ptr));
}

void dump_packet(unsigned char *buf, size_t buf_len) {
    unsigned char version = ((unsigned char)buf[0]) >> 4;
    if (version != 4) {
        printf("Unsupported ip version: %d\n", version);
        return;
    }
    dump_ipv4(buf, buf_len);
    printf("\n");
    dump_tcp(buf, buf_len);
}

// int main(void) {
//     char dev[IFNAMSIZ] = DEVICE_NAME;
//     printf("alloc tun %s\n", dev);
//     int tun_fd = tun_alloc(dev);
//     if (tun_fd < 0) {
//         perror("tun_alloc");
//         return 1;
//     }
//
//     printf("Listening to device %s\n", dev);
//     const int BUFFER_LENGTH = 1024 * 4;
//     unsigned char buffer[BUFFER_LENGTH];
//     while (1) {
//         ssize_t count = read(tun_fd, &buffer, 4096);
//         if (count < 0) {
//             perror("read");
//             return 1;
//         }
//         printf("== %zu bytes received ==\n", count);
//         dump_packet(buffer, count);
//         printf("\n");
//     }
//
//     // for (int i = 1; i <= 20; ++i) {
//     //     printf("\rIdle: %ds", i);
//     //     fflush(stdout);
//     //     sleep(1);
//     // }
//     // printf("\n");
//
//     close(tun_fd);
//     return 0;
// }
