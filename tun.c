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

#define DEVICE_NAME "tun0"
#define IP_ADDR "192.168.1.100"
#define IP_PREFIX_LENGTH 24

static int tun_alloc(char *dev) {
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

// create a new netlink socket
static int nl_new() {
    int sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock_fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;
    sa.nl_pid = getpid();

    if (bind(sock_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        return -1;
    }

    return sock_fd;
}

// set net device ip addr with netlink
static int set_addr(int nl_sock, const char *dev, const char *ip_addr, int prefix_len) {
    struct {
        struct nlmsghdr nh;
        struct ifaddrmsg ifa;
        char attrbuf[512];
    } req;
    struct rtattr *rta;

    in_addr_t addr;
    if (inet_pton(AF_INET, ip_addr, &addr) < 0) {
        perror("inet_pton");
        return -1;
    };

    memset(&req, 0, sizeof(req));

    // netlink header
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nh.nlmsg_type = RTM_NEWADDR;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;

    // address msg
    req.ifa.ifa_family = AF_INET;
    req.ifa.ifa_prefixlen = prefix_len;
    req.ifa.ifa_index = if_nametoindex(dev);

    // ip attributes
    rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.nh.nlmsg_len));
    rta->rta_type = IFA_LOCAL;
    rta->rta_len = RTA_LENGTH(sizeof(addr));
    req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_LENGTH(sizeof(addr));
    memcpy(RTA_DATA(rta), &addr, sizeof(addr));

    struct sockaddr_nl nl_addr;
    memset(&nl_addr, 0, sizeof(nl_addr));
    nl_addr.nl_family = AF_NETLINK;

    if (sendto(nl_sock, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&nl_addr, sizeof(nl_addr)) < 0) {
        perror("sendto");
        return -1;
    }

    return 0;
}

static int link_up(int nl_sock, const char *dev) {
    struct {
        struct nlmsghdr nh;   // netlink header
        struct ifinfomsg ifi; // interface info
        char attrbuf[512];
    } req;
    struct rtattr *rta;

    memset(&req, 0, sizeof(req));

    // netlink header
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nh.nlmsg_type = RTM_NEWLINK;
    req.nh.nlmsg_flags = NLM_F_REQUEST;

    // interface info msg
    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index = if_nametoindex(dev);
    req.ifi.ifi_flags = IFF_UP;
    req.ifi.ifi_change = 0xFFFFFFFF;

    // attribute buffer
    int operstate = IF_OPER_UP;
    rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.nh.nlmsg_len));
    rta->rta_type = IFLA_OPERSTATE;
    rta->rta_len = RTA_LENGTH(sizeof(operstate));
    req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_LENGTH(sizeof(operstate));
    memcpy(RTA_DATA(rta), &operstate, sizeof(operstate));

    struct sockaddr_nl nl_addr;
    memset(&nl_addr, 0, sizeof(nl_addr));
    nl_addr.nl_family = AF_NETLINK;

    if (sendto(nl_sock, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&nl_addr, sizeof(nl_addr)) < 0) {
        perror("sendto");
        return -1;
    }

    return 0;
}

static int nl_configure(int tun_fd, const char *dev) {
    int nl_fd = nl_new();
    if (nl_fd < 0) {
        close(tun_fd);
        perror("nl_new");
        return 1;
    }

    if (set_addr(nl_fd, dev, IP_ADDR, IP_PREFIX_LENGTH) < 0) {
        close(nl_fd);
        close(tun_fd);
        perror("set_addr");
        return 1;
    }
    printf("assigned address %s/%d to %s\n", IP_ADDR, IP_PREFIX_LENGTH, dev);

    if (link_up(nl_fd, dev) < 0) {
        close(nl_fd);
        close(tun_fd);
        perror("link_up");
        return 1;
    }

    close(nl_fd);
    return 0;
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

    struct tcp_hdr {
        uint16_t s_port;
        uint16_t d_port;
        uint32_t seq;
        uint32_t ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
        uint8_t reserved : 4;
        uint8_t data_offset : 4;
#else
        uint8_t data_offset : 4;
        uint8_t reserved : 4;
#endif
        uint8_t flags;
        uint16_t window;
        uint16_t checksum;
        uint16_t urgent_ptr;
    };

    struct iphdr *ip_header = (struct iphdr *)buf;

    if (ip_header->ihl > 5) {
        printf("Handle options!!!\n");
        return;
    }

    struct tcp_hdr *tcp_header = (struct tcp_hdr *)&buf[ip_header->ihl * 4];
    /*
    tcp_header->s_port = ntohs(tcp_header->s_port);
    tcp_header->d_port = ntohs(tcp_header->d_port);
    tcp_header->seq = ntohl(tcp_header->seq);
    tcp_header->ack = ntohl(tcp_header->ack);
    tcp_header->data_offset = ntohs(tcp_header->data_offset);
    tcp_header->reserved = ntohs(tcp_header->reserved);
    // tcpheader->flags = tcp_header->flags;
    tcp_header->window = ntohs(tcp_header->window);
    tcp_header->checksum = ntohs(tcp_header->checksum);
    tcp_header->urgent_ptr = ntohs(tcp_header->urgent_ptr);
    */

    printf("== TCP header (%u bytes) ==\n", tcp_header->data_offset * 4);
    printf("source port: %u, dest port: %u\n", ntohs(tcp_header->s_port), ntohs(tcp_header->d_port));
    printf("seq: %u\n", ntohl(tcp_header->seq));
    printf("ack: %u\n", ntohl(tcp_header->ack));
    printf("data offset: %u, reserved: 0x%0X\n", tcp_header->data_offset, ntohs(tcp_header->reserved));
    printf("flags (0x%02X):\n", tcp_header->flags);
    printf("  CWR: %u\n", (tcp_header->flags & 0x80) >> 7);
    printf("  ECE: %u\n", (tcp_header->flags & 0x40) >> 6);
    printf("  URG: %u\n", (tcp_header->flags & 0x20) >> 5);
    printf("  ACK: %u\n", (tcp_header->flags & 0x10) >> 4);
    printf("  PSH: %u\n", (tcp_header->flags & 0x08) >> 3);
    printf("  RST: %u\n", (tcp_header->flags & 0x04) >> 2);
    printf("  SYN: %u\n", (tcp_header->flags & 0x02) >> 1);
    printf("  FIN: %u\n", tcp_header->flags & 0x01);
    printf("window: %u\n", ntohs(tcp_header->window));
    printf("checksum: 0x%04X, urgent pointer: 0x%04X\n", ntohs(tcp_header->checksum), ntohs(tcp_header->urgent_ptr));
}

void packet_dump(unsigned char *buf, size_t buf_len) {
    unsigned char version = ((unsigned char)buf[0]) >> 4;
    if (version != 4) {
        printf("Unsupported ip version: %d\n", version);
        return;
    }
    dump_ipv4(buf, buf_len);
    printf("\n");
    dump_tcp(buf, buf_len);
}

int main(void) {
    char dev[IFNAMSIZ] = DEVICE_NAME;
    printf("alloc tun %s\n", dev);
    int tun_fd = tun_alloc(dev);
    if (tun_fd < 0) {
        perror("tun_alloc");
        return 1;
    }

    printf("Listening to device %s\n", dev);
    const int BUFFER_LENGTH = 1024 * 4;
    unsigned char buffer[BUFFER_LENGTH];
    while (1) {
        ssize_t count = read(tun_fd, &buffer, 4096);
        if (count < 0) {
            perror("read");
            return 1;
        }
        printf("== %zu bytes received ==\n", count);
        packet_dump(buffer, count);
        printf("\n");
    }

    // for (int i = 1; i <= 20; ++i) {
    //     printf("\rIdle: %ds", i);
    //     fflush(stdout);
    //     sleep(1);
    // }
    // printf("\n");

    close(tun_fd);
    return 0;
}
