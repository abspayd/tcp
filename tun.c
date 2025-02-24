#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
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
    struct {
        uint8_t version;
        uint8_t ihl;
        uint8_t dscp;
        uint8_t ecn;
        uint16_t total_length;
        uint16_t identification;
        uint8_t flags;
        uint16_t fragment_offset;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t header_checksum;
        uint32_t source_addr;
        uint32_t dest_addr;
    } inet_packet;

    if (buf_len < sizeof(inet_packet)) {
        printf("Buffer too small for IP packet\n");
        return;
    }

    memset(&inet_packet, 0, sizeof(inet_packet));
    inet_packet.version = ((uint8_t)buf[0]) >> 4;
    inet_packet.ihl = (uint8_t)buf[0] & 0x0F;
    inet_packet.dscp = ((uint8_t)buf[1]) >> 2;
    inet_packet.ecn = (uint8_t)buf[1] & 0x03;
    inet_packet.total_length = (uint16_t)((uint8_t)buf[2] | (uint8_t)buf[3]);
    inet_packet.identification = (uint16_t)((uint8_t)buf[4] | (uint8_t)buf[5]);
    inet_packet.flags = ((uint8_t)buf[6]) >> 5;
    inet_packet.fragment_offset = (uint16_t)(((uint8_t)buf[6] & 0x1F) | (uint8_t)buf[7]);
    inet_packet.ttl = (uint8_t)buf[8];
    inet_packet.protocol = (uint8_t)buf[9];
    inet_packet.header_checksum = (uint16_t)((uint8_t)buf[10] | (uint8_t)buf[11]);
    inet_packet.source_addr = (uint32_t)((uint8_t)buf[12] | (uint8_t)buf[13] | (uint8_t)buf[14] | (uint8_t)buf[15]);
    inet_packet.source_addr = (uint32_t)((uint8_t)buf[16] | (uint8_t)buf[17] | (uint8_t)buf[18] | (uint8_t)buf[19]);

    printf("version: %d, IHL: %d\n", inet_packet.version, inet_packet.ihl);
    printf("DSCP: %d, ECN: %d\n", inet_packet.dscp, inet_packet.ecn);
    printf("total length: %d\n", inet_packet.total_length);
    printf("identification: 0x%04X (%d)\n", inet_packet.identification, inet_packet.identification);
    printf("flags: 0x%X, fragment offset: %d\n", inet_packet.flags, inet_packet.fragment_offset);
    printf("ttl: %d, protocol: %d\n", inet_packet.ttl, inet_packet.protocol);
    printf("header checksum: 0x%04X\n", inet_packet.header_checksum);

    struct in_addr src_addr = {
        .s_addr = inet_packet.source_addr,
    };
    char src_addr_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &src_addr, src_addr_str, INET_ADDRSTRLEN) <= 0) {
        printf("Invalid source address\n");
        return;
    }

    struct in_addr dest_addr = {
        .s_addr = inet_packet.dest_addr,
    };
    char dest_addr_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &dest_addr, dest_addr_str, INET_ADDRSTRLEN) <= 0) {
        printf("Invalid destination address\n");
        return;
    }

    printf("source address: %s\n", src_addr_str);
    printf("dest address: %s\n", dest_addr_str);
    //
    //
}

void packet_dump(unsigned char *buf, size_t buf_len) {
    unsigned char version = ((unsigned char)buf[0]) >> 4;
    if (version != 4) {
        printf("Unsupported ip version: %d\n", version);
        return;
    }
    dump_ipv4(buf, buf_len);
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
