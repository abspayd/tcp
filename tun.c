#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEVICE_NAME "tun0"
#define IP_ADDR "192.168.1.100"
#define IP_PREFIX_LENGTH 24

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

// create a new netlink socket
int nl_new() {
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
int set_addr(int nl_sock, const char *dev, const char *ip_addr, int prefix_len) {
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
    rta->rta_len = RTA_LENGTH(sizeof(addr)); // IPV4 address is 4 bytes
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

int link_up(int nl_sock, const char *dev) {
    struct {
        struct nlmsghdr hd;   // netlink header
        struct ifinfomsg ifi; // interface info
        char attrbuf[512];
    } req;
    struct rtattr *rta;

    return 0;
}

int main(void) {
    char dev[IFNAMSIZ] = DEVICE_NAME;
    printf("alloc tun %s\n", dev);
    int tun_fd = tun_alloc(dev);
    if (tun_fd < 0) {
        perror("tun_alloc");
        return 1;
    }

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
    close(nl_fd);

    printf("assigned address %s/%d to %s\n", IP_ADDR, IP_PREFIX_LENGTH, dev);

    for (int i = 1; i <= 20; ++i) {
        printf("\rIdle: %ds", i);
        fflush(stdout);
        sleep(1);
    }
    printf("\n");

    close(tun_fd);
    return 0;
}
