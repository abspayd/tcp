#include "tun.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int TUN_Exists(char *dev) {
    struct ifreq ifr;
    int sock_fd, err;

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("Failed to create socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(sock_fd, SIOCGIFINDEX, &ifr)) < 0) {
        close(sock_fd);
        return err;
    }

    close(sock_fd);
    return ifr.ifr_ifindex;
}

int TUN_Alloc(char *dev) {
    // ip tuntap add dev 'dev' mode tun
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Failed to open TUN device");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    // configure tun device with no packet information provided
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if ((err = ioctl(fd, TUNSETIFF, &ifr)) < 0) {
        perror("Error configuring TUN device");
        close(fd);
        return err;
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}

int TUN_Set_Dev_IP_Addr(const char *dev, const char *ip) {
    struct ifreq ifr;
    int sock_fd, err;

    if (!dev) {
        printf("Cannot set device ip address: no device provided");
        return -1;
    }

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        perror("Failed to create socket for tun device configuration");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    // set ip addr
    struct sockaddr_in *addr;
    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, ip, &addr->sin_addr);

    if ((err = ioctl(sock_fd, SIOCSIFADDR, &ifr))) {
        close(sock_fd);
        return err;
    }

    // set netmask
    struct sockaddr_in *netmask;
    netmask = (struct sockaddr_in *)&ifr.ifr_netmask;
    netmask->sin_family = AF_INET;
    inet_pton(AF_INET, "255.255.255.0", &netmask->sin_addr);
    if ((err = ioctl(sock_fd, SIOCSIFNETMASK, &ifr))) {
        close(sock_fd);
        return err;
    }

    // set device status to "up"
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ifr.ifr_flags |= IFF_UP;
    if ((err = ioctl(sock_fd, SIOCSIFFLAGS, &ifr))) {
        close(sock_fd);
        return err;
    }

    close(sock_fd);
    return 0;
}
