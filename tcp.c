#include "tun.h"
#include <net/if.h>
#include <stdio.h>

#define TUN_DEVICE "tun0"
#define TUN_IP_ADDRESS "192.168.100.1"
#define TUN_IP_PREFIX_LENGTH 24

int main(void) {
    char dev[IF_NAMESIZE] = TUN_DEVICE;
    int tun_fd = tun_alloc(dev);
    if (tun_fd < 0) {
        perror("tun_alloc");
        return 1;
    }

    printf("Listening to device %s\n", dev);
    const int BUFFER_LENGTH = 1024 * 4;
    unsigned char buffer[BUFFER_LENGTH];
    while (1) {
        ssize_t count = read(tun_fd, &buffer, BUFFER_LENGTH);
        if (count < 0) {
            perror("read(tun_fd)");
            close(tun_fd);
            return 1;
        }

        printf("=== Received %zu bytes ===\n", count);
        dump_packet(buffer, count);
        printf("\n");
    }

    close(tun_fd);
    return 0;
}
