#include "ping.h"
#include "tcp/tcb_table.h"
#include "tcp/tcp.h"
#include "tun.h"
#include <linux/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char dev[IFNAMSIZ] = TUN_DEVICE;
    int tun_fd = tun_alloc(dev);
    if (tun_fd < 0) {
        perror("tun_alloc");
        return 1;
    }

    if (set_dev_ip_addr(dev, "192.168.100.1") < 0) {
        perror("Unable to set address on tun device");
        return 1;
    }

    TCB_Table *tcb_table = TCB_Table_Create();

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

        // ICMP requests
        if ((size_t)count >= sizeof(struct iphdr)) {
            struct iphdr ip_header;
            memset(&ip_header, 0, sizeof(ip_header));
            ip_header = *(struct iphdr *)buffer;
            if (ip_header.protocol == ICMP_PROTOCOL) {
                printf("PING\n");
                icmp_respond(tun_fd, buffer, count);
                continue;
            }
        }

        struct TCP_IP_Packet *packet = malloc(sizeof(struct TCP_IP_Packet));
        if (TCP_Unwrap_Packet(buffer, count, &packet)) {
            printf("Unwrapped packet.\n");
            TCP_Handle_Packet(tun_fd, tcb_table, packet);

            // tcb_key_t key = {
            //     .s_addr = ntohl(packet->ip_header.saddr),
            //     .s_port = ntohs(packet->tcp_header.s_port),
            //     .d_addr = ntohl(packet->ip_header.daddr),
            //     .d_port = ntohs(packet->tcp_header.d_port),
            // };
            // if (!tcb_table_set(tcb_table, &key, TCP_STATE_ESTABLISHED)) {
            //     printf("Unable to set record in TCB table\n");
            //     exit(1);
            // }
            //
            // printf("STATE: %d\n", tcb_table_get(tcb_table, &key));
            // tcb_table_print(tcb_table);
        }

        if (packet->ip_options_len > 0) {
            free(packet->ip_options);
        }
        if (packet->tcp_options_len > 0) {
            free(packet->tcp_options);
        }
        if (packet->data_len > 0) {
            free(packet->data);
        }
        free(packet);
    }

    TCB_Table_Free(tcb_table);

    close(tun_fd);
    return 0;
}
