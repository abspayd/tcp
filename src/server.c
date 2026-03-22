#include "tcp/socket.h"
#include "tun.h"
#include <arpa/inet.h>
#include <linux/if.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    printf("Server\n");

    char dev[IFNAMSIZ] = TUN_DEVICE;
    int tun_fd = TUN_Alloc(dev);

    int socket = TCP_Socket_Create();

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr = {.s_addr = inet_addr("192.168.100.2")},
        .sin_port = 3000,
    };
    TCP_Socket_Bind(socket, &addr);

    TCP_Socket_Listen(socket);

    while (1) {
        int connected_socket = TCP_Socket_Accept(socket);
        if (connected_socket < 0) {
            continue;
        }

        const size_t BUFFER_SIZE = 4096;
        char buf[BUFFER_SIZE];
        int n = TCP_Socket_Recv(connected_socket, buf, BUFFER_SIZE);
        printf("Got: %s\n", buf);
    }

    TCP_Socket_Close(socket);
    close(tun_fd);

    return 0;
}
