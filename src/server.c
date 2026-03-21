#include "tcp/socket.h"
#include "tcp/tcb_table.h"
#include <arpa/inet.h>
#include <stdio.h>

int main(void) {
    printf("Server\n");

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
            printf("Error accepting socket\n");
            return 1;
        }
    }

    TCP_Socket_Close(socket);

    return 0;
}
