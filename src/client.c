#include "tcp/socket.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    printf("Client\n");

    int socket = TCP_Socket_Create();

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr = {.s_addr = inet_addr("192.168.100.3")},
        .sin_port = 2000,
    };
    TCP_Socket_Bind(socket, &addr);

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_addr = {.s_addr = inet_addr("192.168.100.2")},
        .sin_port = 3000,
    };
    TCP_Socket_Connect(socket, &server_addr);

    const size_t BUFFER_SIZE = 4096;
    char buf[BUFFER_SIZE];
    snprintf(buf, BUFFER_SIZE, "Hello! This is a test.");

    TCP_Socket_Send(socket, buf, strlen(buf));

    TCP_Socket_Close(socket);

    return 0;
}
