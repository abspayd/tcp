#include "tcp/socket.h"
#include "tcp/socket_internal.h"
#include <assert.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int TCP_Socket_Create() {
    TCP_Socket *socket = malloc(sizeof(TCP_Socket));

    int socket_id = next_available_socket++;
    sockets[socket_id] = socket;

    return socket_id;
}

void TCP_Socket_Close(int socket_id) {

    // TODO: do actual TCP disconnect

    free(sockets[socket_id]);

    if (socket_id < next_available_socket) {
        next_available_socket = socket_id;
    }
}

int TCP_Socket_Recv(int socket_id, unsigned char *buf, size_t buf_len) { return 0; }

int TCP_Socket_Send(int socket_id, unsigned char *buf, size_t buf_len) { return 0; }

// server
void TCP_Socket_Bind(int socket_id, struct sockaddr_in *addr) {
    TCP_Socket *socket = sockets[socket_id];
    socket->addr = *addr;
}

void TCP_Socket_Listen(int socket_id) {
    TCP_Socket *socket = sockets[socket_id];

    socket->state = SOCKET_STATE_LISTENING;
}

int TCP_Socket_Accept(int socket_id) {
    TCP_Socket *socket = sockets[socket_id];
    if (socket->state != SOCKET_STATE_LISTENING) {
        return -1;
    }

    return -1;
}

// client
void TCP_Socket_Connect(int socket_id, struct sockaddr_in *addr) {
    TCP_Socket *socket = sockets[socket_id];
    ;
}
