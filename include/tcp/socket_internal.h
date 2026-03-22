#ifndef TCP_SOCKET_INTERNAL_H_INCLUDED
#define TCP_SOCKET_INTERNAL_H_INCLUDED

#include "tcp/types.h"
#include <netinet/in.h>

#define MAX_SOCKETS 1024

enum TCP_Socket_State {
    SOCKET_STATE_CLOSED = 0,
    SOCKET_STATE_OPEN,
    SOCKET_STATE_LISTENING,
    SOCKET_STATE_CONNECTED,
};

typedef struct {
    struct sockaddr_in addr;
    enum TCP_Socket_State state;
} TCP_Socket;

static TCP_Socket *sockets[MAX_SOCKETS];
static int next_available_socket = 0;
static int socket_count = 0;

#endif
