#include <netinet/in.h>
#include <sys/types.h>

#define MAX_SOCKETS 128

enum TCP_Socket_State {
    SOCKET_STATE_CLOSED,
    SOCKET_STATE_OPEN,
    SOCKET_STATE_LISTENING,
    SOCKET_STATE_CONNECTED,
};

typedef struct {
    in_addr_t addr;
    uint16_t port;
    enum TCP_Socket_State state;
} TCP_Socket;

static TCP_Socket *sockets[MAX_SOCKETS];
static int next_socket = 0;
