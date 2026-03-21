#ifndef TCP_SOCKET_H_INCLUDED
#define TCP_SOCKET_H_INCLUDED

#include "tcp/socket_internal.h"
#include "tcp/tcb_table.h"
#include "tcp/types.h"
#include <netinet/in.h>

extern int TCP_Socket_Create();
extern int TCP_Socket_Recv(int socket, unsigned char *buf, size_t buf_len);
extern int TCP_Socket_Send(int socket, unsigned char *buf, size_t buf_len);
extern void TCP_Socket_Close(int socket);

// server
extern void TCP_Socket_Bind(int socket, struct sockaddr_in *addr);
extern void TCP_Socket_Listen(int socket);
extern int TCP_Socket_Accept(int socket);

// client
extern void TCP_Socket_Connect(int socket, struct sockaddr_in *addr);

#endif
