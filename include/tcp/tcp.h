#ifndef TCP_H_INCLUDED
#define TCP_H_INCLUDED

#include "tcb_table.h"
#include <stdbool.h>
#include <stddef.h>

static TCB_Table *tcb_table = NULL;

extern void TCP_Handle_Packet(int tun_fd, TCB_Table *tcb_table, TCP_IP_Packet *packet);
extern bool TCP_Unwrap_Packet(const char *buf, size_t buf_len, TCP_IP_Packet **packet);

void TCP_Init();

#endif
