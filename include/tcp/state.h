#ifndef TCP_STATE_H_INCLUDED
#define TCP_STATE_H_INCLUDED

#include "tcp/types.h"

typedef void (*TCP_State_Handler)(TCP_IP_Packet *packet, TCB *tcb);

extern void TCP_Handle_State(TCP_IP_Packet *packet, TCB *tcb);

#endif
