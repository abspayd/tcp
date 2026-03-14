#include "tcp/state.h"
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

static void TCP_State_Closed(TCP_IP_Packet *packet, TCB *tcb);
static void TCP_State_Listen(TCP_IP_Packet *packet, TCB *tcb);
static void TCP_State_Syn_Sent(TCP_IP_Packet *packet, TCB *tcb);
static void TCP_State_Syn_Received(TCP_IP_Packet *packet, TCB *tcb);
static void TCP_State_Established(TCP_IP_Packet *packet, TCB *tcb);
static void TCP_State_Fin_Wait_1(TCP_IP_Packet *packet, TCB *tcb);
static void TCP_State_Fin_Wait_2(TCP_IP_Packet *packet, TCB *tcb);
static void TCP_State_Close_Wait(TCP_IP_Packet *packet, TCB *tcb);
static void TCP_State_Closing(TCP_IP_Packet *packet, TCB *tcb);
static void TCP_State_Last_Ack(TCP_IP_Packet *packet, TCB *tcb);
static void TCP_State_Time_Wait(TCP_IP_Packet *packet, TCB *tcb);

static TCP_State_Handler state_handlers[] = {
    [TCP_STATE_CLOSED] = TCP_State_Closed,           [TCP_STATE_LISTEN] = TCP_State_Listen,
    [TCP_STATE_SYN_SENT] = TCP_State_Syn_Sent,       [TCP_STATE_SYN_RECEIVED] = TCP_State_Syn_Received,
    [TCP_STATE_ESTABLISHED] = TCP_State_Established, [TCP_STATE_FIN_WAIT_1] = TCP_State_Fin_Wait_1,
    [TCP_STATE_FIN_WAIT_2] = TCP_State_Fin_Wait_2,   [TCP_STATE_CLOSE_WAIT] = TCP_State_Close_Wait,
    [TCP_STATE_CLOSING] = TCP_State_Closing,         [TCP_STATE_LAST_ACK] = TCP_State_Last_Ack,
    [TCP_STATE_TIME_WAIT] = TCP_State_Time_Wait,
};

void TCP_Handle_State(TCP_IP_Packet *packet, TCB *tcb) {
    if (packet == NULL || tcb == NULL) {
        return;
    }
    state_handlers[tcb->state](packet, tcb);
}

void TCP_State_Closed(TCP_IP_Packet *packet, TCB *tcb) { assert(false && "not implemented."); }
void TCP_State_Listen(TCP_IP_Packet *packet, TCB *tcb) { assert(false && "not implemented."); }
void TCP_State_Syn_Sent(TCP_IP_Packet *packet, TCB *tcb) { assert(false && "not implemented."); }
void TCP_State_Syn_Received(TCP_IP_Packet *packet, TCB *tcb) { assert(false && "not implemented."); }
void TCP_State_Established(TCP_IP_Packet *packet, TCB *tcb) { assert(false && "not implemented."); }
void TCP_State_Fin_Wait_1(TCP_IP_Packet *packet, TCB *tcb) { assert(false && "not implemented."); }
void TCP_State_Fin_Wait_2(TCP_IP_Packet *packet, TCB *tcb) { assert(false && "not implemented."); }
void TCP_State_Close_Wait(TCP_IP_Packet *packet, TCB *tcb) { assert(false && "not implemented."); }
void TCP_State_Closing(TCP_IP_Packet *packet, TCB *tcb) { assert(false && "not implemented."); }
void TCP_State_Last_Ack(TCP_IP_Packet *packet, TCB *tcb) { assert(false && "not implemented."); }
void TCP_State_Time_Wait(TCP_IP_Packet *packet, TCB *tcb) { assert(false && "not implemented."); }
