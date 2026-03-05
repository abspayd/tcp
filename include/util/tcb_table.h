#ifndef TCB_TABLE_H_INCLUDED
#define TCB_TABLE_H_INCLUDED

#include "tcp.h"
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/types.h>

typedef struct {
    in_addr_t s_addr;
    in_addr_t d_addr;
    uint16_t s_port;
    uint16_t d_port;
} TCB_Key;

typedef struct TCB_Entry {
    TCB_Key key;
    // enum tcp_state value;

    struct TCB tcb;

    struct TCB_Entry *next;
} TCB_Entry;

typedef struct {
    TCB_Entry **entries;
    size_t capacity;
} TCB_Table;

extern TCB_Table *tcb_table_create(size_t capacity);
extern bool tcb_table_set_state(TCB_Table *tcb_table, TCB_Key *key, enum TCP_State state);
extern enum TCP_State tcb_table_get(TCB_Table *tcb_table, TCB_Key *key);
extern bool tcb_table_delete(TCB_Table *tcb_table, TCB_Key *key);
extern void tcb_table_destroy(TCB_Table *tcb_table);
extern void tcb_table_print(TCB_Table *tcb_table);

#endif
