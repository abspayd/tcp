#ifndef TCB_TABLE_H_INCLUDED
#define TCB_TABLE_H_INCLUDED

#include "types.h"
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
    struct TCB tcb;

    struct TCB_Entry *next;
} TCB_Entry;

typedef struct {
    TCB_Entry **entries;
    size_t capacity;
} TCB_Table;

extern TCB_Table *TCB_Table_Create(size_t capacity);
extern bool TCB_Table_Set(TCB_Table *tcb_table, TCB_Key *key, struct TCB *tcb);
extern bool TCB_Table_Set_State(TCB_Table *tcb_table, TCB_Key *key, enum TCP_State state);
extern enum TCP_State TCB_Table_Get_State(TCB_Table *tcb_table, TCB_Key *key);
extern bool TCB_Table_Delete(TCB_Table *tcb_table, TCB_Key *key);
extern void TCB_Table_Destroy(TCB_Table *tcb_table);
extern void TCB_Table_Print(TCB_Table *tcb_table);

#endif
