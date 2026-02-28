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
} tcb_key_t;

typedef struct tcb_entry_t {
    tcb_key_t key;
    enum tcp_state value;
    struct tcb_entry_t *next;
} tcb_entry_t;

typedef struct {
    tcb_entry_t **entries;
    size_t capacity;
} tcb_table_t;

tcb_table_t *tcb_table_create(size_t capacity);
bool tcb_table_set(tcb_table_t *tcb_table, tcb_key_t *key, enum tcp_state state);
enum tcp_state tcb_table_get(tcb_table_t *tcb_table, tcb_key_t *key);
bool tcb_table_delete(tcb_table_t *tcb_table, tcb_key_t *key);
void tcb_table_destroy(tcb_table_t *tcb_table);
void tcb_table_print(tcb_table_t *tcb_table);

#endif
