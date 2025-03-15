#ifndef __UTIL_H
#define __UTIL_H

#include "tcp.h"
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/types.h>

#define DEFAULT_CAPACITY 256

typedef struct {
    void **values;
    size_t len;
    size_t cap;
} ArrayList;

// Create a new list with a provided capacity. Uses default
ArrayList *arraylist_create(size_t cap);

// Add a new entry item to a list. Returns the index of the new item.
int arraylist_add(ArrayList *list, void *item);

// Removes the entry at index i from a list. Returns true if the item was deleted, false if there was an error.
bool arraylist_del(ArrayList *list, int i);

// Change the capacity of a list. Returns true on success, false if there was an error.
bool arraylist_resize(ArrayList *list, size_t new_cap);

// De-allocate an arraylist
void arraylist_destroy(ArrayList *list);

// struct tcb_key {
//     in_addr_t s_addr;
//     uint16_t s_port;
//     in_addr_t d_addr;
//     uint16_t d_port;
// };
// typedef struct {
//     struct tcb_key key;
//     enum tcp_state val;
//     size_t len;
//     size_t cap;
// } TCB_Table_Item;
// typedef struct {
//     TCB_Table_Item *items;
//     size_t len;
//     size_t cap;
// } TCB_Table;
//
// TCB_Table *tcb_table_create(size_t cap);
// void tcb_table_create(TCB_Table *tcb_table);
// bool tcb_table_add(TCB_Table *tcb_table, struct tcb *tcb_record);
// bool tcb_table_del(TCB_Table *tcb_table, struct tcb *tcb_record);
// struct tcb *tcb_table_get(TCB_Table *tcb_table, struct tcb *tcb_record);
// bool tcb_table_resize(TCB_Table *tcb_table, size_t new_cap);
// void tcb_table_destroy(TCB_Table *tcb_table);

typedef struct {
    in_addr_t s_addr;
    uint16_t s_port;
    in_addr_t d_addr;
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

#endif
