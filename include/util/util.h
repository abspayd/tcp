#ifndef __UTIL_H
#define __UTIL_H

#include "tcp.h"
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/types.h>

// typedef struct {
//     void **values;
//     size_t len;
//     size_t cap;
// } List;
//
// // Create a new list with a provided capacity. Uses default
// List *List_Init(size_t cap);
//
// // Add a new entry item to a list. Returns the index of the new item.
// int List_Add(List *list, void *item);
//
// // Removes the entry at index i from a list. Returns true if the item was deleted, false if there was an error.
// bool List_Remove(List *list, int i);
//
// // Change the capacity of a list. Returns true on success, false if there was an error.
// bool List_Resize(List *list, size_t new_cap);
//
// // De-allocate a list
// void List_Free(List *list);

// typedef struct {
//     in_addr_t s_addr;
//     in_addr_t d_addr;
//     uint16_t s_port;
//     uint16_t d_port;
// } tcb_key_t;
//
// typedef struct tcb_entry_t {
//     tcb_key_t key;
//     enum tcp_state value;
//     struct tcb_entry_t *next;
// } tcb_entry_t;
//
// typedef struct {
//     tcb_entry_t **entries;
//     size_t capacity;
// } tcb_table_t;
//
// tcb_table_t *tcb_table_create(size_t capacity);
// bool tcb_table_set(tcb_table_t *tcb_table, tcb_key_t *key, enum tcp_state state);
// enum tcp_state tcb_table_get(tcb_table_t *tcb_table, tcb_key_t *key);
// bool tcb_table_delete(tcb_table_t *tcb_table, tcb_key_t *key);
// void tcb_table_destroy(tcb_table_t *tcb_table);
// void tcb_table_print(tcb_table_t *tcb_table);

#endif
