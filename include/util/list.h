#ifndef LIST_H
#define LIST_H

#include <stdbool.h>
#include <stddef.h>

typedef void (*CleanupCallback)(void *);

typedef struct {
    void **values;
    CleanupCallback *cleanup;
    size_t len;
    size_t cap;
} List;

// Create a new list with a provided capacity. Uses default
List *List_Init(size_t cap);

// Add a new entry item to a list. Returns the index of the new item.
int List_Add(List *list, void *item);

// Removes the entry at index i from a list. Returns true if the item was deleted, false if there was an error.
bool List_Remove(List *list, int i);

// Change the capacity of a list. Returns true on success, false if there was an error.
bool List_Resize(List *list, size_t new_cap);

// De-allocate a list
void List_Free(List *list);

#endif
