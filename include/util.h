#ifndef __UTIL_H
#define __UTIL_H

#include <stdbool.h>
#include <sys/types.h>

typedef struct {
    void **values;
    size_t len;
    size_t cap;
} ArrayList;

#define DEFAULT_CAPACITY 256

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

#endif
