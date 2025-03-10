#include "../include/util.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ArrayList *arraylist_create(size_t cap) {
    ArrayList *list = (ArrayList *)malloc(sizeof(ArrayList));
    if (!list) {
        return NULL;
    }
    void *values = malloc(cap);
    if (!values) {
        free(list);
        return NULL;
    }

    list->values = values;
    list->cap = cap;
    list->len = 0;
    return list;
}

void arraylist_destroy(ArrayList *list) {
    if (list) {
        free(list->values);
        free(list);
    }
}

int arraylist_add(ArrayList *list, void *item) {
    if (!list) {
        return -1;
    }
    if (list->len + 1 >= list->cap) {
        if (!arraylist_resize(list, list->cap * 2)) {
            return -1;
        }
    }
    list->values[list->len++] = item;
    return list->len - 1;
}

bool arraylist_del(ArrayList *list, int index) {
    if (!list || index > list->len) {
        return false;
    }

    for (int i = index; i < list->len; i++) {
        list->values[i] = list->values[i + 1];
    }

    list->len--;

    if (list->len <= list->cap / 4 && list->cap > 10) {
        arraylist_resize(list, list->cap / 2);
    }

    return true;
}

bool arraylist_resize(ArrayList *list, size_t new_cap) {
    void *new_values = realloc(list->values, new_cap);
    if (!new_values) {
        return false;
    }

    list->values = new_values;
    list->cap = new_cap;
    return true;
}
