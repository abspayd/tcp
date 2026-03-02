#include "util/list.h"

#include <stdlib.h>

List *List_Init(size_t cap) {
    List *list = (List *)malloc(sizeof(List));
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

void List_Free(List *list) {
    if (list) {
        free(list->values);
        free(list);
    }
}

int List_Add(List *list, void *item) {
    if (!list) {
        return -1;
    }
    if (list->len + 1 >= list->cap) {
        if (!List_Resize(list, list->cap * 2)) {
            return -1;
        }
    }
    list->values[list->len++] = item;
    return list->len - 1;
}

bool List_Remove(List *list, int index) {
    if (!list || index > (int)list->len) {
        return false;
    }

    for (int i = index; i < (int)list->len; i++) {
        list->values[i] = list->values[i + 1];
    }

    list->len--;

    if (list->len <= list->cap / 4 && list->cap > 10) {
        List_Resize(list, list->cap / 2);
    }

    return true;
}

bool List_Resize(List *list, size_t new_cap) {
    void *new_values = realloc(list->values, new_cap);
    if (!new_values) {
        return false;
    }

    list->values = new_values;
    list->cap = new_cap;
    return true;
}
