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
    if (!list || index > (int)list->len) {
        return false;
    }

    for (int i = index; i < (int)list->len; i++) {
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

unsigned int tcb_hash(tcb_key_t *key, size_t capacity) {
    return (key->s_addr + key->s_port + key->d_addr + key->d_port) % capacity;
}

bool tcb_key_compare(tcb_key_t *k1, tcb_key_t *k2) {
    return (k1->s_addr == k2->s_addr && k1->s_port == k2->s_port && k1->d_addr == k2->d_addr &&
            k1->d_port == k2->d_port);
}

tcb_table_t *tcb_table_create(size_t capacity) {
    tcb_table_t *table = malloc(sizeof(tcb_table_t));
    memset(table, 0, sizeof(tcb_table_t));

    table->capacity = capacity;

    table->entries = malloc(sizeof(tcb_entry_t) * capacity);
    memset(table->entries, 0, sizeof(tcb_entry_t) * capacity);

    return table;
}

bool tcb_table_set(tcb_table_t *tcb_table, tcb_key_t *key, enum tcp_state state) {
    if (tcb_table == NULL || key == NULL || tcb_table->entries == NULL) {
        return false;
    }
    int index = tcb_hash(key, tcb_table->capacity);
    tcb_entry_t *entry = tcb_table->entries[index];
    while (entry != NULL && entry->next != NULL) {
        if (tcb_key_compare(key, &entry->key)) {
            // update existing tcb entry
            entry->value = state;
            return true;
        }
        entry = entry->next;
    }

    tcb_entry_t *new_entry = malloc(sizeof(tcb_entry_t));
    new_entry->key = *key;
    new_entry->value = state;
    new_entry->next = NULL;

    if (entry != NULL) {
        entry->next = new_entry;
    } else {
        tcb_table->entries[index] = new_entry;
    }

    return true;
}

enum tcp_state tcb_table_get(tcb_table_t *tcb_table, tcb_key_t *key) {
    if (tcb_table == NULL || key == NULL) {
        return TCP_STATE_CLOSED;
    }

    int index = tcb_hash(key, tcb_table->capacity);
    tcb_entry_t *entry = tcb_table->entries[index];
    while (entry != NULL) {
        if (tcb_key_compare(key, &entry->key)) {
            return entry->value;
        }
        entry = entry->next;
    }
    return TCP_STATE_CLOSED;
}

bool tcb_table_delete(tcb_table_t *tcb_table, tcb_key_t *key) {
    if (tcb_table == NULL || key == NULL) {
        return false;
    }

    int index = tcb_hash(key, tcb_table->capacity);
    tcb_entry_t *entry = tcb_table->entries[index];
    tcb_entry_t *prev = NULL;
    while (entry != NULL) {
        if (tcb_key_compare(key, &entry->key)) {
            if (prev != NULL) {
                prev->next = entry->next;
            }
            free(entry);
            return true;
        }
        entry = entry->next;
        prev = entry;
    }
    return false;
}

void tcb_table_destroy(tcb_table_t *tcb_table) {
    if (tcb_table == NULL) {
        return;
    }

    for (int i = 0; i < (int)tcb_table->capacity; i++) {
        tcb_entry_t *entry = tcb_table->entries[i];
        while (entry != NULL) {
            tcb_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
    }

    free(tcb_table->entries);
    free(tcb_table);
}

void tcb_table_print(tcb_table_t *tcb_table) {
    printf("=== TCB Table ===\n");
    for (int i = 0; i < (int)tcb_table->capacity; i++) {
        tcb_entry_t *entry = tcb_table->entries[i];
        if (entry != NULL) {
            printf("  %d  ", i);
            while (entry != NULL) {
                printf(" -> %d", entry->value);
                entry = entry->next;
            }
            printf("\n");
        }
    }
}
