#include "tcb_table.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int tcb_hash(TCB_Key *key, size_t capacity) {
    return (key->s_addr + key->s_port + key->d_addr + key->d_port) % capacity;
}

bool tcb_key_compare(TCB_Key *k1, TCB_Key *k2) {
    return (k1->s_addr == k2->s_addr && k1->s_port == k2->s_port && k1->d_addr == k2->d_addr &&
            k1->d_port == k2->d_port);
}

TCB_Table *TCB_Table_Create(size_t capacity) {
    TCB_Table *table = malloc(sizeof(TCB_Table));
    memset(table, 0, sizeof(TCB_Table));

    table->capacity = capacity;

    table->entries = malloc(sizeof(TCB_Entry) * capacity);
    memset(table->entries, 0, sizeof(TCB_Entry) * capacity);

    return table;
}

bool tcb_table_set(TCB_Table *tcb_table, TCB_Key *key, struct TCB *tcb) {
    // TODO: FNV-1a
    // http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-1a
    return false;
}

bool tcb_table_set_state(TCB_Table *tcb_table, TCB_Key *key, enum TCP_State state) {
    if (tcb_table == NULL || key == NULL || tcb_table->entries == NULL) {
        return false;
    }
    int index = tcb_hash(key, tcb_table->capacity);
    TCB_Entry *entry = tcb_table->entries[index];
    while (entry != NULL && entry->next != NULL) {
        if (tcb_key_compare(key, &entry->key)) {
            // update existing tcb entry
            entry->tcb.state = state;
            return true;
        }
        entry = entry->next;
    }

    TCB_Entry *new_entry = malloc(sizeof(TCB_Entry));
    new_entry->key = *key;
    new_entry->tcb.state = state;
    new_entry->next = NULL;

    if (entry != NULL) {
        entry->next = new_entry;
    } else {
        tcb_table->entries[index] = new_entry;
    }

    return true;
}

enum TCP_State tcb_table_get_state(TCB_Table *tcb_table, TCB_Key *key) {
    if (tcb_table == NULL || key == NULL) {
        return TCP_STATE_CLOSED;
    }

    int index = tcb_hash(key, tcb_table->capacity);
    TCB_Entry *entry = tcb_table->entries[index];
    while (entry != NULL) {
        if (tcb_key_compare(key, &entry->key)) {
            return entry->tcb.state;
        }
        entry = entry->next;
    }
    return TCP_STATE_CLOSED;
}

bool tcb_table_delete(TCB_Table *tcb_table, TCB_Key *key) {
    if (tcb_table == NULL || key == NULL) {
        return false;
    }

    int index = tcb_hash(key, tcb_table->capacity);
    TCB_Entry *entry = tcb_table->entries[index];
    TCB_Entry *prev = NULL;
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

void tcb_table_destroy(TCB_Table *tcb_table) {
    if (tcb_table == NULL) {
        return;
    }

    for (int i = 0; i < (int)tcb_table->capacity; i++) {
        TCB_Entry *entry = tcb_table->entries[i];
        while (entry != NULL) {
            TCB_Entry *next = entry->next;
            free(entry);
            entry = next;
        }
    }

    free(tcb_table->entries);
    free(tcb_table);
}

void tcb_table_print(TCB_Table *tcb_table) {
    printf("=== TCB Table ===\n");
    for (int i = 0; i < (int)tcb_table->capacity; i++) {
        TCB_Entry *entry = tcb_table->entries[i];
        if (entry != NULL) {
            printf("  %d  ", i);
            while (entry != NULL) {
                printf(" -> %d", entry->tcb.state);
                entry = entry->next;
            }
            printf("\n");
        }
    }
}
