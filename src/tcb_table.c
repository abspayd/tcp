#include "tcp/tcb_table.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FNV_PRIME 1099511628211ULL
#define FNV_OFFSET_BASIS 14695981039346656037ULL

// Hash using the FNV-1a hashing technique
// See: http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-1a
static uint64_t TCB_Hash(TCB_Key *key, size_t capacity) {
    uint8_t *data = (uint8_t *)key;
    size_t key_length = sizeof(TCB_Key) / sizeof(uint8_t);

    uint64_t hash = FNV_OFFSET_BASIS;
    for (size_t i = 0; i < key_length; i++) {
        hash ^= data[i];
        hash *= FNV_PRIME;
    }

    return hash & (capacity - 1);
}

static bool TCB_Key_Compare(TCB_Key *k1, TCB_Key *k2) {
    return (k1->s_addr == k2->s_addr && k1->s_port == k2->s_port && k1->d_addr == k2->d_addr &&
            k1->d_port == k2->d_port);
}

TCB_Table *TCB_Table_Create() {
    TCB_Table *table = malloc(sizeof(TCB_Table));
    memset(table, 0, sizeof(TCB_Table));

    table->capacity = TCB_TABLE_DEFAULT_CAPACITY;

    table->entries = malloc(sizeof(TCB_Entry *) * TCB_TABLE_DEFAULT_CAPACITY);
    memset(table->entries, 0, sizeof(TCB_Entry *) * TCB_TABLE_DEFAULT_CAPACITY);

    return table;
}

void TCB_Table_Set(TCB_Table *tcb_table, TCB_Key *key, TCB *tcb) {
    uint64_t hash = TCB_Hash(key, tcb_table->capacity);

    TCB_Entry *prev = NULL;
    TCB_Entry *entry = tcb_table->entries[hash];
    while (entry != NULL) {
        if (TCB_Key_Compare(key, &entry->key)) {
            entry->tcb = *tcb;
            return;
        }
        prev = entry;
        entry = entry->next;
    }

    TCB_Entry *new_entry = malloc(sizeof(TCB_Entry));

    new_entry->key = *key;
    new_entry->tcb = *tcb;
    new_entry->next = NULL;

    if (prev != NULL) {
        prev->next = new_entry;
    } else {
        tcb_table->entries[hash] = new_entry;
    }
}

TCB *TCB_Table_Get(TCB_Table *tcb_table, TCB_Key *key) {
    uint64_t hash = TCB_Hash(key, tcb_table->capacity);

    TCB_Entry *entry = tcb_table->entries[hash];
    while (entry != NULL) {
        if (TCB_Key_Compare(key, &entry->key)) {
            return &entry->tcb;
        }
        entry = entry->next;
    }

    return NULL;
}

bool TCB_Table_Delete(TCB_Table *tcb_table, TCB_Key *key) {
    if (tcb_table == NULL || key == NULL) {
        return false;
    }

    int index = TCB_Hash(key, tcb_table->capacity);
    TCB_Entry *entry = tcb_table->entries[index];
    TCB_Entry *prev = NULL;
    while (entry != NULL) {
        if (TCB_Key_Compare(key, &entry->key)) {
            if (prev != NULL) {
                prev->next = entry->next;
            } else {
                tcb_table->entries[index] = entry->next;
            }
            free(entry);
            return true;
        }
        prev = entry;
        entry = entry->next;
    }
    return false;
}

void TCB_Table_Free(TCB_Table *tcb_table) {
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

void TCB_Table_Print(TCB_Table *tcb_table) {
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
