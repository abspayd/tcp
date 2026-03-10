#include "tcp/tcb_table.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int TCB_Hash(TCB_Key *key, size_t capacity) {
    return (key->s_addr + key->s_port + key->d_addr + key->d_port) % capacity;
}

static bool TCB_Key_Compare(TCB_Key *k1, TCB_Key *k2) {
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

bool TCB_Table_Set(TCB_Table *tcb_table, TCB_Key *key, struct TCB *tcb) {
    // TODO: FNV-1a
    // http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-1a
    return false;
}

bool TCB_Table_Set_State(TCB_Table *tcb_table, TCB_Key *key, enum TCP_State state) {
    if (tcb_table == NULL || key == NULL || tcb_table->entries == NULL) {
        return false;
    }
    int index = TCB_Hash(key, tcb_table->capacity);
    TCB_Entry *entry = tcb_table->entries[index];
    while (entry != NULL && entry->next != NULL) {
        if (TCB_Key_Compare(key, &entry->key)) {
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

enum TCP_State TCB_Table_Get_State(TCB_Table *tcb_table, TCB_Key *key) {
    if (tcb_table == NULL || key == NULL) {
        return TCP_STATE_CLOSED;
    }

    int index = TCB_Hash(key, tcb_table->capacity);
    TCB_Entry *entry = tcb_table->entries[index];
    while (entry != NULL) {
        if (TCB_Key_Compare(key, &entry->key)) {
            return entry->tcb.state;
        }
        entry = entry->next;
    }
    return TCP_STATE_CLOSED;
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
            }
            free(entry);
            return true;
        }
        entry = entry->next;
        prev = entry;
    }
    return false;
}

void TCB_Table_Destroy(TCB_Table *tcb_table) {
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
