#include "tcp/tcb_table.h"
#include "tcp/types.h"
#include "test.h"

/**
 * @file tcb_table_test.c
 */

void test_tcb_table_init(void) {
    TCB_Table *tb = TCB_Table_Create();

    ASSERT(tb);

    ASSERT(tb->capacity > 0);

    TCB_Table_Free(tb);
}

void test_tcb_table_set(void) {
    TCB_Table *tb = TCB_Table_Create();

    TCB_Key key = {
        .s_addr = 0,
        .s_port = 0,
        .d_addr = 0,
        .d_port = 0,
    };

    TCB tcb = {};

    TCB_Table_Set(tb, &key, &tcb);

    TCB_Table_Print(tb);

    tcb.state = TCP_STATE_ESTABLISHED;
    TCB_Table_Set(tb, &key, &tcb);

    TCB_Table_Print(tb);

    // @todo add assertions

    TCB_Table_Free(tb);
}

// @todo implement
void test_tcb_table_get(void) {}

// @todo implement
void test_tcb_table_delete(void) {}

// @todo implement
void test_tcb_table_collision_set(void) {}

// @todo implement
void test_tcb_table_collision_get(void) {}

// @todo implement
void test_tcb_table_collision_delete(void) {}
