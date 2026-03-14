#include "tcp/tcb_table.h"
#include "tcp/types.h"
#include "test.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

/**
 * @file tcb_table_test.c
 */

/**
 * @brief Test CRUD operations on a TCB table
 *
 * Test setting, getting, updating, and deleting records from a TCB table
 */
void Test_TCB_Table_CRUD(void) {
    TCB_Table *table = TCB_Table_Create();
    ASSERT(table);

    in_addr_t src_addr = inet_addr("192.168.100.53");
    uint16_t src_port = 1111;
    in_addr_t dest_addr = inet_addr("192.168.100.52");
    uint16_t dest_port = 2222;

    TCB_Key key = {
        .s_addr = src_addr,
        .s_port = src_port,
        .d_addr = dest_addr,
        .d_port = dest_port,
    };
    TCB tcb = {
        .state = TCP_STATE_LISTEN,
    };

    TCB_Table_Set(table, &key, &tcb);

    ASSERT_EQ(TCB_Table_Get(table, &key)->state, TCP_STATE_LISTEN);

    tcb.state = TCP_STATE_CLOSED;
    TCB_Table_Set(table, &key, &tcb);

    ASSERT_EQ(TCB_Table_Get(table, &key)->state, TCP_STATE_CLOSED);

    ASSERT(TCB_Table_Delete(table, &key));
    ASSERT_EQ(TCB_Table_Get(table, &key), NULL);

    TCB_Table_Free(table);
}

/**
 * @brief Test CRUD operations on a TCB table on key collisions
 *
 * Test setting, getting, updating, and deleting records from a TCB table
 * where two keys collide
 */
void Test_TCB_Table_Collision_CRUD(void) {
    // create small table to force collions
    TCB_Table *table = calloc(1, sizeof(TCB_Table));
    table->capacity = 1;
    table->entries = calloc(table->capacity, sizeof(TCB_Entry *));

    ASSERT(table);

    // insert the first item
    in_addr_t src_addr_1 = inet_addr("192.168.100.53");
    uint16_t src_port_1 = 1111;
    in_addr_t dest_addr_1 = inet_addr("192.168.100.52");
    uint16_t dest_port_1 = 2222;

    TCB_Key key_1 = {
        .s_addr = src_addr_1,
        .s_port = src_port_1,
        .d_addr = dest_addr_1,
        .d_port = dest_port_1,
    };
    TCB tcb_1 = {
        .state = TCP_STATE_LISTEN,
    };

    TCB_Table_Set(table, &key_1, &tcb_1);

    ASSERT_EQ(TCB_Table_Get(table, &key_1)->state, TCP_STATE_LISTEN);

    // insert the second item
    in_addr_t src_addr_2 = inet_addr("192.168.100.63");
    uint16_t src_port_2 = 1111;
    in_addr_t dest_addr_2 = inet_addr("192.168.100.62");
    uint16_t dest_port_2 = 2222;

    TCB_Key key_2 = {
        .s_addr = src_addr_2,
        .s_port = src_port_2,
        .d_addr = dest_addr_2,
        .d_port = dest_port_2,
    };
    TCB tcb_2 = {
        .state = TCP_STATE_ESTABLISHED,
    };

    TCB_Table_Set(table, &key_2, &tcb_2);

    ASSERT_EQ(TCB_Table_Get(table, &key_1)->state, TCP_STATE_LISTEN);
    ASSERT_EQ(TCB_Table_Get(table, &key_2)->state, TCP_STATE_ESTABLISHED);

    // make sure you can still update items
    tcb_1.state = TCP_STATE_FIN_WAIT_1;
    TCB_Table_Set(table, &key_1, &tcb_1);
    tcb_2.state = TCP_STATE_FIN_WAIT_2;
    TCB_Table_Set(table, &key_2, &tcb_2);

    ASSERT_EQ(TCB_Table_Get(table, &key_1)->state, TCP_STATE_FIN_WAIT_1);
    ASSERT_EQ(TCB_Table_Get(table, &key_2)->state, TCP_STATE_FIN_WAIT_2);

    // make sure you can delete the first item in a bucket
    ASSERT(TCB_Table_Delete(table, &key_1));
    ASSERT_EQ(TCB_Table_Get(table, &key_1), NULL);
    ASSERT_NEQ(TCB_Table_Get(table, &key_2), NULL);

    // make sure you can delete the last item in a bucket
    TCB_Table_Set(table, &key_1, &tcb_1);

    ASSERT(TCB_Table_Delete(table, &key_2));
    ASSERT_EQ(TCB_Table_Get(table, &key_2), NULL);
    ASSERT_NEQ(TCB_Table_Get(table, &key_1), NULL);

    // make sure you can delete items in the middle of a bucket
    TCB_Table_Set(table, &key_2, &tcb_2);

    // insert the second item
    in_addr_t src_addr_3 = inet_addr("192.168.100.73");
    uint16_t src_port_3 = 1111;
    in_addr_t dest_addr_3 = inet_addr("192.168.100.72");
    uint16_t dest_port_3 = 2222;

    TCB_Key key_3 = {
        .s_addr = src_addr_3,
        .s_port = src_port_3,
        .d_addr = dest_addr_3,
        .d_port = dest_port_3,
    };
    TCB tcb_3 = {
        .state = TCP_STATE_LAST_ACK,
    };

    TCB_Table_Set(table, &key_3, &tcb_3);
    ASSERT_EQ(TCB_Table_Get(table, &key_3)->state, TCP_STATE_LAST_ACK);

    ASSERT(TCB_Table_Delete(table, &key_2));
    ASSERT_EQ(TCB_Table_Get(table, &key_2), NULL);
    ASSERT_NEQ(TCB_Table_Get(table, &key_1), NULL);
    ASSERT_NEQ(TCB_Table_Get(table, &key_3), NULL);

    TCB_Table_Free(table);
}
