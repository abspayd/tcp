/**
 * @file test.c
 */
#include "test.h"

int main(void) {
    Test_Registry test_map[] = {
        // TCB Table
        {.name = "test_tcb_table_crud", .fn = Test_TCB_Table_CRUD},
        {.name = "test_tcb_table_collision_crud", .fn = Test_TCB_Table_Collision_CRUD},

        // TCP
        {.name = "test_tcp_header_flags", .fn = Test_TCP_Header_Flags},
    };

    int num_tests = sizeof(test_map) / sizeof(Test_Registry);

    for (int i = 0; i < num_tests; i++) {
        Test_Registry test = test_map[i];
        printf("Running test \"%s\"...\n", test.name);
        test_map[i].fn();
    }

    return 0;
}
