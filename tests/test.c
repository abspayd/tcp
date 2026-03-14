/**
 * @file test.c
 */
#include "test.h"

int main(void) {
    test_t test_map[] = {
        // TCB Table
        {.name = "test_tcb_table_crud", .fn = test_tcb_table_crud},
        {.name = "test_tcb_table_collision_crud", .fn = test_tcb_table_collision_crud},

        // TCP
        {.name = "test_tcp_header_flags", .fn = test_tcp_header_flags},
    };

    int num_tests = sizeof(test_map) / sizeof(test_t);

    for (int i = 0; i < num_tests; i++) {
        test_t test = test_map[i];
        printf("Running test \"%s\"...\n", test.name);
        test_map[i].fn();
    }

    return 0;
}
