/**
 * @file test.c
 */
#include "test.h"

int main(void) {
    test_t test_map[] = {
        // TCB Table
        {.name = "test_tcb_table_init", .fn = test_tcb_table_init},
        {.name = "test_tcb_table_set", .fn = test_tcb_table_set},
        {.name = "test_tcb_table_get", .fn = test_tcb_table_get},
        {.name = "test_tcb_table_delete", .fn = test_tcb_table_delete},
        {.name = "test_tcb_table_collision_set", .fn = test_tcb_table_collision_set},
        {.name = "test_tcb_table_collision_get", .fn = test_tcb_table_collision_get},
        {.name = "test_tcb_table_collision_delete", .fn = test_tcb_table_collision_delete},

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
