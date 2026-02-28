#include "test.h"

int main(void) {
    test_t tests[] = {
        {.name = "test_init", .fn = test_tcb_table_init},
        {.name = "Test TCP header flags", .fn = test_tcp_header_flags},
    };

    int num_tests = sizeof(tests) / sizeof(test_t);

    for (int i = 0; i < num_tests; i++) {
        test_t test = tests[i];
        printf("Running test \"%s\"...\n", test.name);
        tests[i].fn();
    }

    return 0;
}
