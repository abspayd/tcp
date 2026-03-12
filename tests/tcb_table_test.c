#include "tcp/tcb_table.h"
#include "test.h"

void test_tcb_table_init(void) { ASSERT(0); }

void test_tcb_table_hash(void) {
    TCB_Key key = {
        .s_addr = 1,
        .s_port = 0,
        .d_port = 0,
        .d_addr = 0,
    };

    // TODO: fix function mapping (tests aren't building object files)
    uint64_t hash = TCB_Hash(&key, 4096);
    printf("hash: 0x%016lX\n", hash);
    ASSERT(hash);
}
