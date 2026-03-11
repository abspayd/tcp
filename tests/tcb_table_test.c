#include "tcp/tcb_table.h"
#include "test.h"

void test_tcb_table_init(void) { ASSERT(0); }

void test_tcb_table_hash(void) {
    TCB_Key key = {
        .s_addr = 1,
        .s_port = 1200,
        .d_port = 3000,
        .d_addr = 2,
    };

    // TODO: fix function mapping (tests aren't building object files)
    uint64_t hash = TCB_Hash(&key, 100);
    ASSERT(hash);
}
