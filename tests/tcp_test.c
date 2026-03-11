#include "tcp/tcp.h"
#include "test.h"

#include <stdbool.h>

void test_tcp_header_flags(void) {

    ASSERT_EQ((TCP_OFFSET(0xF000)), 0x000F);
    ASSERT_EQ(TCP_CWR(0x0080), 1);
    ASSERT_EQ(TCP_ECE(0x0040), 1);
    ASSERT_EQ(TCP_URG(0x0020), 1);
    ASSERT_EQ(TCP_ACK(0x0010), 1);
    ASSERT_EQ(TCP_PSH(0x0008), 1);
    ASSERT_EQ(TCP_RST(0x0004), 1);
    ASSERT_EQ(TCP_SYN(0x0002), 1);
    ASSERT_EQ(TCP_FIN(0x0001), 1);

    // TODO: fix function mapping (tests aren't building object files)
    TCP_Unwrap_Packet(0, 0, 0);
}
