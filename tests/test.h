#ifndef TEST_H_INCLUDED
#define TEST_H_INCLUDED

#include <stdio.h>

#define WHITE "\033[0;37m"
#define RED "\033[0;31m"
#define GREEN "\033[0;32m"

typedef void (*test_fn)(void);

typedef struct {
    const char *name;
    test_fn fn;
} test_t;

#define ASSERT(condition)                                                                                              \
    do {                                                                                                               \
        if (!(condition)) {                                                                                            \
            printf("%sFAIL%s: %s (%s:%d)\n", RED, WHITE, #condition, __FILE_NAME__, __LINE__);                         \
        } else {                                                                                                       \
            printf("%sPASS%s (%s:%d)\n", GREEN, WHITE, __FILE_NAME__, __LINE__);                                       \
        }                                                                                                              \
    } while (0)

#define ASSERT_EQ(a, b) ASSERT((a) == (b))
#define ASSERT_NEQ(a, b) ASSERT((a) != (b))
#define ASSERT_GT(a, b) ASSERT((a) > (b))
#define ASSERT_GTE(a, b) ASSERT((a) >= (b))
#define ASSERT_LT(a, b) ASSERT((a) < (b))
#define ASSERT_LTE(a, b) ASSERT((a) <= (b))

/* === TEST FUNCTIONS === */

// TCP tests
extern void test_tcb_table_init(void);

// TCB tests
extern void test_tcp_header_flags(void);

#endif
