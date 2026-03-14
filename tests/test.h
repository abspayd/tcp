#ifndef TEST_H_INCLUDED
#define TEST_H_INCLUDED

/**
 * @file test.h
 */

#include <stdio.h>

#define WHITE "\033[0;37m"
#define STRONG_WHITE "\033[0;97m"
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
            printf(" %s(%s:%d) %sFAIL%s:\n    %s\n", WHITE, __FILE_NAME__, __LINE__, RED, STRONG_WHITE, #condition);   \
        } else {                                                                                                       \
            printf(" %s(%s:%d) %sPASS%s\n", WHITE, __FILE_NAME__, __LINE__, GREEN, STRONG_WHITE);                      \
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
extern void test_tcp_header_flags(void);

// TCB tests
extern void test_tcb_table_crud(void);
extern void test_tcb_table_collision_crud(void);

#endif
