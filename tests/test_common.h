#ifndef BTC39GAP_TEST_COMMON_H
#define BTC39GAP_TEST_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static const char *test_case = "setup";

/* Keep checks active with NDEBUG and outside test-local exit interception. */
static void test_fail(const char *file, int line, const char *condition) {
    fprintf(stderr, "%s:%d [%s]: check failed: %s\n", file, line, test_case, condition);
    exit(EXIT_FAILURE);
}

#define CHECK(condition) do { \
    if (!(condition)) { \
        test_fail(__FILE__, __LINE__, #condition); \
    } \
} while (0)

static int bytes_are(const void *data, size_t length, uint8_t value) {
    const uint8_t *bytes = (const uint8_t *)data;
    for (size_t i = 0U; i < length; i++) {
        if (bytes[i] != value) return 0;
    }
    return 1;
}

#endif
