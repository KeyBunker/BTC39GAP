/* --small executes the real derivation function against fixed vectors, with
 * only Argon2's memory cost changed in this test wrapper. With no arguments,
 * two actual 8-GiB derivations inspect every arena byte before OS release. */
#ifndef _WIN32
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif
#include "test_common.h"
#include "../argon2.h"
#include <setjmp.h>
#include <stdarg.h>
static int checked_argon2id_ctx(argon2_context *);
static _Noreturn void expected_exit(int);
static int capture_printf(const char *, ...);
static int capture_fprintf(FILE *, const char *, ...);
static int capture_fputs(const char *, FILE *);
static int capture_fputc(int, FILE *);
#define argon2id_ctx checked_argon2id_ctx
#define exit expected_exit
#define printf capture_printf
#define fprintf capture_fprintf
#define fputs capture_fputs
#define fputc capture_fputc
#include "test_memory.h"
#undef argon2id_ctx
#undef exit
#undef printf
#undef fprintf
#undef fputs
#undef fputc

static int small_mode, expect_failure, exit_code, cancel_after_argon;
static unsigned argon_calls;
static jmp_buf failure_jump;
/* Static storage keeps outputs well-defined after longjmp from an expected die. */
static char primary[sizeof("public test phrase 12345")];
static uint8_t entropy[32], fingerprint[8];
static char transcript[8192];
static size_t transcript_length;

/* Capture only application output; CHECK diagnostics still use real stderr.
 * This also checks that 100% is printed only after verified memory release. */
static int capture_format(const char *format, va_list args) {
    size_t available = sizeof(transcript) - transcript_length;
    int written = vsnprintf(transcript + transcript_length, available, format, args);
    CHECK(written >= 0 && (size_t)written < available);
    if (strstr(transcript + transcript_length, "100%") != NULL)
        check_released(memory_probe.bytes);
    transcript_length += (size_t)written;
    return written;
}
static int capture_printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    int written = capture_format(format, args);
    va_end(args);
    return written;
}
static int capture_fprintf(FILE *stream, const char *format, ...) {
    (void)stream;
    va_list args;
    va_start(args, format);
    int written = capture_format(format, args);
    va_end(args);
    return written;
}
static int capture_fputs(const char *value, FILE *stream) {
    (void)stream;
    return capture_printf("%s", value);
}
static int capture_fputc(int value, FILE *stream) {
    (void)stream;
    (void)capture_printf("%c", value);
    return (unsigned char)value;
}

static _Noreturn void expected_exit(int status) {
    if (!expect_failure) fputs(transcript, stderr);
    CHECK(expect_failure);
    exit_code = status;
    longjmp(failure_jump, 1);
}

static int checked_argon2id_ctx(argon2_context *a2) {
    argon_calls++;
    /* Validate the application's configuration BEFORE the test-only override. */
    CHECK(a2->m_cost == 8388608U && a2->t_cost == 3U);
    CHECK(a2->lanes == 4U && a2->threads == 4U);
    CHECK(a2->version == ARGON2_VERSION_13);
    CHECK(a2->outlen == 64U && a2->pwdlen == strlen("public test phrase 12345"));
    CHECK(a2->pwd == (uint8_t *)primary);
    CHECK(a2->saltlen == sizeof(expected_derivation_context));
    CHECK(memcmp(a2->salt, expected_derivation_context, a2->saltlen) == 0);
    CHECK(a2->adlen == sizeof(expected_ad) && memcmp(a2->ad, expected_ad, a2->adlen) == 0);
    CHECK(a2->secret == NULL && a2->secretlen == 0U);
    CHECK(a2->flags == ARGON2_FLAG_CLEAR_PASSWORD);
    CHECK(a2->allocate_cbk == secure_argon_alloc && a2->free_cbk == secure_argon_free);

    argon2_context actual = *a2;
    if (small_mode) actual.m_cost = 32U;
    int result = argon2id_ctx(&actual);
    if (result == ARGON2_OK && small_mode) {
        CHECK(memcmp(a2->out, expected_test_master, a2->outlen) == 0);
    }
    if (cancel_after_argon) request_stop(SIGINT);
    return result;
}

static void run_derivation(int clear_flag, int allocation_failure, int cancellation) {
    recovery_context recovery = {"van dijk", "de vries"};
    uint8_t digest[32];
    int saved_flag = FLAG_clear_internal_memory;
    reset_memory_probe();
    memory_probe.fail_map = allocation_failure;
    stop_requested = 0;
    argon_calls = 0U;
    cancel_after_argon = cancellation;
    expect_failure = allocation_failure || cancellation;
    exit_code = EXIT_SUCCESS;
    transcript_length = 0U;
    transcript[0] = '\0';
    memcpy(primary, "public test phrase 12345", sizeof(primary));
    memset(entropy, 0xa5, sizeof(entropy));
    memset(fingerprint, 0xa5, sizeof(fingerprint));
    build_recovery_context_digest(&recovery, digest);
    CHECK(memcmp(digest, expected_context, sizeof(digest)) == 0);
    FLAG_clear_internal_memory = clear_flag;

    if (setjmp(failure_jump) == 0) {
        derive_bip39_entropy(primary, strlen(primary), digest, 42U, entropy, fingerprint);
        CHECK(!expect_failure);
    } else {
        CHECK(expect_failure && exit_code == EXIT_FAILURE);
    }
    FLAG_clear_internal_memory = saved_flag;
    expect_failure = 0;
    stop_requested = 0;
    CHECK(argon_calls == 1U && memory_probe.map_calls == 1U);
    CHECK(bytes_are(primary, sizeof(primary), 0U));
    CHECK(bytes_are(&post_workspace, sizeof(post_workspace), 0U));
    size_t expected_bytes = small_mode ? 32768U : (size_t)(UINT64_C(8) << 30);
    CHECK(memory_probe.requested_bytes == expected_bytes);
    if (allocation_failure) {
        CHECK(strstr(transcript, "cannot allocate memory") != NULL);
        CHECK(memory_probe.lock_calls == 0U && memory_probe.release_calls == 0U);
        CHECK(bytes_are(entropy, sizeof(entropy), 0xa5));
        CHECK(bytes_are(fingerprint, sizeof(fingerprint), 0xa5));
    } else {
        check_released(expected_bytes);
        if (cancellation) {
            CHECK(strstr(transcript, "cancelled") != NULL);
            CHECK(bytes_are(entropy, sizeof(entropy), 0U));
            CHECK(bytes_are(fingerprint, sizeof(fingerprint), 0U));
        } else if (small_mode) {
            CHECK(memcmp(entropy, expected_test_entropy, sizeof(entropy)) == 0);
            CHECK(memcmp(fingerprint, expected_test_fp, sizeof(fingerprint)) == 0);
        } else {
            CHECK(!bytes_are(entropy, sizeof(entropy), 0U));
        }
    }
    CHECK((strstr(transcript, "100%") != NULL) == !(allocation_failure || cancellation));
}

int main(int argc, char **argv) {
    small_mode = argc == 2 && (strcmp(argv[1], "--small") == 0 ||
                               strcmp(argv[1], "--harness-check") == 0);
    if (argc != 1 && !small_mode) {
        fprintf(stderr, "Usage: %s [--small]\n", argv[0]);
        return EXIT_FAILURE;
    }
    CHECK((size_t)ARGON2_MEMORY_KIB * 1024U == (UINT64_C(8) << 30));
    puts(small_mode ?
        "Integration tests: production parameters checked; actual Argon2 uses 32 KiB in the test wrapper." :
        "Full tests: two actual 8-GiB derivations with PUBLIC dummy inputs and complete wipe inspection.");
    uint8_t first_entropy[32], first_fingerprint[8];
    test_case = "derivation with Argon2 internal wipe disabled";
    run_derivation(0, 0, 0);
    memcpy(first_entropy, entropy, sizeof(entropy));
    memcpy(first_fingerprint, fingerprint, sizeof(fingerprint));
    test_case = "derivation with Argon2 internal wipe enabled";
    run_derivation(1, 0, 0);
    CHECK(memcmp(first_entropy, entropy, sizeof(entropy)) == 0);
    CHECK(memcmp(first_fingerprint, fingerprint, sizeof(fingerprint)) == 0);
    if (small_mode) {
        test_case = "expected allocation error clears primary input";
        run_derivation(0, 1, 0);
        test_case = "expected cancellation clears output and primary input";
        run_derivation(0, 0, 1);
    }
    puts(small_mode ?
        "Integration tests passed (fixed vectors, configuration, complete wipe, allocation error and cancellation)." :
        "Full tests passed (all 8 GiB verified zero before unlock and release, with identical outputs).");
    return EXIT_SUCCESS;
}
