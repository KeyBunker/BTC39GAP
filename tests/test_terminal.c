/* C-only input and terminal-state tests. Mock just the platform console calls
 * so the same tests also run unattended, without a PTY or a Windows console. */
#ifndef _WIN32
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif
#include "test_common.h"
static unsigned terminal_mask = 7U;
static int fail_get_mode, fail_set_mode;
static int cancel_at_character = -1, characters_read;
static int checked_fgetc(FILE *input);
static unsigned set_calls, flush_calls;
#ifdef _WIN32
#include <windows.h>
static DWORD terminal_mode;
static HANDLE WINAPI fake_std_handle(DWORD which) {
    if (which == STD_INPUT_HANDLE) return (HANDLE)(uintptr_t)1U;
    if (which == STD_OUTPUT_HANDLE) return (HANDLE)(uintptr_t)2U;
    if (which == STD_ERROR_HANDLE) return (HANDLE)(uintptr_t)3U;
    return INVALID_HANDLE_VALUE;
}
static BOOL WINAPI fake_get_mode(HANDLE handle, LPDWORD mode) {
    uintptr_t index = (uintptr_t)handle;
    if (index < 1U || index > 3U || !(terminal_mask & (1U << (index - 1U))) || fail_get_mode)
        return FALSE;
    *mode = terminal_mode;
    return TRUE;
}
static BOOL WINAPI fake_set_mode(HANDLE handle, DWORD mode) {
    CHECK(handle == fake_std_handle(STD_INPUT_HANDLE));
    set_calls++;
    if (fail_set_mode) return FALSE;
    terminal_mode = mode;
    return TRUE;
}
static BOOL WINAPI fake_flush(HANDLE handle) {
    CHECK(handle == fake_std_handle(STD_INPUT_HANDLE));
    flush_calls++;
    return TRUE;
}
#define GetStdHandle fake_std_handle
#define GetConsoleMode fake_get_mode
#define SetConsoleMode fake_set_mode
#define FlushConsoleInputBuffer fake_flush
#else
#include <unistd.h>
#include <termios.h>
static struct termios terminal_mode;
static int fake_isatty(int fd) {
    return fd >= 0 && fd < 3 && (terminal_mask & (1U << (unsigned)fd)) != 0U;
}
static int fake_get_mode(int fd, struct termios *mode) {
    CHECK(fd == STDIN_FILENO);
    if (fail_get_mode) return -1;
    *mode = terminal_mode;
    return 0;
}
static int fake_set_mode(int fd, int action, const struct termios *mode) {
    CHECK(fd == STDIN_FILENO && action == TCSANOW);
    set_calls++;
    if (fail_set_mode) return -1;
    terminal_mode = *mode;
    return 0;
}
static int fake_flush(int fd, int queue) {
    CHECK(fd == STDIN_FILENO && queue == TCIFLUSH);
    flush_calls++;
    return 0;
}
#define isatty fake_isatty
#define tcgetattr fake_get_mode
#define tcsetattr fake_set_mode
#define tcflush fake_flush
#endif
#define fgetc checked_fgetc
#define main btc39gap_application_main
#include "../BTC39GAP.c"
#undef main
#undef fgetc
#ifdef _WIN32
#undef GetStdHandle
#undef GetConsoleMode
#undef SetConsoleMode
#undef FlushConsoleInputBuffer
#else
#undef isatty
#undef tcgetattr
#undef tcsetattr
#undef tcflush
#endif

static int checked_fgetc(FILE *input) {
    int ch = fgetc(input);
    if (characters_read++ == cancel_at_character) request_stop(SIGINT);
    return ch;
}

static void test_terminal_restore(void) {
    test_case = "terminal mode restoration and redirected streams";
    for (int cancelled = 0; cancelled <= 1; cancelled++) {
        stop_requested = 0;
        set_calls = flush_calls = 0U;
#ifdef _WIN32
        terminal_mode = ENABLE_PROCESSED_INPUT;
        DWORD original = terminal_mode;
#else
        memset(&terminal_mode, 0, sizeof(terminal_mode));
        terminal_mode.c_lflag = ISIG;
        tcflag_t original = terminal_mode.c_lflag;
#endif
        CHECK(interactive_terminal_available());
        CHECK(enable_terminal_echo());
#ifdef _WIN32
        CHECK(terminal_mode == (original | ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT));
#else
        CHECK(terminal_mode.c_lflag == (original | ECHO | ICANON | ISIG));
#endif
        stop_requested = cancelled;
        restore_terminal_echo();
        CHECK(set_calls == 2U && flush_calls == (unsigned)cancelled);
#ifdef _WIN32
        CHECK(terminal_mode == original && input_mode_saved == 0);
#else
        CHECK(terminal_mode.c_lflag == original && termios_saved == 0);
#endif
        restore_terminal_echo();
        CHECK(set_calls == 2U && flush_calls == (unsigned)cancelled);
    }
    stop_requested = 0;
    for (unsigned stream = 0U; stream < 3U; stream++) {
        terminal_mask = 7U & ~(1U << stream);
        CHECK(!interactive_terminal_available());
        if (stream == 0U) CHECK(!enable_terminal_echo());
    }
    terminal_mask = 7U;
    fail_get_mode = 1;
    CHECK(!enable_terminal_echo());
    fail_get_mode = 0;
    fail_set_mode = 1;
    CHECK(!enable_terminal_echo());
    fail_set_mode = 0;
    unsigned previous = set_calls;
    restore_terminal_echo();
    CHECK(set_calls == previous);
}

static FILE *input_stream(const void *data, size_t length) {
    FILE *input = tmpfile();
    CHECK(input != NULL);
    CHECK(fwrite(data, 1U, length, input) == length);
    rewind(input);
    return input;
}

static void test_lines(void) {
    test_case = "line overflow, EOF, invalid input and cancellation";
    static const unsigned char data[] = {
        'a','b','c','\n', '1','2','3','4','5','6','7','8','\n',
        'o','k','\n', 'a',0,'b','\n', 0x80,'\n', '\n', 'e','n','d'
    };
    char out[8];
    FILE *input = input_stream(data, sizeof(data));
    CHECK(read_ascii_line(input, out, sizeof(out)) == 3U);
    CHECK(strcmp(out, "abc") == 0);
    CHECK(bytes_are(out + 3U, sizeof(out) - 3U, 0U));
    CHECK(read_ascii_line(input, out, sizeof(out)) == INPUT_INVALID);
    CHECK(bytes_are(out, sizeof(out), 0U));
    CHECK(read_ascii_line(input, out, sizeof(out)) == 2U);
    CHECK(strcmp(out, "ok") == 0); /* An overlong line was fully consumed. */
    for (unsigned i = 0U; i < 2U; i++) {
        CHECK(read_ascii_line(input, out, sizeof(out)) == INPUT_INVALID);
        CHECK(bytes_are(out, sizeof(out), 0U));
    }
    CHECK(read_ascii_line(input, out, sizeof(out)) == 0U);
    CHECK(bytes_are(out, sizeof(out), 0U));
    CHECK(read_ascii_line(input, out, sizeof(out)) == INPUT_EOF);
    CHECK(bytes_are(out, sizeof(out), 0U));
    CHECK(fclose(input) == 0);

    input = input_stream("1234567\n", 8U);
    CHECK(read_ascii_line(input, out, sizeof(out)) == sizeof(out) - 1U);
    CHECK(strcmp(out, "1234567") == 0);
    stop_requested = 1;
    CHECK(read_ascii_line(input, out, sizeof(out)) == INPUT_EOF);
    CHECK(bytes_are(out, sizeof(out), 0U));
    stop_requested = 0;
    CHECK(fclose(input) == 0);
}

static void test_all_input_bytes(void) {
    test_case = "all 256 byte values in visible input";
    for (unsigned value = 0U; value <= 255U; value++) {
        unsigned char data[2] = {(unsigned char)value, '\n'};
        unsigned char guard[6];
        memset(guard, 0xa5, sizeof(guard));
        FILE *input = input_stream(data, sizeof(data));
        size_t result = read_ascii_line(input, (char *)guard + 1U, 4U);
        CHECK(guard[0] == 0xa5 && guard[5] == 0xa5);
        if (value == '\n') CHECK(result == 0U && bytes_are(guard + 1U, 4U, 0U));
        else if (value >= 0x20U && value <= 0x7eU) {
            CHECK(result == 1U && guard[1] == value && bytes_are(guard + 2U, 3U, 0U));
        } else CHECK(result == INPUT_INVALID && bytes_are(guard + 1U, 4U, 0U));
        CHECK(fclose(input) == 0);
    }
    test_case = "cancellation during input, including the final newline";
    for (int at = 0; at <= 6; at++) {
        FILE *input = input_stream("secret\n", 7U);
        char out[32];
        memset(out, 0xa5, sizeof(out));
        cancel_at_character = at;
        characters_read = 0;
        CHECK(read_ascii_line(input, out, sizeof(out)) == INPUT_EOF);
        CHECK(bytes_are(out, sizeof(out), 0U));
        CHECK(characters_read == at + 1);
        cancel_at_character = -1;
        stop_requested = 0;
        CHECK(fclose(input) == 0);
    }
}

static void test_validation(void) {
    test_case = "wallet, secret and surname validation";
    static const char *invalid_wallets[] = {
        "", "-1", "+1", "1000001", "00000000", "1 ", " 1", "1x", "1\t"
    };
    uint32_t wallet = UINT32_MAX;
    CHECK(parse_wallet_number("0", 1U, &wallet) && wallet == 0U);
    CHECK(parse_wallet_number("1000000", 7U, &wallet) && wallet == 1000000U);
    CHECK(parse_wallet_number("0000042", 7U, &wallet) && wallet == 42U);
    for (size_t i = 0U; i < sizeof(invalid_wallets) / sizeof(invalid_wallets[0]); i++) {
        wallet = UINT32_MAX;
        CHECK(!parse_wallet_number(invalid_wallets[i], strlen(invalid_wallets[i]), &wallet));
        CHECK(wallet == UINT32_MAX);
    }
    char secret[64] = " \tpublic test phrase 12345\r\n ";
    size_t length = trim_secret(secret, strlen(secret), sizeof(secret));
    CHECK(strcmp(secret, "public test phrase 12345") == 0);
    CHECK(bytes_are(secret + length, sizeof(secret) - length, 0U));
    CHECK(valid_secret_value(secret, length, PRIMARY_SECRET_MIN_LEN, PRIMARY_SECRET_MAX_LEN));
    CHECK(!valid_secret_value("short", 5U, PRIMARY_SECRET_MIN_LEN, PRIMARY_SECRET_MAX_LEN));
    CHECK(!valid_secret_value(" \t\r\n", 4U, 1U, PRIMARY_SECRET_MAX_LEN));
    CHECK(!valid_secret_value("bad\033", 4U, 1U, PRIMARY_SECRET_MAX_LEN));
    CHECK(valid_secret_value("line one\nline two", 17U, 1U, PRIMARY_SECRET_MAX_LEN));
    CHECK(secret_is_file_path("/tmp/public.txt", 15U));
    CHECK(secret_is_file_path("./public.txt", 12U));
    CHECK(secret_is_file_path("../public.txt", 13U));
    CHECK(secret_is_file_path("C:\\public.txt", 13U));
    CHECK(secret_is_file_path("\\\\host\\public.txt", 17U));
    CHECK(!secret_is_file_path("public phrase", 13U));
    CHECK(!secret_is_file_path("", 0U));
    CHECK(valid_surname("Van Dijk", 8U));
    CHECK(!valid_surname(" Van Dijk", 9U));
    CHECK(!valid_surname("Van Dijk ", 9U));
    CHECK(!valid_surname("Dijk1", 5U));
    CHECK(!valid_surname("", 0U));
    char surname[PERSONAL_FIELD_MAX_LEN + 2U];
    memset(surname, 'A', sizeof(surname));
    surname[sizeof(surname) - 1U] = '\0';
    CHECK(valid_surname(surname, PERSONAL_FIELD_MAX_LEN));
    CHECK(!valid_surname(surname, PERSONAL_FIELD_MAX_LEN + 1U));
    ascii_lowercase_inplace(surname);
    CHECK(bytes_are(surname, sizeof(surname) - 1U, 'a'));
}

int main(void) {
    test_terminal_restore();
    test_lines();
    test_all_input_bytes();
    test_validation();
    puts("Input and terminal tests passed (validation, cancellation and mode restoration).");
    return EXIT_SUCCESS;
}
