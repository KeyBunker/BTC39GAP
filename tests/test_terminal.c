 

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
static FILE *secret_input;
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
    int ch = fgetc(input == stdin && secret_input != NULL ? secret_input : input);
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
#ifdef _WIN32
    FILE *input = tmpfile();
#else
     
    char path[] = "./btc39gap-terminal-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    CHECK(unlink(path) == 0);
    FILE *input = fdopen(fd, "w+b");
#endif
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
    CHECK(strcmp(out, "ok") == 0);  
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
    test_case = "normalization is idempotent, preserves literals and checks final length";
    char portable[128] = " \r\n1234567890\r\n\r\n0987654321\t ";
    size_t portable_length = normalize_secret(portable, strlen(portable), sizeof(portable));
    CHECK(portable_length == 20U && strcmp(portable, "12345678900987654321") == 0);
    CHECK(bytes_are(portable + portable_length, sizeof(portable) - portable_length, 0U));
    CHECK(normalize_secret(portable, portable_length, sizeof(portable)) == portable_length);
    strcpy(portable, "123456789\r\n0987654321");
    portable_length = normalize_secret(portable, strlen(portable), sizeof(portable));
    CHECK(!valid_secret_value(portable, portable_length, PRIMARY_SECRET_MIN_LEN, PRIMARY_SECRET_MAX_LEN));
    strcpy(portable, "  C:\\new\\test\t  value  ");
    portable_length = normalize_secret(portable, strlen(portable), sizeof(portable));
    CHECK(strcmp(portable, "C:\\new\\test   value") == 0);
    CHECK(bytes_are(portable + portable_length, sizeof(portable) - portable_length, 0U));
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

static void test_secret_entry(void) {
    test_case = "copied preview text and plain terminal input agree";
    static const char *entries[] = {
        "12345678900987654321\n",
        "/tmp/public-secret-1234567890.txt\n",
        "./public-secret-1234567890.txt\n",
        "../public-secret-1234567890.txt\n",
        "C:\\public-secret-1234567890.txt\n",
        "\\\\host\\public-secret-1234567890.txt\n",
        "text:12345678900987654321\n",
        "  text:12345678900987654321  \n",
        "text:C:\\new\\test  1234567890\n",
        "text:file:12345678900987654321\n",
        "text:text:12345678900987654321\n"
    };
    static const char *expected[] = {
        "12345678900987654321",
        "/tmp/public-secret-1234567890.txt",
        "./public-secret-1234567890.txt",
        "../public-secret-1234567890.txt",
        "C:\\public-secret-1234567890.txt",
        "\\\\host\\public-secret-1234567890.txt",
        "12345678900987654321", "12345678900987654321",
        "C:\\new\\test  1234567890", "file:12345678900987654321", "text:12345678900987654321"
    };
    stop_requested = 0;
    cancel_at_character = -1;
    for (size_t i = 0U; i < sizeof(entries) / sizeof(entries[0]); i++) {
        char out[128];
        secret_input = input_stream(entries[i], strlen(entries[i]));
        secret_source source = {1, "previous-file.txt"};
        size_t n = read_secret("Test secret", out, sizeof(out), PRIMARY_SECRET_MIN_LEN, PRIMARY_SECRET_MAX_LEN, &source);
        CHECK(source.from_file == 0 && source.filename[0] == '\0');
        CHECK(n == strlen(expected[i]) && strcmp(out, expected[i]) == 0);
        CHECK(bytes_are(out + n, sizeof(out) - n, 0U));
        CHECK(fclose(secret_input) == 0);
        secret_input = NULL;
    }
}

static void test_preview(void) {
    test_case = "preview copy round-trip and display-only limits";
    static const char literal[] = "text:C:\\new\\test  1234567890";
    FILE *preview = input_stream("", 0U);
    print_secret_preview(preview, literal, sizeof(literal) - 1U, 254U);
    rewind(preview);
    char rendered[4096];
    size_t count = fread(rendered, 1U, sizeof(rendered) - 1U, preview);
    rendered[count] = '\0';
    CHECK(fclose(preview) == 0);
    char *line = strstr(rendered, "\ntext:");
    CHECK(line != NULL);
    line++;
    char *end = strchr(line, '\n');
    CHECK(end != NULL);
    secret_input = input_stream(line, (size_t)(end - line) + 1U);
    char out[128];
    secret_source source = {1, "previous-file.txt"};
    CHECK(read_secret("Test preview", out, sizeof(out), 20U, PRIMARY_SECRET_MAX_LEN, &source) == sizeof(literal) - 1U);
    CHECK(source.from_file == 0 && source.filename[0] == '\0');
    CHECK(strcmp(out, literal) == 0);
    CHECK(fclose(secret_input) == 0);
    secret_input = NULL;

    const size_t lengths[] = {249U, 250U, 2000U, 2001U};
    char large[2002];
    memset(large, 'x', sizeof(large));
    for (size_t i = 0U; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        preview = input_stream("", 0U);
        print_secret_preview(preview, large, lengths[i], 254U);
        rewind(preview);
        count = fread(rendered, 1U, sizeof(rendered) - 1U, preview);
        rendered[count] = '\0';
        CHECK(fclose(preview) == 0);
        CHECK((strstr(rendered, "\ntext:") != NULL) == (lengths[i] == 249U));
        CHECK((strstr(rendered, "DISPLAY ONLY") != NULL) == (lengths[i] > 249U));
        CHECK((strstr(rendered, "PREVIEW TRUNCATED") != NULL) == (lengths[i] > 2000U));
    }
}

static void test_secret_file_entry(void) {
    test_case = "file prefix loads a file; retries keep the correct input source";
    char path[512];
#ifdef _WIN32
    CHECK(GetTempFileNameA(".", "b39", 0U, path) != 0U);
#else
    strcpy(path, "./btc39gap-entry-XXXXXX");
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    CHECK(close(fd) == 0);
#endif
    static const char expected[] = "12345678900987654321";
    static const char *contents[] = {
        "1234567890\r\n\r\n0987654321", "short", "bad\033file", NULL
    };
    for (size_t i = 0U; i < sizeof(contents) / sizeof(contents[0]); i++) {
        if (contents[i] != NULL) {
            FILE *file = fopen(path, "wb");
            CHECK(file != NULL);
            size_t length = strlen(contents[i]);
            CHECK(fwrite(contents[i], 1U, length, file) == length);
            CHECK(fclose(file) == 0);
        } else {
            CHECK(remove(path) == 0);
        }
        char entry[640], out[640];
        int count = snprintf(entry, sizeof(entry), "file:%s\n%s\n", path, expected);
        CHECK(count > 0 && (size_t)count < sizeof(entry));
        secret_input = input_stream(entry, (size_t)count);
        secret_source source = {1, "previous-file.txt"};
        if (i > 0U) {
            fflush(stdout);
            fputs("\n[EXPECTED TEST REJECTION: deliberately invalid or missing file; "
                  "retrying with valid dummy input.]\n", stderr);
        }
        size_t n = read_secret("Test file", out, sizeof(out), PRIMARY_SECRET_MIN_LEN,
                               PRIMARY_SECRET_MAX_LEN, &source);
        CHECK(n == sizeof(expected) - 1U && strcmp(out, expected) == 0);
        CHECK(source.from_file == (i == 0U));
        CHECK(strcmp(source.filename, i == 0U ? secret_file_name(path) : "") == 0);
        CHECK(bytes_are(out + n, sizeof(out) - n, 0U));
        CHECK(fclose(secret_input) == 0);
        secret_input = NULL;
    }
}

static void test_secret_file_name(void) {
    test_case = "filename extraction uses native separators without OS calls";
    CHECK(strcmp(secret_file_name("secret.txt"), "secret.txt") == 0);
    CHECK(strcmp(secret_file_name("/tmp/secrets/example.txt"), "example.txt") == 0);
    CHECK(strcmp(secret_file_name("./example file%1.txt"), "example file%1.txt") == 0);
    CHECK(strcmp(secret_file_name("../example.txt"), "example.txt") == 0);
    CHECK(strcmp(secret_file_name(""), "") == 0);
    CHECK(strcmp(secret_file_name("/tmp/"), "") == 0);
#ifdef _WIN32
    CHECK(strcmp(secret_file_name("C:\\secrets\\example.txt"), "example.txt") == 0);
    CHECK(strcmp(secret_file_name("C:/secrets\\example.txt"), "example.txt") == 0);
    CHECK(strcmp(secret_file_name("\\\\server\\share\\example.txt"), "example.txt") == 0);
    CHECK(strcmp(secret_file_name("C:example.txt"), "example.txt") == 0);
#else
     
    CHECK(strcmp(secret_file_name("/tmp/back\\slash.txt"), "back\\slash.txt") == 0);
    CHECK(strcmp(secret_file_name("/tmp/C:example.txt"), "C:example.txt") == 0);
#endif
}

static void test_wallet_input_display(void) {
    test_case = "each wallet shows filename or direct secret above both surnames";
    const recovery_context recovery = {"van dijk", "de vries"};
    static const char secret[] = "public secret 1234567890";
    const uint32_t wallets[] = {1U, 42U};
    const secret_source sources[] = {{0, ""}, {1, "example file%1.txt"}, {1, ""}};
    for (size_t s = 0U; s < sizeof(sources) / sizeof(sources[0]); s++) {
        for (size_t i = 0U; i < sizeof(wallets) / sizeof(wallets[0]); i++) {
            FILE *output = input_stream("", 0U);
            print_wallet_inputs(output, wallets[i], secret, sizeof(secret) - 1U,
                                &sources[s], &recovery);
            rewind(output);
            char rendered[512], title[64];
            size_t count = fread(rendered, 1U, sizeof(rendered) - 1U, output);
            rendered[count] = '\0';
            CHECK(fclose(output) == 0);
            (void)snprintf(title, sizeof(title), "RECOVERY INPUTS (wallet %u)", wallets[i]);
            CHECK(strstr(rendered, title) != NULL);
            char *secret_line = strstr(rendered, "Secret: ");
            char *father_line = strstr(rendered, "Last Name Father:        van dijk\n");
            char *mother_line = strstr(rendered, "Maiden Last Name Mother: de vries\n");
            CHECK(secret_line != NULL && father_line != NULL && mother_line != NULL);
            CHECK(secret_line < father_line && father_line < mother_line);
            CHECK((strstr(rendered, secret) != NULL) == !sources[s].from_file);
            if (s == 1U) CHECK(strstr(rendered, "Secret:                  example file%1.txt\n") != NULL);
            if (s == 2U) CHECK(strstr(rendered, "Secret:                  external file\n") != NULL);
        }
    }
}

int main(void) {
    test_terminal_restore();
    test_lines();
    test_all_input_bytes();
    test_validation();
    test_secret_entry();
    test_preview();
    test_secret_file_entry();
    test_secret_file_name();
    test_wallet_input_display();
    puts("\nInput and terminal tests passed (validation, cancellation and mode restoration).");
    return EXIT_SUCCESS;
}
