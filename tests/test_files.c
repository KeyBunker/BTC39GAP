 
#define main btc39gap_application_main
#include "../BTC39GAP.c"
#undef main
#include "test_common.h"

static char fixture_path[512];

static void remove_fixture(void) {
    if (fixture_path[0] != '\0') (void)remove(fixture_path);
}

static void create_fixture(void) {
#ifdef _WIN32
    CHECK(GetTempFileNameA(".", "b39", 0U, fixture_path) != 0U);
#else
    memcpy(fixture_path, "./btc39gap-input-XXXXXX", sizeof("./btc39gap-input-XXXXXX"));
    int fd = mkstemp(fixture_path);
    CHECK(fd >= 0);
    CHECK(close(fd) == 0);
#endif
    CHECK(atexit(remove_fixture) == 0);
}

static void write_fixture(const void *data, size_t length) {
    FILE *file = fopen(fixture_path, "wb");
    CHECK(file != NULL);
    CHECK(fwrite(data, 1U, length, file) == length);
    CHECK(fclose(file) == 0);
}

static void expect_file(const char *path, size_t capacity, const void *expected,
                         size_t expected_length, int success) {
    uint8_t *guard = malloc(capacity + 2U);
    CHECK(guard != NULL);
    memset(guard, 0xa5, capacity + 2U);
    char *out = (char *)(guard + 1U);
    size_t length = SIZE_MAX;
    CHECK(read_secret_file(path, out, capacity, &length) == success);
    CHECK(guard[0] == 0xa5 && guard[capacity + 1U] == 0xa5);
    if (success) {
        CHECK(length == expected_length);
        CHECK(memcmp(out, expected, length) == 0);
        CHECK(bytes_are(out + length, capacity - length, 0U));
    } else {
        CHECK(length == 0U);
        CHECK(bytes_are(out, capacity, 0U));
    }
    free(guard);
}

int main(void) {
    static const char public_text[] = "public test phrase 12345";
    static const char trimmed[] = " \tpublic test phrase 12345\r\n ";
    static const unsigned char invalid[][5] = {
        {'a',0,'b','c','d'}, {'a',0x80,'b','c','d'}, {'a',0x1b,'b','c','d'},
        {' ','\t','\r','\n',' '}, {'a',0x7f,'b','c','d'}
    };
    create_fixture();
    test_case = "file trimming and zeroed trailing storage";
    write_fixture(trimmed, sizeof(trimmed) - 1U);
    expect_file(fixture_path, 128U, public_text, sizeof(public_text) - 1U, 1);

    test_case = "file path and output share the same buffer";
    char alias[sizeof(fixture_path) + 128U];
    memset(alias, 0xa5, sizeof(alias));
    memcpy(alias, fixture_path, strlen(fixture_path) + 1U);
    size_t length = SIZE_MAX;
    CHECK(read_secret_file(alias, alias, sizeof(alias), &length));
    CHECK(length == sizeof(public_text) - 1U && strcmp(alias, public_text) == 0);
    CHECK(bytes_are(alias + length, sizeof(alias) - length, 0U));

    test_case = "exact and undersized output capacity";
    write_fixture(public_text, sizeof(public_text) - 1U);
    expect_file(fixture_path, sizeof(public_text), public_text, sizeof(public_text) - 1U, 1);
    expect_file(fixture_path, sizeof(public_text) - 1U, NULL, 0U, 0);
    test_case = "cancellation while loading a file";
    stop_requested = 1;
    expect_file(fixture_path, 128U, NULL, 0U, 0);
    stop_requested = 0;

    test_case = "binary, control-only, empty and non-regular inputs";
    for (size_t i = 0U; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        write_fixture(invalid[i], sizeof(invalid[i]));
        expect_file(fixture_path, 128U, NULL, 0U, 0);
    }
    write_fixture("", 0U);
    expect_file(fixture_path, 128U, NULL, 0U, 0);
    expect_file(".", 128U, NULL, 0U, 0);
    CHECK(remove(fixture_path) == 0);
    expect_file(fixture_path, 128U, NULL, 0U, 0);

    test_case = "multiline secrets normalize line endings and tabs";
    static const char multiline[] = "public test phrase\nwith\ttwo lines";
    write_fixture(multiline, sizeof(multiline) - 1U);
    expect_file(fixture_path, 128U, "public test phrasewith two lines", sizeof("public test phrasewith two lines") - 1U, 1);

    test_case = "Windows, Unix, classic Mac and mixed endings match terminal text";
    static const char *variants[] = {
        "12345678900987654321", "1234567890\r\n\r\n0987654321",
        "1234567890\n\n0987654321", "1234567890\r\r0987654321",
        " \r\n12345\r67890\n\r09876\r\n54321\t "
    };
    for (size_t i = 0U; i < sizeof(variants) / sizeof(variants[0]); i++) {
        write_fixture(variants[i], strlen(variants[i]));
        expect_file(fixture_path, 128U, "12345678900987654321", 20U, 1);
    }
    test_case = "literal escapes, prefixes and internal spaces are preserved";
    static const char literal[] = "text:file:C:\\new\\test  1234567890";
    write_fixture(literal, sizeof(literal) - 1U);
    expect_file(fixture_path, 128U, literal, sizeof(literal) - 1U, 1);

    const size_t sizes[] = {
        65535U, 65536U, 65537U, PRIMARY_SECRET_MAX_LEN - 1U,
        PRIMARY_SECRET_MAX_LEN, PRIMARY_SECRET_MAX_LEN + 1U
    };
    uint8_t *data = malloc(PRIMARY_SECRET_MAX_LEN + 1U);
    CHECK(data != NULL);
    memset(data, 'x', PRIMARY_SECRET_MAX_LEN + 1U);
    for (size_t i = 0U; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        char label[96];
        (void)snprintf(label, sizeof(label), "file length %zu around chunk/1-MiB boundary", sizes[i]);
        test_case = label;
        write_fixture(data, sizes[i]);
        int accepted = sizes[i] <= PRIMARY_SECRET_MAX_LEN;
        expect_file(fixture_path, PRIMARY_SECRET_MAX_LEN + 2U, data,
                    accepted ? sizes[i] : 0U, accepted);
    }
    test_case = "invalid byte beyond first 64-KiB chunk";
    data[65536U] = 0U;
    write_fixture(data, PRIMARY_SECRET_MAX_LEN);
    expect_file(fixture_path, PRIMARY_SECRET_MAX_LEN + 2U, NULL, 0U, 0);
    free(data);
    remove_fixture();
    fixture_path[0] = '\0';
    puts("File-input tests passed (real files, aliasing, cancellation, invalid data and 1-MiB boundaries).");
    return EXIT_SUCCESS;
}
