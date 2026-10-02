

#ifndef _WIN32
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <secp256k1.h>

#include "wordlist.h"
#include "test_vectors.h"
#include "argon2.h"
#include "argon2/progress.h"
#include "sha/sha256.h"
#include "sha/sha512.h"
#include "sha/hmac_sha512.h"
#include "sha/pbkdf2.h"
#include "qr/qr.h"

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <unistd.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sys/prctl.h>
#include <sys/random.h>
#endif
#endif

#define HARDENED 0x80000000U
#define GREEN    "\033[32m"
#define BLUE     "\033[34m"
#define RED      "\033[31m"
#define YELLOW   "\033[33m"
#define RESET    "\033[0m"
#define PROFILE_ID                  "AIRGAPBIP39-1SECRET-2SURNAMES-WALLET-ARGON2ID-HKDFSHA512-8G-T3-P4-V4"
#define ARGON2_TIME_COST            UINT32_C(3)
#define ARGON2_MEMORY_KIB           UINT32_C(8388608)
#define ARGON2_LANES                UINT32_C(4)
#define ARGON2_OUT_BYTES            64U
#define PRIMARY_SECRET_MIN_LEN      20U
#define PRIMARY_SECRET_MAX_LEN      (1024U * 1024U)
#define SECRET_ENTRY_MAX_LEN        1024U
#define PERSONAL_FIELD_MAX_LEN      80U
#define INPUT_INVALID               SIZE_MAX
#define INPUT_EOF                   (SIZE_MAX - 1U)

_Static_assert(SIZE_MAX > UINT32_MAX, "BTC39GAP requires a 64-bit target");

static const char DOMAIN_RECOVERY_CONTEXT[] =
    "AirgapBIP39/recovery-context/parent-surnames/lowercase-ascii/v4";
static const char DOMAIN_DERIVATION_CONTEXT[] =
    "AirgapBIP39/derivation-context/profile-context-and-wallet/v4";
static const char DOMAIN_ARGON_AD[] =
    "AirgapBIP39/argon2-ad/profile-context-and-wallet/v4";
static const char DOMAIN_HKDF_EXTRACT[] =
    "AirgapBIP39/hkdf-extract/argon2id-v4";
static const char DOMAIN_SECRET_BINDING[] =
    "AirgapBIP39/secret-binding/primary/v4";
static const char DOMAIN_ENTROPY[] =
    "AirgapBIP39/bip39-entropy/24/argon2id-hkdf-sha512/v4";
static const char DOMAIN_RECOVERY_FP_KEY[] =
    "AirgapBIP39/recovery-fields-fingerprint/key";
static const char DOMAIN_RECOVERY_FP[] =
    "AirgapBIP39/recovery-fields-fingerprint/value";
static const char DOMAIN_WALLET_FINGERPRINT[] =
    "AirgapBIP39/wallet-address-fingerprint";

typedef struct {
    char father_last_name[PERSONAL_FIELD_MAX_LEN + 2U];
    char mother_maiden_last_name[PERSONAL_FIELD_MAX_LEN + 2U];
} recovery_context;

static secp256k1_context *ctx = NULL;
static volatile sig_atomic_t stop_requested = 0;
static int memory_lock_failed = 0;
static int swap_active = 0;
static int memory_notice_visible = 0;
static int screen_ready = 0;
static int wallet_display_active = 0;
static uint32_t displayed_wallet = 0U;
static void clear_terminal(void);
static void print_header(void);
static struct {
    void *data;
    size_t size;
} cleanup_buffers[32];
static size_t cleanup_buffer_count = 0U;
static char wallet_input_buffer[256];
static struct {
    uint8_t extract_salt[64], bound_master[64], prk[64], entropy_block[64];
    uint8_t fp_key[64], fp_block[64], info[512];
} post_workspace;

#ifndef _WIN32
static struct termios saved_termios;
static int termios_saved = 0;
#else
static HANDLE saved_input_handle = INVALID_HANDLE_VALUE;
static DWORD saved_input_mode = 0;
static int input_mode_saved = 0;
#endif


static void secure_wipe(void *v, size_t n) {
    volatile uint8_t *p = (volatile uint8_t *)v;
    while (n-- != 0U) {
        *p++ = 0U;
    }
}

static int os_random_bytes(uint8_t *out, size_t n) {
#ifdef _WIN32
    if (n > (size_t)ULONG_MAX) return 0;
    return BCryptGenRandom(NULL, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#elif defined(__linux__)
    size_t done = 0U;
    while (done < n) {
        ssize_t r = getrandom(out + done, n - done, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return 0;
        }
        if (r == 0) return 0;
        done += (size_t)r;
    }
    return 1;
#else
    arc4random_buf(out, n);
    return 1;
#endif
}

static void warn_memory_lock_unavailable(void) {
    memory_lock_failed = 1;
    if (screen_ready && !memory_notice_visible) {
        clear_terminal();
        print_header();
    }
}


static int lock_secret_memory(void *p, size_t n) {
#ifdef _WIN32
    int locked = VirtualLock(p, n) != 0;
#else
    int locked = mlock(p, n) == 0;
#endif
    if (!locked) warn_memory_lock_unavailable();
    return locked;
}

static int secure_argon_alloc(uint8_t **memory, size_t bytes) {
    if (memory == NULL || bytes == 0U) return -1;
    *memory = NULL;
#ifdef _WIN32
    void *p = VirtualAlloc(NULL, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (p == NULL) return -1;
    (void)lock_secret_memory(p, bytes);
    *memory = (uint8_t *)p;
    return 0;
#else
    int flags = MAP_PRIVATE;
#ifdef MAP_ANONYMOUS
    flags |= MAP_ANONYMOUS;
#else
    flags |= MAP_ANON;
#endif
    void *p = mmap(NULL, bytes, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (p == MAP_FAILED) return -1;
#ifdef __linux__
#ifdef MADV_DONTDUMP
    (void)madvise(p, bytes, MADV_DONTDUMP);
#endif
#ifdef MADV_DONTFORK
    (void)madvise(p, bytes, MADV_DONTFORK);
#endif
#endif
    (void)lock_secret_memory(p, bytes);
    *memory = (uint8_t *)p;
    return 0;
#endif
}

static void secure_argon_free(uint8_t *memory, size_t bytes) {
    if (memory == NULL || bytes == 0U) return;

    /* Wipe while still locked and mapped, independent of Argon2's clear flag. */
    secure_wipe(memory, bytes);
#ifdef _WIN32
    (void)VirtualUnlock(memory, bytes);
    (void)VirtualFree(memory, 0, MEM_RELEASE);
#else
    (void)munlock(memory, bytes);
    (void)munmap(memory, bytes);
#endif
}

static void die(const char *msg) {
    fprintf(stderr, "%sError:%s %s\n", RED, RESET, msg);
    exit(EXIT_FAILURE);
}

static void enable_windows_ansi(void) {
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;
    DWORD mode = 0;
    if (!GetConsoleMode(hOut, &mode)) return;
    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    (void)SetConsoleMode(hOut, mode);
#endif
}

static void clear_terminal(void) {
#ifdef _WIN32
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (!GetConsoleMode(out, &mode) || !(mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        CONSOLE_SCREEN_BUFFER_INFO info;
        DWORD written;
        COORD origin = {0, 0};
        if (GetConsoleScreenBufferInfo(out, &info)) {
            DWORD cells = (DWORD)info.dwSize.X * (DWORD)info.dwSize.Y;
            (void)FillConsoleOutputCharacterA(out, ' ', cells, origin, &written);
            (void)FillConsoleOutputAttribute(out, info.wAttributes, cells, origin, &written);
            (void)SetConsoleCursorPosition(out, origin);
        }
        memory_notice_visible = 0;
        return;
    }
#endif
    fputs("\033[2J\033[3J\033[H", stdout);
    fflush(stdout);
    memory_notice_visible = 0;
}

static void print_header(void) {
    printf("%s===============================================%s\n", RED, RESET);
    printf("BTC39GAP - BY - NORDPAX\n");
    printf("Version: 1.0\n");
    printf("Output : 24 Words STANDARD BIP39 [ English ]\n");
    printf("%s===============================================%s\n\n", RED, RESET);
    if (memory_lock_failed) {
        printf("%sWARNING: Some memory could not be locked in RAM.%s\n\n", YELLOW, RESET);
        memory_notice_visible = 1;
    }
    if (swap_active) {
        printf("%sWARNING: swap appears to be enabled. For maximum protection,\n"
               "disable swap before entering secrets on the air-gapped machine.%s\n\n", YELLOW, RESET);
    }
    if (wallet_display_active) printf("Wallet number: %u\n", displayed_wallet);
    screen_ready = 1;
}

static void restore_terminal_echo(void) {
#ifdef _WIN32
    if (input_mode_saved && saved_input_handle != INVALID_HANDLE_VALUE) {
        if (stop_requested) (void)FlushConsoleInputBuffer(saved_input_handle);
        (void)SetConsoleMode(saved_input_handle, saved_input_mode);
        input_mode_saved = 0;
    }
#else
    if (termios_saved) {
        if (stop_requested) (void)tcflush(STDIN_FILENO, TCIFLUSH);
        (void)tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
        termios_saved = 0;
    }
#endif
}


static void register_cleanup_buffer(void *data, size_t size) {
    if (cleanup_buffer_count >= sizeof(cleanup_buffers) / sizeof(cleanup_buffers[0]))
        die("cleanup buffer registry full");
    cleanup_buffers[cleanup_buffer_count].data = data;
    cleanup_buffers[cleanup_buffer_count++].size = size;
}

static void cleanup_process(void) {
    restore_terminal_echo();
    for (size_t i = 0; i < cleanup_buffer_count; i++)
        secure_wipe(cleanup_buffers[i].data, cleanup_buffers[i].size);
    if (ctx != NULL) {
        secp256k1_context_destroy(ctx);
        ctx = NULL;
    }
}

static int interactive_terminal_available(void) {
#ifdef _WIN32
    DWORD mode;
    return GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mode) &&
           GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode) &&
           GetConsoleMode(GetStdHandle(STD_ERROR_HANDLE), &mode);
#else
    return isatty(STDIN_FILENO) && isatty(STDOUT_FILENO) && isatty(STDERR_FILENO);
#endif
}

static void request_stop(int signo) {
    (void)signo;
    stop_requested = 1;
}

static void install_signal_handlers(void) {
#ifndef _WIN32
    struct sigaction action;
    const int signals[] = { SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP };
    memset(&action, 0, sizeof(action));
    action.sa_handler = request_stop;
    if (sigemptyset(&action.sa_mask) != 0) die("signal mask setup failed");

    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
        if (sigaction(signals[i], &action, NULL) != 0)
            die("signal handler setup failed");
    }
#else
    if (signal(SIGINT, request_stop) == SIG_ERR ||
        signal(SIGTERM, request_stop) == SIG_ERR)
        die("signal handler setup failed");
#endif
}

static int enable_terminal_echo(void) {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if (h == INVALID_HANDLE_VALUE || !GetConsoleMode(h, &mode)) return 0;
    saved_input_handle = h;
    saved_input_mode = mode;
    input_mode_saved = 1;
    mode |= ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT;
    if (!SetConsoleMode(h, mode)) {
        input_mode_saved = 0;
        return 0;
    }
    return 1;
#else
    struct termios t;
    if (!isatty(STDIN_FILENO)) return 0;
    if (tcgetattr(STDIN_FILENO, &saved_termios) != 0) return 0;
    termios_saved = 1;
    t = saved_termios;
    t.c_lflag |= ECHO | ICANON | ISIG;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &t) != 0) {
        termios_saved = 0;
        return 0;
    }
    return 1;
#endif
}

static void disable_core_dumps(void) {
#ifndef _WIN32
    struct rlimit lim;
    lim.rlim_cur = 0;
    lim.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &lim) != 0) {
        die("could not disable core dumps");
    }
#ifdef __linux__
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        die("could not mark process non-dumpable");
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        die("could not enable no-new-privileges protection");
#endif
#endif
}

static void protect_process_memory(void) {
#ifndef _WIN32

    if (mlockall(MCL_CURRENT) != 0) warn_memory_lock_unavailable();
#endif
}

static void check_swap_active(void) {
#ifdef __linux__
    FILE *f = fopen("/proc/swaps", "r");
    if (f != NULL) {
        char line[512];
        int lines = 0;
        while (fgets(line, sizeof(line), f) != NULL) {
            lines++;
            if (lines > 1) {
                swap_active = 1;
                break;
            }
        }
        (void)fclose(f);
    }
#endif
}


static int is_portable_ascii(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20U || c > 0x7eU) return 0;
    }
    return 1;
}

static int constant_time_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0U;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0U;
}


static size_t read_ascii_line(FILE *input, char *out, size_t outsz) {
    size_t n = 0U;
    int invalid = 0;
    if (outsz < 2U) die("input buffer too small");
    secure_wipe(out, outsz);
    for (;;) {
        int ch;
        if (stop_requested) {
            secure_wipe(out, outsz);
            return INPUT_EOF;
        }
        ch = fgetc(input);
        if (ch == EOF) {
            secure_wipe(out, outsz);
            return INPUT_EOF;
        }
        if (ch == '\n') break;
        if (ch < 0x20 || ch > 0x7e) invalid = 1;
        if (n < outsz - 1U) out[n++] = (char)ch;
        else invalid = 1;
    }
    if (invalid || stop_requested) {
        secure_wipe(out, outsz);
        return stop_requested ? INPUT_EOF : INPUT_INVALID;
    }
    out[n] = '\0';
    return n;
}

static int parse_wallet_number(const char *s, size_t n, uint32_t *out) {
    uint32_t value = 0U;
    if (n == 0U || n > 7U) return 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return 0;
        value = value * 10U + (uint32_t)(s[i] - '0');
        if (value > 1000000U) return 0;
    }
    *out = value;
    return 1;
}

static int read_wallet_number(uint32_t *wallet, int initial) {
    for (;;) {
        fputs(initial ? "Wallet number (0-1000000, default 1) > " :
              "Next wallet number (0-1000000, ENTER = exit) > ", stdout);
        size_t n = read_ascii_line(stdin, wallet_input_buffer, sizeof(wallet_input_buffer));
        if (stop_requested) die("cancelled");
        if (n == INPUT_EOF) return 0;
        if (n == 0U) {
            if (!initial) return 0;
            *wallet = 1U;
            return 1;
        }
        int valid = n != INPUT_INVALID && parse_wallet_number(wallet_input_buffer, n, wallet);
        secure_wipe(wallet_input_buffer, sizeof(wallet_input_buffer));
        if (valid) return 1;
        fputs("Invalid wallet number. Use digits from 0 to 1000000.\n", stdout);
    }
}

static size_t read_visible_line(const char *prompt, char *out, size_t outsz) {
    fputs(prompt, stdout);
    fflush(stdout);
    size_t n = read_ascii_line(stdin, out, outsz);
    if (n == INPUT_EOF) die(stop_requested ? "cancelled" : "incomplete input");
    return n;
}

static int secret_whitespace(unsigned char ch) {
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

static size_t trim_secret(char *s, size_t n, size_t capacity) {
    size_t first = 0U, last = n;
    while (first < last && secret_whitespace((unsigned char)s[first])) first++;
    while (last > first && secret_whitespace((unsigned char)s[last - 1U])) last--;
    size_t length = last - first;
    memmove(s, s + first, length);
    secure_wipe(s + length, capacity - length);
    return length;
}

static int valid_secret_value(const char *s, size_t n,
                              size_t min_len, size_t max_len) {
    if (n < min_len || n > max_len) return 0;
    int content = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        if ((ch < 0x20U || ch > 0x7eU) && !secret_whitespace(ch)) return 0;
        if (!secret_whitespace(ch)) content = 1;
    }
    return content;
}

static int secret_is_file_path(const char *s, size_t n) {
    if (n == 0U) return 0;
    if (s[0] == '/') return 1;
    if (n >= 2U && s[0] == '.' && s[1] == '/') return 1;
    if (n >= 3U && s[0] == '.' && s[1] == '.' && s[2] == '/') return 1;
    if (n >= 2U && s[0] == '\\' && s[1] == '\\') return 1;
    return n >= 3U && ((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) &&
           s[1] == ':' && (s[2] == '\\' || s[2] == '/');
}

static int read_secret_file(const char *path, char *out, size_t capacity, size_t *length) {
    size_t used = 0U;
    int ok = 0;
    if (path == NULL || out == NULL || length == NULL || capacity < 2U) return 0;
    *length = 0U;
#ifdef _WIN32
    HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) goto done;
    BY_HANDLE_FILE_INFORMATION info;
    LARGE_INTEGER before, after;
    if (GetFileType(file) != FILE_TYPE_DISK || !GetFileInformationByHandle(file, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || !GetFileSizeEx(file, &before) ||
        before.QuadPart < 0 || (uint64_t)before.QuadPart > PRIMARY_SECRET_MAX_LEN) goto close_file;
    secure_wipe(out, capacity);
    while (!stop_requested && used < capacity - 1U) {
        DWORD received = 0U;
        size_t available = capacity - 1U - used;
        DWORD chunk = (DWORD)(available < 65536U ? available : 65536U);
        if (!ReadFile(file, out + used, chunk, &received, NULL)) goto close_file;
        if (received == 0U) break;
        used += (size_t)received;
    }
    if (!GetFileSizeEx(file, &after) || after.QuadPart != before.QuadPart ||
        (uint64_t)before.QuadPart != used) goto close_file;
#else
    int file = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
    if (file < 0) goto done;
    struct stat before, after;
    if (fstat(file, &before) != 0 || !S_ISREG(before.st_mode) || before.st_size < 0 ||
        (uint64_t)before.st_size > PRIMARY_SECRET_MAX_LEN) goto close_file;
    secure_wipe(out, capacity);
    while (!stop_requested && used < capacity - 1U) {
        size_t available = capacity - 1U - used;
        size_t chunk = available < 65536U ? available : 65536U;
        ssize_t received = read(file, out + used, chunk);
        if (received < 0) {
            if (errno == EINTR && !stop_requested) continue;
            goto close_file;
        }
        if (received == 0) break;
        used += (size_t)received;
    }
    if (fstat(file, &after) != 0 || after.st_size != before.st_size ||
        after.st_mtime != before.st_mtime || after.st_ctime != before.st_ctime ||
        (uint64_t)before.st_size != used) goto close_file;
#endif
    if (!stop_requested && used <= PRIMARY_SECRET_MAX_LEN &&
        valid_secret_value(out, used, 1U, PRIMARY_SECRET_MAX_LEN)) {
        *length = trim_secret(out, used, capacity);
        ok = 1;
    }
close_file:
#ifdef _WIN32
    (void)CloseHandle(file);
#else
    (void)close(file);
#endif
 done:
    if (!ok) secure_wipe(out, capacity);
    return ok;
}

static void print_secret_preview(const char *secret, size_t length) {
    size_t shown = 0U, columns = 0U;
    printf("Secret loaded: %zu bytes.\n", length);
    fputs("Preview escapes: \\\\ = backslash, \\r = carriage return, \\n = line feed, \\t = tab.\n"
          "Secret contents (up to 2000 display characters):\n", stdout);
    while (shown < length) {
        unsigned char ch = (unsigned char)secret[shown];
        int escaped = ch == '\\' || ch == '\r' || ch == '\n' || ch == '\t';
        size_t width = escaped ? 2U : 1U;
        if (columns + width > 2000U) break;
        if (escaped) {
            fputc('\\', stdout);
            fputc(ch == '\r' ? 'r' : ch == '\n' ? 'n' : ch == '\t' ? 't' : '\\', stdout);
        } else {
            fputc(ch, stdout);
        }
        columns += width;
        shown++;
    }
    fputs("\nEnd of secret preview.\n", stdout);
    if (shown < length) {
        printf("%sPREVIEW TRUNCATED: showing %zu of %zu secret characters; %zu characters not shown.\n"
               "The FULL secret is used for wallet generation.%s\n", GREEN, shown, length, length - shown, RESET);
    } else {
        fputs("Full secret shown.\n", stdout);
    }
}

static size_t read_secret(const char *label, char *out, size_t outsz,
                          size_t min_len, size_t max_len) {
    char prompt[96];
    size_t entry_max = SECRET_ENTRY_MAX_LEN;
#ifndef _WIN32
    long canonical = fpathconf(STDIN_FILENO, _PC_MAX_CANON);
    if (canonical <= 1) canonical = _POSIX_MAX_CANON;
    if (canonical > 1 && (size_t)canonical <= entry_max) entry_max = (size_t)canonical - 1U;
#endif
    (void)snprintf(prompt, sizeof(prompt), "%s > ", label);
    for (;;) {
        secure_wipe(out, outsz);
        size_t capacity = entry_max + 2U < outsz ? entry_max + 2U : outsz;
        size_t n = read_visible_line(prompt, out, capacity);
        if (n == INPUT_INVALID || n > entry_max) {
            secure_wipe(out, outsz);
            fputs("Invalid Secret. Entry is too long or contains invalid characters; use a file path for large secrets.\n", stderr);
            continue;
        }
        n = trim_secret(out, n, outsz);
        int from_file = 0;
        if (n >= 5U && memcmp(out, "text:", 5U) == 0) {
            memmove(out, out + 5U, n - 5U);
            n = trim_secret(out, n - 5U, outsz);
        } else if ((n >= 5U && memcmp(out, "file:", 5U) == 0) || secret_is_file_path(out, n)) {
            const char *path = n >= 5U && memcmp(out, "file:", 5U) == 0 ? out + 5U : out;
            if (!read_secret_file(path, out, outsz, &n)) {
                if (stop_requested) die("cancelled");
                fputs("Invalid Secret. Cannot read a regular ASCII text file up to 1 MiB; check the path, contents and size.\n", stderr);
                continue;
            }
            from_file = 1;
        }
        if (valid_secret_value(out, n, min_len, max_len)) {
            if (from_file) print_secret_preview(out, n);
            return n;
        }
        secure_wipe(out, outsz);
        fprintf(stderr, "%sInvalid %s.%s Use %zu-%zu ASCII text bytes after trimming; "
                "use a file path for large secrets.\n\n", YELLOW, label, RESET, min_len, max_len);
    }
}

static int valid_surname(const char *s, size_t n) {
    if (n == 0U || n > PERSONAL_FIELD_MAX_LEN || s[0] == ' ' || s[n - 1U] == ' ')
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        if (ch != ' ' && !(ch >= 'A' && ch <= 'Z') && !(ch >= 'a' && ch <= 'z'))
            return 0;
    }
    return 1;
}

static void ascii_lowercase_inplace(char *s) {
    if (s == NULL) return;
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        if (c >= 'A' && c <= 'Z') *s = (char)(c + ('a' - 'A'));
    }
}

static size_t read_visible_lower_field(const char *prompt, char *out, size_t outsz,
                                       const char *field_name) {
    for (;;) {
        size_t n = read_visible_line(prompt, out, outsz);
        if (valid_surname(out, n)) {
            ascii_lowercase_inplace(out);
            return n;
        }
        secure_wipe(out, outsz);
        fprintf(stderr,
                "%sInvalid %s.%s Use 1-%u ASCII letters and internal spaces; "
                "no leading/trailing spaces.\n",
                YELLOW, field_name, RESET, (unsigned)PERSONAL_FIELD_MAX_LEN);
    }
}

static void read_recovery_context(recovery_context *rc) {
    (void)read_visible_lower_field("Last Name Father > ", rc->father_last_name,
                                  sizeof(rc->father_last_name), "Last Name Father");
    (void)read_visible_lower_field("Maiden Last Name Mother > ", rc->mother_maiden_last_name,
                                  sizeof(rc->mother_maiden_last_name), "Maiden Last Name Mother");
}

static void store_be32(uint8_t out[4], uint32_t v) {
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}

static void tagged_hash(const char *tag,
                        const uint8_t *msg, size_t msglen,
                        uint8_t out[32]) {
    uint8_t tagh[32];
    uint8_t buf[96];
    size_t taglen = strlen(tag);

    if (msglen > 32U) die("tagged_hash message too large");
    sha256_hash((const uint8_t *)tag, taglen, tagh);
    memcpy(buf, tagh, 32);
    memcpy(buf + 32, tagh, 32);
    memcpy(buf + 64, msg, msglen);
    sha256_hash(buf, 64U + msglen, out);

    secure_wipe(tagh, sizeof(tagh));
    secure_wipe(buf, sizeof(buf));
}


static void bip39_from_entropy_256(const uint8_t entropy[32],
                                   char *out, size_t outsz) {
    uint8_t hash[32];
    uint8_t data[33];
    size_t used = 0U;

    sha256_hash(entropy, 32, hash);
    memcpy(data, entropy, 32);
    data[32] = hash[0];

    if (outsz == 0U) die("mnemonic buffer too small");
    out[0] = '\0';

    for (int w = 0; w < 24; w++) {
        unsigned idx = 0U;
        for (int j = 0; j < 11; j++) {
            size_t bitpos = (size_t)w * 11U + (size_t)j;
            size_t bytepos = bitpos / 8U;
            unsigned shift = 7U - (unsigned)(bitpos % 8U);
            idx = (idx << 1) | ((unsigned)(data[bytepos] >> shift) & 1U);
        }

        const char *word = wordlist[idx];
        size_t wl = strlen(word);
        size_t needed = wl + ((w == 0) ? 0U : 1U) + 1U;
        if (used + needed > outsz) die("mnemonic buffer too small");

        if (w != 0) out[used++] = ' ';
        memcpy(out + used, word, wl);
        used += wl;
        out[used] = '\0';
    }

    secure_wipe(hash, sizeof(hash));
    secure_wipe(data, sizeof(data));
}

static void print_mnemonic_cols(const char *mnemonic) {
    const char *list[24];
    int lengths[24];
    int count = 0;
    const char *cursor = mnemonic;

    while (*cursor != '\0' && count < 24) {
        size_t length = strcspn(cursor, " ");
        if (length == 0U || length > 8U) die("internal mnemonic word length error");
        list[count] = cursor;
        lengths[count++] = (int)length;
        cursor += length;
        if (*cursor == ' ') cursor++;
    }
    if (count != 24 || *cursor != '\0') die("internal mnemonic word count error");

    for (int r = 0; r < 6; r++) {
        for (int c = 0; c < 4; c++) {
            int idx = r + c * 6;
            printf("%2d.%s%-12.*s%s  ", idx + 1, GREEN, lengths[idx], list[idx], RESET);
        }
        fputc('\n', stdout);
    }
    secure_wipe(list, sizeof(list));
    secure_wipe(lengths, sizeof(lengths));
}

static void bip39_seed_no_passphrase(const char *mnemonic, uint8_t out[64]) {
    static const uint8_t salt[] = "mnemonic";
    if (pbkdf2_hmac_sha512((const uint8_t *)mnemonic, strlen(mnemonic),
                           salt, sizeof(salt) - 1U,
                           2048U, out, 64U) != 0) {
        die("PBKDF2-HMAC-SHA512 failed");
    }
}


typedef struct {
    uint8_t priv[32];
    uint8_t pub[33];
    uint8_t chain[32];
    uint32_t child_index;
} ext_key;

static void pubkey_from_priv(const uint8_t priv[32], uint8_t out33[33]) {
    secp256k1_pubkey pub;
    size_t len = 33U;

    if (!secp256k1_ec_pubkey_create(ctx, &pub, priv)) die("pubkey_create failed");
    if (!secp256k1_ec_pubkey_serialize(ctx, out33, &len, &pub,
                                      SECP256K1_EC_COMPRESSED) || len != 33U) {
        secure_wipe(&pub, sizeof(pub));
        die("pubkey serialization failed");
    }
    secure_wipe(&pub, sizeof(pub));
}

static void bip32_from_seed(const uint8_t seed[64], ext_key *out) {
    static const uint8_t key[] = "Bitcoin seed";
    uint8_t I[64];

    hmac_sha512(key, sizeof(key) - 1U, seed, 64U, I);
    if (!secp256k1_ec_seckey_verify(ctx, I)) {
        secure_wipe(I, sizeof(I));
        die("BIP32 produced invalid master key");
    }

    memcpy(out->priv, I, 32);
    memcpy(out->chain, I + 32, 32);
    out->child_index = 0U;
    pubkey_from_priv(out->priv, out->pub);
    secure_wipe(I, sizeof(I));
}

static uint32_t bip32_ckd_priv(const ext_key *parent,
                               uint32_t requested_index,
                               ext_key *child) {
    uint32_t index = requested_index;
    uint8_t data[37];
    uint8_t I[64];

    for (;;) {
        size_t n = 0U;
        if ((index & HARDENED) != 0U) {
            data[n++] = 0U;
            memcpy(data + n, parent->priv, 32);
            n += 32U;
        } else {
            memcpy(data + n, parent->pub, 33);
            n += 33U;
        }
        data[n++] = (uint8_t)(index >> 24);
        data[n++] = (uint8_t)(index >> 16);
        data[n++] = (uint8_t)(index >> 8);
        data[n++] = (uint8_t)index;

        hmac_sha512(parent->chain, 32U, data, n, I);
        memcpy(child->priv, parent->priv, 32);

        if (secp256k1_ec_seckey_tweak_add(ctx, child->priv, I)) {
            memcpy(child->chain, I + 32, 32);
            child->child_index = index;
            pubkey_from_priv(child->priv, child->pub);
            secure_wipe(data, sizeof(data));
            secure_wipe(I, sizeof(I));
            return index;
        }

        if (index == UINT32_MAX || index == HARDENED - 1U) {
            secure_wipe(data, sizeof(data));
            secure_wipe(I, sizeof(I));
            die("BIP32 child derivation exhausted index range");
        }
        index++;
    }
}


static void tap_output_key(const uint8_t pub33[33], uint8_t output_xonly[32]) {
    secp256k1_pubkey internal_pub;
    uint8_t internal_xonly[32];
    uint8_t tweak[32];
    uint8_t serialized[33];
    size_t serialized_len = sizeof(serialized);

    if (pub33[0] != 0x02U && pub33[0] != 0x03U)
        die("invalid compressed pubkey");
    if (!secp256k1_ec_pubkey_parse(ctx, &internal_pub, pub33, 33U))
        die("Taproot internal pubkey parse failed");

    memcpy(internal_xonly, pub33 + 1, sizeof(internal_xonly));


    if (pub33[0] == 0x03U && !secp256k1_ec_pubkey_negate(ctx, &internal_pub))
        die("Taproot internal-key normalization failed");

    tagged_hash("TapTweak", internal_xonly, sizeof(internal_xonly), tweak);
    if (!secp256k1_ec_pubkey_tweak_add(ctx, &internal_pub, tweak)) {
        secure_wipe(internal_xonly, sizeof(internal_xonly));
        secure_wipe(tweak, sizeof(tweak));
        die("Taproot public-key tweak failed");
    }
    if (!secp256k1_ec_pubkey_serialize(ctx, serialized, &serialized_len,
                                      &internal_pub, SECP256K1_EC_COMPRESSED) ||
        serialized_len != sizeof(serialized)) {
        secure_wipe(internal_xonly, sizeof(internal_xonly));
        secure_wipe(tweak, sizeof(tweak));
        die("Taproot output-key serialization failed");
    }

    memcpy(output_xonly, serialized + 1, 32U);
    secure_wipe(internal_xonly, sizeof(internal_xonly));
    secure_wipe(tweak, sizeof(tweak));
    secure_wipe(serialized, sizeof(serialized));
    secure_wipe(&internal_pub, sizeof(internal_pub));
}


static uint32_t bech32_polymod(const uint8_t *v, size_t n) {
    static const uint32_t GEN[5] = {
        UINT32_C(0x3b6a57b2), UINT32_C(0x26508e6d), UINT32_C(0x1ea119fa),
        UINT32_C(0x3d4233dd), UINT32_C(0x2a1462b3)
    };
    uint32_t chk = 1U;

    for (size_t i = 0; i < n; i++) {
        uint8_t top = (uint8_t)(chk >> 25);
        chk = ((chk & UINT32_C(0x1ffffff)) << 5) ^ (uint32_t)v[i];
        for (unsigned j = 0; j < 5U; j++) {
            if (((top >> j) & 1U) != 0U) chk ^= GEN[j];
        }
    }
    return chk;
}

static size_t hrp_expand(const char *hrp, uint8_t *out, size_t outcap) {
    size_t n = strlen(hrp);
    if (outcap < n * 2U + 1U) die("hrp buffer too small");
    size_t p = 0U;
    for (size_t i = 0; i < n; i++) out[p++] = (uint8_t)((unsigned char)hrp[i] >> 5);
    out[p++] = 0U;
    for (size_t i = 0; i < n; i++) out[p++] = (uint8_t)((unsigned char)hrp[i] & 31U);
    return p;
}

static int convert_bits_8_to_5(const uint8_t *in, size_t inlen,
                               uint8_t *out, size_t outcap,
                               size_t *outlen) {
    uint32_t acc = 0U;
    unsigned bits = 0U;
    size_t p = 0U;
    const uint32_t max_acc = (UINT32_C(1) << 12) - 1U;

    for (size_t i = 0; i < inlen; i++) {
        acc = ((acc << 8) | (uint32_t)in[i]) & max_acc;
        bits += 8U;
        while (bits >= 5U) {
            bits -= 5U;
            if (p >= outcap) return 0;
            out[p++] = (uint8_t)((acc >> bits) & 31U);
        }
    }
    if (bits != 0U) {
        if (p >= outcap) return 0;
        out[p++] = (uint8_t)((acc << (5U - bits)) & 31U);
    }
    *outlen = p;
    return 1;
}

static void bech32m_encode_p2tr(const uint8_t xonly[32],
                                char *out, size_t outsz) {
    static const char *HRP = "bc";
    static const char *CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    uint8_t conv[64];
    uint8_t data[1 + 64];
    uint8_t hrpe[16];
    uint8_t vals[128];
    uint8_t checksum[6];
    size_t conv_len = 0U, data_len, hrp_len, vlen = 0U, pos = 0U;

    if (!convert_bits_8_to_5(xonly, 32U, conv, sizeof(conv), &conv_len))
        die("convertbits failed");

    data[0] = 1U;
    memcpy(data + 1, conv, conv_len);
    data_len = 1U + conv_len;

    hrp_len = hrp_expand(HRP, hrpe, sizeof(hrpe));
    if (hrp_len + data_len + 6U > sizeof(vals)) die("bech32 internal buffer too small");
    memcpy(vals + vlen, hrpe, hrp_len); vlen += hrp_len;
    memcpy(vals + vlen, data, data_len); vlen += data_len;
    memset(vals + vlen, 0, 6U); vlen += 6U;

    uint32_t pm = bech32_polymod(vals, vlen) ^ UINT32_C(0x2bc830a3);
    for (int i = 0; i < 6; i++) checksum[i] = (uint8_t)((pm >> (5 * (5 - i))) & 31U);

    if (outsz < 4U + data_len + 6U) die("address buffer too small");
    out[pos++] = 'b'; out[pos++] = 'c'; out[pos++] = '1';
    for (size_t i = 0; i < data_len; i++) out[pos++] = CHARSET[data[i]];
    for (size_t i = 0; i < 6U; i++) out[pos++] = CHARSET[checksum[i]];
    out[pos] = '\0';

    secure_wipe(conv, sizeof(conv));
    secure_wipe(data, sizeof(data));
    secure_wipe(hrpe, sizeof(hrpe));
    secure_wipe(vals, sizeof(vals));
    secure_wipe(checksum, sizeof(checksum));
}


static void append_framed_field(uint8_t *buf, size_t bufsz, size_t *p,
                                const char *value, size_t value_len) {
    uint8_t be_len[4];
    if (value_len > UINT32_MAX || *p > bufsz || bufsz - *p < 4U ||
        value_len > bufsz - *p - 4U) die("recovery context framing overflow");
    store_be32(be_len, (uint32_t)value_len);
    memcpy(buf + *p, be_len, sizeof(be_len)); *p += sizeof(be_len);
    memcpy(buf + *p, value, value_len); *p += value_len;
    secure_wipe(be_len, sizeof(be_len));
}

static void build_recovery_context_digest(const recovery_context *rc, uint8_t out[32]) {
    uint8_t buf[256];
    size_t p = 0U;
    size_t label_len = strlen(DOMAIN_RECOVERY_CONTEXT);
    memcpy(buf, DOMAIN_RECOVERY_CONTEXT, label_len); p += label_len;
    append_framed_field(buf, sizeof(buf), &p, rc->father_last_name, strlen(rc->father_last_name));
    append_framed_field(buf, sizeof(buf), &p, rc->mother_maiden_last_name, strlen(rc->mother_maiden_last_name));
    sha256_hash(buf, p, out);
    secure_wipe(buf, sizeof(buf));
}

static void derive_wallet_address_fingerprint(const char *address, uint8_t out[8]) {
    uint8_t buf[256];
    uint8_t digest[32];
    size_t label_len = strlen(DOMAIN_WALLET_FINGERPRINT);
    size_t address_len = strlen(address);
    if (label_len + address_len > sizeof(buf)) die("wallet fingerprint framing overflow");
    memcpy(buf, DOMAIN_WALLET_FINGERPRINT, label_len);
    memcpy(buf + label_len, address, address_len);
    sha256_hash(buf, label_len + address_len, digest);
    memcpy(out, digest, 8U);
    secure_wipe(buf, sizeof(buf));
    secure_wipe(digest, sizeof(digest));
}

static void print_fingerprint64(const char *label, const uint8_t fp[8]) {
    printf("%s: ", label);
    for (size_t i = 0; i < 8U; i++) {
        printf("%02X", fp[i]);
        if (i == 1U || i == 3U || i == 5U) fputc('-', stdout);
    }
    fputc('\n', stdout);
}

static void derive_secret_binding(const char *primary, size_t primary_len,
                                  uint8_t out[64]) {
    sha512_ctx h;
    uint8_t be_primary[4];
    size_t label_len = strlen(DOMAIN_SECRET_BINDING);

    if (!valid_secret_value(primary, primary_len, PRIMARY_SECRET_MIN_LEN, PRIMARY_SECRET_MAX_LEN))
        die("invalid secret: use at least 20 bytes and no more than 1 MiB of high-entropy secret input, not only spaces");
    store_be32(be_primary, (uint32_t)primary_len);

    if (sha512_init(&h) != 0) die("secret binding init failed");
    if (sha512_update(&h, (const uint8_t *)DOMAIN_SECRET_BINDING, label_len) != 0 ||
        sha512_update(&h, be_primary, sizeof(be_primary)) != 0 ||
        sha512_update(&h, (const uint8_t *)primary, primary_len) != 0 ||
        sha512_final(&h, out) != 0) {
        secure_wipe(&h, sizeof(h));
        secure_wipe(be_primary, sizeof(be_primary));
        die("secret binding failed");
    }

    secure_wipe(&h, sizeof(h));
    secure_wipe(be_primary, sizeof(be_primary));
}

static void derive_derivation_context(const uint8_t context_digest[32], uint32_t wallet,
                              uint8_t out[32]) {
    uint8_t buf[320];
    uint8_t be_profile_len[4], be_context_len[4];
    size_t label_len = strlen(DOMAIN_DERIVATION_CONTEXT);
    size_t profile_len = strlen(PROFILE_ID);
    size_t p = 0U;

    if (label_len + 4U + profile_len + 4U + 32U + 4U > sizeof(buf))
        die("derivation context framing overflow");

    store_be32(be_profile_len, (uint32_t)profile_len);
    store_be32(be_context_len, 32U);

    memcpy(buf + p, DOMAIN_DERIVATION_CONTEXT, label_len); p += label_len;
    memcpy(buf + p, be_profile_len, sizeof(be_profile_len)); p += sizeof(be_profile_len);
    memcpy(buf + p, PROFILE_ID, profile_len); p += profile_len;
    memcpy(buf + p, be_context_len, sizeof(be_context_len)); p += sizeof(be_context_len);
    memcpy(buf + p, context_digest, 32U); p += 32U;
    store_be32(buf + p, wallet); p += 4U;

    sha256_hash(buf, p, out);

    secure_wipe(buf, sizeof(buf));
    secure_wipe(be_profile_len, sizeof(be_profile_len));
    secure_wipe(be_context_len, sizeof(be_context_len));
}

static void derive_argon_ad(const uint8_t context_digest[32], uint32_t wallet,
                            uint8_t out[64]) {
    uint8_t buf[384];
    uint8_t be_profile_len[4], be_context_len[4];
    size_t label_len = strlen(DOMAIN_ARGON_AD);
    size_t profile_len = strlen(PROFILE_ID);
    size_t p = 0U;

    if (label_len + 4U + profile_len + 4U + 32U + 4U > sizeof(buf))
        die("argon associated-data framing overflow");

    store_be32(be_profile_len, (uint32_t)profile_len);
    store_be32(be_context_len, 32U);

    memcpy(buf + p, DOMAIN_ARGON_AD, label_len); p += label_len;
    memcpy(buf + p, be_profile_len, sizeof(be_profile_len)); p += sizeof(be_profile_len);
    memcpy(buf + p, PROFILE_ID, profile_len); p += profile_len;
    memcpy(buf + p, be_context_len, sizeof(be_context_len)); p += sizeof(be_context_len);
    memcpy(buf + p, context_digest, 32U); p += 32U;
    store_be32(buf + p, wallet); p += 4U;

    sha512_hash(buf, p, out);

    secure_wipe(buf, sizeof(buf));
    secure_wipe(be_profile_len, sizeof(be_profile_len));
    secure_wipe(be_context_len, sizeof(be_context_len));
}


static void derive_post_argon_keys(const uint8_t master[64],
                                   const uint8_t secret_binding[64],
                                   const uint8_t derivation_context[32],
                                   const uint8_t argon_ad[64],
                                   const uint8_t context_digest[32], uint32_t wallet,
                                   uint8_t entropy[32],
                                   uint8_t recovery_fields_fp[8]) {
    secure_wipe(&post_workspace, sizeof(post_workspace));
    (void)lock_secret_memory(&post_workspace, sizeof(post_workspace));
    size_t p = 0U;
    size_t profile_len = strlen(PROFILE_ID);
    size_t extract_domain_len = strlen(DOMAIN_HKDF_EXTRACT);
    size_t entropy_domain_len = strlen(DOMAIN_ENTROPY);
    size_t fp_key_domain_len = strlen(DOMAIN_RECOVERY_FP_KEY);
    size_t fp_domain_len = strlen(DOMAIN_RECOVERY_FP);


    if (extract_domain_len + profile_len + 32U + 64U + 32U + 4U > sizeof(post_workspace.info))
        die("HKDF extract framing overflow");
    memcpy(post_workspace.info + p, DOMAIN_HKDF_EXTRACT, extract_domain_len); p += extract_domain_len;
    memcpy(post_workspace.info + p, PROFILE_ID, profile_len); p += profile_len;
    memcpy(post_workspace.info + p, derivation_context, 32U); p += 32U;
    memcpy(post_workspace.info + p, argon_ad, 64U); p += 64U;
    memcpy(post_workspace.info + p, context_digest, 32U); p += 32U;
    store_be32(post_workspace.info + p, wallet); p += 4U;
    sha512_hash(post_workspace.info, p, post_workspace.extract_salt);
    hmac_sha512(secret_binding, 64U, master, 64U, post_workspace.bound_master);
    hmac_sha512(post_workspace.extract_salt, sizeof(post_workspace.extract_salt), post_workspace.bound_master, sizeof(post_workspace.bound_master), post_workspace.prk);

    secure_wipe(post_workspace.info, sizeof(post_workspace.info));
    p = 0U;
    if (entropy_domain_len + profile_len + 64U + 32U + 4U + 1U > sizeof(post_workspace.info))
        die("entropy HKDF info overflow");
    memcpy(post_workspace.info + p, DOMAIN_ENTROPY, entropy_domain_len); p += entropy_domain_len;
    memcpy(post_workspace.info + p, PROFILE_ID, profile_len); p += profile_len;
    memcpy(post_workspace.info + p, argon_ad, 64U); p += 64U;
    memcpy(post_workspace.info + p, context_digest, 32U); p += 32U;
    store_be32(post_workspace.info + p, wallet); p += 4U;
    post_workspace.info[p++] = 0x01U;
    hmac_sha512(post_workspace.prk, sizeof(post_workspace.prk), post_workspace.info, p, post_workspace.entropy_block);
    memcpy(entropy, post_workspace.entropy_block, 32U);

    secure_wipe(post_workspace.info, sizeof(post_workspace.info));
    p = 0U;
    if (fp_key_domain_len + profile_len + 64U + 32U + 4U + 1U > sizeof(post_workspace.info))
        die("fingerprint key info overflow");
    memcpy(post_workspace.info + p, DOMAIN_RECOVERY_FP_KEY, fp_key_domain_len); p += fp_key_domain_len;
    memcpy(post_workspace.info + p, PROFILE_ID, profile_len); p += profile_len;
    memcpy(post_workspace.info + p, argon_ad, 64U); p += 64U;
    memcpy(post_workspace.info + p, context_digest, 32U); p += 32U;
    store_be32(post_workspace.info + p, wallet); p += 4U;
    post_workspace.info[p++] = 0x01U;
    hmac_sha512(post_workspace.prk, sizeof(post_workspace.prk), post_workspace.info, p, post_workspace.fp_key);

    secure_wipe(post_workspace.info, sizeof(post_workspace.info));
    p = 0U;
    if (fp_domain_len + 32U + 4U > sizeof(post_workspace.info)) die("fingerprint value info overflow");
    memcpy(post_workspace.info + p, DOMAIN_RECOVERY_FP, fp_domain_len); p += fp_domain_len;
    memcpy(post_workspace.info + p, context_digest, 32U); p += 32U;
    hmac_sha512(post_workspace.fp_key, sizeof(post_workspace.fp_key), post_workspace.info, p, post_workspace.fp_block);
    memcpy(recovery_fields_fp, post_workspace.fp_block, 8U);

    secure_wipe(post_workspace.extract_salt, sizeof(post_workspace.extract_salt));
    secure_wipe(post_workspace.bound_master, sizeof(post_workspace.bound_master));
    secure_wipe(post_workspace.prk, sizeof(post_workspace.prk));
    secure_wipe(post_workspace.entropy_block, sizeof(post_workspace.entropy_block));
    secure_wipe(post_workspace.fp_key, sizeof(post_workspace.fp_key));
    secure_wipe(post_workspace.fp_block, sizeof(post_workspace.fp_block));
    secure_wipe(post_workspace.info, sizeof(post_workspace.info));
}

static void render_argon_progress(uint32_t percent) {
    unsigned filled = (unsigned)(percent * 30U / 100U);
    fputs("\rArgon2id [", stdout);
    for (unsigned i = 0U; i < 30U; i++) fputc(i < filled ? '#' : '.', stdout);
    printf("] %3u%%", percent);
    fflush(stdout);
}

static void argon_progress(uint32_t completed, uint32_t total) {
    if (total == 0U) return;
    uint32_t percent = (uint32_t)((uint64_t)completed * 100U / total);
    render_argon_progress(percent < 100U ? percent : 99U);
}

static void derive_bip39_entropy(char *primary, size_t primary_len,
                                 const uint8_t context_digest[32], uint32_t wallet,
                                 uint8_t entropy[32],
                                 uint8_t recovery_fields_fp[8]) {
    uint8_t derivation_context[32];
    uint8_t argon_ad[64];
    uint8_t secret_binding[64] = {0};
    uint8_t master[ARGON2_OUT_BYTES] = {0};
    argon2_context a2;
    (void)lock_secret_memory(secret_binding, sizeof(secret_binding));
    (void)lock_secret_memory(master, sizeof(master));


    derive_secret_binding(primary, primary_len, secret_binding);
    derive_derivation_context(context_digest, wallet, derivation_context);
    derive_argon_ad(context_digest, wallet, argon_ad);

    memset(&a2, 0, sizeof(a2));
    a2.out = master;
    a2.outlen = (uint32_t)sizeof(master);
    a2.pwd = (uint8_t *)primary;
    a2.pwdlen = (uint32_t)primary_len;

    a2.salt = derivation_context;
    a2.saltlen = (uint32_t)sizeof(derivation_context);
    a2.secret = NULL;
    a2.secretlen = 0U;
    a2.ad = argon_ad;
    a2.adlen = (uint32_t)sizeof(argon_ad);
    a2.t_cost = ARGON2_TIME_COST;
    a2.m_cost = ARGON2_MEMORY_KIB;
    a2.lanes = ARGON2_LANES;
    a2.threads = ARGON2_LANES;
    a2.version = ARGON2_VERSION_13;
    a2.allocate_cbk = secure_argon_alloc;
    a2.free_cbk = secure_argon_free;
    a2.flags = ARGON2_FLAG_CLEAR_PASSWORD;

    printf("\n[%s Argon2id started: 8 GiB, t=3, p=4 %s]\n", BLUE, RESET);
    render_argon_progress(0U);
    airgap_argon2_set_progress(argon_progress);
    int rc = argon2id_ctx(&a2);
    airgap_argon2_set_progress(NULL);
    secure_wipe(primary, primary_len);
    if (rc != ARGON2_OK) {
        fputc('\n', stdout);
        secure_wipe(derivation_context, sizeof(derivation_context));
        secure_wipe(argon_ad, sizeof(argon_ad));
        secure_wipe(secret_binding, sizeof(secret_binding));
        secure_wipe(master, sizeof(master));
        secure_wipe(&a2, sizeof(a2));
        die(rc == ARGON2_MEMORY_ALLOCATION_ERROR ?
            "cannot allocate memory for Argon2id; 8 GiB plus process/worker overhead is required" :
            argon2_error_message(rc));
    }

    derive_post_argon_keys(master, secret_binding, derivation_context, argon_ad, context_digest, wallet,
                           entropy, recovery_fields_fp);

    secure_wipe(derivation_context, sizeof(derivation_context));
    secure_wipe(argon_ad, sizeof(argon_ad));
    secure_wipe(secret_binding, sizeof(secret_binding));
    secure_wipe(master, sizeof(master));
    secure_wipe(&a2, sizeof(a2));
    if (stop_requested) {
        secure_wipe(entropy, 32U);
        secure_wipe(recovery_fields_fp, 8U);
        fputc('\n', stdout);
        die("cancelled");
    }
    render_argon_progress(100U);
    fputc('\n', stdout);
}


static int selftest_wordlist(void) {
    static const uint8_t expected[32] = {
        0x2f,0x5e,0xed,0x53,0xa4,0x72,0x7b,0x4b,
        0xf8,0x88,0x0d,0x8f,0x3f,0x19,0x9e,0xfc,
        0x90,0xe5,0x85,0x03,0x64,0x6d,0x9f,0xf8,
        0xef,0xf3,0xa2,0xed,0x3b,0x24,0xdb,0xda
    };
    uint8_t digest[32];
    uint8_t buf[16384];
    size_t p = 0U;

    for (size_t i = 0; i < 2048U; i++) {
        size_t n = strlen(wordlist[i]);
        if (n == 0U || p + n + 1U > sizeof(buf)) return 0;
        memcpy(buf + p, wordlist[i], n);
        p += n;
        buf[p++] = '\n';
    }
    sha256_hash(buf, p, digest);
    int ok = constant_time_equal(digest, expected, sizeof(digest));
    secure_wipe(buf, sizeof(buf));
    secure_wipe(digest, sizeof(digest));
    return ok;
}

static int selftest_bip39(void) {
    uint8_t entropy[32] = {0};
    char mnemonic[512];
    static const char *expected =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon art";

    bip39_from_entropy_256(entropy, mnemonic, sizeof(mnemonic));
    int ok = strcmp(mnemonic, expected) == 0;
    secure_wipe(entropy, sizeof(entropy));
    secure_wipe(mnemonic, sizeof(mnemonic));
    return ok;
}

static int selftest_input_framing(void) {
    char primary[] = "public test phrase 12345";
    recovery_context rc = {"Van Dijk", "De Vries"};
    uint8_t binding[64], digest[32], context[32], ad[64], master[64], entropy[32], fp[8];
    ascii_lowercase_inplace(rc.father_last_name);
    ascii_lowercase_inplace(rc.mother_maiden_last_name);
    for (size_t i = 0; i < sizeof(master); i++) master[i] = (uint8_t)i;
    derive_secret_binding(primary, strlen(primary), binding);
    build_recovery_context_digest(&rc, digest);
    derive_derivation_context(digest, 42U, context);
    derive_argon_ad(digest, 42U, ad);
    derive_post_argon_keys(master, binding, context, ad, digest, 42U, entropy, fp);
    int ok = constant_time_equal(binding, expected_binding, sizeof(binding)) &&
             constant_time_equal(digest, expected_context, sizeof(digest)) &&
             constant_time_equal(context, expected_derivation_context, sizeof(context)) &&
             constant_time_equal(ad, expected_ad, sizeof(ad)) &&
             constant_time_equal(entropy, expected_entropy, sizeof(entropy)) &&
             constant_time_equal(fp, expected_recovery_fp, sizeof(fp));
    secure_wipe(primary, sizeof(primary)); secure_wipe(&rc, sizeof(rc));
    secure_wipe(binding, sizeof(binding)); secure_wipe(digest, sizeof(digest));
    secure_wipe(context, sizeof(context)); secure_wipe(ad, sizeof(ad));
    secure_wipe(master, sizeof(master)); secure_wipe(entropy, sizeof(entropy));
    secure_wipe(fp, sizeof(fp));
    return ok;
}

static int selftest_argon2id(void) {
    uint8_t pwd[32], salt[16], secret[16], ad[12], out[32];
    static const uint8_t expected[32] = { 0x63,0xa6,0x63,0x4b,0x43,0x97,0xb5,0x60,0x21,0xbd,0xab,0xe1,0x22,0xa0,0x74,0x30,0x4c,0x2e,0xf9,0xe9,0x56,0xaa,0x1b,0xbe,0x0e,0x05,0x5a,0xd8,0x38,0xff,0x82,0xe3 };
    argon2_context a2;
    memset(pwd, 0x01, sizeof(pwd));
    memset(salt, 0x02, sizeof(salt));
    memset(secret, 0x03, sizeof(secret));
    memset(ad, 0x04, sizeof(ad));
    memset(&a2, 0, sizeof(a2));
    a2.out = out;
    a2.outlen = (uint32_t)sizeof(out);
    a2.pwd = pwd;
    a2.pwdlen = (uint32_t)sizeof(pwd);
    a2.salt = salt;
    a2.saltlen = (uint32_t)sizeof(salt);
    a2.secret = secret;
    a2.secretlen = (uint32_t)sizeof(secret);
    a2.ad = ad;
    a2.adlen = (uint32_t)sizeof(ad);
    a2.t_cost = 3U;
    a2.m_cost = 32U;
    a2.lanes = 4U;
    a2.threads = 4U;
    a2.version = ARGON2_VERSION_13;
    a2.allocate_cbk = secure_argon_alloc;
    a2.free_cbk = secure_argon_free;
    a2.flags = 0U;

    int rc = argon2id_ctx(&a2);
    int ok = (rc == ARGON2_OK) && constant_time_equal(out, expected, sizeof(out));
    secure_wipe(pwd, sizeof(pwd));
    secure_wipe(salt, sizeof(salt));
    secure_wipe(secret, sizeof(secret));
    secure_wipe(ad, sizeof(ad));
    secure_wipe(out, sizeof(out));
    return ok;
}

static int selftest_bip86(void) {
    static const char *mnemonic =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    static const char *expected0 =
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
    static const char *expected1 =
        "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh";

    uint8_t seed[64];
    ext_key master, p86, c86, a86, base, addr;
    uint8_t xonly[32];
    char address[128];
    int ok = 1;

    memset(&master, 0, sizeof(master));
    memset(&p86, 0, sizeof(p86));
    memset(&c86, 0, sizeof(c86));
    memset(&a86, 0, sizeof(a86));
    memset(&base, 0, sizeof(base));
    memset(&addr, 0, sizeof(addr));

    bip39_seed_no_passphrase(mnemonic, seed);
    bip32_from_seed(seed, &master);
    (void)bip32_ckd_priv(&master, 86U | HARDENED, &p86);
    (void)bip32_ckd_priv(&p86, 0U | HARDENED, &c86);
    (void)bip32_ckd_priv(&c86, 0U | HARDENED, &a86);
    (void)bip32_ckd_priv(&a86, 0U, &base);

    (void)bip32_ckd_priv(&base, 0U, &addr);
    tap_output_key(addr.pub, xonly);
    bech32m_encode_p2tr(xonly, address, sizeof(address));
    if (strcmp(address, expected0) != 0) ok = 0;
    secure_wipe(&addr, sizeof(addr));
    secure_wipe(xonly, sizeof(xonly));
    secure_wipe(address, sizeof(address));

    (void)bip32_ckd_priv(&base, 1U, &addr);
    tap_output_key(addr.pub, xonly);
    bech32m_encode_p2tr(xonly, address, sizeof(address));
    if (strcmp(address, expected1) != 0) ok = 0;

    secure_wipe(seed, sizeof(seed));
    secure_wipe(&master, sizeof(master));
    secure_wipe(&p86, sizeof(p86));
    secure_wipe(&c86, sizeof(c86));
    secure_wipe(&a86, sizeof(a86));
    secure_wipe(&base, sizeof(base));
    secure_wipe(&addr, sizeof(addr));
    secure_wipe(xonly, sizeof(xonly));
    secure_wipe(address, sizeof(address));
    return ok;
}

static int selftest_qr(void) {
    static const char *upper_address =
        "BC1P5CYXNUXMEUWUVKWFEM96LQZSZD02N6XDCJRS20CAC6YQJJWUDPXQKEDRCR";
    airgap_qr qr;
    memset(&qr, 0, sizeof(qr));
    if (!airgap_qr_encode_alphanumeric(upper_address, &qr)) return 0;
    if (qr.module[3][3] == 0U || qr.module[3][AIRGAP_QR_SIZE - 4] == 0U ||
        qr.module[AIRGAP_QR_SIZE - 4][3] == 0U ||
        qr.module[AIRGAP_QR_SIZE - 8][8] == 0U) {
        memset(&qr, 0, sizeof(qr));
        return 0;
    }
    memset(&qr, 0, sizeof(qr));
    return 1;
}

static int run_selftests(void) {
    if (!selftest_wordlist()) {
        fprintf(stderr, "BIP39 English wordlist integrity self-test FAILED\n");
        return 0;
    }
    if (!selftest_bip39()) {
        fprintf(stderr, "BIP39 self-test FAILED\n");
        return 0;
    }
    if (!selftest_input_framing()) {
        fprintf(stderr, "Input framing/key-schedule self-test FAILED\n");
        return 0;
    }
    if (!selftest_argon2id()) {
        fprintf(stderr, "Argon2id raw self-test FAILED\n");
        return 0;
    }
    if (!selftest_bip86()) {
        fprintf(stderr, "BIP86 official-vector self-test FAILED\n");
        return 0;
    }
    if (!selftest_qr()) {
        fprintf(stderr, "QR encoder self-test FAILED\n");
        return 0;
    }
    return 1;
}

static int print_address_qr(const char *address) {
    char qr_text[128] = {0};
    airgap_qr qr;
    size_t addr_len;
    memset(&qr, 0, sizeof(qr));

    if (address == NULL) return 0;
    addr_len = strlen(address);
    if (addr_len == 0U || addr_len >= sizeof(qr_text)) {
        fprintf(stderr, "%sWarning:%s address is invalid for QR buffer.\n", YELLOW, RESET);
        return 0;
    }

    for (size_t i = 0; i < addr_len; i++) {
        unsigned char c = (unsigned char)address[i];
        qr_text[i] = (char)((c >= 'a' && c <= 'z') ? (c - ('a' - 'A')) : c);
    }
    qr_text[addr_len] = '\0';

    if (!airgap_qr_encode_alphanumeric(qr_text, &qr)) {
        fprintf(stderr, "%sWarning:%s QR encoding failed; use the printed address.\n",
                YELLOW, RESET);
        secure_wipe(qr_text, sizeof(qr_text));
        secure_wipe(&qr, sizeof(qr));
        return 0;
    }

    if (!airgap_qr_print_terminal(&qr)) {
        fprintf(stderr,
            "%sWarning:%s QR not rendered (stdout not interactive or terminal too narrow).\n",
            YELLOW, RESET);
        secure_wipe(qr_text, sizeof(qr_text));
        secure_wipe(&qr, sizeof(qr));
        return 0;
    }

    secure_wipe(qr_text, sizeof(qr_text));
    secure_wipe(&qr, sizeof(qr));
    return 1;
}


int main(int argc, char **argv) {
    static char primary_secret[PRIMARY_SECRET_MAX_LEN + 2U];
    static char derivation_secret[PRIMARY_SECRET_MAX_LEN + 2U];
    uint32_t wallet;
    static ext_key addr;
    static recovery_context recovery;
    static uint8_t recovery_context_digest[32];
    static uint8_t recovery_fields_fp[8];
    static uint8_t entropy[32];
    static char mnemonic[512];
    static uint8_t seed[64];
    static ext_key master, p86, c86, a86, base;
    size_t primary_len;
    uint32_t path[4];

    if (atexit(cleanup_process) != 0) die("exit cleanup registration failed");
    register_cleanup_buffer(&post_workspace, sizeof(post_workspace));
    register_cleanup_buffer(primary_secret, sizeof(primary_secret));
    register_cleanup_buffer(derivation_secret, sizeof(derivation_secret));
    register_cleanup_buffer(wallet_input_buffer, sizeof(wallet_input_buffer));
    register_cleanup_buffer(&addr, sizeof(addr));
    register_cleanup_buffer(&recovery, sizeof(recovery));
    register_cleanup_buffer(recovery_context_digest, sizeof(recovery_context_digest));
    register_cleanup_buffer(recovery_fields_fp, sizeof(recovery_fields_fp));
    register_cleanup_buffer(entropy, sizeof(entropy));
    register_cleanup_buffer(mnemonic, sizeof(mnemonic));
    register_cleanup_buffer(seed, sizeof(seed));
    register_cleanup_buffer(&master, sizeof(master));
    register_cleanup_buffer(&p86, sizeof(p86));
    register_cleanup_buffer(&c86, sizeof(c86));
    register_cleanup_buffer(&a86, sizeof(a86));
    register_cleanup_buffer(&base, sizeof(base));
    if (setvbuf(stdin, NULL, _IONBF, 0) != 0 ||
        setvbuf(stdout, NULL, _IONBF, 0) != 0 ||
        setvbuf(stderr, NULL, _IONBF, 0) != 0) die("stdio hardening failed");
    install_signal_handlers();
    enable_windows_ansi();
    if (argc == 1 && interactive_terminal_available()) clear_terminal();
    disable_core_dumps();

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (ctx == NULL) die("secp256k1 context creation failed");
    {
        uint8_t random_seed[32];
        if (!os_random_bytes(random_seed, sizeof(random_seed)))
            die("OS randomness unavailable for secp256k1 blinding");
        if (!secp256k1_context_randomize(ctx, random_seed)) {
            secure_wipe(random_seed, sizeof(random_seed));
            die("secp256k1 context randomization failed");
        }
        secure_wipe(random_seed, sizeof(random_seed));
    }

    if (!run_selftests()) die("cryptographic self-tests failed");

    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) {
        printf("All cryptographic self-tests passed.\n");
        secp256k1_context_destroy(ctx);
        ctx = NULL;
        return EXIT_SUCCESS;
    }
    if (argc == 2 && strcmp(argv[1], "--qr-test") == 0) {
        static const char *test_address =
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
        int rendered;
        printf("Official BIP86 first address:\n%s\n", test_address);
        rendered = print_address_qr(test_address);
        secp256k1_context_destroy(ctx);
        ctx = NULL;
        return rendered ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    if (argc != 1) {
        fprintf(stderr, "Usage: %s [--self-test | --qr-test]\n", argv[0]);
        secp256k1_context_destroy(ctx);
        ctx = NULL;
        return EXIT_FAILURE;
    }

    if (!interactive_terminal_available())
        die("wallet generation requires terminal input, output and error streams; redirection is refused");

    protect_process_memory();
    for (size_t i = 0; i < cleanup_buffer_count; i++) {
        (void)lock_secret_memory(cleanup_buffers[i].data, cleanup_buffers[i].size);
    }
    if (!enable_terminal_echo()) die("visible terminal input unavailable");

    check_swap_active();
    print_header();

    fputs("Type your secret, or enter a file path starting with /.\n", stdout);
    primary_len = read_secret("Secret",
                                        primary_secret, sizeof(primary_secret),
                                        PRIMARY_SECRET_MIN_LEN, PRIMARY_SECRET_MAX_LEN);
    fputc('\n', stdout);
    read_recovery_context(&recovery);
    build_recovery_context_digest(&recovery, recovery_context_digest);
    if (stop_requested) die("cancelled");
    if (!read_wallet_number(&wallet, 1)) return EXIT_SUCCESS;
    do {
        displayed_wallet = wallet;
        wallet_display_active = 1;
        clear_terminal();
        print_header();
        memcpy(derivation_secret, primary_secret, primary_len);
        derive_bip39_entropy(derivation_secret, primary_len, recovery_context_digest, wallet,
                             entropy, recovery_fields_fp);
        secure_wipe(derivation_secret, sizeof(derivation_secret));

        print_fingerprint64("\nRecovery Fields Fingerprint", recovery_fields_fp);

        secure_wipe(recovery_fields_fp, sizeof(recovery_fields_fp));

        bip39_from_entropy_256(entropy, mnemonic, sizeof(mnemonic));
        secure_wipe(entropy, sizeof(entropy));

        bip39_seed_no_passphrase(mnemonic, seed);
        bip32_from_seed(seed, &master);
        secure_wipe(seed, sizeof(seed));
        path[0] = bip32_ckd_priv(&master, 86U | HARDENED, &p86);
        secure_wipe(&master, sizeof(master));
        path[1] = bip32_ckd_priv(&p86, 0U | HARDENED, &c86);
        secure_wipe(&p86, sizeof(p86));
        path[2] = bip32_ckd_priv(&c86, 0U | HARDENED, &a86);
        secure_wipe(&c86, sizeof(c86));
        path[3] = bip32_ckd_priv(&a86, 0U, &base);
        secure_wipe(&a86, sizeof(a86));

        if (stop_requested) die("cancelled");

        printf("\n%sBIP39 mnemonic (24 words):%s\n", GREEN, RESET);
        print_mnemonic_cols(mnemonic);
        secure_wipe(mnemonic, sizeof(mnemonic));
        printf("\n");
        printf("\n%sSECURITY NOTE:%s The generated 24 words provide full wallet access.\n\n",YELLOW, RESET);

        {
            uint8_t xonly[32] = {0};
            char address[128] = {0};
            uint32_t actual = bip32_ckd_priv(&base, 0U, &addr);

            secure_wipe(&base, sizeof(base));
            tap_output_key(addr.pub, xonly);
            secure_wipe(&addr, sizeof(addr));
            bech32m_encode_p2tr(xonly, address, sizeof(address));

            uint8_t wallet_fp[8] = {0};

            printf("BTC Taproot BIP86 address:\n");
            printf("m/%u'/%u'/%u'/%u/%u: %s\n",
                   path[0] & ~HARDENED, path[1] & ~HARDENED,
                   path[2] & ~HARDENED, path[3], actual, address);
            if (path[0] != (86U | HARDENED) || path[1] != HARDENED ||
                path[2] != HARDENED || path[3] != 0U || actual != 0U)
                printf("  [requested m/86'/0'/0'/0/0; BIP32 invalid-child skip occurred]");
            fputc('\n', stdout);

            derive_wallet_address_fingerprint(address, wallet_fp);

            (void)print_address_qr(address);

            print_fingerprint64("\nWallet Address Fingerprint", wallet_fp);

            secure_wipe(wallet_fp, sizeof(wallet_fp));
            secure_wipe(&addr, sizeof(addr));
            secure_wipe(xonly, sizeof(xonly));
            secure_wipe(address, sizeof(address));
        }




    } while (read_wallet_number(&wallet, 0));

    secp256k1_context_destroy(ctx);
    ctx = NULL;
    return EXIT_SUCCESS;
}
