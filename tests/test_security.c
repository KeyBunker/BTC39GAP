#include "test_memory.h"
#include "../argon2/core.h"
#include "../argon2/thread.h"
#include <stdatomic.h>
#ifndef _WIN32
#include <time.h>
#endif

static int checked_thread_create(argon2_thread_handle_t *, argon2_thread_func_t, void *);
static int checked_thread_join(argon2_thread_handle_t);
static void *checked_calloc(size_t, size_t);
static void checked_fill_segment(const argon2_instance_t *, argon2_position_t);
#define argon2_thread_create checked_thread_create
#define argon2_thread_join checked_thread_join
#define calloc checked_calloc
#define fill_segment checked_fill_segment
#undef _DEFAULT_SOURCE
#include "../argon2/core.c"
#undef argon2_thread_create
#undef argon2_thread_join
#undef calloc
#undef fill_segment

static int fail_create_at, fail_join_at, fail_calloc_at, early_join_failure;
static int create_calls, join_calls, calloc_calls, workers_started, workers_joined;
static unsigned progress_calls;
static argon2_thread_handle_t deferred_join;
static int has_deferred_join;
static atomic_int release_delayed_worker;
static struct {
    argon2_thread_func_t function;
    void *argument;
    atomic_int done;
    int delay;
} jobs[48]; /* t=3, four slices and four lanes. */
static _Thread_local int current_job = -1;

static void test_delay(void) {
#ifdef _WIN32
    Sleep(20);
#else
    const struct timespec delay = {0, 20000000};
    (void)nanosleep(&delay, NULL);
#endif
}

static void check_workers_finished(void) {
    for (int i = 0; i < workers_started; i++) {
        CHECK(atomic_load_explicit(&jobs[i].done, memory_order_acquire) == 1);
    }
    CHECK(workers_started == workers_joined + has_deferred_join);
}

static void reset_checks(void) {
    reset_memory_probe();
    memory_probe.before_unlock = check_workers_finished;
    fail_create_at = fail_join_at = fail_calloc_at = -1;
    early_join_failure = 0;
    create_calls = join_calls = calloc_calls = workers_started = workers_joined = 0;
    has_deferred_join = 0;
    progress_calls = 0U;
    atomic_init(&release_delayed_worker, 0);
}

#ifdef _WIN32
static unsigned __stdcall worker_entry(void *argument)
#else
static void *worker_entry(void *argument)
#endif
{
    current_job = (int)((uintptr_t)argument - 1U);
    return jobs[current_job].function(jobs[current_job].argument);
}

static int checked_thread_create(argon2_thread_handle_t *handle,
                                 argon2_thread_func_t function, void *argument) {
    if (create_calls++ == fail_create_at) return -1;
    CHECK(workers_started < (int)(sizeof(jobs) / sizeof(jobs[0])));
    int index = workers_started;
    jobs[index].function = function;
    jobs[index].argument = argument;
    jobs[index].delay = early_join_failure && index == fail_join_at;
    atomic_init(&jobs[index].done, 0);
    int result = argon2_thread_create(handle, worker_entry, (void *)(uintptr_t)(index + 1));
    CHECK(result == 0);
    workers_started++;
    return result;
}

static void checked_fill_segment(const argon2_instance_t *instance, argon2_position_t position) {
    if (current_job >= 0 && jobs[current_job].delay) {
        while (!atomic_load_explicit(&release_delayed_worker, memory_order_acquire)) test_delay();
        /* The failed join returns while this worker still owns the arena. */
        test_delay();
    }
    fill_segment(instance, position);
    if (current_job >= 0) atomic_store_explicit(&jobs[current_job].done, 1, memory_order_release);
}

static int checked_thread_join(argon2_thread_handle_t handle) {
    int failure = join_calls++ == fail_join_at;
    if (failure && early_join_failure) {
        CHECK(!has_deferred_join);
        CHECK(atomic_load_explicit(&jobs[fail_join_at].done, memory_order_acquire) == 0);
        deferred_join = handle;
        has_deferred_join = 1;
        atomic_store_explicit(&release_delayed_worker, 1, memory_order_release);
        return -1;
    }
    CHECK(argon2_thread_join(handle) == 0);
    workers_joined++;
    return failure ? -1 : 0;
}

static void *checked_calloc(size_t count, size_t size) {
    if (calloc_calls++ == fail_calloc_at) return NULL;
    return calloc(count, size);
}

static void check_progress(uint32_t completed, uint32_t total) {
    CHECK(total == 12U && completed == progress_calls + 1U);
    CHECK(memory_probe.release_calls == 0U);
    progress_calls++;
}

static void test_boundaries(void) {
    static const size_t lengths[] = {0U,1U,2U,7U,8U,15U,16U,31U,32U,63U,64U,127U,128U,129U,255U};
    uint8_t guard[300];
    test_case = "unaligned wipe boundaries and no-op arguments";
    for (size_t offset = 1U; offset <= 16U; offset++) {
        for (size_t i = 0U; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
            size_t length = lengths[i];
            reset_checks();
            memory_probe.real_release = 0;
            memory_probe.memory = guard + offset;
            memory_probe.bytes = length;
            memset(guard, 0xa5, sizeof(guard));
            secure_argon_free(guard + offset, length);
            CHECK(bytes_are(guard, offset, 0xa5));
            CHECK(bytes_are(guard + offset, length, 0U));
            CHECK(bytes_are(guard + offset + length, sizeof(guard) - offset - length, 0xa5));
            if (length != 0U) check_released(length);
            else CHECK(memory_probe.unlock_calls == 0U && memory_probe.release_calls == 0U);
        }
    }
    reset_checks();
    secure_argon_free(NULL, SIZE_MAX);
    secure_argon_free(NULL, 0U);
    CHECK(memory_probe.unlock_calls == 0U && memory_probe.release_calls == 0U);
    CHECK(secure_argon_alloc(NULL, 1U) != 0);
    uint8_t *memory = NULL;
    CHECK(secure_argon_alloc(&memory, 0U) != 0);
    CHECK(memory_probe.map_calls == 0U);
}

static void test_real_mapping(size_t bytes, int lock_failure, int unlock_failure) {
    uint8_t *memory = NULL;
    reset_checks();
    memory_lock_failed = 0;
    memory_probe.fail_lock = lock_failure;
    memory_probe.fail_unlock = unlock_failure;
    CHECK(secure_argon_alloc(&memory, bytes) == 0);
    CHECK(memory_probe.map_calls == 1U && memory_probe.lock_calls == 1U);
    if (lock_failure) CHECK(memory_lock_failed == 1);
    for (size_t i = 0U; i < bytes; i++) memory[i] = (uint8_t)(i % 255U + 1U);
    secure_argon_free(memory, bytes);
    check_released(bytes);
}

static void test_allocation_failures(void) {
    const size_t sizes[] = {1U, (size_t)UINT32_MAX + 1U, (size_t)(UINT64_C(8) << 30), SIZE_MAX};
    uint8_t sentinel = 0xa5;
    test_case = "OS allocation failure and 64-bit size forwarding";
    for (size_t i = 0U; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        reset_checks();
        memory_probe.fail_map = 1;
        uint8_t *memory = &sentinel;
        CHECK(secure_argon_alloc(&memory, sizes[i]) != 0);
        CHECK(memory == NULL && sentinel == 0xa5);
        CHECK(memory_probe.map_calls == 1U && memory_probe.requested_bytes == sizes[i]);
        CHECK(memory_probe.lock_calls == 0U && memory_probe.release_calls == 0U);
    }
    reset_checks();
    argon2_context a2;
    memset(&a2, 0, sizeof(a2));
    a2.allocate_cbk = secure_argon_alloc;
    uint8_t *memory = NULL;
    CHECK(allocate_memory(&a2, &memory, SIZE_MAX / 1024U + 1U, 1024U) == ARGON2_MEMORY_ALLOCATION_ERROR);
    CHECK(memory_probe.map_calls == 0U && memory == NULL);
}

static void test_argon_cleanup(int clear_flag, uint32_t threads, int create_failure,
                               int join_failure, int calloc_failure, int map_failure, int early_join) {
    static const uint8_t expected[32] = {
        0x63,0xa6,0x63,0x4b,0x43,0x97,0xb5,0x60,0x21,0xbd,0xab,0xe1,0x22,0xa0,0x74,0x30,
        0x4c,0x2e,0xf9,0xe9,0x56,0xaa,0x1b,0xbe,0x0e,0x05,0x5a,0xd8,0x38,0xff,0x82,0xe3
    };
    uint8_t pwd[32], salt[16], secret[16], ad[12], out[32];
    argon2_context a2;
    char label[160];
    (void)snprintf(label, sizeof(label), "clear=%d threads=%u create=%d join=%d calloc=%d map=%d early=%d",
                   clear_flag, threads, create_failure, join_failure, calloc_failure, map_failure, early_join);
    test_case = label;
    int saved_clear_flag = FLAG_clear_internal_memory;
    reset_checks();
    fail_create_at = create_failure;
    fail_join_at = join_failure;
    fail_calloc_at = calloc_failure;
    early_join_failure = early_join;
    memory_probe.fail_map = map_failure;
    FLAG_clear_internal_memory = clear_flag;
    memset(pwd, 1, sizeof(pwd)); memset(salt, 2, sizeof(salt));
    memset(secret, 3, sizeof(secret)); memset(ad, 4, sizeof(ad));
    memset(out, 0xa5, sizeof(out));
    memset(&a2, 0, sizeof(a2));
    a2.out = out; a2.outlen = (uint32_t)sizeof(out);
    a2.pwd = pwd; a2.pwdlen = (uint32_t)sizeof(pwd);
    a2.salt = salt; a2.saltlen = (uint32_t)sizeof(salt);
    a2.secret = secret; a2.secretlen = (uint32_t)sizeof(secret);
    a2.ad = ad; a2.adlen = (uint32_t)sizeof(ad);
    a2.t_cost = 3U; a2.m_cost = 32U; a2.lanes = 4U; a2.threads = threads;
    a2.version = ARGON2_VERSION_13;
    a2.allocate_cbk = secure_argon_alloc;
    a2.free_cbk = secure_argon_free;
    a2.flags = ARGON2_FLAG_CLEAR_PASSWORD | ARGON2_FLAG_CLEAR_SECRET;
    airgap_argon2_set_progress(check_progress);
    int result = argon2id_ctx(&a2);
    airgap_argon2_set_progress(NULL);
    FLAG_clear_internal_memory = saved_clear_flag;
    if (has_deferred_join) CHECK(argon2_thread_join(deferred_join) == 0);
    CHECK(memory_probe.map_calls == 1U);
    CHECK(bytes_are(salt, sizeof(salt), 2U) && bytes_are(ad, sizeof(ad), 4U));
    if (map_failure) {
        CHECK(result == ARGON2_MEMORY_ALLOCATION_ERROR);
        CHECK(memory_probe.unlock_calls == 0U && memory_probe.release_calls == 0U);
        CHECK(progress_calls == 0U && workers_started == 0);
    } else {
        check_released(32U * 1024U);
        CHECK(bytes_are(pwd, sizeof(pwd), 0U) && bytes_are(secret, sizeof(secret), 0U));
        CHECK(a2.pwdlen == 0U && a2.secretlen == 0U);
        if (calloc_failure >= 0) CHECK(result == ARGON2_MEMORY_ALLOCATION_ERROR);
        else if (create_failure >= 0 || join_failure >= 0) CHECK(result == ARGON2_THREAD_FAIL);
        else {
            CHECK(result == ARGON2_OK && progress_calls == 12U);
            CHECK(memcmp(out, expected, sizeof(out)) == 0);
        }
    }
    if (result != ARGON2_OK) CHECK(bytes_are(out, sizeof(out), 0xa5));
    test_case = "between Argon2 cases";
}

int main(void) {
    test_boundaries();
    test_allocation_failures();
#ifdef _WIN32
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    size_t page = (size_t)info.dwPageSize;
#else
    long page_size = sysconf(_SC_PAGESIZE);
    CHECK(page_size > 1);
    size_t page = (size_t)page_size;
#endif
    const size_t sizes[] = {1U, page - 1U, page, page + 1U, 2U * page + 17U, 2097152U + 17U};
    test_case = "real mappings at page boundaries; lock/unlock failures";
    for (size_t i = 0U; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        test_real_mapping(sizes[i], 0, 0);
        test_real_mapping(sizes[i], 1, 1);
    }
    const int failures[] = {0,1,2,3,4,17,47};
    for (int clear_flag = 0; clear_flag <= 1; clear_flag++) {
        test_argon_cleanup(clear_flag, 1U, -1, -1, -1, 0, 0);
        for (uint32_t threads = 2U; threads <= 4U; threads += 2U) {
            test_argon_cleanup(clear_flag, threads, -1, -1, -1, 0, 0);
            for (size_t i = 0U; i < sizeof(failures) / sizeof(failures[0]); i++) {
                test_argon_cleanup(clear_flag, threads, failures[i], -1, -1, 0, 0);
                test_argon_cleanup(clear_flag, threads, -1, failures[i], -1, 0, 0);
            }
            test_argon_cleanup(clear_flag, threads, -1, -1, 0, 0, 0);
            test_argon_cleanup(clear_flag, threads, -1, -1, 1, 0, 0);
            test_argon_cleanup(clear_flag, threads, -1, -1, -1, 1, 0);
            test_argon_cleanup(clear_flag, threads, -1, 1, -1, 0, 1);
        }
    }
    puts("Security tests passed (wipe boundaries, OS failures, worker failures, active-worker join failure and progress).");
    return EXIT_SUCCESS;
}
