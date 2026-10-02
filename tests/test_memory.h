#ifndef BTC39GAP_TEST_MEMORY_H
#define BTC39GAP_TEST_MEMORY_H

/* Include the actual application with test-local OS allocation/release probes.
 * No production test hooks, linker wrapping or reads after unmapping are used.
 * Both test_security and test_full inspect EVERY byte at both boundaries. */
#ifndef _WIN32
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif
#include "test_common.h"
#ifdef _WIN32
#include <windows.h>
static LPVOID WINAPI probed_map(LPVOID, SIZE_T, DWORD, DWORD);
static BOOL WINAPI probed_lock(LPVOID, SIZE_T);
static BOOL WINAPI probed_unlock(LPVOID, SIZE_T);
static BOOL WINAPI probed_release(LPVOID, SIZE_T, DWORD);
#define VirtualAlloc probed_map
#define VirtualLock probed_lock
#define VirtualUnlock probed_unlock
#define VirtualFree probed_release
#else
#include <sys/mman.h>
static void *probed_map(void *, size_t, int, int, int, off_t);
static int probed_lock(const void *, size_t);
static int probed_unlock(const void *, size_t);
static int probed_release(void *, size_t);
#define mmap probed_map
#define mlock probed_lock
#define munlock probed_unlock
#define munmap probed_release
#endif
#define main btc39gap_application_main
#include "../BTC39GAP.c"
#undef main
#ifdef _WIN32
#undef VirtualAlloc
#undef VirtualLock
#undef VirtualUnlock
#undef VirtualFree
#else
#undef mmap
#undef mlock
#undef munlock
#undef munmap
#endif

static struct {
    uint8_t *memory;
    size_t bytes, requested_bytes, verified_before_unlock, verified_before_release;
    unsigned map_calls, lock_calls, unlock_calls, release_calls;
    int real_release, fail_map, fail_lock, fail_unlock;
    void (*before_unlock)(void);
} memory_probe;

static void reset_memory_probe(void) {
    memset(&memory_probe, 0, sizeof(memory_probe));
    memory_probe.real_release = 1;
}

static void check_before_unlock(const void *memory, size_t bytes) {
    CHECK(memory != NULL && memory == memory_probe.memory);
    CHECK(bytes == memory_probe.bytes);
    CHECK(memory_probe.unlock_calls == 0U && memory_probe.release_calls == 0U);
    if (memory_probe.before_unlock != NULL) memory_probe.before_unlock();
    CHECK(bytes_are(memory, bytes, 0U));
    memory_probe.verified_before_unlock = bytes;
    memory_probe.unlock_calls++;
}

static void check_before_release(const void *memory) {
    CHECK(memory == memory_probe.memory);
    CHECK(memory_probe.unlock_calls == 1U && memory_probe.release_calls == 0U);
    CHECK(bytes_are(memory, memory_probe.bytes, 0U));
    memory_probe.verified_before_release = memory_probe.bytes;
    memory_probe.release_calls++;
}

#ifdef _WIN32
static LPVOID WINAPI probed_map(LPVOID address, SIZE_T bytes, DWORD type, DWORD protect) {
    CHECK(address == NULL && type == (MEM_RESERVE | MEM_COMMIT) && protect == PAGE_READWRITE);
    memory_probe.map_calls++;
    memory_probe.requested_bytes = bytes;
    if (memory_probe.fail_map) return NULL;
    void *memory = VirtualAlloc(address, bytes, type, protect);
    if (memory != NULL) {
        memory_probe.memory = memory;
        memory_probe.bytes = bytes;
    }
    return memory;
}
static BOOL WINAPI probed_lock(LPVOID memory, SIZE_T bytes) {
    if (memory == memory_probe.memory) {
        CHECK(bytes == memory_probe.bytes);
        memory_probe.lock_calls++;
        if (memory_probe.fail_lock) return FALSE;
    }
    return VirtualLock(memory, bytes);
}
static BOOL WINAPI probed_unlock(LPVOID memory, SIZE_T bytes) {
    check_before_unlock(memory, bytes);
    if (memory_probe.fail_unlock) return FALSE;
    return memory_probe.real_release ? VirtualUnlock(memory, bytes) : TRUE;
}
static BOOL WINAPI probed_release(LPVOID memory, SIZE_T bytes, DWORD type) {
    CHECK(bytes == 0U && type == MEM_RELEASE);
    check_before_release(memory);
    if (memory_probe.real_release) CHECK(VirtualFree(memory, bytes, type) != 0);
    return TRUE;
}
#else
static void *probed_map(void *address, size_t bytes, int protect, int flags, int fd, off_t offset) {
    CHECK(address == NULL && protect == (PROT_READ | PROT_WRITE));
    CHECK((flags & MAP_PRIVATE) != 0 && fd == -1 && offset == 0);
    memory_probe.map_calls++;
    memory_probe.requested_bytes = bytes;
    if (memory_probe.fail_map) return MAP_FAILED;
    void *memory = mmap(address, bytes, protect, flags, fd, offset);
    if (memory != MAP_FAILED) {
        memory_probe.memory = memory;
        memory_probe.bytes = bytes;
    }
    return memory;
}
static int probed_lock(const void *memory, size_t bytes) {
    if (memory == memory_probe.memory) {
        CHECK(bytes == memory_probe.bytes);
        memory_probe.lock_calls++;
        if (memory_probe.fail_lock) return -1;
    }
    return mlock(memory, bytes);
}
static int probed_unlock(const void *memory, size_t bytes) {
    check_before_unlock(memory, bytes);
    if (memory_probe.fail_unlock) return -1;
    return memory_probe.real_release ? munlock(memory, bytes) : 0;
}
static int probed_release(void *memory, size_t bytes) {
    CHECK(bytes == memory_probe.bytes);
    check_before_release(memory);
    if (memory_probe.real_release) CHECK(munmap(memory, bytes) == 0);
    return 0;
}
#endif

static void check_released(size_t bytes) {
    CHECK(memory_probe.unlock_calls == 1U && memory_probe.release_calls == 1U);
    CHECK(memory_probe.verified_before_unlock == bytes);
    CHECK(memory_probe.verified_before_release == bytes);
}

#endif
