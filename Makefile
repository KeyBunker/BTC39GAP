APP       := BTC39GAP
SRC_MAIN  := BTC39GAP.c
SRC_QR    := qr/qr.c
HEADERS   := $(wildcard *.h sha/*.h qr/*.h argon2/*.h argon2/blake2/*.h secp256k1/include/*.h secp256k1/src/*.h secp256k1/src/modules/*/*.h)

SRC_SHA := \
    sha/sha256.c \
    sha/sha512.c \
    sha/hmac_sha512.c \
    sha/pbkdf2.c

SRC_ARGON := argon2/argon2.c \
             argon2/core.c \
             argon2/encoding.c \
             argon2/thread.c \
             argon2/opt.c \
             argon2/blake2/blake2b.c

SRC_ARGON_ARM := argon2/argon2.c \
                 argon2/core.c \
                 argon2/encoding.c \
                 argon2/thread.c \
                 argon2/blake2/blake2b.c \
                 argon2/ref.c

SRC_SECP := \
    secp256k1/src/secp256k1.c \
    secp256k1/src/precomputed_ecmult.c \
    secp256k1/src/precomputed_ecmult_gen.c

CFLAGS_SECP :=

COMMON_INC := \
    -I. \
    -Isha \
    -Iargon2 \
    -Iargon2/blake2 \
    -Isecp256k1/include \
    -Isecp256k1/src \
    -Iqr

WARNINGS := -Wall -Wextra -Wformat=2 -Wformat-security -Wshadow -Wconversion -Wno-unused-function
HARDEN_C := -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -fno-common


CFLAGS_ARGON := -Wno-type-limits -Wno-sign-compare -Wno-conversion

UNAME_S := $(shell uname -s 2>/dev/null)
UNAME_M := $(shell uname -m 2>/dev/null)
WINDOWS_HOST := $(filter MINGW%,$(UNAME_S))
TEST_EXE := $(if $(WINDOWS_HOST),.exe,)
TEST_PROGRAMS := test_security test_terminal test_files test_reference test_full
TEST_BINS := $(addprefix tests/,$(addsuffix $(TEST_EXE),$(TEST_PROGRAMS)))
TEST_SAN_BINS := $(addprefix tests/,$(addsuffix _san$(TEST_EXE),$(TEST_PROGRAMS)))
TEST_DEPS := $(SRC_MAIN) $(SRC_QR) $(SRC_SECP) $(SRC_SHA) $(HEADERS) $(wildcard tests/*.h) Makefile
V ?= 0
REPORT := $(SHELL) tests/report.sh
ifeq ($(UNAME_S),Darwin)
SRC_ARGON_NATIVE := $(SRC_ARGON_ARM)
CFLAGS_NATIVE := -D_DARWIN_C_SOURCE -std=c17 -O2 $(COMMON_INC) $(CFLAGS_SECP) $(WARNINGS) $(HARDEN_C) $(CFLAGS_ARGON) \
    -DARGON2_NO_SSE2 -DARGON2_NO_SIMD -DARGON2_REF=1 -pthread
LDFLAGS_NATIVE := -pthread
else
ifneq ($(filter x86_64 amd64 i386 i686,$(UNAME_M)),)
SRC_ARGON_NATIVE := $(SRC_ARGON)
CFLAGS_NATIVE := -std=c17 -O2 $(COMMON_INC) $(CFLAGS_SECP) $(WARNINGS) $(HARDEN_C) $(CFLAGS_ARGON) -pthread
else
SRC_ARGON_NATIVE := $(SRC_ARGON_ARM)
CFLAGS_NATIVE := -std=c17 -O2 $(COMMON_INC) $(CFLAGS_SECP) $(WARNINGS) $(HARDEN_C) $(CFLAGS_ARGON) \
    -DARGON2_NO_SSE2 -DARGON2_NO_SIMD -DARGON2_REF=1 -pthread
endif
LDFLAGS_NATIVE := -Wl,-z,relro,-z,now,-z,noexecstack -pie -pthread
endif

ARM64_CC := aarch64-linux-gnu-gcc
CFLAGS_ARM64 := -std=c17 -O2 $(COMMON_INC) $(CFLAGS_SECP) $(WARNINGS) $(HARDEN_C) $(CFLAGS_ARGON) \
    -DARGON2_NO_SSE2 -DARGON2_NO_SIMD -DARGON2_REF=1 -pthread
LDFLAGS_ARM64 := -Wl,-z,relro,-z,now,-z,noexecstack -pie -pthread


MAC_CC ?= clang
CFLAGS_MAC := -D_DARWIN_C_SOURCE -std=c17 -O2 $(COMMON_INC) $(CFLAGS_SECP) $(WARNINGS) $(HARDEN_C) $(CFLAGS_ARGON) \
    -DARGON2_NO_SSE2 -DARGON2_NO_SIMD -DARGON2_REF=1 -pthread
LDFLAGS_MAC := -pthread

WIN64_CC := x86_64-w64-mingw32-gcc
CFLAGS_WIN64 := -std=c17 -O2 $(COMMON_INC) $(CFLAGS_SECP) $(WARNINGS) \
    -DSECP256K1_STATIC \
    -fstack-protector-strong -fno-common $(CFLAGS_ARGON)
LDFLAGS_WIN64 := -static \
    -Wl,--dynamicbase,--nxcompat,--high-entropy-va \
    -lws2_32 -lbcrypt

ifneq ($(WINDOWS_HOST),)
ifeq ($(origin CC),default)
CC := gcc
endif
APP := BTC39GAP.exe
SRC_ARGON_NATIVE := $(SRC_ARGON)
CFLAGS_NATIVE = $(CFLAGS_WIN64)
LDFLAGS_NATIVE = $(LDFLAGS_WIN64)
WIN64_CC := $(CC)
endif

all: $(APP)

$(APP): $(SRC_MAIN) $(SRC_QR) $(SRC_ARGON_NATIVE) $(SRC_SECP) $(SRC_SHA) $(HEADERS) Makefile
	@$(REPORT) build "$(V)" "$@" $(CC) $(CFLAGS_NATIVE) $(SRC_MAIN) $(SRC_QR) $(SRC_ARGON_NATIVE) $(SRC_SECP) $(SRC_SHA) -o $(APP) $(LDFLAGS_NATIVE)

arm:
	$(ARM64_CC) $(CFLAGS_ARM64) $(SRC_MAIN) $(SRC_QR) $(SRC_ARGON_ARM) $(SRC_SECP) $(SRC_SHA) \
		-o BTC39GAP_arm64 $(LDFLAGS_ARM64)

mac:
ifeq ($(UNAME_S),Darwin)
	$(MAC_CC) $(CFLAGS_MAC) $(SRC_MAIN) $(SRC_QR) $(SRC_ARGON_ARM) $(SRC_SECP) $(SRC_SHA) \
		-o BTC39GAP_mac $(LDFLAGS_MAC)
else
	@echo "make mac requires macOS and the Apple command-line tools." >&2
	@exit 1
endif

win64:
	$(WIN64_CC) $(CFLAGS_WIN64) $(SRC_MAIN) $(SRC_QR) $(SRC_ARGON) $(SRC_SECP) $(SRC_SHA) \
		-o BTC39GAP.exe $(LDFLAGS_WIN64)

self-test: $(APP)
	@$(REPORT) heading "$(V)" "BTC39GAP | Cryptographic self-tests"
	@$(REPORT) test "$(V)" "Cryptographic self-tests" ./$(APP) --self-test
	@$(REPORT) summary "$(V)" "All self-tests passed."

tests/test_security$(TEST_EXE): tests/test_security.c $(TEST_DEPS) $(SRC_ARGON_NATIVE)
	@$(REPORT) build "$(V)" "$@" $(CC) $(CFLAGS_NATIVE) tests/test_security.c $(SRC_QR) $(filter-out argon2/core.c,$(SRC_ARGON_NATIVE)) $(SRC_SECP) $(SRC_SHA) -o $@ $(LDFLAGS_NATIVE)



tests/test_%$(TEST_EXE): tests/test_%.c $(TEST_DEPS) $(SRC_ARGON_NATIVE)
	@$(REPORT) build "$(V)" "$@" $(CC) $(CFLAGS_NATIVE) $< $(SRC_QR) $(SRC_ARGON_NATIVE) $(SRC_SECP) $(SRC_SHA) -o $@ $(LDFLAGS_NATIVE)

test: $(APP) $(TEST_BINS)
	@$(REPORT) heading "$(V)" "BTC39GAP | Regression tests"
	@$(REPORT) test "$(V)" "Cryptographic self-tests" ./$(APP) --self-test
	@$(REPORT) test "$(V)" "Memory and worker security" ./tests/test_security$(TEST_EXE)
	@$(REPORT) test "$(V)" "Input and terminal" ./tests/test_terminal$(TEST_EXE)
	@$(REPORT) test "$(V)" "File input" ./tests/test_files$(TEST_EXE)
	@$(REPORT) test "$(V)" "Reference vectors" ./tests/test_reference$(TEST_EXE)
	@$(REPORT) test "$(V)" "Integration (32 KiB)" ./tests/test_full$(TEST_EXE) --small
	@$(REPORT) summary "$(V)" "All 6 test suites passed."

test-reference: tests/test_reference$(TEST_EXE)
	@$(REPORT) heading "$(V)" "BTC39GAP | Reference tests"
	@$(REPORT) test "$(V)" "Reference vectors" ./tests/test_reference$(TEST_EXE)
	@$(REPORT) summary "$(V)" "All reference tests passed."



test-full: tests/test_full$(TEST_EXE)
	@$(REPORT) heading "$(V)" "BTC39GAP | Full integration tests"
	@$(REPORT) test "$(V)" "Integration (2 x 8 GiB)" ./tests/test_full$(TEST_EXE)
	@$(REPORT) summary "$(V)" "Full integration tests passed."

tests/test_security_san$(TEST_EXE): tests/test_security.c $(TEST_DEPS) $(SRC_ARGON_NATIVE)
	@$(REPORT) build "$(V)" "$@" $(CC) $(CFLAGS_NATIVE) -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined \
		tests/test_security.c $(SRC_QR) $(filter-out argon2/core.c,$(SRC_ARGON_NATIVE)) $(SRC_SECP) $(SRC_SHA) \
		-o $@ $(LDFLAGS_NATIVE) -fsanitize=address,undefined

tests/test_%_san$(TEST_EXE): tests/test_%.c $(TEST_DEPS) $(SRC_ARGON_NATIVE)
	@$(REPORT) build "$(V)" "$@" $(CC) $(CFLAGS_NATIVE) -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined \
		$< $(SRC_QR) $(SRC_ARGON_NATIVE) $(SRC_SECP) $(SRC_SHA) \
		-o $@ $(LDFLAGS_NATIVE) -fsanitize=address,undefined

sanitize: $(TEST_SAN_BINS)
	@$(REPORT) heading "$(V)" "BTC39GAP | Address and undefined-behavior sanitizers"
	@$(REPORT) test "$(V)" "Memory and worker security" ./tests/test_security_san$(TEST_EXE)
	@$(REPORT) test "$(V)" "Input and terminal" ./tests/test_terminal_san$(TEST_EXE)
	@$(REPORT) test "$(V)" "File input" ./tests/test_files_san$(TEST_EXE)
	@$(REPORT) test "$(V)" "Reference vectors" ./tests/test_reference_san$(TEST_EXE)
	@$(REPORT) test "$(V)" "Integration (32 KiB)" ./tests/test_full_san$(TEST_EXE) --small
	@$(REPORT) summary "$(V)" "All 5 sanitizer test suites passed."

clean:
	rm -f BTC39GAP BTC39GAP.exe BTC39GAP_arm64 BTC39GAP_mac BTC39GAP_san
	rm -f $(foreach name,$(TEST_PROGRAMS) $(addsuffix _san,$(TEST_PROGRAMS)),tests/$(name) tests/$(name).exe)
	rm -f tests/terminal_fixture

.PHONY: all arm mac win64 self-test test test-reference test-full sanitize clean
