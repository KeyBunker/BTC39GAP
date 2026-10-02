/* Check the frozen, independently generated vectors already in test_vectors.h.
 * This runs real Argon2 at 32 KiB, without changing the production profile. */
#define main btc39gap_application_main
#include "../BTC39GAP.c"
#undef main
#include "test_common.h"

static void test_small_argon_pipeline(void) {
    char primary[] = "public test phrase 12345";
    recovery_context recovery = {"van dijk", "de vries"};
    uint8_t binding[64], digest[32], context[32], ad[64], master[64], entropy[32], fp[8];
    argon2_context a2;
    derive_secret_binding(primary, strlen(primary), binding);
    build_recovery_context_digest(&recovery, digest);
    derive_derivation_context(digest, 42U, context);
    derive_argon_ad(digest, 42U, ad);
    CHECK(memcmp(binding, expected_binding, sizeof(binding)) == 0);
    CHECK(memcmp(digest, expected_context, sizeof(digest)) == 0);
    CHECK(memcmp(context, expected_derivation_context, sizeof(context)) == 0);
    CHECK(memcmp(ad, expected_ad, sizeof(ad)) == 0);

    memset(&a2, 0, sizeof(a2));
    a2.out = master; a2.outlen = (uint32_t)sizeof(master);
    a2.pwd = (uint8_t *)primary; a2.pwdlen = (uint32_t)strlen(primary);
    a2.salt = context; a2.saltlen = (uint32_t)sizeof(context);
    a2.ad = ad; a2.adlen = (uint32_t)sizeof(ad);
    a2.t_cost = ARGON2_TIME_COST;
    a2.m_cost = 32U;
    a2.lanes = ARGON2_LANES; a2.threads = ARGON2_LANES;
    a2.version = ARGON2_VERSION_13;
    a2.allocate_cbk = secure_argon_alloc;
    a2.free_cbk = secure_argon_free;
    a2.flags = ARGON2_FLAG_CLEAR_PASSWORD;
    CHECK(argon2id_ctx(&a2) == ARGON2_OK);
    CHECK(bytes_are(primary, sizeof(primary), 0U));
    CHECK(memcmp(master, expected_test_master, sizeof(master)) == 0);
    derive_post_argon_keys(master, binding, context, ad, digest, 42U, entropy, fp);
    CHECK(memcmp(entropy, expected_test_entropy, sizeof(entropy)) == 0);
    CHECK(memcmp(fp, expected_test_fp, sizeof(fp)) == 0);
    CHECK(bytes_are(&post_workspace, sizeof(post_workspace), 0U));

    uint8_t other_context[32], other_ad[64], other_digest[32];
    derive_derivation_context(digest, 43U, other_context);
    derive_argon_ad(digest, 43U, other_ad);
    CHECK(memcmp(context, other_context, sizeof(context)) != 0);
    CHECK(memcmp(ad, other_ad, sizeof(ad)) != 0);
    recovery_context swapped = {"de vries", "van dijk"};
    build_recovery_context_digest(&swapped, other_digest);
    CHECK(memcmp(digest, other_digest, sizeof(digest)) != 0);
}

static void check_hex(const uint8_t *bytes, size_t length, const char *hex) {
    static const char digits[] = "0123456789abcdef";
    CHECK(strlen(hex) == length * 2U);
    for (size_t i = 0U; i < length; i++) {
        CHECK(hex[i * 2U] == digits[bytes[i] >> 4]);
        CHECK(hex[i * 2U + 1U] == digits[bytes[i] & 15U]);
    }
}

static void test_sha512_boundaries(void) {
    /* Independent fixed answers from OpenSSL 3.0.13. Input byte i = i % 251.
     * OpenSSL is NOT needed to compile or run this test. */
    static const struct { size_t length; const char *digest; } vectors[] = {
        {0U, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
        {111U, "a1a111449b198d9b1f538bad7f3fc1022b3a5b1a5e90a0bc860de8512746cbc31599e6c834de3a3235327af0b51ff57bf7acf1974a73014d9c3953812edc7c8d"},
        {112U, "c5fbd731d19d2ae1180f001be72c2c1aaba1d7b094b3748880e24593b8e117a750e11c1bd867cc2f96dace8c8b74abd2d5c4f236be444e77d30d1916174070b9"},
        {127U, "eab89674feaa34e27aebeeff3c0a4d70070bb872d5e9f186cf1dbbdee517b6e35724d629ff025a5b07185e911ada7e3c8acf830aa0e4f71777bd2d44f504f7f0"},
        {128U, "1dffd5e3adb71d45d2245939665521ae001a317a03720a45732ba1900ca3b8351fc5c9b4ca513eba6f80bc7b1d1fdad4abd13491cb824d61b08d8c0e1561b3f7"},
        {129U, "1d9da57fbbdab09afb3506ab2d223d06109d65c1c8ad197f50138f714bc4c3f2fe5787922639c680acad1c651f955990425954ce2cba0c5cc83f2667d878eb0f"},
        {255U, "e9746a5516961da1fdc8e6c59350cd147b7d80c120cc7ed621399faeb2462c28f34217a13009a8e6a721f538356db9a9b64d9a5412e0fd07d24cac1315d95548"},
        {256U, "7ff1cd1e9773a4b7ba1f40e642db0d879bd5f6cc151a7d3401a0bc7778b8270c108b530fb195f2383f4cec8cf05778e6af4db56811673371674cec1524488f83"}
    };
    static const size_t chunks[] = {1U,7U,111U,128U};
    uint8_t input[256], output[64];
    for (size_t i = 0U; i < sizeof(input); i++) input[i] = (uint8_t)(i % 251U);
    test_case = "SHA-512 fixed vectors at padding and block boundaries";
    for (size_t v = 0U; v < sizeof(vectors) / sizeof(vectors[0]); v++) {
        sha512_hash(input, vectors[v].length, output);
        check_hex(output, sizeof(output), vectors[v].digest);
        for (size_t c = 0U; c < sizeof(chunks) / sizeof(chunks[0]); c++) {
            sha512_ctx state;
            CHECK(sha512_init(&state) == 0);
            for (size_t at = 0U; at < vectors[v].length; ) {
                size_t remaining = vectors[v].length - at;
                size_t length = remaining < chunks[c] ? remaining : chunks[c];
                CHECK(sha512_update(&state, input + at, length) == 0);
                at += length;
            }
            CHECK(sha512_final(&state, output) == 0);
            check_hex(output, sizeof(output), vectors[v].digest);
            CHECK(bytes_are(&state, sizeof(state), 0U));
        }
    }
}

static void test_hmac_and_pbkdf2(void) {
    /* OpenSSL 3.0.13 HMAC-SHA512, key bytes 0..199, literal message below. */
    static const char hmac_hex[] =
        "badb9830894f0119540c871179ab750756dabdba0c8381464b35d9a25c63c47b8"
        "0f61f2abddaffb4c2d247d3b197305e72d785df4b7e3ec4b0bfc952bfdd8463";
    static const char message[] = "public HMAC regression vector";
    uint8_t key[200], out[64], guard[102];
    for (size_t i = 0U; i < sizeof(key); i++) key[i] = (uint8_t)i;
    test_case = "HMAC long key and overlapping input/output";
    hmac_sha512(key, sizeof(key), (const uint8_t *)message, sizeof(message) - 1U, out);
    check_hex(out, sizeof(out), hmac_hex);
    memcpy(out, message, sizeof(message));
    hmac_sha512(key, sizeof(key), out, sizeof(message) - 1U, out);
    check_hex(out, sizeof(out), hmac_hex);

    const size_t lengths[] = {1U,63U,64U,65U,100U};
    test_case = "PBKDF2 output-block boundaries and guard bytes";
    for (size_t i = 0U; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
        memset(guard, 0xa5, sizeof(guard));
        CHECK(pbkdf2_hmac_sha512((const uint8_t *)"password", 8U,
              (const uint8_t *)"salt", 4U, 2U, guard + 1U, lengths[i]) == 0);
        CHECK(guard[0] == 0xa5);
        CHECK(memcmp(guard + 1U, expected_pbkdf2_multiblock, lengths[i]) == 0);
        CHECK(bytes_are(guard + 1U + lengths[i], sizeof(guard) - 1U - lengths[i], 0xa5));
    }
    test_case = "PBKDF2 invalid parameters and overflow before writing output";
    memset(out, 0xa5, sizeof(out));
    CHECK(pbkdf2_hmac_sha512(NULL, 1U, key, 1U, 1U, out, sizeof(out)) == -1);
    CHECK(pbkdf2_hmac_sha512(key, 1U, NULL, 1U, 1U, out, sizeof(out)) == -1);
    CHECK(pbkdf2_hmac_sha512(key, 1U, key, 1U, 0U, out, sizeof(out)) == -1);
    CHECK(pbkdf2_hmac_sha512(key, 1U, key, 1U, 1U, out, 0U) == -1);
    CHECK(pbkdf2_hmac_sha512(key, 1U, key, 1U, 1U, NULL, 64U) == -1);
    CHECK(pbkdf2_hmac_sha512(key, 1U, key, SIZE_MAX, 1U, out, sizeof(out)) == -1);
    CHECK(pbkdf2_hmac_sha512(key, 1U, key, 1U, 1U, out, (size_t)UINT32_MAX * 64U + 1U) == -1);
    CHECK(bytes_are(out, sizeof(out), 0xa5));
}

static void test_key_separation(void) {
    test_case = "every post-Argon input affects entropy and recovery fingerprint";
    for (unsigned field = 0U; field < 7U; field++) {
        uint8_t master[64], binding[64], context[32], ad[64], digest[32], entropy[32], fp[8];
        uint32_t wallet = 42U;
        memcpy(master, expected_test_master, sizeof(master));
        memcpy(binding, expected_binding, sizeof(binding));
        memcpy(context, expected_derivation_context, sizeof(context));
        memcpy(ad, expected_ad, sizeof(ad));
        memcpy(digest, expected_context, sizeof(digest));
        if (field == 1U) master[0] ^= 1U;
        if (field == 2U) binding[0] ^= 1U;
        if (field == 3U) context[0] ^= 1U;
        if (field == 4U) ad[0] ^= 1U;
        if (field == 5U) digest[0] ^= 1U;
        if (field == 6U) wallet++;
        derive_post_argon_keys(master, binding, context, ad, digest, wallet, entropy, fp);
        CHECK((memcmp(entropy, expected_test_entropy, sizeof(entropy)) == 0) == (field == 0U));
        CHECK((memcmp(fp, expected_test_fp, sizeof(fp)) == 0) == (field == 0U));
        CHECK(bytes_are(&post_workspace, sizeof(post_workspace), 0U));
    }
    test_case = "surname framing avoids ambiguous concatenation";
    recovery_context left = {"ab", "c"}, right = {"a", "bc"};
    uint8_t left_digest[32], right_digest[32];
    build_recovery_context_digest(&left, left_digest);
    build_recovery_context_digest(&right, right_digest);
    CHECK(memcmp(left_digest, right_digest, sizeof(left_digest)) != 0);
}

int main(void) {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    CHECK(ctx != NULL);
    CHECK(run_selftests());
    test_case = "fixed 32-KiB Argon2 pipeline vectors";
    test_small_argon_pipeline();
    test_sha512_boundaries();
    test_hmac_and_pbkdf2();
    test_key_separation();
    test_case = "wallet fingerprint vector";
    uint8_t fingerprint[8];
    derive_wallet_address_fingerprint(
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", fingerprint);
    CHECK(memcmp(fingerprint, expected_wallet_fp, sizeof(fingerprint)) == 0);
    secp256k1_context_destroy(ctx);
    ctx = NULL;
    puts("Reference tests passed (V4, Argon2id, BIP39, BIP86, fingerprints and QR).");
    return EXIT_SUCCESS;
}
