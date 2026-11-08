// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The host tests' backend for ah_crypto.h: SHA-256 from OpenSSL and a seeded
// random source, with the hooks ah_test_crypto.h declares. The rest of
// ah_crypto is the device's own code.
#include <stdint.h>
#include <string.h>

#include "ah_crypto.h"
#include "ah_test_crypto.h"

static uint64_t s_state = 0x9E3779B97F4A7C15ull;
static bool s_sha256_fails;

void ah_test_random_seed(uint64_t seed)
{
    s_state = seed != 0 ? seed : 0x9E3779B97F4A7C15ull;
}

void ah_test_sha256_fail(bool fail)
{
    s_sha256_fails = fail;
}

// splitmix64, whose constants these are.
static uint64_t next_u64(void)
{
    uint64_t z = (s_state += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

void ah_sha256_begin(ah_sha256_ctx_t *ctx)
{
    SHA256_Init(&ctx->ctx);
}

void ah_sha256_update(ah_sha256_ctx_t *ctx, const void *data, size_t len)
{
    if (len > 0) {
        SHA256_Update(&ctx->ctx, data, len);
    }
}

bool ah_sha256_finish(ah_sha256_ctx_t *ctx, uint8_t out[AH_SHA256_LEN])
{
    const bool ok = SHA256_Final(out, &ctx->ctx) == 1 && !s_sha256_fails;
    if (!ok) {
        memset(out, 0xFF, AH_SHA256_LEN);
    }
    return ok;
}

bool ah_sha256(const void *data, size_t len, uint8_t out[AH_SHA256_LEN])
{
    ah_sha256_ctx_t ctx;
    ah_sha256_begin(&ctx);
    ah_sha256_update(&ctx, data, len);
    return ah_sha256_finish(&ctx, out);
}

void ah_random(void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len > 0) {
        const uint64_t v = next_u64();
        const size_t n = len < sizeof(v) ? len : sizeof(v);
        memcpy(p, &v, n);
        p += n;
        len -= n;
    }
}
