// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Backend-independent primitives: everything but SHA-256 and the random
// source, which ah_crypto_esp.c (or the host test backend) provides.
#include "ah_crypto.h"

#include <string.h>

#include "monocypher-ed25519.h"
#include "monocypher.h"

#define HMAC_BLOCK 64u

bool ah_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                    uint8_t out[AH_SHA256_LEN])
{
    uint8_t block[HMAC_BLOCK] = {0};
    bool ok = true;
    if (key_len > HMAC_BLOCK) {
        ok = ah_sha256(key, key_len, block);
    } else if (key_len > 0) {
        memcpy(block, key, key_len);
    }

    uint8_t pad[HMAC_BLOCK];
    uint8_t inner[AH_SHA256_LEN];
    ah_sha256_ctx_t ctx;

    for (size_t i = 0; i < HMAC_BLOCK; ++i) {
        pad[i] = block[i] ^ 0x36u;
    }
    ah_sha256_begin(&ctx);
    ah_sha256_update(&ctx, pad, sizeof(pad));
    ah_sha256_update(&ctx, msg, msg_len);
    ok = ah_sha256_finish(&ctx, inner) && ok;

    for (size_t i = 0; i < HMAC_BLOCK; ++i) {
        pad[i] = block[i] ^ 0x5cu;
    }
    ah_sha256_begin(&ctx);
    ah_sha256_update(&ctx, pad, sizeof(pad));
    ah_sha256_update(&ctx, inner, sizeof(inner));
    ok = ah_sha256_finish(&ctx, out) && ok;

    // The padded key and both hash states are as good as the key itself.
    ah_wipe(block, sizeof(block));
    ah_wipe(pad, sizeof(pad));
    ah_wipe(inner, sizeof(inner));
    ah_wipe(&ctx, sizeof(ctx));
    if (!ok) {
        memset(out, 0xFF, AH_SHA256_LEN);
    }
    return ok;
}

void ah_ed25519_keypair(const uint8_t seed[AH_KEY_LEN], uint8_t secret[AH_ED25519_SECRET_LEN],
                        uint8_t public_key[AH_KEY_LEN])
{
    // Monocypher wipes the seed it is handed; the caller keeps its own copy.
    uint8_t scratch[AH_KEY_LEN];
    memcpy(scratch, seed, sizeof(scratch));
    crypto_ed25519_key_pair(secret, public_key, scratch);
}

void ah_ed25519_sign(const uint8_t secret[AH_ED25519_SECRET_LEN], const uint8_t *msg, size_t len,
                     uint8_t signature[AH_SIGNATURE_LEN])
{
    crypto_ed25519_sign(signature, secret, msg, len);
}

bool ah_ed25519_verify(const uint8_t public_key[AH_KEY_LEN], const uint8_t *msg, size_t len,
                       const uint8_t signature[AH_SIGNATURE_LEN])
{
    return crypto_ed25519_check(signature, public_key, msg, len) == 0;
}

void ah_x25519_public(const uint8_t secret[AH_KEY_LEN], uint8_t public_key[AH_KEY_LEN])
{
    crypto_x25519_public_key(public_key, secret);
}

bool ah_x25519(const uint8_t secret[AH_KEY_LEN], const uint8_t peer_public[AH_KEY_LEN], uint8_t shared[AH_KEY_LEN])
{
    crypto_x25519(shared, secret, peer_public);
    static const uint8_t zero[AH_KEY_LEN] = {0};
    // Compared in constant time: the result is a secret unless it is the
    // low-order zero (RFC 7748 section 6.1).
    return crypto_verify32(shared, zero) != 0;
}

void ah_aead_seal(const uint8_t key[AH_KEY_LEN], const uint8_t nonce[AH_AEAD_NONCE_LEN], const uint8_t *ad,
                  size_t ad_len, const uint8_t *plain, size_t len, uint8_t *out)
{
    // A fresh context per message: Monocypher ratchets the key after each
    // write, and only the first message under a context is RFC 8439.
    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, key, nonce);
    crypto_aead_write(&ctx, out, out + len, ad, ad_len, plain, len);
    crypto_wipe(&ctx, sizeof(ctx));
}

bool ah_aead_open(const uint8_t key[AH_KEY_LEN], const uint8_t nonce[AH_AEAD_NONCE_LEN], const uint8_t *ad,
                  size_t ad_len, const uint8_t *in, size_t len, uint8_t *out)
{
    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, key, nonce);
    const int rc = crypto_aead_read(&ctx, out, in + len, ad, ad_len, in, len);
    crypto_wipe(&ctx, sizeof(ctx));
    if (rc != 0) {
        crypto_wipe(out, len);
        return false;
    }
    return true;
}

uint32_t ah_random_range(uint32_t lo, uint32_t hi)
{
    if (hi <= lo) {
        return lo;
    }
    const uint32_t span = hi - lo + 1u;
    // Rejection sampling keeps the draw uniform when span does not divide 2^32.
    const uint32_t limit = span == 0 ? 0 : UINT32_MAX - (UINT32_MAX % span);
    uint32_t value;
    do {
        ah_random(&value, sizeof(value));
    } while (span != 0 && value >= limit);
    return span == 0 ? value : lo + value % span;
}

void ah_wipe(void *buf, size_t len)
{
    crypto_wipe(buf, len);
}
