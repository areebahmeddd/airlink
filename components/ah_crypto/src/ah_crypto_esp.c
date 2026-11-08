// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Device backend: SHA-256 on the SHA peripheral through PSA Crypto (Mbed TLS
// 4 in ESP-IDF v6), randomness from the hardware RNG. ESP-IDF runs
// psa_crypto_init during startup, before app_main.
#include "ah_crypto.h"

#include <string.h>

#include "esp_random.h"
#include "psa/crypto.h"

static bool failed(uint8_t out[AH_SHA256_LEN])
{
    memset(out, 0xFF, AH_SHA256_LEN);
    return false;
}

void ah_sha256_begin(ah_sha256_ctx_t *ctx)
{
    // The SHA driver allocates its context here, from internal DMA-capable
    // RAM. A failure leaves the operation aborted, and finish reports it.
    ctx->op = psa_hash_operation_init();
    if (psa_hash_setup(&ctx->op, PSA_ALG_SHA_256) != PSA_SUCCESS) {
        psa_hash_abort(&ctx->op);
    }
}

void ah_sha256_update(ah_sha256_ctx_t *ctx, const void *data, size_t len)
{
    if (len > 0 && psa_hash_update(&ctx->op, data, len) != PSA_SUCCESS) {
        psa_hash_abort(&ctx->op);
    }
}

bool ah_sha256_finish(ah_sha256_ctx_t *ctx, uint8_t out[AH_SHA256_LEN])
{
    size_t olen = 0;
    if (psa_hash_finish(&ctx->op, out, AH_SHA256_LEN, &olen) != PSA_SUCCESS || olen != AH_SHA256_LEN) {
        psa_hash_abort(&ctx->op);
        return failed(out);
    }
    return true;
}

bool ah_sha256(const void *data, size_t len, uint8_t out[AH_SHA256_LEN])
{
    // One call, on a context the driver keeps on its stack: no allocation.
    size_t olen = 0;
    if (psa_hash_compute(PSA_ALG_SHA_256, data, len, out, AH_SHA256_LEN, &olen) != PSA_SUCCESS ||
            olen != AH_SHA256_LEN) {
        return failed(out);
    }
    return true;
}

void ah_random(void *buf, size_t len)
{
    // True random only while Bluetooth runs. Before it starts, the RNG is
    // pseudo-random unless the caller brackets the draw with
    // bootloader_random_enable and bootloader_random_disable, as first-boot
    // key generation does (ESP-IDF "Random Number Generation").
    esp_fill_random(buf, len);
}
