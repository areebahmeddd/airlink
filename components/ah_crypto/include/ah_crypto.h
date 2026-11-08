// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The cryptographic primitives the node uses, behind one interface.
//
// Ed25519, X25519 and ChaCha20-Poly1305 come from Monocypher (audited,
// constant-time, maintained) on every target; Mbed TLS has no Ed25519, and one
// library for the curve and AEAD work keeps host and device on the same code.
// SHA-256 goes to the hardware through PSA Crypto on the device and to OpenSSL
// in host tests; each backend defines the streaming context in its own
// ah_sha256_ctx.h. Randomness is esp_fill_random on the device, never rand().
// All functions are reentrant and may be called from any task; none may be
// called from an ISR.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_sha256_ctx.h"

// Every Curve25519 and Ed25519 public key, X25519 secret, Ed25519 seed and
// AEAD key is 32 bytes; the protocol carries keys and signatures at these sizes.
#define AH_KEY_LEN 32u
#define AH_SIGNATURE_LEN 64u
// An Ed25519 secret as Monocypher keeps it: the seed, then the public key.
#define AH_ED25519_SECRET_LEN 64u
#define AH_SHA256_LEN 32u
#define AH_AEAD_NONCE_LEN 12u
#define AH_AEAD_TAG_LEN 16u

// SHA-256 in pieces, and in one call. A false return means the backend
// failed: on the device the SHA driver allocates its context per streaming
// operation, so a short heap is enough to fail it. `out` then holds 0xFF
// bytes, which match nothing real, and the caller must treat the input as
// unhashable rather than use them as an identity.
void ah_sha256_begin(ah_sha256_ctx_t *ctx);
void ah_sha256_update(ah_sha256_ctx_t *ctx, const void *data, size_t len);
bool ah_sha256_finish(ah_sha256_ctx_t *ctx, uint8_t out[AH_SHA256_LEN]);
bool ah_sha256(const void *data, size_t len, uint8_t out[AH_SHA256_LEN]);

// HMAC-SHA256 (RFC 2104). False, with `out` all 0xFF, when a hash failed.
bool ah_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                    uint8_t out[AH_SHA256_LEN]);

// Ed25519 (RFC 8032): a key pair from a seed, signing, and verification.
// Verification runs in variable time, which is safe: it touches only public data.
void ah_ed25519_keypair(const uint8_t seed[AH_KEY_LEN], uint8_t secret[AH_ED25519_SECRET_LEN],
                        uint8_t public_key[AH_KEY_LEN]);
void ah_ed25519_sign(const uint8_t secret[AH_ED25519_SECRET_LEN], const uint8_t *msg, size_t len,
                     uint8_t signature[AH_SIGNATURE_LEN]);
bool ah_ed25519_verify(const uint8_t public_key[AH_KEY_LEN], const uint8_t *msg, size_t len,
                       const uint8_t signature[AH_SIGNATURE_LEN]);

void ah_x25519_public(const uint8_t secret[AH_KEY_LEN], uint8_t public_key[AH_KEY_LEN]);
// False for an all-zero shared secret, which only a low-order peer key yields.
bool ah_x25519(const uint8_t secret[AH_KEY_LEN], const uint8_t peer_public[AH_KEY_LEN], uint8_t shared[AH_KEY_LEN]);

// IETF ChaCha20-Poly1305 (RFC 8439). Seal writes len bytes then the tag;
// open reads them and fails on a bad tag, wiping `out`.
void ah_aead_seal(const uint8_t key[AH_KEY_LEN], const uint8_t nonce[AH_AEAD_NONCE_LEN], const uint8_t *ad,
                  size_t ad_len, const uint8_t *plain, size_t len, uint8_t *out);
bool ah_aead_open(const uint8_t key[AH_KEY_LEN], const uint8_t nonce[AH_AEAD_NONCE_LEN], const uint8_t *ad,
                  size_t ad_len, const uint8_t *in, size_t len, uint8_t *out);

void ah_random(void *buf, size_t len);
// A uniform value in [lo, hi], for relay jitter and timers.
uint32_t ah_random_range(uint32_t lo, uint32_t hi);

// A wipe the compiler cannot elide.
void ah_wipe(void *buf, size_t len);
