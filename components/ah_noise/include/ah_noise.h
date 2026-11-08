// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Noise_XX_25519_ChaChaPoly_SHA256 (Noise rev 34), as bitchat-ios runs it:
// empty prologue, empty handshake payloads, and transport messages framed as
// [nonce u32 BE][ciphertext + tag] so they decrypt out of order behind a
// 1024-nonce replay window (PROTOCOLS section 7).
//
//   msg1  -> e             32 bytes
//   msg2  <- e, ee, s, es  96 bytes
//   msg3  -> s, se         64 bytes
//
// Pure and allocation-free; the caller supplies the ephemeral key's
// randomness so tests are deterministic.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_crypto.h"

#define AH_NOISE_MSG1_LEN 32u
#define AH_NOISE_MSG2_LEN 96u
#define AH_NOISE_MSG3_LEN 64u
#define AH_NOISE_NONCE_PREFIX 4u
#define AH_NOISE_REPLAY_WINDOW 1024u

typedef struct {
    uint8_t ck[AH_SHA256_LEN];
    uint8_t h[AH_SHA256_LEN];
    uint8_t k[AH_KEY_LEN];
    bool has_k;
    bool hash_failed; // a hash under the transcript failed, so nothing derived from it is used
    uint64_t n;
} ah_noise_symmetric_t;

typedef struct {
    ah_noise_symmetric_t ss;
    uint8_t s_secret[AH_KEY_LEN];
    uint8_t s_public[AH_KEY_LEN];
    uint8_t e_secret[AH_KEY_LEN];
    uint8_t e_public[AH_KEY_LEN];
    uint8_t rs[AH_KEY_LEN];
    uint8_t re[AH_KEY_LEN];
    bool initiator;
    uint8_t next; // index of the next message, 0 to 3; 3 means complete
    bool failed;
} ah_noise_handshake_t;

typedef struct {
    uint8_t key[AH_KEY_LEN];
    uint64_t counter;
} ah_noise_sender_t;

typedef struct {
    uint8_t key[AH_KEY_LEN];
    uint64_t highest;
    bool any;
    uint8_t window[AH_NOISE_REPLAY_WINDOW / 8u];
} ah_noise_receiver_t;

// Start a handshake whose ephemeral secret is `ephemeral_seed`, 32 fresh
// random bytes.
void ah_noise_handshake_init(ah_noise_handshake_t *hs, bool initiator, const uint8_t static_secret[AH_KEY_LEN],
                             const uint8_t static_public[AH_KEY_LEN], const uint8_t ephemeral_seed[AH_KEY_LEN]);

// Write this side's next message. Returns its length, or 0 when out of turn,
// when `cap` is short, or when the handshake failed.
size_t ah_noise_write(ah_noise_handshake_t *hs, uint8_t *out, size_t cap);

// Read the peer's next message. False, and the handshake fails, on anything
// malformed or on a hash that failed along the way.
bool ah_noise_read(ah_noise_handshake_t *hs, const uint8_t *msg, size_t len);

// Derive the transport keys once all three messages have passed, and wipe the
// handshake. `remote_static` gets the peer's static key, which its peer ID
// must derive from. False, with nothing derived, before completion or when
// the key derivation's hashes failed (the handshake is wiped then too).
bool ah_noise_split(ah_noise_handshake_t *hs, ah_noise_sender_t *send, ah_noise_receiver_t *recv,
                    uint8_t remote_static[AH_KEY_LEN]);

// Seal a transport message. Returns its length, or 0 when `cap` is short or
// the 32-bit nonces ran out.
size_t ah_noise_seal(ah_noise_sender_t *send, const uint8_t *plain, size_t len, uint8_t *out, size_t cap);

// Open a transport message, refusing replays and anything older than the
// window. A failure changes nothing: a forged or replayed packet must never
// cost a working session. Returns the plaintext length, or SIZE_MAX.
size_t ah_noise_open(ah_noise_receiver_t *recv, const uint8_t *msg, size_t len, uint8_t *out, size_t cap);

// Wipe a handshake that will not complete.
void ah_noise_handshake_wipe(ah_noise_handshake_t *hs);
