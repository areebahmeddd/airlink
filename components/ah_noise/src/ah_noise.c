// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Noise XX on ah_crypto's primitives: the symmetric state, the handshake
// messages, the split, and the transport ciphers.
#include "ah_noise.h"

#include <assert.h>
#include <string.h>

// A static key under encryption: its 32 bytes and the tag.
#define SEALED_KEY_LEN (AH_KEY_LEN + AH_AEAD_TAG_LEN)

static_assert(AH_NOISE_MSG1_LEN == AH_KEY_LEN, "msg1 is e");
static_assert(AH_NOISE_MSG2_LEN == AH_KEY_LEN + SEALED_KEY_LEN + AH_AEAD_TAG_LEN, "msg2 is e, s and an empty payload");
static_assert(AH_NOISE_MSG3_LEN == SEALED_KEY_LEN + AH_AEAD_TAG_LEN, "msg3 is s and an empty payload");

// Exactly HASHLEN bytes, so it is the initial h as is (Noise section 5.2).
static const char s_protocol_name[] = "Noise_XX_25519_ChaChaPoly_SHA256";
static_assert(sizeof(s_protocol_name) - 1u == AH_SHA256_LEN, "protocol name is HASHLEN long");

static void nonce_bytes(uint64_t n, uint8_t out[AH_AEAD_NONCE_LEN])
{
    memset(out, 0, AH_AEAD_NONCE_LEN);
    for (size_t i = 0; i < 8u; ++i) {
        out[4u + i] = (uint8_t)(n >> (8u * i));
    }
}

// HKDF with two outputs over HMAC-SHA256 (Noise section 4.3).
static bool hkdf2(const uint8_t ck[AH_SHA256_LEN], const uint8_t *ikm, size_t ikm_len, uint8_t out1[AH_SHA256_LEN],
                  uint8_t out2[AH_SHA256_LEN])
{
    uint8_t temp[AH_SHA256_LEN];
    bool ok = ah_hmac_sha256(ck, AH_SHA256_LEN, ikm, ikm_len, temp);
    const uint8_t one = 0x01;
    ok = ah_hmac_sha256(temp, sizeof(temp), &one, 1, out1) && ok;
    uint8_t second[AH_SHA256_LEN + 1u];
    memcpy(second, out1, AH_SHA256_LEN);
    second[AH_SHA256_LEN] = 0x02;
    ok = ah_hmac_sha256(temp, sizeof(temp), second, sizeof(second), out2) && ok;
    ah_wipe(temp, sizeof(temp));
    ah_wipe(second, sizeof(second));
    return ok;
}

// A failed hash poisons the transcript rather than returning through every
// token: each write and read checks the flag once, at its end.
static void mix_hash(ah_noise_symmetric_t *ss, const uint8_t *data, size_t len)
{
    ah_sha256_ctx_t ctx;
    ah_sha256_begin(&ctx);
    ah_sha256_update(&ctx, ss->h, sizeof(ss->h));
    ah_sha256_update(&ctx, data, len);
    if (!ah_sha256_finish(&ctx, ss->h)) {
        ss->hash_failed = true;
    }
}

static void mix_key(ah_noise_symmetric_t *ss, const uint8_t ikm[AH_KEY_LEN])
{
    uint8_t ck[AH_SHA256_LEN];
    if (!hkdf2(ss->ck, ikm, AH_KEY_LEN, ck, ss->k)) {
        ss->hash_failed = true;
    }
    memcpy(ss->ck, ck, sizeof(ck));
    ah_wipe(ck, sizeof(ck));
    ss->has_k = true;
    ss->n = 0;
}

static size_t encrypt_and_hash(ah_noise_symmetric_t *ss, const uint8_t *plain, size_t len, uint8_t *out)
{
    static const uint8_t nothing[1] = {0};
    if (plain == NULL) {
        plain = nothing;
    }
    if (!ss->has_k) {
        if (len > 0) {
            memcpy(out, plain, len);
        }
        mix_hash(ss, out, len);
        return len;
    }
    uint8_t nonce[AH_AEAD_NONCE_LEN];
    nonce_bytes(ss->n++, nonce);
    ah_aead_seal(ss->k, nonce, ss->h, sizeof(ss->h), plain, len, out);
    mix_hash(ss, out, len + AH_AEAD_TAG_LEN);
    return len + AH_AEAD_TAG_LEN;
}

static bool decrypt_and_hash(ah_noise_symmetric_t *ss, const uint8_t *in, size_t len, uint8_t *out)
{
    if (!ss->has_k) {
        if (len > 0) {
            memcpy(out, in, len);
        }
        mix_hash(ss, in, len);
        return true;
    }
    if (len < AH_AEAD_TAG_LEN) {
        return false;
    }
    uint8_t nonce[AH_AEAD_NONCE_LEN];
    nonce_bytes(ss->n, nonce);
    if (!ah_aead_open(ss->k, nonce, ss->h, sizeof(ss->h), in, len - AH_AEAD_TAG_LEN, out)) {
        return false;
    }
    ss->n++;
    mix_hash(ss, in, len);
    return true;
}

static bool dh_mix(ah_noise_symmetric_t *ss, const uint8_t secret[AH_KEY_LEN], const uint8_t pub[AH_KEY_LEN])
{
    uint8_t shared[AH_KEY_LEN];
    const bool ok = ah_x25519(secret, pub, shared);
    if (ok) {
        mix_key(ss, shared);
    }
    ah_wipe(shared, sizeof(shared));
    return ok;
}

void ah_noise_handshake_init(ah_noise_handshake_t *hs, bool initiator, const uint8_t static_secret[AH_KEY_LEN],
                             const uint8_t static_public[AH_KEY_LEN], const uint8_t ephemeral_seed[AH_KEY_LEN])
{
    memset(hs, 0, sizeof(*hs));
    hs->initiator = initiator;
    memcpy(hs->ss.h, s_protocol_name, AH_SHA256_LEN);
    memcpy(hs->ss.ck, hs->ss.h, AH_SHA256_LEN);
    // The prologue is empty on every mesh session, as bitchat sends it.
    mix_hash(&hs->ss, hs->ss.h, 0);
    memcpy(hs->s_secret, static_secret, AH_KEY_LEN);
    memcpy(hs->s_public, static_public, AH_KEY_LEN);
    memcpy(hs->e_secret, ephemeral_seed, AH_KEY_LEN);
    ah_x25519_public(hs->e_secret, hs->e_public);
}

static bool my_turn(const ah_noise_handshake_t *hs)
{
    // Initiator writes messages 0 and 2, the responder message 1.
    return !hs->failed && hs->next < 3u && ((hs->next % 2u == 0) == hs->initiator);
}

size_t ah_noise_write(ah_noise_handshake_t *hs, uint8_t *out, size_t cap)
{
    if (!my_turn(hs)) {
        return 0;
    }
    size_t n = 0;
    switch (hs->next) {
    case 0: // -> e
        if (cap < AH_NOISE_MSG1_LEN) {
            return 0;
        }
        memcpy(out, hs->e_public, AH_KEY_LEN);
        mix_hash(&hs->ss, hs->e_public, AH_KEY_LEN);
        n = AH_KEY_LEN;
        n += encrypt_and_hash(&hs->ss, NULL, 0, out + n);
        break;
    case 1: // <- e, ee, s, es
        if (cap < AH_NOISE_MSG2_LEN) {
            return 0;
        }
        memcpy(out, hs->e_public, AH_KEY_LEN);
        mix_hash(&hs->ss, hs->e_public, AH_KEY_LEN);
        n = AH_KEY_LEN;
        if (!dh_mix(&hs->ss, hs->e_secret, hs->re)) {
            hs->failed = true;
            return 0;
        }
        n += encrypt_and_hash(&hs->ss, hs->s_public, AH_KEY_LEN, out + n);
        if (!dh_mix(&hs->ss, hs->s_secret, hs->re)) {
            hs->failed = true;
            return 0;
        }
        n += encrypt_and_hash(&hs->ss, NULL, 0, out + n);
        break;
    case 2: // -> s, se
        if (cap < AH_NOISE_MSG3_LEN) {
            return 0;
        }
        n = encrypt_and_hash(&hs->ss, hs->s_public, AH_KEY_LEN, out);
        if (!dh_mix(&hs->ss, hs->s_secret, hs->re)) {
            hs->failed = true;
            return 0;
        }
        n += encrypt_and_hash(&hs->ss, NULL, 0, out + n);
        break;
    default:
        return 0;
    }
    if (hs->ss.hash_failed) {
        hs->failed = true;
        return 0;
    }
    hs->next++;
    return n;
}

bool ah_noise_read(ah_noise_handshake_t *hs, const uint8_t *msg, size_t len)
{
    if (hs->failed || hs->next >= 3u || ((hs->next % 2u == 0) == hs->initiator)) {
        return false;
    }
    uint8_t empty[1];
    bool ok = false;
    switch (hs->next) {
    case 0: // responder reads -> e
        if (len != AH_NOISE_MSG1_LEN) {
            break;
        }
        memcpy(hs->re, msg, AH_KEY_LEN);
        mix_hash(&hs->ss, hs->re, AH_KEY_LEN);
        ok = decrypt_and_hash(&hs->ss, msg + AH_KEY_LEN, 0, empty);
        break;
    case 1: // initiator reads <- e, ee, s, es
        if (len != AH_NOISE_MSG2_LEN) {
            break;
        }
        memcpy(hs->re, msg, AH_KEY_LEN);
        mix_hash(&hs->ss, hs->re, AH_KEY_LEN);
        ok = dh_mix(&hs->ss, hs->e_secret, hs->re) &&
             decrypt_and_hash(&hs->ss, msg + AH_KEY_LEN, SEALED_KEY_LEN, hs->rs) &&
             dh_mix(&hs->ss, hs->e_secret, hs->rs) &&
             decrypt_and_hash(&hs->ss, msg + AH_KEY_LEN + SEALED_KEY_LEN, AH_AEAD_TAG_LEN, empty);
        break;
    case 2: // responder reads -> s, se
        if (len != AH_NOISE_MSG3_LEN) {
            break;
        }
        ok = decrypt_and_hash(&hs->ss, msg, SEALED_KEY_LEN, hs->rs) && dh_mix(&hs->ss, hs->e_secret, hs->rs) &&
             decrypt_and_hash(&hs->ss, msg + SEALED_KEY_LEN, AH_AEAD_TAG_LEN, empty);
        break;
    default:
        break;
    }
    if (!ok || hs->ss.hash_failed) {
        hs->failed = true;
        return false;
    }
    hs->next++;
    return true;
}

bool ah_noise_split(ah_noise_handshake_t *hs, ah_noise_sender_t *send, ah_noise_receiver_t *recv,
                    uint8_t remote_static[AH_KEY_LEN])
{
    if (hs->failed || hs->next != 3u) {
        return false;
    }
    uint8_t k1[AH_SHA256_LEN];
    uint8_t k2[AH_SHA256_LEN];
    const bool ok = hkdf2(hs->ss.ck, NULL, 0, k1, k2);
    if (ok) {
        memset(send, 0, sizeof(*send));
        memset(recv, 0, sizeof(*recv));
        // The initiator sends with k1 and receives with k2; the responder the reverse.
        memcpy(send->key, hs->initiator ? k1 : k2, AH_KEY_LEN);
        memcpy(recv->key, hs->initiator ? k2 : k1, AH_KEY_LEN);
        memcpy(remote_static, hs->rs, AH_KEY_LEN);
    }
    ah_wipe(k1, sizeof(k1));
    ah_wipe(k2, sizeof(k2));
    ah_noise_handshake_wipe(hs);
    return ok;
}

size_t ah_noise_seal(ah_noise_sender_t *send, const uint8_t *plain, size_t len, uint8_t *out, size_t cap)
{
    if (send->counter > UINT32_MAX || cap < AH_NOISE_NONCE_PREFIX + len + AH_AEAD_TAG_LEN) {
        return 0;
    }
    const uint32_t n = (uint32_t)send->counter++;
    out[0] = (uint8_t)(n >> 24);
    out[1] = (uint8_t)(n >> 16);
    out[2] = (uint8_t)(n >> 8);
    out[3] = (uint8_t)n;
    uint8_t nonce[AH_AEAD_NONCE_LEN];
    nonce_bytes(n, nonce);
    ah_aead_seal(send->key, nonce, NULL, 0, plain, len, out + AH_NOISE_NONCE_PREFIX);
    return AH_NOISE_NONCE_PREFIX + len + AH_AEAD_TAG_LEN;
}

static bool window_bit(const ah_noise_receiver_t *r, uint64_t offset)
{
    return (r->window[offset >> 3] >> (offset & 7u)) & 1u;
}

static void window_set(ah_noise_receiver_t *r, uint64_t offset)
{
    r->window[offset >> 3] |= (uint8_t)(1u << (offset & 7u));
}

// Bit o records nonce highest - o, so a newer highest ages every offset by
// `shift`: a left shift within each byte with a carry from the byte below.
// bitchat-ios and bitchat-android shift right, which forgets recent nonces.
static void window_advance(ah_noise_receiver_t *r, uint64_t shift)
{
    const size_t bytes = sizeof(r->window);
    if (shift >= AH_NOISE_REPLAY_WINDOW) {
        memset(r->window, 0, bytes);
        return;
    }
    const size_t bs = (size_t)(shift >> 3);
    const unsigned bt = (unsigned)(shift & 7u);
    for (size_t i = bytes; i-- > 0;) {
        uint8_t v = 0;
        if (i >= bs) {
            v = (uint8_t)(r->window[i - bs] << bt);
            if (bt != 0 && i >= bs + 1u) {
                v |= (uint8_t)(r->window[i - bs - 1u] >> (8u - bt));
            }
        }
        r->window[i] = v;
    }
}

size_t ah_noise_open(ah_noise_receiver_t *recv, const uint8_t *msg, size_t len, uint8_t *out, size_t cap)
{
    if (len < AH_NOISE_NONCE_PREFIX + AH_AEAD_TAG_LEN) {
        return SIZE_MAX;
    }
    const size_t plain_len = len - AH_NOISE_NONCE_PREFIX - AH_AEAD_TAG_LEN;
    if (plain_len > cap) {
        return SIZE_MAX;
    }
    const uint64_t n = (uint64_t)msg[0] << 24 | (uint64_t)msg[1] << 16 | (uint64_t)msg[2] << 8 | msg[3];
    if (recv->any && n <= recv->highest) {
        const uint64_t offset = recv->highest - n;
        if (offset >= AH_NOISE_REPLAY_WINDOW || window_bit(recv, offset)) {
            return SIZE_MAX;
        }
    }
    uint8_t nonce[AH_AEAD_NONCE_LEN];
    nonce_bytes(n, nonce);
    if (!ah_aead_open(recv->key, nonce, NULL, 0, msg + AH_NOISE_NONCE_PREFIX, plain_len, out)) {
        return SIZE_MAX;
    }
    // The window moves only once the tag has verified.
    if (!recv->any) {
        recv->any = true;
        recv->highest = n;
        memset(recv->window, 0, sizeof(recv->window));
        window_set(recv, 0);
    } else if (n > recv->highest) {
        window_advance(recv, n - recv->highest);
        recv->highest = n;
        window_set(recv, 0);
    } else {
        window_set(recv, recv->highest - n);
    }
    return plain_len;
}

void ah_noise_handshake_wipe(ah_noise_handshake_t *hs)
{
    ah_wipe(hs, sizeof(*hs));
}
