// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// COURIER_ENV (0x04) envelopes and recipient tags (PROTOCOLS section 6). The
// node carries ciphertext it can never open; nothing here touches the seal.
//
// TLVs of [type u8][length u16 BE][value]: 0x01 recipient tag (16), 0x02
// expiry (u64 BE ms), 0x03 ciphertext (1 to 16 KiB), 0x04 copies (u8, omitted
// at 1), 0x05 prekey ID (u32 BE, a v2 seal).
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_wire.h"

typedef struct {
    const uint8_t *tag; // AH_COURIER_TAG_LEN
    uint64_t expiry_ms;
    const uint8_t *ciphertext;
    size_t ciphertext_len;
    uint8_t copies; // clamped to 1..8 as bitchat-ios clamps it
    bool has_prekey_id;
    uint32_t prekey_id;
} ah_envelope_t;

// Decode as Airhop's courier store does: unknown tags skipped, a known tag of
// the wrong length refuses the envelope, and 1 or 2 trailing bytes are
// ignored, where bitchat-ios would refuse them.
bool ah_envelope_decode(const uint8_t *payload, size_t len, ah_envelope_t *out);

// Encode byte-exact with bitchat-ios CourierEnvelope.encode, in its order.
// Returns bytes written, or 0 when it does not fit or the ciphertext is empty
// or over 16 KiB.
size_t ah_envelope_encode(const ah_envelope_t *env, uint8_t *out, size_t cap);

// HMAC-SHA256(noise key, "bitchat-courier-tag-v1" || epochDay u32 BE)[0:16],
// where epoch_day is floor(unix seconds / 86400). False when the hash failed.
bool ah_courier_tag(const uint8_t noise_key[AH_KEY_LEN], uint32_t epoch_day, uint8_t out[AH_COURIER_TAG_LEN]);

// The peer's tags for today, yesterday and tomorrow, in that order
// (CourierEnvelope.candidateTags): computed once to compare against many
// envelopes. False when a hash failed.
#define AH_COURIER_CANDIDATE_TAGS 3u
bool ah_courier_candidate_tags(const uint8_t noise_key[AH_KEY_LEN], uint64_t now_ms,
                               uint8_t out[AH_COURIER_CANDIDATE_TAGS][AH_COURIER_TAG_LEN]);

// Whether `tag` is one of the peer's candidate tags. Never true on a failed
// hash, so mail is not handed to whoever asks while the hash is down.
bool ah_courier_tag_matches(const uint8_t noise_key[AH_KEY_LEN], uint64_t now_ms,
                            const uint8_t tag[AH_COURIER_TAG_LEN]);
