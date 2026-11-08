// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The courier envelope's TLV codec and its recipient tags.
#include "ah_courier_wire.h"

#include <string.h>

#include "ah_bytes.h"
#include "ah_crypto.h"
#include "ah_tlv.h"

static const char s_tag_context[] = "bitchat-courier-tag-v1";

bool ah_envelope_decode(const uint8_t *payload, size_t len, ah_envelope_t *out)
{
    memset(out, 0, sizeof(*out));
    out->copies = 1;
    bool have_expiry = false;
    size_t off = 0;
    ah_tlv16_t rec;
    while (ah_tlv16_next(payload, len, &off, &rec)) {
        switch (rec.type) {
        case AH_COURIER_TLV_TAG:
            if (rec.len != AH_COURIER_TAG_LEN) {
                return false;
            }
            out->tag = rec.value;
            break;
        case AH_COURIER_TLV_EXPIRY:
            if (rec.len != 8u) {
                return false;
            }
            out->expiry_ms = ah_be64(rec.value);
            have_expiry = true;
            break;
        case AH_COURIER_TLV_CIPHERTEXT:
            if (rec.len == 0 || rec.len > AH_COURIER_MAX_CIPHERTEXT) {
                return false;
            }
            out->ciphertext = rec.value;
            out->ciphertext_len = rec.len;
            break;
        case AH_COURIER_TLV_COPIES:
            if (rec.len != 1u) {
                return false;
            }
            out->copies = rec.value[0] > AH_COURIER_MAX_COPIES ? AH_COURIER_MAX_COPIES : rec.value[0];
            if (out->copies == 0) {
                out->copies = 1u;
            }
            break;
        case AH_COURIER_TLV_PREKEY_ID:
            if (rec.len != 4u) {
                return false;
            }
            out->has_prekey_id = true;
            out->prekey_id = ah_be32(rec.value);
            break;
        default:
            break;
        }
    }
    return off != SIZE_MAX && out->tag != NULL && have_expiry && out->ciphertext != NULL;
}

size_t ah_envelope_encode(const ah_envelope_t *env, uint8_t *out, size_t cap)
{
    if (env->ciphertext_len == 0 || env->ciphertext_len > AH_COURIER_MAX_CIPHERTEXT) {
        return 0;
    }
    uint8_t expiry[8];
    ah_put_be64(expiry, env->expiry_ms);
    size_t off = ah_tlv16_put(out, cap, 0, AH_COURIER_TLV_TAG, env->tag, AH_COURIER_TAG_LEN);
    off = ah_tlv16_put(out, cap, off, AH_COURIER_TLV_EXPIRY, expiry, sizeof(expiry));
    off = ah_tlv16_put(out, cap, off, AH_COURIER_TLV_CIPHERTEXT, env->ciphertext, env->ciphertext_len);
    // Omitted at 1 and for a v1 seal, as bitchat-ios omits them.
    if (env->copies > 1u) {
        off = ah_tlv16_put(out, cap, off, AH_COURIER_TLV_COPIES, &env->copies, 1u);
    }
    if (env->has_prekey_id) {
        uint8_t prekey_id[4];
        ah_put_be32(prekey_id, env->prekey_id);
        off = ah_tlv16_put(out, cap, off, AH_COURIER_TLV_PREKEY_ID, prekey_id, sizeof(prekey_id));
    }
    return off == SIZE_MAX ? 0 : off;
}

bool ah_courier_tag(const uint8_t noise_key[AH_KEY_LEN], uint32_t epoch_day, uint8_t out[AH_COURIER_TAG_LEN])
{
    uint8_t msg[sizeof(s_tag_context) - 1u + 4u];
    memcpy(msg, s_tag_context, sizeof(s_tag_context) - 1u);
    ah_put_be32(msg + sizeof(s_tag_context) - 1u, epoch_day);
    uint8_t mac[AH_SHA256_LEN];
    const bool ok = ah_hmac_sha256(noise_key, AH_KEY_LEN, msg, sizeof(msg), mac);
    memcpy(out, mac, AH_COURIER_TAG_LEN);
    return ok;
}

bool ah_courier_candidate_tags(const uint8_t noise_key[AH_KEY_LEN], uint64_t now_ms,
                               uint8_t out[AH_COURIER_CANDIDATE_TAGS][AH_COURIER_TAG_LEN])
{
    const uint32_t today = (uint32_t)(now_ms / 86400000ull);
    const uint32_t days[AH_COURIER_CANDIDATE_TAGS] = {today, today - 1u, today + 1u};
    for (size_t i = 0; i < AH_COURIER_CANDIDATE_TAGS; ++i) {
        if (!ah_courier_tag(noise_key, days[i], out[i])) {
            return false;
        }
    }
    return true;
}

bool ah_courier_tag_matches(const uint8_t noise_key[AH_KEY_LEN], uint64_t now_ms, const uint8_t tag[AH_COURIER_TAG_LEN])
{
    uint8_t candidates[AH_COURIER_CANDIDATE_TAGS][AH_COURIER_TAG_LEN];
    if (!ah_courier_candidate_tags(noise_key, now_ms, candidates)) {
        return false;
    }
    for (size_t i = 0; i < AH_COURIER_CANDIDATE_TAGS; ++i) {
        if (memcmp(candidates[i], tag, AH_COURIER_TAG_LEN) == 0) {
            return true;
        }
    }
    return false;
}
