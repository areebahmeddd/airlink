// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Announce TLV decoding, and the node's own announce.
#include "ah_announce.h"

#include <assert.h>
#include <string.h>

#include "ah_bytes.h"
#include "ah_crypto.h"

static_assert(AH_ANNOUNCE_OWN_MAX < AH_COMPRESS_THRESHOLD,
              "an announce bitchat-ios may compress can fail its signature check there");

bool ah_announce_decode(const uint8_t *payload, size_t len, ah_announce_t *out)
{
    memset(out, 0, sizeof(*out));
    bool have_nickname = false;
    size_t off = 0;
    while (len - off >= 2u) {
        const uint8_t type = payload[off];
        const uint8_t value_len = payload[off + 1u];
        off += 2u;
        if (len - off < value_len) {
            return false;
        }
        const uint8_t *value = payload + off;
        off += value_len;
        switch (type) {
        case AH_ANNOUNCE_TLV_NICKNAME:
            out->nickname = value;
            out->nickname_len = value_len;
            have_nickname = true;
            break;
        case AH_ANNOUNCE_TLV_NOISE_KEY:
            if (value_len != AH_KEY_LEN) {
                return false;
            }
            out->noise_key = value;
            break;
        case AH_ANNOUNCE_TLV_SIGNING_KEY:
            if (value_len != AH_KEY_LEN) {
                return false;
            }
            out->signing_key = value;
            break;
        case AH_ANNOUNCE_TLV_FIRMWARE:
            if (value_len == 4u) {
                out->has_firmware = true;
                out->firmware_version = ah_be32(value);
            }
            break;
        case AH_ANNOUNCE_TLV_RELAY_FLAGS:
            if (value_len >= 1u) {
                out->relay_flags = value[0];
            }
            break;
        default:
            break;
        }
    }
    return have_nickname && out->noise_key != NULL && out->signing_key != NULL;
}

bool ah_peer_id_of(const uint8_t noise_key[AH_KEY_LEN], uint8_t out[AH_PEER_ID_LEN])
{
    uint8_t digest[AH_SHA256_LEN];
    const bool ok = ah_sha256(noise_key, AH_KEY_LEN, digest);
    memcpy(out, digest, AH_PEER_ID_LEN);
    return ok;
}

bool ah_announce_binds(const uint8_t sender[AH_PEER_ID_LEN], const uint8_t noise_key[AH_KEY_LEN])
{
    uint8_t derived[AH_PEER_ID_LEN];
    return ah_peer_id_of(noise_key, derived) && memcmp(derived, sender, AH_PEER_ID_LEN) == 0;
}

// ah_tlv16_put with a one-byte length, chained the same way.
static size_t put_tlv8(uint8_t *out, size_t cap, size_t off, uint8_t type, const uint8_t *value, size_t len)
{
    if (off == SIZE_MAX || len > 255u || cap - off < 2u + len) {
        return SIZE_MAX;
    }
    out[off] = type;
    out[off + 1u] = (uint8_t)len;
    if (len > 0) {
        memcpy(out + off + 2u, value, len);
    }
    return off + 2u + len;
}

size_t ah_announce_encode(const uint8_t *nickname, size_t nickname_len, const uint8_t noise_key[AH_KEY_LEN],
                          const uint8_t signing_key[AH_KEY_LEN], uint32_t firmware_version, uint8_t relay_flags,
                          uint8_t *out, size_t cap)
{
    if (nickname_len > AH_NICKNAME_MAX) {
        return 0;
    }
    uint8_t version[4];
    ah_put_be32(version, firmware_version);
    size_t off = put_tlv8(out, cap, 0, AH_ANNOUNCE_TLV_NICKNAME, nickname, nickname_len);
    off = put_tlv8(out, cap, off, AH_ANNOUNCE_TLV_NOISE_KEY, noise_key, AH_KEY_LEN);
    off = put_tlv8(out, cap, off, AH_ANNOUNCE_TLV_SIGNING_KEY, signing_key, AH_KEY_LEN);
    off = put_tlv8(out, cap, off, AH_ANNOUNCE_TLV_FIRMWARE, version, sizeof(version));
    off = put_tlv8(out, cap, off, AH_ANNOUNCE_TLV_RELAY_FLAGS, &relay_flags, 1u);
    return off == SIZE_MAX ? 0 : off;
}
