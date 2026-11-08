// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Pair keys and frame tags for the trunk, from the crypto core's X25519 and HMAC-SHA256.
#include "ah_trunk_auth.h"

#include <string.h>

#include "ah_crypto.h"

static_assert(AH_TRUNK_KEY_LEN == AH_KEY_LEN, "the trunk's keys are Curve25519 keys");
static_assert(AH_TRUNK_TAG_LEN <= AH_SHA256_LEN, "a tag is a prefix of an HMAC");

// Domain separation: this key is for nothing but trunk tags.
static const char LABEL[] = "airlink trunk v1";
#define LABEL_LEN (sizeof(LABEL) - 1u)

bool ah_trunk_auth_pair_key(const uint8_t secret[AH_TRUNK_KEY_LEN], const uint8_t self[AH_TRUNK_NODE_LEN],
                            const uint8_t peer_key[AH_TRUNK_KEY_LEN], const uint8_t peer[AH_TRUNK_NODE_LEN],
                            uint8_t out[AH_TRUNK_KEY_LEN])
{
    uint8_t shared[AH_KEY_LEN];
    if (!ah_x25519(secret, peer_key, shared)) {
        ah_wipe(out, AH_TRUNK_KEY_LEN);
        return false;
    }
    const bool self_first = memcmp(self, peer, AH_TRUNK_NODE_LEN) < 0;
    uint8_t msg[LABEL_LEN + 2u * AH_TRUNK_NODE_LEN];
    memcpy(msg, LABEL, LABEL_LEN);
    memcpy(msg + LABEL_LEN, self_first ? self : peer, AH_TRUNK_NODE_LEN);
    memcpy(msg + LABEL_LEN + AH_TRUNK_NODE_LEN, self_first ? peer : self, AH_TRUNK_NODE_LEN);
    uint8_t mac[AH_SHA256_LEN];
    const bool ok = ah_hmac_sha256(shared, sizeof(shared), msg, sizeof(msg), mac);
    memcpy(out, mac, AH_TRUNK_KEY_LEN);
    ah_wipe(shared, sizeof(shared));
    ah_wipe(mac, sizeof(mac));
    if (!ok) {
        ah_wipe(out, AH_TRUNK_KEY_LEN);
    }
    return ok;
}

bool ah_trunk_auth_names(const uint8_t key[AH_TRUNK_KEY_LEN], const uint8_t node[AH_TRUNK_NODE_LEN])
{
    uint8_t hash[AH_SHA256_LEN];
    return ah_sha256(key, AH_TRUNK_KEY_LEN, hash) && memcmp(hash, node, AH_TRUNK_NODE_LEN) == 0;
}

bool ah_trunk_auth_tag(const uint8_t pair_key[AH_TRUNK_KEY_LEN], const uint8_t *frame, size_t len,
                       const ah_trunk_frame_t *f, uint8_t out[AH_TRUNK_TAG_LEN])
{
    const size_t at = ah_trunk_frame_tags_at(f->kind);
    const size_t tags = (size_t)f->tag_count * AH_TRUNK_TAG_LEN;
    if (len > AH_TRUNK_FRAME_MAX || at + tags > len) {
        return false;
    }
    uint8_t msg[AH_TRUNK_FRAME_MAX];
    memcpy(msg, frame, at);
    memcpy(msg + at, frame + at + tags, len - at - tags);
    uint8_t mac[AH_SHA256_LEN];
    const bool ok = ah_hmac_sha256(pair_key, AH_TRUNK_KEY_LEN, msg, len - tags, mac);
    memcpy(out, mac, AH_TRUNK_TAG_LEN);
    return ok;
}

int ah_trunk_auth_find(const uint8_t pair_key[AH_TRUNK_KEY_LEN], const uint8_t *frame, size_t len,
                       const ah_trunk_frame_t *f)
{
    uint8_t expected[AH_TRUNK_TAG_LEN];
    if (!ah_trunk_auth_tag(pair_key, frame, len, f, expected)) {
        return -1;
    }
    int found = -1;
    for (uint8_t i = 0; i < f->tag_count; ++i) {
        uint8_t diff = 0;
        for (size_t b = 0; b < AH_TRUNK_TAG_LEN; ++b) {
            diff |= (uint8_t)(expected[b] ^ f->tags[i][b]);
        }
        // Monocypher has no 8-byte verify, so the compare is here: every byte
        // of every tag, whether or not one matched already.
        if (diff == 0 && found < 0) {
            found = (int)i;
        }
    }
    return found;
}
