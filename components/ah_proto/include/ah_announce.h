// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// ANNOUNCE payload TLVs: [type u8][length u8][value] (PROTOCOLS sections 3, 3.5, 10.1).
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_wire.h"

typedef struct {
    const uint8_t *nickname; // aliases the payload; not NUL-terminated
    uint8_t nickname_len;
    const uint8_t *noise_key;   // AH_KEY_LEN
    const uint8_t *signing_key; // AH_KEY_LEN
    bool has_firmware;
    uint32_t firmware_version; // TLV 0xB0, major << 16 | minor << 8 | patch
    uint8_t relay_flags;       // TLV 0xB1; 0 when absent
} ah_announce_t;

// Decode as bitchat-ios AnnouncementPacket.decode does: unknown TLVs skipped
// (the neighbor list and capabilities among them), a length running past the
// end refuses the whole announce, one trailing byte is ignored, and the
// nickname, Noise key and signing key are required. Two differences: both
// keys must be exactly 32 bytes, since they are used as keys here and not
// only displayed; and the nickname's bytes are not checked for UTF-8, since
// Airhop decodes a nickname leniently too and the node only displays it.
bool ah_announce_decode(const uint8_t *payload, size_t len, ah_announce_t *out);

// Whether `sender` is SHA-256(noise_key)[0:8], the binding every announce must
// satisfy. False also when the hash failed.
bool ah_announce_binds(const uint8_t sender[AH_PEER_ID_LEN], const uint8_t noise_key[AH_KEY_LEN]);

// The peer ID a Noise static key derives to (PROTOCOLS section 7). False when
// the hash failed; `out` then holds bytes no announce binds to.
bool ah_peer_id_of(const uint8_t noise_key[AH_KEY_LEN], uint8_t out[AH_PEER_ID_LEN]);

// The node's announce at its longest nickname: five 2-byte TLV headers, the
// nickname, both keys, the 4-byte version and the 1-byte flags.
#define AH_ANNOUNCE_OWN_MAX (2u + AH_NICKNAME_MAX + 2u * (2u + AH_KEY_LEN) + (2u + 4u) + (2u + 1u))

// Encode this node's announce: nickname, Noise key, signing key, then the
// firmware version (0xB0) and relay flags (0xB1), never the neighbor list
// (PROTOCOLS section 2.3) or capabilities. Returns bytes written, at most
// AH_ANNOUNCE_OWN_MAX, or 0 when `cap` is too small or the nickname is over
// AH_NICKNAME_MAX bytes.
size_t ah_announce_encode(const uint8_t *nickname, size_t nickname_len, const uint8_t noise_key[AH_KEY_LEN],
                          const uint8_t signing_key[AH_KEY_LEN], uint32_t firmware_version, uint8_t relay_flags,
                          uint8_t *out, size_t cap);
