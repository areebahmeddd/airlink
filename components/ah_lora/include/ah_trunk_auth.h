// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Authentication between trunk neighbors, with no handshake and no airtime of
// its own. A node's beacon carries its static key, the X25519 key its bitchat
// peer ID is the hash of, so the source ID names the key. Two nodes that have
// each heard the other's beacon hold the same pair key, from X25519 between
// their static keys, and every frame carries an 8-byte tag under it for each
// node the frame is for: only the holder of a source ID's secret can make a
// frame another node acts on as from that ID. A beacon's key is the one thing
// taken untagged, since it is how a node first learns it.
//
// The frame's contents are bitchat packets the mesh verifies end to end; the
// tags protect what the trunk itself acts on: who a link is to, what was
// delivered, and the power each side transmits at.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_trunk_frame.h"

// The pair key two nodes share: HMAC-SHA256 under X25519(our secret, their
// static key) of a label and both node IDs, the lower first, so both ends get
// the same key. False, with `out` wiped, for a low-order key or a failed hash.
bool ah_trunk_auth_pair_key(const uint8_t secret[AH_TRUNK_KEY_LEN], const uint8_t self[AH_TRUNK_NODE_LEN],
                            const uint8_t peer_key[AH_TRUNK_KEY_LEN], const uint8_t peer[AH_TRUNK_NODE_LEN],
                            uint8_t out[AH_TRUNK_KEY_LEN]);

// Whether `key` is the static key `node` names: its SHA-256 begins with the ID.
bool ah_trunk_auth_names(const uint8_t key[AH_TRUNK_KEY_LEN], const uint8_t node[AH_TRUNK_NODE_LEN]);

// The tag under `pair_key` for an encoded frame: the first 8 bytes of
// HMAC-SHA256 over every byte of it but its tags. False when the hash failed.
bool ah_trunk_auth_tag(const uint8_t pair_key[AH_TRUNK_KEY_LEN], const uint8_t *frame, size_t len,
                       const ah_trunk_frame_t *f, uint8_t out[AH_TRUNK_TAG_LEN]);

// The position of the tag `pair_key` makes among the parsed frame's tags, or
// -1 when none matches. Compared in constant time.
int ah_trunk_auth_find(const uint8_t pair_key[AH_TRUNK_KEY_LEN], const uint8_t *frame, size_t len,
                       const ah_trunk_frame_t *f);
