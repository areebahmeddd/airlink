// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Peers this node has verified an announce from: the keys their packets are
// checked against, what they announced about themselves, and the link their
// direct announce bound.
//
// The signing key is pinned on first sight (trust on first use) and an
// announce under a pinned peer ID with a different signing key is refused:
// the peer ID derives from the Noise key alone, so without the pin anyone
// could pair a victim's public Noise key with their own signing key and be
// taken for the victim. A full table gives up the peer heard from longest
// ago, sparing those with a direct link while it can, and a verified LEAVE
// gives one up too; either way its pin moves to a ring of the latest given
// up, so the peer is not first contact when it returns (bitchat-ios falls
// back on the identities it persists). A pin in the ring lasts until as many
// more peers have been given up.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_mesh_ids.h"

typedef struct {
    uint64_t key; // ah_peer_slot_key of the peer ID; 0 a free slot
    uint8_t peer_id[AH_PEER_ID_LEN];
    uint8_t noise_key[AH_KEY_LEN];
    uint8_t signing_key[AH_KEY_LEN];
    uint8_t relay_flags;      // 0xB1; presentation only, never trusted
    uint32_t firmware;        // 0xB0, when announced
    uint64_t announce_ts_ms;  // newest announce timestamp, sender's clock
    int64_t heard_ms;         // monotonic time the last verified announce arrived
    uint16_t direct_link;     // link this peer's direct announce bound, or AH_LINK_NONE
} ah_peer_t;

// The pin of a peer the table gave up. 64 bits of its signing key: matching
// them under another key is as hard as finding a Noise key for its peer ID.
typedef struct {
    uint64_t key;     // ah_peer_slot_key of the peer ID; 0 a free slot
    uint64_t signing; // the signing key's first eight bytes
} ah_peer_pin_t;

typedef struct {
    ah_peer_t *slots;
    uint16_t capacity;
    uint32_t evicted;
    ah_peer_pin_t *pins;
    uint16_t pin_capacity;
    uint16_t pin_next; // the oldest pin, overwritten next
} ah_peers_t;

// `pins` may be NULL with `pin_capacity` 0: a peer given up is then forgotten whole.
void ah_peers_init(ah_peers_t *peers, ah_peer_t *slots, uint16_t capacity, ah_peer_pin_t *pins,
                   uint16_t pin_capacity);

// Index of a known peer, or AH_PEER_NONE.
uint16_t ah_peers_find(const ah_peers_t *peers, const uint8_t peer_id[AH_PEER_ID_LEN]);

typedef enum {
    AH_PEER_LEARNED,   // new entry
    AH_PEER_REFRESHED, // same keys, newer or older announce
    AH_PEER_CONFLICT,  // a different signing key under a pinned peer ID, held or given up: refused
} ah_peer_learn_t;

// Record a verified announce. The caller has checked its signature
// against `signing_key` and that `peer_id` derives from `noise_key`.
// `*out_index` is the entry, unless the result is a conflict.
ah_peer_learn_t ah_peers_learn(ah_peers_t *peers, const uint8_t peer_id[AH_PEER_ID_LEN],
                               const uint8_t noise_key[AH_KEY_LEN], const uint8_t signing_key[AH_KEY_LEN],
                               uint64_t announce_ts_ms, int64_t now_ms, uint16_t *out_index);

// Drop a peer (a verified LEAVE), keeping its pin.
void ah_peers_forget(ah_peers_t *peers, uint16_t index);

// The signing key held for a peer, or NULL.
const uint8_t *ah_peers_signing_key(const ah_peers_t *peers, const uint8_t peer_id[AH_PEER_ID_LEN]);
