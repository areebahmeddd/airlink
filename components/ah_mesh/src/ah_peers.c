// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The peer table: keys learned from verified announces, identity conflicts,
// eviction that spares linked peers, and the pins of peers given up.
#include "ah_peers.h"

#include <string.h>

void ah_peers_init(ah_peers_t *peers, ah_peer_t *slots, uint16_t capacity, ah_peer_pin_t *pins,
                   uint16_t pin_capacity)
{
    memset(slots, 0, sizeof(*slots) * capacity);
    peers->slots = slots;
    peers->capacity = capacity;
    peers->evicted = 0;
    for (uint16_t i = 0; i < capacity; ++i) {
        slots[i].direct_link = AH_LINK_NONE;
    }
    if (pins != NULL) {
        memset(pins, 0, sizeof(*pins) * pin_capacity);
    }
    peers->pins = pins;
    peers->pin_capacity = pins != NULL ? pin_capacity : 0u;
    peers->pin_next = 0;
}

static uint64_t signing_pin(const uint8_t signing_key[AH_KEY_LEN])
{
    uint64_t pin = 0;
    memcpy(&pin, signing_key, sizeof(pin));
    return pin;
}

// An entry leaving the table leaves its pin, over the oldest.
static void keep_pin(ah_peers_t *peers, const ah_peer_t *p)
{
    if (peers->pin_capacity == 0 || p->key == 0) {
        return;
    }
    peers->pins[peers->pin_next] = (ah_peer_pin_t) {
        .key = p->key, .signing = signing_pin(p->signing_key)
    };
    peers->pin_next = (uint16_t)((peers->pin_next + 1u) % peers->pin_capacity);
}

// Whether a peer the table gave up was pinned to another signing key. A pin
// the same key matches is let go: the entry holds it again.
static bool pinned_elsewhere(ah_peers_t *peers, uint64_t key, const uint8_t signing_key[AH_KEY_LEN])
{
    const uint64_t signing = signing_pin(signing_key);
    bool conflict = false;
    for (uint16_t i = 0; i < peers->pin_capacity; ++i) {
        ah_peer_pin_t *pin = &peers->pins[i];
        if (pin->key != key) {
            continue;
        }
        if (pin->signing != signing) {
            conflict = true;
        } else {
            memset(pin, 0, sizeof(*pin));
        }
    }
    return conflict;
}

uint16_t ah_peers_find(const ah_peers_t *peers, const uint8_t peer_id[AH_PEER_ID_LEN])
{
    const uint64_t key = ah_peer_slot_key(peer_id);
    for (uint16_t i = 0; i < peers->capacity; ++i) {
        if (peers->slots[i].key == key && memcmp(peers->slots[i].peer_id, peer_id, AH_PEER_ID_LEN) == 0) {
            return i;
        }
    }
    return AH_PEER_NONE;
}

ah_peer_learn_t ah_peers_learn(ah_peers_t *peers, const uint8_t peer_id[AH_PEER_ID_LEN],
                               const uint8_t noise_key[AH_KEY_LEN], const uint8_t signing_key[AH_KEY_LEN],
                               uint64_t announce_ts_ms, int64_t now_ms, uint16_t *out_index)
{
    const uint16_t found = ah_peers_find(peers, peer_id);
    if (found != AH_PEER_NONE) {
        ah_peer_t *p = &peers->slots[found];
        if (memcmp(p->signing_key, signing_key, AH_KEY_LEN) != 0 || memcmp(p->noise_key, noise_key, AH_KEY_LEN) != 0) {
            return AH_PEER_CONFLICT;
        }
        // An older announce still counts as presence; the newest keeps the name.
        if (announce_ts_ms > p->announce_ts_ms) {
            p->announce_ts_ms = announce_ts_ms;
        }
        p->heard_ms = now_ms;
        *out_index = found;
        return AH_PEER_REFRESHED;
    }
    if (pinned_elsewhere(peers, ah_peer_slot_key(peer_id), signing_key)) {
        return AH_PEER_CONFLICT;
    }

    // A free slot, else the peer heard longest ago among those with no live
    // link, else the one heard longest ago: a linked phone outlasts a crowd of
    // identities heard through others.
    uint16_t victim = AH_PEER_NONE;
    bool victim_linked = true;
    for (uint16_t i = 0; i < peers->capacity; ++i) {
        const ah_peer_t *c = &peers->slots[i];
        if (c->key == 0) {
            victim = i;
            break;
        }
        const bool linked = c->direct_link != AH_LINK_NONE;
        if (victim == AH_PEER_NONE || (victim_linked && !linked) ||
                (linked == victim_linked && c->heard_ms < peers->slots[victim].heard_ms)) {
            victim = i;
            victim_linked = linked;
        }
    }
    ah_peer_t *p = &peers->slots[victim];
    if (p->key != 0) {
        peers->evicted++;
        keep_pin(peers, p);
    }
    memset(p, 0, sizeof(*p));
    p->key = ah_peer_slot_key(peer_id);
    memcpy(p->peer_id, peer_id, AH_PEER_ID_LEN);
    memcpy(p->noise_key, noise_key, AH_KEY_LEN);
    memcpy(p->signing_key, signing_key, AH_KEY_LEN);
    p->announce_ts_ms = announce_ts_ms;
    p->heard_ms = now_ms;
    p->direct_link = AH_LINK_NONE;
    *out_index = victim;
    return AH_PEER_LEARNED;
}

void ah_peers_forget(ah_peers_t *peers, uint16_t index)
{
    if (index < peers->capacity) {
        keep_pin(peers, &peers->slots[index]);
        memset(&peers->slots[index], 0, sizeof(peers->slots[index]));
        peers->slots[index].direct_link = AH_LINK_NONE;
    }
}

const uint8_t *ah_peers_signing_key(const ah_peers_t *peers, const uint8_t peer_id[AH_PEER_ID_LEN])
{
    const uint16_t i = ah_peers_find(peers, peer_id);
    return i == AH_PEER_NONE ? NULL : peers->slots[i].signing_key;
}
