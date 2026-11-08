// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// A seen-set of packet IDs with a time window (PROTOCOLS section 4, "Dedup").
//
// Keyed on the protocol packet ID, so one packet is one entry whatever its
// framing, padding, TTL or route. Slots hold a 32-bit fingerprint and the
// second it was recorded, eight to a bucket, and each ID may sit in either of
// two buckets: a lookup reads sixteen slots, nothing is ever allocated, and
// sized at twice the IDs its window must hold, a set gives up an ID early only
// when run past its rate (counted in `evicted_live`, the node's
// `dedup_evicted`). A false duplicate needs a 32-bit fingerprint collision
// among sixteen slots, about one lookup in 250 million.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_wire.h"

// Separate sets for messages, fragments and live media, so none evicts another.
typedef enum {
    AH_DEDUP_MESSAGE = 0,
    AH_DEDUP_FRAGMENT = 1,
    AH_DEDUP_LIVE = 2,
} ah_dedup_class_t;

// Which set a packet of this type belongs to.
ah_dedup_class_t ah_dedup_class_of(uint8_t type);

typedef struct {
    uint32_t *fingerprint; // 0 is an empty slot
    uint32_t *recorded_s;
    uint32_t bucket_mask;
    uint32_t window_s;
    uint32_t evicted_live; // slots given up before their window ended
} ah_dedup_t;

// Bytes of storage for a set of `slots` (rounded up to a power-of-two count of
// buckets). Size `slots` at twice the IDs the window must hold.
size_t ah_dedup_storage_size(size_t slots);

// Lay out a set over caller memory of ah_dedup_storage_size(slots) bytes,
// recording each ID for `window_s` seconds.
void ah_dedup_init(ah_dedup_t *set, void *storage, size_t slots, uint32_t window_s);

// Whether `id` is recorded and inside its window, without recording it.
bool ah_dedup_seen(const ah_dedup_t *set, const uint8_t id[AH_PACKET_ID_LEN], uint32_t now_s);

// Record `id`. A repeat refreshes nothing: the window runs from the first sighting.
void ah_dedup_add(ah_dedup_t *set, const uint8_t id[AH_PACKET_ID_LEN], uint32_t now_s);

// Forget `id`, so a packet refused earlier can be taken when it is offered again.
void ah_dedup_forget(ah_dedup_t *set, const uint8_t id[AH_PACKET_ID_LEN]);
