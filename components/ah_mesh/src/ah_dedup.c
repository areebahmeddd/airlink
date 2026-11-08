// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The seen-sets: bucketed tables of packet IDs, each entry aging out of its window.
#include "ah_dedup.h"

#include <string.h>

#include "ah_relay.h"

// Eight slots a bucket and two candidate buckets per ID ("power of two
// choices"): at half load the fullest bucket is about four plus ln ln(buckets)
// / ln 2 deep, under six for any table here, so an ID is given up before its
// window only when the set is run past its sized rate.
#define WAYS 8u

ah_dedup_class_t ah_dedup_class_of(uint8_t type)
{
    if (type == AH_TYPE_FRAGMENT) {
        return AH_DEDUP_FRAGMENT;
    }
    return ah_is_live(type) ? AH_DEDUP_LIVE : AH_DEDUP_MESSAGE;
}

static size_t bucket_count(size_t slots)
{
    size_t buckets = 1;
    while (buckets * WAYS < slots) {
        buckets <<= 1;
    }
    return buckets;
}

size_t ah_dedup_storage_size(size_t slots)
{
    return bucket_count(slots) * WAYS * 2u * sizeof(uint32_t);
}

void ah_dedup_init(ah_dedup_t *set, void *storage, size_t slots, uint32_t window_s)
{
    const size_t buckets = bucket_count(slots);
    memset(storage, 0, ah_dedup_storage_size(slots));
    set->fingerprint = storage;
    set->recorded_s = set->fingerprint + buckets * WAYS;
    set->bucket_mask = (uint32_t)(buckets - 1u);
    set->window_s = window_s;
    set->evicted_live = 0;
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

// Packet IDs are SHA-256 output, so their bytes are already uniform and
// independent: two bucket choices and the fingerprint come from three words.
static uint32_t first_bucket(const ah_dedup_t *set, const uint8_t id[AH_PACKET_ID_LEN])
{
    return (le32(id) & set->bucket_mask) * WAYS;
}

static uint32_t second_bucket(const ah_dedup_t *set, const uint8_t id[AH_PACKET_ID_LEN])
{
    return (le32(id + 8) & set->bucket_mask) * WAYS;
}

static uint32_t fingerprint_of(const uint8_t id[AH_PACKET_ID_LEN])
{
    const uint32_t f = le32(id + 4);
    return f == 0 ? 1u : f;
}

static bool live(const ah_dedup_t *set, size_t slot, uint32_t now_s)
{
    return set->fingerprint[slot] != 0 && now_s - set->recorded_s[slot] < set->window_s;
}

static bool in_bucket(const ah_dedup_t *set, uint32_t base, uint32_t f, uint32_t now_s)
{
    for (uint32_t i = 0; i < WAYS; ++i) {
        if (set->fingerprint[base + i] == f && live(set, base + i, now_s)) {
            return true;
        }
    }
    return false;
}

bool ah_dedup_seen(const ah_dedup_t *set, const uint8_t id[AH_PACKET_ID_LEN], uint32_t now_s)
{
    const uint32_t f = fingerprint_of(id);
    return in_bucket(set, first_bucket(set, id), f, now_s) || in_bucket(set, second_bucket(set, id), f, now_s);
}

static uint32_t free_slots(const ah_dedup_t *set, uint32_t base, uint32_t now_s, uint32_t *slot)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < WAYS; ++i) {
        if (!live(set, base + i, now_s)) {
            if (count == 0) {
                *slot = base + i;
            }
            count++;
        }
    }
    return count;
}

void ah_dedup_add(ah_dedup_t *set, const uint8_t id[AH_PACKET_ID_LEN], uint32_t now_s)
{
    if (ah_dedup_seen(set, id, now_s)) {
        return;
    }
    const uint32_t f = fingerprint_of(id);
    const uint32_t a = first_bucket(set, id);
    const uint32_t b = second_bucket(set, id);
    uint32_t slot_a = a;
    uint32_t slot_b = b;
    const uint32_t free_a = free_slots(set, a, now_s, &slot_a);
    const uint32_t free_b = free_slots(set, b, now_s, &slot_b);
    uint32_t victim;
    if (free_a > 0 || free_b > 0) {
        // The emptier of the two keeps the buckets level.
        victim = free_a >= free_b ? slot_a : slot_b;
    } else {
        // Both full of live IDs: the set is past the rate it was sized for,
        // and the oldest of the sixteen goes early.
        victim = a;
        for (uint32_t i = 0; i < 2u * WAYS; ++i) {
            const uint32_t s = i < WAYS ? a + i : b + (i - WAYS);
            // Wraparound-safe: the oldest is the one recorded furthest before now.
            if (now_s - set->recorded_s[s] > now_s - set->recorded_s[victim]) {
                victim = s;
            }
        }
        set->evicted_live++;
    }
    set->fingerprint[victim] = f;
    set->recorded_s[victim] = now_s;
}

void ah_dedup_forget(ah_dedup_t *set, const uint8_t id[AH_PACKET_ID_LEN])
{
    const uint32_t f = fingerprint_of(id);
    const uint32_t bases[2] = {first_bucket(set, id), second_bucket(set, id)};
    for (size_t k = 0; k < 2u; ++k) {
        for (uint32_t i = 0; i < WAYS; ++i) {
            if (set->fingerprint[bases[k] + i] == f) {
                set->fingerprint[bases[k] + i] = 0;
            }
        }
    }
}
