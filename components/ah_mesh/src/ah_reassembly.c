// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Reassembly slots for fragmented packets the node needs itself, bounded in size
// and expired by age.
#include "ah_reassembly.h"

#include <string.h>

void ah_reassembly_init(ah_reassembly_t *r, ah_assembly_t *slots, uint8_t count, uint8_t *arena, size_t slot_bytes)
{
    memset(slots, 0, sizeof(*slots) * count);
    r->slots = slots;
    r->count = count;
    r->slot_bytes = slot_bytes;
    r->evicted = 0;
    for (uint8_t i = 0; i < count; ++i) {
        slots[i].data = arena + (size_t)i * slot_bytes;
    }
}

static ah_assembly_t *find(const ah_reassembly_t *r, const uint8_t sender[AH_PEER_ID_LEN],
                           const uint8_t stream_id[AH_FRAGMENT_STREAM_ID_LEN])
{
    for (uint8_t i = 0; i < r->count; ++i) {
        ah_assembly_t *a = &r->slots[i];
        if (a->in_use && memcmp(a->sender, sender, AH_PEER_ID_LEN) == 0 &&
                memcmp(a->stream_id, stream_id, AH_FRAGMENT_STREAM_ID_LEN) == 0) {
            return a;
        }
    }
    return NULL;
}

static void release(ah_assembly_t *a)
{
    uint8_t *data = a->data;
    memset(a, 0, sizeof(*a));
    a->data = data;
}

static bool has(const ah_assembly_t *a, uint16_t index)
{
    return (a->have[index / 32u] >> (index % 32u)) & 1u;
}

static void mark(ah_assembly_t *a, uint16_t index)
{
    a->have[index / 32u] |= 1u << (index % 32u);
    a->received++;
}

static bool fits(const ah_reassembly_t *r, const ah_assembly_t *a, uint16_t last_len)
{
    return (size_t)(a->total - 1u) * a->chunk + last_len <= r->slot_bytes;
}

ah_reasm_result_t ah_reassembly_add(ah_reassembly_t *r, const uint8_t sender[AH_PEER_ID_LEN], const ah_fragment_t *frag,
                                    uint16_t link, int64_t now_ms, ah_reassembled_t *out)
{
    const bool final_piece = frag->index + 1u == frag->total;
    // An empty piece, or a short one that is not the last, only packs a slot.
    if (frag->total > AH_REASSEMBLY_MAX_PIECES || frag->data_len == 0 || frag->data_len > AH_BLE_FRAME_MAX ||
            (!final_piece && frag->data_len < AH_FRAGMENT_MIN_CHUNK)) {
        return AH_REASM_REFUSED;
    }

    ah_assembly_t *a = find(r, sender, frag->stream_id);
    if (a == NULL) {
        ah_assembly_t *victim = NULL;
        for (uint8_t i = 0; i < r->count; ++i) {
            ah_assembly_t *s = &r->slots[i];
            if (!s->in_use) {
                victim = s;
                break;
            }
            if (victim == NULL || s->touched_ms < victim->touched_ms) {
                victim = s;
            }
        }
        if (victim == NULL) {
            return AH_REASM_REFUSED;
        }
        if (victim->in_use) {
            r->evicted++;
        }
        release(victim);
        a = victim;
        a->in_use = true;
        memcpy(a->sender, sender, AH_PEER_ID_LEN);
        memcpy(a->stream_id, frag->stream_id, AH_FRAGMENT_STREAM_ID_LEN);
        a->inner_type = frag->inner_type;
        a->total = frag->total;
        a->link = link;
        a->one_link = true;
        a->first_ms = now_ms;
    } else if (a->total != frag->total || a->inner_type != frag->inner_type) {
        release(a);
        return AH_REASM_REFUSED;
    }
    a->touched_ms = now_ms;
    a->one_link = a->one_link && a->link == link;
    if (has(a, frag->index)) {
        return AH_REASM_PENDING;
    }

    if (final_piece) {
        if (a->chunk == 0 && a->total > 1u) {
            memcpy(a->held, frag->data, frag->data_len);
            a->last_held = true;
        } else {
            if (a->total > 1u && (frag->data_len > a->chunk || !fits(r, a, (uint16_t)frag->data_len))) {
                release(a);
                return AH_REASM_REFUSED;
            }
            if (frag->data_len > r->slot_bytes) {
                release(a);
                return AH_REASM_REFUSED;
            }
            memcpy(a->data + (size_t)frag->index * a->chunk, frag->data, frag->data_len);
        }
        a->last_len = (uint16_t)frag->data_len;
    } else {
        if (a->chunk == 0) {
            a->chunk = (uint16_t)frag->data_len;
            if (!fits(r, a, a->last_held ? a->last_len : 1u) || (a->last_held && a->last_len > a->chunk)) {
                release(a);
                return AH_REASM_REFUSED;
            }
            if (a->last_held) {
                memcpy(a->data + (size_t)(a->total - 1u) * a->chunk, a->held, a->last_len);
                a->last_held = false;
            }
        } else if (frag->data_len != a->chunk) {
            // One stream is cut at one size; a second size is someone else's bytes.
            release(a);
            return AH_REASM_REFUSED;
        }
        memcpy(a->data + (size_t)frag->index * a->chunk, frag->data, frag->data_len);
    }
    mark(a, frag->index);

    if (a->received < a->total) {
        return AH_REASM_PENDING;
    }
    out->bytes = a->data;
    out->len = (size_t)(a->total - 1u) * a->chunk + a->last_len;
    out->inner_type = a->inner_type;
    out->one_link = a->one_link;
    out->first_ms = a->first_ms;
    // Freed, but its arena keeps the bytes until the slot is reused.
    release(a);
    return AH_REASM_DONE;
}

bool ah_reassembly_holds(const ah_reassembly_t *r, const uint8_t sender[AH_PEER_ID_LEN],
                         const uint8_t stream_id[AH_FRAGMENT_STREAM_ID_LEN])
{
    for (uint8_t i = 0; i < r->count; ++i) {
        const ah_assembly_t *a = &r->slots[i];
        if (a->in_use && memcmp(a->sender, sender, AH_PEER_ID_LEN) == 0 &&
                memcmp(a->stream_id, stream_id, AH_FRAGMENT_STREAM_ID_LEN) == 0) {
            return true;
        }
    }
    return false;
}

void ah_reassembly_expire(ah_reassembly_t *r, int64_t now_ms)
{
    for (uint8_t i = 0; i < r->count; ++i) {
        ah_assembly_t *a = &r->slots[i];
        if (a->in_use && now_ms - a->touched_ms > AH_REASSEMBLY_IDLE_MS) {
            release(a);
            r->evicted++;
        }
    }
}
