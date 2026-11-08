// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The mailbox table: deposits within their quotas and lifetimes, matching by
// recipient tag, spray budgets, and handover.
#include "ah_courier.h"

#include <string.h>

#include "ah_crypto.h"
#include "ah_mesh_ids.h"

void ah_courier_init(ah_courier_t *c, ah_mail_t *slots, uint16_t cap, uint8_t *arena, uint32_t arena_size,
                     uint16_t per_depositor, ah_courier_gone_t gone, void *gone_ctx)
{
    memset(c, 0, sizeof(*c));
    memset(slots, 0, sizeof(*slots) * cap);
    c->mail = slots;
    c->cap = cap;
    c->arena = arena;
    c->arena_size = arena_size;
    c->per_depositor = per_depositor;
    c->next_record = 1;
    c->gone = gone;
    c->gone_ctx = gone_ctx;
}

// False when the hash failed: two envelopes that both failed would otherwise
// share a digest, and the second would merge into the first and be lost.
static bool digest_of(const ah_envelope_t *env, uint8_t out[16])
{
    ah_sha256_ctx_t ctx;
    uint8_t d[AH_SHA256_LEN];
    ah_sha256_begin(&ctx);
    ah_sha256_update(&ctx, env->tag, AH_COURIER_TAG_LEN);
    ah_sha256_update(&ctx, env->ciphertext, env->ciphertext_len);
    const bool ok = ah_sha256_finish(&ctx, d);
    memcpy(out, d, 16);
    return ok;
}

// A carrier judges by its own limits, not the sender's: an expiry past the
// lifetime plus slack is refused outright rather than clamped (PROTOCOLS section 6).
static bool lifetime_ok(const ah_envelope_t *env, uint64_t now_ms)
{
    return env->expiry_ms > now_ms &&
           env->expiry_ms <= now_ms + (uint64_t)AH_COURIER_LIFETIME_MS + (uint64_t)AH_COURIER_EXPIRY_SLACK_MS;
}

void ah_courier_retire(ah_courier_t *c, uint16_t index)
{
    ah_mail_t *m = &c->mail[index];
    if (!m->in_use) {
        return;
    }
    const uint32_t record = m->record;
    // Compact the arena: everything after this envelope moves down.
    const uint32_t end = m->offset + m->len;
    memmove(c->arena + m->offset, c->arena + end, c->arena_used - end);
    for (uint16_t i = 0; i < c->cap; ++i) {
        if (c->mail[i].in_use && c->mail[i].offset > m->offset) {
            c->mail[i].offset -= m->len;
        }
    }
    c->arena_used -= m->len;
    memset(m, 0, sizeof(*m));
    if (c->gone != NULL) {
        c->gone(c->gone_ctx, record);
    }
}

static uint16_t free_slot(const ah_courier_t *c, size_t len)
{
    if (c->arena_size - c->arena_used < len) {
        return AH_MAIL_NONE;
    }
    for (uint16_t i = 0; i < c->cap; ++i) {
        if (!c->mail[i].in_use) {
            return i;
        }
    }
    return AH_MAIL_NONE;
}

static void place(ah_courier_t *c, uint16_t slot, const uint8_t *payload, size_t len, const ah_envelope_t *env,
                  const uint8_t digest[16], uint64_t depositor, uint32_t record)
{
    ah_mail_t *m = &c->mail[slot];
    memset(m, 0, sizeof(*m));
    m->in_use = true;
    m->record = record;
    memcpy(m->tag, env->tag, AH_COURIER_TAG_LEN);
    memcpy(m->digest, digest, sizeof(m->digest));
    m->expiry_ms = env->expiry_ms;
    m->held_since_ms = -1;
    m->copies = env->copies;
    m->depositor = depositor;
    m->offset = c->arena_used;
    m->len = (uint32_t)len;
    memcpy(c->arena + c->arena_used, payload, len);
    c->arena_used += (uint32_t)len;
}

static uint16_t held_by(const ah_courier_t *c, uint64_t depositor)
{
    uint16_t n = 0;
    for (uint16_t i = 0; i < c->cap; ++i) {
        n += c->mail[i].in_use && c->mail[i].depositor == depositor ? 1u : 0u;
    }
    return n;
}

ah_deposit_t ah_courier_deposit(ah_courier_t *c, const uint8_t *payload, size_t len,
                                const uint8_t depositor[AH_PEER_ID_LEN], uint64_t now_ms, uint16_t *out_index)
{
    ah_envelope_t env;
    uint8_t digest[16];
    if (!ah_envelope_decode(payload, len, &env) || !lifetime_ok(&env, now_ms) || !digest_of(&env, digest)) {
        c->refused++;
        return AH_DEPOSIT_REFUSED;
    }
    for (uint16_t i = 0; i < c->cap; ++i) {
        ah_mail_t *m = &c->mail[i];
        if (m->in_use && memcmp(m->digest, digest, sizeof(digest)) == 0) {
            // Another copy of an envelope held: before the first spray its
            // budget may rise to the larger claim, never after (CourierStore).
            *out_index = i;
            if (!m->sprayed && env.copies > m->copies) {
                m->copies = env.copies;
                return AH_DEPOSIT_RAISED;
            }
            return AH_DEPOSIT_MERGED;
        }
    }
    const uint64_t who = ah_peer_key(depositor);
    if (held_by(c, who) >= c->per_depositor) {
        // Refused, as Airhop and bitchat-ios refuse: recycling its own oldest
        // would drop mail its sender counts as carried.
        c->refused++;
        return AH_DEPOSIT_FULL;
    }
    // Full is a refusal. Evicting instead would let fresh identities, one
    // connection each, push out every envelope the node holds.
    const uint16_t slot = free_slot(c, len);
    if (slot == AH_MAIL_NONE) {
        c->refused++;
        return AH_DEPOSIT_FULL;
    }
    place(c, slot, payload, len, &env, digest, who, c->next_record++);
    *out_index = slot;
    return AH_DEPOSIT_STORED;
}

bool ah_courier_restore(ah_courier_t *c, uint32_t record, const uint8_t *payload, size_t len, uint64_t depositor,
                        uint64_t now_ms)
{
    ah_envelope_t env;
    uint8_t digest[16];
    const uint16_t slot = free_slot(c, len);
    if (!ah_envelope_decode(payload, len, &env) || (now_ms != 0 && !lifetime_ok(&env, now_ms)) ||
            !digest_of(&env, digest) || slot == AH_MAIL_NONE || held_by(c, depositor) >= c->per_depositor) {
        c->refused++;
        return false;
    }
    if (record >= c->next_record) {
        c->next_record = record + 1u;
    }
    place(c, slot, payload, len, &env, digest, depositor, record);
    c->mail[slot].sprayed = true;
    return true;
}

size_t ah_courier_expire(ah_courier_t *c, uint64_t now_ms)
{
    size_t n = 0;
    for (uint16_t i = 0; i < c->cap; ++i) {
        const ah_mail_t *m = &c->mail[i];
        if (m->in_use && !m->handing_over && m->expiry_ms <= now_ms) {
            ah_courier_retire(c, i);
            n++;
        }
    }
    return n;
}

size_t ah_courier_expire_held(ah_courier_t *c, int64_t mono_ms)
{
    size_t n = 0;
    for (uint16_t i = 0; i < c->cap; ++i) {
        ah_mail_t *m = &c->mail[i];
        if (!m->in_use) {
            continue;
        }
        if (m->held_since_ms < 0) {
            m->held_since_ms = mono_ms;
        } else if (!m->handing_over &&
                   mono_ms - m->held_since_ms > AH_COURIER_LIFETIME_MS + AH_COURIER_EXPIRY_SLACK_MS) {
            ah_courier_retire(c, i);
            n++;
        }
    }
    return n;
}

bool ah_courier_is_for(const ah_courier_t *c, uint16_t index,
                       const uint8_t tags[AH_COURIER_CANDIDATE_TAGS][AH_COURIER_TAG_LEN])
{
    const ah_mail_t *m = &c->mail[index];
    if (!m->in_use) {
        return false;
    }
    for (size_t i = 0; i < AH_COURIER_CANDIDATE_TAGS; ++i) {
        if (memcmp(m->tag, tags[i], AH_COURIER_TAG_LEN) == 0) {
            return true;
        }
    }
    return false;
}

size_t ah_courier_encode(const ah_courier_t *c, uint16_t index, uint8_t copies, uint8_t *out, size_t cap)
{
    const ah_mail_t *m = &c->mail[index];
    ah_envelope_t env;
    if (!ah_envelope_decode(c->arena + m->offset, m->len, &env)) {
        return 0;
    }
    env.copies = copies == 0 ? 1u : copies;
    return ah_envelope_encode(&env, out, cap);
}

bool ah_courier_sprayed_to(const ah_courier_t *c, uint16_t index, const uint8_t peer[AH_PEER_ID_LEN])
{
    const ah_mail_t *m = &c->mail[index];
    const uint64_t key = ah_peer_key(peer);
    for (uint8_t i = 0; i < m->sprayed_count; ++i) {
        if (m->sprayed_to[i] == key) {
            return true;
        }
    }
    return false;
}

uint8_t ah_courier_spray_share(const ah_courier_t *c, uint16_t index)
{
    return (uint8_t)(c->mail[index].copies / 2u);
}

void ah_courier_spray_commit(ah_courier_t *c, uint16_t index, const uint8_t peer[AH_PEER_ID_LEN], uint8_t given)
{
    ah_mail_t *m = &c->mail[index];
    m->copies = (uint8_t)(m->copies - given);
    m->sprayed = true;
    if (m->sprayed_count < AH_MAIL_SPRAY_MEMORY) {
        m->sprayed_to[m->sprayed_count++] = ah_peer_key(peer);
    } else {
        memmove(m->sprayed_to, m->sprayed_to + 1, (AH_MAIL_SPRAY_MEMORY - 1u) * sizeof(m->sprayed_to[0]));
        m->sprayed_to[AH_MAIL_SPRAY_MEMORY - 1u] = ah_peer_key(peer);
    }
}
