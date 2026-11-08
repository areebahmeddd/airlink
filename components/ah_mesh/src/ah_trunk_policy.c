// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Admission to the trunk: each type's class and priority, the periodic origin
// table, and the announces carried ahead of a message.
#include "ah_trunk_policy.h"

#include <string.h>

#include "ah_mesh_ids.h"

// A whole BLE frame is the largest encrypted packet that crosses; anything
// longer arrives as fragments and is held to the fragment rule.
#define ENCRYPTED_MAX_FRAME AH_BLE_FRAME_MAX
// A long DM or a handshake cut for a small MTU is a few pieces; a file is hundreds.
#define FRAGMENT_MAX_TOTAL 3u
// Encrypted traffic per sender: four packets of burst, then one every 15 s.
// A typed conversation fits; a DM's live voice (about 15 packets a second)
// does not, and is kept off without being read.
#define BUCKET_CAPACITY 4000u
#define BUCKET_REFILL_MS 15000
// Receivers verify a message against the author's announce; one older than
// this on the far side may have aged out of a bitchat-ios registry.
#define ANNOUNCE_FRESH_FOR_MESSAGES_MS 45000

void ah_trunk_policy_init(ah_trunk_policy_t *p, uint32_t announce_interval_ms)
{
    memset(p, 0, sizeof(*p));
    p->announce_interval_ms = announce_interval_ms;
}

static ah_trunk_policy_origin_t *find(ah_trunk_policy_origin_t *table, uint64_t sender)
{
    for (size_t i = 0; i < AH_TRUNK_POLICY_ORIGINS; ++i) {
        if (table[i].sender == sender) {
            return &table[i];
        }
    }
    return NULL;
}

// An entry for a new origin in the periodic table: a free one, or one whose
// interval has run out. NULL while every origin held is still inside its
// interval, so a crowd of origins is refused instead of each pushing out the
// throttle on another.
static ah_trunk_policy_origin_t *claim_periodic(ah_trunk_policy_t *p, uint64_t sender, int64_t now_ms)
{
    for (size_t i = 0; i < AH_TRUNK_POLICY_ORIGINS; ++i) {
        ah_trunk_policy_origin_t *o = &p->periodic[i];
        if (o->sender == 0 || now_ms - o->at_ms >= (int64_t)p->announce_interval_ms) {
            o->sender = sender;
            return o;
        }
    }
    return NULL;
}

bool ah_trunk_policy_needs_announce(const ah_trunk_policy_t *p, const uint8_t sender[AH_PEER_ID_LEN], int64_t now_ms)
{
    const uint64_t key = ah_peer_slot_key(sender);
    for (size_t i = 0; i < AH_TRUNK_POLICY_ORIGINS; ++i) {
        if (p->ahead[i].sender == key) {
            return now_ms - p->ahead[i].at_ms > ANNOUNCE_FRESH_FOR_MESSAGES_MS;
        }
    }
    return true;
}

void ah_trunk_policy_note_ahead(ah_trunk_policy_t *p, const uint8_t sender[AH_PEER_ID_LEN], int64_t now_ms)
{
    const uint64_t key = ah_peer_slot_key(sender);
    // Forgetting an announce sent first costs at most one more sent first.
    ah_trunk_policy_origin_t *o = find(p->ahead, key);
    if (o == NULL) {
        o = &p->ahead[0];
        for (size_t i = 1; i < AH_TRUNK_POLICY_ORIGINS && o->sender != 0; ++i) {
            if (p->ahead[i].sender == 0 || p->ahead[i].at_ms < o->at_ms) {
                o = &p->ahead[i];
            }
        }
        o->sender = key;
    }
    o->at_ms = now_ms;
    ah_trunk_policy_origin_t *periodic = find(p->periodic, key);
    if (periodic == NULL) {
        periodic = claim_periodic(p, key, now_ms);
    }
    if (periodic != NULL) {
        periodic->at_ms = now_ms;
    }
}

static bool take_token(ah_trunk_policy_t *p, uint64_t sender, int64_t now_ms)
{
    ah_trunk_policy_bucket_t *b = NULL;
    ah_trunk_policy_bucket_t *victim = &p->buckets[0];
    for (size_t i = 0; i < AH_TRUNK_POLICY_BUCKETS; ++i) {
        if (p->buckets[i].sender == sender) {
            b = &p->buckets[i];
            break;
        }
        if (p->buckets[i].sender == 0 || p->buckets[i].at_ms < victim->at_ms) {
            victim = &p->buckets[i];
        }
    }
    if (b == NULL) {
        b = victim;
        b->sender = sender;
        b->milli_tokens = BUCKET_CAPACITY;
        b->at_ms = now_ms;
    }
    const int64_t elapsed = now_ms - b->at_ms;
    if (elapsed > 0) {
        const int64_t refill = elapsed * 1000 / BUCKET_REFILL_MS;
        const int64_t tokens = b->milli_tokens + refill;
        b->milli_tokens = (uint16_t)(tokens > BUCKET_CAPACITY ? BUCKET_CAPACITY : tokens);
        b->at_ms = now_ms;
    }
    if (b->milli_tokens < 1000u) {
        return false;
    }
    b->milli_tokens -= 1000u;
    return true;
}

static bool text_class(uint8_t type)
{
    switch (type) {
    case AH_TYPE_CHANNEL_MSG:
    case AH_TYPE_CHANNEL_MSG_AIRHOP:
    case AH_TYPE_CHANNEL_ENC:
    case AH_TYPE_GROUP_MESSAGE:
    case AH_TYPE_BOARD_POST:
    case AH_TYPE_LEAVE:
    case AH_TYPE_PING:
    case AH_TYPE_PONG:
    case AH_TYPE_NOISE_HANDSHAKE:
    case AH_TYPE_COURIER_ENV:
        return true;
    default:
        return false;
    }
}

static bool encrypted(uint8_t type)
{
    return type == AH_TYPE_NOISE_ENCRYPTED || type == AH_TYPE_DR_ENCRYPTED;
}

bool ah_trunk_policy_admit(ah_trunk_policy_t *p, const ah_frame_t *frame, uint8_t inner_type, uint16_t total,
                           int64_t now_ms)
{
    // Sync is link-local, and a reply let past freshness by IS_RSR has no business on air.
    if (frame->flags & AH_FLAG_IS_RSR) {
        return false;
    }
    const uint64_t sender = ah_peer_slot_key(frame->sender);
    switch (frame->type) {
    case AH_TYPE_ANNOUNCE: {
        ah_trunk_policy_origin_t *o = find(p->periodic, sender);
        if (o != NULL && now_ms - o->at_ms < (int64_t)p->announce_interval_ms) {
            return false;
        }
        if (o == NULL && (o = claim_periodic(p, sender, now_ms)) == NULL) {
            return false;
        }
        o->at_ms = now_ms;
        return true;
    }
    case AH_TYPE_NOISE_ENCRYPTED:
    case AH_TYPE_DR_ENCRYPTED:
        return frame->len <= ENCRYPTED_MAX_FRAME && take_token(p, sender, now_ms);
    case AH_TYPE_FRAGMENT:
        if (total == 0 || total > FRAGMENT_MAX_TOTAL) {
            return false;
        }
        if (encrypted(inner_type)) {
            return take_token(p, sender, now_ms);
        }
        return text_class(inner_type);
    default:
        return text_class(frame->type);
    }
}
