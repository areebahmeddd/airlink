// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The courier mailbox (PROTOCOLS section 6, bitchat-ios CourierStore): sealed
// envelopes a phone left for someone the mesh cannot reach now, carried until
// the recipient comes by. The node can never open them.
//
// Bounded per depositor and in total, and refused past either, never pushing
// out mail already taken, as Airhop and bitchat-ios treat depositors who are
// not favorites (the only kind a node has): a crowd of fresh identities can
// fill it but never empty it, and no depositor rewrites its flash in a loop.
// Held in RAM with the flash copy written behind it, so a power cut mid-write
// loses at most the envelope being written (the store's own record format
// makes that hold). Every envelope that leaves, delivered or expired, is
// reported to the `gone` callback, so the flash copy never outlives it.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_courier_wire.h"

#define AH_MAIL_NONE UINT16_MAX
#define AH_MAIL_SPRAY_MEMORY 4u

typedef struct {
    bool in_use;
    uint32_t record;         // persistent record ID, never reused within a boot
    uint8_t tag[AH_COURIER_TAG_LEN];
    uint8_t digest[16];      // SHA-256(tag | ciphertext) prefix: copies of one envelope merge
    uint64_t expiry_ms;
    int64_t held_since_ms;   // monotonic time it was taken, -1 until the next ah_courier_expire_held
    uint8_t copies;          // spray budget still held
    bool sprayed;            // sprayed, or restored: the budget no longer rises on a merge
    uint64_t depositor;      // ah_peer_key of the depositor
    uint32_t offset;         // envelope TLV bytes in the arena
    uint32_t len;
    bool flooded;
    int64_t flooded_ms;      // last flood toward a recipient heard through relays
    uint64_t sprayed_to[AH_MAIL_SPRAY_MEMORY];
    uint8_t sprayed_count;
    bool handing_over;       // a handover is queued; retired once every write of it lands
    int64_t handover_ms;     // when that handover was queued
    uint32_t handover_token; // marks this attempt's writes, so one left from an attempt given up counts for nothing
    uint16_t pieces;         // writes the handover takes: 1, or the pieces of its cut
    uint16_t landed;         // of those, the ones written
} ah_mail_t;

typedef void (*ah_courier_gone_t)(void *ctx, uint32_t record);

typedef struct {
    ah_mail_t *mail;
    uint16_t cap;
    uint8_t *arena;
    uint32_t arena_size;
    uint32_t arena_used;
    uint16_t per_depositor;
    uint32_t next_record;
    uint32_t refused;        // deposits and restores not taken
    ah_courier_gone_t gone;
    void *gone_ctx;
} ah_courier_t;

// `gone`, which may be NULL, is called with each envelope's record as it leaves.
void ah_courier_init(ah_courier_t *c, ah_mail_t *slots, uint16_t cap, uint8_t *arena, uint32_t arena_size,
                     uint16_t per_depositor, ah_courier_gone_t gone, void *gone_ctx);

typedef enum {
    AH_DEPOSIT_STORED,
    AH_DEPOSIT_MERGED,   // a copy of an envelope already held
    AH_DEPOSIT_RAISED,   // a copy of an envelope already held, whose larger budget it took
    AH_DEPOSIT_REFUSED,  // malformed, expired, or past the 24 h + 1 h lifetime
    AH_DEPOSIT_FULL,     // the depositor at its quota, or no room
} ah_deposit_t;

// Take a deposit. The caller has checked that it was addressed to this
// node, signed by the peer bound to the link it arrived on, and that
// the clock is synced. `*out_index` is the slot when the envelope is
// stored, merged or raised.
ah_deposit_t ah_courier_deposit(ah_courier_t *c, const uint8_t *payload, size_t len,
                                const uint8_t depositor[AH_PEER_ID_LEN], uint64_t now_ms, uint16_t *out_index);

// Restore an envelope persisted before a reboot; `record` keeps its ID. A
// `now_ms` of 0 (no clock yet) skips the lifetime check. Never evicts: one
// past the depositor's quota or the room is refused. Its budget is the one
// last persisted, and is never raised again by a merge, since the flash copy
// does not say whether some of it was already sprayed.
bool ah_courier_restore(ah_courier_t *c, uint32_t record, const uint8_t *payload, size_t len, uint64_t depositor,
                        uint64_t now_ms);

// Delete an envelope.
void ah_courier_retire(ah_courier_t *c, uint16_t index);

// Delete every envelope past its expiry but one being handed over, and
// return how many went.
size_t ah_courier_expire(ah_courier_t *c, uint64_t now_ms);

// Delete every envelope held longer than any may live (its 24 h plus the hour
// of slack), by monotonic time since this node took it, but one being handed
// over, and return how many went. The bound that holds when no clock can be
// trusted, so mail no phone can confirm expired still leaves, and a full
// mailbox opens again. An envelope is first timed by the call after it
// arrives, a restored one by the first after boot.
size_t ah_courier_expire_held(ah_courier_t *c, int64_t mono_ms);

// Whether the slot's envelope carries one of a peer's candidate tags (ah_courier_candidate_tags).
bool ah_courier_is_for(const ah_courier_t *c, uint16_t index,
                       const uint8_t tags[AH_COURIER_CANDIDATE_TAGS][AH_COURIER_TAG_LEN]);

// Encode a slot's envelope with `copies` as its spray budget, for a
// handover, a spray or a flood: the bytes written, or 0 when `cap` is short.
size_t ah_courier_encode(const ah_courier_t *c, uint16_t index, uint8_t copies, uint8_t *out, size_t cap);

// Whether this slot was already sprayed to `peer`.
bool ah_courier_sprayed_to(const ah_courier_t *c, uint16_t index, const uint8_t peer[AH_PEER_ID_LEN]);

// The copies a spray of this slot hands over: half the budget it holds.
uint8_t ah_courier_spray_share(const ah_courier_t *c, uint16_t index);

// Record a spray to `peer` that went out with `given` copies of the budget.
void ah_courier_spray_commit(ah_courier_t *c, uint16_t index, const uint8_t peer[AH_PEER_ID_LEN], uint8_t given);
