// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Gossip sync stores and filters (PROTOCOLS section 5), so a phone arriving
// late catches up from the node.
//
// One store per kind, as bitchat-ios and Airhop keep them, so a busy room
// cannot evict the board: announces (the latest per peer), public messages
// (0x02 and the location channels' 0x51), group messages and board posts. Each
// store is a ring of whole frames, oldest out first. Only packets this node
// accepted are kept: verified announces, public messages verified against
// their author's announce, board posts whose own signature verified, and
// group messages as they arrive (they are sealed; nobody outside the group can
// check them, bitchat-ios included).
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_frame.h"
#include "ah_sync_wire.h"

typedef enum {
    AH_STORE_ANNOUNCE = 0,
    AH_STORE_MESSAGE,
    AH_STORE_GROUP,
    AH_STORE_BOARD,
    AH_STORE_COUNT,
} ah_store_kind_t;

typedef struct {
    uint32_t offset;
    uint32_t len; // a reassembled packet can be a whole 64 KiB (AH_BIG_SEND_KIB)
    uint64_t ts_ms;
    uint64_t sender; // ah_peer_key of the sender
    uint8_t id[AH_PACKET_ID_LEN];
    uint32_t seq;
    uint8_t type;
    bool dead; // replaced, purged or aged out; its bytes are reclaimed when it reaches the head
} ah_sync_entry_t;

typedef struct {
    ah_sync_entry_t *entries;
    uint16_t cap;
    uint16_t head;
    uint16_t count;
    uint8_t *arena;
    uint32_t arena_size;
    uint32_t tail;              // where the next frame goes
    uint64_t evicted_newest_ms; // newest timestamp given up to make room; 0 none
} ah_sync_store_t;

typedef struct {
    uint8_t id[AH_PACKET_ID_LEN];
    uint8_t type;
    uint64_t ts_ms;
    uint64_t sender;
} ah_sync_declined_t;

typedef struct {
    uint64_t ts;
    uint64_t hash;
} ah_sync_candidate_t;

typedef struct {
    ah_sync_store_t stores[AH_STORE_COUNT];
    ah_sync_declined_t *declined;
    uint16_t declined_cap;
    uint16_t declined_next;
    uint32_t seq;
    // Scratch for building a filter (the newest that fit one) and decoding a peer's.
    ah_sync_candidate_t *pick;
    size_t pick_cap;
    uint64_t *hashes;
    uint32_t *encode;
    uint32_t *values;
} ah_sync_t;

typedef struct {
    uint16_t entries[AH_STORE_COUNT];
    uint32_t bytes[AH_STORE_COUNT];
    uint16_t declined;
} ah_sync_sizes_t;

// Bytes of memory ah_sync_init needs for these sizes.
size_t ah_sync_memory(const ah_sync_sizes_t *sizes);

// Lay the stores out over `mem` of ah_sync_memory(sizes) bytes.
void ah_sync_init(ah_sync_t *sync, const ah_sync_sizes_t *sizes, void *mem);

// Keep an accepted packet: its canonical bytes as received, unpadded, with
// their original TTL and flags. An announce replaces its sender's older one;
// a duplicate, or anything outside its type's window or dated more than the
// skew ahead of `now_ms`, is not kept. Returns whether it was stored.
bool ah_sync_track(ah_sync_t *sync, const ah_frame_t *frame, const uint8_t id[AH_PACKET_ID_LEN], uint64_t now_ms);

// Whether a packet of this type and ID is held.
bool ah_sync_holds(const ah_sync_t *sync, uint8_t type, const uint8_t id[AH_PACKET_ID_LEN]);

// Note a sync reply this node could not accept, so its filters stop drawing it.
void ah_sync_decline(ah_sync_t *sync, const ah_frame_t *frame, const uint8_t id[AH_PACKET_ID_LEN]);

// Forget declined replies from a sender whose key just became known.
void ah_sync_undecline(ah_sync_t *sync, const uint8_t sender[AH_PEER_ID_LEN]);

// Drop a sender's announce (a verified LEAVE); what they said stays.
void ah_sync_purge_sender(ah_sync_t *sync, const uint8_t sender[AH_PEER_ID_LEN]);

// The latest announce held for `sender`, as it arrived, or NULL.
const uint8_t *ah_sync_latest_announce(const ah_sync_t *sync, const uint8_t sender[AH_PEER_ID_LEN], size_t *len);

// Build a request payload for the types in `types`: a filter over what
// is held, newest first, with the since-cursor set when the filter
// cannot hold everything, or above what a store gave up for room.
// Returns the payload length, or 0 when `cap` is too small.
size_t ah_sync_build_request(ah_sync_t *sync, uint64_t types, uint64_t now_ms, uint8_t *out, size_t cap);

// The types in `types` whose store gave up entries for room, and so asks
// only above the newest it lost.
uint64_t ah_sync_evicted_types(const ah_sync_t *sync, uint64_t types);

typedef struct {
    uint8_t store;
    uint16_t slot;
    uint32_t seq; // guards against the slot being reused before it is sent
} ah_sync_ref_t;

// Up to `cap` refs to the packets the requester appears to be missing, store
// by store with announces first, newest first within each. Returns how many.
size_t ah_sync_plan_reply(ah_sync_t *sync, const ah_sync_request_t *req, uint64_t now_ms, ah_sync_ref_t *refs,
                          size_t cap);

// The bytes of a planned entry, or NULL when it has since been evicted.
const uint8_t *ah_sync_entry_bytes(const ah_sync_t *sync, ah_sync_ref_t ref, size_t *len);

// Drop entries past their age.
void ah_sync_prune(ah_sync_t *sync, uint64_t now_ms);

// Whether a sync reply of this type and age may be taken (PROTOCOLS section 5.1).
bool ah_sync_reply_in_window(uint8_t type, uint64_t ts_ms, uint64_t now_ms);
