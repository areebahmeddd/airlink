// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The LoRa trunk's link layer: carries whole bitchat packets between nodes in
// trunk frames (ah_trunk_frame), authenticated between each pair of nodes
// (ah_trunk_auth).
//
// Each trunk neighbor is a link of its own in the mesh, so the mesh's dedup,
// fanout and priorities apply across LoRa exactly as across Bluetooth, and
// multi-hop over LoRa is the mesh's ordinary TTL flood. The trunk adds what
// the air needs: selective-repeat ARQ, strict priority so an announce never
// waits behind bulk, and a duty budget that every emission (data,
// retransmissions, acknowledgements, beacons) is charged against before it
// is sent, never after.
//
// A packet the mesh queues for several neighbors at once (a flood) goes as
// one transfer to all of them: each piece carries a tag per destination, and
// the destinations answer in turn, in the order of their tags. Pieces any one
// still lacks go again, so the channel carries a flood once, not once per neighbor.
//
// Pure and single-threaded: the LoRa task owns it, feeds it radio events and
// runs its timers. Time is monotonic milliseconds.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_lora_airtime.h"
#include "ah_lora_region.h"
#include "ah_trunk_arq.h"
#include "ah_trunk_frame.h"

#define AH_TRUNK_NEIGHBORS 8u
#define AH_TRUNK_QUEUE 12u
// Packets one neighbor may hold in the queue, so a neighbor with a backlog
// never fills the queue against the others.
#define AH_TRUNK_PER_NEIGHBOR 4u
#define AH_TRUNK_RX_SLOTS 4u
#define AH_TRUNK_CONTROLS 8u
// How long a packet waits before its transfer may start, so the copies the
// mesh hands over for each neighbor in one fanout join one transfer; nothing
// next to a frame's airtime.
#define AH_TRUNK_COALESCE_MS 20
// The current minute and the sixty before it: a sum over them never leaves out
// part of the hour, so the budget errs toward silence.
#define AH_TRUNK_DUTY_BUCKETS 61u
// Fixed, not configured: two nodes that disagreed on it would time each other
// out. A frame tagged for a neighbor restarts the interval for it.
#define AH_TRUNK_BEACON_INTERVAL_MS (5u * 60u * 1000u)
#define AH_TRUNK_BEACON_JITTER_MS 30000u
// Two beacons in a row that do not tag a neighbor, each as late as its jitter
// allows, keep it: two lost, or with a full table, which leaves one neighbor
// out of each beacon in turn, one lost and one that left it out. The third
// drops it. The 30 s on top covers a beacon held behind answers or a busy channel.
#define AH_TRUNK_NEIGHBOR_SILENT_MS (3u * (AH_TRUNK_BEACON_INTERVAL_MS + AH_TRUNK_BEACON_JITTER_MS) + 30000u)

typedef struct {
    void *ctx;
    // Put one frame on air at `power_dbm` (conducted, at the antenna port);
    // TX done comes back through ah_trunk_on_tx_done. An `answer` (an
    // acknowledgement a sender is waiting on) goes at once; anything else may
    // listen before talking. Returns false when the radio cannot take a frame
    // now, and the trunk offers it again.
    bool (*transmit)(void *ctx, const uint8_t *frame, size_t len, int8_t power_dbm, bool answer);
    // A whole bitchat packet arrived from the neighbor in table slot `slot`.
    void (*deliver)(void *ctx, int slot, const uint8_t node[AH_TRUNK_NODE_LEN], const uint8_t *packet, size_t len);
    // The neighbor in `slot` was heard for the first time, or is gone (the slot is free after a down).
    void (*neighbor)(void *ctx, int slot, const uint8_t node[AH_TRUNK_NODE_LEN], bool up);
    // The pair key with the node whose static key is `peer_key`
    // (ah_trunk_auth_pair_key under this node's secret, which the trunk never
    // holds). Returns false for a key no pair key comes from.
    bool (*pair_key)(void *ctx, const uint8_t peer_key[AH_TRUNK_KEY_LEN], const uint8_t peer[AH_TRUNK_NODE_LEN],
                     uint8_t out[AH_TRUNK_KEY_LEN]);
} ah_trunk_ops_t;

typedef struct {
    uint8_t self[AH_TRUNK_NODE_LEN]; // this node's peer ID
    uint8_t key[AH_TRUNK_KEY_LEN];   // this node's static key, which the ID names
    const ah_lora_region_t *region;
    ah_lora_phy_t phy;
    int8_t max_power_dbm;            // ah_lora_power_limit for this board and antenna
} ah_trunk_config_t;

typedef struct {
    bool in_use;
    bool bound;                      // the mesh verified this neighbor's own announce
    uint8_t node[AH_TRUNK_NODE_LEN];
    uint8_t key[AH_TRUNK_KEY_LEN];   // the pair key with it
    int64_t heard_ms;                // the last frame it sent us tagged for us, or the beacon that introduced it
    int64_t tagged_ms;               // the last frame we sent it, tagged for it
    int8_t snr_db;                   // of the last frame heard from it
    int8_t power_dbm;                // the power that frame says it was sent at
    uint8_t failures;                // consecutive transfers that got nowhere
    bool boosted;                    // a round to it went unanswered: full power until a transfer gets through
} ah_trunk_neighbor_t;

// A node given up after failing transfers: not taken back as a neighbor on
// the strength of its beacons until the hold ends. The pair key is kept so a
// frame it sends us, which ends the hold, can be checked.
typedef struct {
    bool in_use;
    uint8_t strikes;                 // holds in a row, each twice the last
    uint8_t node[AH_TRUNK_NODE_LEN];
    uint8_t key[AH_TRUNK_KEY_LEN];
    int64_t until_ms;                // 0 once released; kept to double the next hold
} ah_trunk_hold_t;

typedef struct {
    bool in_use;
    uint8_t prio;
    uint32_t seq;
    int64_t queued_ms;
    uint8_t dest_count;
    uint8_t dests[AH_TRUNK_TAGS_MAX][AH_TRUNK_NODE_LEN];
    uint16_t len;
    uint8_t packet[AH_TRUNK_PACKET_MAX];
} ah_trunk_item_t;

// One destination of the transfer in flight.
typedef struct {
    uint8_t node[AH_TRUNK_NODE_LEN];
    uint8_t held;                    // the pieces it last said it holds
    bool done;                       // it said COMPLETE
    bool failed;                     // given up: silent too long, or gone
    bool answered;                   // it answered this round
    uint8_t silent_rounds;
} ah_trunk_dest_t;

typedef struct {
    bool active;
    uint8_t item;
    ah_trunk_arq_t arq;
    ah_trunk_frame_t header;         // the DATA header every piece repeats
    uint16_t chunk;
    uint8_t dest_count;
    ah_trunk_dest_t dests[AH_TRUNK_TAGS_MAX];
    bool awaiting;
    bool ask_on_air;                 // the asking piece's TX done is still to come
    uint8_t asked;                   // destinations the asking piece was tagged for
    bool probe;                      // after a silent round: one piece, asking for feedback
    int64_t feedback_by_ms;
    int64_t send_at_ms;              // a probe waits until then
    uint8_t silent_rounds;           // rounds in a row nobody answered
} ah_trunk_transfer_t;

typedef struct {
    bool in_use;
    bool done;                       // delivered; kept to answer a sender that missed our COMPLETE
    uint8_t source[AH_TRUNK_NODE_LEN];
    uint32_t transfer;
    uint8_t total;
    uint8_t have;
    uint16_t chunk;
    uint16_t last_len;
    int64_t touched_ms;
    uint8_t data[AH_TRUNK_PACKET_MAX];
    // The last piece, when it arrives before any full one says where it starts.
    uint16_t tail_len;
    uint8_t tail[AH_TRUNK_PIECE_MAX(1)];
} ah_trunk_rx_t;

// An answer waiting to go: to `node`, not before `send_at_ms`, which is its
// turn after the destinations tagged ahead of us.
typedef struct {
    ah_trunk_kind_t kind;
    uint8_t node[AH_TRUNK_NODE_LEN];
    uint32_t transfer;
    uint8_t index;
    uint8_t total;
    int64_t queued_ms;
    int64_t send_at_ms;
} ah_trunk_control_t;

typedef struct {
    uint32_t frames_tx;
    uint32_t frames_rx;
    // Malformed, naming us as source, a piece at odds with its transfer, or a
    // beacon whose key is not its source's or gives no pair key.
    uint32_t frames_bad;
    uint32_t frames_unknown;         // tagged frames from a source we hold no key for
    uint32_t transfers_ok;           // per destination
    uint32_t transfers_failed;       // per destination
    uint32_t refused;                // packets ah_trunk_send turned away
    uint32_t duty_deferred;
    uint32_t holds;                  // neighbors held down after failing
    uint32_t unbound_refused;        // frames for unverified neighbors past their share of the budget
    uint32_t answers_refused;        // answers past their share of the budget
} ah_trunk_stats_t;

typedef struct {
    // Eight-byte fields first, then the tables, then the small ones: the
    // struct is large and lives in internal RAM on boards without PSRAM.
    uint64_t rng;
    uint8_t beacon_turn;             // where the next beacon starts breaking ties, so the one left out rotates
    int64_t on_air_until_ms;
    int64_t last_beacon_ms;
    int64_t next_beacon_ms;
    int64_t reply_at_ms;             // a beacon owed to a node that does not know us; 0 for none
    int64_t duty_minute;
    ah_trunk_ops_t ops;
    ah_trunk_config_t cfg;
    ah_trunk_transfer_t tx;
    ah_trunk_control_t controls[AH_TRUNK_CONTROLS];
    ah_trunk_hold_t holds[AH_TRUNK_NEIGHBORS];
    ah_trunk_neighbor_t neighbors[AH_TRUNK_NEIGHBORS];
    ah_trunk_rx_t rx[AH_TRUNK_RX_SLOTS];
    ah_trunk_item_t queue[AH_TRUNK_QUEUE];
    uint32_t seq;
    uint32_t transfer;               // the last transfer number used
    uint32_t control_ms;             // airtime of an answer
    uint32_t beacon_jitter_ms;       // drawn afresh after each beacon
    ah_trunk_stats_t stats;
    // Airtime charged per minute over the duty window (a rolling hour).
    uint32_t duty_ms[AH_TRUNK_DUTY_BUCKETS];
    // The part of it sent to neighbors the mesh has not verified; a minute
    // holds at most 60,000 ms.
    uint16_t unbound_ms[AH_TRUNK_DUTY_BUCKETS];
    // The part of it spent on answers.
    uint16_t answer_ms[AH_TRUNK_DUTY_BUCKETS];
    uint8_t controls_count;
    bool on_air;
    bool beaconed;                   // a beacon has gone this boot
    bool budget_held;                // a frame waited for budget this tick
} ah_trunk_t;

// The duty ledger as one boot leaves it for the next: `minute_ms[k]` is the
// airtime charged k minutes before the minute it was taken in.
typedef struct {
    uint32_t minute_ms[AH_TRUNK_DUTY_BUCKETS];
} ah_trunk_ledger_t;

// `seed` is 8 random bytes, fresh each boot: it sets beacon and retry timing
// and where this boot's transfer numbers start.
void ah_trunk_init(ah_trunk_t *t, const ah_trunk_config_t *cfg, const ah_trunk_ops_t *ops, const uint8_t seed[8],
                   int64_t now_ms);

// Queue a packet for a neighbor, never displacing one already accepted. The
// same packet already waiting for other neighbors takes this one as another
// destination instead. Returns false, counted in `stats.refused`, when
// neither is possible (ah_trunk_room), `node` is no neighbor, or the packet
// is empty or oversized.
bool ah_trunk_send(ah_trunk_t *t, const uint8_t node[AH_TRUNK_NODE_LEN], const uint8_t *packet, size_t len,
                   uint8_t prio, int64_t now_ms);

// Whether a packet for neighbor `node` would be queued: a free slot, and the neighbor under its share.
bool ah_trunk_room(const ah_trunk_t *t, const uint8_t node[AH_TRUNK_NODE_LEN]);

void ah_trunk_on_frame(ah_trunk_t *t, const uint8_t *frame, size_t len, int8_t snr_db, int64_t now_ms);
void ah_trunk_on_tx_done(ah_trunk_t *t, int64_t now_ms);

// The mesh verified this neighbor's own announce. Until then the mesh sends it
// our announce only, which goes in one round with no probe, and everything
// sent to unverified neighbors together keeps to a share of the budget.
void ah_trunk_set_bound(ah_trunk_t *t, const uint8_t node[AH_TRUNK_NODE_LEN]);

// Run timers and start the next transmission. Returns when to call again.
int64_t ah_trunk_tick(ah_trunk_t *t, int64_t now_ms);

// The neighbor table slot holding `node`, or -1: the LoRa link's handle in the mesh.
int ah_trunk_slot_of(const ah_trunk_t *t, const uint8_t node[AH_TRUNK_NODE_LEN]);

// The node in a neighbor slot, or NULL.
const uint8_t *ah_trunk_node_at(const ah_trunk_t *t, int slot);

// Airtime spent in the rolling window, in milliseconds.
uint32_t ah_trunk_airtime_used(ah_trunk_t *t, int64_t now_ms);

// Airtime the region allows in the rolling window, in milliseconds.
uint32_t ah_trunk_budget_ms(const ah_trunk_t *t);

// The duty ledger as it stands at `now_ms`, for the device to keep across a reset.
void ah_trunk_ledger_save(ah_trunk_t *t, int64_t now_ms, ah_trunk_ledger_t *out);

// Whether a flash copy `flushed`, taken `minutes` before `now`, lacks enough
// of it to be written again: a sixty-first of the budget.
bool ah_trunk_ledger_flush_due(const ah_trunk_t *t, const ah_trunk_ledger_t *now, const ah_trunk_ledger_t *flushed,
                               int64_t minutes);

// Carry the duty window over a reset, right after ah_trunk_init. `saved` is
// the last ledger the boot before kept (in RTC memory across a reset, in
// flash across a power-on), counted as if that boot ended this minute, so the
// time the node was down ages nothing. NULL when nothing survived: the hour
// before is taken to have spent the whole budget, evenly, so the node sends
// nothing until a minute rolls over and then no faster than the region allows.
// A copy from flash (`flashed`) can lack what was charged after it was taken,
// less than a sixty-first of the budget and one frame, so that much more is
// charged to this minute: power cut however often, the node never spends
// airtime its ledger forgot.
void ah_trunk_ledger_restore(ah_trunk_t *t, const ah_trunk_ledger_t *saved, bool flashed, int64_t now_ms);
