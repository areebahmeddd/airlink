// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The trunk's state: neighbors and their pair keys, transfers in each
// direction, the duty budget, beacons and hold-down, advanced by received
// frames and ah_trunk_tick.
#include "ah_trunk.h"

#include <string.h>

#include "ah_crypto.h"
#include "ah_trunk_auth.h"

// Consecutive failed transfers before a neighbor is given up. One failure is
// already SILENT_ROUNDS silent rounds in a row (under 2 % at 30 % loss), so
// two in a row is a neighbor that is gone or cannot hear us, not a lossy one.
#define NEIGHBOR_FAILURES 2u
// A neighbor given up is held down for HOLD_MS, doubling each time it fails
// again, up to HOLD_MAX_MS. A node that hears us addresses us, and that ends
// the hold at once. Without the hold, a node we hear but that cannot hear us
// comes back with every beacon and costs two failed transfers each time: most
// of a tight region's budget.
#define HOLD_MS (10LL * 60 * 1000)
#define HOLD_MAX_MS (2LL * 60 * 60 * 1000)
#define HOLD_DOUBLINGS 4u
// A round is the missing pieces, the last asking for feedback, and the
// answers. At 30 % loss a round goes unanswered half the time (the asking
// piece or the answer lost), so recovery needs rounds to spare.
#define ROUNDS 12u
// Unanswered rounds in a row before a destination is given up. A round nobody
// answered is followed by a probe, one missing piece asking for feedback, not
// by every missing piece again, so a dead next hop costs the pieces plus five
// probes rather than every round in full. At 30 % loss this delivers about
// 99 % of three-piece packets (a Monte Carlo of exactly this state machine;
// the sender learns of about 97 %, the rest lose every COMPLETE).
#define SILENT_ROUNDS 6u
#define RX_IDLE_MS 30000
// A delivered transfer is remembered this long, to answer a sender that
// missed our COMPLETE.
#define RX_DONE_KEEP_MS 60000
// Time on top of the answers' airtime for the last of them to turn around and answer.
#define TURNAROUND_MS 1500u
// Between one destination's turn to answer and the next: the radio's switch
// from receive to transmit and the task's latency, with room for the two
// receivers' clocks to differ, since each counts from the end of the frame.
#define ANSWER_GAP_MS 100u
// How long a frame handed to the radio may wait for a clear channel before it
// is on air: four channel checks and the backoffs between them, each up to
// one full frame (2.3 s at SF10 and 125 kHz). The feedback timer starts at
// TX done; this bounds it when a TX done never comes.
#define CHANNEL_WAIT_MS 12000
// Data and probes stop a tenth short of the budget, so a node out of airtime
// still answers and beacons: its neighbors keep the link and keep reaching
// it, and only its own sending waits.
#define DATA_SHARE_DIVISOR 10u
// Everything sent to neighbors the mesh has not verified (our announce,
// answers to what they send, and beacons owed to nodes that do not know us)
// spends at most this share of the budget between them. Any radio can make a
// fresh identity and its beacon, so without it a few an hour would spend all
// of a tight region's data share; with it they take at most a quarter, and
// verified neighbors keep the rest. A quarter of India's 2.5 % is about a
// dozen announces an hour, enough to meet a full table of real neighbors.
#define UNBOUND_SHARE_DIVISOR 4u
// Answers spend at most this share of the budget. A captured piece tagged for
// us verifies again whenever it is replayed, and each replay that asks earns
// an answer; without a cap a replayer could spend the whole hour, reserve and
// all, and silence the node's own data and beacons. A node taking a neighbor's
// whole data share in pieces answers with well under a third of its own.
#define ANSWER_SHARE_DIVISOR 3u
// An answer not on air this long after it was queued is dropped: longer than
// the radio itself ever holds an answer back (behind our own frame's channel
// checks), so only one the budget holds back expires. Its sender has long
// since probed again, and each probe is answered afresh.
#define CONTROL_KEEP_MS CHANNEL_WAIT_MS
// APC: the margin above the SF's demodulation floor kept on the weakest link.
#define APC_MARGIN_DB 10
#define APC_FLOOR_DBM 2
// The first beacon soon after boot, so neighbors learn of a node at once, but
// spread, so nodes powered up together do not collide.
#define FIRST_BEACON_MS 2000
#define FIRST_BEACON_JITTER_MS 10000u
// A node that does not know us (a beacon without our tag, or a frame from a
// source whose key we lack, as after either side reboots) is owed our beacon
// within seconds, spread so the neighbors of a newcomer do not all answer at
// once, and never within REPLY_GAP_MS of our last: a crowd of new identities
// then costs at most a beacon every 30 s, within the unverified share.
#define REPLY_DELAY_MS 1000
#define REPLY_SPREAD_MS 9000u
#define REPLY_GAP_MS 30000

// Timing and transfer numbers only, nothing secret: splitmix64 over the seed.
static uint32_t random32(ah_trunk_t *t)
{
    uint64_t z = (t->rng += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return (uint32_t)((z ^ (z >> 31)) >> 32);
}

static bool same(const uint8_t a[AH_TRUNK_NODE_LEN], const uint8_t b[AH_TRUNK_NODE_LEN])
{
    return memcmp(a, b, AH_TRUNK_NODE_LEN) == 0;
}

static int64_t answer_slot_ms(const ah_trunk_t *t)
{
    return (int64_t)t->control_ms + (int64_t)ANSWER_GAP_MS;
}

// ---- duty budget ----

// A minute's bucket; minutes before the first of this boot are negative.
static size_t bucket_of(int64_t minute)
{
    const int64_t n = (int64_t)AH_TRUNK_DUTY_BUCKETS;
    return (size_t)(((minute % n) + n) % n);
}

static void duty_roll(ah_trunk_t *t, int64_t now_ms)
{
    const int64_t minute = now_ms / 60000;
    if (minute == t->duty_minute) {
        return;
    }
    const int64_t steps = minute - t->duty_minute;
    for (int64_t i = 1; i <= steps && i <= (int64_t)AH_TRUNK_DUTY_BUCKETS; ++i) {
        t->duty_ms[bucket_of(t->duty_minute + i)] = 0;
        t->unbound_ms[bucket_of(t->duty_minute + i)] = 0;
        t->answer_ms[bucket_of(t->duty_minute + i)] = 0;
    }
    t->duty_minute = minute;
}

static uint32_t unbound_used(ah_trunk_t *t, int64_t now_ms)
{
    duty_roll(t, now_ms);
    uint32_t used = 0;
    for (size_t i = 0; i < AH_TRUNK_DUTY_BUCKETS; ++i) {
        used += t->unbound_ms[i];
    }
    return used;
}

static uint32_t answers_used(ah_trunk_t *t, int64_t now_ms)
{
    duty_roll(t, now_ms);
    uint32_t used = 0;
    for (size_t i = 0; i < AH_TRUNK_DUTY_BUCKETS; ++i) {
        used += t->answer_ms[i];
    }
    return used;
}

uint32_t ah_trunk_airtime_used(ah_trunk_t *t, int64_t now_ms)
{
    duty_roll(t, now_ms);
    uint32_t used = 0;
    for (size_t i = 0; i < AH_TRUNK_DUTY_BUCKETS; ++i) {
        used += t->duty_ms[i];
    }
    return used;
}

uint32_t ah_trunk_budget_ms(const ah_trunk_t *t)
{
    // Per mille of a window in seconds is milliseconds of the window: 10 % of
    // an hour is 100 x 3600 = 360,000 ms.
    return (uint32_t)t->cfg.region->duty_per_mille * t->cfg.region->duty_window_s;
}

void ah_trunk_ledger_save(ah_trunk_t *t, int64_t now_ms, ah_trunk_ledger_t *out)
{
    duty_roll(t, now_ms);
    for (size_t k = 0; k < AH_TRUNK_DUTY_BUCKETS; ++k) {
        out->minute_ms[k] = t->duty_ms[bucket_of(t->duty_minute - (int64_t)k)];
    }
}

// Airtime charged in `now` that `then`, taken `minutes` earlier, does not hold.
static uint32_t ledger_added(const ah_trunk_ledger_t *now, const ah_trunk_ledger_t *then, int64_t minutes)
{
    uint32_t added = 0;
    for (size_t k = 0; k < AH_TRUNK_DUTY_BUCKETS; ++k) {
        // The minute k back now was k + minutes back then.
        const int64_t back = (int64_t)k + minutes;
        const uint32_t before = minutes >= 0 && back < (int64_t)AH_TRUNK_DUTY_BUCKETS ? then->minute_ms[back] : 0u;
        added += now->minute_ms[k] > before ? now->minute_ms[k] - before : 0u;
    }
    return added;
}

bool ah_trunk_ledger_flush_due(const ah_trunk_t *t, const ah_trunk_ledger_t *now, const ah_trunk_ledger_t *flushed,
                               int64_t minutes)
{
    return ledger_added(now, flushed, minutes) >= ah_trunk_budget_ms(t) / AH_TRUNK_DUTY_BUCKETS;
}

void ah_trunk_ledger_restore(ah_trunk_t *t, const ah_trunk_ledger_t *saved, bool flashed, int64_t now_ms)
{
    duty_roll(t, now_ms);
    const uint32_t budget = ah_trunk_budget_ms(t);
    for (size_t k = 0; k < AH_TRUNK_DUTY_BUCKETS; ++k) {
        uint32_t ms = budget / AH_TRUNK_DUTY_BUCKETS + (k == 0 ? budget % AH_TRUNK_DUTY_BUCKETS : 0u);
        if (saved != NULL) {
            // No minute holds more than a minute of airtime: a damaged
            // ledger can only err toward silence, never wrap the sum.
            ms = saved->minute_ms[k] < 60000u ? saved->minute_ms[k] : 60000u;
        }
        t->duty_ms[bucket_of(t->duty_minute - (int64_t)k)] += ms;
    }
    if (saved != NULL && flashed) {
        t->duty_ms[bucket_of(t->duty_minute)] +=
            budget / AH_TRUNK_DUTY_BUCKETS + ah_lora_airtime_charge_ms(&t->cfg.phy, AH_TRUNK_FRAME_MAX);
    }
}

// ---- neighbors ----

int ah_trunk_slot_of(const ah_trunk_t *t, const uint8_t node[AH_TRUNK_NODE_LEN])
{
    for (size_t i = 0; i < AH_TRUNK_NEIGHBORS; ++i) {
        if (t->neighbors[i].in_use && same(t->neighbors[i].node, node)) {
            return (int)i;
        }
    }
    return -1;
}

static ah_trunk_neighbor_t *neighbor_of(ah_trunk_t *t, const uint8_t node[AH_TRUNK_NODE_LEN])
{
    const int slot = ah_trunk_slot_of(t, node);
    return slot < 0 ? NULL : &t->neighbors[slot];
}

// Whether the mesh verified `node` by its own announce; a node no longer in
// the table is not.
static bool verified(const ah_trunk_t *t, const uint8_t node[AH_TRUNK_NODE_LEN])
{
    const int slot = ah_trunk_slot_of(t, node);
    return slot >= 0 && t->neighbors[slot].bound;
}

const uint8_t *ah_trunk_node_at(const ah_trunk_t *t, int slot)
{
    if (slot < 0 || slot >= (int)AH_TRUNK_NEIGHBORS || !t->neighbors[slot].in_use) {
        return NULL;
    }
    return t->neighbors[slot].node;
}

void ah_trunk_set_bound(ah_trunk_t *t, const uint8_t node[AH_TRUNK_NODE_LEN])
{
    ah_trunk_neighbor_t *n = neighbor_of(t, node);
    if (n != NULL) {
        n->bound = true;
    }
}

static bool is_open(const ah_trunk_dest_t *d)
{
    return !d->done && !d->failed;
}

static ah_trunk_dest_t *dest_of(ah_trunk_transfer_t *x, const uint8_t node[AH_TRUNK_NODE_LEN])
{
    for (uint8_t i = 0; i < x->dest_count; ++i) {
        if (same(x->dests[i].node, node)) {
            return &x->dests[i];
        }
    }
    return NULL;
}

// When the next beacon is due: an interval, and this beacon's jitter, after
// the neighbor this node tagged a frame for longest ago, and never sooner
// than an interval after the last beacon. A beacon holds seven tags, so with
// a full table of eight the one left out goes first in the next; none waits
// more than two intervals, well inside the time a silent neighbor is kept.
// The first beacon is set at boot.
static void schedule_beacon(ah_trunk_t *t)
{
    if (!t->beaconed) {
        return;
    }
    int64_t base = t->last_beacon_ms;
    bool any = false;
    for (size_t i = 0; i < AH_TRUNK_NEIGHBORS; ++i) {
        const ah_trunk_neighbor_t *n = &t->neighbors[i];
        if (n->in_use && (!any || n->tagged_ms < base)) {
            base = n->tagged_ms;
            any = true;
        }
    }
    base = base > t->last_beacon_ms ? base : t->last_beacon_ms;
    t->next_beacon_ms = base + (int64_t)AH_TRUNK_BEACON_INTERVAL_MS + (int64_t)t->beacon_jitter_ms;
}

// A neighbor gone takes what was queued for it alone, and its place in the
// transfer in flight; the mesh reopens the link, and resends what matters,
// when the neighbor is heard again.
static void neighbor_gone(ah_trunk_t *t, ah_trunk_neighbor_t *n)
{
    for (size_t i = 0; i < AH_TRUNK_QUEUE; ++i) {
        ah_trunk_item_t *q = &t->queue[i];
        if (!q->in_use || (t->tx.active && t->tx.item == i)) {
            continue;
        }
        for (uint8_t d = 0; d < q->dest_count; ++d) {
            if (same(q->dests[d], n->node)) {
                q->dest_count--;
                memmove(q->dests[d], q->dests[d + 1u], (size_t)(q->dest_count - d) * AH_TRUNK_NODE_LEN);
                break;
            }
        }
        q->in_use = q->dest_count != 0;
    }
    ah_trunk_dest_t *d = t->tx.active ? dest_of(&t->tx, n->node) : NULL;
    if (d != NULL && is_open(d)) {
        d->failed = true;
        t->stats.transfers_failed++;
    }
    n->in_use = false;
    ah_wipe(n->key, sizeof(n->key));
    t->ops.neighbor(t->ops.ctx, (int)(n - t->neighbors), n->node, false);
    schedule_beacon(t);
}

static ah_trunk_hold_t *hold_of(ah_trunk_t *t, const uint8_t node[AH_TRUNK_NODE_LEN])
{
    for (size_t i = 0; i < AH_TRUNK_NEIGHBORS; ++i) {
        if (t->holds[i].in_use && same(t->holds[i].node, node)) {
            return &t->holds[i];
        }
    }
    return NULL;
}

static void hold_drop(ah_trunk_hold_t *h)
{
    h->in_use = false;
    ah_wipe(h->key, sizeof(h->key));
}

static void hold(ah_trunk_t *t, const ah_trunk_neighbor_t *n, int64_t now_ms)
{
    ah_trunk_hold_t *h = hold_of(t, n->node);
    if (h == NULL) {
        // A free entry, else the one released or ending soonest.
        h = &t->holds[0];
        for (size_t i = 0; i < AH_TRUNK_NEIGHBORS; ++i) {
            ah_trunk_hold_t *c = &t->holds[i];
            if (!c->in_use) {
                h = c;
                break;
            }
            if (c->until_ms < h->until_ms) {
                h = c;
            }
        }
        hold_drop(h);
        memset(h, 0, sizeof(*h));
        h->in_use = true;
        memcpy(h->node, n->node, AH_TRUNK_NODE_LEN);
    }
    memcpy(h->key, n->key, AH_TRUNK_KEY_LEN);
    const unsigned doublings = h->strikes < HOLD_DOUBLINGS ? h->strikes : HOLD_DOUBLINGS;
    const int64_t span = HOLD_MS << doublings;
    h->until_ms = now_ms + (span < HOLD_MAX_MS ? span : HOLD_MAX_MS);
    if (h->strikes < UINT8_MAX) {
        h->strikes++;
    }
    t->stats.holds++;
}

// The power a frame says it was sent at, held to what a node may send here:
// even a frame from a real node moves the power choice no further than any
// node's could. Nothing sends under the APC floor or over the region's
// ceiling at 0 dBi.
static int8_t claimed_power(const ah_trunk_t *t, int8_t claimed)
{
    const ah_lora_region_t *r = t->cfg.region;
    const bool conducted = r->conducted_limit_ddbm != 0 && r->conducted_limit_ddbm < r->eirp_limit_ddbm;
    const int ceiling = (conducted ? r->conducted_limit_ddbm : r->eirp_limit_ddbm) / 10;
    if (claimed < APC_FLOOR_DBM) {
        return APC_FLOOR_DBM;
    }
    return (int8_t)(claimed > ceiling ? ceiling : claimed);
}

// What a frame from `n`, tagged for us, says of the link.
static void heard(ah_trunk_t *t, ah_trunk_neighbor_t *n, const ah_trunk_frame_t *f, int8_t snr_db, int64_t now_ms)
{
    n->heard_ms = now_ms;
    n->snr_db = snr_db;
    n->power_dbm = claimed_power(t, f->power_dbm);
}

// Whether a new neighbor would find a place: a free slot, or an unbound one to give up.
static bool has_room(const ah_trunk_t *t)
{
    for (size_t i = 0; i < AH_TRUNK_NEIGHBORS; ++i) {
        if (!t->neighbors[i].in_use || !t->neighbors[i].bound) {
            return true;
        }
    }
    return false;
}

// A new neighbor under its pair key, or NULL when the table is full of
// verified neighbors. A full table gives up an unbound neighbor first, the
// one heard longest ago: fresh identities churn each other, not real nodes.
static ah_trunk_neighbor_t *add_neighbor(ah_trunk_t *t, const uint8_t node[AH_TRUNK_NODE_LEN],
                                         const uint8_t key[AH_TRUNK_KEY_LEN], int64_t now_ms)
{
    ah_trunk_neighbor_t *victim = NULL;
    for (size_t i = 0; i < AH_TRUNK_NEIGHBORS; ++i) {
        ah_trunk_neighbor_t *c = &t->neighbors[i];
        if (!c->in_use) {
            victim = c;
            break;
        }
        if (!c->bound && (victim == NULL || c->heard_ms < victim->heard_ms)) {
            victim = c;
        }
    }
    if (victim == NULL) {
        return NULL;
    }
    if (victim->in_use) {
        neighbor_gone(t, victim);
    }
    memset(victim, 0, sizeof(*victim));
    victim->in_use = true;
    memcpy(victim->node, node, AH_TRUNK_NODE_LEN);
    memcpy(victim->key, key, AH_TRUNK_KEY_LEN);
    victim->heard_ms = now_ms;
    // Introduced by its beacon, not by anything we tagged for it; the beacon
    // it is owed comes through the reply, not the liveness schedule.
    victim->tagged_ms = now_ms;
    t->ops.neighbor(t->ops.ctx, (int)(victim - t->neighbors), victim->node, true);
    return victim;
}

// A node that does not know us is owed our beacon, put off until the gap
// since our last has passed. Before our first, which is due within seconds
// of boot, nothing is owed.
static void owe_reply(ah_trunk_t *t, int64_t now_ms)
{
    if (t->reply_at_ms != 0 || !t->beaconed) {
        return;
    }
    const int64_t soon = now_ms + REPLY_DELAY_MS + (int64_t)(random32(t) % REPLY_SPREAD_MS);
    const int64_t allowed = t->last_beacon_ms + REPLY_GAP_MS;
    t->reply_at_ms = soon > allowed ? soon : allowed;
}

// ---- transmitting ----

static bool listed(const uint8_t (*nodes)[AH_TRUNK_NODE_LEN], uint8_t count, const uint8_t node[AH_TRUNK_NODE_LEN])
{
    for (uint8_t i = 0; i < count; ++i) {
        if (same(nodes[i], node)) {
            return true;
        }
    }
    return false;
}

// The power that reaches every node the frame is for; a beacon is for every neighbor.
static int8_t power_for(const ah_trunk_t *t, const ah_trunk_frame_t *f, const uint8_t (*nodes)[AH_TRUNK_NODE_LEN],
                        uint8_t count)
{
    const int max = t->cfg.max_power_dbm;
    if (!t->cfg.region->adaptive_power) {
        return (int8_t)max;
    }
    // The SNR at the demodulation floor: -7.5 dB at SF7 to -20 dB at SF12,
    // 2.5 dB a step (datasheet table 6-1), rounded toward more power.
    const int floor_db = -((5 * (int)t->cfg.phy.spreading_factor - 20) / 2);
    // The power each destination needs: what it sent at, less how far above
    // the floor and the margin we heard it. Path loss is the same both ways;
    // the powers at each end need not be.
    bool any = false;
    int need = APC_FLOOR_DBM;
    for (size_t i = 0; i < AH_TRUNK_NEIGHBORS; ++i) {
        const ah_trunk_neighbor_t *n = &t->neighbors[i];
        if (!n->in_use || (f->kind != AH_TRUNK_KIND_BEACON && !listed(nodes, count, n->node))) {
            continue;
        }
        // A round it never answered says the margin was not enough (more
        // noise at its end than ours): the ceiling, until a transfer gets through.
        const int p = n->boosted ? max : n->power_dbm - (n->snr_db - floor_db - APC_MARGIN_DB);
        if (!any || p > need) {
            need = p;
        }
        any = true;
    }
    if (!any) {
        return (int8_t)max;
    }
    need = need < APC_FLOOR_DBM ? APC_FLOOR_DBM : need;
    return (int8_t)(need > max ? max : need);
}

typedef enum {
    EMIT_SENT,
    EMIT_LATER,   // the radio: offer it again
    EMIT_BUDGET,  // the duty budget: offer it again once a minute rolls off
    EMIT_REFUSED, // past the share for unverified neighbors or answers, or nobody to tag: waiting would not help
} emit_t;

// Tag the frame for each of `nodes`, charge its airtime and hand it to the
// radio, or refuse when the budget would be passed. Only an `essential` frame
// (an answer or a beacon) may spend the reserve DATA_SHARE_DIVISOR keeps; an
// `unbound` one, or one for unverified neighbors alone, keeps to their share.
static emit_t emit(ah_trunk_t *t, ah_trunk_frame_t *f, const uint8_t (*nodes)[AH_TRUNK_NODE_LEN], uint8_t count,
                   bool essential, bool unbound, int64_t now_ms)
{
    f->power_dbm = power_for(t, f, nodes, count);
    f->tag_count = count;
    memset(f->tags, 0, sizeof(f->tags));
    uint8_t frame[AH_TRUNK_FRAME_MAX];
    const size_t len = ah_trunk_frame_encode(f, frame, sizeof(frame));
    if (len == 0) {
        return EMIT_REFUSED;
    }
    const uint32_t airtime = ah_lora_airtime_charge_ms(&t->cfg.phy, (uint16_t)len);
    if (airtime == 0) {
        return EMIT_LATER;
    }
    bool any_verified = false;
    for (uint8_t i = 0; i < count; ++i) {
        const ah_trunk_neighbor_t *n = neighbor_of(t, nodes[i]);
        if (n == NULL) {
            return EMIT_REFUSED;
        }
        any_verified = any_verified || n->bound;
    }
    unbound = unbound || (f->kind != AH_TRUNK_KIND_BEACON && !any_verified);
    const uint32_t budget = ah_trunk_budget_ms(t);
    const uint32_t limit = essential ? budget : budget - budget / DATA_SHARE_DIVISOR;
    if (ah_trunk_airtime_used(t, now_ms) + airtime > limit) {
        t->stats.duty_deferred++;
        t->budget_held = true;
        return EMIT_BUDGET;
    }
    if (unbound && unbound_used(t, now_ms) + airtime > budget / UNBOUND_SHARE_DIVISOR) {
        t->stats.unbound_refused++;
        return EMIT_REFUSED;
    }
    const bool answer = f->kind == AH_TRUNK_KIND_ACK || f->kind == AH_TRUNK_KIND_COMPLETE;
    if (answer && answers_used(t, now_ms) + airtime > budget / ANSWER_SHARE_DIVISOR) {
        t->stats.answers_refused++;
        return EMIT_REFUSED;
    }
    // Tagged only once the frame may go: a frame the budget holds back costs no hashing.
    const size_t tags_at = ah_trunk_frame_tags_at(f->kind);
    for (uint8_t i = 0; i < count; ++i) {
        const ah_trunk_neighbor_t *n = neighbor_of(t, nodes[i]);
        if (!ah_trunk_auth_tag(n->key, frame, len, f, frame + tags_at + (size_t)i * AH_TRUNK_TAG_LEN)) {
            return EMIT_LATER;
        }
    }
    // Charged before the radio is asked, so the ledger the device keeps across
    // a reset already holds the frame when it goes on air: a brownout as the
    // PA keys still finds it spent. Refunded if the radio refuses.
    const size_t bucket = bucket_of(t->duty_minute);
    t->duty_ms[bucket] += airtime;
    if (unbound) {
        t->unbound_ms[bucket] += (uint16_t)airtime;
    }
    if (answer) {
        t->answer_ms[bucket] += (uint16_t)airtime;
    }
    if (!t->ops.transmit(t->ops.ctx, frame, len, f->power_dbm, answer)) {
        t->duty_ms[bucket] -= airtime;
        if (unbound) {
            t->unbound_ms[bucket] -= (uint16_t)airtime;
        }
        if (answer) {
            t->answer_ms[bucket] -= (uint16_t)airtime;
        }
        return EMIT_LATER;
    }
    t->on_air = true;
    // A TX done that never comes is caught by the radio's own watchdog; this
    // only stops the trunk waiting on it forever.
    t->on_air_until_ms = now_ms + (int64_t)airtime + CHANNEL_WAIT_MS;
    for (uint8_t i = 0; i < count; ++i) {
        neighbor_of(t, nodes[i])->tagged_ms = now_ms;
    }
    if (f->kind == AH_TRUNK_KIND_BEACON) {
        t->beaconed = true;
        t->last_beacon_ms = now_ms;
        t->beacon_jitter_ms = random32(t) % AH_TRUNK_BEACON_JITTER_MS;
        t->reply_at_ms = 0;
    }
    schedule_beacon(t);
    t->stats.frames_tx++;
    return EMIT_SENT;
}

static void drop_control(ah_trunk_t *t, uint8_t i)
{
    const size_t after = (size_t)(t->controls_count - i - 1u);
    memmove(&t->controls[i], &t->controls[i + 1u], after * sizeof(t->controls[0]));
    t->controls_count--;
}

static void queue_answer(ah_trunk_t *t, const ah_trunk_rx_t *slot, ah_trunk_kind_t kind, uint8_t index,
                         int64_t send_at_ms, int64_t now_ms)
{
    // With the answer share spent the answer would be refused at its turn,
    // and the node's own frames would wait for that turn for nothing.
    if (answers_used(t, now_ms) + ah_lora_airtime_charge_ms(&t->cfg.phy, AH_TRUNK_ANSWER_LEN) >
            ah_trunk_budget_ms(t) / ANSWER_SHARE_DIVISOR) {
        t->stats.answers_refused++;
        return;
    }
    const ah_trunk_control_t c = {
        .kind = kind, .transfer = slot->transfer, .index = index, .total = slot->total, .queued_ms = now_ms,
        .send_at_ms = send_at_ms,
    };
    // A newer answer for the same transfer replaces one not yet sent, but
    // keeps a turn still to come, and its age: no honest sender asks again
    // before its turns have passed, so that ask is a replay, maybe with our
    // tag moved to a later turn (tags do not cover their order), and taking
    // its turn would hold the node's own frames back for good. Once the turn
    // has passed, a new round's ask brings its own.
    for (uint8_t i = 0; i < t->controls_count; ++i) {
        ah_trunk_control_t *q = &t->controls[i];
        if (q->transfer == c.transfer && same(q->node, slot->source)) {
            const bool turn_to_come = q->send_at_ms > now_ms;
            const int64_t queued_ms = q->queued_ms;
            const int64_t send_at_ms_kept = q->send_at_ms;
            *q = c;
            if (turn_to_come) {
                q->queued_ms = queued_ms;
                q->send_at_ms = send_at_ms_kept;
            }
            memcpy(q->node, slot->source, AH_TRUNK_NODE_LEN);
            return;
        }
    }
    if (t->controls_count == AH_TRUNK_CONTROLS && verified(t, slot->source)) {
        // A verified neighbor's answer takes the place of the newest one for
        // an unverified source, so a crowd of new identities never crowds out a real one.
        for (uint8_t i = AH_TRUNK_CONTROLS; i-- > 0;) {
            if (!verified(t, t->controls[i].node)) {
                drop_control(t, i);
                break;
            }
        }
    }
    if (t->controls_count < AH_TRUNK_CONTROLS) {
        t->controls[t->controls_count] = c;
        memcpy(t->controls[t->controls_count].node, slot->source, AH_TRUNK_NODE_LEN);
        t->controls_count++;
    }
}

static void finish_transfer(ah_trunk_t *t)
{
    t->queue[t->tx.item].in_use = false;
    t->tx.active = false;
}

static uint8_t open_count(const ah_trunk_transfer_t *x)
{
    uint8_t open = 0;
    for (uint8_t i = 0; i < x->dest_count; ++i) {
        open += is_open(&x->dests[i]) ? 1u : 0u;
    }
    return open;
}

// The pieces every destination still waiting holds: a round sends the rest.
static void update_held(ah_trunk_transfer_t *x)
{
    uint8_t held = ah_trunk_frame_mask(x->arq.total);
    for (uint8_t i = 0; i < x->dest_count; ++i) {
        if (is_open(&x->dests[i])) {
            held &= x->dests[i].held;
        }
    }
    ah_trunk_arq_hold(&x->arq, held);
}

static void delivered_to(ah_trunk_t *t, ah_trunk_dest_t *d)
{
    d->done = true;
    t->stats.transfers_ok++;
    ah_trunk_hold_t *h = hold_of(t, d->node);
    if (h != NULL) {
        hold_drop(h);
    }
    ah_trunk_neighbor_t *n = neighbor_of(t, d->node);
    if (n != NULL) {
        n->failures = 0;
        n->boosted = false;
    }
}

static void fail_dest(ah_trunk_t *t, ah_trunk_dest_t *d, int64_t now_ms)
{
    d->failed = true;
    t->stats.transfers_failed++;
    ah_trunk_neighbor_t *n = neighbor_of(t, d->node);
    if (n != NULL && ++n->failures >= NEIGHBOR_FAILURES) {
        hold(t, n, now_ms);
        neighbor_gone(t, n);
    }
}

static void fail_open(ah_trunk_t *t, int64_t now_ms)
{
    for (uint8_t i = 0; i < t->tx.dest_count; ++i) {
        if (is_open(&t->tx.dests[i])) {
            fail_dest(t, &t->tx.dests[i], now_ms);
        }
    }
    finish_transfer(t);
}

// The next round for whoever still waits; a probe when nobody answered the last.
static void next_round(ah_trunk_t *t, bool probe, int64_t now_ms)
{
    ah_trunk_transfer_t *x = &t->tx;
    if (!ah_trunk_arq_next_round(&x->arq, ROUNDS)) {
        fail_open(t, now_ms);
        return;
    }
    for (uint8_t i = 0; i < x->dest_count; ++i) {
        x->dests[i].answered = false;
    }
    x->probe = probe;
    // A random part of a short frame before the probe: two senders that
    // collided once do not collide again on every probe.
    x->send_at_ms = probe ? now_ms + (int64_t)(random32(t) % (t->control_ms + 1u)) : 0;
}

// The oldest of the most urgent packets whose fanout has had time to join it.
static int next_item(const ah_trunk_t *t, int64_t now_ms)
{
    int best = -1;
    for (size_t i = 0; i < AH_TRUNK_QUEUE; ++i) {
        const ah_trunk_item_t *q = &t->queue[i];
        if (q->in_use && now_ms - q->queued_ms >= AH_TRUNK_COALESCE_MS &&
                (best < 0 || q->prio < t->queue[best].prio ||
                 (q->prio == t->queue[best].prio && q->seq < t->queue[best].seq))) {
            best = (int)i;
        }
    }
    return best;
}

static void start_transfer(ah_trunk_t *t, int64_t now_ms)
{
    const int best = next_item(t, now_ms);
    if (best < 0) {
        return;
    }
    ah_trunk_transfer_t *x = &t->tx;
    const ah_trunk_item_t *item = &t->queue[best];
    memset(x, 0, sizeof(*x));
    // Pieces sized for every destination's tag, so the chunk holds for the
    // whole transfer as destinations finish and drop out of the tags.
    const uint16_t piece_max = (uint16_t)AH_TRUNK_PIECE_MAX(item->dest_count);
    const uint8_t total = (uint8_t)((item->len + piece_max - 1u) / piece_max);
    if (!ah_trunk_arq_init(&x->arq, total)) {
        t->queue[best].in_use = false;
        return;
    }
    // Pieces of equal size, so the last is never a few bytes of lone header.
    x->chunk = (uint16_t)((item->len + total - 1u) / total);
    x->item = (uint8_t)best;
    x->active = true;
    x->dest_count = item->dest_count;
    for (uint8_t i = 0; i < item->dest_count; ++i) {
        memcpy(x->dests[i].node, item->dests[i], AH_TRUNK_NODE_LEN);
    }
    ah_trunk_frame_t *h = &x->header;
    h->kind = AH_TRUNK_KIND_DATA;
    h->total = total;
    memcpy(h->source, t->cfg.self, AH_TRUNK_NODE_LEN);
    if (++t->transfer == 0) {
        t->transfer = 1;
    }
    h->transfer = t->transfer;
}

// Send the next missing piece of the round, or the probe, tagged for every
// destination still waiting, in the order they answer.
static void send_piece(ah_trunk_t *t, int64_t now_ms)
{
    ah_trunk_transfer_t *x = &t->tx;
    const ah_trunk_item_t *item = &t->queue[x->item];
    const int index = x->probe ? ah_trunk_arq_probe(&x->arq) : ah_trunk_arq_next(&x->arq);
    if (index < 0) {
        // Unreachable while some destination still lacks a piece; never leave a transfer stuck.
        fail_open(t, now_ms);
        return;
    }
    uint8_t nodes[AH_TRUNK_TAGS_MAX][AH_TRUNK_NODE_LEN];
    uint8_t count = 0;
    for (uint8_t i = 0; i < x->dest_count; ++i) {
        if (is_open(&x->dests[i])) {
            memcpy(nodes[count++], x->dests[i].node, AH_TRUNK_NODE_LEN);
        }
    }
    ah_trunk_frame_t f = x->header;
    f.index = (uint8_t)index;
    const size_t start = (size_t)index * x->chunk;
    f.payload = item->packet + start;
    f.payload_len = (uint16_t)(item->len - start < x->chunk ? item->len - start : x->chunk);
    // Only the round's last piece asks: one answer each per round, not per piece.
    ah_trunk_arq_t after = x->arq;
    ah_trunk_arq_sent(&after, (uint8_t)index);
    const bool asks = x->probe || ah_trunk_arq_next(&after) < 0;
    f.flags = asks ? AH_TRUNK_FLAG_ASK : 0;
    const emit_t sent = emit(t, &f, (const uint8_t (*)[AH_TRUNK_NODE_LEN])nodes, count, false, false, now_ms);
    if (sent == EMIT_REFUSED) {
        // Our announce to unverified neighbors, past their share: dropped,
        // not failed, and the mesh offers it again at its next interval.
        finish_transfer(t);
        return;
    }
    if (sent != EMIT_SENT) {
        return;
    }
    x->arq = after;
    if (asks) {
        // Provisional: TX done restarts it from when the frame left.
        x->awaiting = true;
        x->ask_on_air = true;
        x->asked = count;
        x->feedback_by_ms = now_ms + CHANNEL_WAIT_MS +
                            (int64_t)ah_lora_airtime_ms(&t->cfg.phy,
                                                        (uint16_t)(AH_TRUNK_DATA_HEADER_LEN(count) + f.payload_len)) +
                            count * answer_slot_ms(t) + (int64_t)TURNAROUND_MS;
    }
}

// A beacon tagged for the neighbors this node tagged a frame for longest ago,
// as many as one beacon holds. `reply` is one owed to a node that does not know us.
// Ties break from a slot that moves on each beacon, so with a full table each
// neighbor in turn is the one left out, never the same two every other beacon.
static void send_beacon(ah_trunk_t *t, bool reply, int64_t now_ms)
{
    uint8_t nodes[AH_TRUNK_TAGS_MAX][AH_TRUNK_NODE_LEN];
    uint8_t count = 0;
    bool taken[AH_TRUNK_NEIGHBORS] = {false};
    while (count < AH_TRUNK_TAGS_MAX) {
        int oldest = -1;
        for (size_t k = 0; k < AH_TRUNK_NEIGHBORS; ++k) {
            const size_t i = (t->beacon_turn + k) % AH_TRUNK_NEIGHBORS;
            const ah_trunk_neighbor_t *n = &t->neighbors[i];
            if (n->in_use && !taken[i] && (oldest < 0 || n->tagged_ms < t->neighbors[oldest].tagged_ms)) {
                oldest = (int)i;
            }
        }
        if (oldest < 0) {
            break;
        }
        taken[oldest] = true;
        memcpy(nodes[count++], t->neighbors[oldest].node, AH_TRUNK_NODE_LEN);
    }
    t->beacon_turn = (uint8_t)((t->beacon_turn + 1u) % AH_TRUNK_NEIGHBORS);
    ah_trunk_frame_t b = {.kind = AH_TRUNK_KIND_BEACON};
    memcpy(b.source, t->cfg.self, AH_TRUNK_NODE_LEN);
    memcpy(b.key, t->cfg.key, AH_TRUNK_KEY_LEN);
    if (emit(t, &b, (const uint8_t (*)[AH_TRUNK_NODE_LEN])nodes, count, true, reply, now_ms) == EMIT_REFUSED) {
        t->reply_at_ms = 0;
    }
}

void ah_trunk_init(ah_trunk_t *t, const ah_trunk_config_t *cfg, const ah_trunk_ops_t *ops, const uint8_t seed[8],
                   int64_t now_ms)
{
    memset(t, 0, sizeof(*t));
    t->cfg = *cfg;
    t->ops = *ops;
    memcpy(&t->rng, seed, sizeof(t->rng));
    // Where this boot's transfer numbers start: a receiver still holding
    // transfers from before a reboot never mistakes a new one for an old one.
    t->transfer = random32(t);
    t->control_ms = ah_lora_airtime_ms(&t->cfg.phy, AH_TRUNK_ANSWER_LEN);
    t->duty_minute = now_ms / 60000;
    t->next_beacon_ms = now_ms + FIRST_BEACON_MS + (int64_t)(random32(t) % FIRST_BEACON_JITTER_MS);
}

static unsigned held_for(const ah_trunk_t *t, const uint8_t node[AH_TRUNK_NODE_LEN], bool *free_slot)
{
    unsigned held = 0;
    *free_slot = false;
    for (size_t i = 0; i < AH_TRUNK_QUEUE; ++i) {
        const ah_trunk_item_t *q = &t->queue[i];
        if (!q->in_use) {
            *free_slot = true;
        } else if (listed((const uint8_t (*)[AH_TRUNK_NODE_LEN])q->dests, q->dest_count, node)) {
            held++;
        }
    }
    return held;
}

bool ah_trunk_send(ah_trunk_t *t, const uint8_t node[AH_TRUNK_NODE_LEN], const uint8_t *packet, size_t len,
                   uint8_t prio, int64_t now_ms)
{
    bool free_slot = false;
    const unsigned held =
        node != NULL && ah_trunk_slot_of(t, node) >= 0 ? held_for(t, node, &free_slot) : AH_TRUNK_PER_NEIGHBOR;
    if (len == 0 || len > AH_TRUNK_PACKET_MAX || held >= AH_TRUNK_PER_NEIGHBOR) {
        t->stats.refused++;
        return false;
    }
    // The same packet waiting for other neighbors, not yet started: one more destination.
    for (size_t i = 0; i < AH_TRUNK_QUEUE; ++i) {
        ah_trunk_item_t *q = &t->queue[i];
        if (q->in_use && !(t->tx.active && t->tx.item == i) && q->len == len && q->dest_count < AH_TRUNK_TAGS_MAX &&
                !listed((const uint8_t (*)[AH_TRUNK_NODE_LEN])q->dests, q->dest_count, node) &&
                memcmp(q->packet, packet, len) == 0) {
            memcpy(q->dests[q->dest_count++], node, AH_TRUNK_NODE_LEN);
            q->prio = prio < q->prio ? prio : q->prio;
            return true;
        }
    }
    if (!free_slot) {
        t->stats.refused++;
        return false;
    }
    for (size_t i = 0; i < AH_TRUNK_QUEUE; ++i) {
        ah_trunk_item_t *q = &t->queue[i];
        if (!q->in_use) {
            memset(q, 0, offsetof(ah_trunk_item_t, packet));
            q->in_use = true;
            q->prio = prio;
            q->seq = ++t->seq;
            q->queued_ms = now_ms;
            q->dest_count = 1;
            memcpy(q->dests[0], node, AH_TRUNK_NODE_LEN);
            q->len = (uint16_t)len;
            memcpy(q->packet, packet, len);
            return true;
        }
    }
    return false;
}

bool ah_trunk_room(const ah_trunk_t *t, const uint8_t node[AH_TRUNK_NODE_LEN])
{
    bool free_slot = false;
    const unsigned held = held_for(t, node, &free_slot);
    return free_slot && held < AH_TRUNK_PER_NEIGHBOR && ah_trunk_slot_of(t, node) >= 0;
}

// ---- receiving ----

static ah_trunk_rx_t *rx_slot(ah_trunk_t *t, const ah_trunk_frame_t *f, int64_t now_ms)
{
    ah_trunk_rx_t *free_slot = NULL;
    ah_trunk_rx_t *oldest = NULL;
    for (size_t i = 0; i < AH_TRUNK_RX_SLOTS; ++i) {
        ah_trunk_rx_t *s = &t->rx[i];
        if (s->in_use && s->transfer == f->transfer && same(s->source, f->source)) {
            return s;
        }
        if (!s->in_use && free_slot == NULL) {
            free_slot = s;
        }
        // Idle longest goes first, done ones before live ones.
        if (s->in_use && (oldest == NULL || (s->done && !oldest->done) ||
                          (s->done == oldest->done && s->touched_ms < oldest->touched_ms))) {
            oldest = s;
        }
    }
    ah_trunk_rx_t *s = free_slot != NULL ? free_slot : oldest;
    memset(s, 0, sizeof(*s));
    s->in_use = true;
    memcpy(s->source, f->source, AH_TRUNK_NODE_LEN);
    s->transfer = f->transfer;
    s->total = f->total;
    s->touched_ms = now_ms;
    return s;
}

// A piece tagged for us at `position` among its destinations: our answer goes
// in that turn, after the answers of those tagged ahead of us.
static void on_data(ah_trunk_t *t, const ah_trunk_frame_t *f, int position, int64_t now_ms)
{
    ah_trunk_rx_t *s = rx_slot(t, f, now_ms);
    if (s->total != f->total) {
        s->in_use = false;
        return;
    }
    s->touched_ms = now_ms;
    const uint8_t bit = (uint8_t)(1u << f->index);
    if (!s->done && (s->have & bit) == 0) {
        // Equal pieces: every piece but the last is the chunk size, and the
        // last is no longer. Its own length says nothing of where it starts,
        // so one that comes first is held until a full piece gives the size.
        const bool last = f->index + 1u == s->total;
        if (last && s->total > 1u && s->chunk == 0) {
            if (f->payload_len > sizeof(s->tail)) {
                s->in_use = false;
                t->stats.frames_bad++;
                return;
            }
            memcpy(s->tail, f->payload, f->payload_len);
            s->tail_len = f->payload_len;
        } else {
            if (s->chunk == 0 && !last) {
                s->chunk = f->payload_len;
            }
            const uint16_t chunk = s->chunk != 0 ? s->chunk : f->payload_len;
            const size_t at = (size_t)f->index * chunk;
            const size_t tail_at = (size_t)(s->total - 1u) * chunk;
            if ((!last && f->payload_len != chunk) || f->payload_len > chunk || at + f->payload_len > sizeof(s->data) ||
                    s->tail_len > chunk || (s->tail_len != 0 && tail_at + s->tail_len > sizeof(s->data))) {
                s->in_use = false;
                t->stats.frames_bad++;
                return;
            }
            memcpy(s->data + at, f->payload, f->payload_len);
            if (last) {
                s->last_len = f->payload_len;
            }
            if (s->tail_len != 0) {
                memcpy(s->data + tail_at, s->tail, s->tail_len);
                s->last_len = s->tail_len;
                s->tail_len = 0;
            }
        }
        s->have |= bit;
        if (s->have == ah_trunk_frame_mask(s->total)) {
            const size_t len = (size_t)(s->total - 1u) * (s->total > 1u ? s->chunk : 0u) + s->last_len;
            s->done = true;
            t->ops.deliver(t->ops.ctx, ah_trunk_slot_of(t, s->source), s->source, s->data, len);
        }
    }
    // Only a piece that asks is answered: the sender listens after it, and
    // after any other is already sending the next piece, which an answer
    // with no channel check would collide with.
    if ((f->flags & AH_TRUNK_FLAG_ASK) == 0) {
        return;
    }
    const int64_t send_at = now_ms + (int64_t)position * answer_slot_ms(t);
    if (s->done) {
        queue_answer(t, s, AH_TRUNK_KIND_COMPLETE, ah_trunk_frame_mask(s->total), send_at, now_ms);
    } else {
        queue_answer(t, s, AH_TRUNK_KIND_ACK, s->have, send_at, now_ms);
    }
}

static void on_control(ah_trunk_t *t, const ah_trunk_frame_t *f, int64_t now_ms)
{
    ah_trunk_transfer_t *x = &t->tx;
    ah_trunk_dest_t *d = x->active && ah_trunk_frame_answers(&x->header, f) ? dest_of(x, f->source) : NULL;
    if (d == NULL || !is_open(d)) {
        return;
    }
    // Taken whenever it comes, but only an answer to the round awaited counts
    // as answering it: a late one says nothing of the round being sent.
    d->answered = d->answered || x->awaiting;
    d->silent_rounds = 0;
    x->silent_rounds = 0;
    if (f->kind == AH_TRUNK_KIND_COMPLETE) {
        delivered_to(t, d);
    } else {
        d->held = f->index;
    }
    if (x->probe) {
        // Feedback is in: a full round of what is missing, not a probe.
        x->probe = false;
        x->send_at_ms = 0;
    }
    if (open_count(x) == 0) {
        finish_transfer(t);
        return;
    }
    update_held(x);
    // Every destination that was asked has answered: the next round starts
    // now, not at the timeout.
    bool all = true;
    for (uint8_t i = 0; i < x->dest_count; ++i) {
        all = all && (!is_open(&x->dests[i]) || x->dests[i].answered);
    }
    if (x->awaiting && all) {
        x->awaiting = false;
        next_round(t, false, now_ms);
    }
}

static void on_beacon(ah_trunk_t *t, const uint8_t *frame, size_t len, const ah_trunk_frame_t *f, int8_t snr_db,
                      int64_t now_ms)
{
    if (!ah_trunk_auth_names(f->key, f->source)) {
        t->stats.frames_bad++;
        return;
    }
    ah_trunk_neighbor_t *n = neighbor_of(t, f->source);
    if (n == NULL) {
        ah_trunk_hold_t *h = hold_of(t, f->source);
        // Held down: its beacons say only that we hear it.
        if (h != NULL && h->until_ms != 0 && now_ms < h->until_ms) {
            return;
        }
        // The exchange costs milliseconds of CPU: none for a node a table
        // full of verified neighbors would turn away anyway.
        if (!has_room(t)) {
            return;
        }
        uint8_t key[AH_TRUNK_KEY_LEN];
        if (!t->ops.pair_key(t->ops.ctx, f->key, f->source, key)) {
            t->stats.frames_bad++;
            return;
        }
        if (h != NULL) {
            h->until_ms = 0;
        }
        n = add_neighbor(t, f->source, key, now_ms);
        ah_wipe(key, sizeof(key));
        if (n == NULL) {
            return;
        }
        // The first word of it: an untagged claim, held to what a node may send.
        n->snr_db = snr_db;
        n->power_dbm = claimed_power(t, f->power_dbm);
    }
    if (ah_trunk_auth_find(n->key, frame, len, f) >= 0) {
        heard(t, n, f, snr_db, now_ms);
    } else if (f->tag_count < AH_TRUNK_TAGS_MAX ||
               now_ms - n->heard_ms > (int64_t)(AH_TRUNK_BEACON_INTERVAL_MS + AH_TRUNK_BEACON_JITTER_MS)) {
        // No tag for us, and room for one: a node that does not know us. A
        // full beacon may simply have left us for the next, unless nothing
        // tagged for us has come from it for a whole interval.
        owe_reply(t, now_ms);
    }
}

void ah_trunk_on_frame(ah_trunk_t *t, const uint8_t *frame, size_t len, int8_t snr_db, int64_t now_ms)
{
    ah_trunk_frame_t f;
    if (!ah_trunk_frame_parse(frame, len, &f) || same(f.source, t->cfg.self)) {
        // A malformed frame, or one claiming this node as its source, gets no
        // answer at all, so one forged frame cannot make every listener reply.
        t->stats.frames_bad++;
        return;
    }
    t->stats.frames_rx++;
    if (f.kind == AH_TRUNK_KIND_BEACON) {
        on_beacon(t, frame, len, &f, snr_db, now_ms);
        return;
    }
    ah_trunk_neighbor_t *n = neighbor_of(t, f.source);
    ah_trunk_hold_t *h = n == NULL ? hold_of(t, f.source) : NULL;
    if (n == NULL && h == NULL) {
        // A source we hold no key for: after either side reboots, or a node we
        // have not met. Our beacon, carrying no tag for it, has it send its own.
        t->stats.frames_unknown++;
        owe_reply(t, now_ms);
        return;
    }
    const int position = ah_trunk_auth_find(n != NULL ? n->key : h->key, frame, len, &f);
    if (position < 0) {
        // For another node, or forged: either way, not ours to act on.
        return;
    }
    if (n == NULL) {
        // A node held down, addressing us: it hears us, so the hold ends.
        h->until_ms = 0;
        n = add_neighbor(t, f.source, h->key, now_ms);
        if (n == NULL) {
            return;
        }
    }
    heard(t, n, &f, snr_db, now_ms);
    if (f.kind == AH_TRUNK_KIND_DATA) {
        on_data(t, &f, position, now_ms);
    } else {
        on_control(t, &f, now_ms);
    }
}

void ah_trunk_on_tx_done(ah_trunk_t *t, int64_t now_ms)
{
    t->on_air = false;
    // The answers can only start once the asking piece has ended, however
    // long the radio waited for a clear channel; an answer of ours sent while
    // they come moves nothing.
    ah_trunk_transfer_t *x = &t->tx;
    if (x->active && x->awaiting && x->ask_on_air) {
        x->ask_on_air = false;
        x->feedback_by_ms = now_ms + x->asked * answer_slot_ms(t) + (int64_t)TURNAROUND_MS;
    }
}

// The feedback window closed: whoever did not answer had a silent round.
static void feedback_timeout(ah_trunk_t *t, int64_t now_ms)
{
    ah_trunk_transfer_t *x = &t->tx;
    x->awaiting = false;
    bool any = false;
    for (uint8_t i = 0; i < x->dest_count && x->active; ++i) {
        ah_trunk_dest_t *d = &x->dests[i];
        if (!is_open(d)) {
            continue;
        }
        if (d->answered) {
            any = true;
            continue;
        }
        d->silent_rounds++;
        ah_trunk_neighbor_t *n = neighbor_of(t, d->node);
        if (n != NULL) {
            n->boosted = true;
        }
        // A neighbor nobody has verified gets one round and no probe: a new
        // identity's beacon then costs our announce once, not the pieces and
        // five probes of a transfer to nobody. The round still counts toward
        // its hold. One that is gone gets nothing more.
        if (n == NULL || !n->bound || d->silent_rounds >= SILENT_ROUNDS) {
            fail_dest(t, d, now_ms);
        }
    }
    if (!x->active) {
        return;
    }
    if (open_count(x) == 0) {
        finish_transfer(t);
        return;
    }
    update_held(x);
    if (!any) {
        x->silent_rounds++;
    }
    next_round(t, !any, now_ms);
}

int64_t ah_trunk_tick(ah_trunk_t *t, int64_t now_ms)
{
    duty_roll(t, now_ms);
    for (size_t i = 0; i < AH_TRUNK_NEIGHBORS; ++i) {
        ah_trunk_neighbor_t *n = &t->neighbors[i];
        if (n->in_use && now_ms - n->heard_ms > (int64_t)AH_TRUNK_NEIGHBOR_SILENT_MS) {
            neighbor_gone(t, n);
        }
    }
    for (size_t i = 0; i < AH_TRUNK_RX_SLOTS; ++i) {
        ah_trunk_rx_t *s = &t->rx[i];
        if (s->in_use && now_ms - s->touched_ms > (s->done ? RX_DONE_KEEP_MS : RX_IDLE_MS)) {
            s->in_use = false;
        }
    }
    int64_t next = now_ms + 1000;
    // What the budget holds back is offered again when the oldest minute
    // rolls off, not every 50 ms.
    const int64_t minute_end = (t->duty_minute + 1) * 60000;
    t->budget_held = false;
    if (t->on_air) {
        if (now_ms < t->on_air_until_ms) {
            return t->on_air_until_ms < next ? t->on_air_until_ms : next;
        }
        t->on_air = false;
    }
    ah_trunk_transfer_t *x = &t->tx;
    if (x->active && open_count(x) == 0) {
        // Its last destinations went with their neighbors.
        finish_transfer(t);
    }
    if (x->active && x->awaiting && now_ms >= x->feedback_by_ms) {
        feedback_timeout(t, now_ms);
    }
    for (uint8_t i = t->controls_count; i-- > 0;) {
        if (now_ms - t->controls[i].queued_ms > CONTROL_KEEP_MS) {
            drop_control(t, i);
        }
    }
    // Answers first, each in its turn: they are short, and a sender is waiting on each.
    for (uint8_t i = 0; i < t->controls_count; ++i) {
        const ah_trunk_control_t *c = &t->controls[i];
        if (now_ms < c->send_at_ms) {
            next = c->send_at_ms < next ? c->send_at_ms : next;
            continue;
        }
        ah_trunk_frame_t a = {
            .kind = c->kind, .transfer = c->transfer, .index = c->index, .total = c->total
        };
        memcpy(a.source, t->cfg.self, AH_TRUNK_NODE_LEN);
        uint8_t to[1][AH_TRUNK_NODE_LEN];
        memcpy(to[0], c->node, AH_TRUNK_NODE_LEN);
        const emit_t sent = emit(t, &a, (const uint8_t (*)[AH_TRUNK_NODE_LEN])to, 1, true, false, now_ms);
        if (sent == EMIT_SENT || sent == EMIT_REFUSED) {
            drop_control(t, i);
        }
        return sent == EMIT_BUDGET ? (minute_end < next ? minute_end : next) : now_ms + 50;
    }
    if (t->controls_count > 0) {
        // An answer waits for its turn: a frame of our own now could still be
        // on air when it comes, and its sender stops listening after the last turn.
        return next;
    }
    // Nor a beacon while the answers to our asking piece are due: the radio hears nothing as it sends.
    const bool beacon_due = now_ms >= t->next_beacon_ms;
    const bool reply_due = t->reply_at_ms != 0 && now_ms >= t->reply_at_ms;
    if ((beacon_due || reply_due) && !(x->active && x->awaiting)) {
        send_beacon(t, !beacon_due, now_ms);
        if (t->on_air) {
            return now_ms + 50;
        }
    }
    if (!x->active) {
        start_transfer(t, now_ms);
    }
    if (x->active && !x->awaiting) {
        if (now_ms < x->send_at_ms) {
            return x->send_at_ms < next ? x->send_at_ms : next;
        }
        send_piece(t, now_ms);
        if (t->budget_held) {
            return minute_end < next ? minute_end : next;
        }
        return now_ms + 50;
    }
    if (x->active && x->awaiting && x->feedback_by_ms < next) {
        next = x->feedback_by_ms;
    }
    if (!x->active) {
        // A packet waiting out its coalescing window.
        for (size_t i = 0; i < AH_TRUNK_QUEUE; ++i) {
            const int64_t at = t->queue[i].queued_ms + AH_TRUNK_COALESCE_MS;
            if (t->queue[i].in_use && at < next) {
                next = at;
            }
        }
    }
    if (t->reply_at_ms != 0 && t->reply_at_ms > now_ms && t->reply_at_ms < next) {
        next = t->reply_at_ms;
    }
    // A beacon the budget or the radio refused is retried within the second.
    return t->next_beacon_ms > now_ms && t->next_beacon_ms < next ? t->next_beacon_ms : next;
}
