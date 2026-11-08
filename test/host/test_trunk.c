// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The LoRa trunk's link layer between simulated radios: authentication, ARQ
// to one neighbor and to several at once, the duty budget and its region
// profiles.
#include <string.h>

#include "ah_crypto.h"
#include "ah_lora_region.h"
#include "ah_trunk.h"
#include "ah_trunk_auth.h"
#include "unity.h"

#define RADIOS 3

// A node's identity: its static secret and key, and the ID the key names.
typedef struct {
    uint8_t secret[32];
    uint8_t key[32];
    uint8_t node[8];
} ident_t;

typedef struct {
    ah_trunk_t trunk;
    ident_t id;
    uint8_t node[8];
    // What the radio is sending, from when it starts until its airtime has passed.
    uint8_t air[255];
    size_t air_len;
    int64_t air_from;
    int64_t air_until;
    // The frame before it, which may still have overlapped another's.
    int64_t prev_from;
    int64_t prev_until;
    bool on_air;
    int8_t last_power;
    // Delivered packets.
    uint8_t got[16][512];
    size_t got_len[16];
    size_t got_count;
    int neighbors_up;
    int neighbors_down;
    uint8_t last_up[8];
    uint32_t sent;
    uint32_t data_frames;
    uint32_t data_ms;                // airtime charged for DATA frames
    uint32_t beacons;
    int64_t beacon_at[16];
    uint8_t beacon_tags_most;        // the most tags any of its beacons carried
    uint32_t answers;
    // The airtime the trunk had charged when it asked for the last frame.
    uint32_t charged_when_sent;
} radio_t;

static radio_t s_r[RADIOS];
static int s_count;
static int64_t s_now;
static uint32_t s_loss_per_mille;
// How long a frame other than an answer waits for a clear channel.
static int64_t s_channel_wait_ms;
// Whether radio i's frames reach anyone, and whether they reach radio j.
static bool s_reach[RADIOS];
static bool s_link[RADIOS][RADIOS];
// Frames that overlap at a receiver are both lost there, and a radio hears
// nothing while it sends.
static bool s_collide;
static uint32_t s_collisions;
static int8_t s_snr;
// Hooks, NULL for none: s_drop may drop a frame before the loss draw, and
// s_after runs once a frame lands.
static bool (*s_drop)(int from, const ah_trunk_frame_t *f);
static void (*s_after)(int to, const ah_trunk_frame_t *f);
// The loss draws, restarted by every setup so a test's losses never depend on
// which tests ran before it.
static uint64_t s_rng;
// The mesh's part: a delivered packet (an announce, in these tests) binds its sender.
static bool s_bind_on_delivery;
// Radio 0's emissions across reboots, when and for how long, by wall time.
#define AIR_LOG 4096u
static int64_t s_air_at[AIR_LOG];
static uint32_t s_air_ms[AIR_LOG];
static size_t s_air_count;

static uint32_t draw(void)
{
    s_rng = s_rng * 6364136223846793005ull + 1442695040888963407ull;
    return (uint32_t)(s_rng >> 33) % 1000u;
}

static void ident_make(ident_t *id, uint8_t seed)
{
    for (size_t i = 0; i < sizeof(id->secret); ++i) {
        id->secret[i] = (uint8_t)(seed + i * 7u);
    }
    ah_x25519_public(id->secret, id->key);
    uint8_t hash[32];
    TEST_ASSERT_TRUE(ah_sha256(id->key, sizeof(id->key), hash));
    memcpy(id->node, hash, 8);
}

static int index_of(const radio_t *r)
{
    return (int)(r - s_r);
}

static bool transmit(void *ctx, const uint8_t *frame, size_t len, int8_t power, bool answer)
{
    radio_t *r = ctx;
    memcpy(r->air, frame, len);
    r->air_len = len;
    // An answer goes at once, as the device sends it, without listening first.
    const int64_t wait = answer ? 0 : s_channel_wait_ms;
    r->prev_from = r->air_from;
    r->prev_until = r->air_until;
    r->air_from = s_now + wait;
    r->air_until = r->air_from + (int64_t)ah_lora_airtime_ms(&r->trunk.cfg.phy, (uint16_t)len);
    r->on_air = true;
    r->sent++;
    r->last_power = power;
    r->charged_when_sent = ah_trunk_airtime_used(&r->trunk, s_now);
    ah_trunk_frame_t f;
    TEST_ASSERT_TRUE(ah_trunk_frame_parse(frame, len, &f));
    if (f.kind == AH_TRUNK_KIND_BEACON) {
        r->beacon_tags_most = f.tag_count > r->beacon_tags_most ? f.tag_count : r->beacon_tags_most;
        if (r->beacons < 16) {
            r->beacon_at[r->beacons] = s_now;
        }
        r->beacons++;
    } else if (f.kind == AH_TRUNK_KIND_DATA) {
        r->data_frames++;
        r->data_ms += ah_lora_airtime_charge_ms(&r->trunk.cfg.phy, (uint16_t)len);
    } else {
        r->answers++;
    }
    if (index_of(r) == 0 && s_air_count < AIR_LOG) {
        s_air_at[s_air_count] = s_now;
        s_air_ms[s_air_count++] = ah_lora_airtime_charge_ms(&r->trunk.cfg.phy, (uint16_t)len);
    }
    return true;
}

static void deliver(void *ctx, int slot, const uint8_t node[8], const uint8_t *packet, size_t len)
{
    TEST_ASSERT_TRUE(slot >= 0);
    radio_t *r = ctx;
    if (r->got_count < 16) {
        memcpy(r->got[r->got_count], packet, len);
        r->got_len[r->got_count++] = len;
    }
    if (s_bind_on_delivery) {
        ah_trunk_set_bound(&r->trunk, node);
    }
}

static void neighbor(void *ctx, int slot, const uint8_t node[8], bool up)
{
    TEST_ASSERT_TRUE(slot >= 0 && slot < (int)AH_TRUNK_NEIGHBORS);
    radio_t *r = ctx;
    if (up) {
        r->neighbors_up++;
        memcpy(r->last_up, node, 8);
    } else {
        r->neighbors_down++;
    }
}

static bool pair_key(void *ctx, const uint8_t peer_key[32], const uint8_t peer[8], uint8_t out[32])
{
    const radio_t *r = ctx;
    return ah_trunk_auth_pair_key(r->id.secret, r->id.node, peer_key, peer, out);
}

// Radio i, booted afresh: the same identity on every boot, as the device keeps it.
static void boot(int i, ah_lora_region_id_t region, uint8_t seed)
{
    radio_t *r = &s_r[i];
    memset(r, 0, sizeof(*r));
    ident_make(&r->id, (uint8_t)(0x51 + i * 0x22));
    memcpy(r->node, r->id.node, 8);
    const ah_lora_region_t *rg = ah_lora_region(region);
    ah_trunk_config_t c = {
        .region = rg,
        .phy = {
            .spreading_factor = rg->spreading_factor, .bandwidth_hz = rg->bandwidth_hz, .coding_rate = 5,
            .preamble_symbols = 8
        },
        .max_power_dbm = 22,
    };
    memcpy(c.self, r->node, 8);
    memcpy(c.key, r->id.key, 32);
    const ah_trunk_ops_t ops = {
        .ctx = r, .transmit = transmit, .deliver = deliver, .neighbor = neighbor, .pair_key = pair_key
    };
    uint8_t s[8];
    memset(s, seed, sizeof(s));
    ah_trunk_init(&r->trunk, &c, &ops, s, s_now);
}

static void setup_n(ah_lora_region_id_t region, int count)
{
    s_now = 1000;
    s_rng = 12345;
    s_count = count;
    s_loss_per_mille = 0;
    s_channel_wait_ms = 0;
    s_collide = false;
    s_collisions = 0;
    s_snr = 5;
    s_drop = NULL;
    s_after = NULL;
    s_bind_on_delivery = false;
    s_air_count = 0;
    for (int i = 0; i < RADIOS; ++i) {
        s_reach[i] = true;
        for (int j = 0; j < RADIOS; ++j) {
            s_link[i][j] = true;
        }
    }
    for (int i = 0; i < count; ++i) {
        boot(i, region, (uint8_t)(0xA0 + i));
    }
}

static void setup(ah_lora_region_id_t region)
{
    setup_n(region, 2);
}

static bool overlaps(int64_t from_a, int64_t until_a, int64_t from_b, int64_t until_b)
{
    return from_a < until_b && from_b < until_a;
}

// Whether radio i's frame, just ended, was lost at radio j to another frame on air there.
static bool collided(int i, int j)
{
    const radio_t *r = &s_r[i];
    for (int k = 0; k < s_count; ++k) {
        if (k == i || (k != j && !(s_reach[k] && s_link[k][j]))) {
            continue;
        }
        const radio_t *o = &s_r[k];
        const bool now = o->air_until != 0 && overlaps(r->air_from, r->air_until, o->air_from, o->air_until);
        const bool before = o->prev_until != 0 && overlaps(r->air_from, r->air_until, o->prev_from, o->prev_until);
        if (now || before) {
            return true;
        }
    }
    return false;
}

// Advance the shared channel: a frame lands on the other radios when its
// airtime ends, unless lost; every trunk runs its timers.
static void run(int64_t ms)
{
    const int64_t end = s_now + ms;
    while (s_now < end) {
        s_now += 10;
        for (int i = 0; i < s_count; ++i) {
            radio_t *r = &s_r[i];
            if (r->on_air && s_now >= r->air_until) {
                r->on_air = false;
                ah_trunk_on_tx_done(&r->trunk, s_now);
                ah_trunk_frame_t f;
                const bool parsed = ah_trunk_frame_parse(r->air, r->air_len, &f);
                const bool dropped = parsed && s_drop != NULL && s_drop(i, &f);
                for (int j = 0; j < s_count; ++j) {
                    if (j == i || !s_reach[i] || !s_link[i][j] || dropped) {
                        continue;
                    }
                    if (s_collide && collided(i, j)) {
                        s_collisions++;
                        continue;
                    }
                    if (draw() >= s_loss_per_mille) {
                        ah_trunk_on_frame(&s_r[j].trunk, r->air, r->air_len, s_snr, s_now);
                        if (parsed && s_after != NULL) {
                            s_after(j, &f);
                        }
                    }
                }
            }
            if (!r->on_air) {
                ah_trunk_tick(&r->trunk, s_now);
            }
        }
    }
}

static void bind_all(void)
{
    for (int i = 0; i < s_count; ++i) {
        for (int j = 0; j < s_count; ++j) {
            if (i != j) {
                ah_trunk_set_bound(&s_r[i].trunk, s_r[j].node);
            }
        }
    }
}

// Past every node's first beacon, so they know each other, and each has
// verified the others' announces, as the mesh tells the trunk.
static void meet_n(ah_lora_region_id_t region, int count)
{
    setup_n(region, count);
    run(20000);
    for (int i = 0; i < count; ++i) {
        for (int j = 0; j < count; ++j) {
            if (i != j) {
                TEST_ASSERT_TRUE(ah_trunk_slot_of(&s_r[i].trunk, s_r[j].node) >= 0);
            }
        }
    }
    bind_all();
}

static void meet(ah_lora_region_id_t region)
{
    meet_n(region, 2);
}

static bool send(int from, int to, const uint8_t *packet, size_t len, uint8_t prio)
{
    return ah_trunk_send(&s_r[from].trunk, s_r[to].node, packet, len, prio, s_now);
}

static size_t encode(const ah_trunk_frame_t *f, uint8_t *out)
{
    const size_t len = ah_trunk_frame_encode(f, out, AH_TRUNK_FRAME_MAX);
    TEST_ASSERT_NOT_EQUAL(0, len);
    return len;
}

// A frame from `from`, tagged for `to` alone, as `from`'s trunk would tag it.
static size_t tagged(const ident_t *from, const ident_t *to, ah_trunk_frame_t *f, uint8_t *wire)
{
    memcpy(f->source, from->node, 8);
    f->tag_count = 1;
    memset(f->tags, 0, sizeof(f->tags));
    const size_t len = encode(f, wire);
    uint8_t key[32];
    TEST_ASSERT_TRUE(ah_trunk_auth_pair_key(from->secret, from->node, to->key, to->node, key));
    TEST_ASSERT_TRUE(ah_trunk_auth_tag(key, wire, len, f, wire + ah_trunk_frame_tags_at(f->kind)));
    return len;
}

// A beacon from `from`, tagged for `known` when it is not NULL, heard by radio `at`.
static void hear_beacon_at(int at, const ident_t *from, const ident_t *known, int8_t power, int8_t snr)
{
    ah_trunk_frame_t b = {.kind = AH_TRUNK_KIND_BEACON, .power_dbm = power};
    memcpy(b.key, from->key, 32);
    uint8_t frame[AH_TRUNK_FRAME_MAX];
    size_t len;
    if (known != NULL) {
        len = tagged(from, known, &b, frame);
    } else {
        memcpy(b.source, from->node, 8);
        len = encode(&b, frame);
    }
    ah_trunk_on_frame(&s_r[at].trunk, frame, len, snr, s_now);
}

static void hear_beacon(const ident_t *from, int8_t power, int8_t snr)
{
    hear_beacon_at(0, from, NULL, power, snr);
}

void setUp(void)
{
}

void tearDown(void)
{
}

// ---- one neighbor ----

static void test_beacons_introduce_neighbors(void)
{
    meet(AH_LORA_REGION_EU868);
    TEST_ASSERT_EQUAL(1, s_r[0].neighbors_up);
    TEST_ASSERT_EQUAL(1, s_r[1].neighbors_up);
    // Each holds the other's pair key, and it is the same key.
    const ah_trunk_neighbor_t *a = &s_r[0].trunk.neighbors[ah_trunk_slot_of(&s_r[0].trunk, s_r[1].node)];
    const ah_trunk_neighbor_t *b = &s_r[1].trunk.neighbors[ah_trunk_slot_of(&s_r[1].trunk, s_r[0].node)];
    TEST_ASSERT_EQUAL_MEMORY(a->key, b->key, 32);
}

static void test_unicast_survives_30_percent_loss(void)
{
    meet(AH_LORA_REGION_EU868);
    s_loss_per_mille = 300;
    uint8_t packet[480];
    for (size_t i = 0; i < sizeof(packet); ++i) {
        packet[i] = (uint8_t)i;
    }
    size_t delivered = 0;
    for (int k = 0; k < 10; ++k) {
        packet[0] = (uint8_t)k;
        TEST_ASSERT_TRUE(send(0, 1, packet, sizeof(packet), 3));
        run(60000);
    }
    for (size_t i = 0; i < s_r[1].got_count; ++i) {
        TEST_ASSERT_EQUAL(sizeof(packet), s_r[1].got_len[i]);
        TEST_ASSERT_EQUAL_MEMORY(packet + 1, s_r[1].got[i] + 1, sizeof(packet) - 1u);
        delivered++;
    }
    // Three pieces each, every frame lost 30 % of the time: ARQ delivers
    // nearly all, and the sender hears of nearly all (a lost COMPLETE leaves
    // a delivered packet unconfirmed).
    TEST_ASSERT_GREATER_OR_EQUAL(9, delivered);
    TEST_ASSERT_GREATER_OR_EQUAL(8, s_r[0].trunk.stats.transfers_ok);
}

static void test_feedback_waits_for_the_frame_to_leave(void)
{
    meet(AH_LORA_REGION_EU868);
    // Every frame waits 4 s for the channel, longer than the turnaround.
    s_channel_wait_ms = 4000;
    uint8_t packet[400];
    memset(packet, 3, sizeof(packet));
    const uint32_t before = s_r[0].trunk.stats.frames_tx;
    TEST_ASSERT_TRUE(send(0, 1, packet, sizeof(packet), 3));
    run(60000);
    TEST_ASSERT_EQUAL(1, s_r[0].trunk.stats.transfers_ok);
    // Two pieces and no probe: no round was counted as silent.
    TEST_ASSERT_EQUAL(2, s_r[0].trunk.stats.frames_tx - before);
}

static void test_room_is_kept_per_neighbor(void)
{
    meet(AH_LORA_REGION_EU868);
    uint8_t packet[32] = {0};
    for (unsigned i = 0; i < AH_TRUNK_PER_NEIGHBOR; ++i) {
        TEST_ASSERT_TRUE(ah_trunk_room(&s_r[0].trunk, s_r[1].node));
        packet[0] = (uint8_t)i;
        TEST_ASSERT_TRUE(send(0, 1, packet, sizeof(packet), 5));
    }
    TEST_ASSERT_FALSE(ah_trunk_room(&s_r[0].trunk, s_r[1].node));
    // Refused, not traded for something already accepted, however urgent.
    TEST_ASSERT_FALSE(send(0, 1, packet, sizeof(packet), 0));
    TEST_ASSERT_EQUAL(1, s_r[0].trunk.stats.refused);
    // Nothing for a node that is no neighbor, and nothing empty or oversized.
    ident_t stranger;
    ident_make(&stranger, 0x77);
    TEST_ASSERT_FALSE(ah_trunk_room(&s_r[0].trunk, stranger.node));
    TEST_ASSERT_FALSE(ah_trunk_send(&s_r[0].trunk, stranger.node, packet, sizeof(packet), 5, s_now));
    TEST_ASSERT_FALSE(send(1, 0, packet, 0, 5));
    TEST_ASSERT_FALSE(send(1, 0, packet, AH_TRUNK_PACKET_MAX + 1u, 5));
}

// One piece of a transfer from radio 0 to radio 1, as radio 0 would frame and tag it.
static void send_piece_raw(const uint8_t *packet, size_t len, uint8_t total, uint8_t index)
{
    const size_t chunk = (len + total - 1u) / total;
    const size_t start = (size_t)index * chunk;
    ah_trunk_frame_t f = {
        .kind = AH_TRUNK_KIND_DATA,
        .flags = index + 1u == total ? AH_TRUNK_FLAG_ASK : 0,
        .transfer = 0x5C5C5C5Cu,
        .index = index,
        .total = total,
        .payload = packet + start,
        .payload_len = (uint16_t)(len - start < chunk ? len - start : chunk),
    };
    uint8_t frame[AH_TRUNK_FRAME_MAX];
    const size_t flen = tagged(&s_r[0].id, &s_r[1].id, &f, frame);
    ah_trunk_on_frame(&s_r[1].trunk, frame, flen, 5, s_now);
}

static void test_a_short_last_piece_first_still_reassembles_exactly(void)
{
    // 301 bytes in two pieces of 151 and 150: the short last one arrives
    // first, as it does whenever the first is lost.
    meet(AH_LORA_REGION_EU868);
    uint8_t packet[301];
    for (size_t i = 0; i < sizeof(packet); ++i) {
        packet[i] = (uint8_t)(i * 7u + 3u);
    }
    send_piece_raw(packet, sizeof(packet), 2, 1);
    TEST_ASSERT_EQUAL(0, s_r[1].got_count);
    send_piece_raw(packet, sizeof(packet), 2, 0);
    TEST_ASSERT_EQUAL(1, s_r[1].got_count);
    TEST_ASSERT_EQUAL(sizeof(packet), s_r[1].got_len[0]);
    TEST_ASSERT_EQUAL_MEMORY(packet, s_r[1].got[0], sizeof(packet));
}

static void test_duty_budget_is_never_exceeded(void)
{
    meet(AH_LORA_REGION_IN865); // 2.5 %: 90 s an hour
    uint8_t packet[400];
    memset(packet, 7, sizeof(packet));
    for (int minute = 0; minute < 90; ++minute) {
        send(0, 1, packet, sizeof(packet), 3);
        run(60000);
        TEST_ASSERT_LESS_OR_EQUAL(90000, ah_trunk_airtime_used(&s_r[0].trunk, s_now));
        TEST_ASSERT_LESS_OR_EQUAL(90000, ah_trunk_airtime_used(&s_r[1].trunk, s_now));
    }
    TEST_ASSERT_GREATER_THAN(0, s_r[0].trunk.stats.duty_deferred);
}

static void test_announces_go_first(void)
{
    meet(AH_LORA_REGION_US915);
    uint8_t bulk[200];
    uint8_t announce[100];
    memset(announce, 0xA0, sizeof(announce));
    for (int i = 0; i < 3; ++i) {
        memset(bulk, 0xB0 + i, sizeof(bulk));
        TEST_ASSERT_TRUE(send(0, 1, bulk, sizeof(bulk), 5));
    }
    TEST_ASSERT_TRUE(send(0, 1, announce, sizeof(announce), 0));
    run(120000);
    TEST_ASSERT_EQUAL(4, s_r[1].got_count);
    TEST_ASSERT_EQUAL(0xA0, s_r[1].got[0][0]);
}

static void test_dead_neighbor_is_given_up(void)
{
    meet(AH_LORA_REGION_EU868);
    uint8_t packet[100];
    const uint32_t frames_before = s_r[0].trunk.stats.frames_tx;
    for (int i = 0; i < 3; ++i) {
        memset(packet, i, sizeof(packet));
        send(0, 1, packet, sizeof(packet), 3);
    }
    // The far node is gone: two transfers fail, and the third goes with the
    // neighbor rather than costing its own rounds.
    s_reach[0] = false;
    s_reach[1] = false;
    run(300000);
    TEST_ASSERT_EQUAL(2, s_r[0].trunk.stats.transfers_failed);
    TEST_ASSERT_EQUAL(1, s_r[0].neighbors_down);
    TEST_ASSERT_EQUAL(1, s_r[0].trunk.stats.holds);
    TEST_ASSERT_FALSE(s_r[0].trunk.tx.active);
    for (size_t i = 0; i < AH_TRUNK_QUEUE; ++i) {
        TEST_ASSERT_FALSE(s_r[0].trunk.queue[i].in_use);
    }
    // Each failed transfer costs its one piece and five probes.
    TEST_ASSERT_LESS_OR_EQUAL(2u * 6u, s_r[0].trunk.stats.frames_tx - frames_before);
}

static void test_junk_gets_no_answer(void)
{
    meet(AH_LORA_REGION_EU868);
    const uint32_t before = s_r[1].sent;
    uint8_t junk[64];
    memset(junk, 0x41, sizeof(junk));
    junk[1] = 0x4C;
    for (int i = 0; i < 50; ++i) {
        junk[2] = (uint8_t)i;
        ah_trunk_on_frame(&s_r[1].trunk, junk, sizeof(junk), 0, s_now);
    }
    run(1000);
    TEST_ASSERT_EQUAL(before, s_r[1].sent);
    TEST_ASSERT_GREATER_THAN(0, s_r[1].trunk.stats.frames_bad);
}

// ---- authentication ----

static void test_a_frame_without_the_sources_key_moves_nothing(void)
{
    // Radio 1 cannot answer; an attacker that knows its ID, but not its
    // secret, tries to end radio 0's transfer, inject a packet, claim a
    // power, and take radio 1's place.
    meet(AH_LORA_REGION_IN865);
    s_reach[1] = false;
    ident_t attacker;
    ident_make(&attacker, 0x99);
    // The attacker under radio 1's ID: its own key, which does not hash to the ID.
    ident_t impostor = attacker;
    memcpy(impostor.node, s_r[1].node, 8);
    uint8_t packet[100];
    memset(packet, 0x3E, sizeof(packet));
    TEST_ASSERT_TRUE(send(0, 1, packet, sizeof(packet), 3));
    run(1000);
    TEST_ASSERT_TRUE(s_r[0].trunk.tx.active);
    const ah_trunk_neighbor_t *before = &s_r[0].trunk.neighbors[ah_trunk_slot_of(&s_r[0].trunk, s_r[1].node)];
    const int8_t power = before->power_dbm;
    const int8_t snr = before->snr_db;

    uint8_t frame[AH_TRUNK_FRAME_MAX];
    ah_trunk_frame_t done = {
        .kind = AH_TRUNK_KIND_COMPLETE, .power_dbm = -128, .transfer = s_r[0].trunk.tx.header.transfer,
        .index = 1, .total = 1
    };
    size_t len = tagged(&impostor, &s_r[0].id, &done, frame);
    ah_trunk_on_frame(&s_r[0].trunk, frame, len, 20, s_now);
    const uint8_t piece[20] = {0x66};
    ah_trunk_frame_t inject = {
        .kind = AH_TRUNK_KIND_DATA, .transfer = 9, .total = 1, .payload = piece, .payload_len = sizeof(piece)
    };
    len = tagged(&impostor, &s_r[0].id, &inject, frame);
    ah_trunk_on_frame(&s_r[0].trunk, frame, len, 20, s_now);
    // A beacon claiming radio 1's ID with the attacker's key: the key does not name the ID.
    const uint32_t bad = s_r[0].trunk.stats.frames_bad;
    hear_beacon_at(0, &impostor, NULL, -128, 20);
    TEST_ASSERT_EQUAL(bad + 1u, s_r[0].trunk.stats.frames_bad);

    TEST_ASSERT_EQUAL(0, s_r[0].trunk.stats.transfers_ok);
    TEST_ASSERT_EQUAL(0, s_r[0].got_count);
    const int slot = ah_trunk_slot_of(&s_r[0].trunk, s_r[1].node);
    TEST_ASSERT_TRUE(slot >= 0);
    TEST_ASSERT_EQUAL_INT8(power, s_r[0].trunk.neighbors[slot].power_dbm);
    TEST_ASSERT_EQUAL_INT8(snr, s_r[0].trunk.neighbors[slot].snr_db);
    // The transfer runs its course and fails, as it should with radio 1 silent.
    run(120000);
    TEST_ASSERT_EQUAL(1, s_r[0].trunk.stats.transfers_failed);
    TEST_ASSERT_EQUAL(0, s_r[0].trunk.stats.transfers_ok);
}

static void test_a_node_that_rebooted_is_known_again_within_seconds(void)
{
    // Radio 1 restarts and forgets every pair key; radio 0 still knows it.
    // Radio 1's first beacon carries no tag for radio 0, so radio 0 answers
    // with its own, and both hold the key again before any transfer is lost.
    // Radio 0 beaconed only seconds before, which radio 1 never heard: its
    // answer waits out the gap since that beacon rather than being dropped.
    meet(AH_LORA_REGION_EU868);
    TEST_ASSERT_LESS_THAN(30000, s_now - s_r[0].trunk.last_beacon_ms);
    boot(1, AH_LORA_REGION_EU868, 0xC1);
    run(45000);
    TEST_ASSERT_TRUE(ah_trunk_slot_of(&s_r[1].trunk, s_r[0].node) >= 0);
    bind_all();
    uint8_t packet[200];
    memset(packet, 0x2B, sizeof(packet));
    TEST_ASSERT_TRUE(send(0, 1, packet, sizeof(packet), 3));
    run(30000);
    TEST_ASSERT_EQUAL(1, s_r[0].trunk.stats.transfers_ok);
    TEST_ASSERT_EQUAL(0, s_r[0].trunk.stats.transfers_failed);
    TEST_ASSERT_EQUAL(0, s_r[0].trunk.stats.holds);
}

// ---- one packet to several neighbors ----

static void test_a_flood_goes_once_to_every_neighbor(void)
{
    // Three nodes in mutual range, colliding frames lost. The mesh queues
    // the same packet for both neighbors in one fanout: one transfer carries
    // it to both, and their answers take turns rather than collide.
    meet_n(AH_LORA_REGION_EU868, 3);
    s_collide = true;
    uint8_t packet[400];
    for (size_t i = 0; i < sizeof(packet); ++i) {
        packet[i] = (uint8_t)(i * 3u + 1u);
    }
    const uint32_t frames = s_r[0].data_frames;
    const uint32_t spent = ah_trunk_airtime_used(&s_r[0].trunk, s_now);
    TEST_ASSERT_TRUE(send(0, 1, packet, sizeof(packet), 3));
    TEST_ASSERT_TRUE(send(0, 2, packet, sizeof(packet), 3));
    TEST_ASSERT_EQUAL(1, s_r[0].trunk.queue[0].in_use + s_r[0].trunk.queue[1].in_use);
    run(30000);
    TEST_ASSERT_EQUAL(1, s_r[1].got_count);
    TEST_ASSERT_EQUAL(1, s_r[2].got_count);
    TEST_ASSERT_EQUAL_MEMORY(packet, s_r[1].got[0], sizeof(packet));
    TEST_ASSERT_EQUAL_MEMORY(packet, s_r[2].got[0], sizeof(packet));
    TEST_ASSERT_EQUAL(2, s_r[0].trunk.stats.transfers_ok);
    // Two pieces on the air, not four, and no answer lost to another.
    TEST_ASSERT_EQUAL(2, s_r[0].data_frames - frames);
    TEST_ASSERT_EQUAL(0, s_collisions);
    // Less than the two unicast transfers would have spent: 2 x 2 pieces of about 2.1 s.
    TEST_ASSERT_LESS_THAN(6000, ah_trunk_airtime_used(&s_r[0].trunk, s_now) - spent);
}

static void test_a_flood_finishes_for_the_live_neighbor_when_the_other_is_gone(void)
{
    meet_n(AH_LORA_REGION_EU868, 3);
    s_collide = true;
    // Radio 2 hears nothing more and says nothing more.
    s_reach[2] = false;
    s_link[0][2] = false;
    s_link[1][2] = false;
    uint8_t packet[300];
    memset(packet, 0x4D, sizeof(packet));
    TEST_ASSERT_TRUE(send(0, 1, packet, sizeof(packet), 3));
    TEST_ASSERT_TRUE(send(0, 2, packet, sizeof(packet), 3));
    run(120000);
    TEST_ASSERT_EQUAL(1, s_r[1].got_count);
    TEST_ASSERT_EQUAL(1, s_r[0].trunk.stats.transfers_ok);
    TEST_ASSERT_EQUAL(1, s_r[0].trunk.stats.transfers_failed);
    TEST_ASSERT_FALSE(s_r[0].trunk.tx.active);
}

static void test_copies_handed_over_apart_join_within_the_window(void)
{
    // The mesh hands the copies of one fanout over a few milliseconds apart,
    // and no transfer starts before the window lets the last of them join.
    meet_n(AH_LORA_REGION_EU868, 3);
    uint8_t packet[60];
    memset(packet, 0x33, sizeof(packet));
    TEST_ASSERT_TRUE(send(0, 1, packet, sizeof(packet), 4));
    run(10);
    TEST_ASSERT_FALSE(s_r[0].trunk.tx.active);
    TEST_ASSERT_TRUE(send(0, 2, packet, sizeof(packet), 4));
    run(AH_TRUNK_COALESCE_MS);
    TEST_ASSERT_TRUE(s_r[0].trunk.tx.active);
    TEST_ASSERT_EQUAL(2, s_r[0].trunk.tx.dest_count);
}

static void test_copies_join_only_while_they_wait(void)
{
    meet_n(AH_LORA_REGION_EU868, 3);
    uint8_t packet[60];
    memset(packet, 0x11, sizeof(packet));
    uint8_t other[60];
    memset(other, 0x22, sizeof(other));
    TEST_ASSERT_TRUE(send(0, 1, packet, sizeof(packet), 4));
    // Another packet, and the same one for the same neighbor again, are packets of their own.
    TEST_ASSERT_TRUE(send(0, 2, other, sizeof(other), 4));
    TEST_ASSERT_TRUE(send(0, 1, packet, sizeof(packet), 4));
    // The same packet for another neighbor joins the first, at the more urgent priority.
    TEST_ASSERT_TRUE(send(0, 2, packet, sizeof(packet), 1));
    const ah_trunk_item_t *q = &s_r[0].trunk.queue[0];
    TEST_ASSERT_EQUAL(2, q->dest_count);
    TEST_ASSERT_EQUAL(1, q->prio);
    TEST_ASSERT_TRUE(s_r[0].trunk.queue[1].in_use && s_r[0].trunk.queue[1].dest_count == 1);
    TEST_ASSERT_TRUE(s_r[0].trunk.queue[2].in_use && s_r[0].trunk.queue[2].dest_count == 1);
    // The most urgent goes first; once it starts, a late copy is a transfer of its own.
    run(100);
    TEST_ASSERT_TRUE(s_r[0].trunk.tx.active);
    TEST_ASSERT_EQUAL(0, s_r[0].trunk.tx.item);
    TEST_ASSERT_EQUAL(2, s_r[0].trunk.tx.dest_count);
    TEST_ASSERT_TRUE(send(0, 1, packet, sizeof(packet), 4));
    TEST_ASSERT_EQUAL(2, q->dest_count);
    run(60000);
    // Both destinations of the joined packet, and three packets of one each.
    TEST_ASSERT_EQUAL(5, s_r[0].trunk.stats.transfers_ok);
}

static void test_a_full_table_is_kept_by_beacons_of_seven_tags(void)
{
    // Eight neighbors and nothing else to send: each beacon tags the seven
    // tagged longest ago, and the one left out goes in the next, an interval
    // on, not a second beacon at once. Every neighbor is tagged within two
    // intervals, inside the time a silent neighbor is kept.
    setup(AH_LORA_REGION_EU868);
    s_reach[0] = false;
    s_reach[1] = false;
    ident_t ids[AH_TRUNK_NEIGHBORS];
    for (size_t i = 0; i < AH_TRUNK_NEIGHBORS; ++i) {
        ident_make(&ids[i], (uint8_t)(0xD0 + i));
        hear_beacon(&ids[i], 22, 5);
    }
    run(3LL * (AH_TRUNK_BEACON_INTERVAL_MS + AH_TRUNK_BEACON_JITTER_MS));
    TEST_ASSERT_EQUAL(AH_TRUNK_TAGS_MAX, s_r[0].beacon_tags_most);
    for (uint32_t k = 1; k < s_r[0].beacons && k < 16; ++k) {
        TEST_ASSERT_GREATER_OR_EQUAL(AH_TRUNK_BEACON_INTERVAL_MS, s_r[0].beacon_at[k] - s_r[0].beacon_at[k - 1]);
    }
    for (size_t i = 0; i < AH_TRUNK_NEIGHBORS; ++i) {
        const int slot = ah_trunk_slot_of(&s_r[0].trunk, ids[i].node);
        TEST_ASSERT_TRUE(slot >= 0);
        TEST_ASSERT_LESS_THAN(2LL * (AH_TRUNK_BEACON_INTERVAL_MS + AH_TRUNK_BEACON_JITTER_MS) + 1000,
                              s_now - s_r[0].trunk.neighbors[slot].tagged_ms);
    }
    // The one left out takes its turn: over sixteen beacons no neighbor is
    // left out of more than three, where two taking it in turns would each be
    // tagged in only every other beacon, and one lost beacon would drop them.
    int left_out[AH_TRUNK_NEIGHBORS] = {0};
    for (int b = 0; b < 16; ++b) {
        // Each neighbor's own beacon, tagged for radio 0, keeps it listed.
        for (size_t i = 0; i < AH_TRUNK_NEIGHBORS; ++i) {
            hear_beacon_at(0, &ids[i], &s_r[0].id, 22, 5);
        }
        const uint32_t before = s_r[0].beacons;
        while (s_r[0].beacons == before) {
            run(1000);
        }
        for (size_t i = 0; i < AH_TRUNK_NEIGHBORS; ++i) {
            const int slot = ah_trunk_slot_of(&s_r[0].trunk, ids[i].node);
            TEST_ASSERT_TRUE(slot >= 0);
            left_out[i] += s_now - s_r[0].trunk.neighbors[slot].tagged_ms > 5000 ? 1 : 0;
        }
    }
    for (size_t i = 0; i < AH_TRUNK_NEIGHBORS; ++i) {
        TEST_ASSERT_LESS_OR_EQUAL(3, left_out[i]);
    }
}

// ---- the receiver loses its state mid-transfer ----

static int s_stage;

static bool drop_the_first_asking_piece(int from, const ah_trunk_frame_t *f)
{
    if (from == 0 && s_stage == 0 && f->kind == AH_TRUNK_KIND_DATA && (f->flags & AH_TRUNK_FLAG_ASK)) {
        s_stage = 1;
        return true;
    }
    return false;
}

static void forget_the_transfer_after_it_acks(int to, const ah_trunk_frame_t *f)
{
    if (to == 0 && s_stage == 1 && f->kind == AH_TRUNK_KIND_ACK) {
        s_stage = 2;
        // Its receive slot expired or was taken by another transfer.
        memset(s_r[1].trunk.rx, 0, sizeof(s_r[1].trunk.rx));
    }
}

static void test_a_receiver_that_lost_its_transfer_gets_every_piece_again(void)
{
    // The receiver holds pieces 0 and 1, says so, and loses its slot. Its new
    // slot holds only what comes next; the sender must believe that, not the
    // older bitmap, or the transfer can never complete.
    meet(AH_LORA_REGION_EU868);
    s_stage = 0;
    s_drop = drop_the_first_asking_piece;
    s_after = forget_the_transfer_after_it_acks;
    uint8_t packet[480];
    for (size_t i = 0; i < sizeof(packet); ++i) {
        packet[i] = (uint8_t)(i * 11u + 1u);
    }
    TEST_ASSERT_TRUE(send(0, 1, packet, sizeof(packet), 3));
    run(180000);
    TEST_ASSERT_EQUAL(2, s_stage);
    TEST_ASSERT_EQUAL(1, s_r[1].got_count);
    TEST_ASSERT_EQUAL(sizeof(packet), s_r[1].got_len[0]);
    TEST_ASSERT_EQUAL_MEMORY(packet, s_r[1].got[0], sizeof(packet));
    TEST_ASSERT_EQUAL(1, s_r[0].trunk.stats.transfers_ok);
    TEST_ASSERT_EQUAL(0, s_r[0].trunk.stats.transfers_failed);
}

// ---- a neighbor we hear but that cannot hear us ----

static bool held_now(const ah_trunk_t *t, const uint8_t node[8])
{
    for (size_t i = 0; i < AH_TRUNK_NEIGHBORS; ++i) {
        const ah_trunk_hold_t *h = &t->holds[i];
        if (h->in_use && memcmp(h->node, node, 8) == 0 && h->until_ms > s_now) {
            return true;
        }
    }
    return false;
}

static void test_a_neighbor_that_cannot_hear_us_is_held_down(void)
{
    setup(AH_LORA_REGION_EU868);
    s_reach[0] = false;
    uint8_t announce[200];
    memset(announce, 0xA5, sizeof(announce));
    int seen_up = 0;
    int64_t next_announce = s_now + 300000;
    // The mesh: our announce on every new link, and every 5 minutes on each.
    const int64_t end = s_now + 2 * 3600000LL;
    while (s_now < end || !held_now(&s_r[0].trunk, s_r[1].node)) {
        run(1000);
        if (s_r[0].neighbors_up != seen_up) {
            seen_up = s_r[0].neighbors_up;
            send(0, 1, announce, sizeof(announce), 0);
        }
        if (s_now >= next_announce) {
            next_announce += 300000;
            if (ah_trunk_slot_of(&s_r[0].trunk, s_r[1].node) >= 0) {
                send(0, 1, announce, sizeof(announce), 0);
            }
        }
        TEST_ASSERT_LESS_THAN(end + 3600000LL, s_now);
    }
    // Without the hold, every beacon would bring it back: a dozen times in
    // two hours, with 45 % of the EU budget spent on transfers nobody heard.
    TEST_ASSERT_LESS_OR_EQUAL(5, s_r[0].neighbors_up);
    TEST_ASSERT_GREATER_OR_EQUAL(3, s_r[0].trunk.stats.holds);
    TEST_ASSERT_LESS_OR_EQUAL(ah_trunk_budget_ms(&s_r[0].trunk) / 10u, ah_trunk_airtime_used(&s_r[0].trunk, s_now));

    // A frame under its ID but not under its key ends nothing; one tagged for
    // us proves it hears us, and ends the hold at once.
    const int ups = s_r[0].neighbors_up;
    const uint8_t piece[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    ah_trunk_frame_t f = {
        .kind = AH_TRUNK_KIND_DATA, .flags = AH_TRUNK_FLAG_ASK, .transfer = 77, .total = 1, .payload = piece,
        .payload_len = sizeof(piece)
    };
    uint8_t frame[AH_TRUNK_FRAME_MAX];
    ident_t impostor;
    ident_make(&impostor, 0x99);
    memcpy(impostor.node, s_r[1].node, 8);
    size_t len = tagged(&impostor, &s_r[0].id, &f, frame);
    ah_trunk_on_frame(&s_r[0].trunk, frame, len, 5, s_now);
    TEST_ASSERT_TRUE(held_now(&s_r[0].trunk, s_r[1].node));
    TEST_ASSERT_EQUAL(ups, s_r[0].neighbors_up);
    len = tagged(&s_r[1].id, &s_r[0].id, &f, frame);
    ah_trunk_on_frame(&s_r[0].trunk, frame, len, 5, s_now);
    TEST_ASSERT_EQUAL(ups + 1, s_r[0].neighbors_up);
    TEST_ASSERT_EQUAL(1, s_r[0].got_count);
}

// ---- the duty reserve ----

static void fill_queue(int from, size_t len)
{
    static uint8_t counter;
    uint8_t bulk[480];
    while (ah_trunk_room(&s_r[from].trunk, s_r[1 - from].node)) {
        memset(bulk, counter++, sizeof(bulk));
        ah_trunk_send(&s_r[from].trunk, s_r[1 - from].node, bulk, len, 4, s_now);
    }
}

static void test_answers_and_beacons_keep_a_reserve(void)
{
    meet(AH_LORA_REGION_IN865);
    const uint32_t budget = ah_trunk_budget_ms(&s_r[0].trunk);
    const uint32_t data_share = budget - budget / 10u;
    // Radio 0 sends all it can, and runs out of data airtime.
    for (int second = 0; second < 15 * 60; ++second) {
        fill_queue(0, 480);
        run(1000);
    }
    // Data stops within a frame of the share; beacons and answers may go on into the reserve.
    TEST_ASSERT_GREATER_OR_EQUAL(data_share - 2400u, ah_trunk_airtime_used(&s_r[0].trunk, s_now));
    TEST_ASSERT_LESS_OR_EQUAL(data_share, s_r[0].data_ms);
    // It still answers, from the reserve: eight packets from radio 1 need
    // more answers than the less than one data frame left of the data share
    // would carry, and all get through while radio 0's own packets wait.
    const uint32_t ok_before = s_r[1].trunk.stats.transfers_ok;
    const uint32_t own_before = s_r[0].trunk.stats.transfers_ok;
    uint8_t packet[100];
    int sent = 0;
    uint32_t peak = 0;
    for (int second = 0; second < 600; ++second) {
        while (sent < 8) {
            memset(packet, 0x90 + sent, sizeof(packet));
            if (!send(1, 0, packet, sizeof(packet), 3)) {
                break;
            }
            sent++;
        }
        fill_queue(0, 480);
        run(1000);
        const uint32_t used = ah_trunk_airtime_used(&s_r[0].trunk, s_now);
        peak = used > peak ? used : peak;
    }
    TEST_ASSERT_EQUAL(8, sent);
    TEST_ASSERT_EQUAL(ok_before + 8u, s_r[1].trunk.stats.transfers_ok);
    TEST_ASSERT_EQUAL(own_before, s_r[0].trunk.stats.transfers_ok);
    TEST_ASSERT_LESS_OR_EQUAL(budget, peak);
    // Neither side lost the other.
    TEST_ASSERT_EQUAL(0, s_r[0].neighbors_down);
    TEST_ASSERT_EQUAL(0, s_r[1].neighbors_down);
}

// ---- timing ----

static void test_traffic_tagged_for_a_neighbor_stands_in_for_beacons(void)
{
    meet(AH_LORA_REGION_EU868);
    const uint32_t beacons0 = s_r[0].beacons;
    const uint32_t beacons1 = s_r[1].beacons;
    uint8_t packet[100];
    for (int k = 0; k < 15; ++k) {
        memset(packet, 0x42 + k, sizeof(packet));
        TEST_ASSERT_TRUE(send(0, 1, packet, sizeof(packet), 3));
        run(120000);
    }
    // Every frame tagged for the other keeps it; the answers count as much as the data.
    TEST_ASSERT_EQUAL(beacons0, s_r[0].beacons);
    TEST_ASSERT_EQUAL(beacons1, s_r[1].beacons);
    TEST_ASSERT_EQUAL(15, s_r[0].trunk.stats.transfers_ok);
    TEST_ASSERT_EQUAL(0, s_r[0].neighbors_down);
    TEST_ASSERT_EQUAL(0, s_r[1].neighbors_down);
    // A node with nothing to say still beacons.
    run(AH_TRUNK_BEACON_INTERVAL_MS + AH_TRUNK_BEACON_JITTER_MS + 1000);
    TEST_ASSERT_GREATER_THAN(beacons0, s_r[0].beacons);
}

static void test_timing_is_random_per_node(void)
{
    // Two nodes powered up together beacon apart and number transfers apart.
    setup(AH_LORA_REGION_EU868);
    const int64_t first0 = s_r[0].trunk.next_beacon_ms - s_now;
    const int64_t first1 = s_r[1].trunk.next_beacon_ms - s_now;
    TEST_ASSERT_TRUE(first0 >= 2000 && first0 < 12000);
    TEST_ASSERT_TRUE(first1 >= 2000 && first1 < 12000);
    TEST_ASSERT_NOT_EQUAL(first0, first1);
    TEST_ASSERT_NOT_EQUAL(s_r[0].trunk.transfer, s_r[1].trunk.transfer);

    // Alone, a node keeps to the interval plus up to the jitter, never in step.
    s_reach[0] = false;
    s_reach[1] = false;
    run(40LL * 60 * 1000);
    TEST_ASSERT_GREATER_OR_EQUAL(7, s_r[0].beacons);
    int64_t shortest = INT64_MAX;
    int64_t longest = 0;
    for (uint32_t k = 1; k < s_r[0].beacons && k < 16; ++k) {
        const int64_t gap = s_r[0].beacon_at[k] - s_r[0].beacon_at[k - 1];
        TEST_ASSERT_TRUE(gap >= (int64_t)AH_TRUNK_BEACON_INTERVAL_MS);
        TEST_ASSERT_TRUE(gap <= (int64_t)(AH_TRUNK_BEACON_INTERVAL_MS + AH_TRUNK_BEACON_JITTER_MS) + 10);
        shortest = gap < shortest ? gap : shortest;
        longest = gap > longest ? gap : longest;
    }
    TEST_ASSERT_GREATER_THAN(1000, longest - shortest);
}

static void test_a_probe_waits_a_random_part_of_a_short_frame(void)
{
    meet(AH_LORA_REGION_EU868);
    s_reach[0] = false;
    s_reach[1] = false;
    uint8_t packet[100];
    memset(packet, 5, sizeof(packet));
    TEST_ASSERT_TRUE(send(0, 1, packet, sizeof(packet), 3));
    run(AH_TRUNK_COALESCE_MS + 10);
    const ah_trunk_t *t = &s_r[0].trunk;
    TEST_ASSERT_TRUE(t->tx.active);
    uint8_t silent = 0;
    int64_t delays[5];
    int seen = 0;
    do {
        run(10);
        if (t->tx.probe && t->tx.silent_rounds != silent) {
            silent = t->tx.silent_rounds;
            delays[seen] = t->tx.send_at_ms - s_now;
            TEST_ASSERT_TRUE(delays[seen] >= 0 && delays[seen] <= (int64_t)t->control_ms);
            seen++;
        }
    } while (seen < 5 && t->tx.active);
    TEST_ASSERT_EQUAL(5, seen);
    bool varied = false;
    for (int k = 1; k < 5; ++k) {
        varied = varied || delays[k] != delays[0];
    }
    TEST_ASSERT_TRUE(varied);
}

static uint32_t s_beacons_from_1;
static uint32_t s_beacons_lost;

static bool lose_beacons_after_the_first(int from, const ah_trunk_frame_t *f)
{
    if (from != 1 || f->kind != AH_TRUNK_KIND_BEACON) {
        return false;
    }
    const uint32_t k = s_beacons_from_1++;
    return k >= 1u && k <= s_beacons_lost;
}

static void test_two_missed_beacons_keep_a_neighbor_and_three_do_not(void)
{
    for (uint32_t lost = 2; lost <= 3; ++lost) {
        setup(AH_LORA_REGION_EU868);
        // An idle trunk: both send nothing but beacons, and radio 1's are
        // lost after the first, which met radio 0.
        s_beacons_from_1 = 0;
        s_beacons_lost = lost;
        s_drop = lose_beacons_after_the_first;
        run(45LL * 60 * 1000);
        TEST_ASSERT_EQUAL(lost == 2 ? 0 : 1, s_r[0].neighbors_down);
        TEST_ASSERT_EQUAL(lost == 2 ? 1 : 2, s_r[0].neighbors_up);
    }
}

// ---- adaptive power ----

// The power radio 0 sends its next data at, to a node heard once.
static int8_t power_toward(ah_lora_region_id_t region, int8_t their_power, int8_t snr)
{
    setup(region);
    ident_t far;
    ident_make(&far, 0x21);
    hear_beacon(&far, their_power, snr);
    const uint8_t packet[50] = {0};
    TEST_ASSERT_TRUE(ah_trunk_send(&s_r[0].trunk, far.node, packet, sizeof(packet), 3, s_now));
    s_now += AH_TRUNK_COALESCE_MS;
    ah_trunk_tick(&s_r[0].trunk, s_now);
    TEST_ASSERT_TRUE(s_r[0].on_air);
    return s_r[0].last_power;
}

static void test_power_follows_what_the_neighbor_sent_at(void)
{
    // India, SF10: the floor is -15 dB, and 10 dB above it is kept.
    // Heard 20 dB above the floor from 22 dBm: 12 dBm reaches it with the margin.
    TEST_ASSERT_EQUAL_INT8(12, power_toward(AH_LORA_REGION_IN865, 22, 5));
    // The same path from a board with a lower ceiling: the path loss, not
    // its power, sets ours.
    TEST_ASSERT_EQUAL_INT8(12, power_toward(AH_LORA_REGION_IN865, 14, -3));
    // A weak link wants more than the board has: the ceiling.
    TEST_ASSERT_EQUAL_INT8(22, power_toward(AH_LORA_REGION_IN865, 20, -10));
    // A strong one is floored, never silenced.
    TEST_ASSERT_EQUAL_INT8(2, power_toward(AH_LORA_REGION_IN865, 2, 12));
    // Without adaptive power, the region's ceiling always.
    TEST_ASSERT_EQUAL_INT8(22, power_toward(AH_LORA_REGION_EU868, 22, 5));

    // A beacon must reach the neighbor that needs the most.
    setup(AH_LORA_REGION_IN865);
    ident_t near;
    ident_t far;
    ident_make(&near, 0x31);
    ident_make(&far, 0x41);
    hear_beacon(&near, 14, 0);
    hear_beacon(&far, 22, 5);
    s_now = s_r[0].trunk.next_beacon_ms;
    ah_trunk_tick(&s_r[0].trunk, s_now);
    TEST_ASSERT_EQUAL(1, s_r[0].beacons);
    TEST_ASSERT_EQUAL_INT8(12, s_r[0].last_power);
}

static void test_a_claimed_power_is_held_to_what_a_node_may_send(void)
{
    // India, SF10. A claim under the APC floor counts as the floor: heard 5
    // dB under the demodulation floor from 2 dBm wants 17 dBm, not 2.
    TEST_ASSERT_EQUAL_INT8(17, power_toward(AH_LORA_REGION_IN865, -128, -20));
    // One over the region's 29 dBm counts as 29: heard 25 dB over the floor, 14 dBm.
    TEST_ASSERT_EQUAL_INT8(14, power_toward(AH_LORA_REGION_IN865, 127, 10));
}

static void run_until_data(uint32_t frames)
{
    while (s_r[0].data_frames < frames) {
        run(10);
    }
}

static void test_power_steps_up_after_a_silent_round_until_a_transfer_gets_through(void)
{
    setup(AH_LORA_REGION_IN865);
    ident_t far;
    ident_make(&far, 0x21);
    // Heard 20 dB over the floor from 22 dBm: 12 dBm, until it goes unanswered.
    hear_beacon(&far, 22, 5);
    ah_trunk_set_bound(&s_r[0].trunk, far.node);
    const uint8_t packet[50] = {0};
    TEST_ASSERT_TRUE(ah_trunk_send(&s_r[0].trunk, far.node, packet, sizeof(packet), 3, s_now));
    run_until_data(1);
    TEST_ASSERT_EQUAL_INT8(12, s_r[0].last_power);
    run_until_data(2);
    // Its far end may hear more noise than ours: the probe goes at the ceiling.
    TEST_ASSERT_EQUAL_INT8(22, s_r[0].last_power);
    ah_trunk_frame_t done = {
        .kind = AH_TRUNK_KIND_COMPLETE, .power_dbm = 22, .transfer = s_r[0].trunk.tx.header.transfer, .index = 1,
        .total = 1
    };
    uint8_t frame[AH_TRUNK_FRAME_MAX];
    const size_t len = tagged(&far, &s_r[0].id, &done, frame);
    run(3000);
    ah_trunk_on_frame(&s_r[0].trunk, frame, len, 5, s_now);
    TEST_ASSERT_EQUAL(1, s_r[0].trunk.stats.transfers_ok);
    // Through: back to what the path needs.
    const uint8_t again[50] = {1};
    TEST_ASSERT_TRUE(ah_trunk_send(&s_r[0].trunk, far.node, again, sizeof(again), 3, s_now));
    run_until_data(3);
    TEST_ASSERT_EQUAL_INT8(12, s_r[0].last_power);
}

// ---- neighbors nobody has verified ----

// The mesh's part, as the trunk sees it: our announce to a neighbor that just came up.
static void announce_to_newcomer(int i, int *seen, const uint8_t *announce, size_t len)
{
    if (s_r[i].neighbors_up != *seen) {
        *seen = s_r[i].neighbors_up;
        ah_trunk_send(&s_r[i].trunk, s_r[i].last_up, announce, len, 0, s_now);
    }
}

static uint32_t unbound_spent(const ah_trunk_t *t)
{
    uint32_t used = 0;
    for (size_t i = 0; i < AH_TRUNK_DUTY_BUCKETS; ++i) {
        used += t->unbound_ms[i];
    }
    return used;
}

static void test_new_identities_cost_one_announce_each_and_a_quarter_of_the_budget_at_most(void)
{
    // India, the tightest data share for its airtime. Any radio can make a
    // fresh identity and beacon under it: seven or eight an hour, each
    // costing a piece and five probes, would spend the whole data share.
    meet(AH_LORA_REGION_IN865);
    const uint32_t budget = ah_trunk_budget_ms(&s_r[0].trunk);
    uint8_t announce[183];
    memset(announce, 0xA5, sizeof(announce));
    uint8_t packet[100];
    int seen = s_r[0].neighbors_up;
    int fresh = 0;
    const uint32_t frames = s_r[0].data_frames;
    // A beacon under a fresh identity every 30 s for half an hour, while the
    // verified neighbor is sent a packet every two minutes.
    for (int k = 0; k < 60; ++k) {
        ident_t id;
        ident_make(&id, (uint8_t)(0xC0 + k));
        hear_beacon(&id, 22, 5);
        fresh += s_r[0].neighbors_up != seen ? 1 : 0;
        announce_to_newcomer(0, &seen, announce, sizeof(announce));
        if (k % 4 == 0) {
            memset(packet, 0x51 + k, sizeof(packet));
            TEST_ASSERT_TRUE(send(0, 1, packet, sizeof(packet), 3));
        }
        run(30000);
        TEST_ASSERT_LESS_OR_EQUAL(budget / 4u, unbound_spent(&s_r[0].trunk));
    }
    TEST_ASSERT_EQUAL(60, fresh);
    // Each transfer to a new identity was one piece and no probe, and the
    // share turned most of them away.
    TEST_ASSERT_GREATER_THAN(0, s_r[0].trunk.stats.transfers_failed);
    TEST_ASSERT_LESS_OR_EQUAL(15u + s_r[0].trunk.stats.transfers_failed, s_r[0].data_frames - frames);
    TEST_ASSERT_GREATER_THAN(0, s_r[0].trunk.stats.unbound_refused);
    // The verified neighbor lost nothing.
    TEST_ASSERT_EQUAL(15, s_r[0].trunk.stats.transfers_ok);
}

// A fresh identity's beacon, then one piece from it to radio 0 that asks for
// an answer: the first of two, so the answer is an ACK.
static void ask_radio_0(const ident_t *from, uint32_t transfer, bool introduce)
{
    if (introduce) {
        hear_beacon_at(0, from, NULL, 22, 5);
    }
    const uint8_t piece[20] = {0};
    ah_trunk_frame_t f = {
        .kind = AH_TRUNK_KIND_DATA, .flags = AH_TRUNK_FLAG_ASK, .transfer = transfer, .index = 0, .total = 2,
        .payload = piece, .payload_len = sizeof(piece)
    };
    uint8_t frame[AH_TRUNK_FRAME_MAX];
    const size_t len = tagged(from, &s_r[0].id, &f, frame);
    ah_trunk_on_frame(&s_r[0].trunk, frame, len, 5, s_now);
}

static void test_answers_to_unverified_sources_keep_to_their_share(void)
{
    meet(AH_LORA_REGION_IN865);
    const uint32_t budget = ah_trunk_budget_ms(&s_r[0].trunk);
    // A fresh identity's beacon and a piece asking for an answer, every 2 s
    // for half an hour: answered, they would cost the node its whole budget
    // four times.
    for (int k = 0; k < 900; ++k) {
        ident_t id;
        ident_make(&id, (uint8_t)k);
        id.secret[31] = (uint8_t)(k >> 8);
        ah_x25519_public(id.secret, id.key);
        uint8_t hash[32];
        TEST_ASSERT_TRUE(ah_sha256(id.key, 32, hash));
        memcpy(id.node, hash, 8);
        ask_radio_0(&id, 0x1000u + (uint32_t)k, true);
        run(2000);
        TEST_ASSERT_LESS_OR_EQUAL(budget / 4u, unbound_spent(&s_r[0].trunk));
    }
    TEST_ASSERT_GREATER_THAN(0, s_r[0].trunk.stats.unbound_refused);
    // The verified neighbor is still answered, and still hears our beacons.
    uint8_t packet[300];
    memset(packet, 0x3A, sizeof(packet));
    TEST_ASSERT_TRUE(send(1, 0, packet, sizeof(packet), 3));
    run(60000);
    TEST_ASSERT_EQUAL(1, s_r[1].trunk.stats.transfers_ok);
    TEST_ASSERT_EQUAL(0, s_r[1].neighbors_down);
}

// A radio in range captures one asking piece of a flood to seven, moves
// radio 0's tag to the last turn (the tags do not cover their order) and
// replays it every 3 s, faster than that turn comes round. Each replay would
// push radio 0's answer back, and a waiting answer holds back every frame of
// its own: the answer keeps its first turn instead, so radio 0 still answers,
// beacons and sends.
static uint8_t s_captured[AH_TRUNK_FRAME_MAX];
static size_t s_captured_len;

static bool capture_a_flood_s_asking_piece(int from, const ah_trunk_frame_t *f)
{
    if (from == 1 && f->kind == AH_TRUNK_KIND_DATA && (f->flags & AH_TRUNK_FLAG_ASK) && f->tag_count >= 2 &&
            s_captured_len == 0) {
        memcpy(s_captured, s_r[1].air, s_r[1].air_len);
        s_captured_len = s_r[1].air_len;
    }
    return false;
}

static void test_a_replayed_piece_never_holds_the_node_silent(void)
{
    meet_n(AH_LORA_REGION_EU868, 3);
    ident_t others[5];
    for (int i = 0; i < 5; ++i) {
        ident_make(&others[i], (uint8_t)(0x10 + i));
        hear_beacon_at(1, &others[i], NULL, 22, 5);
        ah_trunk_set_bound(&s_r[1].trunk, others[i].node);
    }
    s_captured_len = 0;
    s_drop = capture_a_flood_s_asking_piece;
    uint8_t flood[40];
    memset(flood, 0x42, sizeof(flood));
    TEST_ASSERT_TRUE(send(1, 0, flood, sizeof(flood), 3));
    TEST_ASSERT_TRUE(send(1, 2, flood, sizeof(flood), 3));
    for (int i = 0; i < 5; ++i) {
        TEST_ASSERT_TRUE(ah_trunk_send(&s_r[1].trunk, others[i].node, flood, sizeof(flood), 3, s_now));
    }
    run(20000);
    s_drop = NULL;
    TEST_ASSERT_NOT_EQUAL(0, s_captured_len);
    ah_trunk_frame_t f;
    TEST_ASSERT_TRUE(ah_trunk_frame_parse(s_captured, s_captured_len, &f));
    uint8_t key[32];
    TEST_ASSERT_TRUE(ah_trunk_auth_pair_key(s_r[0].id.secret, s_r[0].id.node, s_r[1].id.key, s_r[1].id.node, key));
    const int pos = ah_trunk_auth_find(key, s_captured, s_captured_len, &f);
    TEST_ASSERT_TRUE(pos >= 0);
    uint8_t *tags = s_captured + ah_trunk_frame_tags_at(f.kind);
    uint8_t moved[8];
    memcpy(moved, tags + 8 * pos, 8);
    memcpy(tags + 8 * pos, tags + 8 * (f.tag_count - 1), 8);
    memcpy(tags + 8 * (f.tag_count - 1), moved, 8);
    s_reach[1] = false;
    s_reach[2] = false;
    const uint32_t beacons = s_r[0].beacons;
    const uint32_t data = s_r[0].data_frames;
    const uint32_t answers = s_r[0].answers;
    uint8_t packet[100];
    memset(packet, 0x33, sizeof(packet));
    TEST_ASSERT_TRUE(send(0, 2, packet, sizeof(packet), 3));
    for (int t = 0; t < 20 * 60000; t += 3000) {
        ah_trunk_on_frame(&s_r[0].trunk, s_captured, s_captured_len, 5, s_now);
        run(3000);
    }
    TEST_ASSERT_GREATER_THAN(answers, s_r[0].answers);
    TEST_ASSERT_GREATER_THAN(beacons, s_r[0].beacons);
    TEST_ASSERT_GREATER_THAN(data, s_r[0].data_frames);
}

static void test_replayed_pieces_spend_a_third_of_the_budget_at_most(void)
{
    // A piece radio 1 really sent radio 0, captured and replayed every two
    // seconds for an hour: each replay asks, and each answer would come out
    // of the budget. Answers keep to a third of it, and the node's own
    // beacons and data still go.
    meet(AH_LORA_REGION_IN865);
    const uint32_t budget = ah_trunk_budget_ms(&s_r[0].trunk);
    s_reach[1] = false;
    const uint8_t piece[20] = {0x5E};
    ah_trunk_frame_t f = {
        .kind = AH_TRUNK_KIND_DATA, .flags = AH_TRUNK_FLAG_ASK, .transfer = 0x4242, .total = 1, .payload = piece,
        .payload_len = sizeof(piece)
    };
    uint8_t frame[AH_TRUNK_FRAME_MAX];
    const size_t len = tagged(&s_r[1].id, &s_r[0].id, &f, frame);
    uint32_t answers_ms = 0;
    const uint32_t answers_before = s_r[0].answers;
    int not_queued = 0;
    for (int k = 0; k < 1800; ++k) {
        ah_trunk_on_frame(&s_r[0].trunk, frame, len, 5, s_now);
        // With the share spent nothing is queued for the node's own frames to wait behind.
        not_queued += s_r[0].trunk.controls_count == 0 ? 1 : 0;
        run(2000);
        answers_ms = (s_r[0].answers - answers_before) * ah_lora_airtime_charge_ms(&s_r[0].trunk.cfg.phy, 28);
        TEST_ASSERT_LESS_OR_EQUAL(budget / 3u + 1000u, answers_ms);
    }
    TEST_ASSERT_GREATER_THAN(0, s_r[0].trunk.stats.answers_refused);
    TEST_ASSERT_GREATER_THAN(0, not_queued);
    // The node still beacons, and still has airtime for its own packets.
    TEST_ASSERT_LESS_THAN(budget - budget / 10u - 5000u, ah_trunk_airtime_used(&s_r[0].trunk, s_now));
}

static void test_an_answer_the_budget_holds_back_is_dropped_not_sent_late(void)
{
    meet(AH_LORA_REGION_IN865);
    // The whole hour is spent, as a cold boot assumes.
    ah_trunk_ledger_restore(&s_r[0].trunk, NULL, false, s_now);
    const uint32_t answers = s_r[0].answers;
    ask_radio_0(&s_r[1].id, 0x77, false);
    TEST_ASSERT_EQUAL(1, s_r[0].trunk.controls_count);
    run(13000);
    TEST_ASSERT_EQUAL(0, s_r[0].trunk.controls_count);
    // Minutes roll off and the budget frees, and no stale answer goes.
    run(5 * 60000);
    TEST_ASSERT_EQUAL(answers, s_r[0].answers);
}

static bool bound_to(int i)
{
    const int slot = ah_trunk_slot_of(&s_r[i].trunk, s_r[1 - i].node);
    return slot >= 0 && s_r[i].trunk.neighbors[slot].bound;
}

static void test_two_unverified_nodes_still_meet(void)
{
    // No phone, nothing verified: each node's announce goes once a beacon
    // introduces the other, in one round and no probe, and again at India's
    // 20-minute interval while the link lasts; a delivered announce binds its
    // sender, as the mesh does. Neither waits on the other, so lost first
    // announces only delay them.
    const uint32_t losses[2] = {0, 300};
    for (size_t l = 0; l < 2; ++l) {
        setup(AH_LORA_REGION_IN865);
        s_loss_per_mille = losses[l];
        s_bind_on_delivery = true;
        uint8_t announce[183];
        memset(announce, 0xA5, sizeof(announce));
        int seen[2] = {0, 0};
        int64_t next_announce = s_now + 20LL * 60 * 1000;
        const int64_t start = s_now;
        while (!(bound_to(0) && bound_to(1)) && s_now - start < 4LL * 3600 * 1000) {
            run(1000);
            for (int i = 0; i < 2; ++i) {
                announce_to_newcomer(i, &seen[i], announce, sizeof(announce));
            }
            if (s_now >= next_announce) {
                next_announce += 20LL * 60 * 1000;
                for (int i = 0; i < 2; ++i) {
                    if (ah_trunk_slot_of(&s_r[i].trunk, s_r[1 - i].node) >= 0) {
                        send(i, 1 - i, announce, sizeof(announce), 0);
                    }
                }
            }
        }
        TEST_ASSERT_TRUE(bound_to(0));
        TEST_ASSERT_TRUE(bound_to(1));
        if (losses[l] == 0) {
            TEST_ASSERT_LESS_THAN(30000, s_now - start);
        }
    }
}

// ---- the duty ledger across resets ----

// The most radio 0 spent in any hour of its log.
static uint32_t busiest_hour(void)
{
    uint32_t most = 0;
    for (size_t i = 0; i < s_air_count; ++i) {
        uint32_t sum = 0;
        for (size_t j = i; j < s_air_count && s_air_at[j] < s_air_at[i] + 3600000; ++j) {
            sum += s_air_ms[j];
        }
        most = sum > most ? sum : most;
    }
    return most;
}

static void test_the_duty_ledger_carries_over_a_reset(void)
{
    meet(AH_LORA_REGION_EU868);
    for (int minute = 0; minute < 5; ++minute) {
        fill_queue(0, 480);
        run(60000);
    }
    const uint32_t spent = ah_trunk_airtime_used(&s_r[0].trunk, s_now);
    TEST_ASSERT_GREATER_THAN(0, spent);
    ah_trunk_ledger_t kept;
    ah_trunk_ledger_save(&s_r[0].trunk, s_now, &kept);
    // The next boot's clock starts again from zero; the reset ages nothing.
    static ah_trunk_t next;
    const uint8_t seed[8] = {9, 9, 9, 9, 9, 9, 9, 9};
    ah_trunk_init(&next, &s_r[0].trunk.cfg, &s_r[0].trunk.ops, seed, 1500);
    ah_trunk_ledger_restore(&next, &kept, false, 1500);
    TEST_ASSERT_EQUAL_UINT32(spent, ah_trunk_airtime_used(&next, 1500));
    TEST_ASSERT_EQUAL_UINT32(0, ah_trunk_airtime_used(&next, 1500 + 61LL * 60 * 1000));
}

// Radio 0 resets every `period_ms` for two hours, always with packets to
// send to radio 1, keeping its ledger across each reset or, on a power-on,
// keeping nothing.
static void reset_in_a_loop(int64_t period_ms, bool warm)
{
    meet(AH_LORA_REGION_IN865);
    s_air_count = 0;
    const int64_t end = s_now + 2LL * 3600 * 1000;
    uint8_t seed = 0;
    while (s_now < end) {
        ah_trunk_ledger_t kept;
        ah_trunk_ledger_save(&s_r[0].trunk, s_now, &kept);
        boot(0, AH_LORA_REGION_IN865, seed++);
        ah_trunk_ledger_restore(&s_r[0].trunk, warm ? &kept : NULL, false, s_now);
        for (int64_t t = 0; t < period_ms && s_now < end; t += 1000) {
            if (ah_trunk_slot_of(&s_r[0].trunk, s_r[1].node) >= 0) {
                ah_trunk_set_bound(&s_r[0].trunk, s_r[1].node);
                fill_queue(0, 480);
            }
            run(1000);
        }
    }
}

static void test_a_node_that_resets_in_a_loop_keeps_to_the_duty_limit(void)
{
    const uint32_t budget = 90000; // India: 2.5 % of an hour
    // A restart, a panic or a brownout keeps the ledger; a power-on keeps
    // nothing, at a period shorter than a minute, of a few minutes, and
    // longer than it takes to free the data share.
    const struct {
        int64_t period_ms;
        bool warm;
    } loops[4] = {{3LL * 60 * 1000, true}, {20000, false}, {3LL * 60 * 1000, false}, {13LL * 60 * 1000, false}};
    for (size_t i = 0; i < 4; ++i) {
        reset_in_a_loop(loops[i].period_ms, loops[i].warm);
        TEST_ASSERT_GREATER_THAN(0, s_air_count);
        TEST_ASSERT_LESS_THAN(AIR_LOG, s_air_count);
        TEST_ASSERT_LESS_OR_EQUAL_UINT32(budget, busiest_hour());
    }
}

// Radio 0's flash copy of its ledger, kept as the device keeps it: written as
// the trunk starts, then whenever ah_trunk_ledger_flush_due says.
static ah_trunk_ledger_t s_flash;
static int64_t s_flash_minute = -1;

static void keep_flash_copy(void)
{
    ah_trunk_ledger_t now;
    ah_trunk_ledger_save(&s_r[0].trunk, s_now, &now);
    const int64_t minute = s_now / 60000;
    if (s_flash_minute < 0 || ah_trunk_ledger_flush_due(&s_r[0].trunk, &now, &s_flash, minute - s_flash_minute)) {
        s_flash = now;
        s_flash_minute = minute;
    }
}

// Radio 0 sends all it can for a quarter of an hour, keeping a flash copy of
// its ledger, loses power, and comes back to send all it can for another hour,
// restoring that copy or, with none, taking the hour as spent.
static void busy_then_power_cut(bool flashed)
{
    meet(AH_LORA_REGION_IN865);
    s_air_count = 0;
    s_flash_minute = -1;
    for (int phase = 0; phase < 2; ++phase) {
        const int64_t end = s_now + (phase == 0 ? 15LL : 60LL) * 60 * 1000;
        while (s_now < end) {
            if (ah_trunk_slot_of(&s_r[0].trunk, s_r[1].node) >= 0) {
                ah_trunk_set_bound(&s_r[0].trunk, s_r[1].node);
                fill_queue(0, 480);
            }
            run(1000);
            keep_flash_copy();
        }
        if (phase == 0) {
            boot(0, AH_LORA_REGION_IN865, 7);
            ah_trunk_ledger_restore(&s_r[0].trunk, flashed ? &s_flash : NULL, flashed, s_now);
        }
    }
}

static void test_a_power_cut_after_heavy_use_keeps_to_the_duty_limit(void)
{
    const uint32_t budget = 90000; // India: 2.5 % of an hour
    // With nothing kept, the hour before is assumed spent evenly, while it
    // was spent just now: the hour around the cut runs well over.
    busy_then_power_cut(false);
    TEST_ASSERT_GREATER_THAN_UINT32(budget, busiest_hour());
    // The restore charges what the flash copy can lack.
    busy_then_power_cut(true);
    TEST_ASSERT_LESS_OR_EQUAL_UINT32(budget, busiest_hour());
}

// Power cut every 15 s in Southeast Asia, each boot restoring the flash copy
// and writing it back as the trunk starts. Each boot's beacon is far under a
// sixty-first of the budget, so the copy never holds it: only the charge the
// restore adds keeps the loop to the limit.
static void test_a_power_cut_loop_restoring_from_flash_keeps_to_the_duty_limit(void)
{
    setup(AH_LORA_REGION_SEA922);
    s_reach[0] = false;
    s_reach[1] = false;
    const uint32_t budget = ah_trunk_budget_ms(&s_r[0].trunk);
    s_flash_minute = -1;
    keep_flash_copy();
    const int64_t end = s_now + 2LL * 3600 * 1000;
    uint8_t seed = 0;
    while (s_now < end) {
        boot(0, AH_LORA_REGION_SEA922, seed++);
        ah_trunk_ledger_restore(&s_r[0].trunk, &s_flash, true, s_now);
        s_flash_minute = -1;
        keep_flash_copy();
        for (int t = 0; t < 15; ++t) {
            run(1000);
            keep_flash_copy();
        }
    }
    TEST_ASSERT_GREATER_THAN(0, s_air_count);
    TEST_ASSERT_LESS_OR_EQUAL_UINT32(budget, busiest_hour());
}

static void test_a_cold_boot_waits_for_a_minute_to_roll_over(void)
{
    setup(AH_LORA_REGION_SEA922);
    ah_trunk_ledger_restore(&s_r[0].trunk, NULL, false, s_now);
    TEST_ASSERT_EQUAL_UINT32(ah_trunk_budget_ms(&s_r[0].trunk), ah_trunk_airtime_used(&s_r[0].trunk, s_now));
    s_reach[0] = false;
    s_reach[1] = false;
    // Booted at 1 s: its first beacon waits for the minute's end.
    run(58000);
    TEST_ASSERT_EQUAL(0, s_r[0].beacons);
    run(3000);
    TEST_ASSERT_EQUAL(1, s_r[0].beacons);
}

static void test_the_budget_is_charged_airtime_rounded_up(void)
{
    // A lone node's beacon at SF9 and 125 kHz lasts 308.2 ms: 309 charged, never 308.
    setup(AH_LORA_REGION_SEA922);
    s_now = s_r[0].trunk.next_beacon_ms;
    ah_trunk_tick(&s_r[0].trunk, s_now);
    TEST_ASSERT_EQUAL(1, s_r[0].beacons);
    TEST_ASSERT_EQUAL_UINT32(308, ah_lora_airtime_ms(&s_r[0].trunk.cfg.phy, AH_TRUNK_BEACON_LEN(0)));
    TEST_ASSERT_EQUAL_UINT32(309, ah_trunk_airtime_used(&s_r[0].trunk, s_now));
    // Charged before the radio was asked, so a ledger kept at that moment
    // already holds the frame a reset might cut off.
    TEST_ASSERT_EQUAL_UINT32(309, s_r[0].charged_when_sent);
}

// ---- ARQ ----

static void test_arq_rounds_resend_only_what_is_missing(void)
{
    ah_trunk_arq_t a;
    TEST_ASSERT_TRUE(ah_trunk_arq_init(&a, 3));
    for (int i = 0; i < 3; ++i) {
        TEST_ASSERT_EQUAL(i, ah_trunk_arq_next(&a));
        ah_trunk_arq_sent(&a, (uint8_t)i);
    }
    TEST_ASSERT_EQUAL(-1, ah_trunk_arq_next(&a));
    ah_trunk_arq_hold(&a, 0x05);
    TEST_ASSERT_TRUE(ah_trunk_arq_next_round(&a, 12));
    TEST_ASSERT_EQUAL(1, ah_trunk_arq_next(&a));
    ah_trunk_arq_sent(&a, 1);
    TEST_ASSERT_EQUAL(-1, ah_trunk_arq_next(&a));
    TEST_ASSERT_FALSE(ah_trunk_arq_init(&a, 0));
    TEST_ASSERT_FALSE(ah_trunk_arq_init(&a, AH_TRUNK_PIECES_MAX + 1u));
}

static void test_arq_takes_the_receivers_word_for_what_it_holds(void)
{
    ah_trunk_arq_t a;
    TEST_ASSERT_TRUE(ah_trunk_arq_init(&a, 3));
    ah_trunk_arq_hold(&a, 0x03);
    TEST_ASSERT_TRUE(ah_trunk_arq_next_round(&a, 12));
    TEST_ASSERT_EQUAL(2, ah_trunk_arq_next(&a));
    // It lost its slot: it holds only the piece that came after. Both others go again.
    ah_trunk_arq_hold(&a, 0x04);
    TEST_ASSERT_TRUE(ah_trunk_arq_next_round(&a, 12));
    TEST_ASSERT_EQUAL(0, ah_trunk_arq_next(&a));
    ah_trunk_arq_sent(&a, 0);
    TEST_ASSERT_EQUAL(1, ah_trunk_arq_next(&a));
    ah_trunk_arq_sent(&a, 1);
    TEST_ASSERT_EQUAL(-1, ah_trunk_arq_next(&a));
}

static void test_arq_for_several_receivers_sends_what_any_one_lacks(void)
{
    ah_trunk_arq_t a;
    TEST_ASSERT_TRUE(ah_trunk_arq_init(&a, 3));
    // One holds pieces 0 and 1, another pieces 1 and 2: only piece 1 is everyone's.
    ah_trunk_arq_hold(&a, 0x03 & 0x06);
    TEST_ASSERT_TRUE(ah_trunk_arq_next_round(&a, 12));
    TEST_ASSERT_EQUAL(0, ah_trunk_arq_next(&a));
    ah_trunk_arq_sent(&a, 0);
    TEST_ASSERT_EQUAL(2, ah_trunk_arq_next(&a));
    // Nobody holding anything is every piece, and bits past the transfer mean nothing.
    ah_trunk_arq_hold(&a, 0xF8);
    TEST_ASSERT_EQUAL(0, a.held);
}

static void test_arq_probes_rotate_through_the_missing_pieces(void)
{
    ah_trunk_arq_t a;
    TEST_ASSERT_TRUE(ah_trunk_arq_init(&a, 3));
    ah_trunk_arq_hold(&a, 0x02);
    const int expected[] = {0, 2, 0, 2};
    for (size_t r = 0; r < 4; ++r) {
        TEST_ASSERT_EQUAL(expected[r], ah_trunk_arq_probe(&a));
        TEST_ASSERT_TRUE(ah_trunk_arq_next_round(&a, 12));
    }
}

static void test_arq_rounds_are_bounded(void)
{
    ah_trunk_arq_t a;
    TEST_ASSERT_TRUE(ah_trunk_arq_init(&a, 1));
    for (unsigned round = 1; round < 12; ++round) {
        TEST_ASSERT_TRUE(ah_trunk_arq_next_round(&a, 12));
    }
    TEST_ASSERT_FALSE(ah_trunk_arq_next_round(&a, 12));
}

// ---- region profiles ----

static void test_region_limits(void)
{
    TEST_ASSERT_NULL(ah_lora_region(AH_LORA_REGION_NONE));
    TEST_ASSERT_EQUAL(AH_LORA_REGION_EU868, ah_lora_region_from_code("eu"));
    TEST_ASSERT_EQUAL(AH_LORA_REGION_NONE, ah_lora_region_from_code("xx"));
    const ah_lora_region_t *eu = ah_lora_region(AH_LORA_REGION_EU868);
    // 500 mW e.r.p. is 29.15 dBm e.i.r.p.: 26 dBm conducted into 3 dBi.
    TEST_ASSERT_EQUAL(26, ah_lora_power_limit(eu, 30, 28));
    TEST_ASSERT_EQUAL(22, ah_lora_power_limit(eu, 30, 22));
    const ah_lora_region_t *us = ah_lora_region(AH_LORA_REGION_US915);
    TEST_ASSERT_EQUAL(500000, us->bandwidth_hz);
    // 28 dBm conducted, 2 dB under the PSD limit, whatever the antenna up to
    // 6 dBi; past that, the excess comes off.
    TEST_ASSERT_EQUAL(28, ah_lora_power_limit(us, 30, 33));
    TEST_ASSERT_EQUAL(28, ah_lora_power_limit(us, 60, 33));
    TEST_ASSERT_EQUAL(24, ah_lora_power_limit(us, 100, 33));
    // Australia and New Zealand state e.i.r.p. alone: 27 dBm into 3 dBi.
    const ah_lora_region_t *anz = ah_lora_region(ah_lora_region_from_code("anz"));
    TEST_ASSERT_NOT_NULL(anz);
    TEST_ASSERT_EQUAL(27, ah_lora_power_limit(anz, 30, 28));
    TEST_ASSERT_EQUAL(22, ah_lora_power_limit(anz, 30, 22));
    // 25 mW e.r.p. is 16.13 dBm e.i.r.p.: 13 dBm into 3 dBi, at 1 % of the air.
    const ah_lora_region_t *sea = ah_lora_region(ah_lora_region_from_code("sea"));
    TEST_ASSERT_NOT_NULL(sea);
    TEST_ASSERT_EQUAL(13, ah_lora_power_limit(sea, 30, 28));
    TEST_ASSERT_EQUAL(36000u, (uint32_t)sea->duty_per_mille * sea->duty_window_s);
    TEST_ASSERT_TRUE(sea->bandwidth_hz <= 250000u); // Indonesia's ceiling
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_beacons_introduce_neighbors);
    RUN_TEST(test_unicast_survives_30_percent_loss);
    RUN_TEST(test_feedback_waits_for_the_frame_to_leave);
    RUN_TEST(test_room_is_kept_per_neighbor);
    RUN_TEST(test_a_short_last_piece_first_still_reassembles_exactly);
    RUN_TEST(test_duty_budget_is_never_exceeded);
    RUN_TEST(test_announces_go_first);
    RUN_TEST(test_dead_neighbor_is_given_up);
    RUN_TEST(test_junk_gets_no_answer);
    RUN_TEST(test_a_frame_without_the_sources_key_moves_nothing);
    RUN_TEST(test_a_node_that_rebooted_is_known_again_within_seconds);
    RUN_TEST(test_a_flood_goes_once_to_every_neighbor);
    RUN_TEST(test_a_flood_finishes_for_the_live_neighbor_when_the_other_is_gone);
    RUN_TEST(test_copies_handed_over_apart_join_within_the_window);
    RUN_TEST(test_copies_join_only_while_they_wait);
    RUN_TEST(test_a_full_table_is_kept_by_beacons_of_seven_tags);
    RUN_TEST(test_a_receiver_that_lost_its_transfer_gets_every_piece_again);
    RUN_TEST(test_a_neighbor_that_cannot_hear_us_is_held_down);
    RUN_TEST(test_answers_and_beacons_keep_a_reserve);
    RUN_TEST(test_traffic_tagged_for_a_neighbor_stands_in_for_beacons);
    RUN_TEST(test_timing_is_random_per_node);
    RUN_TEST(test_a_probe_waits_a_random_part_of_a_short_frame);
    RUN_TEST(test_two_missed_beacons_keep_a_neighbor_and_three_do_not);
    RUN_TEST(test_power_follows_what_the_neighbor_sent_at);
    RUN_TEST(test_a_claimed_power_is_held_to_what_a_node_may_send);
    RUN_TEST(test_power_steps_up_after_a_silent_round_until_a_transfer_gets_through);
    RUN_TEST(test_new_identities_cost_one_announce_each_and_a_quarter_of_the_budget_at_most);
    RUN_TEST(test_answers_to_unverified_sources_keep_to_their_share);
    RUN_TEST(test_a_replayed_piece_never_holds_the_node_silent);
    RUN_TEST(test_replayed_pieces_spend_a_third_of_the_budget_at_most);
    RUN_TEST(test_an_answer_the_budget_holds_back_is_dropped_not_sent_late);
    RUN_TEST(test_two_unverified_nodes_still_meet);
    RUN_TEST(test_the_duty_ledger_carries_over_a_reset);
    RUN_TEST(test_a_node_that_resets_in_a_loop_keeps_to_the_duty_limit);
    RUN_TEST(test_a_power_cut_after_heavy_use_keeps_to_the_duty_limit);
    RUN_TEST(test_a_power_cut_loop_restoring_from_flash_keeps_to_the_duty_limit);
    RUN_TEST(test_a_cold_boot_waits_for_a_minute_to_roll_over);
    RUN_TEST(test_the_budget_is_charged_airtime_rounded_up);
    RUN_TEST(test_arq_rounds_resend_only_what_is_missing);
    RUN_TEST(test_arq_takes_the_receivers_word_for_what_it_holds);
    RUN_TEST(test_arq_for_several_receivers_sends_what_any_one_lacks);
    RUN_TEST(test_arq_probes_rotate_through_the_missing_pieces);
    RUN_TEST(test_arq_rounds_are_bounded);
    RUN_TEST(test_region_limits);
    return UNITY_END();
}
