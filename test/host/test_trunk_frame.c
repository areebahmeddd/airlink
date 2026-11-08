// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The trunk frame codec, the tags that authenticate it, and LoRa time on air.
#include <string.h>

#include "ah_crypto.h"
#include "ah_lora_airtime.h"
#include "ah_trunk_auth.h"
#include "ah_trunk_frame.h"
#include "unity.h"

static const uint8_t NODE_A[8] = {1, 2, 3, 4, 5, 6, 7, 8};
static uint8_t s_payload[AH_TRUNK_PIECE_MAX(1)];
static uint8_t s_key[32];

void setUp(void)
{
    for (size_t i = 0; i < sizeof(s_payload); ++i) {
        s_payload[i] = (uint8_t)(i * 13u + 5u);
    }
    for (size_t i = 0; i < sizeof(s_key); ++i) {
        s_key[i] = (uint8_t)(0x90u + i);
    }
}

void tearDown(void)
{
}

static ah_trunk_frame_t frame_of(ah_trunk_kind_t kind)
{
    ah_trunk_frame_t f = {.kind = kind, .power_dbm = 17};
    memcpy(f.source, NODE_A, 8);
    if (kind == AH_TRUNK_KIND_BEACON) {
        memcpy(f.key, s_key, 32);
        f.tag_count = 2;
        memset(f.tags[0], 0xA1, 8);
        memset(f.tags[1], 0xA2, 8);
        return f;
    }
    f.transfer = 0x01020304u;
    f.total = 3;
    f.tag_count = 1;
    memset(f.tags[0], 0xC1, 8);
    switch (kind) {
    case AH_TRUNK_KIND_DATA:
        f.flags = AH_TRUNK_FLAG_ASK;
        f.index = 1;
        f.tag_count = 2;
        memset(f.tags[1], 0xC2, 8);
        f.payload = s_payload;
        f.payload_len = 200;
        break;
    case AH_TRUNK_KIND_ACK:
        f.index = 0x05;
        break;
    default:
        f.index = 0x07;
        break;
    }
    return f;
}

static size_t encode(const ah_trunk_frame_t *f, uint8_t *wire)
{
    const size_t len = ah_trunk_frame_encode(f, wire, AH_TRUNK_FRAME_MAX + 1u);
    TEST_ASSERT_NOT_EQUAL(0, len);
    return len;
}

static void test_a_frame_round_trips_in_the_documented_layout(void)
{
    const ah_trunk_frame_t f = frame_of(AH_TRUNK_KIND_DATA);
    uint8_t wire[AH_TRUNK_FRAME_MAX + 1];
    const size_t len = encode(&f, wire);
    TEST_ASSERT_EQUAL(21u + 16u + 200u, len);
    const uint8_t head[] = {0x41, 0x4C, 1, 1, 0x01, 17};
    TEST_ASSERT_EQUAL_MEMORY(head, wire, sizeof(head));
    TEST_ASSERT_EQUAL_MEMORY(NODE_A, wire + 6, 8);
    const uint8_t rest[] = {0x01, 0x02, 0x03, 0x04, 1, 3, 2};
    TEST_ASSERT_EQUAL_MEMORY(rest, wire + 14, sizeof(rest));
    TEST_ASSERT_EACH_EQUAL_UINT8(0xC1, wire + 21, 8);
    TEST_ASSERT_EACH_EQUAL_UINT8(0xC2, wire + 29, 8);
    TEST_ASSERT_EQUAL_MEMORY(s_payload, wire + 37, 200);

    ah_trunk_frame_t p;
    TEST_ASSERT_TRUE(ah_trunk_frame_parse(wire, len, &p));
    TEST_ASSERT_EQUAL(AH_TRUNK_KIND_DATA, p.kind);
    TEST_ASSERT_EQUAL(AH_TRUNK_FLAG_ASK, p.flags);
    TEST_ASSERT_EQUAL_INT8(17, p.power_dbm);
    TEST_ASSERT_EQUAL_UINT32(0x01020304u, p.transfer);
    TEST_ASSERT_EQUAL(1, p.index);
    TEST_ASSERT_EQUAL(3, p.total);
    TEST_ASSERT_EQUAL(2, p.tag_count);
    TEST_ASSERT_EACH_EQUAL_UINT8(0xC2, p.tags[1], 8);
    TEST_ASSERT_EQUAL(200, p.payload_len);
    TEST_ASSERT_EQUAL_PTR(wire + 37, p.payload);

    // A negative power survives the byte.
    ah_trunk_frame_t quiet = f;
    quiet.power_dbm = -9;
    encode(&quiet, wire);
    TEST_ASSERT_TRUE(ah_trunk_frame_parse(wire, len, &p));
    TEST_ASSERT_EQUAL_INT8(-9, p.power_dbm);

    // An answer: the transfer, the bitmap, the total and one tag, 28 bytes.
    const ah_trunk_frame_t ack = frame_of(AH_TRUNK_KIND_ACK);
    TEST_ASSERT_EQUAL(AH_TRUNK_ANSWER_LEN, encode(&ack, wire));
    TEST_ASSERT_EQUAL(28, AH_TRUNK_ANSWER_LEN);
    const uint8_t answer[] = {0x41, 0x4C, 1, 2, 0, 17};
    TEST_ASSERT_EQUAL_MEMORY(answer, wire, sizeof(answer));
    const uint8_t fields[] = {0x01, 0x02, 0x03, 0x04, 0x05, 3};
    TEST_ASSERT_EQUAL_MEMORY(fields, wire + 14, sizeof(fields));
    TEST_ASSERT_EACH_EQUAL_UINT8(0xC1, wire + 20, 8);
    TEST_ASSERT_TRUE(ah_trunk_frame_parse(wire, AH_TRUNK_ANSWER_LEN, &p));
    TEST_ASSERT_EQUAL(1, p.tag_count);
    TEST_ASSERT_NULL(p.payload);
}

static void test_a_beacon_carries_its_key_and_its_tags(void)
{
    const ah_trunk_frame_t b = frame_of(AH_TRUNK_KIND_BEACON);
    uint8_t wire[AH_TRUNK_FRAME_MAX + 1];
    TEST_ASSERT_EQUAL(47u + 16u, encode(&b, wire));
    TEST_ASSERT_EQUAL_MEMORY(s_key, wire + 14, 32);
    TEST_ASSERT_EQUAL(2, wire[46]);
    TEST_ASSERT_EACH_EQUAL_UINT8(0xA1, wire + 47, 8);
    ah_trunk_frame_t p;
    TEST_ASSERT_TRUE(ah_trunk_frame_parse(wire, 63, &p));
    TEST_ASSERT_EQUAL(AH_TRUNK_KIND_BEACON, p.kind);
    TEST_ASSERT_EQUAL_MEMORY(s_key, p.key, 32);
    TEST_ASSERT_NULL(p.payload);
    // A newcomer's beacon, knowing nobody yet.
    ah_trunk_frame_t lone = b;
    lone.tag_count = 0;
    TEST_ASSERT_EQUAL(AH_TRUNK_BEACON_LEN(0), encode(&lone, wire));
    TEST_ASSERT_EQUAL(47, AH_TRUNK_BEACON_LEN(0));
}

// A valid frame with the byte at `at` set to `value`: refused.
static void assert_refused(ah_trunk_kind_t kind, size_t at, uint8_t value)
{
    const ah_trunk_frame_t f = frame_of(kind);
    uint8_t wire[AH_TRUNK_FRAME_MAX + 1];
    const size_t len = encode(&f, wire);
    wire[at] = value;
    ah_trunk_frame_t p;
    TEST_ASSERT_FALSE_MESSAGE(ah_trunk_frame_parse(wire, len, &p), "a changed byte was accepted");
}

static void test_malformed_frames_are_refused(void)
{
    uint8_t wire[AH_TRUNK_FRAME_MAX + 1];
    ah_trunk_frame_t p;
    const ah_trunk_frame_t data = frame_of(AH_TRUNK_KIND_DATA);
    const size_t len = encode(&data, wire);
    TEST_ASSERT_FALSE(ah_trunk_frame_parse(wire, AH_TRUNK_ANSWER_LEN - 1u, &p));
    TEST_ASSERT_FALSE(ah_trunk_frame_parse(NULL, len, &p));
    // A DATA frame with no piece.
    TEST_ASSERT_FALSE(ah_trunk_frame_parse(wire, AH_TRUNK_DATA_HEADER_LEN(2), &p));
    // Longer than the radio carries.
    memset(wire + len, 0, sizeof(wire) - len);
    TEST_ASSERT_FALSE(ah_trunk_frame_parse(wire, AH_TRUNK_FRAME_MAX + 1u, &p));

    for (int k = AH_TRUNK_KIND_DATA; k <= AH_TRUNK_KIND_BEACON; ++k) {
        const ah_trunk_kind_t kind = (ah_trunk_kind_t)k;
        // Another magic, and a version other than 1.
        assert_refused(kind, 0, 0xB7);
        assert_refused(kind, 1, 0x1E);
        assert_refused(kind, 2, 0);
        assert_refused(kind, 2, 4);
        assert_refused(kind, 3, 0);
        assert_refused(kind, 3, 5);
        for (unsigned bit = 1; bit < 8; ++bit) {
            assert_refused(kind, 4, (uint8_t)(1u << bit));
        }
    }
    // A zero node ID: never encoded, never parsed.
    ah_trunk_frame_t nameless = frame_of(AH_TRUNK_KIND_BEACON);
    const size_t named_len = encode(&nameless, wire);
    memset(wire + 6, 0, 8);
    TEST_ASSERT_FALSE(ah_trunk_frame_parse(wire, named_len, &p));
    memset(nameless.source, 0, 8);
    TEST_ASSERT_EQUAL(0, ah_trunk_frame_encode(&nameless, wire, sizeof(wire)));

    // DATA: a transfer, a piece of a transfer of 1 to 3, one to seven tags, a
    // piece that fits beside them.
    ah_trunk_frame_t f = data;
    f.transfer = 0;
    TEST_ASSERT_EQUAL(0, ah_trunk_frame_encode(&f, wire, sizeof(wire)));
    assert_refused(AH_TRUNK_KIND_DATA, 18, 3);
    assert_refused(AH_TRUNK_KIND_DATA, 19, 0);
    assert_refused(AH_TRUNK_KIND_DATA, 19, 4);
    assert_refused(AH_TRUNK_KIND_DATA, 20, 0);
    assert_refused(AH_TRUNK_KIND_DATA, 20, 8);
    f = data;
    f.tag_count = 0;
    TEST_ASSERT_EQUAL(0, ah_trunk_frame_encode(&f, wire, sizeof(wire)));
    f.tag_count = AH_TRUNK_TAGS_MAX + 1u;
    TEST_ASSERT_EQUAL(0, ah_trunk_frame_encode(&f, wire, sizeof(wire)));
    f = data;
    f.payload_len = AH_TRUNK_PIECE_MAX(2) + 1u;
    TEST_ASSERT_EQUAL(0, ah_trunk_frame_encode(&f, wire, sizeof(wire)));
    f.tag_count = 1;
    f.payload_len = AH_TRUNK_PIECE_MAX(1);
    TEST_ASSERT_EQUAL(AH_TRUNK_FRAME_MAX, encode(&f, wire));

    // ACK: never asks, holds some pieces of this transfer but not all.
    assert_refused(AH_TRUNK_KIND_ACK, 4, AH_TRUNK_FLAG_ASK);
    assert_refused(AH_TRUNK_KIND_ACK, 18, 0x00);
    assert_refused(AH_TRUNK_KIND_ACK, 18, 0x07);
    assert_refused(AH_TRUNK_KIND_ACK, 18, 0x09);
    // COMPLETE: every piece, nothing less.
    assert_refused(AH_TRUNK_KIND_COMPLETE, 18, 0x03);
    assert_refused(AH_TRUNK_KIND_COMPLETE, 4, AH_TRUNK_FLAG_ASK);
    // Answers and beacons are exactly their length.
    const ah_trunk_frame_t ack = frame_of(AH_TRUNK_KIND_ACK);
    TEST_ASSERT_EQUAL(AH_TRUNK_ANSWER_LEN, encode(&ack, wire));
    wire[AH_TRUNK_ANSWER_LEN] = 0x55;
    TEST_ASSERT_FALSE(ah_trunk_frame_parse(wire, AH_TRUNK_ANSWER_LEN + 1u, &p));
    const ah_trunk_frame_t beacon = frame_of(AH_TRUNK_KIND_BEACON);
    const size_t blen = encode(&beacon, wire);
    TEST_ASSERT_FALSE(ah_trunk_frame_parse(wire, blen + 1u, &p));
    TEST_ASSERT_FALSE(ah_trunk_frame_parse(wire, blen - 1u, &p));
    // BEACON: never asks, at most seven tags, and as many as it says.
    assert_refused(AH_TRUNK_KIND_BEACON, 4, AH_TRUNK_FLAG_ASK);
    assert_refused(AH_TRUNK_KIND_BEACON, 46, 3);
    assert_refused(AH_TRUNK_KIND_BEACON, 46, AH_TRUNK_TAGS_MAX + 1u);

    // A buffer too small for the frame.
    TEST_ASSERT_EQUAL(0, ah_trunk_frame_encode(&data, wire, len - 1u));
}

static void test_answers_match_the_exact_transfer(void)
{
    const ah_trunk_frame_t data = frame_of(AH_TRUNK_KIND_DATA);
    const ah_trunk_frame_t ack = frame_of(AH_TRUNK_KIND_ACK);
    TEST_ASSERT_TRUE(ah_trunk_frame_answers(&data, &ack));
    ah_trunk_frame_t complete = ack;
    complete.kind = AH_TRUNK_KIND_COMPLETE;
    TEST_ASSERT_TRUE(ah_trunk_frame_answers(&data, &complete));

    ah_trunk_frame_t other = ack;
    other.transfer ^= 1u;
    TEST_ASSERT_FALSE(ah_trunk_frame_answers(&data, &other));
    other = ack;
    other.total = 2;
    TEST_ASSERT_FALSE(ah_trunk_frame_answers(&data, &other));
    // Our own frame echoed back is no answer.
    TEST_ASSERT_FALSE(ah_trunk_frame_answers(&data, &data));
}

// ---- authentication ----

typedef struct {
    uint8_t secret[32];
    uint8_t key[32];
    uint8_t node[8];
} node_keys_t;

static void make_node(node_keys_t *k, uint8_t seed)
{
    memset(k->secret, seed, sizeof(k->secret));
    ah_x25519_public(k->secret, k->key);
    uint8_t hash[32];
    TEST_ASSERT_TRUE(ah_sha256(k->key, sizeof(k->key), hash));
    memcpy(k->node, hash, 8);
}

static void test_two_nodes_derive_the_same_pair_key_and_no_one_else_does(void)
{
    node_keys_t a;
    node_keys_t b;
    node_keys_t c;
    make_node(&a, 0x11);
    make_node(&b, 0x22);
    make_node(&c, 0x33);
    uint8_t ab[32];
    uint8_t ba[32];
    uint8_t ac[32];
    TEST_ASSERT_TRUE(ah_trunk_auth_pair_key(a.secret, a.node, b.key, b.node, ab));
    TEST_ASSERT_TRUE(ah_trunk_auth_pair_key(b.secret, b.node, a.key, a.node, ba));
    TEST_ASSERT_TRUE(ah_trunk_auth_pair_key(a.secret, a.node, c.key, c.node, ac));
    TEST_ASSERT_EQUAL_MEMORY(ab, ba, 32);
    TEST_ASSERT_FALSE(memcmp(ab, ac, 32) == 0);
    // The IDs are part of the key: the same exchange under other names is another key.
    uint8_t renamed[32];
    TEST_ASSERT_TRUE(ah_trunk_auth_pair_key(a.secret, a.node, b.key, c.node, renamed));
    TEST_ASSERT_FALSE(memcmp(ab, renamed, 32) == 0);
    // A low-order key gives no pair key at all.
    const uint8_t zero[32] = {0};
    TEST_ASSERT_FALSE(ah_trunk_auth_pair_key(a.secret, a.node, zero, b.node, renamed));
    TEST_ASSERT_EACH_EQUAL_UINT8(0, renamed, 32);

    // A key names the ID its hash begins with, and no other.
    TEST_ASSERT_TRUE(ah_trunk_auth_names(a.key, a.node));
    TEST_ASSERT_FALSE(ah_trunk_auth_names(a.key, b.node));
}

static void test_a_tag_covers_every_byte_but_the_tags(void)
{
    node_keys_t a;
    node_keys_t b;
    node_keys_t c;
    make_node(&a, 0x11);
    make_node(&b, 0x22);
    make_node(&c, 0x33);
    uint8_t ab[32];
    uint8_t ac[32];
    uint8_t bc[32];
    TEST_ASSERT_TRUE(ah_trunk_auth_pair_key(a.secret, a.node, b.key, b.node, ab));
    TEST_ASSERT_TRUE(ah_trunk_auth_pair_key(a.secret, a.node, c.key, c.node, ac));
    TEST_ASSERT_TRUE(ah_trunk_auth_pair_key(b.secret, b.node, c.key, c.node, bc));
    // A piece from A for B and C, tagged as the trunk tags it: encoded with
    // the tags blank, then each written in.
    ah_trunk_frame_t f = frame_of(AH_TRUNK_KIND_DATA);
    memcpy(f.source, a.node, 8);
    memset(f.tags, 0, sizeof(f.tags));
    uint8_t wire[AH_TRUNK_FRAME_MAX];
    const size_t len = encode(&f, wire);
    const size_t at = ah_trunk_frame_tags_at(AH_TRUNK_KIND_DATA);
    TEST_ASSERT_TRUE(ah_trunk_auth_tag(ab, wire, len, &f, wire + at));
    TEST_ASSERT_TRUE(ah_trunk_auth_tag(ac, wire, len, &f, wire + at + 8));
    ah_trunk_frame_t p;
    TEST_ASSERT_TRUE(ah_trunk_frame_parse(wire, len, &p));
    // Each finds its own tag, in its turn; a key the sender does not share finds none.
    TEST_ASSERT_EQUAL(0, ah_trunk_auth_find(ab, wire, len, &p));
    TEST_ASSERT_EQUAL(1, ah_trunk_auth_find(ac, wire, len, &p));
    TEST_ASSERT_EQUAL(-1, ah_trunk_auth_find(bc, wire, len, &p));
    // Any byte changed outside the tags, the power included, and no tag holds.
    for (size_t i = 0; i < len; ++i) {
        if (i >= at && i < at + 16u) {
            continue;
        }
        uint8_t changed[AH_TRUNK_FRAME_MAX];
        memcpy(changed, wire, len);
        changed[i] ^= 0x01u;
        ah_trunk_frame_t q;
        if (ah_trunk_frame_parse(changed, len, &q)) {
            TEST_ASSERT_EQUAL(-1, ah_trunk_auth_find(ab, changed, len, &q));
        }
    }
    // A tag moved to another frame does not hold there: an answer's tag
    // covers its transfer, so an old COMPLETE ends no other transfer.
    ah_trunk_frame_t done = frame_of(AH_TRUNK_KIND_COMPLETE);
    memcpy(done.source, b.node, 8);
    const size_t dlen = encode(&done, wire);
    TEST_ASSERT_TRUE(ah_trunk_auth_tag(ab, wire, dlen, &done, wire + 20));
    TEST_ASSERT_TRUE(ah_trunk_frame_parse(wire, dlen, &p));
    TEST_ASSERT_EQUAL(0, ah_trunk_auth_find(ab, wire, dlen, &p));
    wire[17] ^= 0x01u;
    TEST_ASSERT_TRUE(ah_trunk_frame_parse(wire, dlen, &p));
    TEST_ASSERT_EQUAL(-1, ah_trunk_auth_find(ab, wire, dlen, &p));
}

// ---- time on air ----

static void test_airtime_matches_an1200_13(void)
{
    ah_lora_phy_t phy = {.spreading_factor = 10, .bandwidth_hz = 125000, .coding_rate = 5, .preamble_symbols = 8};
    TEST_ASSERT_TRUE(ah_lora_phy_valid(&phy));
    TEST_ASSERT_EQUAL_UINT32(1313, ah_lora_airtime_ms(&phy, 136));
    const uint32_t sixteen[] = {51, 93, 165, 330, 659, 1319};
    for (uint8_t sf = 7; sf <= 12; ++sf) {
        phy.spreading_factor = sf;
        TEST_ASSERT_EQUAL_UINT32(sixteen[sf - 7], ah_lora_airtime_ms(&phy, 16));
    }
    // A 16-symbol preamble, at 16, 136 and 255 bytes.
    phy.preamble_symbols = 16;
    const uint32_t long_preamble[6][3] = {
        {60, 234, 408}, {109, 416, 723}, {198, 751, 1283}, {395, 1378, 2361}, {791, 3002, 5132}, {1581, 5513, 9282},
    };
    for (uint8_t sf = 7; sf <= 12; ++sf) {
        phy.spreading_factor = sf;
        TEST_ASSERT_EQUAL_UINT32(long_preamble[sf - 7][0], ah_lora_airtime_ms(&phy, 16));
        TEST_ASSERT_EQUAL_UINT32(long_preamble[sf - 7][1], ah_lora_airtime_ms(&phy, 136));
        TEST_ASSERT_EQUAL_UINT32(long_preamble[sf - 7][2], ah_lora_airtime_ms(&phy, 255));
    }

    // Low data rate optimization from a 16 ms symbol on, as the driver sets it.
    const ah_lora_phy_t ldro[] = {{11, 125000, 5, 8}, {12, 250000, 5, 8}};
    const ah_lora_phy_t plain[] = {{10, 125000, 5, 8}, {11, 250000, 5, 8}, {12, 500000, 5, 8}};
    for (size_t i = 0; i < 2; ++i) {
        TEST_ASSERT_TRUE(ah_lora_low_data_rate(&ldro[i]));
    }
    for (size_t i = 0; i < 3; ++i) {
        TEST_ASSERT_FALSE(ah_lora_low_data_rate(&plain[i]));
    }

    const ah_lora_phy_t bad[] = {
        {6, 125000, 5, 8}, {13, 125000, 5, 8}, {10, 200000, 5, 8}, {10, 125000, 4, 8}, {10, 125000, 9, 8},
        {10, 125000, 5, 3},
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        TEST_ASSERT_FALSE(ah_lora_phy_valid(&bad[i]));
        TEST_ASSERT_EQUAL_UINT32(0, ah_lora_airtime_ms(&bad[i], 44));
    }
    phy.spreading_factor = 10;
    phy.preamble_symbols = 8;
    TEST_ASSERT_EQUAL_UINT32(0, ah_lora_airtime_ms(&phy, 0));
    TEST_ASSERT_EQUAL_UINT32(0, ah_lora_airtime_ms(&phy, 256));
    TEST_ASSERT_EQUAL_UINT32(0, ah_lora_airtime_ms(NULL, 44));
}

static void test_the_duty_charge_rounds_airtime_up(void)
{
    // 255 bytes at SF12 and 500 kHz last 1,927.168 ms: shown as 1,927, charged 1,928.
    const ah_lora_phy_t us = {12, 500000, 5, 8};
    TEST_ASSERT_EQUAL_UINT32(1927, ah_lora_airtime_ms(&us, 255));
    TEST_ASSERT_EQUAL_UINT32(1928, ah_lora_airtime_charge_ms(&us, 255));
    const uint32_t bandwidths[3] = {125000, 250000, 500000};
    for (uint8_t sf = 7; sf <= 12; ++sf) {
        for (size_t b = 0; b < 3; ++b) {
            const ah_lora_phy_t phy = {sf, bandwidths[b], 5, 8};
            for (uint16_t len = 1; len <= AH_TRUNK_FRAME_MAX; ++len) {
                const uint32_t shown = ah_lora_airtime_ms(&phy, len);
                const uint32_t charged = ah_lora_airtime_charge_ms(&phy, len);
                TEST_ASSERT_TRUE(charged == shown || charged == shown + 1u);
            }
        }
    }
    TEST_ASSERT_EQUAL_UINT32(0, ah_lora_airtime_charge_ms(&us, 0));
    TEST_ASSERT_EQUAL_UINT32(0, ah_lora_airtime_charge_ms(NULL, 44));
}

// The airtime table in docs/LORA.md: CR 4/5, 8-symbol preamble.
static void test_the_documented_airtime_table(void)
{
    const ah_lora_phy_t phys[3] = {{10, 125000, 5, 8}, {12, 500000, 5, 8}, {9, 125000, 5, 8}};
    const uint16_t lens[6] = {AH_TRUNK_ANSWER_LEN, AH_TRUNK_BEACON_LEN(1), 64, 128, 200, AH_TRUNK_FRAME_MAX};
    const uint32_t ms[3][6] = {
        {412, 657, 698, 1231, 1845, 2296},
        {371, 575, 616, 1067, 1559, 1927},
        {226, 349, 390, 677, 1005, 1250},
    };
    for (size_t p = 0; p < 3; ++p) {
        for (size_t l = 0; l < 6; ++l) {
            TEST_ASSERT_EQUAL_UINT32(ms[p][l], ah_lora_airtime_ms(&phys[p], lens[l]));
        }
    }
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_a_frame_round_trips_in_the_documented_layout);
    RUN_TEST(test_a_beacon_carries_its_key_and_its_tags);
    RUN_TEST(test_malformed_frames_are_refused);
    RUN_TEST(test_answers_match_the_exact_transfer);
    RUN_TEST(test_two_nodes_derive_the_same_pair_key_and_no_one_else_does);
    RUN_TEST(test_a_tag_covers_every_byte_but_the_tags);
    RUN_TEST(test_airtime_matches_an1200_13);
    RUN_TEST(test_the_duty_charge_rounds_airtime_up);
    RUN_TEST(test_the_documented_airtime_table);
    return UNITY_END();
}
