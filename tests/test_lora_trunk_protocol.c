#include "lora_trunk_protocol.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const uint8_t SOURCE_A[8] = {1, 2, 3, 4, 5, 6, 7, 8};
static const uint8_t SOURCE_B[8] = {8, 7, 6, 5, 4, 3, 2, 1};
static const uint8_t SOURCE_C[8] = {9, 7, 5, 3, 1, 2, 4, 6};
static const uint8_t BOOT_A[8] = {0x10, 0x20, 0x30, 0x40,
                                  0x50, 0x60, 0x70, 0x80};

static lora_trunk_frame_t make_data(
    const uint8_t *source, const uint8_t *destination, bool broadcast)
{
    static const uint8_t payload[] = {0xAA, 0xBB, 0xCC};
    lora_trunk_frame_t frame = {
        .version = LORA_TRUNK_V3_VERSION,
        .kind = LORA_TRUNK_KIND_DATA,
        .flags = broadcast ? LORA_TRUNK_V3_FLAG_BROADCAST
                           : LORA_TRUNK_V3_FLAG_ACK_REQUESTED,
        .capabilities = LORA_TRUNK_V3_CAP_PROTOCOL,
        .fragment_index = 1,
        .fragment_total = 3,
        .payload = payload,
        .payload_len = sizeof(payload),
    };
    memcpy(frame.source, source, 8);
    if (destination) {
        memcpy(frame.destination, destination, 8);
    }
    lora_trunk_make_transfer_id(BOOT_A, 17, frame.transfer_id);
    return frame;
}

static lora_trunk_frame_t make_control(
    const lora_trunk_frame_t *data, lora_trunk_kind_t kind,
    uint8_t value)
{
    lora_trunk_frame_t control = {
        .version = LORA_TRUNK_V3_VERSION,
        .kind = kind,
        .capabilities = LORA_TRUNK_V3_CAP_PROTOCOL,
        .fragment_index = value,
        .fragment_total = data->fragment_total,
    };
    memcpy(control.source, data->destination, 8);
    memcpy(control.destination, data->source, 8);
    memcpy(control.transfer_id, data->transfer_id, 12);
    return control;
}

static size_t encode(
    const lora_trunk_frame_t *frame, uint8_t out[255])
{
    size_t len = 0;
    assert(lora_trunk_v3_encode(frame, out, 255, &len));
    return len;
}

static void test_v3_round_trip_and_malformed(void)
{
    lora_trunk_frame_t data = make_data(SOURCE_A, SOURCE_B, false);
    data.hop_limit = 3;
    data.hop_count = 2;
    uint8_t wire[255];
    size_t len = encode(&data, wire);
    lora_trunk_frame_t parsed;
    assert(lora_trunk_parse(wire, len, &parsed) == LORA_TRUNK_PARSE_OK);
    assert(parsed.version == 3);
    assert(parsed.kind == LORA_TRUNK_KIND_DATA);
    assert(parsed.payload_len == data.payload_len);
    assert(memcmp(parsed.source, SOURCE_A, 8) == 0);
    assert(memcmp(parsed.destination, SOURCE_B, 8) == 0);
    assert(memcmp(parsed.transfer_id, data.transfer_id, 12) == 0);
    assert(parsed.hop_limit == 3);
    assert(parsed.hop_count == 2);

    for (size_t i = 0; i < LORA_TRUNK_V3_HEADER_LEN; ++i) {
        uint8_t saved = wire[i];
        wire[i] ^= 0x5A;
        assert(lora_trunk_parse(wire, len, &parsed) != LORA_TRUNK_PARSE_OK);
        wire[i] = saved;
    }

    wire[4] = LORA_TRUNK_V3_FLAG_BROADCAST;
    /* Repairing CRC cannot make a broadcast with nonzero destination valid. */
    lora_trunk_frame_t invalid = data;
    invalid.flags = LORA_TRUNK_V3_FLAG_BROADCAST;
    assert(!lora_trunk_v3_encode(&invalid, wire, sizeof(wire), &len));

    invalid = data;
    invalid.fragment_total = 0;
    assert(!lora_trunk_v3_encode(&invalid, wire, sizeof(wire), &len));
    invalid = data;
    memset(invalid.transfer_id, 0, sizeof(invalid.transfer_id));
    assert(!lora_trunk_v3_encode(&invalid, wire, sizeof(wire), &len));
    invalid = data;
    invalid.hop_limit = 5;
    assert(!lora_trunk_v3_encode(&invalid, wire, sizeof(wire), &len));
    invalid = data;
    invalid.hop_count = 4;
    assert(!lora_trunk_v3_encode(&invalid, wire, sizeof(wire), &len));
}

static void test_exact_control_matching(void)
{
    lora_trunk_frame_t data = make_data(SOURCE_A, SOURCE_B, false);
    lora_trunk_frame_t ack =
        make_control(&data, LORA_TRUNK_KIND_BITMAP_ACK, 0x03);
    assert(lora_trunk_v3_control_matches(&data, &ack));

    memcpy(ack.source, SOURCE_C, 8);
    assert(!lora_trunk_v3_control_matches(&data, &ack));
    ack = make_control(&data, LORA_TRUNK_KIND_BITMAP_ACK, 0x03);
    ack.destination[0] ^= 1;
    assert(!lora_trunk_v3_control_matches(&data, &ack));
    ack = make_control(&data, LORA_TRUNK_KIND_BITMAP_ACK, 0x03);
    ack.transfer_id[11] ^= 1;
    assert(!lora_trunk_v3_control_matches(&data, &ack));
    ack = make_control(&data, LORA_TRUNK_KIND_BITMAP_ACK, 0x03);
    ack.fragment_total ^= 1;
    assert(!lora_trunk_v3_control_matches(&data, &ack));

    uint8_t wire[255];
    size_t len = 0;
    lora_trunk_frame_t parsed;
    ack = make_control(&data, LORA_TRUNK_KIND_BITMAP_ACK, 0x03);
    len = encode(&ack, wire);
    assert(lora_trunk_parse(wire, len, &parsed) ==
           LORA_TRUNK_PARSE_OK);
    ack.fragment_index = 0;
    assert(!lora_trunk_v3_encode(&ack, wire, sizeof(wire), &len));
    ack = make_control(&data, LORA_TRUNK_KIND_COMPLETE, 0x07);
    len = encode(&ack, wire);
    assert(lora_trunk_parse(wire, len, &parsed) ==
           LORA_TRUNK_PARSE_OK);
    ack.fragment_index = 0x03;
    assert(!lora_trunk_v3_encode(&ack, wire, sizeof(wire), &len));
    ack = make_control(
        &data, LORA_TRUNK_KIND_ABORT,
        LORA_TRUNK_ABORT_RESOURCE_PRESSURE);
    len = encode(&ack, wire);
    assert(lora_trunk_parse(wire, len, &parsed) ==
           LORA_TRUNK_PARSE_OK);
    ack.fragment_index = 0;
    assert(!lora_trunk_v3_encode(&ack, wire, sizeof(wire), &len));
}

static void test_two_senders_and_broadcast(void)
{
    lora_trunk_frame_t a = make_data(SOURCE_A, SOURCE_C, false);
    lora_trunk_frame_t b = make_data(SOURCE_B, SOURCE_C, false);
    assert(memcmp(a.transfer_id, b.transfer_id, 12) == 0);
    assert(memcmp(a.source, b.source, 8) != 0);

    lora_trunk_frame_t broadcast = make_data(SOURCE_A, NULL, true);
    uint8_t wire[255];
    size_t len = encode(&broadcast, wire);
    lora_trunk_frame_t parsed;
    assert(lora_trunk_parse(wire, len, &parsed) == LORA_TRUNK_PARSE_OK);
    assert((parsed.flags & LORA_TRUNK_V3_FLAG_ACK_REQUESTED) == 0);
    assert((parsed.flags & LORA_TRUNK_V3_FLAG_BROADCAST) != 0);

    for (unsigned receiver = 0; receiver < 4; ++receiver) {
        (void)receiver;
        assert((parsed.flags & LORA_TRUNK_V3_FLAG_ACK_REQUESTED) == 0);
    }
}

static void test_compact_beacon_and_identity_separation(void)
{
    lora_trunk_frame_t beacon;
    assert(lora_trunk_beacon_init(
        &beacon, SOURCE_A, BOOT_A, 7, 1,
        LORA_TRUNK_V3_CAP_PROTOCOL));
    uint8_t wire[255];
    size_t len = encode(&beacon, wire);
    assert(len == LORA_TRUNK_V3_HEADER_LEN);

    lora_trunk_frame_t parsed;
    assert(lora_trunk_parse(wire, len, &parsed) ==
           LORA_TRUNK_PARSE_OK);
    assert(parsed.kind == LORA_TRUNK_KIND_BEACON);
    uint8_t region = 0;
    uint32_t freshness = 0;
    assert(lora_trunk_beacon_fields(
        &parsed, &region, &freshness));
    assert(region == 1);
    assert(freshness == 7);

    lora_trunk_neighbor_table_t table;
    lora_trunk_neighbor_table_init(&table);
    assert(lora_trunk_neighbor_learn_beacon(
               &table, parsed.source, parsed.transfer_id,
               freshness, region, parsed.capabilities, 1000) ==
           LORA_TRUNK_NEIGHBOR_LEARNED);
    assert(lora_trunk_neighbor_count(&table) == 1);
    assert(!table.entries[0].identity_authenticated);

    uint8_t route[8] = {0};
    assert(!lora_trunk_neighbor_route(
        &table, SOURCE_A, 1000, 5000, route, NULL));
    assert(lora_trunk_neighbor_learn_beacon(
               &table, parsed.source, parsed.transfer_id,
               freshness, region, parsed.capabilities, 1100) ==
           LORA_TRUNK_NEIGHBOR_STALE);
    assert(lora_trunk_neighbor_learn_beacon(
               &table, parsed.source, parsed.transfer_id,
               freshness + 1, region, parsed.capabilities, 1200) ==
           LORA_TRUNK_NEIGHBOR_REFRESHED);

    uint8_t key[32] = {1};
    assert(lora_trunk_neighbor_learn_authenticated(
               &table, SOURCE_A, SOURCE_A, key,
               true, LORA_TRUNK_V3_CAP_PROTOCOL, 1300) ==
           LORA_TRUNK_NEIGHBOR_LEARNED);
    assert(table.entries[0].identity_authenticated);
    assert(lora_trunk_neighbor_route(
        &table, SOURCE_A, 1400, 5000, route, NULL));
    assert(lora_trunk_neighbor_forget_next_hop(
               &table, SOURCE_A) == 1);
    assert(!lora_trunk_neighbor_route(
        &table, SOURCE_A, 1500, 5000, route, NULL));

    lora_trunk_frame_t invalid = beacon;
    invalid.fragment_total = 1;
    assert(!lora_trunk_v3_encode(
        &invalid, wire, sizeof(wire), &len));
    invalid = beacon;
    invalid.flags = LORA_TRUNK_V3_FLAG_ACK_REQUESTED;
    assert(!lora_trunk_v3_encode(
        &invalid, wire, sizeof(wire), &len));
    uint8_t zero_epoch[8] = {0};
    assert(!lora_trunk_beacon_init(
        &invalid, SOURCE_A, zero_epoch, 1, 0,
        LORA_TRUNK_V3_CAP_PROTOCOL));
}

static void test_v2_policy(void)
{
    uint8_t data[17] = {
        0xB7, 0x1E, 0x02, 0x02,
        1, 2, 3, 4, 0, 0, 0, 0,
        0, 1, 0, 1, 0xAA,
    };
    lora_trunk_frame_t parsed;
    assert(lora_trunk_parse(data, sizeof(data), &parsed) ==
           LORA_TRUNK_PARSE_OK);
    assert(parsed.version == LORA_TRUNK_V2_VERSION);
    assert(parsed.kind == LORA_TRUNK_KIND_DATA);

    uint8_t ack[16] = {
        0xB7, 0x1E, 0x02, 0x01,
        1, 2, 3, 4, 5, 6, 7, 8,
        0, 1, 0, 1,
    };
    assert(lora_trunk_parse(ack, sizeof(ack), &parsed) ==
           LORA_TRUNK_PARSE_OK);
    ack[3] = 0x03;
    assert(lora_trunk_parse(ack, sizeof(ack), &parsed) ==
           LORA_TRUNK_PARSE_MALFORMED);
    ack[3] = 0x01;
    ack[15] = 0;
    assert(lora_trunk_parse(ack, sizeof(ack), &parsed) ==
           LORA_TRUNK_PARSE_MALFORMED);
}

static void test_neighbor_routes_and_collision(void)
{
    lora_trunk_neighbor_table_t table;
    lora_trunk_neighbor_table_init(&table);
    uint8_t key_a[32] = {1};
    uint8_t key_b[32] = {2};
    uint8_t route[8];
    uint16_t capabilities = 0;

    /* One relay may advertise independently signed routes for several peers;
     * this is not a radio-node identity collision. */
    assert(lora_trunk_neighbor_learn_authenticated(
               &table, SOURCE_B, SOURCE_A, key_a, false,
               LORA_TRUNK_V3_CAP_PROTOCOL, 900) ==
           LORA_TRUNK_NEIGHBOR_LEARNED);
    assert(lora_trunk_neighbor_learn_authenticated(
               &table, SOURCE_B, BOOT_A, key_b, false,
               LORA_TRUNK_V3_CAP_PROTOCOL, 901) ==
           LORA_TRUNK_NEIGHBOR_LEARNED);
    assert(lora_trunk_neighbor_route(
        &table, SOURCE_A, 950, 1000, route, NULL));
    assert(memcmp(route, SOURCE_B, 8) == 0);

    lora_trunk_neighbor_table_init(&table);
    assert(lora_trunk_neighbor_learn_authenticated(
               &table, SOURCE_A, SOURCE_A, key_a,
               true, LORA_TRUNK_V3_CAP_PROTOCOL, 1000) ==
           LORA_TRUNK_NEIGHBOR_LEARNED);
    assert(lora_trunk_neighbor_route(
        &table, SOURCE_A, 1500, 1000, route, &capabilities));
    assert(memcmp(route, SOURCE_A, 8) == 0);
    assert(capabilities == LORA_TRUNK_V3_CAP_PROTOCOL);
    assert(!lora_trunk_neighbor_route(
        &table, SOURCE_A, 2501, 1000, route, NULL));

    assert(lora_trunk_neighbor_learn_authenticated(
               &table, SOURCE_A, SOURCE_A, key_b,
               true, LORA_TRUNK_V3_CAP_PROTOCOL, 2000) ==
           LORA_TRUNK_NEIGHBOR_COLLISION);
    assert(!lora_trunk_neighbor_route(
        &table, SOURCE_A, 2000, 1000, route, NULL));

    lora_trunk_neighbor_table_init(&table);
    for (unsigned i = 0; i < LORA_TRUNK_NEIGHBOR_CAPACITY + 1; ++i) {
        uint8_t node[8] = {0};
        uint8_t key[32] = {0};
        node[0] = (uint8_t)(i + 1);
        key[0] = (uint8_t)(i + 1);
        lora_trunk_neighbor_result_t result =
            lora_trunk_neighbor_learn_authenticated(
                &table, node, node, key, true,
                LORA_TRUNK_V3_CAP_PROTOCOL, i);
        assert(i < LORA_TRUNK_NEIGHBOR_CAPACITY
                   ? result == LORA_TRUNK_NEIGHBOR_LEARNED
                   : result == LORA_TRUNK_NEIGHBOR_EVICTED);
    }
    assert(lora_trunk_neighbor_count(&table) ==
           LORA_TRUNK_NEIGHBOR_CAPACITY);

    lora_trunk_neighbor_table_init(&table);
    for (unsigned i = 0; i < LORA_TRUNK_NEIGHBOR_CAPACITY; ++i) {
        uint8_t node[8] = {0};
        uint8_t key[32] = {0};
        node[0] = (uint8_t)(i + 1);
        key[0] = (uint8_t)(i + 1);
        assert(lora_trunk_neighbor_learn_authenticated(
                   &table, node, node, key,
                   true, LORA_TRUNK_V3_CAP_PROTOCOL, i) ==
               LORA_TRUNK_NEIGHBOR_LEARNED);
        table.entries[i].quarantined = true;
    }
    uint8_t new_node[8] = {0xFE};
    uint8_t new_key[32] = {0xFE};
    assert(lora_trunk_neighbor_learn_authenticated(
               &table, new_node, new_node, new_key,
               true, LORA_TRUNK_V3_CAP_PROTOCOL, 100) ==
           LORA_TRUNK_NEIGHBOR_COLLISION);
}

static uint32_t fuzz_state = 0xC001D00Du;

static uint8_t fuzz_byte(void)
{
    fuzz_state = fuzz_state * 1664525u + 1013904223u;
    return (uint8_t)(fuzz_state >> 24);
}

static void test_deterministic_parser_fuzz(void)
{
    uint8_t wire[255];
    lora_trunk_frame_t parsed;
    for (unsigned sample = 0; sample < 100000; ++sample) {
        size_t len = fuzz_byte();
        for (size_t i = 0; i < len; ++i) {
            wire[i] = fuzz_byte();
        }
        if ((sample & 1u) == 0 && len >= 3) {
            wire[0] = LORA_TRUNK_MAGIC0;
            wire[1] = LORA_TRUNK_MAGIC1;
            wire[2] = (sample & 2u) != 0 ? LORA_TRUNK_V2_VERSION
                                         : LORA_TRUNK_V3_VERSION;
        }
        lora_trunk_parse_result_t result =
            lora_trunk_parse(wire, len, &parsed);
        assert(result >= LORA_TRUNK_PARSE_OK &&
               result <= LORA_TRUNK_PARSE_MALFORMED);
    }
}

int main(void)
{
    test_v3_round_trip_and_malformed();
    test_exact_control_matching();
    test_two_senders_and_broadcast();
    test_compact_beacon_and_identity_separation();
    test_v2_policy();
    test_neighbor_routes_and_collision();
    test_deterministic_parser_fuzz();
    puts("lora_trunk_protocol: ok");
    return 0;
}
