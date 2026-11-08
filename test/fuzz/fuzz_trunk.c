// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The LoRa trunk fed frames off the air: each input is a run of frames, each
// a length byte then the frame, with time moving between them, so beacons,
// acknowledgements, pieces and powers, tagged or not, reach every state the
// trunk keeps. The harness's pair key with a node is that node's static key
// itself, so a seed can tag frames as a real neighbor would
// (tools/vectors/fuzz_seeds.py). Every frame the codec accepts must encode
// back to the same bytes.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ah_lora_region.h"
#include "ah_trunk.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static bool transmit(void *ctx, const uint8_t *frame, size_t len, int8_t power, bool answer)
{
    (void)ctx;
    (void)power;
    (void)answer;
    // What the trunk sends is always well formed.
    ah_trunk_frame_t f;
    if (!ah_trunk_frame_parse(frame, len, &f)) {
        abort();
    }
    return true;
}

static void deliver(void *ctx, int slot, const uint8_t node[8], const uint8_t *packet, size_t len)
{
    (void)ctx;
    (void)slot;
    (void)node;
    (void)packet;
    if (len == 0 || len > AH_TRUNK_PACKET_MAX) {
        abort();
    }
}

static void neighbor(void *ctx, int slot, const uint8_t node[8], bool up)
{
    (void)ctx;
    (void)slot;
    (void)node;
    (void)up;
}

static bool pair_key(void *ctx, const uint8_t peer_key[32], const uint8_t peer[8], uint8_t out[32])
{
    (void)ctx;
    (void)peer;
    memcpy(out, peer_key, 32);
    return true;
}

static void round_trip(const uint8_t *frame, size_t len)
{
    ah_trunk_frame_t f;
    if (!ah_trunk_frame_parse(frame, len, &f)) {
        return;
    }
    uint8_t again[AH_TRUNK_FRAME_MAX];
    if (ah_trunk_frame_encode(&f, again, sizeof(again)) != len || memcmp(again, frame, len) != 0) {
        abort();
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static ah_trunk_t t;
    // India for half the inputs: its adaptive power lets forged power bytes
    // reach the power choice too.
    const ah_lora_region_t *region = ah_lora_region(size % 2 == 0 ? AH_LORA_REGION_IN865 : AH_LORA_REGION_EU868);
    ah_trunk_config_t cfg = {
        .region = region,
        .phy = {.spreading_factor = 10, .bandwidth_hz = 125000, .coding_rate = 5, .preamble_symbols = 8},
        .max_power_dbm = 22,
    };
    memset(cfg.self, 0x42, sizeof(cfg.self));
    memset(cfg.key, 0x24, sizeof(cfg.key));
    const ah_trunk_ops_t ops = {.transmit = transmit, .deliver = deliver, .neighbor = neighbor, .pair_key = pair_key};
    const uint8_t seed[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    int64_t now = 1000;
    ah_trunk_init(&t, &cfg, &ops, seed, now);
    // A third of the inputs start as a cold boot does, with the hour spent.
    if (size % 3 == 0) {
        ah_trunk_ledger_restore(&t, NULL, false, now);
    }
    // Something of our own in flight, so acknowledgements have a transfer to hit.
    uint8_t packet[300];
    memset(packet, 0x5A, sizeof(packet));
    size_t off = 0;
    while (off < size) {
        const size_t len = data[off++];
        if (len > size - off) {
            break;
        }
        round_trip(data + off, len);
        ah_trunk_on_frame(&t, data + off, len, (int8_t)((int)(len % 20) - 10), now);
        // The mesh verifies some sources and not others: an odd-length frame's
        // source is taken as verified, so both kinds of neighbor are reached.
        if (len % 2 == 1 && len >= 14) {
            ah_trunk_set_bound(&t, data + off + 6);
        }
        // A packet for whichever neighbors the frames made, joining one transfer when it can.
        for (int slot = 0; slot < (int)AH_TRUNK_NEIGHBORS; ++slot) {
            const uint8_t *node = ah_trunk_node_at(&t, slot);
            if (node != NULL && ah_trunk_room(&t, node)) {
                ah_trunk_send(&t, node, packet, sizeof(packet), (uint8_t)(len % 7), now);
            }
        }
        off += len;
        now += 50 + (int64_t)(len * 37);
        ah_trunk_on_tx_done(&t, now);
        ah_trunk_tick(&t, now);
    }
    return 0;
}
