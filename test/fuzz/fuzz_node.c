// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// A whole relay node fed hostile frames on three links (two Bluetooth, one
// LoRa), with time passing: the ingress pipeline, relaying, sync, mail and
// the DM path all see the bytes.
//
// Before the first input, two phones announce over the Bluetooth links and a
// node over the LoRa one, so the clock is synced and confirmed and every link
// is bound: the paths behind the clock and the binding are reachable. Every
// input starts from the node as that left it, and is a run of records: a
// control byte, a 2-byte big-endian length, then the frame. The control byte's
// bits 0 and 1 pick the link; bit 5 stamps the frame with the node's current
// time; bit 6 signs it as the link's own peer, so a mutated payload still
// passes the signature gates; bit 7 turns the record into a transport event
// instead, the link refusing writes until a later bit-7 record on it frees it
// again.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ah_announce.h"
#include "ah_bytes.h"
#include "ah_crypto.h"
#include "ah_frame.h"
#include "ah_node.h"
#include "ah_payload.h"
#include "ah_test_crypto.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define LINKS 3u
#define FLAG_STAMP 0x20u
#define FLAG_SIGN 0x40u
#define FLAG_TRANSPORT 0x80u
// The floor and the phones' clocks: 2026, so time-checked paths run.
#define WALL0 1780000000000ull

typedef struct {
    ah_identity_t id;
    bool is_node;
} harness_peer_t;

static harness_peer_t s_peers[LINKS];
static bool s_busy[LINKS + 1u];

static ah_write_t write_stub(void *ctx, ah_link_kind_t kind, uint32_t handle, const uint8_t *frame, size_t len,
                             uint8_t prio)
{
    (void)ctx;
    (void)kind;
    (void)frame;
    (void)len;
    (void)prio;
    return handle <= LINKS && s_busy[handle] ? AH_WRITE_BUSY : AH_WRITE_OK;
}

static void mail_put(void *ctx, uint32_t record, uint64_t depositor, const uint8_t *env, size_t len)
{
    (void)ctx;
    (void)record;
    (void)depositor;
    (void)env;
    (void)len;
}

static void mail_delete(void *ctx, uint32_t record)
{
    (void)ctx;
    (void)record;
}

// The node's memory: one static arena, so its whole state can be copied.
static uint8_t s_arena[2 * 1024 * 1024];
static size_t s_used;

static void *arena_alloc(void *ctx, size_t bytes)
{
    (void)ctx;
    const size_t at = (s_used + 15u) & ~(size_t)15u;
    if (at + bytes > sizeof(s_arena)) {
        return NULL;
    }
    s_used = at + bytes;
    memset(s_arena + at, 0, bytes);
    return s_arena + at;
}

static void make_identity(ah_identity_t *id, uint8_t seed_byte, const char *name)
{
    memset(id, 0, sizeof(*id));
    memset(id->noise_secret, seed_byte, sizeof(id->noise_secret));
    ah_x25519_public(id->noise_secret, id->noise_public);
    uint8_t seed[32];
    memset(seed, (uint8_t)(seed_byte ^ 0x5Au), sizeof(seed));
    ah_ed25519_keypair(seed, id->signing_secret, id->signing_public);
    ah_peer_id_of(id->noise_public, id->peer_id);
    id->nickname_len = (uint8_t)strlen(name);
    memcpy(id->nickname, name, id->nickname_len);
}

// Sign a parsed frame, held in a writable buffer, as `id`.
static void sign_as(const ah_identity_t *id, uint8_t *frame, size_t len)
{
    static uint8_t preimage[AH_CAP_ENVELOPE + 2u * AH_PAD_MAX];
    ah_frame_t view;
    size_t pre_len = 0;
    if (!ah_frame_parse(frame, len, &view) || view.signature == NULL ||
            !ah_frame_signing_preimage(&view, preimage, sizeof(preimage), &pre_len)) {
        return;
    }
    uint8_t signature[AH_SIGNATURE_LEN];
    ah_ed25519_sign(id->signing_secret, preimage, pre_len, signature);
    memcpy((uint8_t *)view.signature, signature, AH_SIGNATURE_LEN);
}

// A peer's signed TTL 7 announce, built once: signing it every run would
// cost more than the run.
static size_t build_announce(const harness_peer_t *p, uint64_t wall, uint8_t frame[AH_BLE_FRAME_MAX])
{
    uint8_t payload[160];
    const size_t plen = ah_announce_encode(p->id.nickname, p->id.nickname_len, p->id.noise_public,
                                           p->id.signing_public, 0x010000u, p->is_node ? AH_RELAY_FLAG_DEDICATED : 0u,
                                           payload, sizeof(payload));
    const ah_frame_fields_t fields = {
        .type = AH_TYPE_ANNOUNCE, .ttl = AH_TTL_DEFAULT, .timestamp_ms = wall, .sender = p->id.peer_id,
        .payload = payload, .payload_len = plen
    };
    const size_t len = ah_frame_encode(&fields, true, frame, AH_BLE_FRAME_MAX);
    sign_as(&p->id, frame, len);
    return len;
}

// The node after the setup: the announces' signature checks and key agreements
// cost tens of milliseconds, most of a run, so each input starts from a copy.
static uint8_t s_snapshot[sizeof(s_arena)];
static size_t s_snapshot_used;
static ah_node_t *s_node;
static uint16_t s_links[LINKS];
static int64_t s_setup_end;

static void setup_node(void)
{
    static ah_identity_t id;
    static uint8_t announces[LINKS][AH_BLE_FRAME_MAX];
    size_t announce_len[LINKS];
    ah_test_random_seed(1);
    make_identity(&id, 0x21, "fuzz");
    make_identity(&s_peers[0].id, 0x31, "phone-a");
    make_identity(&s_peers[1].id, 0x41, "phone-b");
    make_identity(&s_peers[2].id, 0x51, "node-c");
    s_peers[2].is_node = true;
    for (size_t i = 0; i < LINKS; ++i) {
        announce_len[i] = build_announce(&s_peers[i], WALL0 + 1000u, announces[i]);
    }
    const ah_node_config_t cfg = {
        .links = 4,
        .queue_per_link = 8,
        .frame_buffers = 32,
        .peers = 16,
        .peer_pins = 16,
        .dedup_message_slots = 256,
        .dedup_fragment_slots = 256,
        .dedup_live_slots = 256,
        .sync = {.entries = {8, 16, 8, 8}, .bytes = {4096, 8192, 4096, 4096}, .declined = 8},
        .mail_slots = 4,
        .mail_bytes = 32768,
        .mail_per_depositor = 2,
        .mail_flash_bytes_per_hour = 512u * 1024u,
        .reassembly_slots = 2,
        .reassembly_bytes = 17408,
        .relay_slots = 16,
        .reply_backlog = 8,
        .verify_per_second = 1000,
        .inflate_bytes_per_second = (1u << 20),
        .inflate_window = AH_INFLATE_WINDOW_FULL,
        .trunk_announce_interval_ms = 300000,
        .big_send_bytes = 17408,
        .sessions = 2,
    };
    const ah_node_ops_t ops = {
        .write = write_stub,
        .mail_put = mail_put,
        .mail_delete = mail_delete,
        .alloc = arena_alloc,
    };
    s_node = ah_node_create(&cfg, &id, &ops, WALL0);
    if (s_node == NULL) {
        abort();
    }
    int64_t now = 1000;
    s_links[0] = ah_node_link_up(s_node, AH_LINK_BLE, 0, 512, NULL, now);
    s_links[1] = ah_node_link_up(s_node, AH_LINK_BLE, 1, 185, NULL, now);
    s_links[2] = ah_node_link_up(s_node, AH_LINK_LORA, 2, 512, s_peers[2].id.peer_id, now);
    for (size_t i = 0; i < LINKS; ++i) {
        ah_node_on_frame(s_node, s_links[i], announces[i], announce_len[i], now);
    }
    now += 1500;
    ah_node_tick(s_node, now);
    s_setup_end = now;
    s_snapshot_used = s_used;
    memcpy(s_snapshot, s_arena, s_used);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (s_node == NULL) {
        setup_node();
    }
    // The core allocates only at creation and keeps nothing outside its
    // memory, so restoring the arena restores the node. The random source
    // restarts too, so an input replayed alone runs as it did here.
    memcpy(s_arena, s_snapshot, s_snapshot_used);
    s_used = s_snapshot_used;
    memset(s_busy, 0, sizeof(s_busy));
    ah_test_random_seed(2);
    ah_node_t *n = s_node;
    const uint16_t *links = s_links;
    int64_t now = s_setup_end;

    static uint8_t frame[UINT16_MAX];
    size_t off = 0;
    while (size - off >= 3) {
        const uint8_t control = data[off];
        const size_t which = (size_t)(control & 0x03u) % LINKS;
        const size_t len = (size_t)data[off + 1] << 8 | data[off + 2];
        off += 3;
        if (len > size - off) {
            break;
        }
        if (control & FLAG_TRANSPORT) {
            const uint32_t handle = (uint32_t)which;
            s_busy[handle] = !s_busy[handle];
            if (!s_busy[handle]) {
                ah_node_link_ready(n, links[which], now);
            }
            off += len;
        } else {
            memcpy(frame, data + off, len);
            if ((control & FLAG_STAMP) && len >= AH_OFF_TIMESTAMP + 8u) {
                ah_put_be64(frame + AH_OFF_TIMESTAMP, WALL0 + (uint64_t)now);
            }
            if (control & FLAG_SIGN) {
                ah_frame_t view;
                if (ah_frame_parse(frame, len, &view)) {
                    memcpy((uint8_t *)view.sender, s_peers[which].id.peer_id, AH_PEER_ID_LEN);
                    sign_as(&s_peers[which].id, frame, len);
                }
            }
            ah_node_on_frame(n, links[which], frame, len, now);
            off += len;
        }
        now += 37;
        ah_node_tick(n, now);
    }
    // Let every timer the frames armed run out, the links free again.
    memset(s_busy, 0, sizeof(s_busy));
    for (size_t i = 0; i < LINKS; ++i) {
        ah_node_link_ready(n, links[i], now);
    }
    for (int i = 0; i < 20; ++i) {
        now += 1500;
        ah_node_tick(n, now);
    }
    return 0;
}
