// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Whole-node scenarios on a simulated mesh: the contract docs/PROTOCOL.md
// states, and the host-runnable parts of the docs/TESTING.md scenarios.
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ah_announce.h"
#include "ah_bytes.h"
#include "ah_clock.h"
#include "ah_courier_wire.h"
#include "ah_crypto.h"
#include "ah_dm_wire.h"
#include "ah_fragment.h"
#include "ah_frame.h"
#include "ah_gcs.h"
#include "ah_noise.h"
#include "ah_payload.h"
#include "ah_sync_wire.h"
#include "sim.h"
#include "unity.h"
#include "vectors.h"

static sim_world_t *w;
static ah_node_config_t cfg;

void setUp(void)
{
    w = calloc(1, sizeof(*w));
    sim_init(w, 0xA1B2C3D4u);
    cfg = sim_config();
}

void tearDown(void)
{
    sim_free(w);
    free(w);
}

// The node's peer ID, read off the announce a phone received from it.
static bool node_id_seen_by(int peer, uint8_t out[8])
{
    const sim_peer_t *p = &w->peers[peer];
    for (size_t i = 0; i < p->received; ++i) {
        ah_frame_t f;
        if (ah_frame_parse(p->inbox[i].bytes, p->inbox[i].len, &f) && f.type == AH_TYPE_ANNOUNCE &&
                f.ttl == AH_TTL_DEFAULT) {
            memcpy(out, f.sender, 8);
            return true;
        }
    }
    return false;
}

static void announce(int peer, int link)
{
    uint8_t frame[256];
    const size_t len = sim_announce(&w->peers[peer], sim_wall(w), frame, sizeof(frame));
    sim_peer_send(w, peer, link, frame, len);
}

// A node with two phones that cannot hear each other, both bound and the
// node's clock synced from them.
static int node_with_two(int *a, int *b, int *la, int *lb)
{
    const int n = sim_add_node(w, &cfg, "AirhopRelay-0001");
    *a = sim_add_peer(w, "alice");
    *b = sim_add_peer(w, "bob");
    *la = sim_connect_peer(w, n, *a, 512);
    *lb = sim_connect_peer(w, n, *b, 512);
    announce(*a, *la);
    announce(*b, *lb);
    sim_run(w, 2000);
    return n;
}

// The last frame of `type` the peer received from `sender` (anyone when NULL), parsed into `out`.
static const ah_frame_t *last_of(const sim_peer_t *p, uint8_t type, const uint8_t *sender, ah_frame_t *out,
                                 size_t *index)
{
    for (size_t i = p->received; i-- > 0;) {
        if (ah_frame_parse(p->inbox[i].bytes, p->inbox[i].len, out) && out->type == type &&
                (sender == NULL || memcmp(out->sender, sender, 8) == 0)) {
            if (index != NULL) {
                *index = i;
            }
            return out;
        }
    }
    return NULL;
}

// A signed request with an empty filter, so it holds nothing of `types`.
static void sync_request(int peer, int link, uint64_t types, uint8_t *frame, size_t *len)
{
    uint8_t payload[64];
    const ah_sync_request_t req = {.p = 7, .m = 1, .data = payload, .data_len = 0, .has_types = true,
                                   .types = types
                                  };
    const size_t plen = ah_sync_request_encode(&req, payload + 16, sizeof(payload) - 16);
    *len = sim_frame(&w->peers[peer], AH_TYPE_REQUEST_SYNC, 0, sim_wall(w), NULL, payload + 16, plen, true, frame, 256);
    sim_peer_send(w, peer, link, frame, *len);
}

// A signed voice packet of the burst whose stream ID is eight `stream_byte`s.
static size_t voice_packet(int peer, uint8_t stream_byte, uint16_t seq, uint8_t *frame)
{
    uint8_t body[40];
    memset(body, stream_byte, 8);
    body[8] = (uint8_t)(seq >> 8);
    body[9] = (uint8_t)seq;
    body[10] = seq == 0 ? 0x01 : 0x00;
    memset(body + 11, 0x44, sizeof(body) - 11u);
    return sim_frame(&w->peers[peer], AH_TYPE_VOICE_FRAME, 7, sim_wall(w), NULL, body, sizeof(body), true, frame, 256);
}

// An envelope for the holder of `noise_key`, tagged for the day `now` falls in.
static size_t make_envelope(const uint8_t noise_key[32], uint64_t now, uint64_t expiry, uint8_t *out)
{
    uint8_t tag[16];
    ah_courier_tag(noise_key, (uint32_t)(now / 86400000ull), tag);
    uint8_t ct[80];
    ah_random(ct, sizeof(ct));
    const ah_envelope_t env = {.tag = tag, .expiry_ms = expiry, .ciphertext = ct, .ciphertext_len = sizeof(ct),
                               .copies = 4
                              };
    return ah_envelope_encode(&env, out, 256);
}

// The envelopes a node holds in its simulated flash.
static int live_mail(int node)
{
    int n = 0;
    for (size_t i = 0; i < 16; ++i) {
        n += w->mail[node][i].live ? 1 : 0;
    }
    return n;
}

static size_t envelope_for(int recipient, size_t ct_len, uint8_t copies, uint8_t *out, size_t cap)
{
    const uint64_t now = sim_wall(w);
    uint8_t tag[16];
    ah_courier_tag(w->peers[recipient].id.noise_public, (uint32_t)(now / 86400000ull), tag);
    static uint8_t ct[AH_COURIER_MAX_CIPHERTEXT];
    ah_random(ct, ct_len);
    const ah_envelope_t env = {.tag = tag, .expiry_ms = now + 20 * 3600000ull, .ciphertext = ct,
                               .ciphertext_len = ct_len, .copies = copies
                              };
    return ah_envelope_encode(&env, out, cap);
}

// A deposit too long for one simulated write, handed to the node as its
// reassembled whole would be.
static void deposit_whole(int node, int link, int from, int to, size_t ct_len, uint8_t copies)
{
    static uint8_t env[AH_COURIER_MAX_CIPHERTEXT + 64];
    static uint8_t frame[AH_COURIER_MAX_CIPHERTEXT + 256];
    const size_t env_len = envelope_for(to, ct_len, copies, env, sizeof(env));
    const size_t len = sim_frame(&w->peers[from], AH_TYPE_COURIER_ENV, 7, sim_wall(w), w->node_ids[node].peer_id,
                                 env, env_len, true, frame, sizeof(frame));
    ah_node_on_frame(w->nodes[node], w->links[link].a_link, frame, len, w->now_ms);
    sim_run(w, 10);
}

// ---- relaying ----

static void test_relays_announce_and_message_byte_for_byte(void)
{
    int a;
    int b;
    int la;
    int lb;
    node_with_two(&a, &b, &la, &lb);
    ah_frame_t f;
    // Alice's announce reached Bob through the node, one hop down: a relay
    // never forwards an announce at TTL 7, or bitchat-ios binds the wrong link.
    TEST_ASSERT_NOT_NULL(last_of(&w->peers[b], AH_TYPE_ANNOUNCE, w->peers[a].id.peer_id, &f, NULL));
    TEST_ASSERT_EQUAL(6, f.ttl);

    uint8_t frame[256];
    const size_t len = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, "hello from alice", 7, sim_wall(w), frame,
                                   sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 500);
    size_t at = 0;
    TEST_ASSERT_NOT_NULL(last_of(&w->peers[b], AH_TYPE_CHANNEL_MSG, w->peers[a].id.peer_id, &f, &at));
    TEST_ASSERT_EQUAL(len, w->peers[b].inbox[at].len);
    TEST_ASSERT_EQUAL(6, w->peers[b].inbox[at].bytes[AH_OFF_TTL]);
    // Every byte but the TTL is the sender's own.
    TEST_ASSERT_EQUAL_MEMORY(frame, w->peers[b].inbox[at].bytes, AH_OFF_TTL);
    TEST_ASSERT_EQUAL_MEMORY(frame + 3, w->peers[b].inbox[at].bytes + 3, len - 3u);
    // And never back where it came from.
    TEST_ASSERT_EQUAL(-1, sim_find(&w->peers[a], AH_TYPE_CHANNEL_MSG, w->peers[a].id.peer_id));
}

static void test_never_relays_what_it_must_not(void)
{
    int a;
    int b;
    int la;
    int lb;
    node_with_two(&a, &b, &la, &lb);
    const size_t before = w->peers[b].received;
    uint8_t frame[256];
    const uint8_t text[] = "x";
    // TTL 1 ends here.
    size_t len = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, "ttl one", 1, sim_wall(w), frame, sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    // REQUEST_SYNC is link-local at any TTL.
    len = sim_frame(&w->peers[a], AH_TYPE_REQUEST_SYNC, 7, sim_wall(w), w->peers[b].id.peer_id, text, 1, true, frame,
                    sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    // Addressed to the node: it has arrived.
    sim_run(w, 1000);
    uint8_t node_id[8];
    TEST_ASSERT_TRUE(node_id_seen_by(a, node_id));
    len = sim_frame(&w->peers[a], AH_TYPE_NOISE_ENCRYPTED, 7, sim_wall(w), node_id, text, 1, false, frame,
                    sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 1000);
    for (size_t i = before; i < w->peers[b].received; ++i) {
        ah_frame_t f;
        TEST_ASSERT_TRUE(ah_frame_parse(w->peers[b].inbox[i].bytes, w->peers[b].inbox[i].len, &f));
        TEST_ASSERT_FALSE(f.type == AH_TYPE_CHANNEL_MSG && memcmp(f.sender, w->peers[a].id.peer_id, 8) == 0);
        TEST_ASSERT_FALSE(f.type == AH_TYPE_REQUEST_SYNC && memcmp(f.sender, w->peers[a].id.peer_id, 8) == 0);
        TEST_ASSERT_FALSE(f.type == AH_TYPE_NOISE_ENCRYPTED);
    }
}

static void test_relaying_needs_no_clock(void)
{
    // A node fresh from boot, before any phone has told it the time.
    const int n = sim_add_node(w, &cfg, "AirhopRelay-0003");
    const int a = sim_add_peer(w, "alice");
    const int b = sim_add_peer(w, "bob");
    const int la = sim_connect_peer(w, n, a, 512);
    sim_connect_peer(w, n, b, 512);
    uint8_t frame[256];
    const size_t len = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, "before the clock", 7, sim_wall(w), frame,
                                   sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 1000);
    ah_frame_t f;
    TEST_ASSERT_NOT_NULL(last_of(&w->peers[b], AH_TYPE_CHANNEL_MSG, w->peers[a].id.peer_id, &f, NULL));
    TEST_ASSERT_EQUAL(6, f.ttl);
}

static void test_leave_is_relayed_and_acted_on_only_when_verified(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    const uint16_t known = ah_node_stats(w->nodes[n])->peers_known;
    uint8_t frame[256];
    size_t len = sim_frame(&w->peers[a], AH_TYPE_LEAVE, 7, sim_wall(w), NULL, NULL, 0, true, frame, sizeof(frame));
    // A forged leave: Alice's, with her signature broken.
    uint8_t forged[256];
    memcpy(forged, frame, len);
    forged[len - 1] ^= 0x01;
    sim_peer_send(w, a, la, forged, len);
    sim_run(w, 1000);
    TEST_ASSERT_EQUAL(-1, sim_find(&w->peers[b], AH_TYPE_LEAVE, w->peers[a].id.peer_id));
    TEST_ASSERT_EQUAL(known, ah_node_stats(w->nodes[n])->peers_known);
    // The real one crosses, and the node forgets Alice.
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 1000);
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[b], AH_TYPE_LEAVE, w->peers[a].id.peer_id));
    TEST_ASSERT_EQUAL(known - 1u, ah_node_stats(w->nodes[n])->peers_known);
}

// A v2 directed frame with a source route spliced in after the recipient, as
// a bitchat client that plans routes would send it.
static size_t routed_frame(int from, const uint8_t recipient[8], const uint8_t *hops, uint8_t count, uint8_t *out,
                           size_t cap)
{
    uint8_t plain[128];
    const uint8_t body[] = "routed";
    const size_t len = sim_frame(&w->peers[from], AH_TYPE_NOISE_ENCRYPTED, 7, sim_wall(w), recipient, body,
                                 sizeof(body), false, plain, sizeof(plain));
    const size_t at = AH_V2_HEADER_LEN + 2u * AH_PEER_ID_LEN;
    const size_t route = 1u + (size_t)count * AH_PEER_ID_LEN;
    TEST_ASSERT_EQUAL(AH_VERSION_2, plain[AH_OFF_VERSION]);
    TEST_ASSERT_LESS_OR_EQUAL(cap, len + route);
    memcpy(out, plain, at);
    out[AH_OFF_FLAGS] |= AH_FLAG_HAS_ROUTE;
    out[at] = count;
    memcpy(out + at + 1, hops, (size_t)count * AH_PEER_ID_LEN);
    memcpy(out + at + route, plain + at, len - at);
    return len + route;
}

static void test_a_source_route_through_the_node_is_followed(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    const int d = sim_add_peer(w, "dave");
    const int ld = sim_connect_peer(w, n, d, 512);
    announce(d, ld);
    sim_run(w, 2000);
    uint8_t node_id[8];
    TEST_ASSERT_TRUE(node_id_seen_by(a, node_id));
    uint8_t carol[8];
    memset(carol, 0xC0, sizeof(carol));
    // Alice routes through the node, then Bob: only Bob gets it.
    uint8_t hops[16];
    memcpy(hops, node_id, 8);
    memcpy(hops + 8, w->peers[b].id.peer_id, 8);
    uint8_t frame[256];
    size_t len = routed_frame(a, carol, hops, 2, frame, sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 1000);
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[b], AH_TYPE_NOISE_ENCRYPTED, w->peers[a].id.peer_id));
    TEST_ASSERT_EQUAL(-1, sim_find(&w->peers[d], AH_TYPE_NOISE_ENCRYPTED, w->peers[a].id.peer_id));
    // A next hop the node cannot reach: it floods instead, and Dave hears it.
    memset(hops + 8, 0xEE, 8);
    len = routed_frame(a, carol, hops, 2, frame, sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 1000);
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[d], AH_TYPE_NOISE_ENCRYPTED, w->peers[a].id.peer_id));
}

static void test_unknown_and_airhop_types_cross_unread(void)
{
    int a;
    int b;
    int la;
    int lb;
    node_with_two(&a, &b, &la, &lb);
    uint8_t frame[256];
    const uint8_t body[] = {0x05, '#', 'c', 'i', 't', 'y', 0x02, 'm', '1', 0x00, 'h', 'i'};
    // Airhop's own types, types the node carries without reading, and one no
    // client has assigned, which goes out unsigned.
    const uint8_t types[] = {AH_TYPE_DR_ENCRYPTED,  AH_TYPE_CHANNEL_ENC,   AH_TYPE_CHANNEL_MSG_AIRHOP,
                             AH_TYPE_NOSTR_CARRIER, AH_TYPE_PREKEY_BUNDLE, 0x77
                            };
    for (size_t i = 0; i < sizeof(types); ++i) {
        const size_t len = sim_frame(&w->peers[a], types[i], 7, sim_wall(w), NULL, body, sizeof(body),
                                     types[i] != 0x77, frame, sizeof(frame));
        sim_peer_send(w, a, la, frame, len);
    }
    sim_run(w, 1000);
    for (size_t i = 0; i < sizeof(types); ++i) {
        TEST_ASSERT_NOT_EQUAL_MESSAGE(-1, sim_find(&w->peers[b], types[i], w->peers[a].id.peer_id), "not relayed");
    }
}

static void test_directed_goes_only_to_its_recipient(void)
{
    const int n = sim_add_node(w, &cfg, "AirhopRelay-0003");
    const int a = sim_add_peer(w, "alice");
    const int b = sim_add_peer(w, "bob");
    const int c = sim_add_peer(w, "carol");
    const int la = sim_connect_peer(w, n, a, 512);
    const int lb = sim_connect_peer(w, n, b, 512);
    const int lc = sim_connect_peer(w, n, c, 512);
    announce(a, la);
    announce(b, lb);
    announce(c, lc);
    sim_run(w, 2000);
    uint8_t frame[256];
    const uint8_t sealed[48] = {0};
    const size_t len = sim_frame(&w->peers[a], AH_TYPE_NOISE_ENCRYPTED, 7, sim_wall(w), w->peers[b].id.peer_id,
                                 sealed, sizeof(sealed), false, frame, sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 500);
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[b], AH_TYPE_NOISE_ENCRYPTED, w->peers[a].id.peer_id));
    TEST_ASSERT_EQUAL(-1, sim_find(&w->peers[c], AH_TYPE_NOISE_ENCRYPTED, w->peers[a].id.peer_id));
}

static void test_ring_of_three_forwards_each_packet_once(void)
{
    const int n0 = sim_add_node(w, &cfg, "relay-a");
    const int n1 = sim_add_node(w, &cfg, "relay-b");
    const int n2 = sim_add_node(w, &cfg, "relay-c");
    sim_connect_nodes(w, n0, n1, false, 512);
    sim_connect_nodes(w, n1, n2, false, 512);
    sim_connect_nodes(w, n2, n0, false, 512);
    const int a = sim_add_peer(w, "alice");
    const int b = sim_add_peer(w, "bob");
    const int la = sim_connect_peer(w, n0, a, 512);
    const int lb = sim_connect_peer(w, n2, b, 512);
    announce(a, la);
    announce(b, lb);
    sim_run(w, 3000);
    const ah_node_stats_t before[3] = {*ah_node_stats(w->nodes[0]), *ah_node_stats(w->nodes[1]),
                                       *ah_node_stats(w->nodes[2])
                                      };
    uint8_t frame[256];
    const size_t len = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, "round the ring", 7, sim_wall(w), frame,
                                   sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 2000);
    // Each node took one relay decision for it, however many copies it heard.
    for (int i = 0; i < 3; ++i) {
        TEST_ASSERT_EQUAL_MESSAGE(before[i].relayed + 1u, ah_node_stats(w->nodes[i])->relayed, "relayed once");
    }
    TEST_ASSERT_EQUAL(1, sim_count(&w->peers[b], AH_TYPE_CHANNEL_MSG, false));
}

static void test_small_mtu_and_malformed_floods_never_crash(void)
{
    const int n = sim_add_node(w, &cfg, "AirhopRelay-0004");
    const int a = sim_add_peer(w, "alice");
    const int b = sim_add_peer(w, "old-android");
    const int la = sim_connect_peer(w, n, a, 512);
    // ATT MTU 23: 20-byte writes, too small for even a fragment header.
    sim_connect_peer(w, n, b, 20);
    announce(a, la);
    sim_run(w, 2000);
    uint8_t frame[512];
    size_t len = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, "too big for that link", 7, sim_wall(w), frame,
                             sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    // A flood of junk, random lengths and bytes, every other one with a v1 or
    // v2 header's first bytes.
    for (int i = 0; i < 2000; ++i) {
        uint8_t junk[512];
        ah_random(junk, sizeof(junk));
        if (i % 2 == 0) {
            junk[0] = (uint8_t)(1 + (i / 2) % 2);
            junk[2] = 7;
        }
        sim_peer_send(w, a, la, junk, 1u + (size_t)(i * 37) % 511u);
        if (i % 50 == 0) {
            sim_run(w, 10);
        }
    }
    sim_run(w, 2000);
    TEST_ASSERT_GREATER_THAN(0, ah_node_stats(w->nodes[n])->rx_malformed);
    // The node is alive and still relaying.
    len = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, "still here", 7, sim_wall(w), frame, sizeof(frame));
    const int c = sim_add_peer(w, "carol");
    const int lc = sim_connect_peer(w, n, c, 512);
    announce(c, lc);
    sim_run(w, 500);
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 500);
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[c], AH_TYPE_CHANNEL_MSG, w->peers[a].id.peer_id));
}

static void test_live_voice_relays_once_and_never_replays(void)
{
    int a;
    int b;
    int la;
    int lb;
    node_with_two(&a, &b, &la, &lb);
    uint8_t frames[40][256];
    size_t lens[40];
    for (uint16_t i = 0; i < 40; ++i) {
        lens[i] = voice_packet(a, 0x33, i, frames[i]);
        sim_peer_send(w, a, la, frames[i], lens[i]);
        sim_run(w, 64);
    }
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(40, sim_count(&w->peers[b], AH_TYPE_VOICE_FRAME, false));
    // The same frames again inside the 150 s window: dropped as duplicates.
    sim_run(w, 60000);
    for (uint16_t i = 0; i < 40; ++i) {
        sim_peer_send(w, a, la, frames[i], lens[i]);
    }
    sim_run(w, 1000);
    TEST_ASSERT_EQUAL(40, sim_count(&w->peers[b], AH_TYPE_VOICE_FRAME, false));
}

static void test_fragments_relay_one_by_one(void)
{
    int a;
    int b;
    int la;
    int lb;
    node_with_two(&a, &b, &la, &lb);
    // A 3 KiB file from Alice, cut as a phone cuts it.
    static uint8_t file[3200];
    ah_random(file, sizeof(file));
    static uint8_t parent[4096];
    const size_t plen = sim_frame(&w->peers[a], AH_TYPE_FILE_TRANSFER, 7, sim_wall(w), NULL, file, sizeof(file), true,
                                  parent, sizeof(parent));
    ah_frame_t pf;
    TEST_ASSERT_TRUE(ah_frame_parse(parent, plen, &pf));
    ah_fragmenter_t cut;
    const uint8_t sid[8] = {7, 7, 7, 7, 7, 7, 7, 7};
    TEST_ASSERT_TRUE(ah_fragmenter_init(&cut, &pf, parent, plen, 512, sid));
    uint8_t piece[512];
    size_t pieces = 0;
    size_t len;
    while ((len = ah_fragmenter_next(&cut, piece, sizeof(piece))) > 0) {
        sim_peer_send(w, a, la, piece, len);
        sim_run(w, 30);
        pieces++;
    }
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(pieces, sim_count(&w->peers[b], AH_TYPE_FRAGMENT, false));
    // Never a reassembled whole.
    TEST_ASSERT_EQUAL(0, sim_count(&w->peers[b], AH_TYPE_FILE_TRANSFER, false));
    // Message dedup unaffected: a message after the file still crosses.
    uint8_t frame[256];
    len = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, "after the file", 7, sim_wall(w), frame, sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 500);
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[b], AH_TYPE_CHANNEL_MSG, w->peers[a].id.peer_id));
}

static void test_forged_board_posts_and_live_packets_never_cross(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    const int c = sim_add_peer(w, "carol");
    const int lc = sim_connect_peer(w, n, c, 512);
    announce(c, lc);
    sim_run(w, 1000);
    const uint32_t refused = ah_node_stats(w->nodes[n])->rx_refused;
    // A board post whose author signature verifies, and one altered after signing.
    const vec_board_t *genuine = &VEC_BOARDS[0];
    const vec_board_t *altered = &VEC_BOARDS[5];
    TEST_ASSERT_TRUE(genuine->check);
    TEST_ASSERT_FALSE(altered->check);
    uint8_t frame[512];
    size_t len = sim_frame(&w->peers[a], AH_TYPE_BOARD_POST, 7, sim_wall(w), NULL, altered->payload.data,
                           altered->payload.len, true, frame, sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    len = sim_frame(&w->peers[a], AH_TYPE_BOARD_POST, 7, sim_wall(w), NULL, genuine->payload.data,
                    genuine->payload.len, true, frame, sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(1, sim_count(&w->peers[b], AH_TYPE_BOARD_POST, false));
    ah_frame_t f;
    TEST_ASSERT_NOT_NULL(last_of(&w->peers[b], AH_TYPE_BOARD_POST, NULL, &f, NULL));
    TEST_ASSERT_EQUAL(genuine->payload.len, f.payload_len);
    TEST_ASSERT_EQUAL_MEMORY(genuine->payload.data, f.payload, f.payload_len);
    // A voice burst from Alice crosses; the first packet of a burst under her
    // name that she did not sign never does, nor anything after it.
    len = voice_packet(a, 0x77, 0, frame);
    sim_peer_send(w, a, la, frame, len);
    len = voice_packet(a, 0x99, 0, frame);
    frame[len - 1u] ^= 0x01u;
    sim_peer_send(w, c, lc, frame, len);
    sim_run(w, 300);
    len = voice_packet(a, 0x99, 1, frame);
    frame[len - 1u] ^= 0x01u;
    sim_peer_send(w, c, lc, frame, len);
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(1, sim_count(&w->peers[b], AH_TYPE_VOICE_FRAME, false));
    TEST_ASSERT_EQUAL(0, sim_count(&w->peers[a], AH_TYPE_VOICE_FRAME, false));
    TEST_ASSERT_EQUAL(refused + 3u, ah_node_stats(w->nodes[n])->rx_refused);
    // Nor does one riding Alice's verified burst from another link: her ID and
    // the burst's are in clear, but only her link's packets skip the check.
    for (uint16_t seq = 1; seq <= 3; ++seq) {
        len = voice_packet(a, 0x77, seq, frame);
        frame[len - 1u] ^= 0x01u;
        sim_peer_send(w, c, lc, frame, len);
        sim_run(w, 100);
    }
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(1, sim_count(&w->peers[b], AH_TYPE_VOICE_FRAME, false));
    TEST_ASSERT_EQUAL(refused + 6u, ah_node_stats(w->nodes[n])->rx_refused);
    // Nor from a newcomer that takes Alice's link once it is gone.
    sim_disconnect(w, la);
    const int d = sim_add_peer(w, "dave");
    const int ld = sim_connect_peer(w, n, d, 512);
    announce(d, ld);
    sim_run(w, 1000);
    len = voice_packet(a, 0x77, 4, frame);
    frame[len - 1u] ^= 0x01u;
    sim_peer_send(w, d, ld, frame, len);
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(1, sim_count(&w->peers[b], AH_TYPE_VOICE_FRAME, false));
}

static void test_a_stale_packet_is_relayed_but_never_acted_on(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    const uint32_t stored = ah_node_stats(w->nodes[n])->sync_stored;
    uint8_t frame[256];
    const size_t len = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, "ten minutes late", 7,
                                   sim_wall(w) - 10 * 60000ull, frame, sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 1000);
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[b], AH_TYPE_CHANNEL_MSG, w->peers[a].id.peer_id));
    TEST_ASSERT_EQUAL(stored, ah_node_stats(w->nodes[n])->sync_stored);
    TEST_ASSERT_EQUAL(1, ah_node_stats(w->nodes[n])->rx_stale);
}

static void test_fresh_pieces_of_a_stale_packet_are_never_acted_on(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    sim_run(w, 1000);
    const uint32_t stored = ah_node_stats(w->nodes[n])->sync_stored;
    const uint32_t stale = ah_node_stats(w->nodes[n])->rx_stale;
    // Ten minutes old, cut into pieces that each claim to be new (pieces are unsigned).
    uint8_t parent[256];
    const size_t plen = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, "ten minutes late, in pieces", 7,
                                    sim_wall(w) - 10 * 60000ull, parent, sizeof(parent));
    ah_frame_t pf;
    TEST_ASSERT_TRUE(ah_frame_parse(parent, plen, &pf));
    ah_fragmenter_t cut;
    const uint8_t sid[AH_FRAGMENT_STREAM_ID_LEN] = {9, 9, 9, 9, 9, 9, 9, 9};
    TEST_ASSERT_TRUE(ah_fragmenter_init(&cut, &pf, parent, plen, 110, sid));
    uint8_t piece[256];
    size_t len;
    while ((len = ah_fragmenter_next(&cut, piece, sizeof(piece))) > 0) {
        ah_put_be64(piece + AH_OFF_TIMESTAMP, sim_wall(w));
        sim_peer_send(w, a, la, piece, len);
    }
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(stored, ah_node_stats(w->nodes[n])->sync_stored);
    TEST_ASSERT_EQUAL(stale + 1u, ah_node_stats(w->nodes[n])->rx_stale);

    // The same with IS_RSR set inside: the flag is the sender's claim, and
    // pieces that came as no reply to a request of ours make it no reply.
    const size_t plen2 = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, "ten minutes late, claiming a reply", 7,
                                     sim_wall(w) - 10 * 60000ull, parent, sizeof(parent));
    parent[AH_OFF_FLAGS] |= AH_FLAG_IS_RSR;
    TEST_ASSERT_TRUE(ah_frame_parse(parent, plen2, &pf));
    const uint8_t sid2[AH_FRAGMENT_STREAM_ID_LEN] = {8, 8, 8, 8, 8, 8, 8, 8};
    TEST_ASSERT_TRUE(ah_fragmenter_init(&cut, &pf, parent, plen2, 110, sid2));
    while ((len = ah_fragmenter_next(&cut, piece, sizeof(piece))) > 0) {
        ah_put_be64(piece + AH_OFF_TIMESTAMP, sim_wall(w));
        piece[AH_OFF_FLAGS] &= (uint8_t)~AH_FLAG_IS_RSR;
        sim_peer_send(w, a, la, piece, len);
    }
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(stored, ah_node_stats(w->nodes[n])->sync_stored);
    TEST_ASSERT_EQUAL(stale + 2u, ah_node_stats(w->nodes[n])->rx_stale);
}

static void test_a_slow_packet_in_pieces_is_judged_from_its_first_piece(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    sim_run(w, 1000);
    const uint32_t stored = ah_node_stats(w->nodes[n])->sync_stored;
    // A fresh message cut into pieces stamped as it was cut, on a link so slow
    // the last piece arrives well past the two-minute window.
    char text[400];
    memset(text, 'x', sizeof(text) - 1u);
    text[sizeof(text) - 1u] = '\0';
    uint8_t parent[512];
    const size_t plen = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, text, 7, sim_wall(w), parent, sizeof(parent));
    ah_frame_t pf;
    TEST_ASSERT_TRUE(ah_frame_parse(parent, plen, &pf));
    ah_fragmenter_t cut;
    const uint8_t sid[AH_FRAGMENT_STREAM_ID_LEN] = {6, 6, 6, 6, 6, 6, 6, 6};
    TEST_ASSERT_TRUE(ah_fragmenter_init(&cut, &pf, parent, plen, 110, sid));
    uint8_t piece[256];
    size_t len;
    size_t pieces = 0;
    while ((len = ah_fragmenter_next(&cut, piece, sizeof(piece))) > 0) {
        sim_peer_send(w, a, la, piece, len);
        sim_run(w, 25000);
        pieces++;
    }
    // Six pieces or more, 25 s apart: over two minutes from the first to the last.
    TEST_ASSERT_GREATER_OR_EQUAL(6, pieces);
    // Kept: its pieces were taken as one stream, and the packet is dated from
    // no earlier than the first of them.
    TEST_ASSERT_EQUAL(stored + 1u, ah_node_stats(w->nodes[n])->sync_stored);
}

// ---- announces and links ----

static void test_node_announces_as_equipment_once_synced(void)
{
    int a;
    int b;
    int la;
    int lb;
    node_with_two(&a, &b, &la, &lb);
    sim_run(w, 1000);
    // The node's own announce: TTL 7, signed, 0xB1 bit 0, 0xB0 firmware version.
    const sim_peer_t *pa = &w->peers[a];
    bool found = false;
    for (size_t i = 0; i < pa->received && !found; ++i) {
        ah_frame_t g;
        if (!ah_frame_parse(pa->inbox[i].bytes, pa->inbox[i].len, &g) || g.type != AH_TYPE_ANNOUNCE ||
                g.ttl != 7) {
            continue;
        }
        ah_announce_t ann;
        TEST_ASSERT_TRUE(ah_announce_decode(g.payload, g.payload_len, &ann));
        TEST_ASSERT_TRUE(ah_announce_binds(g.sender, ann.noise_key));
        TEST_ASSERT_EQUAL_HEX8(AH_RELAY_FLAG_DEDICATED, ann.relay_flags);
        TEST_ASSERT_TRUE(ann.has_firmware);
        TEST_ASSERT_EQUAL(2, g.version);
        TEST_ASSERT_NOT_NULL(g.signature);
        TEST_ASSERT_UINT64_WITHIN(5000, sim_wall(w), g.timestamp_ms);
        found = true;
    }
    TEST_ASSERT_TRUE(found);
}

static void test_an_announce_too_big_for_a_new_link_is_tried_again(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    // Just after one of the node's rounds of announces, so the next is at least 11 s away.
    const size_t heard = sim_count_from(&w->peers[a], AH_TYPE_ANNOUNCE, w->node_ids[n].peer_id);
    for (int step = 0; step < 250 && sim_count_from(&w->peers[a], AH_TYPE_ANNOUNCE, w->node_ids[n].peer_id) == heard;
            ++step) {
        sim_run(w, 100);
    }
    // A phone whose MTU exchange lands a second after it connects.
    const int c = sim_add_peer(w, "carol");
    const int lc = sim_connect_peer(w, n, c, 20);
    sim_run(w, 1000);
    w->links[lc].max_write = 512;
    ah_node_link_mtu(w->nodes[n], w->links[lc].a_link, 512);
    sim_run(w, 2500);
    // The node's announce came within the retry, not the next round of announces.
    uint8_t node_id[8];
    TEST_ASSERT_TRUE(node_id_seen_by(c, node_id));
    TEST_ASSERT_EQUAL_MEMORY(w->node_ids[n].peer_id, node_id, AH_PEER_ID_LEN);
}

static void test_one_connection_is_one_peer_and_one_clock_voice(void)
{
    const int n = sim_add_node(w, &cfg, "AirhopRelay-0001");
    const int a = sim_add_peer(w, "alice");
    const int la = sim_connect_peer(w, n, a, 512);
    announce(a, la);
    sim_run(w, 500);
    // Over Alice's connection come announces for other identities, a day
    // ahead: none takes the link from her, and none moves the clock.
    for (int i = 0; i < 4; ++i) {
        const int m = sim_add_peer(w, "mallory");
        uint8_t frame[256];
        const size_t len = sim_announce(&w->peers[m], sim_wall(w) + 86400000ull, frame, sizeof(frame));
        sim_peer_send(w, m, la, frame, len);
        sim_run(w, 15000);
    }
    const uint8_t *bound = ah_node_link_peer(w->nodes[n], w->links[la].a_link);
    TEST_ASSERT_NOT_NULL(bound);
    TEST_ASSERT_EQUAL_MEMORY(w->peers[a].id.peer_id, bound, 8);
    uint64_t wall = 0;
    TEST_ASSERT_TRUE(ah_node_wall_time(w->nodes[n], w->now_ms, &wall));
    TEST_ASSERT_UINT64_WITHIN(AH_MAX_SKEW_MS, sim_wall(w), wall);
}

static void test_a_crowd_of_identities_never_evicts_a_linked_phone(void)
{
    cfg.peers = 4;
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    // Bob's phone relays announces of ten identities the node hears only
    // through him (TTL 6): the table is full, but Alice keeps her link.
    for (int i = 0; i < 10; ++i) {
        const int far = sim_add_peer(w, "far");
        uint8_t frame[256];
        const size_t len = sim_announce(&w->peers[far], sim_wall(w), frame, sizeof(frame));
        frame[AH_OFF_TTL] = 6; // as a relay forwards it
        sim_peer_send(w, b, lb, frame, len);
        sim_run(w, 100);
    }
    const uint8_t *bound = ah_node_link_peer(w->nodes[n], w->links[la].a_link);
    TEST_ASSERT_NOT_NULL(bound);
    TEST_ASSERT_EQUAL_MEMORY(w->peers[a].id.peer_id, bound, 8);
}

static void test_a_replayed_announce_never_takes_a_direct_link(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    const int c = sim_add_peer(w, "carol");
    const int lc = sim_connect_peer(w, n, c, 512);
    announce(c, lc);
    const int m = sim_add_peer(w, "mallory");
    const int lm = sim_connect_peer(w, n, m, 512);
    uint8_t frame[256];
    size_t len = sim_announce(&w->peers[a], sim_wall(w), frame, sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    // Past the dedup window, inside the announce window, Mallory replays
    // Alice's newest announce over her own link: it binds nothing.
    sim_run(w, 310000);
    sim_peer_send(w, m, lm, frame, len);
    sim_run(w, 500);
    TEST_ASSERT_NULL(ah_node_link_peer(w->nodes[n], w->links[lm].a_link));
    uint8_t sealed[48];
    ah_random(sealed, sizeof(sealed));
    uint8_t dm[256];
    size_t dm_len = sim_frame(&w->peers[b], AH_TYPE_NOISE_ENCRYPTED, 7, sim_wall(w), w->peers[a].id.peer_id, sealed,
                              sizeof(sealed), false, dm, sizeof(dm));
    sim_peer_send(w, b, lb, dm, dm_len);
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(1, sim_count(&w->peers[a], AH_TYPE_NOISE_ENCRYPTED, false));
    TEST_ASSERT_EQUAL(0, sim_count(&w->peers[m], AH_TYPE_NOISE_ENCRYPTED, false));

    // Alice's link drops, and Mallory repeats her latest announce inside the
    // dedup window: the repeat joins Mallory's link to Alice, but never as
    // her direct link, so Alice's traffic floods rather than going to Mallory alone.
    len = sim_announce(&w->peers[a], sim_wall(w), frame, sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 500);
    sim_disconnect(w, la);
    sim_run(w, 100);
    sim_peer_send(w, m, lm, frame, len);
    sim_run(w, 500);
    ah_random(sealed, sizeof(sealed));
    dm_len = sim_frame(&w->peers[b], AH_TYPE_NOISE_ENCRYPTED, 7, sim_wall(w), w->peers[a].id.peer_id, sealed,
                       sizeof(sealed), false, dm, sizeof(dm));
    sim_peer_send(w, b, lb, dm, dm_len);
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(1, sim_count(&w->peers[c], AH_TYPE_NOISE_ENCRYPTED, false));
}

static void test_a_dropped_link_hands_its_peer_to_no_other_link(void)
{
    const int n = sim_add_node(w, &cfg, "AirhopRelay-0005");
    const int a = sim_add_peer(w, "alice");
    const int b = sim_add_peer(w, "bob");
    const int c = sim_add_peer(w, "carol");
    const int la1 = sim_connect_peer(w, n, a, 512);
    const int la2 = sim_connect_peer(w, n, a, 512);
    const int lb = sim_connect_peer(w, n, b, 512);
    const int lc = sim_connect_peer(w, n, c, 512);
    // Alice's announce over her first link, and the same bytes over a second.
    uint8_t frame[256];
    size_t len = sim_announce(&w->peers[a], sim_wall(w), frame, sizeof(frame));
    sim_peer_send(w, a, la1, frame, len);
    sim_run(w, 50);
    sim_peer_send(w, a, la2, frame, len);
    announce(b, lb);
    announce(c, lc);
    sim_run(w, 2000);
    // Her first link drops: the second, bound only by the repeat, is not
    // trusted with her directed traffic, which floods instead.
    sim_disconnect(w, la1);
    sim_run(w, 100);
    uint8_t sealed[48];
    ah_random(sealed, sizeof(sealed));
    len = sim_frame(&w->peers[b], AH_TYPE_NOISE_ENCRYPTED, 7, sim_wall(w), w->peers[a].id.peer_id, sealed,
                    sizeof(sealed), false, frame, sizeof(frame));
    sim_peer_send(w, b, lb, frame, len);
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(1, sim_count(&w->peers[c], AH_TYPE_NOISE_ENCRYPTED, false));
    TEST_ASSERT_EQUAL(1, sim_count(&w->peers[a], AH_TYPE_NOISE_ENCRYPTED, false));
    // Her next direct announce over the second link makes it her direct link.
    announce(a, la2);
    sim_run(w, 500);
    ah_random(sealed, sizeof(sealed));
    len = sim_frame(&w->peers[b], AH_TYPE_NOISE_ENCRYPTED, 7, sim_wall(w), w->peers[a].id.peer_id, sealed,
                    sizeof(sealed), false, frame, sizeof(frame));
    sim_peer_send(w, b, lb, frame, len);
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(1, sim_count(&w->peers[c], AH_TYPE_NOISE_ENCRYPTED, false));
    TEST_ASSERT_EQUAL(2, sim_count(&w->peers[a], AH_TYPE_NOISE_ENCRYPTED, false));
}

static void test_a_peer_given_up_keeps_its_signing_key(void)
{
    cfg.peers = 4;
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    // Victor is heard through Bob's phone, then a crowd of fresh identities
    // through Bob pushes him out of the table.
    const int v = sim_add_peer(w, "victor");
    uint8_t frame[256];
    size_t len = sim_announce(&w->peers[v], sim_wall(w), frame, sizeof(frame));
    frame[AH_OFF_TTL] = 6;
    sim_peer_send(w, b, lb, frame, len);
    sim_run(w, 100);
    for (int i = 0; i < 4; ++i) {
        const int far = sim_add_peer(w, "far");
        len = sim_announce(&w->peers[far], sim_wall(w), frame, sizeof(frame));
        frame[AH_OFF_TTL] = 6;
        sim_peer_send(w, b, lb, frame, len);
        sim_run(w, 100);
    }
    TEST_ASSERT_GREATER_THAN(0, ah_node_stats(w->nodes[n])->peers_evicted);
    // Mallory announces Victor's public Noise key under her own signing key.
    const int m = sim_add_peer(w, "mallory");
    const int lm = sim_connect_peer(w, n, m, 512);
    memcpy(w->peers[m].id.noise_public, w->peers[v].id.noise_public, sizeof(w->peers[m].id.noise_public));
    memcpy(w->peers[m].id.peer_id, w->peers[v].id.peer_id, AH_PEER_ID_LEN);
    uint32_t refused = ah_node_stats(w->nodes[n])->rx_refused;
    len = sim_announce(&w->peers[m], sim_wall(w), frame, sizeof(frame));
    frame[AH_OFF_TTL] = 6;
    sim_peer_send(w, m, lm, frame, len);
    sim_run(w, 100);
    TEST_ASSERT_EQUAL(refused + 1u, ah_node_stats(w->nodes[n])->rx_refused);
    // Victor's own announce is welcome back, and his leave crosses.
    len = sim_announce(&w->peers[v], sim_wall(w), frame, sizeof(frame));
    frame[AH_OFF_TTL] = 6;
    sim_peer_send(w, b, lb, frame, len);
    sim_run(w, 100);
    len = sim_frame(&w->peers[v], AH_TYPE_LEAVE, 6, sim_wall(w), NULL, NULL, 0, true, frame, sizeof(frame));
    sim_peer_send(w, b, lb, frame, len);
    sim_run(w, 500);
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[a], AH_TYPE_LEAVE, w->peers[v].id.peer_id));
    // A verified leave gives him up as well, and keeps his key too.
    refused = ah_node_stats(w->nodes[n])->rx_refused;
    len = sim_announce(&w->peers[m], sim_wall(w), frame, sizeof(frame));
    frame[AH_OFF_TTL] = 6;
    sim_peer_send(w, m, lm, frame, len);
    sim_run(w, 100);
    TEST_ASSERT_EQUAL(refused + 1u, ah_node_stats(w->nodes[n])->rx_refused);
}

// ---- the clock ----

static void test_nothing_time_checked_before_the_clock_syncs(void)
{
    const int n = sim_add_node(w, &cfg, "AirhopRelay-0002");
    const int a = sim_add_peer(w, "alice");
    const int la = sim_connect_peer(w, n, a, 512);
    sim_run(w, 5000);
    // No phone has spoken: the node cannot know the time, so it says nothing.
    TEST_ASSERT_EQUAL(0, w->peers[a].received);
    announce(a, la);
    sim_run(w, 5000);
    // One phone is tentative: still nothing of its own.
    TEST_ASSERT_EQUAL(-1, sim_find(&w->peers[a], AH_TYPE_ANNOUNCE, NULL));
    // The same phone, consistent across 30 s, confirms the time.
    for (int i = 0; i < 3; ++i) {
        sim_run(w, 15000);
        announce(a, la);
    }
    sim_run(w, 3000);
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[a], AH_TYPE_ANNOUNCE, NULL));
}

static void test_one_phone_on_two_connections_is_one_clock_voice(void)
{
    const int n = sim_add_node(w, &cfg, "AirhopRelay-0001");
    const int a = sim_add_peer(w, "alice");
    const int la1 = sim_connect_peer(w, n, a, 512);
    const int la2 = sim_connect_peer(w, n, a, 512);
    // Each announce reaches the node first over one link or the other, as a
    // dual-role connection's do: her clock agrees with itself, and that
    // confirms nothing.
    for (int i = 0; i < 6; ++i) {
        uint8_t frame[256];
        const size_t len = sim_announce(&w->peers[a], sim_wall(w), frame, sizeof(frame));
        sim_peer_send(w, a, i % 2 == 0 ? la1 : la2, frame, len);
        sim_run(w, 50);
        sim_peer_send(w, a, i % 2 == 0 ? la2 : la1, frame, len);
        sim_run(w, 15000);
    }
    TEST_ASSERT_EQUAL(AH_CLOCK_SYNCED, ah_node_stats(w->nodes[n])->clock_state);
    TEST_ASSERT_FALSE(ah_node_stats(w->nodes[n])->clock_confirmed);
}

static void test_a_lone_skewed_phone_never_destroys_mail_or_the_floor(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    sim_disconnect(w, lb);
    uint8_t env[256];
    const size_t env_len = make_envelope(w->peers[b].id.noise_public, sim_wall(w), sim_wall(w) + 20 * 3600000ull, env);
    uint8_t frame[512];
    size_t len = sim_frame(&w->peers[a], AH_TYPE_COURIER_ENV, 7, sim_wall(w), w->node_ids[n].peer_id, env, env_len,
                           true, frame, sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    // Two agreeing phones confirmed the time, so the floor is saved.
    sim_run(w, 11 * 60000);
    const uint64_t floor = w->saved_clock[n];
    TEST_ASSERT_UINT64_WITHIN(11 * 60000, sim_wall(w), floor);
    TEST_ASSERT_EQUAL(1, live_mail(n));

    // After a reboot the only phone around reads two days ahead.
    sim_disconnect(w, la);
    sim_reboot(w, n);
    const int m = sim_add_peer(w, "mallory");
    const int lm = sim_connect_peer(w, n, m, 512);
    for (int i = 0; i < 48; ++i) {
        len = sim_announce(&w->peers[m], sim_wall(w) + 2 * 86400000ull, frame, sizeof(frame));
        sim_peer_send(w, m, lm, frame, len);
        sim_run(w, 15000);
    }
    // It syncs the clock on its own word, but destroys nothing on it.
    TEST_ASSERT_EQUAL(AH_CLOCK_SYNCED, ah_node_stats(w->nodes[n])->clock_state);
    TEST_ASSERT_FALSE(ah_node_stats(w->nodes[n])->clock_confirmed);
    TEST_ASSERT_EQUAL(1, live_mail(n));
    // The floor climbs only by the time the node has run, never toward the
    // phone's two days ahead.
    TEST_ASSERT_TRUE(w->saved_clock[n] >= floor);
    TEST_ASSERT_TRUE(w->saved_clock[n] <= sim_wall(w));

    // So after the next reboot two honest phones sync it again.
    sim_disconnect(w, lm);
    sim_reboot(w, n);
    la = sim_connect_peer(w, n, a, 512);
    lb = sim_connect_peer(w, n, b, 512);
    announce(a, la);
    announce(b, lb);
    sim_run(w, 2000);
    uint64_t wall = 0;
    TEST_ASSERT_TRUE(ah_node_wall_time(w->nodes[n], w->now_ms, &wall));
    TEST_ASSERT_UINT64_WITHIN(AH_MAX_SKEW_MS, sim_wall(w), wall);
    TEST_ASSERT_TRUE(ah_node_stats(w->nodes[n])->clock_confirmed);
}

// A solar node that browns out every night with no two phones in reach never
// confirms its clock again, and the hold timer starts over at each boot; the
// floor, climbing by each boot's uptime, still expires the mail it holds.
static void test_mail_expires_across_reboots_with_no_two_phones(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    uint8_t env[256];
    const size_t env_len = make_envelope(w->peers[b].id.noise_public, sim_wall(w), sim_wall(w) + 20 * 3600000ull, env);
    uint8_t frame[512];
    const size_t len = sim_frame(&w->peers[a], AH_TYPE_COURIER_ENV, 7, sim_wall(w), w->node_ids[n].peer_id, env,
                                 env_len, true, frame, sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 2000);
    TEST_ASSERT_EQUAL(1, live_mail(n));
    sim_disconnect(w, la);
    sim_disconnect(w, lb);
    // Twelve hours up, then a power cut, three times over: 36 h in all.
    for (int night = 0; night < 3; ++night) {
        sim_run(w, 12 * 3600000);
        sim_reboot(w, n);
        TEST_ASSERT_FALSE(ah_node_stats(w->nodes[n])->clock_confirmed);
    }
    sim_run(w, 2000);
    TEST_ASSERT_EQUAL(0, live_mail(n));
    TEST_ASSERT_TRUE(w->saved_clock[n] <= sim_wall(w));
}

static void announce_at(int peer, int link, uint64_t ts_ms)
{
    uint8_t frame[256];
    const size_t len = sim_announce(&w->peers[peer], ts_ms, frame, sizeof(frame));
    sim_peer_send(w, peer, link, frame, len);
}

// A lone phone `skew_ms` off syncs the node on its own word, over 30 s.
static void lone_phone_syncs(int n, int peer, int link, int64_t skew_ms)
{
    for (int i = 0; i < 3; ++i) {
        announce_at(peer, link, (uint64_t)((int64_t)sim_wall(w) + skew_ms));
        sim_run(w, 16000);
    }
    TEST_ASSERT_EQUAL(AH_CLOCK_SYNCED, ah_node_stats(w->nodes[n])->clock_state);
    TEST_ASSERT_FALSE(ah_node_stats(w->nodes[n])->clock_confirmed);
}

static uint64_t node_wall(int n)
{
    uint64_t wall = 0;
    TEST_ASSERT_TRUE(ah_node_wall_time(w->nodes[n], w->now_ms, &wall));
    return wall;
}

static void test_two_honest_phones_outvote_a_skewed_first_one(void)
{
    const int n = sim_add_node(w, &cfg, "AirhopRelay-0001");
    const int s = sim_add_peer(w, "skewed");
    const int ls = sim_connect_peer(w, n, s, 512);
    lone_phone_syncs(n, s, ls, 3600000);
    // An hour off the node's time, the honest phones' announces are still
    // heard: they bind, and outvote the phone that stays.
    const int a = sim_add_peer(w, "alice");
    const int b = sim_add_peer(w, "bob");
    const int la = sim_connect_peer(w, n, a, 512);
    const int lb = sim_connect_peer(w, n, b, 512);
    announce(a, la);
    announce(b, lb);
    sim_run(w, 2000);
    TEST_ASSERT_NOT_NULL(ah_node_link_peer(w->nodes[n], w->links[la].a_link));
    TEST_ASSERT_NOT_NULL(ah_node_link_peer(w->nodes[n], w->links[lb].a_link));
    TEST_ASSERT_UINT64_WITHIN(AH_MAX_SKEW_MS, sim_wall(w), node_wall(n));
    TEST_ASSERT_TRUE(ah_node_stats(w->nodes[n])->clock_confirmed);
}

static void test_a_lone_honest_phone_takes_over_from_a_skewed_one_that_left(void)
{
    const int n = sim_add_node(w, &cfg, "AirhopRelay-0001");
    const int s = sim_add_peer(w, "skewed");
    const int ls = sim_connect_peer(w, n, s, 512);
    lone_phone_syncs(n, s, ls, -3600000);
    sim_disconnect(w, ls);
    // Once nothing backs the skewed time, the one phone in reach is followed,
    // as it would be after a reboot.
    const int h = sim_add_peer(w, "honest");
    const int lh = sim_connect_peer(w, n, h, 512);
    for (int i = 0; i < 48; ++i) {
        announce(h, lh);
        sim_run(w, 15000);
    }
    TEST_ASSERT_EQUAL(AH_CLOCK_SYNCED, ah_node_stats(w->nodes[n])->clock_state);
    TEST_ASSERT_UINT64_WITHIN(AH_MAX_SKEW_MS, sim_wall(w), node_wall(n));
    TEST_ASSERT_NOT_NULL(ah_node_link_peer(w->nodes[n], w->links[lh].a_link));
}

static void test_hostile_links_never_walk_the_clock_or_plant_a_future_floor(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    sim_disconnect(w, lb);
    uint8_t env[256];
    const size_t env_len = make_envelope(w->peers[b].id.noise_public, sim_wall(w), sim_wall(w) + 6 * 3600000ull, env);
    uint8_t frame[512];
    const size_t len = sim_frame(&w->peers[a], AH_TYPE_COURIER_ENV, 7, sim_wall(w), w->node_ids[n].peer_id, env,
                                 env_len, true, frame, sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 11 * 60000);
    sim_disconnect(w, la);
    TEST_ASSERT_TRUE(ah_node_stats(w->nodes[n])->clock_confirmed);
    TEST_ASSERT_EQUAL(1, live_mail(n));

    // With the honest phones gone, two hostile links agree on a time 14
    // minutes past the node's, inside the announce window, every 15 s.
    const int m1 = sim_add_peer(w, "mallory");
    const int m2 = sim_add_peer(w, "mallet");
    int lm1 = sim_connect_peer(w, n, m1, 512);
    int lm2 = sim_connect_peer(w, n, m2, 512);
    for (int i = 0; i < 60; ++i) {
        const uint64_t ahead = node_wall(n) + 14 * 60000ull;
        announce_at(m1, lm1, ahead);
        announce_at(m2, lm2, ahead);
        sim_run(w, 15000);
    }
    // A confirmed clock moves no faster than a crystal drifts.
    TEST_ASSERT_UINT64_WITHIN(5000, sim_wall(w), node_wall(n));
    TEST_ASSERT_EQUAL(1, live_mail(n));
    TEST_ASSERT_UINT64_WITHIN(11 * 60000, sim_wall(w), w->saved_clock[n]);
    TEST_ASSERT_TRUE(w->saved_clock[n] <= sim_wall(w));

    // After a reboot they reach the node before any honest phone and set its
    // time a day ahead. That time holds until the next reboot, but the floor
    // it saves is never later than the restored one plus the time since.
    sim_disconnect(w, lm1);
    sim_disconnect(w, lm2);
    sim_reboot(w, n);
    lm1 = sim_connect_peer(w, n, m1, 512);
    lm2 = sim_connect_peer(w, n, m2, 512);
    for (int i = 0; i < 48; ++i) {
        announce_at(m1, lm1, sim_wall(w) + 86400000ull);
        announce_at(m2, lm2, sim_wall(w) + 86400000ull);
        sim_run(w, 15000);
    }
    TEST_ASSERT_TRUE(ah_node_stats(w->nodes[n])->clock_confirmed);
    TEST_ASSERT_TRUE(w->saved_clock[n] <= sim_wall(w));

    // So after the next one, honest phones sync it again.
    sim_disconnect(w, lm1);
    sim_disconnect(w, lm2);
    sim_reboot(w, n);
    la = sim_connect_peer(w, n, a, 512);
    lb = sim_connect_peer(w, n, b, 512);
    announce(a, la);
    announce(b, lb);
    sim_run(w, 2000);
    TEST_ASSERT_UINT64_WITHIN(AH_MAX_SKEW_MS, sim_wall(w), node_wall(n));
    TEST_ASSERT_TRUE(ah_node_stats(w->nodes[n])->clock_confirmed);
}

static void test_an_unconfirmed_clock_never_prunes_history(void)
{
    const int n = sim_add_node(w, &cfg, "AirhopRelay-0001");
    const int p = sim_add_peer(w, "pat");
    int lp = sim_connect_peer(w, n, p, 512);
    lone_phone_syncs(n, p, lp, 0);
    uint8_t frame[256];
    size_t len = sim_message(&w->peers[p], AH_TYPE_CHANNEL_MSG, "kept for whoever comes", 7, sim_wall(w), frame,
                             sizeof(frame));
    sim_peer_send(w, p, lp, frame, len);
    sim_run(w, 1000);
    TEST_ASSERT_EQUAL(1, ah_node_stats(w->nodes[n])->sync_stored);
    sim_disconnect(w, lp);

    // A lone phone seven hours ahead takes the unconfirmed clock over: Pat's
    // message falls outside the window, but is not destroyed on its word.
    const int h = sim_add_peer(w, "hasty");
    const int lh = sim_connect_peer(w, n, h, 512);
    for (int i = 0; i < 44; ++i) {
        announce_at(h, lh, sim_wall(w) + 7 * 3600000ull);
        sim_run(w, 15000);
    }
    TEST_ASSERT_UINT64_WITHIN(AH_MAX_SKEW_MS, sim_wall(w) + 7 * 3600000ull, node_wall(n));
    sim_disconnect(w, lh);

    // Two honest phones bring it back, and a newcomer still gets the message.
    const int q = sim_add_peer(w, "quinn");
    lp = sim_connect_peer(w, n, p, 512);
    const int lq = sim_connect_peer(w, n, q, 512);
    announce(p, lp);
    announce(q, lq);
    sim_run(w, 2000);
    TEST_ASSERT_UINT64_WITHIN(AH_MAX_SKEW_MS, sim_wall(w), node_wall(n));
    const int c = sim_add_peer(w, "carol");
    const int lc = sim_connect_peer(w, n, c, 512);
    announce(c, lc);
    sim_run(w, 300);
    sync_request(c, lc, 1ull << AH_SYNC_BIT_MESSAGE, frame, &len);
    sim_run(w, 2000);
    TEST_ASSERT_EQUAL(1, sim_count_from(&w->peers[c], AH_TYPE_CHANNEL_MSG, w->peers[p].id.peer_id));
}

// ---- gossip sync ----

static void test_late_phone_catches_up_including_location_channels(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    sim_run(w, 3000);
    uint8_t frame[256];
    size_t len = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, "said while carol was away", 7, sim_wall(w), frame,
                             sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    const uint8_t body[] = {0x05, '#', 'c', 'i', 't', 'y', 0x02, 'm', '1', 0x00, 'l', 'o', 'c'};
    len = sim_frame(&w->peers[a], AH_TYPE_CHANNEL_MSG_AIRHOP, 7, sim_wall(w), NULL, body, sizeof(body), true, frame,
                    sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 2000);
    TEST_ASSERT_GREATER_OR_EQUAL(2, ah_node_stats(w->nodes[n])->sync_stored);

    // Carol arrives and asks with an empty filter for the message round.
    const int c = sim_add_peer(w, "carol");
    const int lc = sim_connect_peer(w, n, c, 512);
    announce(c, lc);
    sim_run(w, 300);
    const uint64_t message_round = (1ull << AH_SYNC_BIT_ANNOUNCE) | (1ull << AH_SYNC_BIT_MESSAGE) |
                                   (1ull << AH_SYNC_BIT_GROUP) | (1ull << AH_SYNC_BIT_CHANNEL_AIRHOP);
    sync_request(c, lc, message_round, frame, &len);
    sim_run(w, 2000);
    TEST_ASSERT_GREATER_OR_EQUAL(1, sim_count(&w->peers[c], AH_TYPE_CHANNEL_MSG, true));
    TEST_ASSERT_GREATER_OR_EQUAL(1, sim_count(&w->peers[c], AH_TYPE_CHANNEL_MSG_AIRHOP, true));
    // Alice's announce comes back too, so Carol can verify what Alice said.
    TEST_ASSERT_GREATER_OR_EQUAL(1, sim_count(&w->peers[c], AH_TYPE_ANNOUNCE, true));
    // Replies ride TTL 0 with IS_RSR, and still verify against Alice's key.
    ah_frame_t f;
    TEST_ASSERT_NOT_NULL(last_of(&w->peers[c], AH_TYPE_CHANNEL_MSG, w->peers[a].id.peer_id, &f, NULL));
    TEST_ASSERT_EQUAL(0, f.ttl);
    uint8_t pre[1024];
    size_t pre_len = 0;
    TEST_ASSERT_TRUE(ah_frame_signing_preimage(&f, pre, sizeof(pre), &pre_len));
    TEST_ASSERT_TRUE(ah_ed25519_verify(w->peers[a].id.signing_public, pre, pre_len, f.signature));
    // And the node asks Carol in the phones' rounds, its own typed request.
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[c], AH_TYPE_REQUEST_SYNC, NULL));
}

static void test_sync_answers_only_the_link_peer_and_is_rate_limited(void)
{
    int a;
    int b;
    int la;
    int lb;
    node_with_two(&a, &b, &la, &lb);
    sim_run(w, 1000);
    uint8_t frame[256];
    size_t len = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, "history", 7, sim_wall(w), frame, sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 500);
    // Bob's request over Alice's link is not Alice's: refused.
    sync_request(b, la, 1ull << AH_SYNC_BIT_MESSAGE, frame, &len);
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(0, sim_count(&w->peers[a], AH_TYPE_CHANNEL_MSG, true));
    // Bob, on his own link: eight answers per 30 s.
    for (int i = 0; i < 12; ++i) {
        sync_request(b, lb, 1ull << AH_SYNC_BIT_MESSAGE, frame, &len);
        sim_run(w, 100);
    }
    sim_run(w, 1000);
    TEST_ASSERT_EQUAL(8, sim_count(&w->peers[b], AH_TYPE_CHANNEL_MSG, true));
}

static void test_back_to_back_sync_requests_are_both_answered(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    uint8_t frame[256];
    for (int i = 0; i < 40; ++i) {
        char text[32];
        snprintf(text, sizeof(text), "history %d", i);
        const size_t len = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, text, 7, sim_wall(w), frame,
                                       sizeof(frame));
        sim_peer_send(w, a, la, frame, len);
        sim_run(w, 50);
    }
    const int c = sim_add_peer(w, "carol");
    const int lc = sim_connect_peer(w, n, c, 512);
    announce(c, lc);
    sim_run(w, 2000);
    const size_t before = sim_count(&w->peers[c], AH_TYPE_CHANNEL_MSG, true);
    // Carol's link drains slowly while she asks for the message round and the
    // board round back to back, as phones do.
    sim_throttle(w, lc, 5);
    size_t len;
    sync_request(c, lc, 1ull << AH_SYNC_BIT_MESSAGE, frame, &len);
    sync_request(c, lc, 1ull << AH_SYNC_BIT_BOARD, frame, &len);
    sim_run(w, 500);
    sim_release(w, lc);
    sim_run(w, 2000);
    TEST_ASSERT_EQUAL(40, sim_count(&w->peers[c], AH_TYPE_CHANNEL_MSG, true) - before);
}

static void test_a_stalled_reply_resumes_on_its_own(void)
{
    cfg.frame_buffers = 24;
    cfg.queue_per_link = 12;
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    uint8_t frame[256];
    for (int i = 0; i < 10; ++i) {
        char text[32];
        snprintf(text, sizeof(text), "history %d", i);
        const size_t len = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, text, 7, sim_wall(w), frame,
                                       sizeof(frame));
        sim_peer_send(w, a, la, frame, len);
        sim_run(w, 50);
    }
    int stalled[3];
    for (int s = 0; s < 3; ++s) {
        const int p = sim_add_peer(w, "stalled");
        stalled[s] = sim_connect_peer(w, n, p, 512);
        announce(p, stalled[s]);
    }
    const int c = sim_add_peer(w, "carol");
    const int lc = sim_connect_peer(w, n, c, 512);
    announce(c, lc);
    sim_run(w, 2000);
    // Three stalled links hold enough distinct DMs to leave the pool short.
    uint8_t sealed[48];
    for (int s = 0; s < 3; ++s) {
        sim_throttle(w, stalled[s], 0);
        for (int i = 0; i < 6; ++i) {
            ah_random(sealed, sizeof(sealed));
            const size_t len = sim_frame(&w->peers[a], AH_TYPE_NOISE_ENCRYPTED, 7, sim_wall(w),
                                         w->peers[w->links[stalled[s]].b_peer].id.peer_id, sealed, sizeof(sealed),
                                         false, frame, sizeof(frame));
            sim_peer_send(w, a, la, frame, len);
            sim_run(w, 50);
        }
    }
    size_t len;
    sync_request(c, lc, 1ull << AH_SYNC_BIT_MESSAGE, frame, &len);
    sim_run(w, 300);
    TEST_ASSERT_EQUAL(0, sim_count(&w->peers[c], AH_TYPE_CHANNEL_MSG, true));
    // The stalled links drain; Carol's reply goes on with nothing new for her.
    for (int s = 0; s < 3; ++s) {
        sim_release(w, stalled[s]);
    }
    sim_run(w, 1500);
    TEST_ASSERT_EQUAL(10, sim_count(&w->peers[c], AH_TYPE_CHANNEL_MSG, true));
}

static void test_a_sync_burst_past_the_verify_budget_is_offered_again(void)
{
    cfg.verify_per_second = 40;
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    const int c = sim_add_peer(w, "carol");
    const int lc = sim_connect_peer(w, n, c, 512);
    announce(c, lc);
    sim_run(w, 2000);
    // Carol answers the node's rounds with a hundred messages it lacks, all
    // at once, as a phone holding history does after the node rebooted.
    static uint8_t replies[100][256];
    size_t lens[100];
    for (int i = 0; i < 100; ++i) {
        char text[32];
        snprintf(text, sizeof(text), "history %d", i);
        lens[i] = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, text, 7, sim_wall(w) - 3600000ull + (uint64_t)i,
                              replies[i], sizeof(replies[i]));
        replies[i][AH_OFF_TTL] = 0;
        replies[i][AH_OFF_FLAGS] |= AH_FLAG_IS_RSR;
    }
    const uint32_t before = ah_node_stats(w->nodes[n])->sync_stored;
    for (int i = 0; i < 100; ++i) {
        sim_peer_send(w, c, lc, replies[i], lens[i]);
    }
    sim_run(w, 10);
    // In the same second, after them, Alice starts a voice burst: the check
    // before its relay still finds budget, which the history could not take.
    uint8_t voice[256];
    const size_t vlen = voice_packet(a, 0x33, 0, voice);
    sim_peer_send(w, a, la, voice, vlen);
    sim_run(w, 100);
    TEST_ASSERT_LESS_THAN(100, ah_node_stats(w->nodes[n])->sync_stored - before);
    TEST_ASSERT_GREATER_THAN(0, ah_node_stats(w->nodes[n])->verify_skipped);
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[b], AH_TYPE_VOICE_FRAME, w->peers[a].id.peer_id));
    // What was put off is neither declined nor recorded, so the next rounds
    // take it.
    for (int round = 0; round < 4; ++round) {
        sim_run(w, 15000);
        for (int i = 0; i < 100; ++i) {
            sim_peer_send(w, c, lc, replies[i], lens[i]);
        }
        sim_run(w, 100);
    }
    TEST_ASSERT_EQUAL(100, ah_node_stats(w->nodes[n])->sync_stored - before);
}

static void test_a_message_relayed_but_not_kept_is_kept_from_a_sync_reply(void)
{
    cfg.verify_per_second = 8;
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    sim_run(w, 3000);
    const uint32_t before = ah_node_stats(w->nodes[n])->sync_stored;
    // Twenty messages from Alice at once: every one is relayed, since that
    // takes no check, but the checks that would keep them run out.
    static uint8_t msgs[20][256];
    size_t lens[20];
    for (int i = 0; i < 20; ++i) {
        char text[32];
        snprintf(text, sizeof(text), "said at once %d", i);
        lens[i] = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, text, 7, sim_wall(w) + (uint64_t)i, msgs[i],
                              sizeof(msgs[i]));
        sim_peer_send(w, a, la, msgs[i], lens[i]);
    }
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(20, sim_count_from(&w->peers[b], AH_TYPE_CHANNEL_MSG, w->peers[a].id.peer_id));
    TEST_ASSERT_LESS_THAN(20, ah_node_stats(w->nodes[n])->sync_stored - before);
    // Alice answers the node's next rounds with them: copies of what it
    // relayed, kept now, and never relayed again.
    for (int i = 0; i < 20; ++i) {
        msgs[i][AH_OFF_TTL] = 0;
        msgs[i][AH_OFF_FLAGS] |= AH_FLAG_IS_RSR;
    }
    for (int round = 0; round < 6; ++round) {
        sim_run(w, 15000);
        for (int i = 0; i < 20; ++i) {
            sim_peer_send(w, a, la, msgs[i], lens[i]);
        }
        sim_run(w, 100);
    }
    TEST_ASSERT_EQUAL(20, ah_node_stats(w->nodes[n])->sync_stored - before);
    TEST_ASSERT_EQUAL(20, sim_count_from(&w->peers[b], AH_TYPE_CHANNEL_MSG, w->peers[a].id.peer_id));
}

static void test_a_forged_sync_reply_never_hides_the_genuine_message(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    const int c = sim_add_peer(w, "carol");
    const int lc = sim_connect_peer(w, n, c, 512);
    announce(c, lc);
    sim_run(w, 2000);
    // An hour-old message of Alice's, as history in a sync reply, and Carol's
    // copy with its signature broken. The packet ID does not cover the
    // signature, so both copies share it.
    uint8_t genuine[256];
    const size_t len = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, "history", 7, sim_wall(w) - 3600000ull, genuine,
                                   sizeof(genuine));
    genuine[AH_OFF_TTL] = 0;
    genuine[AH_OFF_FLAGS] |= AH_FLAG_IS_RSR;
    uint8_t forged[256];
    memcpy(forged, genuine, len);
    ah_frame_t view;
    TEST_ASSERT_TRUE(ah_frame_parse(forged, len, &view));
    TEST_ASSERT_NOT_NULL(view.signature);
    forged[view.signature - forged] ^= 0x01u;
    uint8_t id[AH_PACKET_ID_LEN];
    TEST_ASSERT_TRUE(ah_packet_id(&view, NULL, id));
    const uint32_t before = ah_node_stats(w->nodes[n])->sync_stored;
    sim_peer_send(w, c, lc, forged, len);
    sim_run(w, 100);
    TEST_ASSERT_EQUAL(before, ah_node_stats(w->nodes[n])->sync_stored);
    // The node's next round does not claim the message: its filter, which
    // tells peers what not to send, leaves the ID out.
    const size_t seen = w->peers[a].received;
    sim_run(w, 15000);
    bool asked = false;
    for (size_t i = seen; i < w->peers[a].received; ++i) {
        ah_frame_t f;
        if (!ah_frame_parse(w->peers[a].inbox[i].bytes, w->peers[a].inbox[i].len, &f) ||
                f.type != AH_TYPE_REQUEST_SYNC || memcmp(f.sender, w->node_ids[n].peer_id, AH_PEER_ID_LEN) != 0) {
            continue;
        }
        uint8_t payload[1024];
        size_t plen = 0;
        ah_sync_request_t req;
        TEST_ASSERT_TRUE(ah_payload_decode(&f, NULL, payload, sizeof(payload), &plen));
        TEST_ASSERT_TRUE(ah_sync_request_decode(payload, plen, &req));
        if ((req.types & (1ull << AH_SYNC_BIT_MESSAGE)) == 0) {
            continue;
        }
        static uint32_t values[1024];
        const size_t count = ah_gcs_decode(req.p, req.m, req.data, req.data_len, values, 1024);
        TEST_ASSERT_FALSE(ah_gcs_contains(values, count, ah_gcs_bucket(ah_gcs_hash(id), req.m)));
        asked = true;
    }
    TEST_ASSERT_TRUE(asked);
    // The genuine copy in reply is kept: the forged one left its ID unseen.
    sim_peer_send(w, a, la, genuine, len);
    sim_run(w, 100);
    TEST_ASSERT_EQUAL(before + 1u, ah_node_stats(w->nodes[n])->sync_stored);
}

static void test_a_store_that_gave_up_room_asks_for_its_own_history_alone(void)
{
    cfg.sync.entries[AH_STORE_MESSAGE] = 4;
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    // Six messages into a store of four: it gives up the two oldest.
    uint8_t frame[256];
    for (int i = 0; i < 6; ++i) {
        char text[32];
        snprintf(text, sizeof(text), "message %d", i);
        const size_t len = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, text, 7, sim_wall(w) + (uint64_t)i, frame,
                                       sizeof(frame));
        sim_peer_send(w, a, la, frame, len);
    }
    sim_run(w, 500);
    const size_t seen = w->peers[b].received;
    sim_run(w, 15000);
    // The next round asks with that store's cursor only for what it holds,
    // and for announces and group messages with no cursor at all.
    bool messages_above_the_cursor = false;
    bool groups_from_the_start = false;
    for (size_t i = seen; i < w->peers[b].received; ++i) {
        ah_frame_t f;
        if (!ah_frame_parse(w->peers[b].inbox[i].bytes, w->peers[b].inbox[i].len, &f) ||
                f.type != AH_TYPE_REQUEST_SYNC || memcmp(f.sender, w->node_ids[n].peer_id, AH_PEER_ID_LEN) != 0) {
            continue;
        }
        uint8_t payload[1024];
        size_t plen = 0;
        ah_sync_request_t req;
        TEST_ASSERT_TRUE(ah_payload_decode(&f, NULL, payload, sizeof(payload), &plen));
        TEST_ASSERT_TRUE(ah_sync_request_decode(payload, plen, &req));
        if ((req.types & (1ull << AH_SYNC_BIT_MESSAGE)) != 0) {
            messages_above_the_cursor = req.has_since && (req.types & (1ull << AH_SYNC_BIT_GROUP)) == 0;
        }
        if ((req.types & (1ull << AH_SYNC_BIT_GROUP)) != 0) {
            groups_from_the_start = !req.has_since && (req.types & (1ull << AH_SYNC_BIT_ANNOUNCE)) != 0;
        }
    }
    TEST_ASSERT_TRUE(messages_above_the_cursor);
    TEST_ASSERT_TRUE(groups_from_the_start);
}

// ---- courier mail ----

// Answer the node's handshake as a phone would, with the same Noise code.
static bool phone_answers_handshake(int peer, int link, ah_noise_handshake_t *hs)
{
    ah_frame_t f;
    size_t at = 0;
    if (last_of(&w->peers[peer], AH_TYPE_NOISE_HANDSHAKE, NULL, &f, &at) == NULL ||
            f.payload_len != AH_NOISE_MSG1_LEN) {
        return false;
    }
    uint8_t seed[32];
    ah_random(seed, sizeof(seed));
    ah_noise_handshake_init(hs, false, w->peers[peer].id.noise_secret, w->peers[peer].id.noise_public, seed);
    uint8_t msg[128];
    if (!ah_noise_read(hs, f.payload, f.payload_len)) {
        return false;
    }
    const size_t len = ah_noise_write(hs, msg, sizeof(msg));
    uint8_t frame[256];
    const size_t flen = sim_frame(&w->peers[peer], AH_TYPE_NOISE_HANDSHAKE, 7, sim_wall(w), f.sender, msg, len, false,
                                  frame, sizeof(frame));
    sim_peer_send(w, peer, link, frame, flen);
    return true;
}

// Fragments a peer received whose inner type is `inner`: the pieces a cut of
// such a packet arrives as.
static size_t pieces_of(const sim_peer_t *p, uint8_t inner)
{
    size_t n = 0;
    for (size_t i = 0; i < p->received; ++i) {
        ah_frame_t f;
        if (ah_frame_parse(p->inbox[i].bytes, p->inbox[i].len, &f) && f.type == AH_TYPE_FRAGMENT &&
                f.payload_len > AH_FRAGMENT_HEADER_LEN && f.payload[AH_FRAGMENT_HEADER_LEN - 1u] == inner) {
            n++;
        }
    }
    return n;
}

static void test_mail_survives_a_reboot_and_is_handed_over(void)
{
    int a;
    int b;
    int la;
    int lb;
    int n = node_with_two(&a, &b, &la, &lb);
    sim_disconnect(w, lb);
    sim_run(w, 1000);
    // Alice leaves mail for Bob with the node.
    uint8_t env[256];
    const uint64_t now = sim_wall(w);
    const size_t env_len = make_envelope(w->peers[b].id.noise_public, now, now + 24 * 3600000ull, env);
    uint8_t frame[512];
    uint8_t node_id[8];
    TEST_ASSERT_TRUE(node_id_seen_by(a, node_id));
    size_t len = sim_frame(&w->peers[a], AH_TYPE_COURIER_ENV, 7, sim_wall(w), node_id, env, env_len, true, frame,
                           sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    // One past 25 h is refused, not clamped.
    uint8_t late[256];
    const size_t late_len = make_envelope(w->peers[b].id.noise_public, now, now + 25 * 3600000ull + 60000, late);
    len = sim_frame(&w->peers[a], AH_TYPE_COURIER_ENV, 7, sim_wall(w), node_id, late, late_len, true, frame,
                    sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 1000);
    TEST_ASSERT_EQUAL(1, ah_node_stats(w->nodes[n])->mail_stored);
    TEST_ASSERT_TRUE(w->mail[n][0].live);

    // Power cut: a fresh instance with the same identity restores the mail
    // from flash and must learn the time again before handing anything over.
    sim_run(w, 600000);
    sim_reboot(w, n);
    announce(a, la);
    sim_run(w, 500);

    // Bob comes back: with the clock agreed by two phones, the node floods
    // his mail at once and opens a Noise session to prove who he is.
    lb = sim_connect_peer(w, n, b, 512);
    announce(b, lb);
    sim_run(w, 1000);
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[b], AH_TYPE_COURIER_ENV, NULL));
    ah_noise_handshake_t hs;
    TEST_ASSERT_TRUE(phone_answers_handshake(b, lb, &hs));
    sim_run(w, 500);
    // msg3 completes Bob's side; the node, done on msg2, has handed over.
    ah_frame_t f;
    TEST_ASSERT_NOT_NULL(last_of(&w->peers[b], AH_TYPE_NOISE_HANDSHAKE, NULL, &f, NULL));
    TEST_ASSERT_TRUE(ah_noise_read(&hs, f.payload, f.payload_len));
    TEST_ASSERT_EQUAL(1, ah_node_stats(w->nodes[n])->mail_delivered);
    TEST_ASSERT_FALSE(w->mail[n][0].live);
    TEST_ASSERT_GREATER_OR_EQUAL(2, sim_count(&w->peers[b], AH_TYPE_COURIER_ENV, false));
    ah_envelope_t got;
    TEST_ASSERT_NOT_NULL(last_of(&w->peers[b], AH_TYPE_COURIER_ENV, NULL, &f, NULL));
    TEST_ASSERT_TRUE(ah_envelope_decode(f.payload, f.payload_len, &got));
    ah_envelope_t sent;
    ah_envelope_decode(env, env_len, &sent);
    TEST_ASSERT_EQUAL_MEMORY(sent.ciphertext, got.ciphertext, sent.ciphertext_len);
}

static void test_a_reused_link_inherits_no_proof(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    uint8_t node_id[8];
    TEST_ASSERT_TRUE(node_id_seen_by(a, node_id));
    sim_disconnect(w, lb);
    sim_run(w, 1000);
    uint8_t env[256];
    uint8_t frame[512];
    size_t env_len = make_envelope(w->peers[b].id.noise_public, sim_wall(w), sim_wall(w) + 3600000ull, env);
    size_t len = sim_frame(&w->peers[a], AH_TYPE_COURIER_ENV, 7, sim_wall(w), node_id, env, env_len, true, frame,
                           sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 500);

    // Bob proves himself on a new connection and takes his mail.
    const int lb2 = sim_connect_peer(w, n, b, 512);
    announce(b, lb2);
    sim_run(w, 1000);
    ah_noise_handshake_t hs;
    TEST_ASSERT_TRUE(phone_answers_handshake(b, lb2, &hs));
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(1, ah_node_stats(w->nodes[n])->mail_delivered);

    // Bob goes, more mail arrives for him, and Mallory takes the same link
    // slot replaying an announce Bob signed: she gets a handshake, never mail.
    sim_disconnect(w, lb2);
    sim_run(w, 1000);
    env_len = make_envelope(w->peers[b].id.noise_public, sim_wall(w), sim_wall(w) + 3600000ull, env);
    len = sim_frame(&w->peers[a], AH_TYPE_COURIER_ENV, 7, sim_wall(w), node_id, env, env_len, true, frame,
                    sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(2, ah_node_stats(w->nodes[n])->mail_stored);
    const int m = sim_add_peer(w, "mallory");
    const int lm = sim_connect_peer(w, n, m, 512);
    TEST_ASSERT_EQUAL(w->links[lb2].a_link, w->links[lm].a_link);
    len = sim_announce(&w->peers[b], sim_wall(w), frame, sizeof(frame));
    sim_peer_send(w, m, lm, frame, len);
    sim_run(w, 2000);
    TEST_ASSERT_EQUAL(1, ah_node_stats(w->nodes[n])->mail_delivered);
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[m], AH_TYPE_NOISE_HANDSHAKE, NULL));
}

static void test_a_depositor_at_its_quota_writes_no_more_flash(void)
{
    cfg.mail_per_depositor = 1;
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    sim_disconnect(w, lb);
    sim_run(w, 1000);
    for (int i = 0; i < 3; ++i) {
        uint8_t env[256];
        const size_t env_len = make_envelope(w->peers[b].id.noise_public, sim_wall(w), sim_wall(w) + 3600000ull, env);
        uint8_t frame[512];
        const size_t len = sim_frame(&w->peers[a], AH_TYPE_COURIER_ENV, 7, sim_wall(w), w->node_ids[n].peer_id, env,
                                     env_len, true, frame, sizeof(frame));
        sim_peer_send(w, a, la, frame, len);
        sim_run(w, 500);
    }
    // Alice is at her quota after the first: the others are refused and
    // written nowhere, so one depositor cannot spend the flash budget.
    TEST_ASSERT_EQUAL(1, ah_node_stats(w->nodes[n])->mail_stored);
    TEST_ASSERT_EQUAL(2, ah_node_stats(w->nodes[n])->mail_refused);
    TEST_ASSERT_EQUAL(1, live_mail(n));
    // The one taken comes back with a reboot, and nothing else.
    sim_reboot(w, n);
    sim_run(w, 1000);
    TEST_ASSERT_EQUAL(1, live_mail(n));
}

static void test_mail_is_sprayed_only_to_a_peer_that_proved_its_key(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    sim_disconnect(w, lb);
    sim_run(w, 1000);
    deposit_whole(n, la, a, b, 80, 4);
    // Mallory replays an announce Carol signed: she is offered a handshake she
    // cannot finish, and no copy.
    const int c = sim_add_peer(w, "carol");
    const int m = sim_add_peer(w, "mallory");
    const int lm = sim_connect_peer(w, n, m, 512);
    uint8_t frame[256];
    const size_t len = sim_announce(&w->peers[c], sim_wall(w), frame, sizeof(frame));
    sim_peer_send(w, m, lm, frame, len);
    sim_run(w, 1000);
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[m], AH_TYPE_NOISE_HANDSHAKE, NULL));
    TEST_ASSERT_EQUAL(0, sim_count(&w->peers[m], AH_TYPE_COURIER_ENV, false));
    // Carol herself comes by once that handshake has lapsed, and proves
    // herself: the copies were kept for her.
    sim_disconnect(w, lm);
    sim_run(w, 31000);
    const int lc = sim_connect_peer(w, n, c, 512);
    announce(c, lc);
    sim_run(w, 1000);
    TEST_ASSERT_EQUAL(0, sim_count(&w->peers[c], AH_TYPE_COURIER_ENV, false));
    ah_noise_handshake_t hs;
    TEST_ASSERT_TRUE(phone_answers_handshake(c, lc, &hs));
    sim_run(w, 1000);
    ah_frame_t f;
    TEST_ASSERT_NOT_NULL(last_of(&w->peers[c], AH_TYPE_COURIER_ENV, NULL, &f, NULL));
    ah_envelope_t got;
    TEST_ASSERT_TRUE(ah_envelope_decode(f.payload, f.payload_len, &got));
    TEST_ASSERT_EQUAL(2, got.copies);
}

static size_t msg1_count(int peer)
{
    size_t count = 0;
    for (size_t i = 0; i < w->peers[peer].received; ++i) {
        ah_frame_t f;
        if (ah_frame_parse(w->peers[peer].inbox[i].bytes, w->peers[peer].inbox[i].len, &f) &&
                f.type == AH_TYPE_NOISE_HANDSHAKE && f.payload_len == AH_NOISE_MSG1_LEN) {
            count++;
        }
    }
    return count;
}

static void test_a_session_on_a_phone_s_second_link_is_proof_too(void)
{
    // A phone on two connections answers the node's handshake over the one
    // the node did not use: the session is still proof, the spray goes, and
    // the node does not start over.
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    sim_disconnect(w, lb);
    sim_run(w, 1000);
    deposit_whole(n, la, a, b, 80, 4);
    const int c = sim_add_peer(w, "carol");
    const int lc1 = sim_connect_peer(w, n, c, 512);
    const int lc2 = sim_connect_peer(w, n, c, 512);
    uint8_t frame[256];
    const size_t len = sim_announce(&w->peers[c], sim_wall(w), frame, sizeof(frame));
    sim_peer_send(w, c, lc1, frame, len);
    sim_run(w, 50);
    sim_peer_send(w, c, lc2, frame, len);
    sim_run(w, 1000);
    ah_noise_handshake_t hs;
    size_t answered = 0;
    for (int t = 0; t < 60; ++t) {
        if (msg1_count(c) > answered) {
            answered = msg1_count(c);
            phone_answers_handshake(c, lc2, &hs);
        }
        sim_run(w, 1000);
    }
    TEST_ASSERT_EQUAL(1, msg1_count(c));
    TEST_ASSERT_EQUAL(1, sim_count(&w->peers[c], AH_TYPE_COURIER_ENV, false));
}

static void test_a_spray_that_could_not_go_is_tried_again(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    sim_disconnect(w, lb);
    sim_run(w, 1000);
    // Mail for Bob: one long envelope, cut into many pieces, and one short.
    deposit_whole(n, la, a, b, 12000, 4);
    deposit_whole(n, la, a, b, 80, 4);
    TEST_ASSERT_EQUAL(2, ah_node_stats(w->nodes[n])->mail_stored);
    // Carol comes by and proves herself, then her link slows: the long one's
    // cut stalls there, so the short one cannot go yet.
    const int c = sim_add_peer(w, "carol");
    const int lc = sim_connect_peer(w, n, c, 512);
    announce(c, lc);
    sim_run(w, 1000);
    sim_throttle(w, lc, 4);
    ah_noise_handshake_t hs;
    TEST_ASSERT_TRUE(phone_answers_handshake(c, lc, &hs));
    sim_run(w, 2000);
    TEST_ASSERT_EQUAL(0, sim_count(&w->peers[c], AH_TYPE_COURIER_ENV, false));
    sim_release(w, lc);
    sim_run(w, 3000);
    // Her next announce brings the short one, whole.
    announce(c, lc);
    sim_run(w, 2000);
    TEST_ASSERT_EQUAL(1, sim_count(&w->peers[c], AH_TYPE_COURIER_ENV, false));
    TEST_ASSERT_GREATER_THAN(0, pieces_of(&w->peers[c], AH_TYPE_COURIER_ENV));
}

static void test_a_stalled_cut_gives_way(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    sim_disconnect(w, lb);
    sim_run(w, 1000);
    deposit_whole(n, la, a, b, 12000, 4);
    // Carol proves herself, and her link stops taking writes with the cut of
    // a spray to her under way.
    const int c = sim_add_peer(w, "carol");
    const int lc = sim_connect_peer(w, n, c, 512);
    announce(c, lc);
    sim_run(w, 1000);
    sim_throttle(w, lc, 0);
    ah_noise_handshake_t hs;
    TEST_ASSERT_TRUE(phone_answers_handshake(c, lc, &hs));
    sim_run(w, 1000);
    const int d = sim_add_peer(w, "dave");
    const int ld = sim_connect_peer(w, n, d, 512);
    announce(d, ld);
    sim_run(w, 1000);
    TEST_ASSERT_TRUE(phone_answers_handshake(d, ld, &hs));
    sim_run(w, 1000);
    TEST_ASSERT_EQUAL(0, pieces_of(&w->peers[d], AH_TYPE_COURIER_ENV));
    // Once nothing has moved it for AH_LINK_STALE_MS, it no longer holds Dave up.
    sim_run(w, AH_LINK_STALE_MS + 2000);
    announce(d, ld);
    sim_run(w, 3000);
    TEST_ASSERT_GREATER_THAN(0, pieces_of(&w->peers[d], AH_TYPE_COURIER_ENV));
}

static void test_a_handover_that_lost_a_piece_keeps_the_mail(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    sim_disconnect(w, lb);
    sim_run(w, 1000);
    deposit_whole(n, la, a, b, 12000, 4);
    TEST_ASSERT_EQUAL(1, ah_node_stats(w->nodes[n])->mail_stored);
    const int lb2 = sim_connect_peer(w, n, b, 512);
    announce(b, lb2);
    sim_run(w, 2000);
    const size_t copy = pieces_of(&w->peers[b], AH_TYPE_COURIER_ENV);
    // Bob proves himself, and his link stalls once the handshake's last
    // message is out: the handover's cut fills his queue and waits.
    sim_throttle(w, lb2, 1);
    ah_noise_handshake_t hs;
    TEST_ASSERT_TRUE(phone_answers_handshake(b, lb2, &hs));
    sim_run(w, 100);
    // Two announces relayed to him fill the queue, and the second pushes out
    // a piece from the middle of the cut.
    for (int i = 0; i < 2; ++i) {
        announce(a, la);
        sim_run(w, 500);
    }
    const uint32_t dropped = ah_node_stats(w->nodes[n])->tx_dropped;
    TEST_ASSERT_GREATER_THAN(0, dropped);
    sim_release(w, lb2);
    sim_run(w, 2000);
    // The rest of the cut, the last piece with it, went: short of the pieces
    // of the copy he had before, Bob cannot rebuild it, so the node keeps it.
    const size_t got = pieces_of(&w->peers[b], AH_TYPE_COURIER_ENV) - copy;
    TEST_ASSERT_GREATER_THAN(copy / 2u, got);
    TEST_ASSERT_LESS_THAN(copy, got);
    TEST_ASSERT_EQUAL(0, ah_node_stats(w->nodes[n])->mail_delivered);
    TEST_ASSERT_EQUAL(1, live_mail(n));
    // Given up after a minute, the handover goes again whole on his next announces.
    sim_run(w, 61000);
    for (int i = 0; i < 2; ++i) {
        announce(b, lb2);
        sim_run(w, 2000);
    }
    TEST_ASSERT_EQUAL(1, ah_node_stats(w->nodes[n])->mail_delivered);
    TEST_ASSERT_EQUAL(0, live_mail(n));
}

static void test_a_deposit_put_off_for_budget_is_taken_from_its_next_copy(void)
{
    // Two signature checks a second, so three deposits at once cannot all be checked.
    cfg.verify_per_second = 2;
    const int n = sim_add_node(w, &cfg, "AirhopRelay-0001");
    const int a = sim_add_peer(w, "alice");
    const int b = sim_add_peer(w, "bob");
    const int la = sim_connect_peer(w, n, a, 512);
    const int lb = sim_connect_peer(w, n, b, 512);
    announce(a, la);
    sim_run(w, 1100);
    announce(b, lb);
    sim_run(w, 1100);
    sim_disconnect(w, lb);
    sim_run(w, 1100);
    uint8_t env[256];
    static uint8_t frames[3][512];
    size_t lens[3];
    for (int i = 0; i < 3; ++i) {
        const size_t env_len = make_envelope(w->peers[b].id.noise_public, sim_wall(w), sim_wall(w) + 3600000ull, env);
        lens[i] = sim_frame(&w->peers[a], AH_TYPE_COURIER_ENV, 7, sim_wall(w), w->node_ids[n].peer_id, env, env_len,
                            true, frames[i], sizeof(frames[i]));
    }
    for (int i = 0; i < 3; ++i) {
        sim_peer_send(w, a, la, frames[i], lens[i]);
    }
    sim_run(w, 1100);
    TEST_ASSERT_LESS_THAN(3, ah_node_stats(w->nodes[n])->mail_stored);
    // Nothing judged the one put off, so the same bytes again are no
    // duplicate; the others are, and cost nothing.
    for (int i = 0; i < 3; ++i) {
        sim_peer_send(w, a, la, frames[i], lens[i]);
    }
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(3, ah_node_stats(w->nodes[n])->mail_stored);
}

static void test_a_long_deposit_is_taken_while_a_cut_is_under_way(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    sim_disconnect(w, lb);
    sim_run(w, 1000);
    deposit_whole(n, la, a, b, 12000, 4);
    // Bob comes back on a link that stalls, so the copy of his mail the node
    // sends while he proves himself is a cut that stays under way.
    const int lb2 = sim_connect_peer(w, n, b, 512);
    sim_throttle(w, lb2, 2);
    announce(b, lb2);
    sim_run(w, 500);
    TEST_ASSERT_GREATER_THAN(0, pieces_of(&w->peers[b], AH_TYPE_COURIER_ENV));
    // Meanwhile Alice leaves a long envelope for Carol: its check needs no
    // buffer the cut is using.
    const int c = sim_add_peer(w, "carol");
    deposit_whole(n, la, a, c, 12000, 4);
    TEST_ASSERT_EQUAL(2, ah_node_stats(w->nodes[n])->mail_stored);
}

static void test_expired_mail_is_kept_but_never_sent_on(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    sim_disconnect(w, lb);
    sim_run(w, 1000);
    uint8_t env[256];
    const size_t env_len = make_envelope(w->peers[b].id.noise_public, sim_wall(w), sim_wall(w) + 3600000ull, env);
    uint8_t frame[512];
    const size_t len = sim_frame(&w->peers[a], AH_TYPE_COURIER_ENV, 7, sim_wall(w), w->node_ids[n].peer_id, env,
                                 env_len, true, frame, sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(1, live_mail(n));
    // A reboot, then half an hour with nobody about.
    sim_disconnect(w, la);
    sim_reboot(w, n);
    sim_run(w, 30 * 60000);
    // Bob alone comes back with his clock an hour fast. His word sets the
    // clock but never confirms it, so the mail is kept; and by that clock it
    // is past its expiry, so none of it goes to him.
    lb = sim_connect_peer(w, n, b, 512);
    for (int i = 0; i < 4; ++i) {
        announce_at(b, lb, sim_wall(w) + 3600000ull);
        sim_run(w, 15000);
    }
    TEST_ASSERT_EQUAL(AH_CLOCK_SYNCED, ah_node_stats(w->nodes[n])->clock_state);
    TEST_ASSERT_FALSE(ah_node_stats(w->nodes[n])->clock_confirmed);
    TEST_ASSERT_EQUAL(1, live_mail(n));
    // Once the floor plus the time the node has run is past the expiry, the
    // mail is surely expired whoever is about, and leaves flash.
    sim_run(w, 3600000);
    TEST_ASSERT_EQUAL(0, live_mail(n));
    TEST_ASSERT_EQUAL(0, sim_count(&w->peers[b], AH_TYPE_COURIER_ENV, false));
    TEST_ASSERT_EQUAL(0, pieces_of(&w->peers[b], AH_TYPE_COURIER_ENV));
}

// The spray budget of the one envelope a node holds in flash, or 0.
static uint8_t persisted_copies(int node)
{
    for (size_t i = 0; i < 16; ++i) {
        ah_envelope_t env;
        if (w->mail[node][i].live && ah_envelope_decode(w->mail[node][i].bytes, w->mail[node][i].len, &env)) {
            return env.copies;
        }
    }
    return 0;
}

static void test_a_changed_budget_is_written_back_so_a_reboot_mints_no_copies(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    sim_disconnect(w, lb);
    sim_run(w, 1000);
    // One envelope deposited twice, carry-only first, then with its budget.
    uint8_t tag[16];
    ah_courier_tag(w->peers[b].id.noise_public, (uint32_t)(sim_wall(w) / 86400000ull), tag);
    uint8_t ct[80];
    ah_random(ct, sizeof(ct));
    ah_envelope_t sealed = {.tag = tag, .expiry_ms = sim_wall(w) + 3600000ull, .ciphertext = ct,
                            .ciphertext_len = sizeof(ct), .copies = 1
                           };
    uint8_t env[256];
    uint8_t frame[512];
    for (uint8_t copies = 1; copies <= 4; copies += 3) {
        sealed.copies = copies;
        const size_t env_len = ah_envelope_encode(&sealed, env, sizeof(env));
        const size_t len = sim_frame(&w->peers[a], AH_TYPE_COURIER_ENV, 7, sim_wall(w), w->node_ids[n].peer_id, env,
                                     env_len, true, frame, sizeof(frame));
        sim_peer_send(w, a, la, frame, len);
        sim_run(w, 500);
    }
    TEST_ASSERT_EQUAL(1, live_mail(n));
    TEST_ASSERT_EQUAL(4, persisted_copies(n));
    // Carol proves herself and is sprayed half.
    const int c = sim_add_peer(w, "carol");
    const int lc = sim_connect_peer(w, n, c, 512);
    announce(c, lc);
    sim_run(w, 1000);
    ah_noise_handshake_t hs;
    TEST_ASSERT_TRUE(phone_answers_handshake(c, lc, &hs));
    sim_run(w, 1000);
    TEST_ASSERT_EQUAL(1, sim_count(&w->peers[c], AH_TYPE_COURIER_ENV, false));
    TEST_ASSERT_EQUAL(1, live_mail(n));
    TEST_ASSERT_EQUAL(2, persisted_copies(n));
    // After a reboot Dave is sprayed half of the two left, not of four.
    sim_disconnect(w, lc);
    sim_reboot(w, n);
    announce(a, la);
    sim_run(w, 500);
    const int d = sim_add_peer(w, "dave");
    const int ld = sim_connect_peer(w, n, d, 512);
    announce(d, ld);
    sim_run(w, 1000);
    TEST_ASSERT_TRUE(phone_answers_handshake(d, ld, &hs));
    sim_run(w, 1000);
    ah_frame_t f;
    TEST_ASSERT_NOT_NULL(last_of(&w->peers[d], AH_TYPE_COURIER_ENV, NULL, &f, NULL));
    ah_envelope_t got;
    TEST_ASSERT_TRUE(ah_envelope_decode(f.payload, f.payload_len, &got));
    TEST_ASSERT_EQUAL(1, got.copies);
}

static void test_the_mailbox_writes_flash_within_its_hourly_budget(void)
{
    uint8_t env[256];
    const uint8_t any_key[32] = {0};
    const size_t env_len = make_envelope(any_key, 0, 1, env);
    cfg.mail_flash_bytes_per_hour = 2u * ((uint32_t)env_len + AH_MAIL_RECORD_OVERHEAD);
    // One depositor's share is then the whole budget.
    cfg.mail_per_depositor = cfg.mail_slots;
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    sim_disconnect(w, lb);
    sim_run(w, 1000);
    uint8_t frame[512];
    for (int i = 0; i < 4; ++i) {
        if (i == 3) {
            // The next hour has a budget of its own.
            sim_run(w, 3600000);
        }
        make_envelope(w->peers[b].id.noise_public, sim_wall(w), sim_wall(w) + 20 * 3600000ull, env);
        const size_t len = sim_frame(&w->peers[a], AH_TYPE_COURIER_ENV, 7, sim_wall(w), w->node_ids[n].peer_id, env,
                                     env_len, true, frame, sizeof(frame));
        sim_peer_send(w, a, la, frame, len);
        sim_run(w, 500);
        TEST_ASSERT_EQUAL(i < 2 ? i + 1 : i, (int)ah_node_stats(w->nodes[n])->mail_stored);
    }
    TEST_ASSERT_EQUAL(1, ah_node_stats(w->nodes[n])->mail_refused);
    TEST_ASSERT_EQUAL(3, live_mail(n));
}

// A depositor whose mail expires as fast as it comes is held to its share of
// the hour's flash, so the next phone's deposit is still taken.
static void test_one_depositor_spends_only_its_share_of_the_flash_budget(void)
{
    uint8_t env[256];
    const uint8_t any_key[32] = {0};
    const size_t env_len = make_envelope(any_key, 0, 1, env);
    // Eight records an hour, a quarter of the slots each: two records a depositor.
    cfg.mail_flash_bytes_per_hour = 8u * ((uint32_t)env_len + AH_MAIL_RECORD_OVERHEAD);
    cfg.mail_per_depositor = cfg.mail_slots / 4u;
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    uint8_t frame[512];
    for (int i = 0; i < 6; ++i) {
        make_envelope(w->peers[b].id.noise_public, sim_wall(w), sim_wall(w) + 3000u, env);
        const size_t len = sim_frame(&w->peers[a], AH_TYPE_COURIER_ENV, 7, sim_wall(w), w->node_ids[n].peer_id, env,
                                     env_len, true, frame, sizeof(frame));
        sim_peer_send(w, a, la, frame, len);
        // Past its expiry: the slot is free again for the next.
        sim_run(w, 5000);
    }
    TEST_ASSERT_EQUAL(2, ah_node_stats(w->nodes[n])->mail_stored);
    make_envelope(w->peers[a].id.noise_public, sim_wall(w), sim_wall(w) + 20 * 3600000ull, env);
    const size_t len = sim_frame(&w->peers[b], AH_TYPE_COURIER_ENV, 7, sim_wall(w), w->node_ids[n].peer_id, env,
                                 env_len, true, frame, sizeof(frame));
    sim_peer_send(w, b, lb, frame, len);
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(3, ah_node_stats(w->nodes[n])->mail_stored);
}

// Raising an envelope's copies rewrites its record, so a rise spends the
// depositor's share as a new envelope does.
static void test_raising_an_envelope_s_copies_spends_the_depositor_s_share(void)
{
    uint8_t tag[16] = {0};
    uint8_t ct[80] = {0};
    ah_envelope_t e = {.tag = tag, .ciphertext = ct, .ciphertext_len = sizeof(ct), .copies = 2};
    uint8_t env[256];
    // A raised envelope carries its copies, a few bytes past one that has none.
    const size_t raised_len = ah_envelope_encode(&e, env, sizeof(env));
    // Eight records an hour, a quarter of the slots each: two records a depositor.
    cfg.mail_flash_bytes_per_hour = 8u * ((uint32_t)raised_len + AH_MAIL_RECORD_OVERHEAD);
    cfg.mail_per_depositor = cfg.mail_slots / 4u;
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    ah_courier_tag(w->peers[b].id.noise_public, (uint32_t)(sim_wall(w) / 86400000ull), tag);
    e.expiry_ms = sim_wall(w) + 20 * 3600000ull;
    uint8_t frame[512];
    for (uint8_t copies = 1; copies <= 4; ++copies) {
        e.copies = copies;
        const size_t env_len = ah_envelope_encode(&e, env, sizeof(env));
        const size_t len = sim_frame(&w->peers[a], AH_TYPE_COURIER_ENV, 7, sim_wall(w), w->node_ids[n].peer_id, env,
                                     env_len, true, frame, sizeof(frame));
        sim_peer_send(w, a, la, frame, len);
        sim_run(w, 500);
    }
    // The deposit and its first rise are both of Alice's share; the next two are refused.
    TEST_ASSERT_EQUAL(1, ah_node_stats(w->nodes[n])->mail_stored);
    TEST_ASSERT_EQUAL(2, ah_node_stats(w->nodes[n])->mail_refused);
}

// ---- DMs to the node ----

static void test_dm_to_the_node_gets_a_receipt_and_one_auto_reply(void)
{
    int a;
    int b;
    int la;
    int lb;
    node_with_two(&a, &b, &la, &lb);
    sim_run(w, 1000);
    uint8_t node_id[8];
    TEST_ASSERT_TRUE(node_id_seen_by(a, node_id));
    // Alice initiates, as bitchat-ios does to message someone.
    ah_noise_handshake_t hs;
    uint8_t seed[32];
    ah_random(seed, sizeof(seed));
    ah_noise_handshake_init(&hs, true, w->peers[a].id.noise_secret, w->peers[a].id.noise_public, seed);
    uint8_t msg[128];
    size_t mlen = ah_noise_write(&hs, msg, sizeof(msg));
    uint8_t frame[512];
    size_t len = sim_frame(&w->peers[a], AH_TYPE_NOISE_HANDSHAKE, 7, sim_wall(w), node_id, msg, mlen, false, frame,
                           sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 500);
    ah_frame_t f;
    TEST_ASSERT_NOT_NULL(last_of(&w->peers[a], AH_TYPE_NOISE_HANDSHAKE, node_id, &f, NULL));
    // The handshake frame is padded on air; its payload is the 96-byte msg2.
    TEST_ASSERT_EQUAL(AH_NOISE_MSG2_LEN, f.payload_len);
    TEST_ASSERT_TRUE(ah_noise_read(&hs, f.payload, f.payload_len));
    mlen = ah_noise_write(&hs, msg, sizeof(msg));
    len = sim_frame(&w->peers[a], AH_TYPE_NOISE_HANDSHAKE, 7, sim_wall(w), node_id, msg, mlen, false, frame,
                    sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    ah_noise_sender_t tx;
    ah_noise_receiver_t rx;
    uint8_t remote[32];
    TEST_ASSERT_TRUE(ah_noise_split(&hs, &tx, &rx, remote));
    sim_run(w, 300);

    for (int round = 0; round < 2; ++round) {
        uint8_t plain[64];
        const size_t plen = ah_private_message_encode((const uint8_t *)"m-1", 3, (const uint8_t *)"hi relay", 8, plain,
                                                      sizeof(plain));
        uint8_t sealed[128];
        const size_t slen = ah_noise_seal(&tx, plain, plen, sealed, sizeof(sealed));
        len = sim_frame(&w->peers[a], AH_TYPE_NOISE_ENCRYPTED, 7, sim_wall(w), node_id, sealed, slen, false, frame,
                        sizeof(frame));
        sim_peer_send(w, a, la, frame, len);
        sim_run(w, 500);
    }
    size_t receipts = 0;
    size_t replies = 0;
    for (size_t i = 0; i < w->peers[a].received; ++i) {
        ah_frame_t g;
        if (!ah_frame_parse(w->peers[a].inbox[i].bytes, w->peers[a].inbox[i].len, &g) ||
                g.type != AH_TYPE_NOISE_ENCRYPTED || memcmp(g.sender, node_id, 8) != 0) {
            continue;
        }
        uint8_t plain[700];
        const size_t plen = ah_noise_open(&rx, g.payload, g.payload_len, plain, sizeof(plain));
        TEST_ASSERT_NOT_EQUAL(SIZE_MAX, plen);
        if (plain[0] == AH_NOISE_PAYLOAD_DELIVERED) {
            receipts++;
            TEST_ASSERT_EQUAL_MEMORY("m-1", plain + 1, 3);
        } else if (plain[0] == AH_NOISE_PAYLOAD_PRIVATE_MESSAGE) {
            replies++;
            // The reply says what the node is, in plain words.
            ah_private_message_t pm;
            TEST_ASSERT_TRUE(ah_private_message_decode(plain + 1, plen - 1u, &pm));
            static const char expected[] = "This is an Airhop relay node, not a person. It carries messages for the "
                                           "people around it without reading them, and nobody here will see what "
                                           "you send.";
            TEST_ASSERT_EQUAL(sizeof(expected) - 1u, pm.content_len);
            TEST_ASSERT_EQUAL_MEMORY(expected, pm.content, pm.content_len);
        }
    }
    TEST_ASSERT_EQUAL(2, receipts);
    // Rate-limited: one auto-reply for two messages.
    TEST_ASSERT_EQUAL(1, replies);
}

// A frame from an identity no simulated peer holds.
static size_t frame_from(const ah_identity_t *id, uint8_t type, uint8_t ttl, uint64_t ts, const uint8_t *recipient,
                         const uint8_t *payload, size_t payload_len, uint8_t *out, size_t cap)
{
    static sim_peer_t as;
    as.id = *id;
    return sim_frame(&as, type, ttl, ts, recipient, payload, payload_len, false, out, cap);
}

static size_t frames_from_node(const sim_peer_t *p, int node, uint8_t type, size_t payload_len)
{
    size_t n = 0;
    for (size_t i = 0; i < p->received; ++i) {
        ah_frame_t f;
        if (ah_frame_parse(p->inbox[i].bytes, p->inbox[i].len, &f) && f.type == type &&
                memcmp(f.sender, w->node_ids[node].peer_id, AH_PEER_ID_LEN) == 0 && f.payload_len == payload_len) {
            n++;
        }
    }
    return n;
}

static void test_handshake_budgets_are_checked_before_either_is_spent(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    sim_run(w, 1000);
    ah_identity_t forged;
    sim_make_identity(&forged, "forged");
    uint8_t msg1[AH_NOISE_MSG1_LEN];
    uint8_t frame[256];
    // Eleven msg1 under one claimed ID: ten answered, the eleventh refused by
    // its own budget without spending the shared one.
    for (int i = 0; i < 11; ++i) {
        ah_random(msg1, sizeof(msg1));
        const size_t len = frame_from(&forged, AH_TYPE_NOISE_HANDSHAKE, 7, sim_wall(w) + (uint64_t)i,
                                      w->node_ids[n].peer_id, msg1, sizeof(msg1), frame, sizeof(frame));
        sim_peer_send(w, b, lb, frame, len);
        sim_run(w, 20);
    }
    // So twenty more claimed peers fill the 30 a minute exactly.
    for (int i = 0; i < 20; ++i) {
        sim_make_identity(&forged, "forged");
        ah_random(msg1, sizeof(msg1));
        const size_t len = frame_from(&forged, AH_TYPE_NOISE_HANDSHAKE, 7, sim_wall(w), w->node_ids[n].peer_id, msg1,
                                      sizeof(msg1), frame, sizeof(frame));
        sim_peer_send(w, b, lb, frame, len);
        sim_run(w, 20);
    }
    sim_run(w, 500);
    TEST_ASSERT_EQUAL(30, frames_from_node(&w->peers[a], n, AH_TYPE_NOISE_HANDSHAKE, AH_NOISE_MSG2_LEN));
}

static void test_sealed_traffic_without_a_session_is_charged_like_a_handshake(void)
{
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    sim_run(w, 1000);
    // Forty identities heard through Bob, then sealed traffic under each of
    // their names to the node, which holds no session with any.
    uint8_t frame[256];
    uint8_t sealed[48];
    for (int i = 0; i < 40; ++i) {
        static sim_peer_t far;
        sim_make_identity(&far.id, "far");
        size_t len = sim_announce(&far, sim_wall(w), frame, sizeof(frame));
        frame[AH_OFF_TTL] = 6;
        sim_peer_send(w, b, lb, frame, len);
        sim_run(w, 20);
        ah_random(sealed, sizeof(sealed));
        len = frame_from(&far.id, AH_TYPE_NOISE_ENCRYPTED, 7, sim_wall(w), w->node_ids[n].peer_id, sealed,
                         sizeof(sealed), frame, sizeof(frame));
        sim_peer_send(w, b, lb, frame, len);
        sim_run(w, 20);
    }
    sim_run(w, 500);
    // At most 30 a minute start a handshake, like inbound msg1.
    TEST_ASSERT_EQUAL(30, frames_from_node(&w->peers[a], n, AH_TYPE_NOISE_HANDSHAKE, AH_NOISE_MSG1_LEN));
}

// ---- the LoRa trunk ----

static void test_two_nodes_over_lora_carry_text_only(void)
{
    const int n0 = sim_add_node(w, &cfg, "relay-west");
    const int n1 = sim_add_node(w, &cfg, "relay-east");
    sim_connect_nodes(w, n0, n1, true, 512);
    const int a = sim_add_peer(w, "alice");
    const int b = sim_add_peer(w, "bob");
    const int a2 = sim_add_peer(w, "anna");
    const int b2 = sim_add_peer(w, "ben");
    const int la = sim_connect_peer(w, n0, a, 512);
    const int la2 = sim_connect_peer(w, n0, a2, 512);
    const int lb = sim_connect_peer(w, n1, b, 512);
    const int lb2 = sim_connect_peer(w, n1, b2, 512);
    announce(a, la);
    announce(a2, la2);
    announce(b, lb);
    announce(b2, lb2);
    sim_run(w, 5000);
    // The trunk link binds once each node has heard the other's announce; a
    // phone's next announce, 15 to 30 s on, is the one that crosses.
    sim_run(w, 15000);
    announce(a, la);
    sim_run(w, 10000);
    // Alice's announce crossed (within 60 s), and her message after it.
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[b], AH_TYPE_ANNOUNCE, w->peers[a].id.peer_id));
    uint8_t frame[512];
    size_t len = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, "across the trunk", 7, sim_wall(w), frame,
                             sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    // Live voice and a whole file never cross.
    len = voice_packet(a, 0x33, 1, frame);
    sim_peer_send(w, a, la, frame, len);
    uint8_t file[200];
    memset(file, 1, sizeof(file));
    len = sim_frame(&w->peers[a], AH_TYPE_FILE_TRANSFER, 7, sim_wall(w), NULL, file, sizeof(file), true, frame,
                    sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 10000);
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[b], AH_TYPE_CHANNEL_MSG, w->peers[a].id.peer_id));
    TEST_ASSERT_EQUAL(-1, sim_find(&w->peers[b], AH_TYPE_VOICE_FRAME, w->peers[a].id.peer_id));
    TEST_ASSERT_EQUAL(-1, sim_find(&w->peers[b], AH_TYPE_FILE_TRANSFER, w->peers[a].id.peer_id));
    // Anna, beside Alice, heard both directly through the node.
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[a2], AH_TYPE_VOICE_FRAME, w->peers[a].id.peer_id));
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[a2], AH_TYPE_FILE_TRANSFER, w->peers[a].id.peer_id));
    TEST_ASSERT_GREATER_THAN(0, ah_node_stats(w->nodes[n0])->trunk_refused);
    // Public messages under made-up senders, whose announce the node never
    // heard, would be dropped across the trunk: they spend no airtime there.
    ah_identity_t ghost;
    sim_make_identity(&ghost, "ghost");
    const int g = sim_add_peer(w, "ghost-carrier");
    const int lg = sim_connect_peer(w, n0, g, 512);
    static sim_peer_t forged;
    forged.id = ghost;
    for (int i = 0; i < 5; ++i) {
        len = sim_message(&forged, AH_TYPE_CHANNEL_MSG, "nobody can check this", 7, sim_wall(w) + (uint64_t)i, frame,
                          sizeof(frame));
        sim_peer_send(w, g, lg, frame, len);
        sim_run(w, 1000);
    }
    sim_run(w, 10000);
    TEST_ASSERT_EQUAL(-1, sim_find(&w->peers[b], AH_TYPE_CHANNEL_MSG, ghost.peer_id));
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[a2], AH_TYPE_CHANNEL_MSG, ghost.peer_id));
}

// Mail sprayed to a node beyond the trunk: a text-sized envelope crosses as
// one packet; one that needs a cut never does, since its pieces would take
// minutes of the duty budget the trunk's own policy keeps for text.
static void lora_spray(size_t ct_len, int *east_mail, int *pieces_on_trunk)
{
    const int n0 = sim_add_node(w, &cfg, "relay-west");
    const int n1 = sim_add_node(w, &cfg, "relay-east");
    const int trunk = sim_connect_nodes(w, n0, n1, true, 512);
    const int a = sim_add_peer(w, "alice");
    const int a2 = sim_add_peer(w, "anna");
    const int b = sim_add_peer(w, "bob");
    const int e1 = sim_add_peer(w, "erin");
    const int e2 = sim_add_peer(w, "ed");
    const int la = sim_connect_peer(w, n0, a, 512);
    const int la2 = sim_connect_peer(w, n0, a2, 512);
    const int le1 = sim_connect_peer(w, n1, e1, 512);
    const int le2 = sim_connect_peer(w, n1, e2, 512);
    announce(a, la);
    announce(a2, la2);
    announce(e1, le1);
    announce(e2, le2);
    sim_run(w, 20000);
    const size_t from = w->write_logged;
    deposit_whole(n0, la, a, b, ct_len, 4);
    sim_run(w, 12 * 60000);
    *east_mail = live_mail(n1);
    *pieces_on_trunk = 0;
    for (size_t i = from; i < w->write_logged; ++i) {
        const sim_write_t *e = &w->write_log[i];
        *pieces_on_trunk += e->node == n0 && e->link == trunk && e->type == AH_TYPE_FRAGMENT;
    }
}

static void test_mail_too_large_for_the_trunk_never_crosses_it(void)
{
    int east_mail;
    int pieces;
    lora_spray(80, &east_mail, &pieces);
    TEST_ASSERT_EQUAL(1, east_mail);
    TEST_ASSERT_EQUAL(0, pieces);
    tearDown();
    setUp();
    lora_spray(12000, &east_mail, &pieces);
    TEST_ASSERT_EQUAL(0, east_mail);
    TEST_ASSERT_EQUAL(0, pieces);
}

static void test_a_node_with_no_phones_carries_text_between_two_lora_nodes(void)
{
    const int na = sim_add_node(w, &cfg, "relay-west");
    const int nr = sim_add_node(w, &cfg, "relay-hill");
    const int nb = sim_add_node(w, &cfg, "relay-east");
    const int a1 = sim_add_peer(w, "alice");
    const int a2 = sim_add_peer(w, "anna");
    const int b1 = sim_add_peer(w, "bob");
    const int b2 = sim_add_peer(w, "ben");
    const int la1 = sim_connect_peer(w, na, a1, 512);
    const int la2 = sim_connect_peer(w, na, a2, 512);
    const int lb1 = sim_connect_peer(w, nb, b1, 512);
    const int lb2 = sim_connect_peer(w, nb, b2, 512);
    announce(a1, la1);
    announce(a2, la2);
    announce(b1, lb1);
    announce(b2, lb2);
    sim_run(w, 3000);
    // The hill node has no phone: only its neighbors' announces give it the time.
    const int ar = sim_connect_nodes(w, na, nr, true, 512);
    const int rb = sim_connect_nodes(w, nr, nb, true, 512);
    sim_run(w, 10000);
    const ah_node_stats_t *hill = ah_node_stats(w->nodes[nr]);
    TEST_ASSERT_EQUAL(AH_CLOCK_SYNCED, hill->clock_state);
    TEST_ASSERT_FALSE(hill->clock_confirmed);
    // It announced, so every trunk link bound, on both sides.
    const uint8_t *bound = ah_node_link_peer(w->nodes[na], w->links[ar].a_link);
    TEST_ASSERT_NOT_NULL(bound);
    TEST_ASSERT_EQUAL_MEMORY(w->node_ids[nr].peer_id, bound, AH_PEER_ID_LEN);
    bound = ah_node_link_peer(w->nodes[nb], w->links[rb].b_link);
    TEST_ASSERT_NOT_NULL(bound);
    TEST_ASSERT_EQUAL_MEMORY(w->node_ids[nr].peer_id, bound, AH_PEER_ID_LEN);
    TEST_ASSERT_NOT_NULL(ah_node_link_peer(w->nodes[nr], w->links[ar].b_link));
    TEST_ASSERT_NOT_NULL(ah_node_link_peer(w->nodes[nr], w->links[rb].a_link));
    // Alice announces again, now that the west node keeps announces.
    announce(a1, la1);
    sim_run(w, 2000);
    // And text crosses both hops, one TTL each.
    uint8_t frame[256];
    const size_t len = sim_message(&w->peers[a1], AH_TYPE_CHANNEL_MSG, "over the hill", 7, sim_wall(w), frame,
                                   sizeof(frame));
    sim_peer_send(w, a1, la1, frame, len);
    sim_run(w, 15000);
    ah_frame_t f;
    TEST_ASSERT_NOT_NULL(last_of(&w->peers[b1], AH_TYPE_CHANNEL_MSG, w->peers[a1].id.peer_id, &f, NULL));
    TEST_ASSERT_EQUAL(4, f.ttl);
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[b1], AH_TYPE_ANNOUNCE, w->peers[a1].id.peer_id));
}

// The first write a node made on a link after `from`, of `type` and `sender`, or -1.
static int write_at(int node, int link, uint8_t type, const uint8_t *sender, size_t from)
{
    for (size_t i = from; i < w->write_logged; ++i) {
        const sim_write_t *e = &w->write_log[i];
        if (e->node == node && e->link == link && e->type == type &&
                (sender == NULL || memcmp(e->sender, sender, AH_PEER_ID_LEN) == 0)) {
            return (int)i;
        }
    }
    return -1;
}

// Two nodes meeting over LoRa: the announce each sends as the link opens often
// arrives before the far node holds its key, so once the link binds it goes
// again rather than an announce interval later.
static void test_a_lora_link_announces_again_once_it_binds(void)
{
    const int n0 = sim_add_node(w, &cfg, "relay-west");
    const int n1 = sim_add_node(w, &cfg, "relay-east");
    const int a = sim_add_peer(w, "alice");
    const int a2 = sim_add_peer(w, "anna");
    const int b = sim_add_peer(w, "bob");
    const int b2 = sim_add_peer(w, "ben");
    announce(a, sim_connect_peer(w, n0, a, 512));
    announce(a2, sim_connect_peer(w, n0, a2, 512));
    announce(b, sim_connect_peer(w, n1, b, 512));
    announce(b2, sim_connect_peer(w, n1, b2, 512));
    sim_run(w, 3000);
    const int ab = sim_connect_nodes(w, n0, n1, true, 512);
    const size_t mark = w->write_logged;
    sim_run(w, 5000);
    const int first = write_at(n0, ab, AH_TYPE_ANNOUNCE, w->node_ids[n0].peer_id, mark);
    TEST_ASSERT_NOT_EQUAL(-1, first);
    TEST_ASSERT_NOT_EQUAL(-1, write_at(n0, ab, AH_TYPE_ANNOUNCE, w->node_ids[n0].peer_id, (size_t)first + 1u));
    TEST_ASSERT_NOT_NULL(ah_node_link_peer(w->nodes[n0], w->links[ab].a_link));
}

static void test_phone_presence_waits_behind_text_on_the_trunk(void)
{
    const int na = sim_add_node(w, &cfg, "relay-west");
    const int nb = sim_add_node(w, &cfg, "relay-east");
    const int a1 = sim_add_peer(w, "alice");
    const int a2 = sim_add_peer(w, "anna");
    const int b1 = sim_add_peer(w, "bob");
    const int b2 = sim_add_peer(w, "ben");
    const int la1 = sim_connect_peer(w, na, a1, 512);
    const int la2 = sim_connect_peer(w, na, a2, 512);
    const int lb1 = sim_connect_peer(w, nb, b1, 512);
    const int lb2 = sim_connect_peer(w, nb, b2, 512);
    announce(a1, la1);
    announce(a2, la2);
    announce(b1, lb1);
    announce(b2, lb2);
    sim_run(w, 3000);
    const int ab = sim_connect_nodes(w, na, nb, true, 512);
    sim_run(w, 5000);
    // The node's own announce goes first on the trunk.
    const int own = write_at(na, ab, AH_TYPE_ANNOUNCE, w->node_ids[na].peer_id, 0);
    TEST_ASSERT_NOT_EQUAL(-1, own);
    TEST_ASSERT_EQUAL(AH_PRIO_ANNOUNCE, w->write_log[own].prio);
    // Alice talks once, so her announce has crossed ahead of her. Her first
    // announce came before the clock synced, so the node kept none of hers
    // until this periodic one.
    announce(a1, la1);
    sim_run(w, 500);
    uint8_t frame[256];
    size_t len = sim_message(&w->peers[a1], AH_TYPE_CHANNEL_MSG, "first", 7, sim_wall(w), frame, sizeof(frame));
    sim_peer_send(w, a1, la1, frame, len);
    sim_run(w, 5000);

    // With the trunk busy, a new phone's announce and Alice's next message wait.
    sim_throttle(w, ab, 0);
    const int c = sim_add_peer(w, "carol");
    const int lc = sim_connect_peer(w, na, c, 512);
    announce(c, lc);
    sim_run(w, 500);
    len = sim_message(&w->peers[a1], AH_TYPE_CHANNEL_MSG, "second", 7, sim_wall(w), frame, sizeof(frame));
    sim_peer_send(w, a1, la1, frame, len);
    sim_run(w, 500);
    // A phone that speaks before its announce crossed takes it along, first.
    const int d = sim_add_peer(w, "dave");
    const int ld = sim_connect_peer(w, na, d, 512);
    announce(d, ld);
    len = sim_message(&w->peers[d], AH_TYPE_CHANNEL_MSG, "hello", 7, sim_wall(w), frame, sizeof(frame));
    sim_peer_send(w, d, ld, frame, len);
    sim_run(w, 500);
    const size_t mark = w->write_logged;
    sim_release(w, ab);
    sim_run(w, 2000);
    const int presence = write_at(na, ab, AH_TYPE_ANNOUNCE, w->peers[c].id.peer_id, mark);
    const int second = write_at(na, ab, AH_TYPE_CHANNEL_MSG, w->peers[a1].id.peer_id, mark);
    TEST_ASSERT_NOT_EQUAL(-1, presence);
    TEST_ASSERT_NOT_EQUAL(-1, second);
    TEST_ASSERT_EQUAL(AH_PRIO_PRESENCE, w->write_log[presence].prio);
    TEST_ASSERT_LESS_THAN(presence, second);
    const int ahead = write_at(na, ab, AH_TYPE_ANNOUNCE, w->peers[d].id.peer_id, mark);
    const int hello = write_at(na, ab, AH_TYPE_CHANNEL_MSG, w->peers[d].id.peer_id, mark);
    TEST_ASSERT_NOT_EQUAL(-1, ahead);
    TEST_ASSERT_NOT_EQUAL(-1, hello);
    TEST_ASSERT_EQUAL(AH_PRIO_ANNOUNCE, w->write_log[ahead].prio);
    TEST_ASSERT_LESS_THAN(hello, ahead);
    // Bob hears Dave's message, his key having come first.
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[b1], AH_TYPE_CHANNEL_MSG, w->peers[d].id.peer_id));
}

static void test_a_lora_link_binds_only_the_node_behind_it(void)
{
    const int na = sim_add_node(w, &cfg, "relay-west");
    const int nb = sim_add_node(w, &cfg, "relay-east");
    const int a1 = sim_add_peer(w, "alice");
    const int a2 = sim_add_peer(w, "anna");
    const int b1 = sim_add_peer(w, "bob");
    const int b2 = sim_add_peer(w, "ben");
    const int la1 = sim_connect_peer(w, na, a1, 512);
    const int la2 = sim_connect_peer(w, na, a2, 512);
    const int lb1 = sim_connect_peer(w, nb, b1, 512);
    const int lb2 = sim_connect_peer(w, nb, b2, 512);
    announce(a1, la1);
    announce(a2, la2);
    announce(b1, lb1);
    announce(b2, lb2);
    sim_run(w, 3000);
    const int ab = sim_connect_nodes(w, na, nb, true, 512);
    // Before the far node's own announce arrives, someone else's comes over
    // the trunk link at TTL 7.
    const int m = sim_add_peer(w, "mallory");
    uint8_t frame[256];
    const size_t len = sim_announce(&w->peers[m], sim_wall(w), frame, sizeof(frame));
    ah_node_on_frame(w->nodes[na], w->links[ab].a_link, frame, len, w->now_ms);
    TEST_ASSERT_NULL(ah_node_link_peer(w->nodes[na], w->links[ab].a_link));
    sim_run(w, 5000);
    const uint8_t *bound = ah_node_link_peer(w->nodes[na], w->links[ab].a_link);
    TEST_ASSERT_NOT_NULL(bound);
    TEST_ASSERT_EQUAL_MEMORY(w->node_ids[nb].peer_id, bound, AH_PEER_ID_LEN);
}

static void test_a_lora_link_never_binds_to_a_phone(void)
{
    // Whatever the trunk hands the mesh, a LoRa link is a node's: a neighbor
    // named as Alice sends her own announce, captured, at TTL 7.
    const int n = sim_add_node(w, &cfg, "relay-west");
    const int a = sim_add_peer(w, "alice");
    const uint16_t lora = ah_node_link_up(w->nodes[n], AH_LINK_LORA, 900, 512, w->peers[a].id.peer_id, w->now_ms);
    uint8_t frame[256];
    size_t len = sim_announce(&w->peers[a], sim_wall(w), frame, sizeof(frame));
    ah_node_on_frame(w->nodes[n], lora, frame, len, w->now_ms);
    TEST_ASSERT_NULL(ah_node_link_peer(w->nodes[n], lora));
    // Nor as a second link, with the same bytes Alice sent over Bluetooth.
    const int la = sim_connect_peer(w, n, a, 512);
    len = sim_announce(&w->peers[a], sim_wall(w) + 1000, frame, sizeof(frame));
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 100);
    TEST_ASSERT_NOT_NULL(ah_node_link_peer(w->nodes[n], w->links[la].a_link));
    const uint16_t again = ah_node_link_up(w->nodes[n], AH_LINK_LORA, 901, 512, w->peers[a].id.peer_id, w->now_ms);
    ah_node_on_frame(w->nodes[n], again, frame, len, w->now_ms);
    TEST_ASSERT_NULL(ah_node_link_peer(w->nodes[n], again));
}

// ---- buffers and budgets each link has a share of ----

static void test_a_compact_node_keeps_relaying_past_stalled_links(void)
{
    cfg.frame_buffers = 24;
    cfg.queue_per_link = 12;
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    const int s1 = sim_add_peer(w, "stalled-1");
    const int s2 = sim_add_peer(w, "stalled-2");
    const int ls1 = sim_connect_peer(w, n, s1, 512);
    const int ls2 = sim_connect_peer(w, n, s2, 512);
    announce(s1, ls1);
    announce(s2, ls2);
    sim_run(w, 2000);
    // Two phones that stop taking writes, each sent distinct DMs to hold.
    sim_throttle(w, ls1, 0);
    sim_throttle(w, ls2, 0);
    uint8_t sealed[48];
    uint8_t frame[256];
    for (int i = 0; i < 12; ++i) {
        ah_random(sealed, sizeof(sealed));
        size_t len = sim_frame(&w->peers[a], AH_TYPE_NOISE_ENCRYPTED, 7, sim_wall(w), w->peers[s1].id.peer_id, sealed,
                               sizeof(sealed), false, frame, sizeof(frame));
        sim_peer_send(w, a, la, frame, len);
        ah_random(sealed, sizeof(sealed));
        len = sim_frame(&w->peers[a], AH_TYPE_NOISE_ENCRYPTED, 7, sim_wall(w), w->peers[s2].id.peer_id, sealed,
                        sizeof(sealed), false, frame, sizeof(frame));
        sim_peer_send(w, a, la, frame, len);
        sim_run(w, 100);
    }
    // Everyone else still hears everything: neither the queues nor the
    // relays can take the whole pool.
    for (int i = 0; i < 20; ++i) {
        char text[32];
        snprintf(text, sizeof(text), "still flowing %d", i);
        const size_t len = sim_message(&w->peers[a], AH_TYPE_CHANNEL_MSG, text, 7, sim_wall(w), frame,
                                       sizeof(frame));
        sim_peer_send(w, a, la, frame, len);
        sim_run(w, 100);
    }
    sim_run(w, 1000);
    TEST_ASSERT_EQUAL(20, sim_count(&w->peers[b], AH_TYPE_CHANNEL_MSG, false));
    // And what the stalled links held goes stale and lets go of its buffers.
    TEST_ASSERT_GREATER_OR_EQUAL(12, ah_node_stats(w->nodes[n])->buffers_in_use);
    sim_run(w, AH_LINK_STALE_MS + 2000);
    // Left: only what the node queued for them since (its announce and sync requests).
    TEST_ASSERT_LESS_OR_EQUAL(4, ah_node_stats(w->nodes[n])->buffers_in_use);
}

static void test_the_node_keeps_buffers_for_its_own_frames(void)
{
    cfg.frame_buffers = 24;
    cfg.queue_per_link = 12;
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    int stalled[4];
    for (int s = 0; s < 4; ++s) {
        const int p = sim_add_peer(w, "stalled");
        stalled[s] = sim_connect_peer(w, n, p, 512);
        announce(p, stalled[s]);
    }
    sim_run(w, 2000);
    // Four stalled links could hold every buffer between them; relays stop
    // short of the reserve.
    uint8_t sealed[48];
    uint8_t frame[256];
    for (int s = 0; s < 4; ++s) {
        sim_throttle(w, stalled[s], 0);
        for (int i = 0; i < 6; ++i) {
            ah_random(sealed, sizeof(sealed));
            const size_t len = sim_frame(&w->peers[a], AH_TYPE_NOISE_ENCRYPTED, 7, sim_wall(w),
                                         w->peers[w->links[stalled[s]].b_peer].id.peer_id, sealed, sizeof(sealed),
                                         false, frame, sizeof(frame));
            sim_peer_send(w, a, la, frame, len);
            sim_run(w, 50);
        }
    }
    sim_run(w, 500);
    TEST_ASSERT_GREATER_THAN(0, ah_node_stats(w->nodes[n])->relay_dropped);
    // So a phone arriving now still gets the node's announce at once.
    const int e = sim_add_peer(w, "eve");
    sim_connect_peer(w, n, e, 512);
    sim_run(w, 1500);
    uint8_t node_id[8];
    TEST_ASSERT_TRUE(node_id_seen_by(e, node_id));
}

static void test_a_flood_on_one_link_never_spends_another_link_s_checks(void)
{
    cfg.verify_per_second = 20;
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    const int m = sim_add_peer(w, "mallory");
    const int lm = sim_connect_peer(w, n, m, 512);
    sim_run(w, 3000);
    // Mallory floods file transfers in Alice's name whose signatures do not
    // verify, each with a payload of its own, so none is a replay.
    uint8_t frame[256];
    for (int i = 0; i < 100; ++i) {
        uint8_t body[16];
        memset(body, i, sizeof(body));
        const size_t len = sim_frame(&w->peers[a], AH_TYPE_FILE_TRANSFER, 7, sim_wall(w), NULL, body, sizeof(body),
                                     true, frame, sizeof(frame));
        frame[len - 1u] ^= 0x01u;
        sim_peer_send(w, m, lm, frame, len);
    }
    sim_run(w, 10);
    // In the same second Bob's own file transfer still crosses, and a phone
    // that has just arrived binds.
    const uint8_t body[] = "bob's file";
    const size_t len = sim_frame(&w->peers[b], AH_TYPE_FILE_TRANSFER, 7, sim_wall(w), NULL, body, sizeof(body), true,
                                 frame, sizeof(frame));
    sim_peer_send(w, b, lb, frame, len);
    const int c = sim_add_peer(w, "carol");
    const int lc = sim_connect_peer(w, n, c, 512);
    announce(c, lc);
    sim_run(w, 300);
    TEST_ASSERT_GREATER_THAN(0, ah_node_stats(w->nodes[n])->verify_skipped);
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[a], AH_TYPE_FILE_TRANSFER, w->peers[b].id.peer_id));
    TEST_ASSERT_NOT_NULL(ah_node_link_peer(w->nodes[n], w->links[lc].a_link));
}

static void test_a_budget_smaller_than_the_links_still_holds_one_check_each(void)
{
    // The S3's default of 8 checks against up to 14 links: here 5 against 7.
    cfg.verify_per_second = 5;
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    const int m = sim_add_peer(w, "mallory");
    const int lm = sim_connect_peer(w, n, m, 512);
    for (int i = 0; i < 4; ++i) {
        sim_connect_peer(w, n, sim_add_peer(w, "idle"), 512);
    }
    sim_run(w, 3000);
    uint8_t frame[256];
    for (int i = 0; i < 20; ++i) {
        uint8_t body[16];
        memset(body, i, sizeof(body));
        const size_t len = sim_frame(&w->peers[a], AH_TYPE_FILE_TRANSFER, 7, sim_wall(w), NULL, body, sizeof(body),
                                     true, frame, sizeof(frame));
        frame[len - 1u] ^= 0x01u;
        sim_peer_send(w, m, lm, frame, len);
    }
    sim_run(w, 10);
    // Mallory's link took one check; Bob's file transfer finds one too.
    const uint8_t body[] = "bob's file";
    const size_t len = sim_frame(&w->peers[b], AH_TYPE_FILE_TRANSFER, 7, sim_wall(w), NULL, body, sizeof(body), true,
                                 frame, sizeof(frame));
    sim_peer_send(w, b, lb, frame, len);
    sim_run(w, 300);
    TEST_ASSERT_EQUAL(19, ah_node_stats(w->nodes[n])->verify_skipped);
    TEST_ASSERT_NOT_EQUAL(-1, sim_find(&w->peers[a], AH_TYPE_FILE_TRANSFER, w->peers[b].id.peer_id));
}

static void test_a_sync_request_past_the_rate_costs_no_signature_check(void)
{
    cfg.verify_per_second = 40;
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    uint8_t frame[256];
    size_t len = 0;
    for (int i = 0; i < 8; ++i) {
        sync_request(b, lb, 1ull << AH_SYNC_BIT_MESSAGE, frame, &len);
        sim_run(w, 200);
    }
    sim_run(w, 2000);
    const uint32_t skipped = ah_node_stats(w->nodes[n])->verify_skipped;
    // Past eight answers in 30 s, Bob is refused before any check, however
    // fast he asks.
    for (int i = 0; i < 60; ++i) {
        sync_request(b, lb, 1ull << AH_SYNC_BIT_MESSAGE, frame, &len);
    }
    sim_run(w, 100);
    TEST_ASSERT_EQUAL(skipped, ah_node_stats(w->nodes[n])->verify_skipped);
}

// A v1 broadcast carrying a raw DEFLATE stream that declares `size` bytes, as
// bitchat-ios sends a compressed message, signed by the peer.
static size_t compressed_message(int peer, uint64_t ts_ms, const uint8_t *stream, size_t stream_len, uint16_t size,
                                 uint8_t *out)
{
    const size_t at = AH_V1_HEADER_LEN + AH_PEER_ID_LEN;
    const size_t len = at + 2u + stream_len + AH_SIGNATURE_LEN;
    memset(out, 0, len);
    out[AH_OFF_VERSION] = AH_VERSION_1;
    out[AH_OFF_TYPE] = AH_TYPE_CHANNEL_MSG;
    out[AH_OFF_TTL] = 7;
    ah_put_be64(out + AH_OFF_TIMESTAMP, ts_ms);
    out[AH_OFF_FLAGS] = AH_FLAG_IS_COMPRESSED | AH_FLAG_HAS_SIGNATURE;
    ah_put_be16(out + AH_OFF_LENGTH, (uint16_t)(2u + stream_len));
    memcpy(out + AH_V1_HEADER_LEN, w->peers[peer].id.peer_id, AH_PEER_ID_LEN);
    ah_put_be16(out + at, size);
    memcpy(out + at + 2u, stream, stream_len);
    ah_frame_t f;
    static uint8_t pre[4096];
    size_t pre_len = 0;
    TEST_ASSERT_TRUE(ah_frame_parse(out, len, &f));
    TEST_ASSERT_TRUE(ah_frame_signing_preimage(&f, pre, sizeof(pre), &pre_len));
    uint8_t sig[AH_SIGNATURE_LEN];
    ah_ed25519_sign(w->peers[peer].id.signing_secret, pre, pre_len, sig);
    ah_frame_attach_signature(out, len, sig);
    return len;
}

// Raw DEFLATE of 32 KiB of zeros: 46 bytes the node must inflate 32 KiB to read.
static const uint8_t s_zeros_32k[] = {
    0xed, 0xc1, 0x01, 0x01, 0x00, 0x00, 0x00, 0x80, 0x90, 0xfe, 0xaf, 0xee, 0x08, 0x0a, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18,
};

// An inflater of the test's own, for the packet IDs a phone computes.
static ah_inflater_t *phone_inflater(void)
{
    static _Alignas(max_align_t) uint8_t mem[48u * 1024u];
    TEST_ASSERT_LESS_OR_EQUAL(sizeof(mem), ah_inflater_size(AH_INFLATE_WINDOW_FULL));
    return ah_inflater_init(mem, AH_INFLATE_WINDOW_FULL);
}

// A request whose filter holds `count` packet IDs, as a phone holding those sends it.
static void sync_request_holding(int peer, int link, const uint8_t (*ids)[AH_PACKET_ID_LEN], size_t count)
{
    uint64_t hashes[8];
    uint32_t scratch[8];
    for (size_t i = 0; i < count; ++i) {
        hashes[i] = ah_gcs_hash(ids[i]);
    }
    uint8_t data[64];
    ah_gcs_built_t built;
    TEST_ASSERT_TRUE(ah_gcs_build(hashes, count, data, sizeof(data), scratch, &built));
    TEST_ASSERT_EQUAL(count, built.included);
    const ah_sync_request_t req = {.p = built.p, .m = built.m, .data = data, .data_len = built.data_len,
                                   .has_types = true, .types = 1ull << AH_SYNC_BIT_MESSAGE
                                  };
    uint8_t payload[128];
    const size_t plen = ah_sync_request_encode(&req, payload, sizeof(payload));
    uint8_t frame[256];
    const size_t len = sim_frame(&w->peers[peer], AH_TYPE_REQUEST_SYNC, 0, sim_wall(w), NULL, payload, plen, true,
                                 frame, sizeof(frame));
    sim_peer_send(w, peer, link, frame, len);
}

static void test_a_link_inflating_hard_never_spends_another_link_s_share(void)
{
    cfg.inflate_bytes_per_second = 512u * 1024u;
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    const int m = sim_add_peer(w, "mallory");
    const int lm = sim_connect_peer(w, n, m, 512);
    sim_run(w, 3000);
    const uint32_t stored = ah_node_stats(w->nodes[n])->sync_stored;
    // Each of Mallory's messages makes the node inflate 32 KiB: sixteen of
    // them are the whole second's budget.
    uint8_t frame[512];
    for (int i = 0; i < 24; ++i) {
        const size_t len = compressed_message(m, sim_wall(w) + (uint64_t)i, s_zeros_32k, sizeof(s_zeros_32k), 32768,
                                              frame);
        sim_peer_send(w, m, lm, frame, len);
    }
    sim_run(w, 10);
    // In the same second Alice's compressed messages still cross.
    const vec_compress_t *v = &VEC_COMPRESS[1];
    uint8_t ids[3][AH_PACKET_ID_LEN];
    for (int i = 0; i < 3; ++i) {
        const size_t len = compressed_message(a, sim_wall(w) + (uint64_t)i, v->compressed.data, v->compressed.len,
                                              (uint16_t)v->plain.len, frame);
        ah_frame_t f;
        TEST_ASSERT_TRUE(ah_frame_parse(frame, len, &f));
        TEST_ASSERT_TRUE(ah_packet_id(&f, phone_inflater(), ids[i]));
        sim_peer_send(w, a, la, frame, len);
    }
    sim_run(w, 300);
    TEST_ASSERT_GREATER_THAN(0, ah_node_stats(w->nodes[n])->inflate_skipped);
    TEST_ASSERT_EQUAL(3, sim_count_from(&w->peers[b], AH_TYPE_CHANNEL_MSG, w->peers[a].id.peer_id));
    TEST_ASSERT_GREATER_OR_EQUAL(stored + 3u, ah_node_stats(w->nodes[n])->sync_stored);
    // The node keeps them under the IDs the phones give them: a phone holding
    // two of the three is sent only the third.
    const int c = sim_add_peer(w, "carol");
    const int lc = sim_connect_peer(w, n, c, 512);
    announce(c, lc);
    sim_run(w, 300);
    sync_request_holding(c, lc, ids, 2);
    sim_run(w, 2000);
    ah_frame_t f;
    size_t at = 0;
    TEST_ASSERT_NOT_NULL(last_of(&w->peers[c], AH_TYPE_CHANNEL_MSG, w->peers[a].id.peer_id, &f, &at));
    TEST_ASSERT_TRUE((f.flags & AH_FLAG_IS_RSR) != 0);
    uint8_t id[AH_PACKET_ID_LEN];
    TEST_ASSERT_TRUE(ah_packet_id(&f, phone_inflater(), id));
    TEST_ASSERT_EQUAL_MEMORY(ids[2], id, AH_PACKET_ID_LEN);
    TEST_ASSERT_EQUAL(1, sim_count_from(&w->peers[c], AH_TYPE_CHANNEL_MSG, w->peers[a].id.peer_id));
}

static void test_a_stream_that_fails_costs_what_it_inflated_not_what_it_claimed(void)
{
    cfg.inflate_bytes_per_second = 512u * 1024u;
    int a;
    int b;
    int la;
    int lb;
    const int n = node_with_two(&a, &b, &la, &lb);
    sim_run(w, 3000);
    // Streams declaring as much as a v1 frame can that fail at their first
    // byte (block type 3): more than the whole second's budget in claims, and
    // a run of smaller claims after them that would leave nothing over.
    uint8_t junk[400];
    memset(junk, 0xFF, sizeof(junk));
    uint8_t frame[512];
    uint32_t claims[20];
    size_t count = 0;
    for (int i = 0; i < 8; ++i) {
        claims[count++] = UINT16_MAX;
    }
    for (uint32_t c = 32768u; c >= 128u; c /= 2u) {
        claims[count++] = c;
    }
    const uint32_t malformed = ah_node_stats(w->nodes[n])->rx_malformed;
    for (size_t i = 0; i < count; ++i) {
        const size_t len = compressed_message(a, sim_wall(w) + i, junk, sizeof(junk), (uint16_t)claims[i], frame);
        sim_peer_send(w, a, la, frame, len);
    }
    sim_run(w, 10);
    TEST_ASSERT_EQUAL(malformed + count, ah_node_stats(w->nodes[n])->rx_malformed);
    // On the same link, in the same second, Alice's real one crosses.
    const vec_compress_t *v = &VEC_COMPRESS[1];
    const size_t len = compressed_message(a, sim_wall(w) + 100u, v->compressed.data, v->compressed.len,
                                          (uint16_t)v->plain.len, frame);
    sim_peer_send(w, a, la, frame, len);
    sim_run(w, 300);
    TEST_ASSERT_EQUAL(1, sim_count_from(&w->peers[b], AH_TYPE_CHANNEL_MSG, w->peers[a].id.peer_id));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_relays_announce_and_message_byte_for_byte);
    RUN_TEST(test_never_relays_what_it_must_not);
    RUN_TEST(test_relaying_needs_no_clock);
    RUN_TEST(test_leave_is_relayed_and_acted_on_only_when_verified);
    RUN_TEST(test_a_source_route_through_the_node_is_followed);
    RUN_TEST(test_unknown_and_airhop_types_cross_unread);
    RUN_TEST(test_directed_goes_only_to_its_recipient);
    RUN_TEST(test_ring_of_three_forwards_each_packet_once);
    RUN_TEST(test_small_mtu_and_malformed_floods_never_crash);
    RUN_TEST(test_live_voice_relays_once_and_never_replays);
    RUN_TEST(test_fragments_relay_one_by_one);
    RUN_TEST(test_forged_board_posts_and_live_packets_never_cross);
    RUN_TEST(test_a_stale_packet_is_relayed_but_never_acted_on);
    RUN_TEST(test_fresh_pieces_of_a_stale_packet_are_never_acted_on);
    RUN_TEST(test_a_slow_packet_in_pieces_is_judged_from_its_first_piece);
    RUN_TEST(test_node_announces_as_equipment_once_synced);
    RUN_TEST(test_an_announce_too_big_for_a_new_link_is_tried_again);
    RUN_TEST(test_one_connection_is_one_peer_and_one_clock_voice);
    RUN_TEST(test_a_crowd_of_identities_never_evicts_a_linked_phone);
    RUN_TEST(test_a_replayed_announce_never_takes_a_direct_link);
    RUN_TEST(test_a_dropped_link_hands_its_peer_to_no_other_link);
    RUN_TEST(test_a_peer_given_up_keeps_its_signing_key);
    RUN_TEST(test_nothing_time_checked_before_the_clock_syncs);
    RUN_TEST(test_one_phone_on_two_connections_is_one_clock_voice);
    RUN_TEST(test_a_lone_skewed_phone_never_destroys_mail_or_the_floor);
    RUN_TEST(test_mail_expires_across_reboots_with_no_two_phones);
    RUN_TEST(test_two_honest_phones_outvote_a_skewed_first_one);
    RUN_TEST(test_a_lone_honest_phone_takes_over_from_a_skewed_one_that_left);
    RUN_TEST(test_hostile_links_never_walk_the_clock_or_plant_a_future_floor);
    RUN_TEST(test_an_unconfirmed_clock_never_prunes_history);
    RUN_TEST(test_late_phone_catches_up_including_location_channels);
    RUN_TEST(test_sync_answers_only_the_link_peer_and_is_rate_limited);
    RUN_TEST(test_back_to_back_sync_requests_are_both_answered);
    RUN_TEST(test_a_stalled_reply_resumes_on_its_own);
    RUN_TEST(test_a_sync_burst_past_the_verify_budget_is_offered_again);
    RUN_TEST(test_a_message_relayed_but_not_kept_is_kept_from_a_sync_reply);
    RUN_TEST(test_a_forged_sync_reply_never_hides_the_genuine_message);
    RUN_TEST(test_a_store_that_gave_up_room_asks_for_its_own_history_alone);
    RUN_TEST(test_mail_survives_a_reboot_and_is_handed_over);
    RUN_TEST(test_a_reused_link_inherits_no_proof);
    RUN_TEST(test_a_depositor_at_its_quota_writes_no_more_flash);
    RUN_TEST(test_mail_is_sprayed_only_to_a_peer_that_proved_its_key);
    RUN_TEST(test_a_session_on_a_phone_s_second_link_is_proof_too);
    RUN_TEST(test_a_spray_that_could_not_go_is_tried_again);
    RUN_TEST(test_a_stalled_cut_gives_way);
    RUN_TEST(test_a_handover_that_lost_a_piece_keeps_the_mail);
    RUN_TEST(test_a_deposit_put_off_for_budget_is_taken_from_its_next_copy);
    RUN_TEST(test_a_long_deposit_is_taken_while_a_cut_is_under_way);
    RUN_TEST(test_expired_mail_is_kept_but_never_sent_on);
    RUN_TEST(test_a_changed_budget_is_written_back_so_a_reboot_mints_no_copies);
    RUN_TEST(test_the_mailbox_writes_flash_within_its_hourly_budget);
    RUN_TEST(test_one_depositor_spends_only_its_share_of_the_flash_budget);
    RUN_TEST(test_raising_an_envelope_s_copies_spends_the_depositor_s_share);
    RUN_TEST(test_dm_to_the_node_gets_a_receipt_and_one_auto_reply);
    RUN_TEST(test_handshake_budgets_are_checked_before_either_is_spent);
    RUN_TEST(test_sealed_traffic_without_a_session_is_charged_like_a_handshake);
    RUN_TEST(test_two_nodes_over_lora_carry_text_only);
    RUN_TEST(test_mail_too_large_for_the_trunk_never_crosses_it);
    RUN_TEST(test_a_node_with_no_phones_carries_text_between_two_lora_nodes);
    RUN_TEST(test_a_lora_link_announces_again_once_it_binds);
    RUN_TEST(test_phone_presence_waits_behind_text_on_the_trunk);
    RUN_TEST(test_a_lora_link_binds_only_the_node_behind_it);
    RUN_TEST(test_a_lora_link_never_binds_to_a_phone);
    RUN_TEST(test_a_compact_node_keeps_relaying_past_stalled_links);
    RUN_TEST(test_the_node_keeps_buffers_for_its_own_frames);
    RUN_TEST(test_a_flood_on_one_link_never_spends_another_link_s_checks);
    RUN_TEST(test_a_budget_smaller_than_the_links_still_holds_one_check_each);
    RUN_TEST(test_a_sync_request_past_the_rate_costs_no_signature_check);
    RUN_TEST(test_a_link_inflating_hard_never_spends_another_link_s_share);
    RUN_TEST(test_a_stream_that_fails_costs_what_it_inflated_not_what_it_claimed);
    return UNITY_END();
}
