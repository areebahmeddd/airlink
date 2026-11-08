// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// A simulated mesh for host tests: relay nodes running the real protocol core,
// test peers that build signed packets the way a phone does, and links between
// them with latency and a write queue a test can make refuse.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_node.h"

#define SIM_MAX_NODES 6
#define SIM_MAX_PEERS 16
#define SIM_MAX_LINKS 32
#define SIM_MAX_INFLIGHT 4096
#define SIM_INBOX 512

typedef struct sim_world sim_world_t;

// A phone stand-in: its keys, and every frame delivered to it.
typedef struct {
    ah_identity_t id;
    struct {
        uint8_t bytes[AH_FRAME_BUF_MAX + 64];
        size_t len;
    } inbox[SIM_INBOX];
    size_t received;
} sim_peer_t;

typedef struct {
    bool up;
    bool lora;
    int a_node, a_peer; // one end: a node index or a peer index (-1 for none)
    int b_node, b_peer;
    uint16_t a_link, b_link; // link IDs inside each node end
    uint16_t max_write;
    int64_t latency_ms;
    int32_t write_budget; // writes the link takes before it refuses (BUSY) until released; -1 never refuses
} sim_link_t;

// One write a node made, in order, for tests that check what went first.
typedef struct {
    int link;
    int node;
    uint8_t type;
    uint8_t prio;
    uint8_t sender[AH_PEER_ID_LEN];
} sim_write_t;

#define SIM_WRITE_LOG 4096

struct sim_world {
    int64_t now_ms;
    ah_node_t *nodes[SIM_MAX_NODES];
    int node_count;
    sim_peer_t peers[SIM_MAX_PEERS];
    int peer_count;
    sim_link_t links[SIM_MAX_LINKS];
    int link_count;
    struct {
        int link;
        bool to_b;
        int64_t at_ms;
        uint8_t bytes[AH_FRAME_BUF_MAX + 64];
        size_t len;
    } inflight[SIM_MAX_INFLIGHT];
    size_t inflight_count;
    uint64_t wall_offset_ms; // what an honest clock reads: now_ms + this
    // Persistence the nodes asked for, kept per node for a simulated reboot.
    struct {
        uint32_t record;
        uint64_t depositor;
        uint8_t bytes[AH_COURIER_MAX_CIPHERTEXT + 64];
        size_t len;
        bool live;
    } mail[SIM_MAX_NODES][16];
    uint64_t saved_clock[SIM_MAX_NODES];
    sim_write_t write_log[SIM_WRITE_LOG];
    size_t write_logged;
    ah_identity_t node_ids[SIM_MAX_NODES];
    ah_node_config_t node_cfg[SIM_MAX_NODES];
    void *allocations[SIM_MAX_NODES][32];
    int allocation_count[SIM_MAX_NODES];
};

// The node configuration the simulations use: small tables, every path exercised.
ah_node_config_t sim_config(void);

void sim_init(sim_world_t *w, uint64_t seed);
int sim_add_node(sim_world_t *w, const ah_node_config_t *cfg, const char *name);
int sim_add_peer(sim_world_t *w, const char *name);
// Fresh keys and a peer ID for an identity no simulated peer holds.
void sim_make_identity(ah_identity_t *id, const char *name);
// A BLE link between a node and a peer.
int sim_connect_peer(sim_world_t *w, int node, int peer, uint16_t max_write);
// A link between two nodes: a LoRa trunk, each end naming the other, or BLE.
int sim_connect_nodes(sim_world_t *w, int a, int b, bool lora, uint16_t max_write);
void sim_disconnect(sim_world_t *w, int link);

// Let a link take `writes` more writes, then refuse them (BUSY) until released,
// as a transport with a full queue does.
void sim_throttle(sim_world_t *w, int link, int32_t writes);
// Lift a throttle and report the link ready, as a transport whose queue drained does.
void sim_release(sim_world_t *w, int link);

// Power-cycle a node: a fresh instance with the same identity, its persisted mail and clock floor.
void sim_reboot(sim_world_t *w, int node);

// Free every node's memory.
void sim_free(sim_world_t *w);

// Deliver a frame from a peer over a link it holds.
void sim_peer_send(sim_world_t *w, int peer, int link, const uint8_t *frame, size_t len);
// Advance time, delivering frames and running node timers.
void sim_run(sim_world_t *w, int64_t ms);

// Wall time an honest phone reads now.
uint64_t sim_wall(const sim_world_t *w);

// ---- frames a phone builds ----

// A signed v1 announce from a peer, as bitchat-ios sends one, TTL 7.
size_t sim_announce(const sim_peer_t *p, uint64_t ts_ms, uint8_t *out, size_t cap);
// A signed v1 frame of `type` carrying `text`, as bitchat-ios sends a public message.
size_t sim_message(const sim_peer_t *p, uint8_t type, const char *text, uint8_t ttl, uint64_t ts_ms, uint8_t *out,
                   size_t cap);
// Any frame from a peer: encode v2, sign when asked.
size_t sim_frame(const sim_peer_t *p, uint8_t type, uint8_t ttl, uint64_t ts_ms, const uint8_t *recipient,
                 const uint8_t *payload, size_t payload_len, bool sign, uint8_t *out, size_t cap);

// How many frames of `type` the peer has received (optionally only IS_RSR ones).
size_t sim_count(const sim_peer_t *p, uint8_t type, bool rsr_only);
// How many frames of `type` from `sender` the peer has received.
size_t sim_count_from(const sim_peer_t *p, uint8_t type, const uint8_t *sender);
// Index of the first received frame of `type` from `sender` (anyone when NULL), or -1.
int sim_find(const sim_peer_t *p, uint8_t type, const uint8_t *sender);
