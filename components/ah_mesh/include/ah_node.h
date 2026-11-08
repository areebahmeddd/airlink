// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The relay node's protocol core: every packet in, every decision, every
// packet out. Pure C with no ESP-IDF dependency, so the whole mesh behavior
// runs in host tests and simulations exactly as it runs on the device.
//
// Single-threaded by contract: one owner task (the mesh task on the device)
// makes every call. Transports never call in from their own callbacks; they
// post events to that task, which calls here. Time is monotonic milliseconds
// supplied by the caller. All memory is allocated once, at creation.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_links.h"
#include "ah_sync.h"

typedef struct ah_node ah_node_t;

typedef enum {
    AH_WRITE_OK = 0, // the transport has taken a copy
    AH_WRITE_BUSY,   // no room now; the transport will report ready
    AH_WRITE_GONE,   // the link is gone
} ah_write_t;

typedef struct {
    uint8_t peer_id[AH_PEER_ID_LEN];
    uint8_t noise_secret[AH_KEY_LEN];
    uint8_t noise_public[AH_KEY_LEN];
    uint8_t signing_secret[64];
    uint8_t signing_public[AH_KEY_LEN];
    uint8_t nickname[AH_NICKNAME_MAX];
    uint8_t nickname_len;
    uint32_t firmware_version; // major << 16 | minor << 8 | patch
} ah_identity_t;

// What one mailbox record costs the flash budget beyond its envelope: the
// depositor ahead of it and the store's own bookkeeping (NVS spends an index
// entry and a header per chunk, each 32 bytes, and rounds data to 32 bytes).
#define AH_MAIL_RECORD_OVERHEAD 128u

// Every table's capacity, chosen per target in Kconfig (see main/Kconfig.projbuild
// for the arithmetic behind each default).
typedef struct {
    uint16_t links;
    uint8_t queue_per_link;    // at most a quarter of frame_buffers is used per link
    uint16_t frame_buffers;
    uint16_t peers;
    uint16_t peer_pins;        // signing keys kept for peers given up (ah_peers.h); 0 none
    uint32_t dedup_message_slots;
    uint32_t dedup_fragment_slots;
    uint32_t dedup_live_slots;
    ah_sync_sizes_t sync;
    uint16_t mail_slots;
    uint32_t mail_bytes;
    uint16_t mail_per_depositor;
    uint32_t mail_flash_bytes_per_hour; // what the mailbox may write to flash in an hour
    uint8_t reassembly_slots;
    uint32_t reassembly_bytes; // per slot
    uint16_t relay_slots;
    uint16_t reply_backlog;    // planned sync replies held per link
    uint16_t verify_per_second;
    uint32_t inflate_bytes_per_second;
    uint32_t inflate_window;   // AH_INFLATE_WINDOW_FULL, or less on a board short of RAM (ah_inflater_size)
    uint32_t trunk_announce_interval_ms;
    uint32_t big_send_bytes;   // largest packet the node cuts into fragments itself
    uint8_t sessions;          // Noise sessions with peers that talk to the node
} ah_node_config_t;

typedef struct {
    void *ctx;
    // Write one frame; the transport copies it before returning. `prio` is the
    // frame's ah_prio_t, for a transport that queues on its own (the trunk).
    ah_write_t (*write)(void *ctx, ah_link_kind_t kind, uint32_t handle, const uint8_t *frame, size_t len,
                        uint8_t prio);
    // Persist a stored envelope (asynchronously is fine).
    void (*mail_put)(void *ctx, uint32_t record, uint64_t depositor, const uint8_t *envelope, size_t len);
    // Delete a persisted envelope: delivered, expired or evicted.
    void (*mail_delete)(void *ctx, uint32_t record);
    // Persist the wall clock as a lower bound for the next boot.
    void (*clock_save)(void *ctx, uint64_t wall_ms);
    // Memory for the node's tables, zeroed or not; never freed.
    void *(*alloc)(void *ctx, size_t bytes);
} ah_node_ops_t;

typedef struct {
    uint32_t rx;
    uint32_t rx_malformed;
    uint32_t rx_duplicate;
    uint32_t rx_refused;         // failed a pre-relay check or a signature
    uint32_t relayed;            // relay decisions taken
    uint32_t relay_dropped;      // scheduler or buffers full
    uint32_t tx;                 // writes the transports accepted
    uint32_t tx_dropped;         // writes given up: queues full or deadlines passed
    uint32_t verify_skipped;     // checks put off for lack of budget
    uint32_t inflate_skipped;    // packets refused for lack of inflate budget
    uint32_t rx_stale;           // relayed, but outside the freshness window to act on
    uint32_t trunk_refused;      // frames the trunk policy kept off LoRa
    uint32_t sync_served;
    uint32_t sync_stored;
    uint32_t mail_stored;
    uint32_t mail_delivered;
    uint32_t mail_refused;       // deposits and restores the mailbox did not take
    uint32_t dedup_evicted;      // IDs forgotten before their window: a set run past its rate
    uint32_t buffers_exhausted;  // frame buffers refused
    uint32_t peers_evicted;      // peers forgotten for room
    uint32_t reassembly_evicted; // fragment streams dropped unfinished
    uint32_t clock_rejected;     // time samples set aside
    uint16_t peers_known;
    uint16_t links_open;
    uint16_t links_bound;        // links a verified direct announce has bound to a peer
    uint16_t buffers_in_use;
    uint8_t clock_state;
    bool clock_confirmed;        // two agreeing phones have backed the time since boot
} ah_node_stats_t;

// A node with every table allocated through `ops->alloc`, or NULL when an
// allocation failed.
ah_node_t *ah_node_create(const ah_node_config_t *config, const ah_identity_t *identity, const ah_node_ops_t *ops,
                          uint64_t restored_wall_ms);

// A transport link is up and can be written. `expected_peer` is who the
// transport says is behind it (a LoRa neighbor's node ID), or NULL: when
// given, only that identity's announce binds the link. Returns the link ID,
// or AH_LINK_NONE when the table is full.
uint16_t ah_node_link_up(ah_node_t *node, ah_link_kind_t kind, uint32_t handle, uint16_t max_write,
                         const uint8_t expected_peer[AH_PEER_ID_LEN], int64_t now_ms);

// The link's largest single write changed (an MTU exchange).
void ah_node_link_mtu(ah_node_t *node, uint16_t link, uint16_t max_write);

void ah_node_link_down(ah_node_t *node, uint16_t link);

// The transport has room again after a BUSY.
void ah_node_link_ready(ah_node_t *node, uint16_t link, int64_t now_ms);

// One frame arrived on a link. The bytes are read during the call only.
void ah_node_on_frame(ah_node_t *node, uint16_t link, const uint8_t *bytes, size_t len, int64_t now_ms);

// Restore an envelope persisted before this boot.
void ah_node_restore_mail(ah_node_t *node, uint32_t record, uint64_t depositor, const uint8_t *envelope, size_t len);

// Run the timers due by `now_ms`. Returns the monotonic time the next is due.
int64_t ah_node_tick(ah_node_t *node, int64_t now_ms);

// Wall time, when known.
bool ah_node_wall_time(const ah_node_t *node, int64_t now_ms, uint64_t *out);

// The counters, with the gauges (links, peers, buffers, clock) brought up to date.
const ah_node_stats_t *ah_node_stats(ah_node_t *node);

// The link the transport knows by `handle`, or AH_LINK_NONE.
uint16_t ah_node_link_by_handle(const ah_node_t *node, ah_link_kind_t kind, uint32_t handle);

// Queue a frame built elsewhere (the OTA task's) on one link, at bulk
// priority, untouched. Link-local by contract: the node never relays it.
// Returns false for a link not open, a frame longer than one write, or no
// buffer or queue slot free.
bool ah_node_send_raw(ah_node_t *node, uint16_t link, const uint8_t *frame, size_t len, int64_t now_ms);

// The peer bound to a link, or NULL.
const uint8_t *ah_node_link_peer(const ah_node_t *node, uint16_t link);

typedef struct {
    ah_link_kind_t kind;
    uint32_t handle;
    uint16_t max_write;
    const uint8_t *peer_id;   // NULL until a verified direct announce binds the link
    bool peer_is_node;        // the bound peer's 0xB1 bit 0; a claim, never trusted
    uint32_t peer_firmware;   // the bound peer's 0xB0, 0 when it sent none
} ah_node_link_info_t;

// What the node knows of an open link; false for a link not open.
bool ah_node_link_info(const ah_node_t *node, uint16_t link, ah_node_link_info_t *out);
