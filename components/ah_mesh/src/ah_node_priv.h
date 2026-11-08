// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The node's internal state, shared by its source files and nothing else.
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "ah_clock.h"
#include "ah_courier.h"
#include "ah_dedup.h"
#include "ah_fragment.h"
#include "ah_live.h"
#include "ah_node.h"
#include "ah_noise.h"
#include "ah_payload.h"
#include "ah_peers.h"
#include "ah_reassembly.h"
#include "ah_relay.h"
#include "ah_sync.h"
#include "ah_trunk_policy.h"

// Scratch big enough for any control payload decoded in place, and for a
// signing preimage of a full BLE frame plus its padding.
#define AH_SCRATCH_LEN (AH_CAP_CONTROL + AH_PAD_MAX + 64u)
// bitchat-ios answers this many pings per link in AH_PING_WINDOW_MS.
#define AH_PINGS_PER_WINDOW 5u
#define AH_PING_WINDOW_MS 10000
// Live streams whose first packet verified, remembered at once.
#define AH_LIVE_VERIFIED_SLOTS 16u
// Claimed peers whose handshake budget is tracked at once.
#define AH_HANDSHAKE_PEERS 32u

typedef struct {
    bool in_use;
    uint16_t buf;
    int64_t due_ms;
    uint16_t from_link;
    uint16_t from_peer;
    uint8_t prio;
    int64_t deadline_ms; // live frames: dropped unsent past this
} ah_pending_relay_t;

// A planned sync reply, drained into the link queue as it empties.
typedef struct {
    ah_sync_ref_t *refs;
    uint16_t count;
    uint16_t next;
} ah_reply_backlog_t;

typedef struct {
    int64_t window_start_ms;
    uint32_t used;
} ah_budget_t;

// The per-second budgets the links share (ah_node_share_ask).
typedef enum {
    AH_SHARE_VERIFY,  // signature checks
    AH_SHARE_INFLATE, // bytes inflated
    AH_SHARES,
} ah_share_t;

typedef struct {
    int64_t request_sent_ms;   // our last REQUEST_SYNC down this link; 0 none
    int64_t answered_ms[AH_SYNC_RESPONSES_PER_WINDOW];
    uint8_t answered_next;
    int64_t next_round_ms;     // when this link's next sync round is due; 0 not scheduled
    uint32_t round;
    int64_t announce_due_ms;   // a forced announce on this link; 0 none
    int64_t ping_answered[AH_PINGS_PER_WINDOW];
    uint8_t ping_next;
    ah_reply_backlog_t backlog;
    // What this link drew on each shared budget in the window it last asked
    // in; window_start_ms 0 if it never asked.
    ah_budget_t drawn[AH_SHARES];
} ah_link_extra_t;

// One packet being cut into fragments, sourced from a copy the node owns.
typedef struct {
    bool active;
    uint16_t link;
    uint8_t prio;
    uint32_t token;
    int64_t progress_ms; // last time a piece was queued: a cut that stalls is given up
    uint8_t *bytes;      // big_send_bytes: the packet being cut
    uint8_t *preimage;   // big_send_bytes + AH_PAD_MAX: its signing preimage while it is built
    ah_fragmenter_t cutter;
} ah_big_send_t;

typedef struct {
    bool in_use;
    uint8_t peer_id[AH_PEER_ID_LEN];
    bool established;
    uint16_t link;          // link the session was completed over
    bool direct;            // completed with every message at TTL 7 on that link
    ah_noise_handshake_t hs;
    bool hs_active;
    int64_t hs_started_ms;
    bool hs_direct;
    ah_noise_sender_t tx;
    ah_noise_receiver_t rx;
    int64_t used_ms;
    int64_t replied_ms;     // last auto-reply
} ah_session_t;

// Depositors whose share of the mailbox's hourly flash budget is tracked at once.
#define AH_MAIL_WRITERS 16u

// What one depositor wrote to the mailbox's flash this hour.
typedef struct {
    uint64_t depositor;
    ah_budget_t budget;
} ah_mail_writer_t;

// Handshake messages a claimed peer may cause per minute, kept apart from the
// sessions so evicting a session never refills its budget.
typedef struct {
    uint64_t key;
    ah_budget_t budget;
} ah_handshake_peer_t;

// A live burst or stream whose first packet verified (ah_node_rx.c).
typedef struct {
    uint64_t sender;
    uint8_t stream[AH_LIVE_STREAM_ID_LEN];
    uint16_t link; // the link it verified on
    int64_t at_ms;
} ah_live_verified_t;

typedef enum {
    AH_VERIFIED,
    AH_VERIFY_FAILED,   // no key, no signature, or a signature that does not verify
    AH_VERIFY_DEFERRED, // no budget left this second: neither good nor bad
} ah_verify_t;

struct ah_node {
    ah_node_config_t cfg;
    ah_identity_t id;
    ah_node_ops_t ops;
    ah_node_stats_t stats;

    ah_clock_t clock;
    ah_inflater_t *inflater;
    ah_dedup_t dedup[3];
    ah_peers_t peers;
    ah_links_t links;
    ah_link_extra_t *extra;
    ah_reassembly_t reassembly;
    ah_sync_t sync;
    ah_courier_t courier;
    ah_trunk_policy_t trunk;
    ah_pending_relay_t *relays;
    ah_session_t *sessions;
    ah_big_send_t big;

    ah_live_verified_t live[AH_LIVE_VERIFIED_SLOTS];
    ah_handshake_peer_t handshake_peers[AH_HANDSHAKE_PEERS];
    ah_budget_t shares[AH_SHARES];
    uint16_t rx_link; // the link whose frame is being handled, else AH_LINK_NONE: what its checks are charged to
    ah_budget_t handshake_budget;
    ah_budget_t mail_flash_budget; // bytes the mailbox wrote to flash this hour
    ah_mail_writer_t mail_writers[AH_MAIL_WRITERS];
    uint32_t mail_token;           // the last handover token handed out

    int64_t started_ms; // monotonic time of the first tick, -1 before it
    uint64_t saved_floor_ms; // the clock floor last saved, or restored at boot
    int64_t next_announce_ms;
    int64_t next_maintenance_ms;
    int64_t next_clock_save_ms;

    uint8_t scratch[AH_SCRATCH_LEN];
    uint8_t frame_out[AH_FRAME_BUF_MAX + AH_PAD_MAX];
};

// ---- ah_node.c ----
uint32_t ah_node_degree(const ah_node_t *n);
// Spend `cost` from a budget of `limit` per `window_ms`, or refuse when it
// would run over.
bool ah_node_budget_take(ah_budget_t *b, int64_t now_ms, uint32_t cost, uint32_t limit, int64_t window_ms);
// Whether the link may spend `cost` of a budget of `full` per second that it
// shares with the other open links. Each open link is held its share of the
// second (`full` split evenly, at least 1), or only `floor` of it when it has not asked
// in the last two seconds; a link draws on what it is held, then on what no
// link is held. With `reserve_div`, the ask leaves 1/reserve_div of its own
// share, and of the whole budget, to asks without one. AH_LINK_NONE is held
// nothing. Spend what was allowed with ah_node_share_spend.
bool ah_node_share_ask(ah_node_t *n, ah_share_t which, uint16_t link, uint32_t cost, uint32_t full, uint32_t floor,
                       uint32_t reserve_div, int64_t now_ms);
// Charge what an ask allowed, no more than it asked.
void ah_node_share_spend(ah_node_t *n, ah_share_t which, uint16_t link, uint32_t cost);
// Spend one signature check, charged to the receiving link. One for the
// node's own use leaves a quarter of the link's share, and of the budget, to
// the checks before a relay decision.
bool ah_node_verify_budget(ah_node_t *n, bool before_relay, int64_t now_ms);
// Sign (when `sign`), pad when the type pads on air, and queue a frame this
// node built; to `link` only, or to everything when it is AH_LINK_NONE.
// Returns whether it was queued on at least one link.
bool ah_node_originate(ah_node_t *n, const ah_frame_fields_t *fields, bool sign, uint16_t link, int64_t now_ms,
                       uint32_t token);
void ah_node_drain(ah_node_t *n, uint16_t link, int64_t now_ms);
// Build, sign and cut a packet too large for one write (a courier handover).
bool ah_node_originate_big(ah_node_t *n, const ah_frame_fields_t *fields, uint16_t link, uint32_t token,
                           int64_t now_ms);
// Start the one streamed cut of a frame too large for `link`.
bool ah_node_big_send(ah_node_t *n, uint16_t link, const uint8_t *frame, size_t len, ah_prio_t prio, uint32_t token,
                      int64_t now_ms);
bool ah_node_schedule_relay(ah_node_t *n, const uint8_t *frame, size_t len, uint8_t ttl, uint32_t jitter_min_ms,
                            uint32_t jitter_max_ms, uint16_t from_link, uint16_t from_peer, ah_prio_t prio,
                            int64_t deadline_ms, int64_t now_ms);

// ---- ah_node_rx.c ----
ah_verify_t ah_node_verify(ah_node_t *n, const ah_frame_t *f, const uint8_t key[AH_KEY_LEN], bool before_relay,
                           int64_t now_ms);
// ah_packet_id and ah_payload_decode with a compressed payload inflated on the
// receiving link's share of the inflate budget: VERIFIED when done, FAILED when
// malformed, DEFERRED when out of budget.
ah_verify_t ah_node_packet_id(ah_node_t *n, const ah_frame_t *f, uint8_t id[AH_PACKET_ID_LEN], int64_t now_ms);
ah_verify_t ah_node_decode(ah_node_t *n, const ah_frame_t *f, uint8_t *out, size_t cap, size_t *len, int64_t now_ms);

// ---- ah_node_sync.c ----
void ah_node_sync_on_request(ah_node_t *n, uint16_t link, const ah_frame_t *f, int64_t now_ms);
void ah_node_sync_round(ah_node_t *n, uint16_t link, int64_t now_ms);
void ah_node_sync_drain(ah_node_t *n, uint16_t link, int64_t now_ms);
bool ah_node_sync_reply_expected(const ah_node_t *n, uint16_t link, int64_t now_ms);
bool ah_node_sync_pending(const ah_node_t *n, uint16_t link);

// ---- ah_node_mail.c ----
// Take a deposit; true when its signature check was put off for lack of
// budget, so nothing judged it and its ID may be forgotten.
bool ah_node_mail_on_deposit(ah_node_t *n, uint16_t link, const ah_frame_t *f, const uint8_t *payload, size_t len,
                             int64_t now_ms);
void ah_node_mail_on_announce(ah_node_t *n, uint16_t peer, bool direct, int64_t now_ms);
// A frame queued with `token` was cut into `pieces` writes, each carrying it.
void ah_node_mail_cut(ah_node_t *n, uint32_t token, uint16_t pieces);
// One write queued with `token` was taken by its transport.
void ah_node_mail_written(ah_node_t *n, uint32_t token);
void ah_node_mail_expire(ah_node_t *n, int64_t now_ms);
// The mailbox's `gone` callback: an envelope left, so its flash copy goes too.
void ah_node_mail_gone(void *ctx, uint32_t record);

// ---- ah_dm.c ----
void ah_dm_on_handshake(ah_node_t *n, uint16_t link, const ah_frame_t *f, const uint8_t *payload, size_t len,
                        int64_t now_ms);
void ah_dm_on_encrypted(ah_node_t *n, const ah_frame_t *f, const uint8_t *payload, size_t len, int64_t now_ms);
uint16_t ah_dm_proven_link(const ah_node_t *n, const uint8_t peer_id[AH_PEER_ID_LEN], uint16_t peer);
// Open a session with a peer the node needs one with (a courier handover or spray).
void ah_dm_start(ah_node_t *n, uint16_t peer, int64_t now_ms);
void ah_dm_forget(ah_node_t *n, const uint8_t peer_id[AH_PEER_ID_LEN]);
// A link closed or changed hands: no session counts as proven on it any more.
void ah_dm_link_gone(ah_node_t *n, uint16_t link);
void ah_dm_expire(ah_node_t *n, int64_t now_ms);
