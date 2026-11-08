// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Open links (a BLE connection, a LoRa trunk neighbor), the frame buffers
// shared between them, and each link's outbound queue.
//
// A frame bound for several links is one pooled buffer with a reference per
// queue. A queue serves strict priority, oldest first within a level, so an
// announce never waits behind bulk traffic. A full queue makes room by
// dropping its lowest-priority entry, and only for something more urgent.
//
// Nothing waits forever: a live frame is dropped unsent past its deadline
// (PROTOCOLS section 4, "Link write deadline"), anything else after
// AH_LINK_STALE_MS, or AH_LINK_STALE_LORA_MS on a LoRa link. Each queue holds
// at most a quarter of the pool, so links the transport keeps busy cannot
// hold every buffer between them.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_frame.h"
#include "ah_mesh_ids.h"

#define AH_BUF_NONE UINT16_MAX
#define AH_FRAME_BUF_MAX AH_BLE_FRAME_MAX
// A frame not written by now is not worth writing: whatever it carried has
// been retried, relayed by someone else or given up on by its sender.
#define AH_LINK_STALE_MS 10000
// A LoRa link waits on a duty budget counted in minutes, so text keeps its
// place longer there; the queue's share of the pool still bounds what it holds.
#define AH_LINK_STALE_LORA_MS (5 * 60 * 1000)
// Buffers a relay leaves free, so the node's own announces, replies and
// handovers always find one.
#define AH_POOL_RESERVE 4u

// Link queue priority, lowest number first.
typedef enum {
    AH_PRIO_ANNOUNCE = 0,
    AH_PRIO_HANDSHAKE,
    AH_PRIO_DIRECTED,
    AH_PRIO_PUBLIC,
    // A phone's periodic announce on a trunk link: presence, which waits
    // behind text there (ah_trunk_policy.h).
    AH_PRIO_PRESENCE,
    AH_PRIO_LIVE,
    AH_PRIO_BULK,
    AH_PRIO_SYNC,
} ah_prio_t;

// The queue priority of a frame of this type.
ah_prio_t ah_priority_of(const ah_frame_t *frame);

typedef enum {
    AH_LINK_BLE = 0,
    AH_LINK_LORA = 1,
} ah_link_kind_t;

typedef struct {
    uint16_t len;
    uint16_t refs;
    uint16_t next_free;
    uint8_t data[AH_FRAME_BUF_MAX];
} ah_frame_buf_t;

typedef struct {
    ah_frame_buf_t *bufs;
    uint16_t capacity;
    uint16_t free_head;
    uint16_t in_use;
    uint32_t exhausted; // allocations refused
} ah_pool_t;

typedef struct {
    uint16_t buf;
    uint8_t prio;
    uint32_t seq;
    uint32_t token;      // the sender's own mark, reported when the write lands; 0 none
    int64_t deadline_ms; // dropped unsent after this monotonic time
} ah_queued_t;

typedef struct {
    bool in_use;
    ah_link_kind_t kind;
    uint32_t handle;     // the transport's own name for the link
    uint16_t max_write;  // largest frame one write may carry
    uint16_t peer;       // peer bound by a verified direct announce, or AH_PEER_NONE
    bool has_expected;   // the transport named who is behind the link: only they bind it
    uint8_t expected[AH_PEER_ID_LEN];
    bool busy;           // the transport refused a write; resume on its ready signal
    bool announced;      // our announce was queued on this link
    ah_queued_t *queue;
    uint8_t queued;
    uint8_t queue_cap;
} ah_link_t;

typedef struct {
    ah_link_t *links;
    uint16_t capacity;
    uint32_t seq;
    uint32_t dropped; // writes given up on every link: overflow and deadlines
    ah_pool_t pool;
} ah_links_t;

// Lay the table out over caller memory. `queue_storage` holds
// `capacity * queue_cap` entries, of which each queue uses at most a quarter
// of `buf_count`, or four on a smaller pool.
void ah_links_init(ah_links_t *t, ah_link_t *links, uint16_t capacity, ah_queued_t *queue_storage, uint8_t queue_cap,
                   ah_frame_buf_t *bufs, uint16_t buf_count);

// Open a link, naming the peer the transport says is behind it in `expected`
// (NULL for none). Returns its ID, or AH_LINK_NONE when the table is full.
uint16_t ah_links_open(ah_links_t *t, ah_link_kind_t kind, uint32_t handle, uint16_t max_write,
                       const uint8_t expected[AH_PEER_ID_LEN]);

// Close a link, releasing everything it had queued.
void ah_links_close(ah_links_t *t, uint16_t link);

// The open link the transport knows by `handle`, or AH_LINK_NONE.
uint16_t ah_links_by_handle(const ah_links_t *t, ah_link_kind_t kind, uint32_t handle);

// Whether `peer_id` may bind this link: anyone, unless the transport named someone.
bool ah_links_may_bind(const ah_link_t *l, const uint8_t peer_id[AH_PEER_ID_LEN]);

// A pooled buffer holding a copy of `frame`, with one reference, or
// AH_BUF_NONE when the frame is too long or no more than `keep_free` buffers
// are free.
uint16_t ah_pool_copy(ah_pool_t *pool, const uint8_t *frame, size_t len, uint16_t keep_free);
void ah_pool_unref(ah_pool_t *pool, uint16_t buf);
ah_frame_buf_t *ah_pool_get(ah_pool_t *pool, uint16_t buf);
uint16_t ah_pool_free(const ah_pool_t *pool);

// Queue a buffer on a link, taking a reference on success. It is dropped
// unsent after `deadline_ms`, or when that is 0, once the link kind's stale
// time from `now_ms` has passed.
bool ah_links_enqueue(ah_links_t *t, uint16_t link, uint16_t buf, ah_prio_t prio, int64_t deadline_ms,
                      uint32_t token, int64_t now_ms);

// Free slots in a link's queue.
uint8_t ah_links_room(const ah_links_t *t, uint16_t link);

// Take the next frame to write, dropping expired ones on the way. The entry's
// buffer reference passes to the caller; its `buf` is AH_BUF_NONE when the
// queue is empty.
ah_queued_t ah_links_dequeue(ah_links_t *t, uint16_t link, int64_t now_ms);

// Put a frame the transport refused back at the head of its priority.
void ah_links_requeue(ah_links_t *t, uint16_t link, const ah_queued_t *entry);

// Drop every entry past its deadline, for a link the transport keeps busy.
void ah_links_expire(ah_links_t *t, uint16_t link, int64_t now_ms);
