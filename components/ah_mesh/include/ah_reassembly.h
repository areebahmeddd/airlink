// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Reassembly of fragmented packets this node needs for itself: a deposit or a
// handshake addressed to it, a long public message, group message or board
// post to keep for sync, a sync reply it asked for. Never a packet to relay:
// fragments are forwarded one by one as they arrive (PROTOCOLS section 10).
//
// Bounded in slots and bytes (PROTOCOLS section 3.4). A slot is dropped after
// 30 s idle, and a full table gives up the slot idle longest: a transfer
// survives a crowd of new streams only while its pieces keep arriving faster
// than the crowd fills the table, and with one slot, any new stream ends it.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_fragment.h"

#define AH_REASSEMBLY_IDLE_MS 30000
#define AH_REASSEMBLY_MAX_PIECES 128u

typedef struct {
    bool in_use;
    uint8_t sender[AH_PEER_ID_LEN];
    uint8_t stream_id[AH_FRAGMENT_STREAM_ID_LEN];
    uint8_t inner_type;
    uint16_t total;
    uint16_t received;
    uint16_t chunk;      // data bytes in every piece but the last, learned from the first non-final one
    uint16_t link;       // link of the first piece
    bool one_link;       // every piece so far came over that link
    int64_t touched_ms;
    int64_t first_ms;    // when the first piece arrived
    uint32_t have[AH_REASSEMBLY_MAX_PIECES / 32u];
    uint16_t last_len;   // length of the final piece, once seen
    bool last_held;      // the final piece arrived before the chunk size was known
    uint8_t held[AH_BLE_FRAME_MAX];
    uint8_t *data;       // this slot's arena
} ah_assembly_t;

typedef struct {
    ah_assembly_t *slots;
    uint8_t count;
    size_t slot_bytes;
    uint32_t evicted; // streams dropped unfinished: idle past the timeout, or for a newer one
} ah_reassembly_t;

typedef enum {
    AH_REASM_PENDING,
    AH_REASM_DONE,
    AH_REASM_REFUSED,
} ah_reasm_result_t;

// Lay the table out over `arena`, `count * slot_bytes` bytes split one region per slot.
void ah_reassembly_init(ah_reassembly_t *r, ah_assembly_t *slots, uint8_t count, uint8_t *arena, size_t slot_bytes);

typedef struct {
    const uint8_t *bytes; // valid until the next call
    size_t len;
    uint8_t inner_type;
    bool one_link;        // every piece came over the link of the first
    int64_t first_ms;     // when the stream's first piece arrived
} ah_reassembled_t;

// Add one piece. When it completes the packet, the slot is freed and
// `out` points at the whole packet until the next call.
ah_reasm_result_t ah_reassembly_add(ah_reassembly_t *r, const uint8_t sender[AH_PEER_ID_LEN], const ah_fragment_t *frag,
                                    uint16_t link, int64_t now_ms, ah_reassembled_t *out);

// Whether `sender`'s stream `stream_id` is being assembled.
bool ah_reassembly_holds(const ah_reassembly_t *r, const uint8_t sender[AH_PEER_ID_LEN],
                         const uint8_t stream_id[AH_FRAGMENT_STREAM_ID_LEN]);

// Drop slots idle past the timeout.
void ah_reassembly_expire(ah_reassembly_t *r, int64_t now_ms);
