// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// FRAGMENT (0x20) payloads, and cutting a packet into fragments for a link too
// small to carry it whole (PROTOCOLS section 3.4).
//
// Payload: [stream ID 8][index u16 BE][total u16 BE][inner type u8][data].
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_frame.h"

typedef struct {
    const uint8_t *stream_id; // AH_FRAGMENT_STREAM_ID_LEN bytes
    uint16_t index;
    uint16_t total;
    uint8_t inner_type;
    const uint8_t *data;
    size_t data_len;
} ah_fragment_t;

// Parse a decoded FRAGMENT payload as bitchat-ios accepts one: 0 < total <=
// 10,000 and index < total. Empty and short non-final pieces pass here, as
// bitchat-ios's receiver lets them through; the reassembler is where a slot is
// refused for them.
bool ah_fragment_parse(const uint8_t *payload, size_t len, ah_fragment_t *out);

// Cuts one packet into fragment frames, one at a time, so a caller can pace
// the pieces out as its link queue drains. Every piece is unsigned and copies
// the parent's sender, recipient, TTL and IS_RSR, never its route (PROTOCOLS
// section 3.4), so a routed packet's pieces travel as any directed packet
// does. The timestamp is the parent's, as bitchat-ios stamps its pieces, which
// is why a sync reply's fragments are judged by the window of the packet
// inside (PROTOCOLS section 5.1).
typedef struct {
    uint8_t ttl;
    uint8_t flags; // HAS_RECIPIENT and IS_RSR as the parent carried them
    uint64_t timestamp_ms;
    uint8_t sender[AH_PEER_ID_LEN];
    uint8_t recipient[AH_PEER_ID_LEN];
    uint8_t inner_type;
    uint8_t stream_id[AH_FRAGMENT_STREAM_ID_LEN];
    const uint8_t *data; // the parent's bytes as they would have gone out whole; must outlive the cutter
    size_t data_len;
    size_t chunk;
    uint16_t total;
    uint16_t next;
} ah_fragmenter_t;

// Prepare to cut `data` (the parent frame as it would be sent, TTL and flags
// already set, padding included) into pieces that each fit `link_limit`
// bytes. `parent` is a view of `data` itself, parsed after those edits: the
// pieces take their header from it. False when it is a view of other bytes,
// when not even a 64-byte chunk fits the link, or when more than 10,000
// pieces would be needed.
bool ah_fragmenter_init(ah_fragmenter_t *cutter, const ah_frame_t *parent, const uint8_t *data, size_t data_len,
                        size_t link_limit, const uint8_t stream_id[AH_FRAGMENT_STREAM_ID_LEN]);

// Write the next piece into `out`. Returns its length, or 0 when every piece is out.
size_t ah_fragmenter_next(ah_fragmenter_t *cutter, uint8_t *out, size_t cap);
