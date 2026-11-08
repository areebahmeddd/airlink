// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// A packet's decoded payload: bounded inflation of a compressed one, and the
// packet ID computed over it (PROTOCOLS sections 2.2 and 2.3).
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_frame.h"

// Raw-DEFLATE state plus its window. One per owner task, allocated at init:
// it is never touched from two tasks.
typedef struct ah_inflater ah_inflater_t;

// The DEFLATE window: with it any stream inflates, in about 40 KiB all told
// (the window and about 8 KiB of decoder state).
#define AH_INFLATE_WINDOW_FULL 32768u

// Bytes to allocate for an inflater with a `window`-byte window:
// AH_INFLATE_WINDOW_FULL, or less for a board short of RAM. A smaller window
// refuses any payload that decodes to more than `window` bytes, since the
// whole output must then fit the buffer the stream refers back into.
size_t ah_inflater_size(size_t window);

// Prepare memory of ah_inflater_size(window) bytes for use.
ah_inflater_t *ah_inflater_init(void *mem, size_t window);

typedef bool (*ah_inflate_sink_t)(void *ctx, const uint8_t *data, size_t len);

// Inflate a raw DEFLATE stream, handing output to `sink` in pieces. True only
// when the stream produced exactly `expected` bytes and every sink call
// succeeded: refused at the first byte past `expected`, when the stream ends
// short of it, and at a back-reference to before its first byte, as both
// bitchat clients refuse (PROTOCOLS section 2.2). The output depends on `in`
// alone, never on what the window held. Never allocates.
bool ah_inflate(ah_inflater_t *inf, const uint8_t *in, size_t in_len, size_t expected, ah_inflate_sink_t sink,
                void *sink_ctx);

// The 16-byte packet ID, SHA-256(type | sender | timestamp BE | payload)[0:16],
// over the decoded payload, inflating a compressed one on the way with `inf`,
// which may be NULL for a frame that is not compressed. Stable across
// padding, framing version and route edits, which is what makes it the dedup
// key and the gossip-sync identity.
//
// False when a compressed payload does not inflate to its declared size, or
// when the hash failed: such a packet is malformed, never a copy of another
// that failed the same way.
bool ah_packet_id(const ah_frame_t *frame, ah_inflater_t *inf, uint8_t out[AH_PACKET_ID_LEN]);

// ah_packet_id, also setting `inflated` to the bytes inflated on the way, even
// when it fails, so a caller can charge the work a stream actually cost.
bool ah_packet_id_counted(const ah_frame_t *frame, ah_inflater_t *inf, uint8_t out[AH_PACKET_ID_LEN],
                          size_t *inflated);

// Copy the decoded payload into `out`, inflating when compressed. False when
// it does not fit `cap` or does not inflate.
bool ah_payload_decode(const ah_frame_t *frame, ah_inflater_t *inf, uint8_t *out, size_t cap, size_t *out_len);
