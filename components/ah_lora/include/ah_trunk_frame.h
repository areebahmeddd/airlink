// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The trunk frame, version 1. Only Airlink nodes speak it. Every frame
// carries a tag for each node it is for, so a receiver takes it only from the
// node that holds the source ID's secret (ah_trunk_auth.h); a beacon's key,
// which introduces its sender, is the one thing taken untagged.
//
// Every frame:
//   0-1   magic 41 4C ("AL")
//   2     version, 1
//   3     kind: DATA 1, ACK 2, COMPLETE 3, BEACON 4
//   4     flags: bit 0 ASK, a DATA piece asking for feedback; the rest 0
//   5     the sender's conducted power for this frame, signed dBm
//   6-13  source node ID (its bitchat peer ID), never zero
// BEACON:
//   14-45 the source's static key (X25519), whose SHA-256 begins with the source ID
//   46    tags, 0 to 7: one per neighbor the beacon keeps
//   47-   the tags
// DATA:
//   14-17 transfer, big-endian, never zero
//   18    the piece
//   19    pieces in the transfer, 1 to 3
//   20    tags, 1 to 7: one per destination, in the order they answer
//   21-   the tags, then the piece, 1 byte to the end of the frame
// ACK and COMPLETE:
//   14-17 the transfer answered
//   18    ACK: the pieces held (not none, not all); COMPLETE: all
//   19    pieces in the transfer
//   20-27 the tag for the DATA sender
//
// The PHY's CRC covers the whole frame, so the frame carries none, and the
// frame length gives the piece's.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AH_TRUNK_MAGIC0 0x41u
#define AH_TRUNK_MAGIC1 0x4Cu
#define AH_TRUNK_VERSION 1u
// The SX1262's largest frame.
#define AH_TRUNK_FRAME_MAX 255u
#define AH_TRUNK_NODE_LEN 8u
#define AH_TRUNK_KEY_LEN 32u
// 64 bits: a forger gets at most seven guesses per frame on air, some tens of
// thousands an hour, against 2^64.
#define AH_TRUNK_TAG_LEN 8u
// Seven tags leave a piece room for a third of the largest packet; a packet
// for more destinations goes in more than one transfer.
#define AH_TRUNK_TAGS_MAX 7u
#define AH_TRUNK_PREFIX_LEN 14u
#define AH_TRUNK_ANSWER_LEN (20u + AH_TRUNK_TAG_LEN)
#define AH_TRUNK_BEACON_LEN(tags) (47u + AH_TRUNK_TAG_LEN * (unsigned)(tags))
#define AH_TRUNK_DATA_HEADER_LEN(tags) (21u + AH_TRUNK_TAG_LEN * (unsigned)(tags))
#define AH_TRUNK_PIECE_MAX(tags) (AH_TRUNK_FRAME_MAX - AH_TRUNK_DATA_HEADER_LEN(tags))
// The largest bitchat packet a LoRa link takes in one write, and the pieces it needs.
#define AH_TRUNK_PACKET_MAX 512u
#define AH_TRUNK_PIECES_MAX 3u
#define AH_TRUNK_FLAG_ASK 0x01u

static_assert(AH_TRUNK_PIECES_MAX * AH_TRUNK_PIECE_MAX(AH_TRUNK_TAGS_MAX) >= AH_TRUNK_PACKET_MAX,
              "a packet fits its pieces for every destination count");
static_assert((AH_TRUNK_PIECES_MAX - 1u) * AH_TRUNK_PIECE_MAX(1) < AH_TRUNK_PACKET_MAX, "no piece count to spare");
static_assert(AH_TRUNK_BEACON_LEN(AH_TRUNK_TAGS_MAX) <= AH_TRUNK_FRAME_MAX, "a beacon fits a frame");

typedef enum {
    AH_TRUNK_KIND_DATA = 1,
    AH_TRUNK_KIND_ACK = 2,
    AH_TRUNK_KIND_COMPLETE = 3,
    AH_TRUNK_KIND_BEACON = 4,
} ah_trunk_kind_t;

typedef struct {
    ah_trunk_kind_t kind;
    uint8_t flags;
    int8_t power_dbm;
    uint8_t source[AH_TRUNK_NODE_LEN];
    uint8_t key[AH_TRUNK_KEY_LEN];   // BEACON only
    uint32_t transfer;               // DATA, ACK, COMPLETE
    uint8_t index;
    uint8_t total;
    uint8_t tag_count;               // BEACON 0 to 7, DATA 1 to 7, ACK and COMPLETE 1
    uint8_t tags[AH_TRUNK_TAGS_MAX][AH_TRUNK_TAG_LEN];
    const uint8_t *payload;          // into the parsed frame; DATA only
    uint16_t payload_len;
} ah_trunk_frame_t;

// Every piece of a transfer of `total` pieces, as a bitmap; 0 for a total out of range.
uint8_t ah_trunk_frame_mask(uint8_t total);

// Where a frame of `kind` keeps its tags.
size_t ah_trunk_frame_tags_at(ah_trunk_kind_t kind);

// Returns false for anything but a well-formed version 1 frame; `out` points into `data`.
bool ah_trunk_frame_parse(const uint8_t *data, size_t len, ah_trunk_frame_t *out);

// Returns the frame's length, or 0 when it is not well formed or `cap` is too small.
size_t ah_trunk_frame_encode(const ah_trunk_frame_t *frame, uint8_t *out, size_t cap);

// Whether `answer` (an ACK or COMPLETE) answers the transfer `data` belongs
// to; which destination sent it is the tag's to say.
bool ah_trunk_frame_answers(const ah_trunk_frame_t *data, const ah_trunk_frame_t *answer);
