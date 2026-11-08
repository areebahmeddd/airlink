// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// BOARD_POST (0x23) payloads: a signed post or tombstone whose author key and
// signature travel inside the payload, so a post is checked without knowing
// its author (PROTOCOLS section 3.6). The layout and signed bytes are
// bitchat-ios BoardPackets'.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    AH_BOARD_KIND_POST = 1,
    AH_BOARD_KIND_TOMBSTONE = 2,
} ah_board_post_kind_t;

typedef struct {
    ah_board_post_kind_t kind;
    uint64_t created_ms;  // posts
    uint64_t expires_ms;  // posts
    uint64_t deleted_ms;  // tombstones
    bool urgent;          // flags TLV bit 0
} ah_board_post_t;

// Decode and verify the author signature, as bitchat-ios and Airhop accept a
// board payload: a known TLV of the wrong length refuses it wherever it
// appears, text fields must be valid UTF-8, a post carries 1 to 512 bytes of
// content and lives at most 7 days.
bool ah_board_post_check(const uint8_t *payload, size_t len, ah_board_post_t *out);

// A post still live at `now_ms`: unexpired, not dated over an hour ahead, and
// not expiring more than 7 days and an hour from now. A tombstone is always
// live.
bool ah_board_post_is_live(const ah_board_post_t *board, uint64_t now_ms);
