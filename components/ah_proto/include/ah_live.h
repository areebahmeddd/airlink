// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Live voice (0x29) and video (0x2D) payloads, checked the way a relay must
// check them before forwarding (PROTOCOLS sections 3.1, 3.6 and 3.10).
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AH_LIVE_STREAM_ID_LEN 8u
// Both start [burst or stream ID 8][seq u16][flags or kind u8].
#define AH_LIVE_HEADER_LEN (AH_LIVE_STREAM_ID_LEN + 3u)

// Whether a voice burst packet is long enough to carry its header. A relay
// reads nothing past the burst ID (PROTOCOLS section 3.6); the phones decode
// the rest.
bool ah_voice_valid(size_t len);

// Whether a VideoBurstPacket passes every rule a bitchat decoder holds it to
// (LIVE_VIDEO_V1): kind-specific lengths, START bounds, DATA entries, PARITY
// shard counts, at most 352 bytes.
bool ah_video_valid(const uint8_t *payload, size_t len);
