// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Live voice and video checks against their wire layouts.
#include "ah_live.h"

#include "ah_bytes.h"

#define VIDEO_HEADER AH_LIVE_HEADER_LEN
#define VIDEO_PARITY_HEADER (VIDEO_HEADER + 7u)
#define VIDEO_MAX 352u
// A parity symbol is a DATA region behind its u16 length, so a region gets
// only what a whole PARITY packet leaves for it.
#define VIDEO_MAX_REGION (VIDEO_MAX - VIDEO_PARITY_HEADER - 2u)
#define VIDEO_MAX_SOURCES 32u
#define VIDEO_MAX_PARITY 16u
#define VIDEO_MAX_DIMENSION 1920u
#define VIDEO_MAX_FPS 60u
#define VIDEO_ENTRY_HEADER 11u
#define VIDEO_TRACK_MASK 0x03u
#define VIDEO_KEYFRAME 0x04u

enum {
    KIND_DATA = 0x00,
    KIND_START = 0x01,
    KIND_END = 0x02,
    KIND_PARITY = 0x03,
    KIND_CANCELED = 0x04,
};

bool ah_voice_valid(size_t len)
{
    return len >= AH_LIVE_HEADER_LEN;
}

// Entries: [flags][unit seq u16][pts u32][fragment index][fragment count][length u16][bytes].
static bool entries_valid(const uint8_t *region, size_t len)
{
    size_t cursor = 0;
    size_t count = 0;
    while (cursor < len) {
        if (len - cursor < VIDEO_ENTRY_HEADER) {
            return false;
        }
        const uint8_t flags = region[cursor];
        const uint8_t track = flags & VIDEO_TRACK_MASK;
        if ((flags & ~(VIDEO_TRACK_MASK | VIDEO_KEYFRAME)) != 0 || track > 1u) {
            return false;
        }
        // A keyframe is a video unit by definition.
        if ((flags & VIDEO_KEYFRAME) != 0 && track != 0) {
            return false;
        }
        const uint8_t fragment_index = region[cursor + 7u];
        const uint8_t fragment_count = region[cursor + 8u];
        const uint16_t unit_len = ah_be16(region + cursor + 9u);
        const size_t start = cursor + VIDEO_ENTRY_HEADER;
        if (fragment_count < 1u || fragment_index >= fragment_count || unit_len == 0 || len - start < unit_len) {
            return false;
        }
        cursor = start + unit_len;
        count++;
    }
    return count > 0;
}

// The bodies after the header (PROTOCOLS section 3.10):
//
//   START     [version 1][codec 1][width u16][height u16][fps][kbps u16][audio codec]
//   DATA      [block u16][index][entries]
//   PARITY    [block u16][parity index][k][r][symbol length u16][symbol]
//   END       [duration u32][video units u16][audio units u16][packets u16]
//   CANCELED  nothing
bool ah_video_valid(const uint8_t *payload, size_t len)
{
    if (len < VIDEO_HEADER || len > VIDEO_MAX) {
        return false;
    }
    const uint8_t *b = payload + VIDEO_HEADER;
    const size_t body = len - VIDEO_HEADER;
    switch (payload[VIDEO_HEADER - 1u]) {
    case KIND_START: {
        if (body != 10u || b[0] != 1u || b[1] != 0x01u || (b[9] != 0x00u && b[9] != 0x01u)) {
            return false;
        }
        const uint16_t width = ah_be16(b + 2);
        const uint16_t height = ah_be16(b + 4);
        const uint8_t fps = b[6];
        const uint16_t kbps = ah_be16(b + 7);
        return width >= 16u && width <= VIDEO_MAX_DIMENSION && height >= 16u && height <= VIDEO_MAX_DIMENSION &&
               width % 2u == 0 && height % 2u == 0 && fps >= 1u && fps <= VIDEO_MAX_FPS && kbps >= 1u;
    }
    case KIND_DATA: {
        if (body <= 3u) {
            return false;
        }
        const uint8_t index = b[2];
        const size_t region_len = body - 3u;
        return index < VIDEO_MAX_SOURCES && region_len <= VIDEO_MAX_REGION && entries_valid(b + 3, region_len);
    }
    case KIND_PARITY: {
        if (body < 7u || body != 7u + ah_be16(b + 5)) {
            return false;
        }
        const uint8_t parity_index = b[2];
        const uint8_t sources = b[3];
        const uint8_t parity = b[4];
        const size_t symbol_len = body - 7u;
        return sources >= 1u && sources <= VIDEO_MAX_SOURCES && parity >= 1u && parity <= VIDEO_MAX_PARITY &&
               parity_index < parity && symbol_len >= 3u && symbol_len <= VIDEO_MAX_REGION + 2u;
    }
    case KIND_END:
        return body == 10u;
    case KIND_CANCELED:
        return body == 0;
    default:
        return false;
    }
}
