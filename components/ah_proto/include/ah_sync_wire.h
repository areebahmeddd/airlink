// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// REQUEST_SYNC (0x21) payloads (PROTOCOLS section 5), byte-exact with
// bitchat-ios RequestSyncPacket. The filter inside is ah_gcs.h's.
//
// Payload: TLVs of [type u8][length u16 BE][value]: 0x01 P (u8), 0x02 M
// (u32 BE), 0x03 the Golomb-Rice bitstream, 0x04 SyncTypeFlags (1 to 8 bytes,
// little-endian), 0x05 sinceTimestamp (u64 BE ms).
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_wire.h"

// bitchat-ios refuses a request whose filter is longer than this.
#define AH_GCS_DATA_DECODE_MAX 1024u

typedef struct {
    uint8_t p;
    uint32_t m;
    const uint8_t *data;
    size_t data_len;
    bool has_types;
    uint64_t types;
    bool has_since;
    uint64_t since_ms;
} ah_sync_request_t;

// Decode as bitchat-ios does: 1 or 2 trailing bytes ignored, unknown tags
// skipped, a repeated tag's last well-formed copy kept, and a P, M, since or
// types field of the wrong length ignored, so an earlier valid copy stands.
// P, M and data are required, with 1 <= P <= 32 and M > 0; a filter over
// 1024 bytes refuses the request.
bool ah_sync_request_decode(const uint8_t *payload, size_t len, ah_sync_request_t *out);

// Encode a request, writing types and since only when set. Returns bytes
// written, or 0 when `cap` is too small.
size_t ah_sync_request_encode(const ah_sync_request_t *req, uint8_t *out, size_t cap);
