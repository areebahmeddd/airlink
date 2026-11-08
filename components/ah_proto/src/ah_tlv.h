// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The [type u8][length u16 BE][value] record that REQUEST_SYNC payloads,
// courier envelopes and board posts are built from. Private to this component.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ah_bytes.h"

typedef struct {
    uint8_t type;
    uint16_t len;
    const uint8_t *value; // aliases the payload
} ah_tlv16_t;

// Read the record at `*off` and move past it. False at the end of the run,
// which is fewer than 3 bytes left (so one or two trailing bytes are no
// record), and for a record whose value runs past `len`: `*off` is then
// SIZE_MAX, for the caller to refuse the whole payload once the loop ends.
static inline bool ah_tlv16_next(const uint8_t *buf, size_t len, size_t *off, ah_tlv16_t *rec)
{
    if (*off == SIZE_MAX || len - *off < 3u) {
        return false;
    }
    const size_t value_at = *off + 3u;
    rec->type = buf[*off];
    rec->len = ah_be16(buf + *off + 1u);
    if (len - value_at < rec->len) {
        *off = SIZE_MAX;
        return false;
    }
    rec->value = buf + value_at;
    *off = value_at + rec->len;
    return true;
}

// Append one record at `off`. Returns the offset past it, or SIZE_MAX when
// `off` is already SIZE_MAX or the record does not fit, so a run of appends
// needs one check at the end.
static inline size_t ah_tlv16_put(uint8_t *out, size_t cap, size_t off, uint8_t type, const uint8_t *value, size_t len)
{
    if (off == SIZE_MAX || len > UINT16_MAX || cap - off < 3u + len) {
        return SIZE_MAX;
    }
    out[off] = type;
    ah_put_be16(out + off + 1u, (uint16_t)len);
    if (len > 0) {
        memcpy(out + off + 3u, value, len);
    }
    return off + 3u + len;
}
