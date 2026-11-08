// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The REQUEST_SYNC TLV codec.
#include "ah_sync_wire.h"

#include <string.h>

#include "ah_bytes.h"
#include "ah_tlv.h"

bool ah_sync_request_decode(const uint8_t *payload, size_t len, ah_sync_request_t *out)
{
    memset(out, 0, sizeof(*out));
    bool have_p = false;
    bool have_m = false;
    bool have_data = false;
    size_t off = 0;
    ah_tlv16_t rec;
    while (ah_tlv16_next(payload, len, &off, &rec)) {
        switch (rec.type) {
        case AH_SYNC_TLV_P:
            if (rec.len == 1u) {
                have_p = true;
                out->p = rec.value[0];
            }
            break;
        case AH_SYNC_TLV_M:
            if (rec.len == 4u) {
                have_m = true;
                out->m = ah_be32(rec.value);
            }
            break;
        case AH_SYNC_TLV_DATA:
            if (rec.len > AH_GCS_DATA_DECODE_MAX) {
                return false;
            }
            have_data = true;
            out->data = rec.value;
            out->data_len = rec.len;
            break;
        case AH_SYNC_TLV_TYPES:
            if (rec.len >= 1u && rec.len <= 8u) {
                out->has_types = true;
                out->types = 0;
                for (uint16_t i = 0; i < rec.len; ++i) {
                    out->types |= (uint64_t)rec.value[i] << (8u * i);
                }
            }
            break;
        case AH_SYNC_TLV_SINCE:
            if (rec.len == 8u) {
                out->has_since = true;
                out->since_ms = ah_be64(rec.value);
            }
            break;
        default:
            break;
        }
    }
    return off != SIZE_MAX && have_p && have_m && have_data && out->p >= 1u && out->p <= AH_GCS_P_MAX && out->m > 0;
}

size_t ah_sync_request_encode(const ah_sync_request_t *req, uint8_t *out, size_t cap)
{
    uint8_t m[4];
    ah_put_be32(m, req->m);
    size_t off = ah_tlv16_put(out, cap, 0, AH_SYNC_TLV_P, &req->p, 1u);
    off = ah_tlv16_put(out, cap, off, AH_SYNC_TLV_M, m, sizeof(m));
    off = ah_tlv16_put(out, cap, off, AH_SYNC_TLV_DATA, req->data, req->data_len);
    if (req->has_types) {
        // Little-endian, trailing zero bytes trimmed, at least one byte.
        uint8_t types[8];
        size_t n = 0;
        uint64_t v = req->types;
        do {
            types[n++] = (uint8_t)v;
            v >>= 8;
        } while (v != 0 && n < sizeof(types));
        off = ah_tlv16_put(out, cap, off, AH_SYNC_TLV_TYPES, types, n);
    }
    if (req->has_since) {
        uint8_t since[8];
        ah_put_be64(since, req->since_ms);
        off = ah_tlv16_put(out, cap, off, AH_SYNC_TLV_SINCE, since, sizeof(since));
    }
    return off == SIZE_MAX ? 0 : off;
}
