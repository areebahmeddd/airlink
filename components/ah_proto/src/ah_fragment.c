// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Fragment parsing, and the cutter that splits a packet for a small link.
#include "ah_fragment.h"

#include <string.h>

#include "ah_bytes.h"

bool ah_fragment_parse(const uint8_t *payload, size_t len, ah_fragment_t *out)
{
    if (len < AH_FRAGMENT_HEADER_LEN) {
        return false;
    }
    out->stream_id = payload;
    out->index = ah_be16(payload + AH_FRAGMENT_STREAM_ID_LEN);
    out->total = ah_be16(payload + AH_FRAGMENT_STREAM_ID_LEN + 2u);
    out->inner_type = payload[AH_FRAGMENT_STREAM_ID_LEN + 4u];
    out->data = payload + AH_FRAGMENT_HEADER_LEN;
    out->data_len = len - AH_FRAGMENT_HEADER_LEN;
    return out->total > 0 && out->total <= AH_FRAGMENT_MAX_TOTAL && out->index < out->total;
}

static size_t piece_overhead(const ah_fragmenter_t *c)
{
    return AH_V2_HEADER_LEN + AH_PEER_ID_LEN + ((c->flags & AH_FLAG_HAS_RECIPIENT) ? AH_PEER_ID_LEN : 0u) +
           AH_FRAGMENT_HEADER_LEN;
}

bool ah_fragmenter_init(ah_fragmenter_t *cutter, const ah_frame_t *parent, const uint8_t *data, size_t data_len,
                        size_t link_limit, const uint8_t stream_id[AH_FRAGMENT_STREAM_ID_LEN])
{
    memset(cutter, 0, sizeof(*cutter));
    // Every header field comes from the view, so the view must be of these
    // bytes: one of another buffer would cut them under its TTL and IS_RSR
    // flag, silently dropping a sync reply's tag.
    if (parent->bytes != data || data_len < parent->len) {
        return false;
    }
    cutter->ttl = parent->ttl;
    cutter->timestamp_ms = parent->timestamp_ms;
    cutter->inner_type = parent->type;
    memcpy(cutter->sender, parent->sender, AH_PEER_ID_LEN);
    if (parent->recipient != NULL) {
        cutter->flags |= AH_FLAG_HAS_RECIPIENT;
        memcpy(cutter->recipient, parent->recipient, AH_PEER_ID_LEN);
    }
    cutter->flags |= parent->flags & AH_FLAG_IS_RSR;
    memcpy(cutter->stream_id, stream_id, sizeof(cutter->stream_id));
    cutter->data = data;
    cutter->data_len = data_len;

    const size_t overhead = piece_overhead(cutter);
    if (link_limit <= overhead || link_limit - overhead < AH_FRAGMENT_MIN_CHUNK) {
        return false;
    }
    cutter->chunk = link_limit - overhead;
    const size_t total = (data_len + cutter->chunk - 1u) / cutter->chunk;
    if (total == 0 || total > AH_FRAGMENT_MAX_TOTAL) {
        return false;
    }
    cutter->total = (uint16_t)total;
    return true;
}

size_t ah_fragmenter_next(ah_fragmenter_t *cutter, uint8_t *out, size_t cap)
{
    if (cutter->next >= cutter->total) {
        return 0;
    }
    const size_t start = (size_t)cutter->next * cutter->chunk;
    const size_t piece = cutter->data_len - start < cutter->chunk ? cutter->data_len - start : cutter->chunk;
    const size_t payload_len = AH_FRAGMENT_HEADER_LEN + piece;
    const size_t frame_len = piece_overhead(cutter) - AH_FRAGMENT_HEADER_LEN + payload_len;
    if (cap < frame_len) {
        return 0;
    }

    size_t off = 0;
    out[off++] = AH_VERSION_2;
    out[off++] = AH_TYPE_FRAGMENT;
    out[off++] = cutter->ttl;
    ah_put_be64(out + off, cutter->timestamp_ms);
    off += 8;
    out[off++] = cutter->flags;
    ah_put_be32(out + off, (uint32_t)payload_len);
    off += 4;
    memcpy(out + off, cutter->sender, AH_PEER_ID_LEN);
    off += AH_PEER_ID_LEN;
    if (cutter->flags & AH_FLAG_HAS_RECIPIENT) {
        memcpy(out + off, cutter->recipient, AH_PEER_ID_LEN);
        off += AH_PEER_ID_LEN;
    }
    memcpy(out + off, cutter->stream_id, AH_FRAGMENT_STREAM_ID_LEN);
    off += AH_FRAGMENT_STREAM_ID_LEN;
    ah_put_be16(out + off, cutter->next);
    off += 2;
    ah_put_be16(out + off, cutter->total);
    off += 2;
    out[off++] = cutter->inner_type;
    memcpy(out + off, cutter->data + start, piece);
    off += piece;
    cutter->next++;
    return off;
}
