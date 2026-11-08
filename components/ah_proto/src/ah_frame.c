// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The packet frame: v1 and v2 headers, the signing preimage, padding and encoding.
#include "ah_frame.h"

#include <string.h>

#include "ah_bytes.h"

// Flag bits a re-encode reproduces. bitchat derives every flag from a field,
// so bits 5 to 7 never survive one and never reach a signing preimage.
#define DEFINED_FLAGS \
    (AH_FLAG_HAS_RECIPIENT | AH_FLAG_HAS_SIGNATURE | AH_FLAG_IS_COMPRESSED | AH_FLAG_HAS_ROUTE | AH_FLAG_IS_RSR)

static const size_t s_pad_blocks[] = {256, 512, 1024, AH_PAD_BLOCK_MAX};

// Ceiling on the declared and the decompressed payload of a type (PROTOCOLS section 4).
static uint32_t payload_cap(uint8_t type)
{
    switch (type) {
    case AH_TYPE_FILE_TRANSFER:
    case AH_TYPE_NOISE_ENCRYPTED:
        return AH_CAP_FRAMED_FILE;
    case AH_TYPE_COURIER_ENV:
    case AH_TYPE_NOSTR_CARRIER:
        return AH_CAP_ENVELOPE;
    case AH_TYPE_REQUEST_SYNC:
        return AH_CAP_REQUEST_SYNC;
    case AH_TYPE_FRAGMENT:
        return AH_CAP_FRAGMENT;
    case AH_TYPE_ANNOUNCE:
    case AH_TYPE_ANNOUNCE_V2:
    case AH_TYPE_LEAVE:
    case AH_TYPE_BOARD_POST:
    case AH_TYPE_PREKEY_BUNDLE:
    case AH_TYPE_VOICE_FRAME:
    case AH_TYPE_VIDEO_FRAME:
    case AH_TYPE_NOISE_HANDSHAKE:
    case AH_TYPE_PING:
    case AH_TYPE_PONG:
        return AH_CAP_CONTROL;
    default:
        // Public, group and Airhop messages, and every unknown type, stay
        // relayable up to twice a v1 frame.
        return AH_CAP_TWICE_V1;
    }
}

bool ah_frame_parse(const uint8_t *buf, size_t len, ah_frame_t *out)
{
    if (buf == NULL || out == NULL || len < AH_MIN_FRAME_LEN) {
        return false;
    }
    const uint8_t version = buf[AH_OFF_VERSION];
    if (version != AH_VERSION_1 && version != AH_VERSION_2) {
        return false;
    }
    const bool v2 = version == AH_VERSION_2;
    const size_t header_len = v2 ? AH_V2_HEADER_LEN : AH_V1_HEADER_LEN;
    const size_t size_field = v2 ? 4u : 2u;
    if (len < header_len + AH_PEER_ID_LEN) {
        return false;
    }

    ah_frame_t *f = out;
    memset(f, 0, sizeof(*f));
    f->bytes = buf;
    f->version = version;
    f->type = buf[AH_OFF_TYPE];
    f->ttl = buf[AH_OFF_TTL];
    f->timestamp_ms = ah_be64(buf + AH_OFF_TIMESTAMP);
    f->flags = buf[AH_OFF_FLAGS];
    f->compressed = (f->flags & AH_FLAG_IS_COMPRESSED) != 0;
    const uint32_t declared = v2 ? ah_be32(buf + AH_OFF_LENGTH) : ah_be16(buf + AH_OFF_LENGTH);

    // The declared length bounds everything allocated or inflated downstream,
    // so it is held to the type's ceiling before any field is read. Only a
    // compressed payload carries the original-size field on top.
    const uint32_t cap = payload_cap(f->type);
    if (declared > cap + (f->compressed ? size_field : 0u)) {
        return false;
    }

    size_t off = header_len;
    f->sender = buf + off;
    off += AH_PEER_ID_LEN;

    if (f->flags & AH_FLAG_HAS_RECIPIENT) {
        if (len - off < AH_PEER_ID_LEN) {
            return false;
        }
        f->recipient = buf + off;
        off += AH_PEER_ID_LEN;
    }

    // HAS_ROUTE means nothing in a v1 frame, which has no route section.
    if (v2 && (f->flags & AH_FLAG_HAS_ROUTE)) {
        if (len - off < 1u) {
            return false;
        }
        f->route_field = true;
        f->route_count = buf[off++];
        const size_t route_bytes = (size_t)f->route_count * AH_PEER_ID_LEN;
        if (len - off < route_bytes) {
            return false;
        }
        f->route = f->route_count > 0 ? buf + off : NULL;
        off += route_bytes;
    }

    if (len - off < declared) {
        return false;
    }
    if (f->compressed) {
        if (declared <= size_field) {
            return false;
        }
        f->original_size = v2 ? ah_be32(buf + off) : ah_be16(buf + off);
        f->payload = buf + off + size_field;
        f->payload_len = declared - size_field;
        // Both clients refuse a stream that inflates to nothing.
        if (f->original_size == 0 || f->original_size > cap ||
                (uint64_t)f->original_size > (uint64_t)f->payload_len * AH_DEFLATE_MAX_RATIO) {
            return false;
        }
    } else {
        f->payload = buf + off;
        f->payload_len = declared;
        f->original_size = declared;
    }
    off += declared;

    if (f->flags & AH_FLAG_HAS_SIGNATURE) {
        if (len - off < AH_SIGNATURE_LEN) {
            return false;
        }
        f->signature = buf + off;
        off += AH_SIGNATURE_LEN;
    }
    f->len = off;
    return true;
}

bool ah_frame_is_broadcast(const ah_frame_t *frame)
{
    if (frame->recipient == NULL) {
        return true;
    }
    bool zeros = true;
    bool ones = true;
    for (size_t i = 0; i < AH_PEER_ID_LEN; ++i) {
        zeros = zeros && frame->recipient[i] == 0x00;
        ones = ones && frame->recipient[i] == 0xFF;
    }
    return zeros || ones;
}

bool ah_frame_is_for(const ah_frame_t *frame, const uint8_t peer_id[AH_PEER_ID_LEN])
{
    return frame->recipient != NULL && memcmp(frame->recipient, peer_id, AH_PEER_ID_LEN) == 0;
}

bool ah_frame_next_hop(const ah_frame_t *frame, const uint8_t self[AH_PEER_ID_LEN], const uint8_t **next)
{
    if (frame->version < AH_VERSION_2 || frame->route == NULL || frame->route_count == 0) {
        return false;
    }
    int at = -1;
    for (uint8_t i = 0; i < frame->route_count; ++i) {
        if (memcmp(frame->route + (size_t)i * AH_PEER_ID_LEN, self, AH_PEER_ID_LEN) == 0) {
            if (at >= 0) {
                return false;
            }
            at = i;
        }
    }
    if (at < 0) {
        return false;
    }
    if (at == frame->route_count - 1) {
        if (ah_frame_is_broadcast(frame)) {
            return false;
        }
        *next = frame->recipient;
        return true;
    }
    *next = frame->route + (size_t)(at + 1) * AH_PEER_ID_LEN;
    return true;
}

bool ah_frame_signing_preimage(const ah_frame_t *frame, uint8_t *out, size_t cap, size_t *out_len)
{
    const bool v2 = frame->version == AH_VERSION_2;
    const size_t header_len = v2 ? AH_V2_HEADER_LEN : AH_V1_HEADER_LEN;
    const size_t end = frame->len - (frame->signature != NULL ? AH_SIGNATURE_LEN : 0u);
    // bitchat decodes a v2 route of count 0 to no route and re-encodes it
    // without the flag or the count byte, so neither is in what was signed.
    const bool drop_empty_route = frame->route_field && frame->route_count == 0;
    const size_t body_len = end - (drop_empty_route ? 1u : 0u);
    if (cap < body_len + AH_PAD_MAX) {
        return false;
    }

    size_t n = 0;
    if (drop_empty_route) {
        const size_t route_at = header_len + AH_PEER_ID_LEN + (frame->recipient != NULL ? AH_PEER_ID_LEN : 0u);
        memcpy(out, frame->bytes, route_at);
        memcpy(out + route_at, frame->bytes + route_at + 1u, end - route_at - 1u);
        n = end - 1u;
    } else {
        memcpy(out, frame->bytes, end);
        n = end;
    }

    uint8_t flags = frame->flags & DEFINED_FLAGS;
    flags &= (uint8_t)~(AH_FLAG_HAS_SIGNATURE | AH_FLAG_IS_RSR);
    if (!v2 || drop_empty_route) {
        flags &= (uint8_t)~AH_FLAG_HAS_ROUTE;
    }
    out[AH_OFF_TTL] = 0;
    out[AH_OFF_FLAGS] = flags;

    *out_len = ah_pad(out, n, cap);
    return true;
}

size_t ah_pad_target(size_t len)
{
    for (size_t i = 0; i < sizeof(s_pad_blocks) / sizeof(s_pad_blocks[0]); ++i) {
        if (len + AH_PAD_OVERHEAD <= s_pad_blocks[i]) {
            return s_pad_blocks[i];
        }
    }
    return len;
}

size_t ah_pad(uint8_t *buf, size_t len, size_t cap)
{
    const size_t target = ah_pad_target(len);
    if (target <= len || target - len > AH_PAD_MAX || target > cap) {
        return len;
    }
    const uint8_t pad = (uint8_t)(target - len);
    memset(buf + len, pad, pad);
    return target;
}

bool ah_frame_pads_on_air(uint8_t type)
{
    return type == AH_TYPE_NOISE_ENCRYPTED || type == AH_TYPE_NOISE_HANDSHAKE;
}

size_t ah_frame_encode(const ah_frame_fields_t *fields, bool signed_frame, uint8_t *out, size_t cap)
{
    const size_t need = AH_V2_HEADER_LEN + AH_PEER_ID_LEN + (fields->recipient != NULL ? AH_PEER_ID_LEN : 0u) +
                        fields->payload_len + (signed_frame ? AH_SIGNATURE_LEN : 0u);
    if (fields->payload_len > AH_CAP_FRAMED_FILE || need > cap) {
        return 0;
    }
    uint8_t flags = 0;
    if (fields->recipient != NULL) {
        flags |= AH_FLAG_HAS_RECIPIENT;
    }
    if (signed_frame) {
        flags |= AH_FLAG_HAS_SIGNATURE;
    }
    if (fields->is_rsr) {
        flags |= AH_FLAG_IS_RSR;
    }

    size_t off = 0;
    out[off++] = AH_VERSION_2;
    out[off++] = fields->type;
    out[off++] = fields->ttl;
    ah_put_be64(out + off, fields->timestamp_ms);
    off += 8;
    out[off++] = flags;
    ah_put_be32(out + off, (uint32_t)fields->payload_len);
    off += 4;
    memcpy(out + off, fields->sender, AH_PEER_ID_LEN);
    off += AH_PEER_ID_LEN;
    if (fields->recipient != NULL) {
        memcpy(out + off, fields->recipient, AH_PEER_ID_LEN);
        off += AH_PEER_ID_LEN;
    }
    if (fields->payload_len > 0) {
        memcpy(out + off, fields->payload, fields->payload_len);
        off += fields->payload_len;
    }
    if (signed_frame) {
        memset(out + off, 0, AH_SIGNATURE_LEN);
        off += AH_SIGNATURE_LEN;
    }
    return off;
}

void ah_frame_attach_signature(uint8_t *frame, size_t len, const uint8_t signature[AH_SIGNATURE_LEN])
{
    memcpy(frame + len - AH_SIGNATURE_LEN, signature, AH_SIGNATURE_LEN);
}
