// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The version 1 trunk frame's encoder and its strict parser.
#include "ah_trunk_frame.h"

#include <string.h>

#define OFF_KIND 3u
#define OFF_FLAGS 4u
#define OFF_POWER 5u
#define OFF_SOURCE 6u
#define OFF_KEY 14u
#define OFF_BEACON_TAGS 46u
#define OFF_TRANSFER 14u
#define OFF_INDEX 18u
#define OFF_TOTAL 19u
#define OFF_DATA_TAGS 20u

static_assert(OFF_SOURCE + AH_TRUNK_NODE_LEN == AH_TRUNK_PREFIX_LEN, "the prefix adds up");
static_assert(OFF_KEY + AH_TRUNK_KEY_LEN == OFF_BEACON_TAGS, "the beacon adds up");
static_assert(OFF_BEACON_TAGS + 1u == AH_TRUNK_BEACON_LEN(0), "the beacon adds up");
static_assert(OFF_DATA_TAGS + 1u == AH_TRUNK_DATA_HEADER_LEN(0), "the data header adds up");

static bool zero(const uint8_t *p, size_t n)
{
    uint8_t any = 0;
    for (size_t i = 0; i < n; ++i) {
        any |= p[i];
    }
    return any == 0;
}

uint8_t ah_trunk_frame_mask(uint8_t total)
{
    return total >= 1u && total <= AH_TRUNK_PIECES_MAX ? (uint8_t)((1u << total) - 1u) : 0u;
}

size_t ah_trunk_frame_tags_at(ah_trunk_kind_t kind)
{
    switch (kind) {
    case AH_TRUNK_KIND_BEACON:
        return OFF_BEACON_TAGS + 1u;
    case AH_TRUNK_KIND_DATA:
        return OFF_DATA_TAGS + 1u;
    default:
        return OFF_DATA_TAGS;
    }
}

// The frame's length when well formed, else 0.
static size_t length_of(const ah_trunk_frame_t *f)
{
    if ((f->flags & (uint8_t)~AH_TRUNK_FLAG_ASK) != 0 || zero(f->source, AH_TRUNK_NODE_LEN)) {
        return 0;
    }
    if (f->kind == AH_TRUNK_KIND_BEACON) {
        return f->flags == 0 && f->tag_count <= AH_TRUNK_TAGS_MAX && f->payload_len == 0
               ? AH_TRUNK_BEACON_LEN(f->tag_count)
               : 0;
    }
    const uint8_t all = ah_trunk_frame_mask(f->total);
    if (f->transfer == 0 || all == 0) {
        return 0;
    }
    switch (f->kind) {
    case AH_TRUNK_KIND_DATA:
        return f->tag_count >= 1u && f->tag_count <= AH_TRUNK_TAGS_MAX && f->index < f->total &&
               f->payload != NULL && f->payload_len >= 1u && f->payload_len <= AH_TRUNK_PIECE_MAX(f->tag_count)
               ? AH_TRUNK_DATA_HEADER_LEN(f->tag_count) + f->payload_len
               : 0;
    case AH_TRUNK_KIND_ACK:
        return f->flags == 0 && f->tag_count == 1u && f->payload_len == 0 && f->index != 0 && f->index != all &&
               (f->index & ~all) == 0
               ? AH_TRUNK_ANSWER_LEN
               : 0;
    case AH_TRUNK_KIND_COMPLETE:
        return f->flags == 0 && f->tag_count == 1u && f->payload_len == 0 && f->index == all ? AH_TRUNK_ANSWER_LEN
               : 0;
    default:
        return 0;
    }
}

bool ah_trunk_frame_parse(const uint8_t *data, size_t len, ah_trunk_frame_t *out)
{
    if (data == NULL || out == NULL || len < AH_TRUNK_ANSWER_LEN || len > AH_TRUNK_FRAME_MAX ||
            data[0] != AH_TRUNK_MAGIC0 || data[1] != AH_TRUNK_MAGIC1 || data[2] != AH_TRUNK_VERSION) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->kind = (ah_trunk_kind_t)data[OFF_KIND];
    out->flags = data[OFF_FLAGS];
    out->power_dbm = (int8_t)data[OFF_POWER];
    memcpy(out->source, data + OFF_SOURCE, AH_TRUNK_NODE_LEN);
    size_t tags_at = 0;
    switch (out->kind) {
    case AH_TRUNK_KIND_BEACON:
        if (len < AH_TRUNK_BEACON_LEN(0)) {
            return false;
        }
        memcpy(out->key, data + OFF_KEY, AH_TRUNK_KEY_LEN);
        out->tag_count = data[OFF_BEACON_TAGS];
        tags_at = OFF_BEACON_TAGS + 1u;
        break;
    case AH_TRUNK_KIND_DATA:
    case AH_TRUNK_KIND_ACK:
    case AH_TRUNK_KIND_COMPLETE: {
        const uint8_t *t = data + OFF_TRANSFER;
        out->transfer = ((uint32_t)t[0] << 24) | ((uint32_t)t[1] << 16) | ((uint32_t)t[2] << 8) | t[3];
        out->index = data[OFF_INDEX];
        out->total = data[OFF_TOTAL];
        out->tag_count = out->kind == AH_TRUNK_KIND_DATA ? data[OFF_DATA_TAGS] : 1u;
        tags_at = ah_trunk_frame_tags_at(out->kind);
        break;
    }
    default:
        return false;
    }
    if (out->tag_count > AH_TRUNK_TAGS_MAX || tags_at + (size_t)out->tag_count * AH_TRUNK_TAG_LEN > len) {
        return false;
    }
    for (uint8_t i = 0; i < out->tag_count; ++i) {
        memcpy(out->tags[i], data + tags_at + (size_t)i * AH_TRUNK_TAG_LEN, AH_TRUNK_TAG_LEN);
    }
    const size_t body_at = tags_at + (size_t)out->tag_count * AH_TRUNK_TAG_LEN;
    out->payload_len = (uint16_t)(len - body_at);
    out->payload = out->payload_len != 0 ? data + body_at : NULL;
    return length_of(out) == len;
}

size_t ah_trunk_frame_encode(const ah_trunk_frame_t *frame, uint8_t *out, size_t cap)
{
    const size_t len = frame != NULL && out != NULL ? length_of(frame) : 0;
    if (len == 0 || cap < len) {
        return 0;
    }
    out[0] = AH_TRUNK_MAGIC0;
    out[1] = AH_TRUNK_MAGIC1;
    out[2] = AH_TRUNK_VERSION;
    out[OFF_KIND] = (uint8_t)frame->kind;
    out[OFF_FLAGS] = frame->flags;
    out[OFF_POWER] = (uint8_t)frame->power_dbm;
    memcpy(out + OFF_SOURCE, frame->source, AH_TRUNK_NODE_LEN);
    if (frame->kind == AH_TRUNK_KIND_BEACON) {
        memcpy(out + OFF_KEY, frame->key, AH_TRUNK_KEY_LEN);
        out[OFF_BEACON_TAGS] = frame->tag_count;
    } else {
        out[OFF_TRANSFER] = (uint8_t)(frame->transfer >> 24);
        out[OFF_TRANSFER + 1u] = (uint8_t)(frame->transfer >> 16);
        out[OFF_TRANSFER + 2u] = (uint8_t)(frame->transfer >> 8);
        out[OFF_TRANSFER + 3u] = (uint8_t)frame->transfer;
        out[OFF_INDEX] = frame->index;
        out[OFF_TOTAL] = frame->total;
        if (frame->kind == AH_TRUNK_KIND_DATA) {
            out[OFF_DATA_TAGS] = frame->tag_count;
        }
    }
    const size_t tags_at = ah_trunk_frame_tags_at(frame->kind);
    for (uint8_t i = 0; i < frame->tag_count; ++i) {
        memcpy(out + tags_at + (size_t)i * AH_TRUNK_TAG_LEN, frame->tags[i], AH_TRUNK_TAG_LEN);
    }
    if (frame->payload_len != 0) {
        memcpy(out + tags_at + (size_t)frame->tag_count * AH_TRUNK_TAG_LEN, frame->payload, frame->payload_len);
    }
    return len;
}

bool ah_trunk_frame_answers(const ah_trunk_frame_t *data, const ah_trunk_frame_t *answer)
{
    return data->kind == AH_TRUNK_KIND_DATA &&
           (answer->kind == AH_TRUNK_KIND_ACK || answer->kind == AH_TRUNK_KIND_COMPLETE) &&
           answer->transfer == data->transfer && answer->total == data->total;
}
