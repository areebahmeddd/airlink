// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The private message and delivery receipt TLVs the node reads and writes.
#include "ah_dm_wire.h"

#include <string.h>

enum {
    PM_TLV_MESSAGE_ID = 0x00,
    PM_TLV_CONTENT = 0x01,
};

bool ah_private_message_decode(const uint8_t *body, size_t len, ah_private_message_t *out)
{
    memset(out, 0, sizeof(*out));
    bool have_id = false;
    bool have_content = false;
    size_t off = 0;
    while (len - off >= 2u) {
        const uint8_t type = body[off];
        const uint8_t value_len = body[off + 1u];
        off += 2u;
        if (len - off < value_len) {
            return false;
        }
        if (type == PM_TLV_MESSAGE_ID) {
            out->message_id = body + off;
            out->message_id_len = value_len;
            have_id = true;
        } else if (type == PM_TLV_CONTENT) {
            out->content = body + off;
            out->content_len = value_len;
            have_content = true;
        } else {
            return false;
        }
        off += value_len;
    }
    return have_id && have_content;
}

size_t ah_private_message_encode(const uint8_t *message_id, size_t id_len, const uint8_t *content, size_t content_len,
                                 uint8_t *out, size_t cap)
{
    const size_t need = 1u + 2u + id_len + 2u + content_len;
    if (id_len > 255u || content_len > 255u || need > cap) {
        return 0;
    }
    size_t off = 0;
    out[off++] = AH_NOISE_PAYLOAD_PRIVATE_MESSAGE;
    out[off++] = PM_TLV_MESSAGE_ID;
    out[off++] = (uint8_t)id_len;
    if (id_len > 0) {
        memcpy(out + off, message_id, id_len);
    }
    off += id_len;
    out[off++] = PM_TLV_CONTENT;
    out[off++] = (uint8_t)content_len;
    if (content_len > 0) {
        memcpy(out + off, content, content_len);
    }
    off += content_len;
    return off;
}

size_t ah_delivered_encode(const uint8_t *message_id, size_t id_len, uint8_t *out, size_t cap)
{
    if (id_len + 1u > cap) {
        return 0;
    }
    out[0] = AH_NOISE_PAYLOAD_DELIVERED;
    if (id_len > 0) {
        memcpy(out + 1, message_id, id_len);
    }
    return id_len + 1u;
}
