// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Board post TLV parsing and checks, as bitchat-ios makes them.
#include "ah_board_post.h"

#include <string.h>

#include "ah_bytes.h"
#include "ah_crypto.h"
#include "ah_tlv.h"
#include "ah_wire.h"

enum {
    TLV_KIND = 0x01,
    TLV_POST_ID = 0x02,
    TLV_GEOHASH = 0x03,
    TLV_CONTENT = 0x04,
    TLV_AUTHOR_KEY = 0x05,
    TLV_NICKNAME = 0x06,
    TLV_CREATED = 0x07,
    TLV_EXPIRES = 0x08,
    TLV_FLAGS = 0x09,
    TLV_SIGNATURE = 0x0A,
    TLV_DELETED = 0x0B,
};

#define POST_ID_LEN 16u
#define GEOHASH_MAX 12u
#define CONTENT_MAX 512u
#define NICKNAME_MAX 64u
#define URGENT_FLAG 0x01u

static const char s_post_context[] = "bitchat-board-v1";
static const char s_tombstone_context[] = "bitchat-board-del-v1";

typedef struct {
    const uint8_t *value;
    uint16_t len;
    bool present;
} field_t;

// RFC 3629 well-formedness: no overlongs, no surrogates, nothing past U+10FFFF.
static bool utf8_valid(const uint8_t *s, size_t len)
{
    size_t i = 0;
    while (i < len) {
        const uint8_t c = s[i];
        size_t extra;
        uint32_t min;
        uint32_t cp;
        if (c < 0x80u) {
            i++;
            continue;
        } else if ((c & 0xE0u) == 0xC0u) {
            extra = 1;
            min = 0x80u;
            cp = c & 0x1Fu;
        } else if ((c & 0xF0u) == 0xE0u) {
            extra = 2;
            min = 0x800u;
            cp = c & 0x0Fu;
        } else if ((c & 0xF8u) == 0xF0u) {
            extra = 3;
            min = 0x10000u;
            cp = c & 0x07u;
        } else {
            return false;
        }
        if (len - i <= extra) {
            return false;
        }
        for (size_t k = 1; k <= extra; ++k) {
            if ((s[i + k] & 0xC0u) != 0x80u) {
                return false;
            }
            cp = cp << 6 | (s[i + k] & 0x3Fu);
        }
        if (cp < min || cp > 0x10FFFFu || (cp >= 0xD800u && cp <= 0xDFFFu)) {
            return false;
        }
        i += extra + 1u;
    }
    return true;
}

static bool geohash_valid(const uint8_t *s, size_t len)
{
    static const char alphabet[] = "0123456789bcdefghjkmnpqrstuvwxyz";
    for (size_t i = 0; i < len; ++i) {
        if (memchr(alphabet, s[i], sizeof(alphabet) - 1u) == NULL) {
            return false;
        }
    }
    return true;
}

// The lengths both clients hold a TLV to as they meet it, before a later copy
// could replace it. Timestamps are checked once decoding ends, on the copy kept.
static bool length_ok(uint8_t type, uint16_t len)
{
    switch (type) {
    case TLV_KIND:
    case TLV_FLAGS:
        return len == 1u;
    case TLV_POST_ID:
        return len == POST_ID_LEN;
    case TLV_GEOHASH:
        return len <= GEOHASH_MAX;
    case TLV_CONTENT:
        return len <= CONTENT_MAX;
    case TLV_AUTHOR_KEY:
        return len == AH_KEY_LEN;
    case TLV_NICKNAME:
        return len <= NICKNAME_MAX;
    case TLV_SIGNATURE:
        return len == AH_SIGNATURE_LEN;
    default:
        return true;
    }
}

static size_t put_context(uint8_t *out, const char *context, size_t context_len)
{
    out[0] = (uint8_t)context_len;
    memcpy(out + 1, context, context_len);
    return 1u + context_len;
}

static size_t put_prefixed(uint8_t *out, const field_t *f)
{
    ah_put_be16(out, f->len);
    if (f->len > 0) {
        memcpy(out + 2, f->value, f->len);
    }
    return 2u + f->len;
}

bool ah_board_post_check(const uint8_t *payload, size_t len, ah_board_post_t *out)
{
    field_t fields[TLV_DELETED + 1] = {0};
    size_t off = 0;
    ah_tlv16_t rec;
    while (ah_tlv16_next(payload, len, &off, &rec)) {
        if (!length_ok(rec.type, rec.len)) {
            return false;
        }
        if (rec.type >= TLV_KIND && rec.type <= TLV_DELETED) {
            fields[rec.type] = (field_t) {
                .value = rec.value, .len = rec.len, .present = true
            };
        }
    }
    if (off == SIZE_MAX) {
        return false;
    }

    const field_t *kind = &fields[TLV_KIND];
    const field_t *post_id = &fields[TLV_POST_ID];
    const field_t *author = &fields[TLV_AUTHOR_KEY];
    const field_t *signature = &fields[TLV_SIGNATURE];
    if (!kind->present || !post_id->present || !author->present || !signature->present) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    // Room for the longest canonical post: context, ID, three length-prefixed
    // texts at their caps, the key, two timestamps and the flags.
    uint8_t signed_bytes[1u + 32u + POST_ID_LEN + (2u + GEOHASH_MAX) + (2u + CONTENT_MAX) + AH_KEY_LEN +
                         (2u + NICKNAME_MAX) + 8u + 8u + 1u];
    size_t n = 0;

    if (kind->value[0] == AH_BOARD_KIND_POST) {
        const field_t *geohash = &fields[TLV_GEOHASH];
        const field_t *content = &fields[TLV_CONTENT];
        const field_t *nickname = &fields[TLV_NICKNAME];
        const field_t *created = &fields[TLV_CREATED];
        const field_t *expires = &fields[TLV_EXPIRES];
        const field_t *flags = &fields[TLV_FLAGS];
        if (!geohash->present || !geohash_valid(geohash->value, geohash->len) || !content->present ||
                content->len < 1u || !utf8_valid(content->value, content->len) || !nickname->present ||
                !utf8_valid(nickname->value, nickname->len) || !created->present || created->len != 8u ||
                !expires->present || expires->len != 8u || !flags->present) {
            return false;
        }
        out->kind = AH_BOARD_KIND_POST;
        out->created_ms = ah_be64(created->value);
        out->expires_ms = ah_be64(expires->value);
        out->urgent = (flags->value[0] & URGENT_FLAG) != 0;
        if (out->expires_ms <= out->created_ms ||
                out->expires_ms - out->created_ms > (uint64_t)AH_BOARD_MAX_LIFETIME_MS) {
            return false;
        }
        n += put_context(signed_bytes + n, s_post_context, sizeof(s_post_context) - 1u);
        memcpy(signed_bytes + n, post_id->value, POST_ID_LEN);
        n += POST_ID_LEN;
        n += put_prefixed(signed_bytes + n, geohash);
        n += put_prefixed(signed_bytes + n, content);
        memcpy(signed_bytes + n, author->value, AH_KEY_LEN);
        n += AH_KEY_LEN;
        n += put_prefixed(signed_bytes + n, nickname);
        memcpy(signed_bytes + n, created->value, 8u);
        n += 8u;
        memcpy(signed_bytes + n, expires->value, 8u);
        n += 8u;
        signed_bytes[n++] = flags->value[0];
    } else if (kind->value[0] == AH_BOARD_KIND_TOMBSTONE) {
        const field_t *deleted = &fields[TLV_DELETED];
        if (!deleted->present || deleted->len != 8u) {
            return false;
        }
        out->kind = AH_BOARD_KIND_TOMBSTONE;
        out->deleted_ms = ah_be64(deleted->value);
        n += put_context(signed_bytes + n, s_tombstone_context, sizeof(s_tombstone_context) - 1u);
        memcpy(signed_bytes + n, post_id->value, POST_ID_LEN);
        n += POST_ID_LEN;
        memcpy(signed_bytes + n, deleted->value, 8u);
        n += 8u;
    } else {
        return false;
    }
    return ah_ed25519_verify(author->value, signed_bytes, n, signature->value);
}

bool ah_board_post_is_live(const ah_board_post_t *board, uint64_t now_ms)
{
    if (board->kind != AH_BOARD_KIND_POST) {
        return true;
    }
    return board->expires_ms > now_ms && board->created_ms <= now_ms + (uint64_t)AH_BOARD_CLOCK_SKEW_MS &&
           board->expires_ms <= now_ms + (uint64_t)AH_BOARD_MAX_LIFETIME_MS + (uint64_t)AH_BOARD_CLOCK_SKEW_MS;
}
