// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Payload decoding with bounded inflation, and packet IDs.
#include "ah_payload.h"

#include <assert.h>
#include <string.h>

#include "ah_bytes.h"
#include "ah_crypto.h"
#include "miniz.h"

static_assert(AH_INFLATE_WINDOW_FULL == TINFL_LZ_DICT_SIZE, "the full window is DEFLATE's own");

struct ah_inflater {
    tinfl_decompressor state;
    size_t window_size;
    uint8_t window[];
};

size_t ah_inflater_size(size_t window)
{
    return sizeof(struct ah_inflater) + window;
}

ah_inflater_t *ah_inflater_init(void *mem, size_t window)
{
    // The decoder state is reset by every ah_inflate.
    ah_inflater_t *inf = mem;
    inf->window_size = window;
    return inf;
}

bool ah_inflate(ah_inflater_t *inf, const uint8_t *in, size_t in_len, size_t expected, ah_inflate_sink_t sink,
                void *sink_ctx)
{
    // The full window wraps, so any length streams through it. A smaller one
    // cannot (a back-reference may reach 32 KiB), so it holds the whole output.
    const bool wraps = inf->window_size == TINFL_LZ_DICT_SIZE;
    if (!wraps && expected > inf->window_size) {
        return false;
    }
    tinfl_init(&inf->state);
    size_t in_off = 0;
    size_t win_off = 0;
    size_t produced = 0;
    for (;;) {
        if (win_off == inf->window_size) {
            if (!wraps) {
                // A buffer that does not wrap filled, and `expected` fit it.
                return false;
            }
            win_off = 0;
        }
        // tinfl checks a match's distance against the output so far only when
        // told the buffer holds the whole stream, and the window still holds
        // the last packet's bytes. So the first 32 KiB inflate as one flat
        // buffer, refusing a reference before this packet's first byte as
        // zlib and both clients do; past that every distance lands in this
        // packet's own output, and the window wraps. The packet ID is then a
        // function of the packet alone. Codes RFC 1951 leaves undefined, which
        // zlib refuses, still pass as tinfl reads them, on this packet's own
        // bytes: length codes 286 and 287 as an empty match, and past 32 KiB
        // distance codes 30 and 31 as a copy from 32 KiB back.
        const mz_uint32 flags = produced < inf->window_size ? TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF : 0u;
        size_t in_bytes = in_len - in_off;
        size_t out_bytes = inf->window_size - win_off;
        // A flat buffer may be handed less than its free space (a wrapping one
        // must reach the window's end), so tinfl stops one byte past the claim
        // rather than inflating a whole window a small claim never paid for.
        if (flags != 0u && out_bytes > expected - produced) {
            out_bytes = expected - produced + 1u;
        }
        // Raw DEFLATE (no zlib header) with every input byte present, into
        // the window: output is bounded by the window, not by the declared
        // size, so a hostile size claim costs no memory.
        const tinfl_status status = tinfl_decompress(&inf->state, in + in_off, &in_bytes, inf->window,
                                                     inf->window + win_off, &out_bytes, flags);
        in_off += in_bytes;
        if (out_bytes > 0) {
            if (out_bytes > expected - produced) {
                return false;
            }
            produced += out_bytes;
            if (sink != NULL && !sink(sink_ctx, inf->window + win_off, out_bytes)) {
                return false;
            }
            win_off += out_bytes;
        }
        if (status == TINFL_STATUS_DONE) {
            return produced == expected;
        }
        if (status != TINFL_STATUS_HAS_MORE_OUTPUT) {
            // Failed, bad parameter, or wanting input that is not there.
            return false;
        }
    }
}

typedef struct {
    ah_sha256_ctx_t sha;
    size_t len;
} hash_sink_t;

static bool hash_sink(void *ctx, const uint8_t *data, size_t len)
{
    hash_sink_t *h = ctx;
    ah_sha256_update(&h->sha, data, len);
    h->len += len;
    return true;
}

bool ah_packet_id_counted(const ah_frame_t *frame, ah_inflater_t *inf, uint8_t out[AH_PACKET_ID_LEN],
                          size_t *inflated)
{
    uint8_t ts[8];
    ah_put_be64(ts, frame->timestamp_ms);
    hash_sink_t h = {.len = 0};
    ah_sha256_begin(&h.sha);
    ah_sha256_update(&h.sha, &frame->type, 1);
    ah_sha256_update(&h.sha, frame->sender, AH_PEER_ID_LEN);
    ah_sha256_update(&h.sha, ts, sizeof(ts));
    bool ok = true;
    if (frame->compressed) {
        ok = inf != NULL && ah_inflate(inf, frame->payload, frame->payload_len, frame->original_size, hash_sink, &h);
    } else {
        ah_sha256_update(&h.sha, frame->payload, frame->payload_len);
    }
    // Finished even after a failed inflate, so the hash operation never leaks.
    uint8_t digest[AH_SHA256_LEN];
    ok = ah_sha256_finish(&h.sha, digest) && ok;
    memcpy(out, digest, AH_PACKET_ID_LEN);
    if (inflated != NULL) {
        *inflated = h.len;
    }
    return ok;
}

bool ah_packet_id(const ah_frame_t *frame, ah_inflater_t *inf, uint8_t out[AH_PACKET_ID_LEN])
{
    return ah_packet_id_counted(frame, inf, out, NULL);
}

typedef struct {
    uint8_t *out;
    size_t cap;
    size_t len;
} copy_sink_t;

static bool copy_sink(void *ctx, const uint8_t *data, size_t len)
{
    copy_sink_t *s = ctx;
    if (len > s->cap - s->len) {
        return false;
    }
    memcpy(s->out + s->len, data, len);
    s->len += len;
    return true;
}

bool ah_payload_decode(const ah_frame_t *frame, ah_inflater_t *inf, uint8_t *out, size_t cap, size_t *out_len)
{
    if (!frame->compressed) {
        if (frame->payload_len > cap) {
            return false;
        }
        memcpy(out, frame->payload, frame->payload_len);
        *out_len = frame->payload_len;
        return true;
    }
    if (inf == NULL || frame->original_size > cap) {
        return false;
    }
    copy_sink_t sink = {.out = out, .cap = cap, .len = 0};
    if (!ah_inflate(inf, frame->payload, frame->payload_len, frame->original_size, copy_sink, &sink)) {
        return false;
    }
    *out_len = sink.len;
    return true;
}
