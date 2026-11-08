// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The wire format against frames recorded from bitchat-ios and the spec
// generator's vectors (test/vectors).
#include <stddef.h>
#include <string.h>

#include "ah_announce.h"
#include "ah_board_post.h"
#include "ah_bytes.h"
#include "ah_courier_wire.h"
#include "ah_crypto.h"
#include "ah_dm_wire.h"
#include "ah_fragment.h"
#include "ah_frame.h"
#include "ah_live.h"
#include "ah_noise.h"
#include "ah_ota_manifest.h"
#include "ah_payload.h"
#include "ah_sync_wire.h"
#include "ah_test_crypto.h"
#include "unity.h"
#include "vectors.h"

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static _Alignas(max_align_t) uint8_t s_inflater_mem[64 * 1024];
static ah_inflater_t *s_inf;

void setUp(void)
{
    s_inf = ah_inflater_init(s_inflater_mem, AH_INFLATE_WINDOW_FULL);
}

void tearDown(void)
{
    ah_test_sha256_fail(false);
}

static const vec_spec_packet_t *spec_packet(const char *name)
{
    for (size_t i = 0; i < COUNT(VEC_SPEC_PACKETS); ++i) {
        if (strcmp(VEC_SPEC_PACKETS[i].name, name) == 0) {
            return &VEC_SPEC_PACKETS[i];
        }
    }
    TEST_FAIL_MESSAGE(name);
    return NULL;
}

static void check_packet(const vec_packet_t *v, const vec_bytes_t *wire)
{
    ah_frame_t f;
    TEST_ASSERT_TRUE_MESSAGE(ah_frame_parse(wire->data, wire->len, &f), v->name);
    TEST_ASSERT_EQUAL_MESSAGE(v->ttl, f.ttl, v->name);
    // The view keeps flags as received, bits 5 to 7 and a v1 route flag
    // included; only the preimage drops them.
    TEST_ASSERT_EQUAL_MESSAGE(v->flags, f.flags, v->name);
    TEST_ASSERT_EQUAL_MESSAGE(v->has_recipient, f.recipient != NULL, v->name);
    TEST_ASSERT_EQUAL_MESSAGE(v->route_count, f.route_count, v->name);
    TEST_ASSERT_EQUAL_MESSAGE(v->has_signature, f.signature != NULL, v->name);
    TEST_ASSERT_EQUAL_MESSAGE(v->unpadded.len, f.len, v->name);

    static uint8_t payload[AH_CAP_TWICE_V1];
    size_t len = 0;
    TEST_ASSERT_TRUE_MESSAGE(ah_payload_decode(&f, s_inf, payload, sizeof(payload), &len), v->name);
    TEST_ASSERT_EQUAL_MESSAGE(v->payload.len, len, v->name);
    if (len > 0) {
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(v->payload.data, payload, len, v->name);
    }

    // The preimage built from the received bytes is exactly what bitchat-ios signs.
    static uint8_t pre[AH_CAP_TWICE_V1];
    size_t pre_len = 0;
    TEST_ASSERT_TRUE_MESSAGE(ah_frame_signing_preimage(&f, pre, sizeof(pre), &pre_len), v->name);
    TEST_ASSERT_EQUAL_MESSAGE(v->preimage.len, pre_len, v->name);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(v->preimage.data, pre, pre_len, v->name);
}

static void test_packets_decode_and_sign_like_bitchat_ios(void)
{
    for (size_t i = 0; i < COUNT(VEC_PACKETS); ++i) {
        check_packet(&VEC_PACKETS[i], &VEC_PACKETS[i].unpadded);
        check_packet(&VEC_PACKETS[i], &VEC_PACKETS[i].padded);
    }
}

static void test_packet_id_is_stable_across_padding(void)
{
    for (size_t i = 0; i < COUNT(VEC_PACKETS); ++i) {
        const vec_packet_t *v = &VEC_PACKETS[i];
        ah_frame_t a;
        ah_frame_t b;
        TEST_ASSERT_TRUE(ah_frame_parse(v->unpadded.data, v->unpadded.len, &a));
        TEST_ASSERT_TRUE(ah_frame_parse(v->padded.data, v->padded.len, &b));
        uint8_t ida[AH_PACKET_ID_LEN];
        uint8_t idb[AH_PACKET_ID_LEN];
        TEST_ASSERT_TRUE(ah_packet_id(&a, s_inf, ida));
        TEST_ASSERT_TRUE(ah_packet_id(&b, s_inf, idb));
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(ida, idb, sizeof(ida), v->name);
    }
}

static void test_decode_accepts_and_refuses_as_bitchat_ios(void)
{
    for (size_t i = 0; i < COUNT(VEC_DECODES); ++i) {
        const vec_decode_t *v = &VEC_DECODES[i];
        ah_frame_t f;
        bool decodes = ah_frame_parse(v->bytes.data, v->bytes.len, &f);
        if (decodes && f.compressed) {
            // A refusal at inflation is still a refusal to decode.
            uint8_t out[AH_CAP_CONTROL];
            size_t len = 0;
            decodes = ah_payload_decode(&f, s_inf, out, sizeof(out), &len);
        }
        TEST_ASSERT_EQUAL_MESSAGE(v->decodes, decodes, v->name);
        if (v->decodes && v->payload.len > 0) {
            TEST_ASSERT_EQUAL_MESSAGE(v->payload.len, f.payload_len, v->name);
            TEST_ASSERT_EQUAL_MEMORY_MESSAGE(v->payload.data, f.payload, f.payload_len, v->name);
        }
    }
}

static void test_payload_ceilings_match_both_clients(void)
{
    // An uncompressed payload must fit its type's ceiling itself: only a
    // compressed one carries the original-size field on top.
    static uint8_t frame[AH_V2_HEADER_LEN + AH_PEER_ID_LEN + AH_CAP_FRAGMENT + 8u];
    for (uint32_t declared = AH_CAP_FRAGMENT; declared <= AH_CAP_FRAGMENT + 4u; ++declared) {
        memset(frame, 0, sizeof(frame));
        frame[AH_OFF_VERSION] = AH_VERSION_2;
        frame[AH_OFF_TYPE] = AH_TYPE_FRAGMENT;
        ah_put_be32(frame + AH_OFF_LENGTH, declared);
        ah_frame_t f;
        TEST_ASSERT_EQUAL(declared == AH_CAP_FRAGMENT,
                          ah_frame_parse(frame, AH_V2_HEADER_LEN + AH_PEER_ID_LEN + declared, &f));
    }
    // A compressed v1 message declaring 0 bytes, carrying an empty stream:
    // both clients refuse a stream that inflates to nothing.
    const uint8_t empty[] = {AH_VERSION_1, AH_TYPE_CHANNEL_MSG, 7, 0, 0, 0, 0, 0, 0, 0, 1, AH_FLAG_IS_COMPRESSED, 0, 4,
                             1, 2, 3, 4, 5, 6, 7, 8, 0x00, 0x00, 0x03, 0x00
                            };
    ah_frame_t f;
    TEST_ASSERT_FALSE(ah_frame_parse(empty, sizeof(empty), &f));
    // The same frame declaring 1 byte, the stream for "a", decodes.
    const uint8_t a[] = {AH_VERSION_1, AH_TYPE_CHANNEL_MSG, 7, 0, 0, 0, 0, 0, 0, 0, 1, AH_FLAG_IS_COMPRESSED, 0, 5,
                         1, 2, 3, 4, 5, 6, 7, 8, 0x00, 0x01, 0x4b, 0x04, 0x00
                        };
    TEST_ASSERT_TRUE(ah_frame_parse(a, sizeof(a), &f));
    uint8_t out[4];
    size_t len = 0;
    TEST_ASSERT_TRUE(ah_payload_decode(&f, s_inf, out, sizeof(out), &len));
    TEST_ASSERT_EQUAL(1, len);
    TEST_ASSERT_EQUAL_HEX8('a', out[0]);
}

static void test_padding_matches_message_padding(void)
{
    for (size_t i = 0; i < COUNT(VEC_BLOCKS); ++i) {
        TEST_ASSERT_EQUAL(VEC_BLOCKS[i].block, ah_pad_target(VEC_BLOCKS[i].size));
    }
    // ah_pad targets the optimal block; check it on the cases that ask for it.
    size_t checked = 0;
    for (size_t i = 0; i < COUNT(VEC_PADDING); ++i) {
        const vec_pad_t *v = &VEC_PADDING[i];
        if (v->target != ah_pad_target(v->data.len)) {
            continue;
        }
        checked++;
        uint8_t buf[4096];
        if (v->data.len > 0) {
            memcpy(buf, v->data.data, v->data.len);
        }
        const size_t len = ah_pad(buf, v->data.len, sizeof(buf));
        TEST_ASSERT_EQUAL(v->padded.len, len);
        if (len > 0) {
            TEST_ASSERT_EQUAL_MEMORY(v->padded.data, buf, len);
        }
    }
    TEST_ASSERT_GREATER_THAN(0, checked);
}

static void test_announces_decode_as_bitchat_ios(void)
{
    for (size_t i = 0; i < COUNT(VEC_ANNOUNCES); ++i) {
        const vec_announce_t *v = &VEC_ANNOUNCES[i];
        ah_announce_t a;
        const bool ok = ah_announce_decode(v->bytes.data, v->bytes.len, &a);
        TEST_ASSERT_EQUAL_MESSAGE(v->decodes, ok, v->name);
        if (!ok) {
            continue;
        }
        TEST_ASSERT_EQUAL_MESSAGE(strlen(v->nickname), a.nickname_len, v->name);
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(v->nickname, a.nickname, a.nickname_len, v->name);
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(v->noise.data, a.noise_key, AH_KEY_LEN, v->name);
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(v->signing.data, a.signing_key, AH_KEY_LEN, v->name);
    }
}

static void test_announce_round_trip_with_relay_tlvs(void)
{
    uint8_t noise[32];
    uint8_t sign[32];
    memset(noise, 0x11, sizeof(noise));
    memset(sign, 0x22, sizeof(sign));
    uint8_t out[160];
    const size_t len = ah_announce_encode((const uint8_t *)"AirhopRelay-1A2B", 16, noise, sign, 0x010203, 0x01, out,
                                          sizeof(out));
    TEST_ASSERT_NOT_EQUAL(0, len);
    ah_announce_t a;
    TEST_ASSERT_TRUE(ah_announce_decode(out, len, &a));
    TEST_ASSERT_TRUE(a.has_firmware);
    TEST_ASSERT_EQUAL_HEX32(0x010203, a.firmware_version);
    TEST_ASSERT_EQUAL_HEX8(0x01, a.relay_flags);
    // Never the neighbor list (PROTOCOLS section 2.3): a node lists no phone, and lists no node either.
    for (size_t off = 0; off + 2 <= len; off += 2u + out[off + 1u]) {
        TEST_ASSERT_NOT_EQUAL(AH_ANNOUNCE_TLV_NEIGHBORS, out[off]);
    }
    // At its longest nickname the announce stays under the 100 bytes where
    // bitchat-ios starts compressing a payload to check its signature; one
    // byte more is refused, since a repetitive name is what DEFLATE shrinks.
    const uint8_t *longest = (const uint8_t *)"relay.relay.relay.relay.relay.re";
    TEST_ASSERT_EQUAL(AH_ANNOUNCE_OWN_MAX, ah_announce_encode(longest, 20, noise, sign, 0, 1, out, sizeof(out)));
    TEST_ASSERT_LESS_THAN(AH_COMPRESS_THRESHOLD, AH_ANNOUNCE_OWN_MAX);
    TEST_ASSERT_EQUAL(0, ah_announce_encode(longest, 21, noise, sign, 0, 1, out, sizeof(out)));
}

typedef struct {
    uint8_t *out;
    size_t len;
} sink_t;

static bool collect(void *ctx, const uint8_t *data, size_t len)
{
    sink_t *s = ctx;
    memcpy(s->out + s->len, data, len);
    s->len += len;
    return true;
}

static void test_inflate_is_bounded_by_the_declared_size(void)
{
    for (size_t i = 0; i < COUNT(VEC_COMPRESS); ++i) {
        const vec_compress_t *v = &VEC_COMPRESS[i];
        static uint8_t out[8192];
        sink_t s = {.out = out, .len = 0};
        TEST_ASSERT_TRUE_MESSAGE(ah_inflate(s_inf, v->compressed.data, v->compressed.len, v->plain.len, collect, &s),
                                 v->name);
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(v->plain.data, out, v->plain.len, v->name);
        // One byte short of the stream: refused at the first byte over.
        s.len = 0;
        TEST_ASSERT_FALSE_MESSAGE(
            ah_inflate(s_inf, v->compressed.data, v->compressed.len, v->plain.len - 1u, collect, &s), v->name);
        // One byte more than the stream gives: refused at the end.
        s.len = 0;
        TEST_ASSERT_FALSE_MESSAGE(
            ah_inflate(s_inf, v->compressed.data, v->compressed.len, v->plain.len + 1u, collect, &s), v->name);
    }
}

static void test_a_small_window_inflates_what_fits_it(void)
{
    // A board short of RAM inflates into a buffer the size of the output:
    // what fits decodes byte for byte as the full window does, the rest is
    // refused rather than overrun.
    static const size_t windows[] = {256u, 4096u};
    static _Alignas(max_align_t) uint8_t mem[sizeof(s_inflater_mem)];
    size_t fitted = 0;
    size_t refused = 0;
    for (size_t w = 0; w < COUNT(windows); ++w) {
        ah_inflater_t *small = ah_inflater_init(mem, windows[w]);
        TEST_ASSERT_LESS_OR_EQUAL(sizeof(mem), ah_inflater_size(windows[w]));
        for (size_t i = 0; i < COUNT(VEC_COMPRESS); ++i) {
            const vec_compress_t *v = &VEC_COMPRESS[i];
            static uint8_t out[8192];
            sink_t s = {.out = out, .len = 0};
            const bool ok = ah_inflate(small, v->compressed.data, v->compressed.len, v->plain.len, collect, &s);
            if (v->plain.len <= windows[w]) {
                TEST_ASSERT_TRUE_MESSAGE(ok, v->name);
                TEST_ASSERT_EQUAL_MEMORY_MESSAGE(v->plain.data, out, v->plain.len, v->name);
                fitted++;
            } else {
                TEST_ASSERT_FALSE_MESSAGE(ok, v->name);
                refused++;
            }
        }
    }
    TEST_ASSERT_GREATER_THAN(0, fitted);
    TEST_ASSERT_GREATER_THAN(0, refused);
}

// A final stored block of 32 KiB of one byte, so the window holds nothing
// else: what an earlier packet's output would have left there.
static void fill_window(ah_inflater_t *inf, uint8_t byte)
{
    static uint8_t stored[5u + AH_INFLATE_WINDOW_FULL] = {0x01, 0x00, 0x80, 0xFF, 0x7F};
    memset(stored + 5, byte, AH_INFLATE_WINDOW_FULL);
    TEST_ASSERT_TRUE(ah_inflate(inf, stored, sizeof(stored), AH_INFLATE_WINDOW_FULL, NULL, NULL));
}

static bool hash_into(void *ctx, const uint8_t *data, size_t len)
{
    ah_sha256_update(ctx, data, len);
    return true;
}

// A v1 public message carrying the stream, declaring its size.
static size_t compressed_frame(const vec_inflate_t *v, uint8_t *out, size_t cap)
{
    const size_t at = AH_V1_HEADER_LEN + AH_PEER_ID_LEN;
    TEST_ASSERT_LESS_OR_EQUAL(cap, at + 2u + v->stream.len);
    memset(out, 0, at);
    out[AH_OFF_VERSION] = AH_VERSION_1;
    out[AH_OFF_TYPE] = AH_TYPE_CHANNEL_MSG;
    out[AH_OFF_TTL] = 7;
    out[AH_OFF_FLAGS] = AH_FLAG_IS_COMPRESSED;
    ah_put_be16(out + AH_OFF_LENGTH, (uint16_t)(2u + v->stream.len));
    ah_put_be16(out + at, (uint16_t)v->size);
    memcpy(out + at + 2u, v->stream.data, v->stream.len);
    return at + 2u + v->stream.len;
}

static void test_inflate_refuses_what_zlib_refuses(void)
{
    // zlib's verdict on each stream, whatever an earlier packet left in the
    // window: a match reaching before the stream's first byte is refused,
    // never read from those bytes, so a packet's ID is its own, and the same
    // on a board whose window is too small to wrap.
    static _Alignas(max_align_t) uint8_t small_mem[16u * 1024u];
    TEST_ASSERT_LESS_OR_EQUAL(sizeof(small_mem), ah_inflater_size(4096u));
    ah_inflater_t *small = ah_inflater_init(small_mem, 4096u);
    for (size_t i = 0; i < COUNT(VEC_INFLATE); ++i) {
        const vec_inflate_t *v = &VEC_INFLATE[i];
        uint8_t frame[512];
        ah_frame_t f;
        TEST_ASSERT_TRUE_MESSAGE(ah_frame_parse(frame, compressed_frame(v, frame, sizeof(frame)), &f), v->name);
        uint8_t ids[2][AH_PACKET_ID_LEN];
        for (size_t k = 0; k < 2; ++k) {
            const uint8_t fill = k == 0 ? 0x00 : 0xFF;
            fill_window(s_inf, fill);
            ah_sha256_ctx_t ctx;
            ah_sha256_begin(&ctx);
            const bool ok = ah_inflate(s_inf, v->stream.data, v->stream.len, v->size, hash_into, &ctx);
            uint8_t digest[AH_SHA256_LEN];
            TEST_ASSERT_TRUE(ah_sha256_finish(&ctx, digest));
            TEST_ASSERT_EQUAL_MESSAGE(v->accept, ok, v->name);
            if (ok) {
                TEST_ASSERT_EQUAL_MEMORY_MESSAGE(v->sha256.data, digest, sizeof(digest), v->name);
            }
            fill_window(s_inf, fill);
            TEST_ASSERT_EQUAL_MESSAGE(v->accept, ah_packet_id(&f, s_inf, ids[k]), v->name);
        }
        if (v->accept) {
            TEST_ASSERT_EQUAL_MEMORY_MESSAGE(ids[0], ids[1], AH_PACKET_ID_LEN, v->name);
        }
        const bool fits = v->size <= 4096u;
        const bool inflated = ah_inflate(small, v->stream.data, v->stream.len, v->size, NULL, NULL);
        TEST_ASSERT_EQUAL_MESSAGE(fits && v->accept, inflated, v->name);
    }
}

static void test_inflate_stops_one_byte_past_the_claim(void)
{
    // A stream that expands to 33,346 bytes, claimed as 1: refused after
    // writing at most 2 bytes, so a small claim buys no window of work. The
    // window is the tail of the caller's memory, so a byte it never wrote
    // still holds the fill.
    const vec_inflate_t *v = NULL;
    for (size_t i = 0; i < COUNT(VEC_INFLATE); ++i) {
        if (VEC_INFLATE[i].size > AH_INFLATE_WINDOW_FULL) {
            v = &VEC_INFLATE[i];
        }
    }
    TEST_ASSERT_NOT_NULL(v);
    static _Alignas(max_align_t) uint8_t mem[64u * 1024u];
    const size_t size = ah_inflater_size(AH_INFLATE_WINDOW_FULL);
    TEST_ASSERT_LESS_OR_EQUAL(sizeof(mem), size);
    memset(mem, 0xA5, sizeof(mem));
    ah_inflater_t *inf = ah_inflater_init(mem, AH_INFLATE_WINDOW_FULL);
    TEST_ASSERT_FALSE(ah_inflate(inf, v->stream.data, v->stream.len, 1u, NULL, NULL));
    // Past the window's first bytes, with room for the struct's tail padding.
    const uint8_t *tail = mem + size - AH_INFLATE_WINDOW_FULL + 64u;
    size_t written = 0;
    for (const uint8_t *p = tail; p < mem + size - 64u; ++p) {
        written += *p != 0xA5;
    }
    TEST_ASSERT_EQUAL(0, written);
}

static void test_fragments_parse_and_carry_their_parent(void)
{
    for (size_t i = 0; i < COUNT(VEC_FRAGMENTS); ++i) {
        const vec_fragments_t *v = &VEC_FRAGMENTS[i];
        uint8_t whole[4096];
        size_t whole_len = 0;
        uint8_t inner = 0;
        for (size_t k = 0; k < v->count; ++k) {
            ah_frame_t f;
            TEST_ASSERT_TRUE_MESSAGE(ah_frame_parse(v->pieces[k].data, v->pieces[k].len, &f), v->name);
            TEST_ASSERT_EQUAL(AH_TYPE_FRAGMENT, f.type);
            TEST_ASSERT_NULL(f.signature);
            uint8_t payload[AH_CAP_FRAGMENT];
            size_t len = 0;
            TEST_ASSERT_TRUE(ah_payload_decode(&f, s_inf, payload, sizeof(payload), &len));
            ah_fragment_t frag;
            TEST_ASSERT_TRUE_MESSAGE(ah_fragment_parse(payload, len, &frag), v->name);
            TEST_ASSERT_EQUAL(k, frag.index);
            TEST_ASSERT_EQUAL(v->count, frag.total);
            inner = frag.inner_type;
            memcpy(whole + whole_len, frag.data, frag.data_len);
            whole_len += frag.data_len;
        }
        ah_frame_t parent;
        TEST_ASSERT_TRUE_MESSAGE(ah_frame_parse(whole, whole_len, &parent), v->name);
        TEST_ASSERT_EQUAL(inner, parent.type);
    }
}

static void test_fragmenter_cuts_to_the_link_and_reassembles(void)
{
    // A 1000-byte public message cut for a 185-byte ATT MTU (182-byte writes).
    uint8_t payload[1000];
    for (size_t i = 0; i < sizeof(payload); ++i) {
        payload[i] = (uint8_t)i;
    }
    uint8_t sender[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const ah_frame_fields_t fields = {.type = AH_TYPE_CHANNEL_MSG, .ttl = 5, .timestamp_ms = 1780000000000ull,
                                      .sender = sender, .payload = payload, .payload_len = sizeof(payload)
                                     };
    uint8_t frame[1200];
    const size_t len = ah_frame_encode(&fields, true, frame, sizeof(frame));
    ah_frame_t parent;
    TEST_ASSERT_TRUE(ah_frame_parse(frame, len, &parent));
    ah_fragmenter_t cutter;
    const uint8_t stream[AH_FRAGMENT_STREAM_ID_LEN] = {9, 9, 9, 9, 9, 9, 9, 9};
    TEST_ASSERT_TRUE(ah_fragmenter_init(&cutter, &parent, frame, len, 182, stream));
    uint8_t whole[1200];
    size_t whole_len = 0;
    uint8_t piece[512];
    size_t n;
    while ((n = ah_fragmenter_next(&cutter, piece, sizeof(piece))) > 0) {
        TEST_ASSERT_LESS_OR_EQUAL(182, n);
        ah_frame_t f;
        TEST_ASSERT_TRUE(ah_frame_parse(piece, n, &f));
        TEST_ASSERT_EQUAL(5, f.ttl);
        TEST_ASSERT_EQUAL_UINT64(parent.timestamp_ms, f.timestamp_ms);
        TEST_ASSERT_EQUAL_MEMORY(sender, f.sender, 8);
        ah_fragment_t frag;
        TEST_ASSERT_TRUE(ah_fragment_parse(f.payload, f.payload_len, &frag));
        memcpy(whole + whole_len, frag.data, frag.data_len);
        whole_len += frag.data_len;
    }
    TEST_ASSERT_EQUAL(len, whole_len);
    TEST_ASSERT_EQUAL_MEMORY(frame, whole, len);
    // A 23-byte MTU (20-byte writes) cannot carry even a fragment header.
    TEST_ASSERT_FALSE(ah_fragmenter_init(&cutter, &parent, frame, len, 20, stream));
    // A copy tagged as a sync reply, TTL 0 and IS_RSR, under the original's
    // view: its pieces would go out untagged at TTL 5, so it is refused.
    uint8_t reply[1200];
    memcpy(reply, frame, len);
    reply[AH_OFF_TTL] = 0;
    reply[AH_OFF_FLAGS] |= AH_FLAG_IS_RSR;
    TEST_ASSERT_FALSE(ah_fragmenter_init(&cutter, &parent, reply, len, 182, stream));
    TEST_ASSERT_FALSE(ah_fragmenter_init(&cutter, &parent, frame, len - 1u, 182, stream));
    ah_frame_t tagged;
    TEST_ASSERT_TRUE(ah_frame_parse(reply, len, &tagged));
    TEST_ASSERT_TRUE(ah_fragmenter_init(&cutter, &tagged, reply, len, 182, stream));
    n = ah_fragmenter_next(&cutter, piece, sizeof(piece));
    ah_frame_t f;
    TEST_ASSERT_TRUE(ah_frame_parse(piece, n, &f));
    TEST_ASSERT_EQUAL(0, f.ttl);
    TEST_ASSERT_EQUAL_HEX8(AH_FLAG_IS_RSR, f.flags & AH_FLAG_IS_RSR);
}

static void test_fragments_carry_their_parents_recipient_never_its_route(void)
{
    // PROTOCOLS section 3.4: a routed packet's pieces travel as a directed packet does.
    const vec_spec_packet_t *routed = spec_packet("v2_directed_routed");
    ah_frame_t parent;
    TEST_ASSERT_TRUE(ah_frame_parse(routed->frame.data, routed->frame.len, &parent));
    TEST_ASSERT_EQUAL(2, parent.route_count);
    ah_fragmenter_t cutter;
    const uint8_t stream[AH_FRAGMENT_STREAM_ID_LEN] = {7};
    TEST_ASSERT_TRUE(ah_fragmenter_init(&cutter, &parent, routed->frame.data, routed->frame.len, 120, stream));
    uint8_t piece[120];
    size_t n;
    size_t pieces = 0;
    while ((n = ah_fragmenter_next(&cutter, piece, sizeof(piece))) > 0) {
        ah_frame_t f;
        TEST_ASSERT_TRUE(ah_frame_parse(piece, n, &f));
        TEST_ASSERT_FALSE(f.route_field);
        TEST_ASSERT_EQUAL_HEX8(0, f.flags & AH_FLAG_HAS_ROUTE);
        TEST_ASSERT_NOT_NULL(f.recipient);
        TEST_ASSERT_EQUAL_MEMORY(parent.recipient, f.recipient, AH_PEER_ID_LEN);
        pieces++;
    }
    TEST_ASSERT_GREATER_THAN(1, pieces);
}

static void test_peer_ids_derive_as_bitchat_ios(void)
{
    for (size_t i = 0; i < COUNT(VEC_PEER_IDS); ++i) {
        uint8_t id[8];
        TEST_ASSERT_TRUE(ah_peer_id_of(VEC_PEER_IDS[i].noise.data, id));
        TEST_ASSERT_EQUAL_MEMORY(VEC_PEER_IDS[i].peer_id.data, id, 8);
    }
}

static void test_courier_tags_derive_as_bitchat_ios(void)
{
    uint8_t tag[16];
    TEST_ASSERT_TRUE(ah_courier_tag(VEC_COURIER_NOISE_KEY.data, VEC_COURIER_EPOCH_DAY, tag));
    TEST_ASSERT_EQUAL_MEMORY(VEC_COURIER_TAG.data, tag, sizeof(tag));
    for (size_t i = 0; i < COUNT(VEC_TAGS); ++i) {
        TEST_ASSERT_TRUE(ah_courier_tag(VEC_TAG_KEY.data, VEC_TAGS[i].epoch_day, tag));
        TEST_ASSERT_EQUAL_MEMORY(VEC_TAGS[i].tag.data, tag, sizeof(tag));
    }
}

static void test_courier_envelope_round_trips_byte_exact(void)
{
    ah_envelope_t env;
    TEST_ASSERT_TRUE(ah_envelope_decode(VEC_COURIER_ENVELOPE.data, VEC_COURIER_ENVELOPE.len, &env));
    uint8_t again[256];
    const size_t len = ah_envelope_encode(&env, again, sizeof(again));
    TEST_ASSERT_EQUAL(VEC_COURIER_ENVELOPE.len, len);
    TEST_ASSERT_EQUAL_MEMORY(VEC_COURIER_ENVELOPE.data, again, len);
    // One or two trailing bytes are ignored, as Airhop's courier store ignores them.
    TEST_ASSERT_LESS_OR_EQUAL(sizeof(again) - 2u, len);
    again[len] = 0x7F;
    again[len + 1u] = 0x00;
    TEST_ASSERT_TRUE(ah_envelope_decode(again, len + 2u, &env));
    uint8_t short_out[256];
    TEST_ASSERT_EQUAL(0, ah_envelope_encode(&env, short_out, len - 1u));
}

static void test_courier_packet_signs_as_bitchat_ios(void)
{
    // The courier packet's signing preimage, padded to 256 as bitchat-ios pads it.
    ah_frame_t f;
    TEST_ASSERT_TRUE(ah_frame_parse(VEC_COURIER_PACKET_UNSIGNED.data, VEC_COURIER_PACKET_UNSIGNED.len, &f));
    uint8_t pre[512];
    size_t pre_len = 0;
    TEST_ASSERT_TRUE(ah_frame_signing_preimage(&f, pre, sizeof(pre), &pre_len));
    TEST_ASSERT_EQUAL(VEC_COURIER_PREIMAGE.len, pre_len);
    TEST_ASSERT_EQUAL_MEMORY(VEC_COURIER_PREIMAGE.data, pre, pre_len);

    uint8_t secret[64];
    uint8_t pub[32];
    ah_ed25519_keypair(VEC_COURIER_SEED.data, secret, pub);
    TEST_ASSERT_EQUAL_MEMORY(VEC_COURIER_PUBLIC.data, pub, sizeof(pub));
    uint8_t sig[64];
    ah_ed25519_sign(secret, pre, pre_len, sig);
    TEST_ASSERT_TRUE(ah_ed25519_verify(pub, pre, pre_len, sig));
    sig[0] ^= 1u;
    TEST_ASSERT_FALSE(ah_ed25519_verify(pub, pre, pre_len, sig));
}

static void test_ota_manifests_as_the_spec_generator_signs_them(void)
{
    for (size_t i = 0; i < COUNT(VEC_OTA_MANIFESTS); ++i) {
        const vec_ota_t *v = &VEC_OTA_MANIFESTS[i];
        ah_ota_manifest_t m;
        const bool ok = ah_ota_manifest_check(v->manifest.data, v->manifest.len, VEC_OTA_OWNER.data, VEC_OTA_BOARD, &m);
        TEST_ASSERT_EQUAL_MESSAGE(v->accept, ok, v->name);
        if (ok) {
            TEST_ASSERT_EQUAL_UINT32(VEC_OTA_VERSION, m.version);
            TEST_ASSERT_EQUAL_UINT32(VEC_OTA_SIZE, m.size);
            TEST_ASSERT_EQUAL_MEMORY(VEC_OTA_SHA256.data, m.sha256, sizeof(m.sha256));
        }
    }
    // A board whose name is a prefix of the manifest's is not that board.
    ah_ota_manifest_t m;
    TEST_ASSERT_FALSE(ah_ota_manifest_check(VEC_OTA_MANIFESTS[0].manifest.data, VEC_OTA_MANIFESTS[0].manifest.len,
                                            VEC_OTA_OWNER.data, "heltec", &m));
}

static void test_board_posts_as_the_spec_generator_signs_them(void)
{
    for (size_t i = 0; i < COUNT(VEC_BOARDS); ++i) {
        const vec_board_t *v = &VEC_BOARDS[i];
        ah_board_post_t b;
        const bool ok = ah_board_post_check(v->payload.data, v->payload.len, &b);
        TEST_ASSERT_EQUAL_MESSAGE(v->check, ok, v->name);
        if (ok) {
            TEST_ASSERT_EQUAL_MESSAGE(v->live, ah_board_post_is_live(&b, VEC_BOARD_NOW), v->name);
            TEST_ASSERT_EQUAL_MESSAGE(v->urgent, b.urgent, v->name);
        }
    }
}

static void test_live_payloads_as_bitchat_decodes_them(void)
{
    for (size_t i = 0; i < COUNT(VEC_LIVE); ++i) {
        const vec_live_t *v = &VEC_LIVE[i];
        const bool ok = v->video ? ah_video_valid(v->payload.data, v->payload.len) : ah_voice_valid(v->payload.len);
        TEST_ASSERT_EQUAL_MESSAGE(v->accept, ok, v->name);
    }
}

static void test_a_source_route_names_the_next_hop(void)
{
    const vec_spec_packet_t *routed = spec_packet("v2_directed_routed");
    ah_frame_t f;
    TEST_ASSERT_TRUE(ah_frame_parse(routed->frame.data, routed->frame.len, &f));
    // The route is 1111..., 2222...; the recipient 0102030405060708.
    uint8_t first[8];
    uint8_t second[8];
    uint8_t stranger[8];
    memset(first, 0x11, sizeof(first));
    memset(second, 0x22, sizeof(second));
    memset(stranger, 0x33, sizeof(stranger));
    const uint8_t *next = NULL;
    TEST_ASSERT_TRUE(ah_frame_next_hop(&f, first, &next));
    TEST_ASSERT_EQUAL_MEMORY(second, next, 8);
    TEST_ASSERT_TRUE(ah_frame_next_hop(&f, second, &next));
    TEST_ASSERT_EQUAL_MEMORY(f.recipient, next, 8);
    TEST_ASSERT_FALSE(ah_frame_next_hop(&f, stranger, &next));
    // A route that names us twice is a loop, not a path: flood.
    uint8_t loop[512];
    memcpy(loop, routed->frame.data, routed->frame.len);
    memcpy(loop + (f.route - routed->frame.data) + AH_PEER_ID_LEN, first, AH_PEER_ID_LEN);
    ah_frame_t g;
    TEST_ASSERT_TRUE(ah_frame_parse(loop, routed->frame.len, &g));
    TEST_ASSERT_FALSE(ah_frame_next_hop(&g, first, &next));
}

static void test_an_all_ones_recipient_is_a_broadcast(void)
{
    uint8_t frame[64];
    uint8_t sender[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t ones[8];
    memset(ones, 0xFF, sizeof(ones));
    const ah_frame_fields_t fields = {.type = AH_TYPE_VOICE_FRAME, .ttl = 7, .sender = sender, .recipient = ones};
    const size_t len = ah_frame_encode(&fields, false, frame, sizeof(frame));
    ah_frame_t f;
    TEST_ASSERT_TRUE(ah_frame_parse(frame, len, &f));
    TEST_ASSERT_TRUE(ah_frame_is_broadcast(&f));
    ones[3] = 0;
    ah_frame_encode(&fields, false, frame, sizeof(frame));
    TEST_ASSERT_TRUE(ah_frame_parse(frame, len, &f));
    TEST_ASSERT_FALSE(ah_frame_is_broadcast(&f));
}

static void test_sync_request_keeps_a_valid_field_over_a_malformed_copy(void)
{
    // P 7, M 1280, two bytes of filter and since 1234, then a P, an M and a
    // since of the wrong length: bitchat-ios ignores each and keeps the first.
    const uint8_t req[] = {
        AH_SYNC_TLV_P, 0, 1, 7, AH_SYNC_TLV_M, 0, 4, 0, 0, 5, 0, AH_SYNC_TLV_DATA, 0, 2, 0xAB, 0xCD,
        AH_SYNC_TLV_SINCE, 0, 8, 0, 0, 0, 0, 0, 0, 0x04, 0xD2, AH_SYNC_TLV_P, 0, 2, 9, 9, AH_SYNC_TLV_M, 0, 1, 1,
        AH_SYNC_TLV_SINCE, 0, 1, 1,
    };
    ah_sync_request_t r;
    TEST_ASSERT_TRUE(ah_sync_request_decode(req, sizeof(req), &r));
    TEST_ASSERT_EQUAL(7, r.p);
    TEST_ASSERT_EQUAL_UINT32(1280, r.m);
    TEST_ASSERT_TRUE(r.has_since);
    TEST_ASSERT_EQUAL_UINT64(1234, r.since_ms);
}

static bool sync_decodes(const uint8_t *p, size_t len)
{
    ah_sync_request_t r;
    return ah_sync_request_decode(p, len, &r);
}

static bool envelope_decodes(const uint8_t *p, size_t len)
{
    ah_envelope_t e;
    return ah_envelope_decode(p, len, &e);
}

static bool board_decodes(const uint8_t *p, size_t len)
{
    ah_board_post_t b;
    return ah_board_post_check(p, len, &b);
}

static void test_tlv16_runs_end_alike_in_every_decoder(void)
{
    // The three [type][length u16][value] decoders share one reader: one or
    // two bytes after the last record are no record, and a record whose
    // value runs past the end refuses the whole payload.
    const uint8_t sync[] = {AH_SYNC_TLV_P, 0, 1, 7, AH_SYNC_TLV_M, 0, 4, 0, 0, 5, 0, AH_SYNC_TLV_DATA, 0, 1, 0xAB};
    const struct {
        bool (*decodes)(const uint8_t *p, size_t len);
        const uint8_t *payload;
        size_t len;
    } runs[] = {
        {sync_decodes, sync, sizeof(sync)},
        {envelope_decodes, VEC_COURIER_ENVELOPE.data, VEC_COURIER_ENVELOPE.len},
        {board_decodes, VEC_BOARDS[0].payload.data, VEC_BOARDS[0].payload.len},
    };
    TEST_ASSERT_TRUE(VEC_BOARDS[0].check);
    // A record of an unknown type claiming 5 bytes, none of them there.
    static const uint8_t overrun[] = {0x7F, 0x00, 0x05};
    static uint8_t buf[2048];
    for (size_t i = 0; i < COUNT(runs); ++i) {
        TEST_ASSERT_LESS_OR_EQUAL(sizeof(buf), runs[i].len + sizeof(overrun));
        memcpy(buf, runs[i].payload, runs[i].len);
        memcpy(buf + runs[i].len, overrun, sizeof(overrun));
        TEST_ASSERT_TRUE(runs[i].decodes(buf, runs[i].len));
        TEST_ASSERT_TRUE(runs[i].decodes(buf, runs[i].len + 1u));
        TEST_ASSERT_TRUE(runs[i].decodes(buf, runs[i].len + 2u));
        TEST_ASSERT_FALSE(runs[i].decodes(buf, runs[i].len + 3u));
        TEST_ASSERT_FALSE(runs[i].decodes(buf, runs[i].len - 1u));
    }
}

static void test_private_messages_round_trip_and_refuse_unknown_tlvs(void)
{
    const uint8_t body[] = {0x00, 2, 'i', 'd', 0x01, 2, 'h', 'i'};
    ah_private_message_t m;
    TEST_ASSERT_TRUE(ah_private_message_decode(body, sizeof(body), &m));
    TEST_ASSERT_EQUAL_MEMORY("hi", m.content, m.content_len);
    // Airhop and bitchat-ios both refuse a TLV of a type they do not know.
    const uint8_t extra[] = {0x00, 2, 'i', 'd', 0x01, 2, 'h', 'i', 0x02, 1, 'x'};
    TEST_ASSERT_FALSE(ah_private_message_decode(extra, sizeof(extra), &m));
    uint8_t out[16];
    const size_t n = ah_private_message_encode((const uint8_t *)"id", 2, (const uint8_t *)"hi", 2, out, sizeof(out));
    TEST_ASSERT_EQUAL(1u + sizeof(body), n);
    TEST_ASSERT_EQUAL_HEX8(AH_NOISE_PAYLOAD_PRIVATE_MESSAGE, out[0]);
    TEST_ASSERT_EQUAL_MEMORY(body, out + 1, sizeof(body));
}

static void test_a_failed_hash_is_never_an_identity(void)
{
    ah_frame_t f;
    TEST_ASSERT_TRUE(ah_frame_parse(VEC_PACKETS[0].unpadded.data, VEC_PACKETS[0].unpadded.len, &f));
    uint8_t id[AH_PACKET_ID_LEN];
    uint8_t peer[AH_PEER_ID_LEN];
    uint8_t tag[AH_COURIER_TAG_LEN];
    ah_test_sha256_fail(true);
    // Every failure would share one ID; such a packet is malformed instead.
    TEST_ASSERT_FALSE(ah_packet_id(&f, s_inf, id));
    TEST_ASSERT_FALSE(ah_peer_id_of(VEC_PEER_IDS[0].noise.data, peer));
    // The failure's own bytes bind nothing and match no mail.
    TEST_ASSERT_FALSE(ah_announce_binds(peer, VEC_PEER_IDS[0].noise.data));
    TEST_ASSERT_FALSE(ah_courier_tag(VEC_TAG_KEY.data, 1, tag));
    TEST_ASSERT_FALSE(ah_courier_tag_matches(VEC_TAG_KEY.data, 86400000ull, tag));
    // A handshake whose transcript cannot be hashed sends nothing.
    uint8_t s[AH_KEY_LEN] = {1};
    uint8_t s_pub[AH_KEY_LEN];
    const uint8_t e[AH_KEY_LEN] = {2};
    ah_x25519_public(s, s_pub);
    ah_noise_handshake_t hs;
    ah_noise_handshake_init(&hs, true, s, s_pub, e);
    uint8_t msg[AH_NOISE_MSG1_LEN];
    TEST_ASSERT_EQUAL(0, ah_noise_write(&hs, msg, sizeof(msg)));
    ah_test_sha256_fail(false);
    TEST_ASSERT_TRUE(ah_packet_id(&f, s_inf, id));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_packets_decode_and_sign_like_bitchat_ios);
    RUN_TEST(test_packet_id_is_stable_across_padding);
    RUN_TEST(test_decode_accepts_and_refuses_as_bitchat_ios);
    RUN_TEST(test_payload_ceilings_match_both_clients);
    RUN_TEST(test_padding_matches_message_padding);
    RUN_TEST(test_announces_decode_as_bitchat_ios);
    RUN_TEST(test_announce_round_trip_with_relay_tlvs);
    RUN_TEST(test_inflate_is_bounded_by_the_declared_size);
    RUN_TEST(test_a_small_window_inflates_what_fits_it);
    RUN_TEST(test_inflate_refuses_what_zlib_refuses);
    RUN_TEST(test_inflate_stops_one_byte_past_the_claim);
    RUN_TEST(test_fragments_parse_and_carry_their_parent);
    RUN_TEST(test_fragmenter_cuts_to_the_link_and_reassembles);
    RUN_TEST(test_fragments_carry_their_parents_recipient_never_its_route);
    RUN_TEST(test_peer_ids_derive_as_bitchat_ios);
    RUN_TEST(test_courier_tags_derive_as_bitchat_ios);
    RUN_TEST(test_courier_envelope_round_trips_byte_exact);
    RUN_TEST(test_courier_packet_signs_as_bitchat_ios);
    RUN_TEST(test_ota_manifests_as_the_spec_generator_signs_them);
    RUN_TEST(test_board_posts_as_the_spec_generator_signs_them);
    RUN_TEST(test_live_payloads_as_bitchat_decodes_them);
    RUN_TEST(test_a_source_route_names_the_next_hop);
    RUN_TEST(test_an_all_ones_recipient_is_a_broadcast);
    RUN_TEST(test_sync_request_keeps_a_valid_field_over_a_malformed_copy);
    RUN_TEST(test_tlv16_runs_end_alike_in_every_decoder);
    RUN_TEST(test_private_messages_round_trip_and_refuse_unknown_tlvs);
    RUN_TEST(test_a_failed_hash_is_never_an_identity);
    return UNITY_END();
}
