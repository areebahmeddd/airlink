// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The protocol core's building blocks, against the spec-derived vectors and
// the rules docs/PROTOCOL.md states.
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "ah_bytes.h"
#include "ah_clock.h"
#include "ah_courier.h"
#include "ah_crypto.h"
#include "ah_dedup.h"
#include "ah_frame.h"
#include "ah_gcs.h"
#include "ah_links.h"
#include "ah_noise.h"
#include "ah_payload.h"
#include "ah_peers.h"
#include "ah_reassembly.h"
#include "ah_relay.h"
#include "ah_sync.h"
#include "ah_sync_wire.h"
#include "ah_trunk_policy.h"
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
}

// ---- frames ----

static void test_spec_packets_id_preimage_and_signature(void)
{
    for (size_t i = 0; i < COUNT(VEC_SPEC_PACKETS); ++i) {
        const vec_spec_packet_t *v = &VEC_SPEC_PACKETS[i];
        ah_frame_t f;
        TEST_ASSERT_TRUE_MESSAGE(ah_frame_parse(v->frame.data, v->frame.len, &f), v->name);
        uint8_t id[AH_PACKET_ID_LEN];
        TEST_ASSERT_TRUE_MESSAGE(ah_packet_id(&f, s_inf, id), v->name);
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(v->packet_id.data, id, sizeof(id), v->name);
        static uint8_t pre[4096];
        size_t len = 0;
        TEST_ASSERT_TRUE(ah_frame_signing_preimage(&f, pre, sizeof(pre), &len));
        TEST_ASSERT_EQUAL_MESSAGE(v->preimage.len, len, v->name);
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(v->preimage.data, pre, len, v->name);
        TEST_ASSERT_TRUE_MESSAGE(ah_ed25519_verify(v->public_key.data, pre, len, f.signature), v->name);
    }
}

static void test_relay_changes_only_the_ttl_and_still_verifies(void)
{
    // A relayed copy is the received frame with one byte changed; the
    // signature, compressed bytes and padding all survive.
    for (size_t i = 0; i < COUNT(VEC_SPEC_PACKETS); ++i) {
        const vec_spec_packet_t *v = &VEC_SPEC_PACKETS[i];
        uint8_t copy[4096];
        memcpy(copy, v->frame.data, v->frame.len);
        copy[AH_OFF_TTL] = copy[AH_OFF_TTL] > 0 ? (uint8_t)(copy[AH_OFF_TTL] - 1u) : 0;
        ah_frame_t f;
        TEST_ASSERT_TRUE(ah_frame_parse(copy, v->frame.len, &f));
        static uint8_t pre[4096];
        size_t len = 0;
        TEST_ASSERT_TRUE(ah_frame_signing_preimage(&f, pre, sizeof(pre), &len));
        TEST_ASSERT_TRUE_MESSAGE(ah_ed25519_verify(v->public_key.data, pre, len, f.signature), v->name);
        TEST_ASSERT_EQUAL_MEMORY(v->frame.data + 3, copy + 3, v->frame.len - 3u);
        // Retagged as a sync reply: TTL 0 and IS_RSR, still verifying.
        copy[AH_OFF_TTL] = 0;
        copy[AH_OFF_FLAGS] |= AH_FLAG_IS_RSR;
        TEST_ASSERT_TRUE(ah_frame_parse(copy, v->frame.len, &f));
        TEST_ASSERT_TRUE(ah_frame_signing_preimage(&f, pre, sizeof(pre), &len));
        TEST_ASSERT_TRUE_MESSAGE(ah_ed25519_verify(v->public_key.data, pre, len, f.signature), v->name);
    }
}

// ---- primitives ----

// Hex text from a standard into bytes; returns the byte count.
static size_t unhex(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = 0;
    for (; hex[0] != '\0' && hex[1] != '\0' && n < cap; hex += 2) {
        unsigned byte = 0;
        for (int i = 0; i < 2; ++i) {
            const char c = hex[i];
            byte = byte << 4 | (unsigned)(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
        }
        out[n++] = (uint8_t)byte;
    }
    return n;
}

#define ASSERT_HEX(hex, bytes, len)                     \
    do {                                                \
        uint8_t want_[256];                             \
        const size_t n_ = unhex(hex, want_, sizeof(want_)); \
        TEST_ASSERT_EQUAL(n_, len);                     \
        TEST_ASSERT_EQUAL_MEMORY(want_, bytes, n_);     \
    } while (0)

// Each primitive the node's identity, packet IDs, signatures, Noise sessions,
// trunk tags and OTA manifests rest on, against the published vectors of its
// standard rather than a round trip, and one changed byte refused.
static void test_primitives_match_their_published_vectors(void)
{
    // SHA-256, FIPS 180-2 appendix B.1 and B.2 (the second streamed in pieces).
    uint8_t digest[AH_SHA256_LEN];
    TEST_ASSERT_TRUE(ah_sha256("abc", 3, digest));
    ASSERT_HEX("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", digest, sizeof(digest));
    static const char long_msg[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    ah_sha256_ctx_t ctx;
    ah_sha256_begin(&ctx);
    ah_sha256_update(&ctx, long_msg, 20);
    ah_sha256_update(&ctx, long_msg + 20, sizeof(long_msg) - 1u - 20u);
    TEST_ASSERT_TRUE(ah_sha256_finish(&ctx, digest));
    ASSERT_HEX("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", digest, sizeof(digest));

    // HMAC-SHA256, RFC 4231 test cases 1 and 6 (a key longer than a block is hashed first).
    uint8_t key[131];
    memset(key, 0x0b, 20);
    TEST_ASSERT_TRUE(ah_hmac_sha256(key, 20, (const uint8_t *)"Hi There", 8, digest));
    ASSERT_HEX("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", digest, sizeof(digest));
    memset(key, 0xaa, sizeof(key));
    static const char tc6[] = "Test Using Larger Than Block-Size Key - Hash Key First";
    TEST_ASSERT_TRUE(ah_hmac_sha256(key, sizeof(key), (const uint8_t *)tc6, sizeof(tc6) - 1u, digest));
    ASSERT_HEX("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", digest, sizeof(digest));

    // Ed25519, RFC 8032 section 7.1, tests 1 and 2.
    static const struct {
        const char *seed;
        const char *public_key;
        const char *msg;
        const char *signature;
    } ed[] = {
        {
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        },
        {
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        },
    };
    for (size_t i = 0; i < COUNT(ed); ++i) {
        uint8_t seed[AH_KEY_LEN];
        uint8_t msg[1];
        uint8_t secret[AH_ED25519_SECRET_LEN];
        uint8_t public_key[AH_KEY_LEN];
        uint8_t signature[AH_SIGNATURE_LEN];
        unhex(ed[i].seed, seed, sizeof(seed));
        const size_t msg_len = unhex(ed[i].msg, msg, sizeof(msg));
        ah_ed25519_keypair(seed, secret, public_key);
        ASSERT_HEX(ed[i].public_key, public_key, sizeof(public_key));
        ah_ed25519_sign(secret, msg, msg_len, signature);
        ASSERT_HEX(ed[i].signature, signature, sizeof(signature));
        TEST_ASSERT_TRUE(ah_ed25519_verify(public_key, msg, msg_len, signature));
        signature[i * 17u] ^= 0x01;
        TEST_ASSERT_FALSE(ah_ed25519_verify(public_key, msg, msg_len, signature));
    }

    // X25519, RFC 7748 section 6.1, and the low-order zero point refused.
    uint8_t alice[AH_KEY_LEN];
    uint8_t bob[AH_KEY_LEN];
    uint8_t alice_pub[AH_KEY_LEN];
    uint8_t bob_pub[AH_KEY_LEN];
    uint8_t shared[AH_KEY_LEN];
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", alice, sizeof(alice));
    unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", bob, sizeof(bob));
    ah_x25519_public(alice, alice_pub);
    ah_x25519_public(bob, bob_pub);
    ASSERT_HEX("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", alice_pub, sizeof(alice_pub));
    ASSERT_HEX("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", bob_pub, sizeof(bob_pub));
    TEST_ASSERT_TRUE(ah_x25519(alice, bob_pub, shared));
    ASSERT_HEX("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", shared, sizeof(shared));
    TEST_ASSERT_TRUE(ah_x25519(bob, alice_pub, shared));
    ASSERT_HEX("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", shared, sizeof(shared));
    static const uint8_t zero_point[AH_KEY_LEN] = {0};
    TEST_ASSERT_FALSE(ah_x25519(alice, zero_point, shared));

    // ChaCha20-Poly1305, RFC 8439 section 2.8.2.
    uint8_t aead_key[AH_KEY_LEN];
    uint8_t nonce[AH_AEAD_NONCE_LEN];
    uint8_t ad[12];
    for (size_t i = 0; i < sizeof(aead_key); ++i) {
        aead_key[i] = (uint8_t)(0x80u + i);
    }
    unhex("070000004041424344454647", nonce, sizeof(nonce));
    unhex("50515253c0c1c2c3c4c5c6c7", ad, sizeof(ad));
    static const char plain[] = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
                                "future, sunscreen would be it.";
    const size_t plain_len = sizeof(plain) - 1u;
    uint8_t sealed[sizeof(plain) - 1u + AH_AEAD_TAG_LEN];
    ah_aead_seal(aead_key, nonce, ad, sizeof(ad), (const uint8_t *)plain, plain_len, sealed);
    ASSERT_HEX("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b"
               "1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
               "3ff4def08e4b7a9de576d26586cec64b6116"
               "1ae10b594f09e26a7e902ecbd0600691",
               sealed, sizeof(sealed));
    uint8_t opened[sizeof(plain) - 1u];
    TEST_ASSERT_TRUE(ah_aead_open(aead_key, nonce, ad, sizeof(ad), sealed, plain_len, opened));
    TEST_ASSERT_EQUAL_MEMORY(plain, opened, plain_len);
    sealed[40] ^= 0x01;
    TEST_ASSERT_FALSE(ah_aead_open(aead_key, nonce, ad, sizeof(ad), sealed, plain_len, opened));
    sealed[40] ^= 0x01;
    ad[0] ^= 0x01;
    TEST_ASSERT_FALSE(ah_aead_open(aead_key, nonce, ad, sizeof(ad), sealed, plain_len, opened));
}

// ---- Noise ----

static void test_noise_xx_matches_the_spec_transcript(void)
{
    uint8_t si[32];
    uint8_t ei[32];
    uint8_t sr[32];
    uint8_t er[32];
    memset(si, 0x10, 32);
    memset(ei, 0x20, 32);
    memset(sr, 0x30, 32);
    memset(er, 0x40, 32);
    uint8_t si_pub[32];
    uint8_t sr_pub[32];
    ah_x25519_public(si, si_pub);
    ah_x25519_public(sr, sr_pub);

    ah_noise_handshake_t init;
    ah_noise_handshake_t resp;
    ah_noise_handshake_init(&init, true, si, si_pub, ei);
    ah_noise_handshake_init(&resp, false, sr, sr_pub, er);
    uint8_t msg[128];
    size_t len = ah_noise_write(&init, msg, sizeof(msg));
    TEST_ASSERT_EQUAL(AH_NOISE_MSG1_LEN, len);
    TEST_ASSERT_EQUAL_MEMORY(VEC_NOISE_MSG1.data, msg, len);
    TEST_ASSERT_TRUE(ah_noise_read(&resp, msg, len));
    len = ah_noise_write(&resp, msg, sizeof(msg));
    TEST_ASSERT_EQUAL(AH_NOISE_MSG2_LEN, len);
    TEST_ASSERT_EQUAL_MEMORY(VEC_NOISE_MSG2.data, msg, len);
    // One changed byte anywhere in a message past the first fails its read.
    for (size_t at = 0; at < len; at += 7u) {
        ah_noise_handshake_t copy = init;
        msg[at] ^= 0x01;
        TEST_ASSERT_FALSE(ah_noise_read(&copy, msg, len));
        msg[at] ^= 0x01;
    }
    TEST_ASSERT_TRUE(ah_noise_read(&init, msg, len));
    len = ah_noise_write(&init, msg, sizeof(msg));
    TEST_ASSERT_EQUAL(AH_NOISE_MSG3_LEN, len);
    TEST_ASSERT_EQUAL_MEMORY(VEC_NOISE_MSG3.data, msg, len);
    for (size_t at = 0; at < len; at += 7u) {
        ah_noise_handshake_t copy = resp;
        msg[at] ^= 0x01;
        TEST_ASSERT_FALSE(ah_noise_read(&copy, msg, len));
        msg[at] ^= 0x01;
    }
    TEST_ASSERT_TRUE(ah_noise_read(&resp, msg, len));

    ah_noise_sender_t itx;
    ah_noise_receiver_t irx;
    ah_noise_sender_t rtx;
    ah_noise_receiver_t rrx;
    uint8_t remote[32];
    TEST_ASSERT_TRUE(ah_noise_split(&init, &itx, &irx, remote));
    TEST_ASSERT_EQUAL_MEMORY(sr_pub, remote, 32);
    TEST_ASSERT_TRUE(ah_noise_split(&resp, &rtx, &rrx, remote));
    TEST_ASSERT_EQUAL_MEMORY(si_pub, remote, 32);

    uint8_t sealed[64];
    len = ah_noise_seal(&itx, (const uint8_t *)"hello relay", 11, sealed, sizeof(sealed));
    TEST_ASSERT_EQUAL(VEC_NOISE_TO_RESPONDER.len, len);
    TEST_ASSERT_EQUAL_MEMORY(VEC_NOISE_TO_RESPONDER.data, sealed, len);
    uint8_t plain[64];
    TEST_ASSERT_EQUAL(11, ah_noise_open(&rrx, sealed, len, plain, sizeof(plain)));
    TEST_ASSERT_EQUAL_MEMORY("hello relay", plain, 11);
    len = ah_noise_seal(&rtx, (const uint8_t *)"hello phone", 11, sealed, sizeof(sealed));
    TEST_ASSERT_EQUAL_MEMORY(VEC_NOISE_TO_INITIATOR.data, sealed, len);
}

static void test_noise_replay_window(void)
{
    ah_noise_sender_t tx = {0};
    ah_noise_receiver_t rx = {0};
    memset(tx.key, 7, 32);
    memset(rx.key, 7, 32);
    static uint8_t sealed[2048][32];
    uint8_t plain[16];
    const uint8_t body[4] = {1, 2, 3, 4};
    for (size_t i = 0; i < 2048; ++i) {
        TEST_ASSERT_EQUAL(4u + 4u + 16u, ah_noise_seal(&tx, body, sizeof(body), sealed[i], sizeof(sealed[i])));
    }
    for (size_t i = 0; i <= 100; ++i) {
        TEST_ASSERT_EQUAL(4, ah_noise_open(&rx, sealed[i], 24, plain, sizeof(plain)));
    }
    // bitchat's window shifts the wrong way, so 93 to 99 decrypt again there.
    for (size_t i = 0; i <= 100; ++i) {
        TEST_ASSERT_EQUAL_MESSAGE(SIZE_MAX, ah_noise_open(&rx, sealed[i], 24, plain, sizeof(plain)), "replayed");
    }
    // Out of order inside the window: once only.
    TEST_ASSERT_EQUAL(4, ah_noise_open(&rx, sealed[500], 24, plain, sizeof(plain)));
    TEST_ASSERT_EQUAL(4, ah_noise_open(&rx, sealed[300], 24, plain, sizeof(plain)));
    TEST_ASSERT_EQUAL(SIZE_MAX, ah_noise_open(&rx, sealed[300], 24, plain, sizeof(plain)));
    // Behind the window: refused.
    TEST_ASSERT_EQUAL(4, ah_noise_open(&rx, sealed[1600], 24, plain, sizeof(plain)));
    TEST_ASSERT_EQUAL(SIZE_MAX, ah_noise_open(&rx, sealed[400], 24, plain, sizeof(plain)));
    // A forgery changes nothing: the next genuine message still opens.
    uint8_t forged[32];
    memcpy(forged, sealed[1601], sizeof(forged));
    forged[10] ^= 1u;
    const ah_noise_receiver_t before = rx;
    TEST_ASSERT_EQUAL(SIZE_MAX, ah_noise_open(&rx, forged, 24, plain, sizeof(plain)));
    TEST_ASSERT_EQUAL_MEMORY(&before, &rx, sizeof(rx));
    TEST_ASSERT_EQUAL(4, ah_noise_open(&rx, sealed[1601], 24, plain, sizeof(plain)));
}

// ---- dedup, relaying and reassembly ----

static void test_dedup_window_and_classes(void)
{
    static uint8_t storage[64 * 1024];
    ah_dedup_t d;
    // 1000 IDs over five minutes, the message set's contract, in 2048 slots.
    ah_dedup_init(&d, storage, 2048, 300);
    uint8_t id[32];
    for (uint32_t i = 0; i < 1000; ++i) {
        ah_sha256(&i, sizeof(i), id);
        TEST_ASSERT_FALSE(ah_dedup_seen(&d, id, 10));
        ah_dedup_add(&d, id, 10);
    }
    uint32_t still = 0;
    for (uint32_t i = 0; i < 1000; ++i) {
        ah_sha256(&i, sizeof(i), id);
        still += ah_dedup_seen(&d, id, 309) ? 1u : 0u;
    }
    // Sized at twice its load, the set holds every ID for its full window.
    TEST_ASSERT_EQUAL(1000, still);
    TEST_ASSERT_EQUAL(0, d.evicted_live);
    ah_sha256("x", 1, id);
    ah_dedup_add(&d, id, 0);
    TEST_ASSERT_TRUE(ah_dedup_seen(&d, id, 299));
    TEST_ASSERT_FALSE(ah_dedup_seen(&d, id, 300));
    ah_dedup_forget(&d, id);
    TEST_ASSERT_FALSE(ah_dedup_seen(&d, id, 1));

    TEST_ASSERT_EQUAL(AH_DEDUP_FRAGMENT, ah_dedup_class_of(AH_TYPE_FRAGMENT));
    TEST_ASSERT_EQUAL(AH_DEDUP_LIVE, ah_dedup_class_of(AH_TYPE_VOICE_FRAME));
    TEST_ASSERT_EQUAL(AH_DEDUP_LIVE, ah_dedup_class_of(AH_TYPE_VIDEO_FRAME));
    TEST_ASSERT_EQUAL(AH_DEDUP_MESSAGE, ah_dedup_class_of(AH_TYPE_CHANNEL_MSG));
    TEST_ASSERT_EQUAL(AH_DEDUP_MESSAGE, ah_dedup_class_of(AH_TYPE_NOISE_ENCRYPTED));
}

static void test_live_set_covers_150_s_at_peak_rate(void)
{
    // Two video streams and voice through one node, as main/Kconfig.projbuild
    // sizes the set: 24 + 24 + 6 packets a second for the whole 150 s window
    // is 8,100 IDs, which the PSRAM-board default of 16,384 slots holds.
    static uint8_t storage[256 * 1024];
    ah_dedup_t d;
    TEST_ASSERT_LESS_OR_EQUAL(sizeof(storage), ah_dedup_storage_size(16384));
    ah_dedup_init(&d, storage, 16384, 150);
    uint8_t id[32];
    for (uint32_t i = 0; i < 8100; ++i) {
        ah_sha256(&i, sizeof(i), id);
        ah_dedup_add(&d, id, i / 54u);
    }
    for (uint32_t i = 0; i < 8100; ++i) {
        ah_sha256(&i, sizeof(i), id);
        TEST_ASSERT_TRUE(ah_dedup_seen(&d, id, 149));
    }
    TEST_ASSERT_EQUAL(0, d.evicted_live);
}

static ah_frame_t frame_of(uint8_t *buf, size_t cap, uint8_t type, uint8_t ttl, const uint8_t *recipient)
{
    static const uint8_t sender[8] = {9, 9, 9, 9, 9, 9, 9, 9};
    const uint8_t payload[4] = {1, 2, 3, 4};
    const ah_frame_fields_t fields = {.type = type, .ttl = ttl, .sender = sender, .recipient = recipient,
                                      .payload = payload, .payload_len = 4
                                     };
    const size_t len = ah_frame_encode(&fields, false, buf, cap);
    ah_frame_t f;
    ah_frame_parse(buf, len, &f);
    return f;
}

static void test_relay_policy_matches_the_phones(void)
{
    const uint8_t self[8] = {1, 1, 1, 1, 1, 1, 1, 1};
    const uint8_t other[8] = {2, 2, 2, 2, 2, 2, 2, 2};
    uint8_t buf[128];
    ah_frame_t f = frame_of(buf, sizeof(buf), AH_TYPE_CHANNEL_MSG, 7, NULL);
    ah_relay_decision_t d = ah_relay_decide(&f, 2, self, false);
    TEST_ASSERT_TRUE(d.relay);
    TEST_ASSERT_EQUAL(6, d.ttl);
    TEST_ASSERT_EQUAL(10, d.jitter_min_ms);
    TEST_ASSERT_EQUAL(40, d.jitter_max_ms);
    d = ah_relay_decide(&f, 4, self, false);
    TEST_ASSERT_EQUAL(5, d.ttl);
    TEST_ASSERT_EQUAL(60, d.jitter_min_ms);
    TEST_ASSERT_EQUAL(150, d.jitter_max_ms);
    d = ah_relay_decide(&f, 8, self, false);
    TEST_ASSERT_EQUAL(4, d.ttl);
    TEST_ASSERT_EQUAL(80, d.jitter_min_ms);
    d = ah_relay_decide(&f, 12, self, false);
    TEST_ASSERT_EQUAL(100, d.jitter_min_ms);
    TEST_ASSERT_EQUAL(220, d.jitter_max_ms);

    // Announces and urgent board posts keep the full TTL at mid degree.
    f = frame_of(buf, sizeof(buf), AH_TYPE_ANNOUNCE, 7, NULL);
    TEST_ASSERT_EQUAL(6, ah_relay_decide(&f, 4, self, false).ttl);
    f = frame_of(buf, sizeof(buf), AH_TYPE_BOARD_POST, 7, NULL);
    TEST_ASSERT_EQUAL(6, ah_relay_decide(&f, 4, self, true).ttl);
    TEST_ASSERT_EQUAL(5, ah_relay_decide(&f, 4, self, false).ttl);

    // Streams: 7, or 5 when dense, 8 to 25 ms.
    f = frame_of(buf, sizeof(buf), AH_TYPE_VOICE_FRAME, 7, NULL);
    d = ah_relay_decide(&f, 6, self, false);
    TEST_ASSERT_EQUAL(4, d.ttl);
    TEST_ASSERT_EQUAL(8, d.jitter_min_ms);
    TEST_ASSERT_EQUAL(25, d.jitter_max_ms);

    // Directed: min(ttl, 7) - 1 unclamped; handshakes 10 to 35 ms.
    f = frame_of(buf, sizeof(buf), AH_TYPE_NOISE_ENCRYPTED, 9, other);
    d = ah_relay_decide(&f, 12, self, false);
    TEST_ASSERT_EQUAL(6, d.ttl);
    TEST_ASSERT_EQUAL(20, d.jitter_min_ms);
    f = frame_of(buf, sizeof(buf), AH_TYPE_NOISE_HANDSHAKE, 7, other);
    d = ah_relay_decide(&f, 12, self, false);
    TEST_ASSERT_EQUAL(10, d.jitter_min_ms);
    TEST_ASSERT_EQUAL(35, d.jitter_max_ms);

    // Never: ttl <= 1, REQUEST_SYNC, OTA, ours, addressed to us.
    f = frame_of(buf, sizeof(buf), AH_TYPE_CHANNEL_MSG, 1, NULL);
    TEST_ASSERT_FALSE(ah_relay_decide(&f, 2, self, false).relay);
    f = frame_of(buf, sizeof(buf), AH_TYPE_REQUEST_SYNC, 7, NULL);
    TEST_ASSERT_FALSE(ah_relay_decide(&f, 2, self, false).relay);
    for (uint8_t type = AH_TYPE_OTA_MANIFEST; type <= AH_TYPE_OTA_STATUS; ++type) {
        f = frame_of(buf, sizeof(buf), type, 7, NULL);
        TEST_ASSERT_FALSE(ah_relay_decide(&f, 2, self, false).relay);
    }
    f = frame_of(buf, sizeof(buf), AH_TYPE_CHANNEL_MSG, 7, self);
    TEST_ASSERT_FALSE(ah_relay_decide(&f, 2, self, false).relay);
    const uint8_t nine[8] = {9, 9, 9, 9, 9, 9, 9, 9};
    TEST_ASSERT_FALSE(ah_relay_decide(&f, 2, nine, false).relay);

    // Unknown types relay as broadcasts: how Airhop's own types cross a bitchat mesh.
    f = frame_of(buf, sizeof(buf), 0x77, 7, NULL);
    TEST_ASSERT_TRUE(ah_relay_decide(&f, 2, self, false).relay);
    f = frame_of(buf, sizeof(buf), AH_TYPE_CHANNEL_MSG_AIRHOP, 7, NULL);
    TEST_ASSERT_TRUE(ah_relay_decide(&f, 2, self, false).relay);
}

static void test_reassembly_bounds(void)
{
    static ah_assembly_t slots[2];
    static uint8_t arena[2 * 1024];
    ah_reassembly_t r;
    ah_reassembly_init(&r, slots, 2, arena, 1024);
    const uint8_t sender[8] = {4};
    uint8_t stream[8] = {1};
    uint8_t data[200];
    memset(data, 0xAA, sizeof(data));
    ah_reassembled_t out;
    // The last piece first, then the rest: completes in order regardless.
    ah_fragment_t frag = {.stream_id = stream, .index = 2, .total = 3, .inner_type = 2, .data = data, .data_len = 50};
    TEST_ASSERT_EQUAL(AH_REASM_PENDING, ah_reassembly_add(&r, sender, &frag, 0, 0, &out));
    frag.index = 0;
    frag.data_len = 200;
    TEST_ASSERT_EQUAL(AH_REASM_PENDING, ah_reassembly_add(&r, sender, &frag, 0, 1, &out));
    frag.index = 1;
    TEST_ASSERT_EQUAL(AH_REASM_DONE, ah_reassembly_add(&r, sender, &frag, 1, 2, &out));
    TEST_ASSERT_EQUAL(450, out.len);
    TEST_ASSERT_FALSE(out.one_link);
    // A short non-final piece packs a slot for nothing: refused.
    frag.index = 0;
    frag.data_len = 10;
    TEST_ASSERT_EQUAL(AH_REASM_REFUSED, ah_reassembly_add(&r, sender, &frag, 0, 3, &out));
    // Too large for a slot: refused once the chunk size shows it.
    frag.total = 9;
    frag.data_len = 200;
    TEST_ASSERT_EQUAL(AH_REASM_REFUSED, ah_reassembly_add(&r, sender, &frag, 0, 4, &out));
    // Idle 30 s: dropped.
    stream[0] = 2;
    frag.total = 2;
    TEST_ASSERT_EQUAL(AH_REASM_PENDING, ah_reassembly_add(&r, sender, &frag, 0, 5, &out));
    const uint32_t evicted = r.evicted;
    ah_reassembly_expire(&r, 31000);
    TEST_ASSERT_EQUAL(evicted + 1u, r.evicted);
    // The stream's other piece now starts over instead of completing it.
    frag.index = 1;
    TEST_ASSERT_EQUAL(AH_REASM_PENDING, ah_reassembly_add(&r, sender, &frag, 0, 31001, &out));
}

// ---- link queues ----

static void test_link_queue_priority_and_live_deadline(void)
{
    static ah_link_t links[2];
    static ah_queued_t queues[2 * 4];
    static ah_frame_buf_t bufs[8];
    ah_links_t t;
    ah_links_init(&t, links, 2, queues, 4, bufs, 8);
    const uint16_t link = ah_links_open(&t, AH_LINK_BLE, 7, 512, NULL);
    const uint8_t data[1] = {0};
    uint16_t b[6];
    for (int i = 0; i < 6; ++i) {
        b[i] = ah_pool_copy(&t.pool, data, 1, 0);
    }
    TEST_ASSERT_TRUE(ah_links_enqueue(&t, link, b[0], AH_PRIO_BULK, 0, 0, 0));
    TEST_ASSERT_TRUE(ah_links_enqueue(&t, link, b[1], AH_PRIO_LIVE, 100, 0, 0));
    TEST_ASSERT_TRUE(ah_links_enqueue(&t, link, b[2], AH_PRIO_PUBLIC, 0, 0, 0));
    TEST_ASSERT_TRUE(ah_links_enqueue(&t, link, b[3], AH_PRIO_SYNC, 0, 0, 0));
    // Full: an announce evicts the sync reply; another sync reply is refused.
    TEST_ASSERT_TRUE(ah_links_enqueue(&t, link, b[4], AH_PRIO_ANNOUNCE, 0, 0, 0));
    TEST_ASSERT_FALSE(ah_links_enqueue(&t, link, b[5], AH_PRIO_SYNC, 0, 0, 0));
    TEST_ASSERT_EQUAL(b[4], ah_links_dequeue(&t, link, 50).buf);
    TEST_ASSERT_EQUAL(b[2], ah_links_dequeue(&t, link, 50).buf);
    // The live frame waited past its deadline: dropped unsent.
    TEST_ASSERT_EQUAL(b[0], ah_links_dequeue(&t, link, 200).buf);
    TEST_ASSERT_EQUAL(AH_BUF_NONE, ah_links_dequeue(&t, link, 200).buf);
    // The evicted sync reply, the refused one, and the expired live frame.
    TEST_ASSERT_EQUAL(3, t.dropped);
}

static void test_link_queues_share_the_pool_and_let_go_of_stale_frames(void)
{
    static ah_link_t links[3];
    static ah_queued_t queues[3 * 24];
    static ah_frame_buf_t bufs[24];
    ah_links_t t;
    ah_links_init(&t, links, 3, queues, 24, bufs, 24);
    const uint16_t a = ah_links_open(&t, AH_LINK_BLE, 1, 512, NULL);
    // A quarter of the pool per queue, whatever the queue was sized to.
    TEST_ASSERT_EQUAL(6, links[a].queue_cap);
    const uint8_t data[1] = {0};
    for (int i = 0; i < 8; ++i) {
        const uint16_t b = ah_pool_copy(&t.pool, data, 1, 0);
        ah_links_enqueue(&t, a, b, AH_PRIO_PUBLIC, 0, 0, 0);
        ah_pool_unref(&t.pool, b);
    }
    TEST_ASSERT_EQUAL(6, links[a].queued);
    TEST_ASSERT_EQUAL(6, t.pool.in_use);
    // A relay leaves the reserve to the node's own frames.
    uint16_t held[24];
    size_t n = 0;
    while ((held[n] = ah_pool_copy(&t.pool, data, 1, AH_POOL_RESERVE)) != AH_BUF_NONE) {
        n++;
    }
    TEST_ASSERT_EQUAL(AH_POOL_RESERVE, ah_pool_free(&t.pool));
    held[n] = ah_pool_copy(&t.pool, data, 1, 0);
    TEST_ASSERT_NOT_EQUAL(AH_BUF_NONE, held[n]);
    for (size_t i = 0; i <= n; ++i) {
        ah_pool_unref(&t.pool, held[i]);
    }
    // A link the transport keeps busy still lets go of what went stale.
    ah_links_expire(&t, a, AH_LINK_STALE_MS);
    TEST_ASSERT_EQUAL(6, links[a].queued);
    ah_links_expire(&t, a, AH_LINK_STALE_MS + 1);
    TEST_ASSERT_EQUAL(0, links[a].queued);
    TEST_ASSERT_EQUAL(0, t.pool.in_use);
    // Two refused at the full queue, six gone stale; a reopened slot keeps the count.
    TEST_ASSERT_EQUAL(8, t.dropped);
    ah_links_close(&t, a);
    TEST_ASSERT_EQUAL(a, ah_links_open(&t, AH_LINK_BLE, 2, 512, NULL));
    TEST_ASSERT_EQUAL(8, t.dropped);
}

// ---- the clock ----

// A sample from a phone, or node, of its own on each link.
static void vote(ah_clock_t *c, uint32_t link, bool node, uint64_t ts_ms, int64_t at_ms)
{
    ah_clock_sample(c, link, link, node, ts_ms, at_ms);
}

static void test_clock_states_and_hostile_claims(void)
{
    ah_clock_t c;
    const uint32_t a = 1;
    const uint32_t b = 2;
    const uint32_t evil = 3;
    const uint32_t evil2 = 4;
    const uint64_t real = 1780000000000ull;
    ah_clock_init(&c, 0);
    uint64_t now;
    TEST_ASSERT_FALSE(ah_clock_now(&c, 0, &now));
    TEST_ASSERT_FALSE(ah_clock_synced(&c));
    vote(&c, a, false, real + 1000, 1000);
    TEST_ASSERT_EQUAL(AH_CLOCK_TENTATIVE, c.state);
    TEST_ASSERT_FALSE(ah_clock_synced(&c));
    vote(&c, b, false, real + 2100, 2000);
    TEST_ASSERT_TRUE(ah_clock_synced(&c));
    TEST_ASSERT_TRUE(ah_clock_confirmed(&c));
    TEST_ASSERT_TRUE(ah_clock_now(&c, 2000, &now));
    TEST_ASSERT_UINT64_WITHIN(500, real + 2000, now);

    // One voice ten minutes ahead cannot move a synced clock.
    for (int i = 0; i < 20; ++i) {
        vote(&c, evil, false, real + 600000 + 3000 + (uint64_t)i * 15000, 3000 + i * 15000);
    }
    ah_clock_now(&c, 3000 + 19 * 15000, &now);
    TEST_ASSERT_UINT64_WITHIN(1000, real + 3000 + 19 * 15000, now);
    TEST_ASSERT_GREATER_THAN(0, c.rejected);

    // Two hostile links a day ahead against the two honest ones: an even split
    // never re-syncs the clock.
    for (int i = 0; i < 4; ++i) {
        const int64_t at = 300000 + i * 15000;
        vote(&c, evil, false, real + 86400000ull + (uint64_t)at, at);
        vote(&c, evil2, false, real + 86400000ull + (uint64_t)at, at);
        vote(&c, a, false, real + (uint64_t)at, at);
        vote(&c, b, false, real + (uint64_t)at, at);
    }
    ah_clock_now(&c, 345000, &now);
    TEST_ASSERT_UINT64_WITHIN(5000, real + 345000, now);

    // A lone phone confirms itself only across 30 s of consistent announces.
    ah_clock_init(&c, 0);
    vote(&c, a, false, real, 0);
    vote(&c, a, false, real + 15000, 15000);
    TEST_ASSERT_FALSE(ah_clock_synced(&c));
    vote(&c, a, false, real + 31000, 31000);
    TEST_ASSERT_TRUE(ah_clock_synced(&c));
    // Synced, but on one phone's word: nothing destructive rests on it.
    TEST_ASSERT_FALSE(ah_clock_confirmed(&c));

    // A restored floor refuses a phone claiming a time before it.
    ah_clock_init(&c, real);
    vote(&c, evil, false, real - 3600000, 0);
    TEST_ASSERT_EQUAL(AH_CLOCK_UNSYNCED, c.state);

    // A time near the top of the range is refused outright, so no offset sum
    // or difference can overflow (the sanitizers would abort on one).
    ah_clock_init(&c, 0);
    vote(&c, evil, false, (uint64_t)INT64_MAX - 1000u, 1000);
    vote(&c, a, false, 1, 2000);
    TEST_ASSERT_EQUAL(1, c.rejected);
    TEST_ASSERT_EQUAL(AH_CLOCK_TENTATIVE, c.state);
    (void)ah_clock_now(&c, 3000, &now);
}

static void test_one_device_never_confirms_or_walks_the_clock(void)
{
    ah_clock_t c;
    const uint64_t real = 1780000000000ull;
    const uint64_t phone = 0xA11CEull;
    uint64_t now;
    // One phone over two connections, then back on a third: one voice,
    // whichever link each announce comes over first, which confirms nothing.
    ah_clock_init(&c, 0);
    ah_clock_sample(&c, 1, phone, false, real, 0);
    ah_clock_sample(&c, 2, phone, false, real + 15000, 15000);
    TEST_ASSERT_FALSE(ah_clock_synced(&c));
    ah_clock_sample(&c, 1, phone, false, real + 31000, 31000);
    ah_clock_sample(&c, 3, phone, false, real + 46000, 46000);
    TEST_ASSERT_TRUE(ah_clock_synced(&c));
    TEST_ASSERT_FALSE(ah_clock_confirmed(&c));
    // A link that changes hands is one voice too: the second identity over
    // link 1 replaces the first.
    ah_clock_init(&c, 0);
    ah_clock_sample(&c, 1, phone, false, real, 0);
    ah_clock_sample(&c, 1, phone + 1u, false, real + 1000, 1000);
    TEST_ASSERT_FALSE(ah_clock_synced(&c));

    // Two phones confirm the clock and go. Two hostile links then agree on a
    // time 14 minutes past the node's, every second: it never jumps.
    ah_clock_init(&c, 0);
    vote(&c, 1, false, real + 1000, 1000);
    vote(&c, 2, false, real + 2000, 2000);
    TEST_ASSERT_TRUE(ah_clock_confirmed(&c));
    int64_t at = 11 * 60000;
    for (int i = 0; i < 100; ++i, at += 1000) {
        ah_clock_now(&c, at, &now);
        vote(&c, 3, false, now + 14 * 60000, at);
        vote(&c, 4, false, now + 14 * 60000, at);
    }
    ah_clock_now(&c, at, &now);
    TEST_ASSERT_UINT64_WITHIN(1000, real + (uint64_t)at, now);
    TEST_ASSERT_TRUE(ah_clock_confirmed(&c));

    // Once they are stale, one link announces just inside the agreement bound
    // of the node's own time, twenty times a second for ten minutes: the
    // clock moves no faster than a crystal drifts.
    at += 11 * 60000;
    for (int i = 0; i < 20 * 600; ++i, at += 50) {
        ah_clock_now(&c, at, &now);
        vote(&c, 5, false, now + 4900, at);
    }
    ah_clock_now(&c, at, &now);
    TEST_ASSERT_UINT64_WITHIN(1000, real + (uint64_t)at, now);
}

static void test_an_unconfirmed_clock_gives_way_once_nothing_backs_it(void)
{
    ah_clock_t c;
    const uint64_t real = 1780000000000ull;
    const uint64_t skewed = real + 3600000ull;
    uint64_t now;
    ah_clock_init(&c, 0);
    vote(&c, 1, false, skewed, 0);
    vote(&c, 1, false, skewed + 15000, 15000);
    vote(&c, 1, false, skewed + 31000, 31000);
    TEST_ASSERT_TRUE(ah_clock_synced(&c));
    // While the skewed phone is fresh, an honest one against it is an even
    // split: the clock holds.
    for (int64_t at = 40000; at <= 100000; at += 15000) {
        vote(&c, 1, false, skewed + (uint64_t)at, at);
        vote(&c, 2, false, real + (uint64_t)at, at);
    }
    ah_clock_now(&c, 100000, &now);
    TEST_ASSERT_UINT64_WITHIN(1000, skewed + 100000, now);
    // Once it is stale, the honest phone is followed, and trusted as soon as
    // it has held across 30 s, which it already has.
    int64_t at = 115000;
    for (; at <= 115000 + 11 * 60000; at += 15000) {
        vote(&c, 2, false, real + (uint64_t)at, at);
    }
    ah_clock_now(&c, at, &now);
    TEST_ASSERT_UINT64_WITHIN(1000, real + (uint64_t)at, now);
    TEST_ASSERT_TRUE(ah_clock_synced(&c));
    TEST_ASSERT_FALSE(ah_clock_confirmed(&c));
}

static void test_clock_hears_nodes_only_without_phones(void)
{
    ah_clock_t c;
    const uint64_t real = 1780000000000ull;
    uint64_t now;
    // With no phone at all, two agreeing nodes keep time, never confirmed.
    ah_clock_init(&c, 0);
    vote(&c, 3, true, real, 0);
    vote(&c, 4, true, real + 1000, 1000);
    TEST_ASSERT_TRUE(ah_clock_synced(&c));
    TEST_ASSERT_FALSE(ah_clock_confirmed(&c));
    ah_clock_now(&c, 1000, &now);
    TEST_ASSERT_UINT64_WITHIN(1000, real + 1000, now);

    // A phone that disagrees with second-hand time takes over: its time is
    // followed at once, and trusted only once it has held across 30 s.
    const uint64_t phone = real + 3600000ull;
    vote(&c, 5, false, phone + 2000, 2000);
    TEST_ASSERT_EQUAL(AH_CLOCK_TENTATIVE, c.state);
    ah_clock_now(&c, 2000, &now);
    TEST_ASSERT_UINT64_WITHIN(1000, phone + 2000, now);
    // While a phone's voice is fresh, the nodes have none, however many agree
    // and however long one of them holds steady.
    for (int64_t at = 3000; at <= 40000; at += 5000) {
        vote(&c, 3, true, real + (uint64_t)at, at);
        vote(&c, 4, true, real + (uint64_t)at, at);
    }
    TEST_ASSERT_EQUAL(AH_CLOCK_TENTATIVE, c.state);
    ah_clock_now(&c, 40000, &now);
    TEST_ASSERT_UINT64_WITHIN(1000, phone + 40000, now);
    vote(&c, 5, false, phone + 41000, 41000);
    vote(&c, 5, false, phone + 72000, 72000);
    TEST_ASSERT_TRUE(ah_clock_synced(&c));
    TEST_ASSERT_FALSE(ah_clock_confirmed(&c));
    ah_clock_now(&c, 72000, &now);
    TEST_ASSERT_UINT64_WITHIN(1000, phone + 72000, now);
}

// A confirmed node left alone for a week drifts past what two phones may
// differ by (12 s at 20 ppm); the first honest phone back still pulls it in.
// A hostile phone in the same place gains no more than that drift: one far
// past it is still refused.
static void test_a_lone_phone_pulls_back_a_clock_that_drifted_alone(void)
{
    const uint64_t real = 1780000000000ull;
    const int64_t week = 7LL * 24 * 60 * 60 * 1000;
    const int64_t drifted = 12100;
    ah_clock_t c;
    ah_clock_init(&c, 0);
    vote(&c, 1, false, real + 1000, 1000);
    vote(&c, 2, false, real + 2000, 2000);
    TEST_ASSERT_TRUE(ah_clock_confirmed(&c));

    // A week later the crystal has run slow: the phone's time is 12.1 s ahead.
    ah_clock_t hostile = c;
    uint64_t now;
    for (int i = 0; i < 40; ++i) {
        const int64_t at = week + i * 15000;
        vote(&c, 3, false, real + (uint64_t)at + (uint64_t)drifted, at);
    }
    const int64_t end = week + 39 * 15000;
    ah_clock_now(&c, end, &now);
    TEST_ASSERT_UINT64_WITHIN(1000, real + (uint64_t)end + (uint64_t)drifted, now);
    TEST_ASSERT_TRUE(ah_clock_confirmed(&c));

    // A phone a minute off after the same week is past any drift and refused.
    for (int i = 0; i < 40; ++i) {
        const int64_t at = week + i * 15000;
        vote(&hostile, 3, false, real + (uint64_t)at + 60000u, at);
    }
    ah_clock_now(&hostile, end, &now);
    TEST_ASSERT_UINT64_WITHIN(1000, real + (uint64_t)end, now);
}

static void test_the_saved_floor_never_runs_ahead_of_real_time(void)
{
    ah_clock_t c;
    const uint64_t real = 1780000000000ull;
    uint64_t floor;
    // With nothing restored, the first confirmed time is the floor, and an
    // unconfirmed one saves none.
    ah_clock_init(&c, 0);
    vote(&c, 1, false, real, 0);
    TEST_ASSERT_FALSE(ah_clock_floor(&c, 0, &floor));
    vote(&c, 2, false, real + 1000, 1000);
    TEST_ASSERT_TRUE(ah_clock_floor(&c, 1000, &floor));
    TEST_ASSERT_UINT64_WITHIN(500, real + 1000, floor);

    // Restored from an hour before, then two agreeing voices a day ahead: the
    // time they set holds until the next boot, but the floor is the restored
    // one plus the time since, so the next boot's honest phones are heard.
    const uint64_t restored = real - 3600000ull;
    ah_clock_init(&c, restored);
    vote(&c, 1, false, real + 86400000ull, 5000);
    vote(&c, 2, false, real + 86400000ull, 6000);
    TEST_ASSERT_TRUE(ah_clock_confirmed(&c));
    TEST_ASSERT_TRUE(ah_clock_floor(&c, 605000, &floor));
    TEST_ASSERT_TRUE(floor <= restored + 600000u);
    TEST_ASSERT_UINT64_WITHIN(1000, restored + 600000u, floor);
}

static void test_phones_agreeing_behind_a_wrong_floor_overrule_it(void)
{
    ah_clock_t c;
    const uint64_t real = 1780000000000ull;
    // A floor a year ahead, as a hostile majority at a fresh node's first
    // boot could have planted it.
    ah_clock_init(&c, real + 365ull * 86400000ull);
    // One honest phone alone is a rewind, refused, as is a relay node's time.
    vote(&c, 1, false, real, 0);
    vote(&c, 3, true, real, 100);
    TEST_ASSERT_EQUAL(AH_CLOCK_UNSYNCED, c.state);
    // A second phone agreeing with it: two phones behind the floor and none
    // ahead of it overrule it, and the floor is gone for this boot.
    vote(&c, 2, false, real + 1000, 1000);
    TEST_ASSERT_TRUE(ah_clock_synced(&c));
    TEST_ASSERT_EQUAL_UINT64(0, c.floor_wall_ms);
    uint64_t now = 0;
    TEST_ASSERT_TRUE(ah_clock_now(&c, 1000, &now));
    TEST_ASSERT_UINT64_WITHIN(1000, real + 1000, now);

    // Two phones behind the floor and two at it is no majority: the floor holds.
    ah_clock_init(&c, real);
    vote(&c, 1, false, real + 1000, 1000);
    vote(&c, 2, false, real + 1000, 1000);
    vote(&c, 3, false, real - 86400000ull, 2000);
    vote(&c, 4, false, real - 86400000ull, 2000);
    TEST_ASSERT_EQUAL_UINT64(real, c.floor_wall_ms);
    TEST_ASSERT_TRUE(ah_clock_now(&c, 2000, &now));
    TEST_ASSERT_UINT64_WITHIN(1000, real + 2000, now);
}

// ---- gossip sync ----

static void test_gcs_matches_the_spec_filter(void)
{
    static uint64_t hashes[1024];
    static uint32_t scratch[1024];
    static uint32_t values[4096];
    for (size_t i = 0; i < COUNT(VEC_GCS); ++i) {
        const vec_gcs_t *v = &VEC_GCS[i];
        for (size_t k = 0; k < v->count; ++k) {
            hashes[k] = ah_gcs_hash(v->ids.data + k * 16u);
        }
        // The node's budget, and one so small it holds a single ID: still
        // with the M = n << P a peer accepts, as bitchat-ios builds it.
        uint8_t data[AH_GCS_MAX_BYTES];
        TEST_ASSERT_LESS_OR_EQUAL(sizeof(data), v->max_bytes);
        ah_gcs_built_t built;
        TEST_ASSERT_TRUE(ah_gcs_build(hashes, v->count, data, v->max_bytes, scratch, &built));
        TEST_ASSERT_EQUAL(v->p, built.p);
        TEST_ASSERT_EQUAL_UINT32(v->m, built.m);
        TEST_ASSERT_EQUAL(v->included, built.included);
        TEST_ASSERT_EQUAL(v->data.len, built.data_len);
        if (built.data_len > 0) {
            TEST_ASSERT_EQUAL_MEMORY(v->data.data, data, built.data_len);
        }
        // Every included ID reads back as a member.
        const size_t n = ah_gcs_decode((uint8_t)built.p, built.m, data, built.data_len, values, COUNT(values));
        for (size_t k = 0; k < built.included; ++k) {
            TEST_ASSERT_TRUE(ah_gcs_contains(values, n, ah_gcs_bucket(hashes[k], built.m)));
        }
    }
}

static void test_sync_request_codec(void)
{
    const uint8_t data[] = {0xAB, 0xCD};
    const ah_sync_request_t req = {.p = 7, .m = 1280, .data = data, .data_len = 2, .has_types = true,
                                   .types = (1ull << 1) | (1ull << 24), .has_since = true, .since_ms = 1234
                                  };
    uint8_t out[64];
    const size_t len = ah_sync_request_encode(&req, out, sizeof(out));
    TEST_ASSERT_NOT_EQUAL(0, len);
    ah_sync_request_t back;
    TEST_ASSERT_TRUE(ah_sync_request_decode(out, len, &back));
    TEST_ASSERT_EQUAL(7, back.p);
    TEST_ASSERT_EQUAL_UINT32(1280, back.m);
    TEST_ASSERT_TRUE(back.has_types);
    TEST_ASSERT_EQUAL_UINT64(req.types, back.types);
    TEST_ASSERT_EQUAL_UINT64(1234, back.since_ms);
    // Types are little-endian with trailing zeros trimmed: bits 1 and 24 are 4 bytes.
    TEST_ASSERT_EQUAL_HEX8(0x04, out[3 + 1 + 3 + 4 + 3 + 2]);
    TEST_ASSERT_EQUAL(4, out[3 + 1 + 3 + 4 + 3 + 2 + 2]);
    // bitchat-ios refusals: m = 0, p outside 1..32, a filter over 1024 bytes.
    // P 7 (its value at [3]) and M 1 (its low byte at [10]), then an empty filter.
    static uint8_t raw[14u + AH_GCS_DATA_DECODE_MAX + 1u] = {
        AH_SYNC_TLV_P, 0, 1, 7, AH_SYNC_TLV_M, 0, 4, 0, 0, 0, 1, AH_SYNC_TLV_DATA,
    };
    TEST_ASSERT_TRUE(ah_sync_request_decode(raw, 14u, &back));
    raw[10] = 0;
    TEST_ASSERT_FALSE(ah_sync_request_decode(raw, 14u, &back));
    raw[10] = 1;
    raw[3] = 0;
    TEST_ASSERT_FALSE(ah_sync_request_decode(raw, 14u, &back));
    raw[3] = AH_GCS_P_MAX + 1u;
    TEST_ASSERT_FALSE(ah_sync_request_decode(raw, 14u, &back));
    raw[3] = AH_GCS_P_MAX;
    TEST_ASSERT_TRUE(ah_sync_request_decode(raw, 14u, &back));
    // The longest filter taken, then one byte more.
    ah_put_be16(raw + 12, AH_GCS_DATA_DECODE_MAX);
    TEST_ASSERT_TRUE(ah_sync_request_decode(raw, 14u + AH_GCS_DATA_DECODE_MAX, &back));
    ah_put_be16(raw + 12, AH_GCS_DATA_DECODE_MAX + 1u);
    TEST_ASSERT_FALSE(ah_sync_request_decode(raw, 14u + AH_GCS_DATA_DECODE_MAX + 1u, &back));
}

// A stored frame of `len` bytes whose every byte is its own timestamp's low byte.
static bool track_marked(ah_sync_t *s, uint64_t ts, size_t len, uint64_t now)
{
    static uint8_t bytes[512];
    memset(bytes, (uint8_t)ts, len);
    uint8_t sender[AH_PEER_ID_LEN] = {1};
    memcpy(sender + 1, &ts, 7);
    uint8_t id[AH_PACKET_ID_LEN] = {0};
    memcpy(id, &ts, sizeof(ts));
    const ah_frame_t f = {
        .bytes = bytes, .len = len, .type = AH_TYPE_CHANNEL_MSG, .timestamp_ms = ts, .sender = sender
    };
    return ah_sync_track(s, &f, id, now);
}

static bool store_intact(const ah_sync_store_t *st)
{
    for (uint16_t i = 0; i < st->count; ++i) {
        const ah_sync_entry_t *e = &st->entries[(st->head + i) % st->cap];
        for (uint32_t k = 0; k < e->len && !e->dead; ++k) {
            if (st->arena[e->offset + k] != (uint8_t)e->ts_ms) {
                return false;
            }
        }
    }
    return true;
}

static void test_sync_store_never_overwrites_what_it_holds(void)
{
    const uint64_t now = 1780000000000ull;
    const ah_sync_sizes_t sizes = {.entries = {8, 64, 8, 8}, .bytes = {1024, 1000, 1024, 1024}, .declined = 8};
    static uint8_t mem[64 * 1024];
    TEST_ASSERT_LESS_OR_EQUAL(sizeof(mem), ah_sync_memory(&sizes));
    ah_sync_t s;
    // Frames that fill the arena exactly: every wrap ends on an exact fit.
    ah_sync_init(&s, &sizes, mem);
    for (uint64_t i = 0; i < 40; ++i) {
        TEST_ASSERT_TRUE(track_marked(&s, now + i, 100, now + 40));
        TEST_ASSERT_TRUE_MESSAGE(store_intact(&s.stores[AH_STORE_MESSAGE]), "uniform lengths");
    }
    TEST_ASSERT_EQUAL(10, s.stores[AH_STORE_MESSAGE].count);
    // And lengths that vary, so the gaps the wraps leave vary too.
    ah_sync_init(&s, &sizes, mem);
    for (uint64_t i = 0; i < 2000; ++i) {
        TEST_ASSERT_TRUE(track_marked(&s, now + i, 20u + (size_t)(i * 37u) % 281u, now + 2000));
        TEST_ASSERT_TRUE_MESSAGE(store_intact(&s.stores[AH_STORE_MESSAGE]), "varied lengths");
    }
}

static void test_sync_cursor_rises_above_what_was_given_up(void)
{
    const uint64_t now = 1780000000000ull;
    const ah_sync_sizes_t sizes = {.entries = {8, 4, 8, 8}, .bytes = {1024, 4096, 1024, 1024}, .declined = 8};
    static uint8_t mem[64 * 1024];
    TEST_ASSERT_LESS_OR_EQUAL(sizeof(mem), ah_sync_memory(&sizes));
    ah_sync_t s;
    ah_sync_init(&s, &sizes, mem);
    // Two old messages arrive first, then four recent ones push them out.
    const uint64_t old = now - (uint64_t)AH_SYNC_MESSAGE_MAX_AGE_MS + 5000u;
    TEST_ASSERT_TRUE(track_marked(&s, old, 100, now + 10));
    TEST_ASSERT_TRUE(track_marked(&s, old + 1u, 100, now + 10));
    for (uint64_t i = 0; i < 4; ++i) {
        TEST_ASSERT_TRUE(track_marked(&s, now + i, 100, now + 10));
    }
    uint8_t payload[512];
    ah_sync_request_t req;
    const uint64_t types = 1ull << AH_SYNC_BIT_MESSAGE;
    size_t len = ah_sync_build_request(&s, types, now + 10, payload, sizeof(payload));
    TEST_ASSERT_TRUE(ah_sync_request_decode(payload, len, &req));
    // Everything held fits the filter: only what was given up is withheld,
    // not the history older than what is held.
    TEST_ASSERT_TRUE(req.has_since);
    TEST_ASSERT_EQUAL_UINT64(old + 2u, req.since_ms);
    // Once what was lost has aged out everywhere, the store asks for everything.
    const uint64_t later = now + 10000u;
    ah_sync_prune(&s, later);
    len = ah_sync_build_request(&s, types, later, payload, sizeof(payload));
    TEST_ASSERT_TRUE(ah_sync_request_decode(payload, len, &req));
    TEST_ASSERT_FALSE(req.has_since);
}

// A requester's cursor holds back messages older than it, never announces:
// they carry the keys the rest is verified against (bitchat-ios exempts them).
static void test_announces_are_served_past_the_cursor(void)
{
    const uint64_t now = 1780000000000ull;
    const ah_sync_sizes_t sizes = {.entries = {8, 8, 8, 8}, .bytes = {1024, 1024, 1024, 1024}, .declined = 8};
    static uint8_t mem[64 * 1024];
    ah_sync_t s;
    ah_sync_init(&s, &sizes, mem);
    static uint8_t bytes[2][100];
    const uint8_t types[2] = {AH_TYPE_ANNOUNCE, AH_TYPE_CHANNEL_MSG};
    for (size_t i = 0; i < 2u; ++i) {
        const uint8_t sender[AH_PEER_ID_LEN] = {(uint8_t)(i + 1u)};
        uint8_t id[AH_PACKET_ID_LEN] = {(uint8_t)(i + 1u)};
        const ah_frame_t f = {
            .bytes = bytes[i], .len = sizeof(bytes[i]), .type = types[i], .timestamp_ms = now - 30000u, .sender = sender
        };
        TEST_ASSERT_TRUE(ah_sync_track(&s, &f, id, now));
    }
    const ah_sync_request_t req = {
        .p = AH_GCS_P,
        .m = 1,
        .has_types = true,
        .types = (1ull << AH_SYNC_BIT_ANNOUNCE) | (1ull << AH_SYNC_BIT_MESSAGE),
        .has_since = true,
        .since_ms = now - 10000u,
    };
    ah_sync_ref_t refs[4];
    TEST_ASSERT_EQUAL(1, ah_sync_plan_reply(&s, &req, now, refs, COUNT(refs)));
    TEST_ASSERT_EQUAL(AH_STORE_ANNOUNCE, refs[0].store);
}

static void test_a_64_kib_packet_is_kept_and_served_whole(void)
{
    const uint64_t now = 1780000000000ull;
    const ah_sync_sizes_t sizes = {.entries = {2, 2, 2, 2}, .bytes = {1024, 70000, 1024, 1024}, .declined = 2};
    static uint8_t mem[96 * 1024];
    TEST_ASSERT_LESS_OR_EQUAL(sizeof(mem), ah_sync_memory(&sizes));
    ah_sync_t s;
    ah_sync_init(&s, &sizes, mem);
    // AH_BIG_SEND_KIB at its ceiling reassembles a packet of exactly 64 KiB.
    static uint8_t bytes[65536];
    memset(bytes, 0x5A, sizeof(bytes));
    const uint8_t sender[AH_PEER_ID_LEN] = {1};
    const uint8_t id[AH_PACKET_ID_LEN] = {7};
    const ah_frame_t f = {
        .bytes = bytes, .len = sizeof(bytes), .type = AH_TYPE_CHANNEL_MSG, .timestamp_ms = now, .sender = sender
    };
    TEST_ASSERT_TRUE(ah_sync_track(&s, &f, id, now));
    const ah_sync_request_t req = {.p = 7, .m = 1, .has_types = true, .types = 1ull << AH_SYNC_BIT_MESSAGE};
    ah_sync_ref_t ref;
    TEST_ASSERT_EQUAL(1, ah_sync_plan_reply(&s, &req, now, &ref, 1));
    size_t len = 0;
    TEST_ASSERT_NOT_NULL(ah_sync_entry_bytes(&s, ref, &len));
    TEST_ASSERT_EQUAL(sizeof(bytes), len);
}

// ---- courier mail ----

static size_t envelope(uint8_t *out, uint8_t tag_byte, uint64_t expiry, uint8_t copies)
{
    uint8_t tag[16];
    memset(tag, tag_byte, sizeof(tag));
    uint8_t ct[40];
    memset(ct, tag_byte ^ 0x5A, sizeof(ct));
    const ah_envelope_t env = {.tag = tag, .expiry_ms = expiry, .ciphertext = ct, .ciphertext_len = sizeof(ct),
                               .copies = copies
                              };
    return ah_envelope_encode(&env, out, 256);
}

static void test_courier_lifetime_quota_and_merge(void)
{
    static ah_mail_t slots[4];
    static uint8_t arena[2048];
    ah_courier_t c;
    ah_courier_init(&c, slots, 4, arena, sizeof(arena), 2, NULL, NULL);
    const uint64_t now = 1780000000000ull;
    const uint8_t alice[8] = {1};
    const uint8_t bob[8] = {2};
    uint8_t buf[256];
    uint16_t slot;
    // Past 24 h plus 1 h of slack: refused, not clamped.
    size_t len = envelope(buf, 1, now + 25 * 3600000ull + 1, 4);
    TEST_ASSERT_EQUAL(AH_DEPOSIT_REFUSED, ah_courier_deposit(&c, buf, len, alice, now, &slot));
    // Expired already: refused.
    len = envelope(buf, 1, now, 4);
    TEST_ASSERT_EQUAL(AH_DEPOSIT_REFUSED, ah_courier_deposit(&c, buf, len, alice, now, &slot));
    // Bob's copy of an envelope Alice left merges into hers.
    len = envelope(buf, 1, now + 25 * 3600000ull, 4);
    TEST_ASSERT_EQUAL(AH_DEPOSIT_STORED, ah_courier_deposit(&c, buf, len, alice, now, &slot));
    TEST_ASSERT_EQUAL(AH_DEPOSIT_MERGED, ah_courier_deposit(&c, buf, len, bob, now, &slot));
    len = envelope(buf, 2, now + 3600000ull, 4);
    TEST_ASSERT_EQUAL(AH_DEPOSIT_STORED, ah_courier_deposit(&c, buf, len, alice, now, &slot));
    len = envelope(buf, 3, now + 7200000ull, 4);
    TEST_ASSERT_EQUAL(AH_DEPOSIT_STORED, ah_courier_deposit(&c, buf, len, bob, now, &slot));
    // Alice's third deposit is past her quota: refused, and hers are kept.
    len = envelope(buf, 4, now + 7200000ull, 4);
    TEST_ASSERT_EQUAL(AH_DEPOSIT_FULL, ah_courier_deposit(&c, buf, len, alice, now, &slot));
    size_t held = 0;
    for (int i = 0; i < 4; ++i) {
        held += slots[i].in_use ? 1u : 0u;
    }
    TEST_ASSERT_EQUAL(3, held);
    len = envelope(buf, 3, now + 7200000ull, 4);
    TEST_ASSERT_EQUAL(AH_DEPOSIT_MERGED, ah_courier_deposit(&c, buf, len, bob, now, &slot));
    // Spraying hands over half and remembers the carrier.
    TEST_ASSERT_EQUAL(2, ah_courier_spray_share(&c, slot));
    ah_courier_spray_commit(&c, slot, bob, 2);
    TEST_ASSERT_TRUE(ah_courier_sprayed_to(&c, slot, bob));
    TEST_ASSERT_EQUAL(2, slots[slot].copies);
    TEST_ASSERT_EQUAL(3, ah_courier_expire(&c, now + 30 * 3600000ull));
}

static uint32_t s_gone[16];
static size_t s_gone_count;

static void note_gone(void *ctx, uint32_t record)
{
    (void)ctx;
    s_gone[s_gone_count++] = record;
}

static void test_courier_reports_every_envelope_that_leaves(void)
{
    static ah_mail_t slots[2];
    static uint8_t arena[2048];
    ah_courier_t c;
    s_gone_count = 0;
    ah_courier_init(&c, slots, 2, arena, sizeof(arena), 1, note_gone, NULL);
    const uint64_t now = 1780000000000ull;
    const uint8_t alice[8] = {1};
    const uint8_t bob[8] = {2};
    uint8_t buf[256];
    uint16_t slot;
    size_t len = envelope(buf, 1, now + 3600000ull, 4);
    TEST_ASSERT_EQUAL(AH_DEPOSIT_STORED, ah_courier_deposit(&c, buf, len, alice, now, &slot));
    // Alice's second is past her quota: refused, so nothing leaves.
    len = envelope(buf, 2, now + 7200000ull, 4);
    TEST_ASSERT_EQUAL(AH_DEPOSIT_FULL, ah_courier_deposit(&c, buf, len, alice, now, &slot));
    TEST_ASSERT_EQUAL(0, s_gone_count);
    len = envelope(buf, 3, now + 7200000ull, 4);
    TEST_ASSERT_EQUAL(AH_DEPOSIT_STORED, ah_courier_deposit(&c, buf, len, bob, now, &slot));
    // Delivered and expired both report.
    ah_courier_retire(&c, slot);
    TEST_ASSERT_EQUAL(1, s_gone_count);
    TEST_ASSERT_EQUAL(2, s_gone[0]);
    TEST_ASSERT_EQUAL(1, ah_courier_expire(&c, now + 8000000ull));
    TEST_ASSERT_EQUAL(2, s_gone_count);
    TEST_ASSERT_EQUAL(1, s_gone[1]);

    // A restore never evicts: past the depositor's quota, or the slots, it is refused.
    const uint64_t carol = 7;
    len = envelope(buf, 4, now + 3600000ull, 1);
    TEST_ASSERT_TRUE(ah_courier_restore(&c, 40, buf, len, carol, 0));
    len = envelope(buf, 5, now + 3600000ull, 1);
    TEST_ASSERT_FALSE(ah_courier_restore(&c, 41, buf, len, carol, 0));
    TEST_ASSERT_TRUE(ah_courier_restore(&c, 42, buf, len, carol + 1u, 0));
    len = envelope(buf, 6, now + 3600000ull, 1);
    TEST_ASSERT_FALSE(ah_courier_restore(&c, 43, buf, len, carol + 2u, 0));
    TEST_ASSERT_EQUAL(2, s_gone_count);
    TEST_ASSERT_EQUAL(3, c.refused);
}

static void test_a_full_mailbox_refuses_rather_than_evicting(void)
{
    static ah_mail_t slots[2];
    static uint8_t arena[2048];
    ah_courier_t c;
    ah_courier_init(&c, slots, 2, arena, sizeof(arena), 1, NULL, NULL);
    const uint64_t now = 1780000000000ull;
    const uint8_t alice[8] = {1};
    const uint8_t bob[8] = {2};
    const uint8_t carol[8] = {3};
    uint8_t buf[256];
    uint16_t slot;
    size_t len = envelope(buf, 1, now + 3600000ull, 4);
    TEST_ASSERT_EQUAL(AH_DEPOSIT_STORED, ah_courier_deposit(&c, buf, len, alice, now, &slot));
    len = envelope(buf, 2, now + 7200000ull, 4);
    TEST_ASSERT_EQUAL(AH_DEPOSIT_STORED, ah_courier_deposit(&c, buf, len, bob, now, &slot));
    // A newcomer finds it full: refused, and nobody's mail goes for it.
    len = envelope(buf, 3, now + 7200000ull, 4);
    TEST_ASSERT_EQUAL(AH_DEPOSIT_FULL, ah_courier_deposit(&c, buf, len, carol, now, &slot));
    TEST_ASSERT_TRUE(slots[0].in_use && slots[1].in_use);
    // Alice, at her quota, is refused too, and her first is kept.
    len = envelope(buf, 4, now + 7200000ull, 4);
    TEST_ASSERT_EQUAL(AH_DEPOSIT_FULL, ah_courier_deposit(&c, buf, len, alice, now, &slot));
    TEST_ASSERT_TRUE(slots[0].in_use && slots[1].in_use);
    TEST_ASSERT_EQUAL(1, slots[0].record);
    TEST_ASSERT_EQUAL(2, c.refused);
}

static void test_mail_held_past_any_lifetime_leaves_with_no_clock(void)
{
    // No phones ever agree on the time, so wall-clock expiry never runs: mail
    // still leaves once held longer than any envelope may live, by the node's
    // own monotonic time, and the full mailbox takes deposits again.
    static ah_mail_t slots[1];
    static uint8_t arena[1024];
    ah_courier_t c;
    ah_courier_init(&c, slots, 1, arena, sizeof(arena), 1, NULL, NULL);
    const uint64_t now = 1780000000000ull;
    const uint8_t alice[8] = {1};
    const uint8_t bob[8] = {2};
    uint8_t buf[256];
    uint16_t slot;
    size_t len = envelope(buf, 1, now + 3600000ull, 4);
    TEST_ASSERT_EQUAL(AH_DEPOSIT_STORED, ah_courier_deposit(&c, buf, len, alice, now, &slot));
    const int64_t limit = AH_COURIER_LIFETIME_MS + AH_COURIER_EXPIRY_SLACK_MS;
    TEST_ASSERT_EQUAL(0, ah_courier_expire_held(&c, 5000));
    TEST_ASSERT_EQUAL(0, ah_courier_expire_held(&c, 5000 + limit));
    len = envelope(buf, 2, now + 3600000ull, 4);
    TEST_ASSERT_EQUAL(AH_DEPOSIT_FULL, ah_courier_deposit(&c, buf, len, bob, now, &slot));
    TEST_ASSERT_EQUAL(1, ah_courier_expire_held(&c, 5001 + limit));
    TEST_ASSERT_EQUAL(AH_DEPOSIT_STORED, ah_courier_deposit(&c, buf, len, bob, now, &slot));
}

static void test_a_restored_budget_never_rises_on_a_merge(void)
{
    static ah_mail_t slots[2];
    static uint8_t arena[2048];
    ah_courier_t c;
    ah_courier_init(&c, slots, 2, arena, sizeof(arena), 2, NULL, NULL);
    const uint64_t now = 1780000000000ull;
    const uint8_t alice[8] = {1};
    uint8_t buf[256];
    uint16_t slot;
    // Never sprayed: a copy with a larger budget raises it, and says so.
    size_t len = envelope(buf, 1, now + 3600000ull, 1);
    TEST_ASSERT_EQUAL(AH_DEPOSIT_STORED, ah_courier_deposit(&c, buf, len, alice, now, &slot));
    len = envelope(buf, 1, now + 3600000ull, 4);
    TEST_ASSERT_EQUAL(AH_DEPOSIT_RAISED, ah_courier_deposit(&c, buf, len, alice, now, &slot));
    TEST_ASSERT_EQUAL(4, slots[slot].copies);
    // Restored, it may have been sprayed before the reboot: never raised.
    len = envelope(buf, 2, now + 3600000ull, 2);
    TEST_ASSERT_TRUE(ah_courier_restore(&c, 9, buf, len, 7, 0));
    len = envelope(buf, 2, now + 3600000ull, 8);
    TEST_ASSERT_EQUAL(AH_DEPOSIT_MERGED, ah_courier_deposit(&c, buf, len, alice, now, &slot));
    TEST_ASSERT_EQUAL(2, slots[slot].copies);
}

static void test_courier_matches_mail_by_any_candidate_tag(void)
{
    const uint64_t now = (uint64_t)VEC_COURIER_EPOCH_DAY * 86400000ull + 5000u;
    uint8_t tags[AH_COURIER_CANDIDATE_TAGS][AH_COURIER_TAG_LEN];
    TEST_ASSERT_TRUE(ah_courier_candidate_tags(VEC_COURIER_NOISE_KEY.data, now, tags));
    TEST_ASSERT_EQUAL_MEMORY(VEC_COURIER_TAG.data, tags[0], AH_COURIER_TAG_LEN);
    uint8_t day[AH_COURIER_TAG_LEN];
    TEST_ASSERT_TRUE(ah_courier_tag(VEC_COURIER_NOISE_KEY.data, VEC_COURIER_EPOCH_DAY - 1u, day));
    TEST_ASSERT_EQUAL_MEMORY(day, tags[1], AH_COURIER_TAG_LEN);
    TEST_ASSERT_TRUE(ah_courier_tag(VEC_COURIER_NOISE_KEY.data, VEC_COURIER_EPOCH_DAY + 1u, day));
    TEST_ASSERT_EQUAL_MEMORY(day, tags[2], AH_COURIER_TAG_LEN);
    // A held envelope matches by any of the three.
    static ah_mail_t slots[1];
    static uint8_t arena[512];
    ah_courier_t c;
    ah_courier_init(&c, slots, 1, arena, sizeof(arena), 1, NULL, NULL);
    uint8_t ct[40];
    memset(ct, 0x5A, sizeof(ct));
    const ah_envelope_t env = {.tag = tags[2], .expiry_ms = now + 3600000ull, .ciphertext = ct,
                               .ciphertext_len = sizeof(ct), .copies = 1
                              };
    uint8_t buf[256];
    const size_t len = ah_envelope_encode(&env, buf, sizeof(buf));
    const uint8_t alice[8] = {1};
    uint16_t slot;
    TEST_ASSERT_EQUAL(AH_DEPOSIT_STORED, ah_courier_deposit(&c, buf, len, alice, now, &slot));
    TEST_ASSERT_TRUE(ah_courier_is_for(&c, slot, tags));
    tags[2][0] ^= 0x01u;
    TEST_ASSERT_FALSE(ah_courier_is_for(&c, slot, tags));
}

// ---- the trunk policy ----

static void test_trunk_carries_text_only(void)
{
    ah_trunk_policy_t p;
    ah_trunk_policy_init(&p, 300000);
    uint8_t buf[128];
    const uint8_t to[8] = {5, 5, 5, 5, 5, 5, 5, 5};
    ah_frame_t f = frame_of(buf, sizeof(buf), AH_TYPE_CHANNEL_MSG, 7, NULL);
    TEST_ASSERT_TRUE(ah_trunk_policy_admit(&p, &f, 0, 0, 0));
    static const uint8_t never[] = {AH_TYPE_VOICE_FRAME, AH_TYPE_VIDEO_FRAME, AH_TYPE_FILE_TRANSFER,
                                    AH_TYPE_REQUEST_SYNC, AH_TYPE_PREKEY_BUNDLE, AH_TYPE_OTA_CHUNK,
                                    AH_TYPE_NOSTR_CARRIER, 0x77
                                   };
    for (size_t i = 0; i < sizeof(never); ++i) {
        f = frame_of(buf, sizeof(buf), never[i], 7, NULL);
        TEST_ASSERT_FALSE(ah_trunk_policy_admit(&p, &f, 0, 0, 0));
    }
    // Sync replies never cross, whatever they carry.
    f = frame_of(buf, sizeof(buf), AH_TYPE_CHANNEL_MSG, 0, NULL);
    f.flags |= AH_FLAG_IS_RSR;
    TEST_ASSERT_FALSE(ah_trunk_policy_admit(&p, &f, 0, 0, 0));
    // Announces once per origin per interval.
    f = frame_of(buf, sizeof(buf), AH_TYPE_ANNOUNCE, 7, NULL);
    TEST_ASSERT_TRUE(ah_trunk_policy_admit(&p, &f, 0, 0, 1000));
    TEST_ASSERT_FALSE(ah_trunk_policy_admit(&p, &f, 0, 0, 2000));
    TEST_ASSERT_TRUE(ah_trunk_policy_admit(&p, &f, 0, 0, 302000));
    // Encrypted DMs: one Bluetooth frame at most, refused without spending a
    // token, then a burst of four and one per 15 s.
    f = frame_of(buf, sizeof(buf), AH_TYPE_NOISE_ENCRYPTED, 7, to);
    const size_t len = f.len;
    f.len = AH_BLE_FRAME_MAX + 1u;
    TEST_ASSERT_FALSE(ah_trunk_policy_admit(&p, &f, 0, 0, 10));
    f.len = len;
    for (int i = 0; i < 4; ++i) {
        TEST_ASSERT_TRUE(ah_trunk_policy_admit(&p, &f, 0, 0, 10));
    }
    TEST_ASSERT_FALSE(ah_trunk_policy_admit(&p, &f, 0, 0, 20));
    TEST_ASSERT_TRUE(ah_trunk_policy_admit(&p, &f, 0, 0, 15100));
    // Fragments: a few of a text type, never a file's hundreds.
    f = frame_of(buf, sizeof(buf), AH_TYPE_FRAGMENT, 7, NULL);
    TEST_ASSERT_TRUE(ah_trunk_policy_admit(&p, &f, AH_TYPE_CHANNEL_MSG, 3, 0));
    TEST_ASSERT_FALSE(ah_trunk_policy_admit(&p, &f, AH_TYPE_CHANNEL_MSG, 4, 0));
    TEST_ASSERT_FALSE(ah_trunk_policy_admit(&p, &f, AH_TYPE_FILE_TRANSFER, 2, 0));
}

static void test_trunk_presence_never_crowds_out_its_own_throttle(void)
{
    ah_trunk_policy_t p;
    ah_trunk_policy_init(&p, 300000);
    uint8_t buf[128];
    ah_frame_t f = frame_of(buf, sizeof(buf), AH_TYPE_ANNOUNCE, 7, NULL);
    uint8_t ids[AH_TRUNK_POLICY_ORIGINS + 1u][AH_PEER_ID_LEN];
    for (size_t i = 0; i <= AH_TRUNK_POLICY_ORIGINS; ++i) {
        memset(ids[i], (int)(i + 1u), AH_PEER_ID_LEN);
    }
    // Every origin inside its interval: a new one is refused rather than let
    // in by forgetting one, which would let that one straight back in.
    for (size_t i = 0; i < AH_TRUNK_POLICY_ORIGINS; ++i) {
        f.sender = ids[i];
        TEST_ASSERT_TRUE(ah_trunk_policy_admit(&p, &f, 0, 0, 1000));
    }
    f.sender = ids[AH_TRUNK_POLICY_ORIGINS];
    TEST_ASSERT_FALSE(ah_trunk_policy_admit(&p, &f, 0, 0, 2000));
    f.sender = ids[0];
    TEST_ASSERT_FALSE(ah_trunk_policy_admit(&p, &f, 0, 0, 2000));
    f.sender = ids[AH_TRUNK_POLICY_ORIGINS];
    TEST_ASSERT_TRUE(ah_trunk_policy_admit(&p, &f, 0, 0, 301000));

    // A periodic announce may still wait behind text, so it spares no message
    // the announce ahead of it; one sent first does, for 45 s.
    ah_trunk_policy_init(&p, 300000);
    f.sender = ids[0];
    TEST_ASSERT_TRUE(ah_trunk_policy_admit(&p, &f, 0, 0, 1000));
    TEST_ASSERT_TRUE(ah_trunk_policy_needs_announce(&p, ids[0], 1000));
    ah_trunk_policy_note_ahead(&p, ids[0], 2000);
    TEST_ASSERT_FALSE(ah_trunk_policy_needs_announce(&p, ids[0], 2000));
    TEST_ASSERT_TRUE(ah_trunk_policy_needs_announce(&p, ids[0], 48000));
    // And one sent first stands in for the periodic one.
    ah_trunk_policy_note_ahead(&p, ids[1], 2000);
    f.sender = ids[1];
    TEST_ASSERT_FALSE(ah_trunk_policy_admit(&p, &f, 0, 0, 3000));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_spec_packets_id_preimage_and_signature);
    RUN_TEST(test_relay_changes_only_the_ttl_and_still_verifies);
    RUN_TEST(test_primitives_match_their_published_vectors);
    RUN_TEST(test_noise_xx_matches_the_spec_transcript);
    RUN_TEST(test_noise_replay_window);
    RUN_TEST(test_dedup_window_and_classes);
    RUN_TEST(test_live_set_covers_150_s_at_peak_rate);
    RUN_TEST(test_relay_policy_matches_the_phones);
    RUN_TEST(test_reassembly_bounds);
    RUN_TEST(test_link_queue_priority_and_live_deadline);
    RUN_TEST(test_link_queues_share_the_pool_and_let_go_of_stale_frames);
    RUN_TEST(test_clock_states_and_hostile_claims);
    RUN_TEST(test_one_device_never_confirms_or_walks_the_clock);
    RUN_TEST(test_an_unconfirmed_clock_gives_way_once_nothing_backs_it);
    RUN_TEST(test_clock_hears_nodes_only_without_phones);
    RUN_TEST(test_a_lone_phone_pulls_back_a_clock_that_drifted_alone);
    RUN_TEST(test_the_saved_floor_never_runs_ahead_of_real_time);
    RUN_TEST(test_phones_agreeing_behind_a_wrong_floor_overrule_it);
    RUN_TEST(test_gcs_matches_the_spec_filter);
    RUN_TEST(test_sync_request_codec);
    RUN_TEST(test_sync_store_never_overwrites_what_it_holds);
    RUN_TEST(test_sync_cursor_rises_above_what_was_given_up);
    RUN_TEST(test_announces_are_served_past_the_cursor);
    RUN_TEST(test_a_64_kib_packet_is_kept_and_served_whole);
    RUN_TEST(test_courier_lifetime_quota_and_merge);
    RUN_TEST(test_courier_reports_every_envelope_that_leaves);
    RUN_TEST(test_a_full_mailbox_refuses_rather_than_evicting);
    RUN_TEST(test_mail_held_past_any_lifetime_leaves_with_no_clock);
    RUN_TEST(test_a_restored_budget_never_rises_on_a_merge);
    RUN_TEST(test_courier_matches_mail_by_any_candidate_tag);
    RUN_TEST(test_trunk_carries_text_only);
    RUN_TEST(test_trunk_presence_never_crowds_out_its_own_throttle);
    return UNITY_END();
}
