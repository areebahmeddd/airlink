// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Every payload parser the node runs on bytes off the air, from one input:
// the first byte picks the parser, the rest is the hostile payload. Two more
// selectors read Noise messages from a peer, and build a filter of the node's
// own to read back.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ah_announce.h"
#include "ah_board_post.h"
#include "ah_bytes.h"
#include "ah_courier_wire.h"
#include "ah_dm_wire.h"
#include "ah_fragment.h"
#include "ah_gcs.h"
#include "ah_live.h"
#include "ah_noise.h"
#include "ah_ota_manifest.h"
#include "ah_sync_wire.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

// Each handshake stage just before it reads the peer's next message, and the
// responder's receiver once it has opened nonces 5 and 1000, all from the
// spec generator's keys, so seeds cut from its transcript pass and their
// mutants reach the checks behind the tag.
static ah_noise_handshake_t s_stage[3];
static ah_noise_receiver_t s_receiver;

static void noise_setup(void)
{
    uint8_t si[AH_KEY_LEN];
    uint8_t ei[AH_KEY_LEN];
    uint8_t sr[AH_KEY_LEN];
    uint8_t er[AH_KEY_LEN];
    memset(si, 0x10, sizeof(si));
    memset(ei, 0x20, sizeof(ei));
    memset(sr, 0x30, sizeof(sr));
    memset(er, 0x40, sizeof(er));
    uint8_t si_pub[AH_KEY_LEN];
    uint8_t sr_pub[AH_KEY_LEN];
    ah_x25519_public(si, si_pub);
    ah_x25519_public(sr, sr_pub);
    ah_noise_handshake_t init;
    ah_noise_handshake_t resp;
    ah_noise_handshake_init(&init, true, si, si_pub, ei);
    ah_noise_handshake_init(&resp, false, sr, sr_pub, er);
    uint8_t msg[AH_NOISE_MSG2_LEN];
    s_stage[0] = resp;
    if (ah_noise_write(&init, msg, sizeof(msg)) != AH_NOISE_MSG1_LEN) {
        __builtin_trap();
    }
    s_stage[1] = init;
    if (!ah_noise_read(&resp, msg, AH_NOISE_MSG1_LEN) || ah_noise_write(&resp, msg, sizeof(msg)) != AH_NOISE_MSG2_LEN) {
        __builtin_trap();
    }
    s_stage[2] = resp;
    if (!ah_noise_read(&init, msg, AH_NOISE_MSG2_LEN) || ah_noise_write(&init, msg, sizeof(msg)) != AH_NOISE_MSG3_LEN ||
            !ah_noise_read(&resp, msg, AH_NOISE_MSG3_LEN)) {
        __builtin_trap();
    }
    ah_noise_sender_t tx;
    ah_noise_sender_t unused_tx;
    ah_noise_receiver_t unused_rx;
    uint8_t remote[AH_KEY_LEN];
    if (!ah_noise_split(&init, &tx, &unused_rx, remote) || !ah_noise_split(&resp, &unused_tx, &s_receiver, remote)) {
        __builtin_trap();
    }
    static const uint32_t opened[] = {5, 1000};
    for (size_t i = 0; i < sizeof(opened) / sizeof(opened[0]); ++i) {
        uint8_t sealed[AH_NOISE_NONCE_PREFIX + 1u + AH_AEAD_TAG_LEN];
        uint8_t plain[1];
        tx.counter = opened[i];
        const size_t len = ah_noise_seal(&tx, (const uint8_t *)"x", 1, sealed, sizeof(sealed));
        if (len == 0 || ah_noise_open(&s_receiver, sealed, len, plain, sizeof(plain)) != 1u) {
            __builtin_trap();
        }
    }
}

// A message from the peer: the first byte picks the stage, 0 to 2 for the
// three handshake messages and 3 for a transport message.
static void noise_read(const uint8_t *p, size_t n)
{
    static bool ready;
    if (!ready) {
        noise_setup();
        ready = true;
    }
    if (n < 1) {
        return;
    }
    const uint8_t stage = p[0] % 4u;
    const uint8_t *msg = p + 1;
    const size_t len = n - 1;
    if (stage < 3u) {
        ah_noise_handshake_t hs = s_stage[stage];
        if (ah_noise_read(&hs, msg, len)) {
            // The reply still comes out whole, or not at all (a low-order key).
            uint8_t reply[AH_NOISE_MSG2_LEN];
            const size_t out = ah_noise_write(&hs, reply, sizeof(reply));
            const size_t want = stage == 0 ? AH_NOISE_MSG2_LEN : stage == 1 ? AH_NOISE_MSG3_LEN : 0;
            if (out != 0 && out != want) {
                __builtin_trap();
            }
        } else if (!hs.failed) {
            // A refused message ends the handshake.
            __builtin_trap();
        }
        ah_noise_handshake_wipe(&hs);
        return;
    }
    ah_noise_receiver_t rx;
    memcpy(&rx, &s_receiver, sizeof(rx));
    static uint8_t plain[4096];
    const size_t out = ah_noise_open(&rx, msg, len, plain, sizeof(plain));
    if (out == SIZE_MAX) {
        // A refusal never costs the session anything.
        if (memcmp(&rx, &s_receiver, sizeof(rx)) != 0) {
            __builtin_trap();
        }
    } else if (out != len - AH_NOISE_NONCE_PREFIX - AH_AEAD_TAG_LEN ||
               ah_noise_open(&rx, msg, len, plain, sizeof(plain)) != SIZE_MAX) {
        // Opened once, and never again.
        __builtin_trap();
    }
}

// A filter as the node builds one, read back as a peer reads it: the first two
// bytes pick the byte budget, then 8 bytes per hash. Every hash the filter
// says it includes must read back as a member, and a filter over any hash
// must have an M a peer accepts.
static void gcs_round_trip(const uint8_t *p, size_t n)
{
    if (n < 2) {
        return;
    }
    static uint64_t hashes[512];
    static uint32_t scratch[512];
    static uint32_t members[512];
    static uint8_t filter[AH_GCS_MAX_BYTES];
    const size_t cap = 1u + ((size_t)ah_be16(p) % AH_GCS_MAX_BYTES);
    size_t count = (n - 2) / 8u;
    if (count > sizeof(hashes) / sizeof(hashes[0])) {
        count = sizeof(hashes) / sizeof(hashes[0]);
    }
    for (size_t i = 0; i < count; ++i) {
        hashes[i] = ah_be64(p + 2 + 8 * i) & 0x7FFFFFFFFFFFFFFFull;
    }
    ah_gcs_built_t built;
    if (!ah_gcs_build(hashes, count, filter, cap, scratch, &built) || built.data_len > cap || built.included > count ||
            (count > 0 && (built.included == 0 || built.m <= 1u))) {
        __builtin_trap();
    }
    const size_t got = ah_gcs_decode(built.p, built.m, filter, built.data_len, members, 512);
    for (size_t i = 0; i < built.included; ++i) {
        if (!ah_gcs_contains(members, got, ah_gcs_bucket(hashes[i], built.m))) {
            __builtin_trap();
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) {
        return 0;
    }
    const uint8_t *p = data + 1;
    const size_t n = size - 1;
    switch (data[0] % 11u) {
    case 0: {
        ah_announce_t a;
        ah_announce_decode(p, n, &a);
        break;
    }
    case 1: {
        ah_board_post_t b;
        if (ah_board_post_check(p, n, &b)) {
            ah_board_post_is_live(&b, 1780000000000ull);
        }
        break;
    }
    case 2: {
        ah_envelope_t e;
        ah_envelope_decode(p, n, &e);
        break;
    }
    case 3: {
        ah_private_message_t m;
        ah_private_message_decode(p, n, &m);
        break;
    }
    case 4: {
        ah_fragment_t f;
        ah_fragment_parse(p, n, &f);
        break;
    }
    case 5: {
        ah_sync_request_t r;
        ah_sync_request_decode(p, n, &r);
        break;
    }
    case 6: {
        static const uint8_t owner[AH_KEY_LEN] = {0x0A};
        ah_ota_manifest_t m;
        ah_ota_manifest_check(p, n, owner, "heltec_v3", &m);
        break;
    }
    case 7: {
        // A filter as a peer would send it: P, then M, then the bits.
        if (n < 5) {
            break;
        }
        static uint32_t values[1024];
        const uint32_t m = (uint32_t)p[1] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 8 | p[4];
        ah_gcs_decode(p[0], m, p + 5, n - 5, values, sizeof(values) / sizeof(values[0]));
        break;
    }
    case 8:
        ah_voice_valid(n);
        ah_video_valid(p, n);
        break;
    case 9:
        noise_read(p, n);
        break;
    case 10:
        gcs_round_trip(p, n);
        break;
    }
    return 0;
}
