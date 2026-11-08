// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The frame codec as the node meets a frame: parse, then everything the node
// computes from a parsed frame (packet ID through inflation, the signing
// preimage, the decoded payload, the pieces it would cut for a small link),
// under both inflate windows. The packet ID must be the packet's own: the same
// whatever an earlier packet left in the window, and the same through the
// small window whenever the payload fits it.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ah_fragment.h"
#include "ah_frame.h"
#include "ah_payload.h"

// The largest frame ah_frame_parse accepts: both peer IDs, a 255-hop route,
// the framed-file payload with its size field, and a signature.
#define MAX_FRAME \
    (AH_V2_HEADER_LEN + 2u * AH_PEER_ID_LEN + 1u + 255u * AH_PEER_ID_LEN + 4u + AH_CAP_FRAMED_FILE + AH_SIGNATURE_LEN)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define SMALL_WINDOW 4096u

static _Alignas(max_align_t) uint8_t s_full[64 * 1024];
static _Alignas(max_align_t) uint8_t s_small[16 * 1024];
// Final stored blocks of 32 KiB of 0x00 and of 0xFF, each leaving the full
// window holding nothing else.
static uint8_t s_fill[2][5u + AH_INFLATE_WINDOW_FULL];

static bool id_after_fill(const ah_frame_t *f, ah_inflater_t *inf, size_t fill, uint8_t id[AH_PACKET_ID_LEN])
{
    if (!ah_inflate(inf, s_fill[fill], sizeof(s_fill[fill]), AH_INFLATE_WINDOW_FULL, NULL, NULL)) {
        __builtin_trap();
    }
    return ah_packet_id(f, inf, id);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static ah_inflater_t *full;
    static ah_inflater_t *small;
    if (full == NULL) {
        if (ah_inflater_size(AH_INFLATE_WINDOW_FULL) > sizeof(s_full) ||
                ah_inflater_size(SMALL_WINDOW) > sizeof(s_small)) {
            __builtin_trap();
        }
        full = ah_inflater_init(s_full, AH_INFLATE_WINDOW_FULL);
        small = ah_inflater_init(s_small, SMALL_WINDOW);
        // BFINAL with BTYPE 00, then LEN 0x8000 and NLEN, little-endian.
        static const uint8_t stored[5] = {0x01, 0x00, 0x80, 0xFF, 0x7F};
        for (size_t k = 0; k < 2; ++k) {
            memcpy(s_fill[k], stored, sizeof(stored));
            memset(s_fill[k] + sizeof(stored), k == 0 ? 0x00 : 0xFF, AH_INFLATE_WINDOW_FULL);
        }
    }
    ah_frame_t f;
    if (!ah_frame_parse(data, size, &f)) {
        return 0;
    }
    uint8_t id[AH_PACKET_ID_LEN];
    uint8_t other[AH_PACKET_ID_LEN];
    const bool ok = f.compressed ? id_after_fill(&f, full, 0, id) : ah_packet_id(&f, full, id);
    if (f.compressed && (id_after_fill(&f, full, 1, other) != ok || (ok && memcmp(id, other, sizeof(id)) != 0))) {
        __builtin_trap();
    }
    const bool small_ok = ah_packet_id(&f, small, other);
    if (f.original_size <= SMALL_WINDOW && (small_ok != ok || (ok && memcmp(id, other, sizeof(id)) != 0))) {
        __builtin_trap();
    }
    static uint8_t pre[MAX_FRAME + AH_PAD_MAX];
    size_t pre_len = 0;
    if (!ah_frame_signing_preimage(&f, pre, sizeof(pre), &pre_len)) {
        __builtin_trap();
    }
    // The payload decodes exactly when its ID could be computed.
    static uint8_t out[16 * 1024];
    size_t out_len = 0;
    if (ah_payload_decode(&f, full, out, sizeof(out), &out_len) != (ok && f.original_size <= sizeof(out))) {
        __builtin_trap();
    }

    // Cut for a 185-byte ATT MTU; every piece must parse as a fragment.
    static const uint8_t stream[AH_FRAGMENT_STREAM_ID_LEN] = {0};
    ah_fragmenter_t cutter;
    if (ah_fragmenter_init(&cutter, &f, f.bytes, f.len, 182, stream)) {
        uint8_t piece[AH_BLE_FRAME_MAX];
        size_t n;
        while ((n = ah_fragmenter_next(&cutter, piece, sizeof(piece))) > 0) {
            ah_frame_t pf;
            if (!ah_frame_parse(piece, n, &pf) || pf.type != AH_TYPE_FRAGMENT) {
                __builtin_trap();
            }
        }
    }
    return 0;
}
