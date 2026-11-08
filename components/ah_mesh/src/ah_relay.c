// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The relay decision: which types never go further, TTL caps by degree, and the
// jitter windows.
#include "ah_relay.h"

#include <string.h>

// bitchat-ios TransportConfig: bleFragmentRelayTtlCap(Dense), and the
// RelayController broadcast clamps by degree.
#define STREAM_TTL_CAP 7u
#define STREAM_TTL_CAP_DENSE 5u
#define BROADCAST_TTL_CAP_MID 6u
#define BROADCAST_TTL_CAP_DENSE 5u

bool ah_is_live(uint8_t type)
{
    return type == AH_TYPE_VOICE_FRAME || type == AH_TYPE_VIDEO_FRAME;
}

bool ah_is_ota(uint8_t type)
{
    return type >= AH_TYPE_OTA_MANIFEST && type <= AH_TYPE_OTA_STATUS;
}

static bool is_stream(uint8_t type)
{
    return type == AH_TYPE_FRAGMENT || ah_is_live(type);
}

// bitchat-ios BLEReceivePipeline's isDirectedEncrypted set, plus Airhop's DR_ENCRYPTED.
static bool is_directed_type(uint8_t type)
{
    switch (type) {
    case AH_TYPE_NOISE_ENCRYPTED:
    case AH_TYPE_DR_ENCRYPTED:
    case AH_TYPE_COURIER_ENV:
    case AH_TYPE_PING:
    case AH_TYPE_PONG:
    case AH_TYPE_NOSTR_CARRIER:
    case AH_TYPE_FRAGMENT:
        return true;
    default:
        return false;
    }
}

static uint8_t min_u8(uint8_t a, uint8_t b)
{
    return a < b ? a : b;
}

ah_relay_decision_t ah_relay_decide(const ah_frame_t *frame, uint32_t degree, const uint8_t self[AH_PEER_ID_LEN],
                                    bool urgent)
{
    ah_relay_decision_t d = {0};
    const uint8_t ttl_cap = min_u8(frame->ttl, AH_TTL_DEFAULT);
    // REQUEST_SYNC asks the far end of one link; relayed, it turns every node
    // it reaches into a responder replaying its store. OTA is node-to-node
    // over one link only, so phones never carry firmware chunks.
    if (frame->type == AH_TYPE_REQUEST_SYNC || ah_is_ota(frame->type) || ttl_cap <= 1u) {
        return d;
    }
    if (memcmp(frame->sender, self, AH_PEER_ID_LEN) == 0 || ah_frame_is_for(frame, self)) {
        return d;
    }

    const bool broadcast = ah_frame_is_broadcast(frame);
    const bool handshake = frame->type == AH_TYPE_NOISE_HANDSHAKE;
    if (handshake || (!broadcast && is_directed_type(frame->type))) {
        // Directed traffic goes at full depth: fewer hops is fewer deliveries.
        d.relay = true;
        d.ttl = (uint8_t)(ttl_cap - 1u);
        d.jitter_min_ms = handshake ? 10u : 20u;
        d.jitter_max_ms = handshake ? 35u : 60u;
        return d;
    }

    const bool dense = degree >= AH_DEGREE_DENSE;
    uint8_t limit;
    if (is_stream(frame->type)) {
        // A stream floods like a fragment, contained in a dense graph, and
        // keeps its jitter inside the receivers' 350 ms buffer.
        limit = min_u8(ttl_cap, dense ? STREAM_TTL_CAP_DENSE : STREAM_TTL_CAP);
        d.jitter_min_ms = 8u;
        d.jitter_max_ms = 25u;
    } else {
        if (dense) {
            limit = min_u8(ttl_cap, BROADCAST_TTL_CAP_DENSE);
        } else if (degree <= 2u) {
            limit = ttl_cap;
        } else {
            const bool priority = frame->type == AH_TYPE_ANNOUNCE || (frame->type == AH_TYPE_BOARD_POST && urgent);
            limit = min_u8(ttl_cap, priority ? AH_TTL_DEFAULT : BROADCAST_TTL_CAP_MID);
        }
        if (degree <= 2u) {
            d.jitter_min_ms = 10u;
            d.jitter_max_ms = 40u;
        } else if (degree <= 5u) {
            d.jitter_min_ms = 60u;
            d.jitter_max_ms = 150u;
        } else if (degree <= 9u) {
            d.jitter_min_ms = 80u;
            d.jitter_max_ms = 180u;
        } else {
            d.jitter_min_ms = 100u;
            d.jitter_max_ms = 220u;
        }
    }
    // ttl_cap is at least 2 here and every cap at least 5, so `limit` is too.
    d.relay = true;
    d.ttl = (uint8_t)(limit - 1u);
    return d;
}
