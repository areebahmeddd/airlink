// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// What may cross the LoRa trunk. In the EU profile (SF10, 125 kHz, 10 % duty)
// the trunk carries about 156 full frames an hour, in India's about 39 and in
// Southeast Asia's (SF9, 1 %) about 28, so it carries only text and the
// control traffic that text needs.
//
// Crosses: announces, handshakes, encrypted DMs within a size ceiling and a
// per-sender token bucket, courier envelopes, public, location-channel,
// private-channel and group messages, board posts, leaves, pings and pongs,
// and, when there are only a few, the fragments of any of those but an
// announce. Never: live voice and video, files, sync traffic (link-local by
// protocol), OTA, prekey bundles, gateway carriers, unknown types. A DM's
// voice or video rides inside encryption, so the size ceiling and the bucket
// keep it off without reading it.
//
// Announces are what a duty budget runs out on first, so they cross two ways.
// An announce carried ahead of its sender's message, and the node's own, go
// first: a receiver needs the key before the message. A phone's periodic
// announce is presence: one per origin per interval, from a table that
// refuses a new origin rather than forget one still inside its interval, and
// queued behind text (AH_PRIO_PRESENCE).
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "ah_frame.h"

#define AH_TRUNK_POLICY_ORIGINS 32u
#define AH_TRUNK_POLICY_BUCKETS 16u

typedef struct {
    uint64_t sender;
    int64_t at_ms;
} ah_trunk_policy_origin_t;

typedef struct {
    uint64_t sender;
    int64_t at_ms;
    uint16_t milli_tokens;
} ah_trunk_policy_bucket_t;

typedef struct {
    uint32_t announce_interval_ms;
    ah_trunk_policy_origin_t periodic[AH_TRUNK_POLICY_ORIGINS]; // periodic announces admitted
    ah_trunk_policy_origin_t ahead[AH_TRUNK_POLICY_ORIGINS];    // announces sent first
    ah_trunk_policy_bucket_t buckets[AH_TRUNK_POLICY_BUCKETS];
} ah_trunk_policy_t;

void ah_trunk_policy_init(ah_trunk_policy_t *p, uint32_t announce_interval_ms);

// Whether a frame may go out on a LoRa link; for an announce, whether its
// origin's periodic one is due, which admitting it records. `inner_type` and
// `total` are a FRAGMENT's header fields, ignored for any other type.
bool ah_trunk_policy_admit(ah_trunk_policy_t *p, const ah_frame_t *frame, uint8_t inner_type, uint16_t total,
                           int64_t now_ms);

// Whether a message from this sender needs the sender's announce sent
// ahead of it: none of theirs went first recently, and receivers verify
// a public message against the key the announce carries. A periodic
// announce does not count, since it may still be queued behind text.
bool ah_trunk_policy_needs_announce(const ah_trunk_policy_t *p, const uint8_t sender[AH_PEER_ID_LEN], int64_t now_ms);

// Record that the sender's announce went out first now; it also stands in for their periodic one.
void ah_trunk_policy_note_ahead(ah_trunk_policy_t *p, const uint8_t sender[AH_PEER_ID_LEN], int64_t now_ms);
