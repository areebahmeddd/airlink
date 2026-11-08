// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Whether a packet goes further, at what TTL and after how much jitter: the
// phones' relay policy (PROTOCOLS section 4, bitchat-ios RelayController,
// Airhop flood-router), so a node keeps the mesh balanced rather than flooding
// harder than the phones around it.
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "ah_frame.h"

typedef struct {
    bool relay;
    uint8_t ttl; // carried by the relayed copy
    uint16_t jitter_min_ms;
    uint16_t jitter_max_ms;
} ah_relay_decision_t;

// The relay decision for a received packet, given the node's `degree` (the
// phones and nodes bound to one of its Bluetooth links directly) and, for a
// BOARD_POST, whether its urgent flag is set.
ah_relay_decision_t ah_relay_decide(const ah_frame_t *frame, uint32_t degree, const uint8_t self[AH_PEER_ID_LEN],
                                    bool urgent);

// Live voice or video: its own dedup set, stream jitter and a write deadline.
bool ah_is_live(uint8_t type);

// Relay firmware's link-local OTA types (0xA0 to 0xA3).
bool ah_is_ota(uint8_t type);
