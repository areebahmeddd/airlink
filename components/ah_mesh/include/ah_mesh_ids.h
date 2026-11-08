// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The values the mesh tables hand each other: the "none" of each index, and
// the 64-bit key a peer ID is compared by.
#pragma once

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "ah_wire.h"

#define AH_LINK_NONE UINT16_MAX
#define AH_PEER_NONE UINT16_MAX

static_assert(AH_PEER_ID_LEN == sizeof(uint64_t), "a peer key is the whole peer ID");

// The whole peer ID as one integer, for tables that compare IDs often.
static inline uint64_t ah_peer_key(const uint8_t peer_id[AH_PEER_ID_LEN])
{
    uint64_t k = 0;
    memcpy(&k, peer_id, sizeof(k));
    return k;
}

// The key of a table whose free slots hold 0: the all-zero peer ID, which is
// the broadcast spelling and never announces, is moved to 1.
static inline uint64_t ah_peer_slot_key(const uint8_t peer_id[AH_PEER_ID_LEN])
{
    const uint64_t k = ah_peer_key(peer_id);
    return k == 0 ? 1u : k;
}
