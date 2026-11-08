// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The Golomb-Coded Set a REQUEST_SYNC carries (PROTOCOLS section 5),
// byte-exact with bitchat-ios GCSFilter: hashing a packet ID to a bucket,
// building a filter, and reading one back.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_wire.h"

// First 8 bytes of SHA-256(packet ID), big-endian, sign bit cleared
// (GCSFilter.h64). A failed hash maps every ID to one value: at worst one
// false member for a round, never a shared identity.
uint64_t ah_gcs_hash(const uint8_t packet_id[AH_PACKET_ID_LEN]);

// h mod M with 0 stored as 1 (GCSFilter.mapHash).
uint32_t ah_gcs_bucket(uint64_t hash, uint32_t m);

// Decode a filter into its strictly increasing bucket values, stopping at the
// end of the data or once the running sum reaches M. Values past `cap` are
// not kept, so a filter larger than the buffer reads as missing those
// entries: the responder sends more than it needed to, never less. Returns
// values written; 0 when P is outside 1..32 or M <= 1.
size_t ah_gcs_decode(uint8_t p, uint32_t m, const uint8_t *data, size_t len, uint32_t *values, size_t cap);

// Binary search of a decoded filter.
bool ah_gcs_contains(const uint32_t *values, size_t count, uint32_t bucket);

typedef struct {
    uint8_t p;
    uint32_t m;
    size_t data_len;
    size_t included; // newest-first prefix of the input the filter covers
} ah_gcs_built_t;

// Build a filter over hashes given newest first, trimming the oldest 10% at a
// time until it fits `cap` bytes, M fixed from the starting count as
// bitchat-ios fixes it (GCSFilter.buildFilter). `scratch` holds `count`
// values. False only when `cap` is 0; a filter that fits no hash at all comes
// back empty, with `included` 0.
bool ah_gcs_build(const uint64_t *hashes, size_t count, uint8_t *out, size_t cap, uint32_t *scratch,
                  ah_gcs_built_t *built);
