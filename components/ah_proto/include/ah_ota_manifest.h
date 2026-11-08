// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The signed manifest a node checks before it takes a byte of a firmware
// image from a neighbor (docs/OTA.md). All integers big-endian:
//
//   "AHOT" format(1) version(4) size(4) sha256(32) board(16) | signature(64)
//
// The Ed25519 signature, by the fleet's owner key, covers "airhop-fw-v1"
// followed by every byte before it. The board name is NUL-padded.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_wire.h"

#define AH_OTA_BOARD_LEN 16u
#define AH_OTA_FIELDS_LEN (4u + 1u + 4u + 4u + 32u + AH_OTA_BOARD_LEN)
#define AH_OTA_MANIFEST_LEN (AH_OTA_FIELDS_LEN + AH_SIGNATURE_LEN)

typedef struct {
    uint32_t version; // major << 16 | minor << 8 | patch, as the announce's 0xB0
    uint32_t size;
    uint8_t sha256[32];
} ah_ota_manifest_t;

// Check a manifest for this node: its format, the owner's signature, and that
// it names `board`. False for anything else: another fleet's image, another
// board's, a forgery, or a malformed record. Never fetch on false.
bool ah_ota_manifest_check(const uint8_t *data, size_t len, const uint8_t owner[AH_KEY_LEN], const char *board,
                           ah_ota_manifest_t *out);
