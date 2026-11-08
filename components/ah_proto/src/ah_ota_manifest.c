// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The OTA manifest's parser and its signature check.
#include "ah_ota_manifest.h"

#include <assert.h>
#include <string.h>

#include "ah_bytes.h"
#include "ah_crypto.h"

#define MAGIC "AHOT"
#define FORMAT 1u
#define SIGN_CONTEXT "airhop-fw-v1"
#define CONTEXT_LEN (sizeof(SIGN_CONTEXT) - 1u)
#define OFF_FORMAT 4u
#define OFF_VERSION 5u
#define OFF_SIZE 9u
#define OFF_SHA 13u
#define OFF_BOARD (OFF_SHA + 32u)
static_assert(OFF_BOARD + AH_OTA_BOARD_LEN == AH_OTA_FIELDS_LEN, "manifest layout");

bool ah_ota_manifest_check(const uint8_t *data, size_t len, const uint8_t owner[AH_KEY_LEN], const char *board,
                           ah_ota_manifest_t *out)
{
    if (len != AH_OTA_MANIFEST_LEN || memcmp(data, MAGIC, 4) != 0 || data[OFF_FORMAT] != FORMAT) {
        return false;
    }
    uint8_t msg[CONTEXT_LEN + AH_OTA_FIELDS_LEN];
    memcpy(msg, SIGN_CONTEXT, CONTEXT_LEN);
    memcpy(msg + CONTEXT_LEN, data, AH_OTA_FIELDS_LEN);
    if (!ah_ed25519_verify(owner, msg, sizeof(msg), data + AH_OTA_FIELDS_LEN)) {
        return false;
    }
    // The name fills the field or ends in NUL padding, with nothing after.
    const size_t name_len = strlen(board);
    if (name_len > AH_OTA_BOARD_LEN || memcmp(data + OFF_BOARD, board, name_len) != 0) {
        return false;
    }
    for (size_t i = name_len; i < AH_OTA_BOARD_LEN; ++i) {
        if (data[OFF_BOARD + i] != 0) {
            return false;
        }
    }
    out->version = ah_be32(data + OFF_VERSION);
    out->size = ah_be32(data + OFF_SIZE);
    memcpy(out->sha256, data + OFF_SHA, sizeof(out->sha256));
    return out->size > 0;
}
