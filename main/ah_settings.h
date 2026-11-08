// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Per-node data, provisioned into NVS rather than compiled in: the identity,
// the nickname, the LoRa region, the OTA owner key, and the last good wall
// time.
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "sdkconfig.h"

#include "ah_lora_region.h"
#include "ah_node.h"

// The longest nickname the node takes: the core's own bound, which keeps the
// announce under 100 bytes, where bitchat-ios starts compressing a payload
// to check its signature (ah_wire.h).
#define AH_SETTINGS_NICKNAME_MAX AH_NICKNAME_MAX

// On a release board the lock also burns DIS_DOWNLOAD_MODE: Secure Download
// Mode still writes flash, so a board in hand could otherwise erase these
// settings and the lock with them, or garble otadata into booting the other
// slot. A development board keeps its serial loader.
#if CONFIG_SECURE_BOOT_V2_ENABLED && CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE
#define AH_LOCK_CLOSES_DOWNLOAD_MODE 1
#else
#define AH_LOCK_CLOSES_DOWNLOAD_MODE 0
#endif

typedef struct {
    ah_identity_t identity;
    ah_lora_region_id_t region;    // AH_LORA_REGION_NONE until provisioned: no LoRa transmission at all
    bool has_owner_key;
    uint8_t owner_key[AH_KEY_LEN]; // Ed25519 key OTA manifests must verify against
    bool locked;                   // provisioning closed: the console reads, never writes
    uint64_t clock_floor_ms;       // the last good wall time, the clock's lower bound at boot
} ah_settings_t;

// Load the node's settings, creating its identity on first boot. The keys are
// generated on the device and never leave it.
esp_err_t ah_settings_load(ah_settings_t *out);

// The provisioning writes: each refused (ESP_ERR_INVALID_STATE) once locked.
esp_err_t ah_settings_set_nickname(const char *nickname);
esp_err_t ah_settings_set_region(ah_lora_region_id_t region);
// Write once, too: an owner key already set is never replaced (a factory reset clears it).
esp_err_t ah_settings_set_owner_key(const uint8_t key[AH_KEY_LEN]);
esp_err_t ah_settings_lock(void);
// Whether the serial loader is closed for good (DIS_DOWNLOAD_MODE burned); false on a dev build.
bool ah_settings_loader_closed(void);
esp_err_t ah_settings_save_clock(uint64_t wall_ms);
// Ask for the identity, settings, mailbox and last crash to be erased at the
// next boot, before any task can write again. Refused once locked. The update
// state (ah_ota's namespace) stays: its manifests are checked again against
// whatever owner key comes next, and a refused version is this board's history.
esp_err_t ah_settings_factory_reset(void);
// Carry out a factory reset asked for before this boot. Call once storage is
// open, before the settings load.
esp_err_t ah_settings_finish_reset(void);

// Erase the settings namespace whatever the lock says: for boot only,
// when the settings cannot be read at all.
esp_err_t ah_settings_erase(void);
