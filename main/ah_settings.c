// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The settings store in NVS: the identity made on first boot, the provisioned
// values, and the clock floor.
#include "ah_settings.h"

#include <stdio.h>
#include <string.h>

#include "bootloader_random.h"
#include "esp_check.h"
#include "esp_core_dump.h"
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "esp_log.h"
#include "nvs.h"

#include "ah_announce.h"
#include "ah_crypto.h"
#include "ah_mailbox.h"

static const char *TAG = "ah_settings";

#define NAMESPACE "airhop"
#define KEY_NOISE "noise_sk"
#define KEY_SIGNING "sign_seed"
#define KEY_NICKNAME "nickname"
#define KEY_REGION "region"
#define KEY_OWNER "owner_pk"
#define KEY_LOCKED "locked"
#define KEY_CLOCK "clock_ms"
// A factory reset asked for, carried out at the next boot.
#define KEY_RESET "reset"

static esp_err_t open_rw(nvs_handle_t *h)
{
    return nvs_open(NAMESPACE, NVS_READWRITE, h);
}

// Locked by the NVS flag, or on a release board by the eFuse the lock burns,
// which outlives any erase of this namespace.
static bool is_locked(nvs_handle_t h)
{
    uint8_t locked = 0;
    nvs_get_u8(h, KEY_LOCKED, &locked);
#if AH_LOCK_CLOSES_DOWNLOAD_MODE
    if (esp_efuse_read_field_bit(ESP_EFUSE_DIS_DOWNLOAD_MODE)) {
        return true;
    }
#endif
    return locked != 0;
}

// Open the settings for a provisioning write: refused once locked.
static esp_err_t open_unlocked(nvs_handle_t *h)
{
    ESP_RETURN_ON_ERROR(open_rw(h), TAG, "open");
    if (is_locked(*h)) {
        nvs_close(*h);
        return ESP_ERR_INVALID_STATE;
    }
    return ESP_OK;
}

// Commit what `err` says was written, and close.
static esp_err_t commit_and_close(nvs_handle_t h, esp_err_t err)
{
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

static esp_err_t read_or_create_secret(nvs_handle_t h, const char *key, uint8_t out[AH_KEY_LEN], bool *created)
{
    size_t len = AH_KEY_LEN;
    esp_err_t err = nvs_get_blob(h, key, out, &len);
    if (err == ESP_OK && len == AH_KEY_LEN) {
        return ESP_OK;
    }
    if (err != ESP_ERR_NVS_NOT_FOUND) {
        return err == ESP_OK ? ESP_ERR_INVALID_SIZE : err;
    }
    // First boot: the radio is not running yet, so the RNG is fed from the
    // bootloader's entropy source for as long as the keys take to draw.
    bootloader_random_enable();
    ah_random(out, AH_KEY_LEN);
    bootloader_random_disable();
    *created = true;
    return nvs_set_blob(h, key, out, AH_KEY_LEN);
}

// Says what the box is, and keeps to nickname_ok's alphabet, so phones show
// it as written.
static void default_nickname(const uint8_t peer_id[AH_PEER_ID_LEN], char *out, size_t cap)
{
    snprintf(out, cap, "AirhopRelay-%02X%02X", peer_id[0], peer_id[1]);
}

esp_err_t ah_settings_load(ah_settings_t *out)
{
    memset(out, 0, sizeof(*out));
    nvs_handle_t h;
    ESP_RETURN_ON_ERROR(open_rw(&h), TAG, "open");
    bool created = false;
    uint8_t noise_secret[AH_KEY_LEN];
    uint8_t seed[AH_KEY_LEN];
    esp_err_t err = read_or_create_secret(h, KEY_NOISE, noise_secret, &created);
    if (err == ESP_OK) {
        err = read_or_create_secret(h, KEY_SIGNING, seed, &created);
    }
    if (err != ESP_OK) {
        nvs_close(h);
        return err;
    }
    ah_identity_t *id = &out->identity;
    memcpy(id->noise_secret, noise_secret, sizeof(noise_secret));
    ah_x25519_public(id->noise_secret, id->noise_public);
    ah_ed25519_keypair(seed, id->signing_secret, id->signing_public);
    const bool derived = ah_peer_id_of(id->noise_public, id->peer_id);
    ah_wipe(noise_secret, sizeof(noise_secret));
    ah_wipe(seed, sizeof(seed));
    if (!derived) {
        // The hash had no memory: a reboot retries with the stored keys intact.
        ah_wipe(out, sizeof(*out));
        nvs_close(h);
        return ESP_ERR_NO_MEM;
    }

    // A stored name longer than this build takes reads as none.
    char nick[AH_SETTINGS_NICKNAME_MAX + 1];
    size_t nick_len = sizeof(nick);
    if (nvs_get_str(h, KEY_NICKNAME, nick, &nick_len) != ESP_OK) {
        default_nickname(id->peer_id, nick, sizeof(nick));
    }
    id->nickname_len = (uint8_t)strnlen(nick, AH_SETTINGS_NICKNAME_MAX);
    memcpy(id->nickname, nick, id->nickname_len);

    uint8_t region = AH_LORA_REGION_NONE;
    nvs_get_u8(h, KEY_REGION, &region);
    out->region = ah_lora_region(region) != NULL ? (ah_lora_region_id_t)region : AH_LORA_REGION_NONE;
    size_t owner_len = sizeof(out->owner_key);
    out->has_owner_key = nvs_get_blob(h, KEY_OWNER, out->owner_key, &owner_len) == ESP_OK && owner_len == AH_KEY_LEN;
    out->locked = is_locked(h);
    nvs_get_u64(h, KEY_CLOCK, &out->clock_floor_ms);

    if (created) {
        err = nvs_commit(h);
        ESP_LOGI(TAG, "new identity %02x%02x%02x%02x", id->peer_id[0], id->peer_id[1], id->peer_id[2], id->peer_id[3]);
    }
    nvs_close(h);
    return err;
}

// ASCII letters, digits, '-', '_' and '.': nothing Airhop's canonicalization
// (PROTOCOLS section 3.5) would change, so phones show what was typed.
static bool nickname_ok(const char *s)
{
    const size_t n = strlen(s);
    if (n == 0 || n > AH_SETTINGS_NICKNAME_MAX) {
        return false;
    }
    for (size_t i = 0; i < n; ++i) {
        const char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                c == '.')) {
            return false;
        }
    }
    return true;
}

esp_err_t ah_settings_set_nickname(const char *nickname)
{
    if (nickname == NULL || !nickname_ok(nickname)) {
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t h;
    const esp_err_t err = open_unlocked(&h);
    return err != ESP_OK ? err : commit_and_close(h, nvs_set_str(h, KEY_NICKNAME, nickname));
}

esp_err_t ah_settings_set_region(ah_lora_region_id_t region)
{
    if (ah_lora_region(region) == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t h;
    const esp_err_t err = open_unlocked(&h);
    return err != ESP_OK ? err : commit_and_close(h, nvs_set_u8(h, KEY_REGION, (uint8_t)region));
}

esp_err_t ah_settings_set_owner_key(const uint8_t key[AH_KEY_LEN])
{
    nvs_handle_t h;
    const esp_err_t err = open_unlocked(&h);
    if (err != ESP_OK) {
        return err;
    }
    uint8_t existing[AH_KEY_LEN];
    size_t len = sizeof(existing);
    // Write once: whoever reaches the console later cannot claim the fleet.
    const bool set = nvs_get_blob(h, KEY_OWNER, existing, &len) == ESP_OK;
    return commit_and_close(h, set ? ESP_ERR_INVALID_STATE : nvs_set_blob(h, KEY_OWNER, key, AH_KEY_LEN));
}

esp_err_t ah_settings_lock(void)
{
    nvs_handle_t h;
    ESP_RETURN_ON_ERROR(open_rw(&h), TAG, "open");
    ESP_RETURN_ON_ERROR(commit_and_close(h, nvs_set_u8(h, KEY_LOCKED, 1)), TAG, "lock");
#if AH_LOCK_CLOSES_DOWNLOAD_MODE
    // After the flag, so a failure here still leaves the node locked.
    ESP_RETURN_ON_ERROR(esp_efuse_disable_rom_download_mode(), TAG, "download mode");
#endif
    return ESP_OK;
}

esp_err_t ah_settings_save_clock(uint64_t wall_ms)
{
    nvs_handle_t h;
    ESP_RETURN_ON_ERROR(open_rw(&h), TAG, "open");
    return commit_and_close(h, nvs_set_u64(h, KEY_CLOCK, wall_ms));
}

esp_err_t ah_settings_erase(void)
{
    nvs_handle_t h;
    ESP_RETURN_ON_ERROR(open_rw(&h), TAG, "open");
    return commit_and_close(h, nvs_erase_all(h));
}

// Only marked here: the mesh task keeps persisting until the restart, so an
// erase now could be followed by a deposit or a clock save that survives it.
esp_err_t ah_settings_factory_reset(void)
{
    nvs_handle_t h;
    const esp_err_t err = open_unlocked(&h);
    return err != ESP_OK ? err : commit_and_close(h, nvs_set_u8(h, KEY_RESET, 1));
}

esp_err_t ah_settings_finish_reset(void)
{
    nvs_handle_t h;
    ESP_RETURN_ON_ERROR(open_rw(&h), TAG, "open");
    uint8_t asked = 0;
    nvs_get_u8(h, KEY_RESET, &asked);
    if (asked == 0) {
        nvs_close(h);
        return ESP_OK;
    }
    ESP_LOGW(TAG, "factory reset");
    // The settings, and with them the mark, go last: a power cut on the way
    // leaves the reset to run again. The identity goes even if the rest
    // cannot, so a reset never leaves the node as it was.
    if (ah_mailbox_erase_all() != ESP_OK) {
        ESP_LOGE(TAG, "mailbox not erased");
    }
    // The last crash's task stacks can hold session keys.
    if (esp_core_dump_image_erase() != ESP_OK) {
        ESP_LOGE(TAG, "crash not erased");
    }
    return commit_and_close(h, nvs_erase_all(h));
}

bool ah_settings_loader_closed(void)
{
#if AH_LOCK_CLOSES_DOWNLOAD_MODE
    return esp_efuse_read_field_bit(ESP_EFUSE_DIS_DOWNLOAD_MODE);
#else
    return false;
#endif
}
