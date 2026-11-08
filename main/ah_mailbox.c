// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Courier envelopes in the mailbox partition, one NVS entry each, restored into
// the node at boot.
#include "ah_mailbox.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

static const char *TAG = "ah_mailbox";

#define PARTITION "mailbox"
#define NAMESPACE "mail"
// The depositor's peer ID prefix ahead of the envelope in each blob.
#define HEADER 8u
// The node takes no envelope its big-packet buffer cannot send again.
#define BLOB_MAX (CONFIG_AH_BIG_SEND_KIB * 1024u + HEADER)

static nvs_handle_t s_handle;
static bool s_ready;
// Erasing while an NVS iterator is open is not allowed, so a delete asked for
// during a restore (an envelope the node refused) waits in this list until the
// iteration ends.
static bool s_iterating;
static uint32_t *s_deferred;
static size_t s_deferred_count;
static size_t s_deferred_cap;
// Deletes asked for during the restore, whether or not the list took them.
static size_t s_deletes_while_iterating;
// One blob in flight at a time, on the mesh task only.
static uint8_t *s_blob;

static void key_of(uint32_t record, char out[16])
{
    snprintf(out, 16, "m%08lx", (unsigned long)record);
}

// nvs_flash_init sets up encryption for the settings partition alone; this
// one takes the same keys explicitly, which needs nvs_flash_init to have run.
static esp_err_t open_partition(void)
{
#if CONFIG_NVS_ENCRYPTION
    nvs_sec_scheme_t *scheme = nvs_flash_get_default_security_scheme();
    nvs_sec_cfg_t cfg = {0};
    esp_err_t err = scheme != NULL ? nvs_flash_read_security_cfg_v2(scheme, &cfg) : ESP_ERR_NOT_FOUND;
    if (err == ESP_OK) {
        err = nvs_flash_secure_init_partition(PARTITION, &cfg);
    }
    memset(&cfg, 0, sizeof(cfg));
    return err;
#else
    return nvs_flash_init_partition(PARTITION);
#endif
}

esp_err_t ah_mailbox_init(void)
{
    esp_err_t err = open_partition();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "mailbox unreadable (%s); erasing", esp_err_to_name(err));
        nvs_flash_erase_partition(PARTITION);
        err = open_partition();
    }
    if (err == ESP_OK) {
        err = nvs_open_from_partition(PARTITION, NAMESPACE, NVS_READWRITE, &s_handle);
    }
    if (err == ESP_OK) {
        s_blob = malloc(BLOB_MAX);
        err = s_blob != NULL ? ESP_OK : ESP_ERR_NO_MEM;
    }
    s_ready = err == ESP_OK;
    return err;
}

void ah_mailbox_put(uint32_t record, uint64_t depositor, const uint8_t *envelope, size_t len)
{
    if (!s_ready || len + HEADER > BLOB_MAX) {
        return;
    }
    memcpy(s_blob, &depositor, HEADER);
    memcpy(s_blob + HEADER, envelope, len);
    char key[16];
    key_of(record, key);
    esp_err_t err = nvs_set_blob(s_handle, key, s_blob, len + HEADER);
    if (err == ESP_OK) {
        err = nvs_commit(s_handle);
    }
    if (err != ESP_OK) {
        // The envelope still travels from RAM; only a reboot would lose it.
        ESP_LOGW(TAG, "persist %s: %s", key, esp_err_to_name(err));
    }
}

static void defer_delete(uint32_t record)
{
    s_deletes_while_iterating++;
    if (s_deferred_count == s_deferred_cap) {
        const size_t cap = s_deferred_cap == 0 ? 16u : s_deferred_cap * 2u;
        uint32_t *grown = realloc(s_deferred, cap * sizeof(*grown));
        if (grown == NULL) {
            // Left in flash: the next boot's restore meets it again.
            return;
        }
        s_deferred = grown;
        s_deferred_cap = cap;
    }
    s_deferred[s_deferred_count++] = record;
}

void ah_mailbox_delete(uint32_t record)
{
    if (!s_ready) {
        return;
    }
    if (s_iterating) {
        defer_delete(record);
        return;
    }
    char key[16];
    key_of(record, key);
    if (nvs_erase_key(s_handle, key) == ESP_OK) {
        nvs_commit(s_handle);
    }
}

void ah_mailbox_restore(ah_node_t *node)
{
    if (!s_ready) {
        return;
    }
    nvs_iterator_t it = NULL;
    esp_err_t err = nvs_entry_find(PARTITION, NAMESPACE, NVS_TYPE_BLOB, &it);
    size_t handed = 0;
    size_t unreadable = 0;
    s_iterating = true;
    s_deferred_count = 0;
    s_deletes_while_iterating = 0;
    while (err == ESP_OK) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);
        if (info.key[0] == 'm') {
            const uint32_t record = (uint32_t)strtoul(info.key + 1, NULL, 16);
            size_t len = BLOB_MAX;
            const esp_err_t got = nvs_get_blob(s_handle, info.key, s_blob, &len);
            if (got == ESP_OK && len > HEADER) {
                uint64_t depositor = 0;
                memcpy(&depositor, s_blob, HEADER);
                ah_node_restore_mail(node, record, depositor, s_blob + HEADER, len - HEADER);
                handed++;
            } else if (got == ESP_ERR_NVS_INVALID_LENGTH || got == ESP_OK) {
                // Larger than this build takes, or empty: never one it can hand on.
                defer_delete(record);
                unreadable++;
            }
        }
        err = nvs_entry_next(&it);
    }
    nvs_release_iterator(it);
    s_iterating = false;
    for (size_t i = 0; i < s_deferred_count; ++i) {
        ah_mailbox_delete(s_deferred[i]);
    }
    // Every other delete asked for during the restore names an envelope handed
    // over earlier in it that the node refused: a restore never evicts.
    const size_t deleted = s_deletes_while_iterating;
    const size_t refused = deleted - unreadable;
    const size_t kept = handed > refused ? handed - refused : 0;
    free(s_deferred);
    s_deferred = NULL;
    s_deferred_count = 0;
    s_deferred_cap = 0;
    ESP_LOGI(TAG, "restored %u envelope(s), %u dropped", (unsigned)kept, (unsigned)deleted);
}

esp_err_t ah_mailbox_erase_all(void)
{
    if (!s_ready) {
        return nvs_flash_erase_partition(PARTITION);
    }
    esp_err_t err = nvs_erase_all(s_handle);
    if (err == ESP_OK) {
        err = nvs_commit(s_handle);
    }
    return err;
}
