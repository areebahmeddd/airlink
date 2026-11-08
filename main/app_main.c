// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Boot, in the order docs/ARCHITECTURE.md gives. Setup that cannot continue
// stops the boot (ESP_ERROR_CHECK); a missing radio or display only narrows
// what the node does.
#include <string.h>

#include "esp_check.h"
#include "esp_log.h"
#include "esp_pm.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#include "ah_app.h"
#include "ah_ble.h"
#include "ah_board.h"
#include "ah_console.h"
#include "ah_crypto.h"
#include "ah_display.h"
#include "ah_lora.h"
#include "ah_mailbox.h"
#include "ah_ota.h"
#include "ah_settings.h"
#include "ah_trunk_auth.h"

static const char *TAG = "airlink";

// The lowest frequency the scaler may choose. Both Bluetooth controllers hold
// the APB bus at its maximum while enabled, which needs the CPU at 80 MHz or
// above, so a lower floor would never be reached.
#define CPU_FLOOR_MHZ 80

// Each transport's events, posted to the mesh task under its link kind.
static void ble_link_up(uint32_t handle, uint16_t max_write)
{
    ah_app_post_link_up(AH_LINK_BLE, handle, max_write, NULL);
}

static void ble_link_down(uint32_t handle)
{
    ah_app_post_link_down(AH_LINK_BLE, handle);
}

static void ble_mtu(uint32_t handle, uint16_t max_write)
{
    ah_app_post_mtu(AH_LINK_BLE, handle, max_write);
}

static void ble_frame(uint32_t handle, const uint8_t *data, size_t len)
{
    ah_app_post_frame(AH_LINK_BLE, handle, data, len);
}

static void ble_ready(uint32_t handle)
{
    ah_app_post_ready(AH_LINK_BLE, handle);
}

static void lora_link_up(uint32_t handle, uint16_t max_write, const uint8_t node[AH_TRUNK_NODE_LEN])
{
    ah_app_post_link_up(AH_LINK_LORA, handle, max_write, node);
}

static void lora_link_down(uint32_t handle)
{
    ah_app_post_link_down(AH_LINK_LORA, handle);
}

static void lora_frame(uint32_t handle, const uint8_t *packet, size_t len)
{
    ah_app_post_frame(AH_LINK_LORA, handle, packet, len);
}

static void lora_ready(uint32_t handle)
{
    ah_app_post_ready(AH_LINK_LORA, handle);
}

// The trunk's own copy of what its pair keys come from, as the node and the
// console keep theirs: app_main wipes its identity once they are taken, long
// before the first neighbor's beacon arrives.
static uint8_t s_trunk_secret[AH_KEY_LEN];
static uint8_t s_trunk_self[AH_TRUNK_NODE_LEN];

static bool lora_pair_key(const uint8_t peer_key[AH_TRUNK_KEY_LEN], const uint8_t peer[AH_TRUNK_NODE_LEN],
                          uint8_t out[AH_TRUNK_KEY_LEN])
{
    return ah_trunk_auth_pair_key(s_trunk_secret, s_trunk_self, peer_key, peer, out);
}

// Frequency scaling only: the CPU runs at its default speed while the mesh
// task holds its lock and drops to the floor between. Automatic light sleep
// stays off: no GPIO wakeup is armed for the SX1262's interrupt, the console
// would lose input while asleep, and Bluetooth's timing would narrow.
static esp_err_t power_init(void)
{
    const esp_pm_config_t pm = {
        .max_freq_mhz = CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ,
        .min_freq_mhz = CPU_FLOOR_MHZ,
        .light_sleep_enable = false,
    };
    return esp_pm_configure(&pm);
}

static esp_err_t storage_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // An unreadable settings store: the node starts over with a new
        // identity and must be provisioned again.
        ESP_LOGE(TAG, "settings store unreadable (%s); erasing it", esp_err_to_name(err));
        ESP_RETURN_ON_ERROR(nvs_flash_erase(), TAG, "erase");
        err = nvs_flash_init();
    }
    ESP_RETURN_ON_ERROR(err, TAG, "nvs");
    // Mail is what a node carries for others, not what it needs to run: an
    // unreadable mailbox leaves it relaying, with nothing kept across reboots.
    const esp_err_t mail = ah_mailbox_init();
    if (mail != ESP_OK) {
        ESP_LOGE(TAG, "mailbox unavailable (%s): mail is held in RAM only", esp_err_to_name(mail));
    }
    // Before the settings load, and before any task that could write them runs.
    return ah_settings_finish_reset();
}

// Every boot says why the last one ended; a crash, a watchdog or a power fault
// at warning level, which a release build's log keeps.
static void log_reset_reason(void)
{
    const esp_reset_reason_t why = esp_reset_reason();
    const bool fault = why == ESP_RST_PANIC || why == ESP_RST_INT_WDT || why == ESP_RST_TASK_WDT ||
                       why == ESP_RST_WDT || why == ESP_RST_BROWNOUT || why == ESP_RST_PWR_GLITCH ||
                       why == ESP_RST_CPU_LOCKUP;
    ESP_LOG_LEVEL(fault ? ESP_LOG_WARN : ESP_LOG_INFO, TAG, "last reset: %s%s", ah_console_reset_reason(),
                  why == ESP_RST_PANIC ? " (console: crash)" : "");
}

// Settings that will not load (a corrupt entry, keys of the wrong size) would
// otherwise stop every boot. Starting over costs the identity and the
// provisioning, which a reboot loop costs too, and leaves a node that runs.
// Running out of memory is no corruption: it stops this boot, and the next
// one retries with the stored keys intact.
static esp_err_t load_settings(ah_settings_t *out)
{
    const esp_err_t err = ah_settings_load(out);
    if (err == ESP_OK || err == ESP_ERR_NO_MEM) {
        return err;
    }
    ESP_LOGE(TAG, "settings unreadable (%s); starting over with a new identity", esp_err_to_name(err));
    ESP_RETURN_ON_ERROR(ah_settings_erase(), TAG, "erase settings");
    return ah_settings_load(out);
}

static ah_screen_lora_t start_lora(const ah_board_t *board, const ah_settings_t *settings, bool board_ok)
{
    if (!board->has_lora) {
        return AH_SCREEN_LORA_ABSENT;
    }
    if (!board_ok) {
        // A front end never told apart, or a rail never driven, leaves the
        // output power unknown: no transmission is safer than one over the limit.
        ESP_LOGE(TAG, "LoRa left off: the board did not set up");
        return AH_SCREEN_LORA_ABSENT;
    }
    if (settings->region == AH_LORA_REGION_NONE) {
        // No default region: an unprovisioned node is silent on LoRa everywhere.
        ESP_LOGW(TAG, "LoRa region not provisioned: the trunk stays off (console: region us|eu|in|anz|sea)");
        return AH_SCREEN_LORA_NO_REGION;
    }
    ah_lora_config_t cfg = {
        .radio = board->radio,
        .region = settings->region,
        .antenna_gain_ddbi = CONFIG_AH_LORA_ANTENNA_GAIN_DDBI,
        .task_stack = CONFIG_AH_LORA_TASK_STACK,
        .task_priority = CONFIG_AH_LORA_TASK_PRIORITY,
        .task_core = 0,
    };
    memcpy(s_trunk_secret, settings->identity.noise_secret, sizeof(s_trunk_secret));
    memcpy(s_trunk_self, settings->identity.peer_id, sizeof(s_trunk_self));
    memcpy(cfg.self, settings->identity.peer_id, sizeof(cfg.self));
    memcpy(cfg.key, settings->identity.noise_public, sizeof(cfg.key));
    cfg.pair_key = lora_pair_key;
    const ah_lora_events_t events = {
        .link_up = lora_link_up,
        .link_down = lora_link_down,
        .frame = lora_frame,
        .ready = lora_ready,
    };
    esp_err_t err = ah_board_radio_power(true);
    if (err == ESP_OK) {
        err = ah_lora_start(&cfg, &events);
    }
    if (err != ESP_OK) {
        ah_board_radio_power(false);
        ah_wipe(s_trunk_secret, sizeof(s_trunk_secret));
        ESP_LOGW(TAG, "LoRa trunk not started (%s): BLE only", esp_err_to_name(err));
        return AH_SCREEN_LORA_ABSENT;
    }
    return AH_SCREEN_LORA_UP;
}

// ESP-IDF calls it; no header declares it.
void app_main(void);

void app_main(void)
{
    log_reset_reason();
    ESP_ERROR_CHECK(power_init());
    ESP_ERROR_CHECK(storage_init());
    static ah_settings_t settings;
    ESP_ERROR_CHECK(load_settings(&settings));
    settings.identity.firmware_version = ah_ota_running_version();
    // A rail or front end that will not come up costs LoRa (start_lora) or
    // the display, which its own start-up reports; Bluetooth still runs.
    const esp_err_t board_err = ah_board_init();
    if (board_err != ESP_OK) {
        ESP_LOGE(TAG, "board setup incomplete (%s)", esp_err_to_name(board_err));
    }
    const ah_board_t *board = ah_board();
    ESP_ERROR_CHECK(ah_ota_init(&settings, board->name));

    // The queue first: the LoRa task may post the moment it starts.
    ESP_ERROR_CHECK(ah_app_init());
    const ah_screen_lora_t lora = start_lora(board, &settings, board_err == ESP_OK);
    ESP_ERROR_CHECK(ah_app_start(&settings, lora));

    const ah_ble_config_t ble = {
        .adv_interval_ms = CONFIG_AH_BLE_ADV_INTERVAL_MS,
        .max_node_links = CONFIG_AH_BLE_NODE_LINKS,
        .reserved_for_phones = CONFIG_AH_BLE_PHONE_SLOTS,
        .scan_every_ms = CONFIG_AH_BLE_SCAN_EVERY_S * 1000u,
        .scan_for_ms = CONFIG_AH_BLE_SCAN_FOR_MS,
    };
    const ah_ble_events_t ble_events = {
        .link_up = ble_link_up,
        .link_down = ble_link_down,
        .mtu = ble_mtu,
        .frame = ble_frame,
        .ready = ble_ready,
    };
    ESP_ERROR_CHECK(ah_ble_start(&ble, &ble_events));

    char nickname[AH_NICKNAME_MAX + 1] = {0};
    memcpy(nickname, settings.identity.nickname, settings.identity.nickname_len);
    if (ah_display_start(board, nickname) != ESP_OK) {
        ESP_LOGW(TAG, "display failed to start; running headless");
    }
    if (ah_console_start(&settings, board->name) != ESP_OK) {
        ESP_LOGW(TAG, "console unavailable");
    }
    // The node, the console and the LoRa link hold their own copies of the identity; this one goes.
    ah_wipe(&settings.identity, sizeof(settings.identity));
}
