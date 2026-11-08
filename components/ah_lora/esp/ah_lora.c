// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The LoRa task drives the SX1262 through listen, channel check, backoff and
// transmit, and runs the trunk. One mutex guards the radio and the trunk
// together; the task holds it while it works, the mesh task only to hand over
// a packet or read a snapshot.
#include "ah_lora.h"

#include <stddef.h>
#include <string.h>

#include "esp_attr.h"
#include "esp_check.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_rom_crc.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nvs.h"

#include "ah_sx1262.h"

static const char *TAG = "ah_lora";

// The SX126x form of the private sync word 0x12, not LoRaWAN's public 0x34:
// LoRaWAN gateways and the trunk do not demodulate each other's frames.
#define SYNC_WORD 0x1424u
// Part of the modulation, so every node must use the same: constants, not
// settings. 8 symbols is LoRaWAN's preamble and the airtime table's.
#define CODING_RATE 5u
#define PREAMBLE_SYMBOLS 8u
// Channel checks before a frame goes regardless. Nothing in the region rules
// requires listen-before-talk alongside the duty limit; it is courtesy, and
// a channel that never reads clear (an interferer, a false detection) must
// not silence the node.
#define CAD_TRIES 4u
// A CAD over 4 symbols takes under 140 ms even at SF12/125 kHz.
#define CAD_TIMEOUT_MS 500
// The mesh task waits this long for the lock before giving up as busy.
#define SEND_LOCK_MS 20
#define TASK_LOCK_MS 1000
#define RECOVER_RETRY_MS 30000
// How often a listening radio is asked whether it reset on its own: such a
// radio raises no interrupt, so this bounds how long the node is deaf. Two
// short SPI exchanges each time.
#define RADIO_CHECK_MS 5000
#define LEDGER_MAGIC 0x4C445459u
// The ledger's copy in the settings partition, for a power-on (save_ledger).
#define LEDGER_NAMESPACE "ah_lora"
#define LEDGER_KEY "duty"
#define SLOT_BITS 4u
#define SLOT_MASK ((1u << SLOT_BITS) - 1u)

static_assert(AH_TRUNK_NEIGHBORS <= (1u << SLOT_BITS), "slots must fit the handle's low bits");
static_assert(AH_TRUNK_FRAME_MAX <= AH_SX1262_FRAME_MAX, "a trunk frame fits the radio");

typedef enum {
    RADIO_LISTEN = 0,
    RADIO_CAD,
    RADIO_BACKOFF,
    RADIO_TX,
} radio_state_t;

static struct {
    ah_lora_config_t cfg;
    ah_lora_events_t ev;
    ah_trunk_t trunk;
    SemaphoreHandle_t lock;
    TaskHandle_t task;
    bool running;
    bool radio_ok;
    int64_t retry_at_ms;
    radio_state_t state;
    int64_t deadline_ms; // CAD timeout, end of a backoff, or the TX watchdog
    uint8_t cad_tries;
    uint8_t frame[AH_SX1262_FRAME_MAX];
    size_t frame_len;
    int8_t frame_power;
    uint32_t backoff_min_ms;
    uint32_t backoff_max_ms;
    // A handle is a neighbor slot and the slot's generation, so a write meant
    // for a neighbor that left never reaches the next one in its slot.
    uint16_t generation[AH_TRUNK_NEIGHBORS];
    bool refused[AH_TRUNK_NEIGHBORS];
    // Slots whose send found the lock taken: set without the lock, so the
    // task still owes them a `ready` once it lets go.
    uint32_t missed;
    uint8_t rx[AH_SX1262_FRAME_MAX];
    uint32_t cad_busy;
    uint32_t cad_forced;
    uint32_t rx_yields;
    int64_t check_at_ms;
    uint32_t kept_frames; // frames_tx when the ledger was last kept
} s_lora;

// The duty ledger, kept in RTC memory, which a software restart, a panic, the
// task and interrupt watchdogs and a brownout (a reset of the digital core
// alone) leave as it was on the S3 and the C6. A node that resets in a loop
// then never starts a boot with a fresh hour. Checked by a CRC, since a
// power-on, or any reset that clears RTC memory, leaves noise there.
typedef struct {
    uint32_t magic;
    ah_trunk_ledger_t ledger;
    uint32_t crc;
} kept_ledger_t;

static RTC_NOINIT_ATTR kept_ledger_t s_kept;

// A power-on clears RTC memory, so the ledger also goes to flash as the trunk
// starts and whenever ah_trunk_ledger_flush_due says: about 61 small writes an
// hour at full use, and one per boot (docs/MEMORY.md).
static ah_trunk_ledger_t s_flushed;
static int64_t s_flushed_minute = -1;
static bool s_flush_due;

static uint32_t kept_crc(void)
{
    return esp_rom_crc32_le(0, (const uint8_t *)&s_kept, offsetof(kept_ledger_t, crc));
}

static int64_t now_ms(void)
{
    return esp_timer_get_time() / 1000;
}

static uint32_t handle_of(int slot)
{
    return ((uint32_t)s_lora.generation[slot] << SLOT_BITS) | (uint32_t)slot;
}

// The slot `handle` names, or -1 once that neighbor is gone.
static int slot_of(uint32_t handle)
{
    const int slot = (int)(handle & SLOT_MASK);
    if (slot >= (int)AH_TRUNK_NEIGHBORS || ah_trunk_node_at(&s_lora.trunk, slot) == NULL ||
            s_lora.generation[slot] != (uint16_t)(handle >> SLOT_BITS)) {
        return -1;
    }
    return slot;
}

static int gain_at(int dbm)
{
    const ah_lora_radio_t *r = &s_lora.cfg.radio;
    if (r->fem_gain_db == NULL || r->fem_points == 0) {
        return 0;
    }
    int i = dbm < 0 ? 0 : dbm;
    if (i >= r->fem_points) {
        i = r->fem_points - 1;
    }
    return r->fem_gain_db[i];
}

// The SX1262 setting whose output, through any front end, does not pass
// `conducted` dBm at the antenna port: the rule is a ceiling, never a target.
static int8_t radio_setting(int conducted)
{
    for (int dbm = s_lora.cfg.radio.radio_max_dbm; dbm > AH_SX1262_POWER_MIN; --dbm) {
        if (dbm + gain_at(dbm) <= conducted) {
            return (int8_t)dbm;
        }
    }
    return AH_SX1262_POWER_MIN;
}

// The radio stopped answering or never finished. A frame the trunk had
// handed over is lost; its ARQ resends what mattered.
static void radio_failed(bool frame_accepted, int64_t now)
{
    const bool was_sending = s_lora.state != RADIO_LISTEN;
    s_lora.state = RADIO_LISTEN;
    s_lora.radio_ok = ah_sx1262_recover() == ESP_OK;
    s_lora.retry_at_ms = now + RECOVER_RETRY_MS;
    if (frame_accepted && was_sending) {
        ah_trunk_on_tx_done(&s_lora.trunk, now);
    }
}

// Wait, listening, before checking the channel again.
static void backoff(int64_t now, uint32_t min_ms, uint32_t max_ms)
{
    s_lora.state = RADIO_BACKOFF;
    s_lora.deadline_ms = now + (int64_t)(min_ms + esp_random() % (max_ms - min_ms + 1u));
}

// A frame is arriving and the radio kept listening: check again soon, which
// costs no channel check toward sending regardless.
static void yield_to_arrival(int64_t now)
{
    s_lora.rx_yields++;
    backoff(now, s_lora.backoff_min_ms, s_lora.backoff_min_ms);
}

static esp_err_t start_tx(int64_t now)
{
    const esp_err_t err = ah_sx1262_transmit(s_lora.frame, s_lora.frame_len, s_lora.frame_power);
    if (err == ESP_OK) {
        s_lora.state = RADIO_TX;
        s_lora.deadline_ms = now + (int64_t)ah_sx1262_tx_deadline_ms(s_lora.frame_len);
    }
    return err;
}

static esp_err_t start_cad(int64_t now)
{
    const esp_err_t err = ah_sx1262_cad();
    if (err == ESP_OK) {
        s_lora.state = RADIO_CAD;
        s_lora.deadline_ms = now + CAD_TIMEOUT_MS;
    }
    return err;
}

// Check the channel for a held frame; a frame arriving holds it longer.
static void check_channel(int64_t now)
{
    const esp_err_t err = start_cad(now);
    if (err == ESP_ERR_NOT_FINISHED) {
        yield_to_arrival(now);
    } else if (err != ESP_OK) {
        radio_failed(true, now);
    }
}

// Send the held frame now; a frame arriving holds it in a backoff instead.
static void send_held(int64_t now)
{
    const esp_err_t err = start_tx(now);
    if (err == ESP_ERR_NOT_FINISHED) {
        if (ah_sx1262_receive() == ESP_OK) {
            yield_to_arrival(now);
        } else {
            radio_failed(true, now);
        }
    } else if (err != ESP_OK) {
        radio_failed(true, now);
    }
}

// ---- the trunk's operations, on this task with the lock held ----

static void save_ledger(int64_t now)
{
    s_lora.kept_frames = s_lora.trunk.stats.frames_tx;
    ah_trunk_ledger_save(&s_lora.trunk, now, &s_kept.ledger);
    s_kept.magic = LEDGER_MAGIC;
    s_kept.crc = kept_crc();
    const int64_t minute = now / 60000;
    if (s_flushed_minute < 0 ||
            ah_trunk_ledger_flush_due(&s_lora.trunk, &s_kept.ledger, &s_flushed, minute - s_flushed_minute)) {
        s_flushed = s_kept.ledger;
        s_flushed_minute = minute;
        s_flush_due = true;
    }
}

// Outside the lock: a flash write can take a page erase.
static void write_ledger(const ah_trunk_ledger_t *ledger)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(LEDGER_NAMESPACE, NVS_READWRITE, &h);
    if (err == ESP_OK) {
        err = nvs_set_blob(h, LEDGER_KEY, ledger, sizeof(*ledger));
        if (err == ESP_OK) {
            err = nvs_commit(h);
        }
        nvs_close(h);
    }
    if (err != ESP_OK) {
        // The copy in flash is older than s_flushed says: the next save writes.
        s_flushed_minute = -1;
        ESP_LOGW(TAG, "duty ledger not written to flash: %s", esp_err_to_name(err));
    }
}

static bool read_ledger(ah_trunk_ledger_t *out)
{
    nvs_handle_t h;
    if (nvs_open(LEDGER_NAMESPACE, NVS_READONLY, &h) != ESP_OK) {
        return false;
    }
    size_t len = sizeof(*out);
    const bool ok = nvs_get_blob(h, LEDGER_KEY, out, &len) == ESP_OK && len == sizeof(*out);
    nvs_close(h);
    return ok;
}

static bool op_transmit(void *ctx, const uint8_t *frame, size_t len, int8_t power_dbm, bool answer)
{
    (void)ctx;
    if (!s_lora.radio_ok || s_lora.state != RADIO_LISTEN || len > sizeof(s_lora.frame)) {
        return false;
    }
    memcpy(s_lora.frame, frame, len);
    s_lora.frame_len = len;
    s_lora.frame_power = radio_setting(power_dbm);
    s_lora.cad_tries = 0;
    const int64_t now = now_ms();
    // The trunk charged this frame before asking; kept now, an answer that
    // keys the radio at once is in the ledger a reset finds.
    save_ledger(now);
    // An answer goes in its turn without a channel check: its sender is
    // listening for exactly this. One that finds a frame arriving is refused,
    // and the trunk offers it again.
    const esp_err_t err = answer ? start_tx(now) : start_cad(now);
    if (err == ESP_OK) {
        return true;
    }
    if (err == ESP_ERR_NOT_FINISHED) {
        if (answer) {
            s_lora.rx_yields++;
            return false;
        }
        yield_to_arrival(now);
        return true;
    }
    radio_failed(false, now);
    return false;
}

static void op_deliver(void *ctx, int slot, const uint8_t node[AH_TRUNK_NODE_LEN], const uint8_t *packet, size_t len)
{
    (void)ctx;
    (void)node;
    if (slot >= 0) {
        s_lora.ev.frame(handle_of(slot), packet, len);
    }
}

static void op_neighbor(void *ctx, int slot, const uint8_t node[AH_TRUNK_NODE_LEN], bool up)
{
    (void)ctx;
    ESP_LOGI(TAG, "neighbor %02x%02x%02x%02x %s", node[0], node[1], node[2], node[3], up ? "up" : "gone");
    s_lora.refused[slot] = false;
    if (up) {
        s_lora.generation[slot]++;
        s_lora.ev.link_up(handle_of(slot), AH_TRUNK_PACKET_MAX, node);
    } else {
        s_lora.ev.link_down(handle_of(slot));
    }
}

static bool op_pair_key(void *ctx, const uint8_t peer_key[AH_TRUNK_KEY_LEN], const uint8_t peer[AH_TRUNK_NODE_LEN],
                        uint8_t out[AH_TRUNK_KEY_LEN])
{
    (void)ctx;
    return s_lora.cfg.pair_key(peer_key, peer, out);
}

// ---- the task ----

static void on_radio(ah_sx1262_event_t ev, int64_t now)
{
    switch (ev) {
    case AH_SX1262_EVENT_RX_DONE: {
        size_t len = 0;
        int8_t snr = 0;
        int16_t rssi = 0;
        if (ah_sx1262_read(s_lora.rx, sizeof(s_lora.rx), &len, &snr, &rssi) == ESP_OK) {
            // A few frames a minute at most, and what a range test records.
            ESP_LOGI(TAG, "frame in: %u bytes, RSSI %d dBm, SNR %d dB", (unsigned)len, rssi, snr);
            ah_trunk_on_frame(&s_lora.trunk, s_lora.rx, len, snr, now);
        }
        break;
    }
    case AH_SX1262_EVENT_TIMEOUT:
    case AH_SX1262_EVENT_TX_DONE:
        if (s_lora.state != RADIO_TX) {
            break;
        }
        s_lora.state = RADIO_LISTEN;
        if (ah_sx1262_receive() != ESP_OK) {
            radio_failed(false, now);
        }
        ah_trunk_on_tx_done(&s_lora.trunk, now);
        break;
    case AH_SX1262_EVENT_CAD_CLEAR:
        if (s_lora.state == RADIO_CAD) {
            send_held(now);
        }
        break;
    case AH_SX1262_EVENT_CAD_BUSY:
        if (s_lora.state != RADIO_CAD) {
            break;
        }
        s_lora.cad_busy++;
        if (++s_lora.cad_tries >= CAD_TRIES) {
            s_lora.cad_forced++;
            send_held(now);
            break;
        }
        // Listen through the backoff, so frames that start in it are heard.
        if (ah_sx1262_receive() != ESP_OK) {
            radio_failed(true, now);
            break;
        }
        backoff(now, s_lora.backoff_min_ms, s_lora.backoff_max_ms);
        break;
    case AH_SX1262_EVENT_ERROR:
        radio_failed(s_lora.state != RADIO_LISTEN, now);
        break;
    default:
        break;
    }
}

static void run_deadlines(int64_t now)
{
    if (!s_lora.radio_ok && now >= s_lora.retry_at_ms) {
        s_lora.radio_ok = ah_sx1262_recover() == ESP_OK;
        s_lora.retry_at_ms = now + RECOVER_RETRY_MS;
    }
    if (s_lora.radio_ok && s_lora.state == RADIO_LISTEN && now >= s_lora.check_at_ms) {
        s_lora.check_at_ms = now + RADIO_CHECK_MS;
        if (ah_sx1262_check() != ESP_OK) {
            radio_failed(false, now);
        }
    }
    if (s_lora.state == RADIO_LISTEN || now < s_lora.deadline_ms) {
        return;
    }
    if (s_lora.state == RADIO_BACKOFF) {
        check_channel(now);
        return;
    }
    // A CAD or a transmission the radio never finished: the watchdog.
    ESP_LOGW(TAG, "radio stuck in %s; resetting it", s_lora.state == RADIO_TX ? "transmit" : "channel check");
    radio_failed(true, now);
}

// Tell the mesh about links that refused a send and have room again.
static void release_refused(void)
{
    const uint32_t missed = __atomic_exchange_n(&s_lora.missed, 0u, __ATOMIC_ACQ_REL);
    for (int i = 0; i < (int)AH_TRUNK_NEIGHBORS; ++i) {
        if (missed & (1u << i)) {
            s_lora.refused[i] = true;
        }
    }
    for (int i = 0; i < (int)AH_TRUNK_NEIGHBORS; ++i) {
        if (!s_lora.refused[i]) {
            continue;
        }
        const uint8_t *node = ah_trunk_node_at(&s_lora.trunk, i);
        if (node == NULL) {
            s_lora.refused[i] = false;
        } else if (ah_trunk_room(&s_lora.trunk, node)) {
            s_lora.refused[i] = false;
            s_lora.ev.ready(handle_of(i));
        }
    }
}

// Every charge is a frame sent, so the ledger is kept when one went.
static void keep_ledger(int64_t now)
{
    if (s_lora.trunk.stats.frames_tx != s_lora.kept_frames) {
        save_ledger(now);
    }
}

// Registered without ESP_INTR_FLAG_IRAM (see ah_sx1262_init), so it may live
// in flash and use FreeRTOS from flash.
static void dio1_isr(void *arg)
{
    (void)arg;
    BaseType_t woken = pdFALSE;
    if (s_lora.task != NULL) {
        vTaskNotifyGiveFromISR(s_lora.task, &woken);
    }
    portYIELD_FROM_ISR(woken);
}

static void lora_task(void *arg)
{
    (void)arg;
    ESP_ERROR_CHECK(esp_task_wdt_add(NULL));
    int64_t next_tick = 0;
    for (;;) {
        int64_t wake = next_tick;
        if (s_lora.state != RADIO_LISTEN && s_lora.deadline_ms < wake) {
            wake = s_lora.deadline_ms;
        }
        int64_t wait = wake - now_ms();
        wait = wait < 0 ? 0 : wait > 1000 ? 1000 : wait;
        // Round up, so a wait shorter than a tick sleeps one rather than spinning.
        ulTaskNotifyTake(pdTRUE, (TickType_t)((wait + portTICK_PERIOD_MS - 1) / portTICK_PERIOD_MS));
        if (xSemaphoreTake(s_lora.lock, pdMS_TO_TICKS(TASK_LOCK_MS)) == pdTRUE) {
            const int64_t now = now_ms();
            // DIO1 stays high while any cause is pending; take them all.
            for (int i = 0; i < 4; ++i) {
                const ah_sx1262_event_t ev = ah_sx1262_poll();
                if (ev == AH_SX1262_EVENT_NONE) {
                    break;
                }
                on_radio(ev, now);
            }
            run_deadlines(now);
            next_tick = ah_trunk_tick(&s_lora.trunk, now);
            keep_ledger(now);
            release_refused();
            ah_trunk_ledger_t flush;
            const bool flush_now = s_flush_due;
            if (flush_now) {
                flush = s_flushed;
                s_flush_due = false;
            }
            xSemaphoreGive(s_lora.lock);
            if (flush_now) {
                write_ledger(&flush);
            }
        }
        esp_task_wdt_reset();
    }
}

// ---- the mesh task's side ----

ah_lora_send_t ah_lora_send(uint32_t handle, const uint8_t *packet, size_t len, uint8_t prio)
{
    if (!s_lora.running || len == 0 || len > AH_TRUNK_PACKET_MAX) {
        return AH_LORA_SEND_GONE;
    }
    if (xSemaphoreTake(s_lora.lock, pdMS_TO_TICKS(SEND_LOCK_MS)) != pdTRUE) {
        // The task is mid recovery or mid exchange: busy, and owed a `ready`.
        __atomic_fetch_or(&s_lora.missed, 1u << (handle & SLOT_MASK), __ATOMIC_ACQ_REL);
        xTaskNotifyGive(s_lora.task);
        return AH_LORA_SEND_BUSY;
    }
    ah_lora_send_t r = AH_LORA_SEND_GONE;
    const int slot = slot_of(handle);
    if (slot >= 0) {
        if (ah_trunk_send(&s_lora.trunk, ah_trunk_node_at(&s_lora.trunk, slot), packet, len, prio, now_ms())) {
            r = AH_LORA_SEND_OK;
        } else {
            s_lora.refused[slot] = true;
            r = AH_LORA_SEND_BUSY;
        }
    }
    xSemaphoreGive(s_lora.lock);
    if (r == AH_LORA_SEND_OK) {
        xTaskNotifyGive(s_lora.task);
    }
    return r;
}

bool ah_lora_set_bound(uint32_t handle)
{
    if (!s_lora.running || xSemaphoreTake(s_lora.lock, pdMS_TO_TICKS(SEND_LOCK_MS)) != pdTRUE) {
        return false;
    }
    const int slot = slot_of(handle);
    if (slot >= 0) {
        ah_trunk_set_bound(&s_lora.trunk, ah_trunk_node_at(&s_lora.trunk, slot));
    }
    xSemaphoreGive(s_lora.lock);
    return true;
}

bool ah_lora_links(ah_lora_link_t out[AH_TRUNK_NEIGHBORS], size_t *count)
{
    *count = 0;
    if (!s_lora.running || xSemaphoreTake(s_lora.lock, pdMS_TO_TICKS(SEND_LOCK_MS)) != pdTRUE) {
        return false;
    }
    for (int i = 0; i < (int)AH_TRUNK_NEIGHBORS; ++i) {
        const uint8_t *node = ah_trunk_node_at(&s_lora.trunk, i);
        if (node != NULL) {
            out[*count] = (ah_lora_link_t) {
                .handle = handle_of(i), .room = ah_trunk_room(&s_lora.trunk, node)
            };
            memcpy(out[*count].node, node, AH_TRUNK_NODE_LEN);
            (*count)++;
        }
    }
    xSemaphoreGive(s_lora.lock);
    return true;
}

void ah_lora_status(ah_lora_status_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!s_lora.running || xSemaphoreTake(s_lora.lock, pdMS_TO_TICKS(SEND_LOCK_MS)) != pdTRUE) {
        return;
    }
    out->running = s_lora.radio_ok;
    for (int i = 0; i < (int)AH_TRUNK_NEIGHBORS; ++i) {
        out->neighbors += ah_trunk_node_at(&s_lora.trunk, i) != NULL ? 1u : 0u;
    }
    out->airtime_ms = ah_trunk_airtime_used(&s_lora.trunk, now_ms());
    out->budget_ms = ah_trunk_budget_ms(&s_lora.trunk);
    out->max_power_dbm = s_lora.trunk.cfg.max_power_dbm;
    out->trunk = s_lora.trunk.stats;
    out->cad_busy = s_lora.cad_busy;
    out->cad_forced = s_lora.cad_forced;
    out->rx_yields = s_lora.rx_yields;
    xSemaphoreGive(s_lora.lock);
}

esp_err_t ah_lora_start(const ah_lora_config_t *config, const ah_lora_events_t *events)
{
    const ah_lora_region_t *region = ah_lora_region(config->region);
    ESP_RETURN_ON_FALSE(region != NULL, ESP_ERR_INVALID_ARG, TAG, "no region");
    ESP_RETURN_ON_FALSE(!s_lora.running, ESP_ERR_INVALID_STATE, TAG, "already started");
    ESP_RETURN_ON_FALSE(config->pair_key != NULL, ESP_ERR_INVALID_ARG, TAG, "no pair key");
    s_lora.cfg = *config;
    s_lora.ev = *events;
    const ah_lora_radio_t *r = &config->radio;
    const int board_max = r->radio_max_dbm + gain_at(r->radio_max_dbm);
    const int8_t limit = ah_lora_power_limit(region, config->antenna_gain_ddbi, (int8_t)board_max);
    // The radio's lowest setting through the board's front end: a front end
    // of high gain, an antenna of high gain and a low-power region can leave
    // it over the limit, and then no power the node can choose is legal.
    const int lowest = AH_SX1262_POWER_MIN + gain_at(AH_SX1262_POWER_MIN);
    ESP_RETURN_ON_FALSE(lowest <= limit, ESP_ERR_INVALID_ARG, TAG,
                        "even the lowest power, %d dBm, is over the %d dBm limit for this antenna", lowest, limit);
    const ah_lora_phy_t phy = {
        .spreading_factor = region->spreading_factor,
        .bandwidth_hz = region->bandwidth_hz,
        .coding_rate = CODING_RATE,
        .preamble_symbols = PREAMBLE_SYMBOLS,
    };
    const ah_sx1262_config_t radio = {
        .pin_sck = r->pin_sck,
        .pin_miso = r->pin_miso,
        .pin_mosi = r->pin_mosi,
        .pin_nss = r->pin_nss,
        .pin_reset = r->pin_reset,
        .pin_busy = r->pin_busy,
        .pin_dio1 = r->pin_dio1,
        .pin_rxen = r->pin_rxen,
        .pin_txen = r->pin_txen,
        .dio2_rf_switch = r->dio2_rf_switch,
        .tcxo_mv = r->tcxo_mv,
        .frequency_hz = region->frequency_hz,
        .phy = phy,
        .sync_word = SYNC_WORD,
    };
    s_lora.lock = xSemaphoreCreateMutex();
    ESP_RETURN_ON_FALSE(s_lora.lock != NULL, ESP_ERR_NO_MEM, TAG, "lock");
    const esp_err_t err = ah_sx1262_init(&radio, dio1_isr, NULL);
    if (err != ESP_OK) {
        vSemaphoreDelete(s_lora.lock);
        return err;
    }
    s_lora.radio_ok = true;

    ah_trunk_config_t tc = {
        .region = region,
        .phy = phy,
        .max_power_dbm = limit,
    };
    memcpy(tc.self, config->self, sizeof(tc.self));
    memcpy(tc.key, config->key, sizeof(tc.key));
    const ah_trunk_ops_t ops = {
        .transmit = op_transmit, .deliver = op_deliver, .neighbor = op_neighbor, .pair_key = op_pair_key
    };
    uint8_t seed[8];
    esp_fill_random(seed, sizeof(seed));
    ah_trunk_init(&s_lora.trunk, &tc, &ops, seed, now_ms());
    // RTC memory survives a reset, flash a power-on; with neither the hour
    // before is taken as spent.
    const bool kept =
        esp_reset_reason() != ESP_RST_POWERON && s_kept.magic == LEDGER_MAGIC && s_kept.crc == kept_crc();
    ah_trunk_ledger_t stored;
    const bool flashed = !kept && read_ledger(&stored);
    ah_trunk_ledger_restore(&s_lora.trunk, kept ? &s_kept.ledger : flashed ? &stored : NULL, flashed, now_ms());
    s_lora.kept_frames = UINT32_MAX;
    keep_ledger(now_ms());
    if (s_flush_due) {
        s_flush_due = false;
        write_ledger(&s_flushed);
    }
    ESP_LOGI(TAG, "duty ledger %s: %lu of %lu ms spent",
             kept ? "carried over the reset" : flashed ? "restored from flash" : "taken as spent",
             (unsigned long)ah_trunk_airtime_used(&s_lora.trunk, now_ms()),
             (unsigned long)ah_trunk_budget_ms(&s_lora.trunk));
    // A backoff of half an answer up to one full frame: about how long a
    // channel found busy stays busy.
    s_lora.backoff_min_ms = ah_lora_airtime_ms(&phy, AH_TRUNK_ANSWER_LEN) / 2u;
    s_lora.backoff_max_ms = ah_lora_airtime_ms(&phy, AH_TRUNK_FRAME_MAX);

    s_lora.running = true;
    if (xTaskCreatePinnedToCore(lora_task, "lora", config->task_stack, NULL, config->task_priority, &s_lora.task,
                                config->task_core) != pdPASS) {
        s_lora.running = false;
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "trunk on %s: %lu Hz, SF%u, %lu kHz, %d dBm conducted (radio %d dBm), duty %u per mille",
             region->code, (unsigned long)region->frequency_hz, region->spreading_factor,
             (unsigned long)(region->bandwidth_hz / 1000u), tc.max_power_dbm, radio_setting(tc.max_power_dbm),
             region->duty_per_mille);
    return ESP_OK;
}
