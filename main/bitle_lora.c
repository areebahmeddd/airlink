#include "bitle_lora.h"

#include <math.h>
#include <string.h>

#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"

#include "bitchat_ble.h"
#include "bitle_link.h"
#include "bitle_mesh.h"
#include "bitle_stats.h"
#include "lora_airtime.h"
#include "lora_packet_reliability.h"
#include "lora_region.h"
#include "lora_trunk_protocol.h"
#include "lora_tx_scheduler.h"
#include "noise_handshake.h"
#include "packet_codec.h"
#include "sx1262.h"

static const char *TAG = "bitle_lora";

/* --- Trunk admission policy -----------------------------------------------
 * The LoRa trunk is bandwidth-precious (default SF10/BW125 ~= 1 kbps shared,
 * whole-packet airtimes from hundreds of ms to seconds), so not everything
 * the mesh would relay over BLE belongs on it. Encoded BitChat header
 * offsets (see packet_codec): [1]=type, [2]=ttl, [14..21]=sender id. */
#define PKT_TYPE_OFF    1
#define PKT_SENDER_OFF  14
#define PKT_MIN_LEN     22

/* Per-origin throttle for identity/announce floods: an announce carries no
 * time-critical content, so one per origin per interval is plenty for
 * discovery while a chatty phone cannot monopolize the channel. */
#define THROTTLE_SLOTS           8
#define ANNOUNCE_MIN_INTERVAL_MS 30000ULL

/* Airtime governor (token bucket, credit measured in milliseconds of
 * on-air time). Refills at duty_frac of wall time up to a burst ceiling;
 * every transmitted packet debits its computed airtime. Protects the
 * shared channel and our own power budget regardless of relay volume. */
#define GOV_BURST_MS   5000.0

/* Board wiring for the LoRa trunk, selected via Kconfig (menuconfig →
 * Bitle hardware → SX1262 board wiring). XIAO pins per the board's shipping
 * Meshtastic variant; Heltec V3 pins per the MeshCore heltec_v3 variant.
 * With no wiring selected the boot probe finds no radio and the node runs
 * BLE-only. */
#if CONFIG_BITLE_LORA_BOARD_HELTEC_V3
#define LORA_PIN_SCK   9
#define LORA_PIN_MISO  11
#define LORA_PIN_MOSI  10
#define LORA_PIN_CS    8
#define LORA_PIN_RESET 12
#define LORA_PIN_BUSY  13
#define LORA_PIN_DIO1  14
#define LORA_PIN_RXEN  -1  /* DIO2 keys the RF switch; no board RXEN */
#elif CONFIG_BITLE_LORA_BOARD_XIAO_WIO_SX1262
#define LORA_PIN_SCK   7
#define LORA_PIN_MISO  8
#define LORA_PIN_MOSI  9
#define LORA_PIN_CS    41
#define LORA_PIN_RESET 42
#define LORA_PIN_BUSY  40
#define LORA_PIN_DIO1  39
#define LORA_PIN_RXEN  38
#else
#define LORA_PIN_SCK   -1
#define LORA_PIN_MISO  -1
#define LORA_PIN_MOSI  -1
#define LORA_PIN_CS    -1
#define LORA_PIN_RESET -1
#define LORA_PIN_BUSY  -1
#define LORA_PIN_DIO1  -1
#define LORA_PIN_RXEN  -1
#endif

#if defined(CONFIG_BITLE_LORA_REGION_EU868) && CONFIG_BITLE_LORA_REGION_EU868
#define LORA_DEFAULT_REGION LORA_REGION_EU868
#else
#define LORA_DEFAULT_REGION LORA_REGION_US915
#endif

#ifdef CONFIG_BITLE_LORA_DEFAULT_SF
#define LORA_DEFAULT_SF CONFIG_BITLE_LORA_DEFAULT_SF
#else
#define LORA_DEFAULT_SF 10
#endif

#ifdef CONFIG_BITLE_LORA_PREAMBLE_SYMBOLS
#define LORA_PREAMBLE_SYMBOLS CONFIG_BITLE_LORA_PREAMBLE_SYMBOLS
#else
#define LORA_PREAMBLE_SYMBOLS 16
#endif

/* v3 uses the portable parser/encoder in lora_trunk_protocol. RX retains the
 * documented v2 migration path, whose shorter header permits a larger legacy
 * chunk than v3. TX caps chunks well below either wire maximum so each frame's
 * on-air time stays short. */
#define TRUNK_CHUNK_RX_MAX \
    (SX1262_MAX_PAYLOAD - LORA_TRUNK_V2_HEADER_LEN)
#define TRUNK_CHUNK_TX   120
#define TRUNK_MAX_FRAGS  ((BITCHAT_BLE_MAX_PACKET_SIZE + TRUNK_CHUNK_TX - 1) / TRUNK_CHUNK_TX)

/* Channel access: CAD (listen-before-talk) + random backoff before TX. */
#define CAD_RETRIES      5
#define CAD_BACKOFF_MIN  30
#define CAD_BACKOFF_SPAN 120
#define ACK_BURST_MAX    4
#define RELIABILITY_CONTENTION_MS \
    (1200U + CAD_RETRIES * (CAD_BACKOFF_MIN + CAD_BACKOFF_SPAN))

typedef struct {
    uint16_t len;
    bool want_ack;
    uint8_t data[SX1262_MAX_PAYLOAD];
} lora_frame_t;

_Static_assert(BITCHAT_BLE_MAX_PACKET_SIZE <= LORA_TX_PACKET_MAX_LEN,
               "LoRa packet pool must hold the largest BitChat packet");

static lora_tx_scheduler_t s_tx_scheduler;
static TaskHandle_t s_task;
static bool s_active;
static uint8_t s_node_id[LORA_TRUNK_V3_NODE_ID_LEN];
static uint8_t s_boot_epoch[8];
static uint32_t s_transfer_counter;

typedef struct {
    bool valid;
    bool ack_requested;
    uint8_t destination[LORA_TRUNK_V3_NODE_ID_LEN];
    uint8_t transfer_id[LORA_TRUNK_V3_TRANSFER_ID_LEN];
} tx_trunk_context_t;
static tx_trunk_context_t s_tx_context[LORA_TX_PACKET_POOL_SIZE];

/* Packet-level feedback is consumed on the LoRa task. RX and TX state are
 * therefore serialized without another lock. */
static bool s_feedback_seen;
static bool s_expected_control_valid;
static lora_trunk_frame_t s_expected_control_data;
static lora_selective_tx_t s_selective_tx;
static lora_trunk_neighbor_table_t s_neighbors;

/* Modem params (for airtime), governor, and throttle state — shared
 * between relay callers and the beacon path, guarded by a spinlock. */
static uint8_t s_sf;
static uint32_t s_bw;
static uint8_t s_cr;             /* denominator 5..8 => 4/5..4/8 */
static uint16_t s_preamble_symbols;
static bool s_ota_over_trunk;    /* OTA image chunks on the trunk (default off) */
static bitle_lora_diag_t s_diag;

static portMUX_TYPE s_gov_mux = portMUX_INITIALIZER_UNLOCKED;
static double s_gov_credit_ms;
static double s_gov_refill_frac; /* airtime allowed per ms of wall time */
static uint64_t s_gov_last_ms;

typedef struct {
    bool in_use;
    uint8_t tag[8];
    uint64_t last_ms;
} throttle_t;
static throttle_t s_throttle[THROTTLE_SLOTS];

/* Firmware wrapper around the host-testable Semtech time-on-air calculation. */
static uint32_t trunk_airtime_ms(uint16_t payload_len)
{
    lora_airtime_params_t params = {
        .spreading_factor = s_sf,
        .bandwidth_hz = s_bw,
        .coding_rate = s_cr,
        .preamble_symbols = s_preamble_symbols,
        .explicit_header = true,
        .crc_enabled = true,
    };
    return lora_airtime_ms(&params, payload_len);
}

static bool trunk_reliability_timing(
    uint8_t fragment_total, lora_reliability_timing_t *out)
{
    return lora_reliability_timing(
        trunk_airtime_ms(LORA_TRUNK_V3_HEADER_LEN + TRUNK_CHUNK_TX),
        trunk_airtime_ms(LORA_TRUNK_V3_HEADER_LEN),
        fragment_total,
        LORA_SELECTIVE_REPEAT_ROUNDS,
        RELIABILITY_CONTENTION_MS,
        out);
}

static void diag_inc(uint32_t *counter)
{
    taskENTER_CRITICAL(&s_gov_mux);
    (*counter)++;
    taskEXIT_CRITICAL(&s_gov_mux);
}

/* Caller holds s_gov_mux. */
static void diag_sync_scheduler_locked(void)
{
    lora_tx_scheduler_metrics_t metrics;
    lora_tx_scheduler_metrics(&s_tx_scheduler, &metrics);
    s_diag.queue_depth = metrics.in_use;
    s_diag.queue_high_water = metrics.high_water;
    s_diag.packet_released = metrics.released;
    s_diag.packet_cancelled = metrics.cancelled;
    for (size_t priority = 0; priority < LORA_TX_PRIORITY_COUNT; ++priority) {
        s_diag.packet_accepted[priority] = metrics.accepted[priority];
        s_diag.packet_deferred[priority] = metrics.deferred[priority];
    }
}

/* Per-origin announce throttle (call inside the governor critical section).
 * Returns true if this sender's announce should be dropped now. */
static bool announce_throttled(const uint8_t *sender, uint64_t now)
{
    throttle_t *slot = NULL, *free_slot = NULL, *oldest = &s_throttle[0];
    for (size_t i = 0; i < THROTTLE_SLOTS; ++i) {
        throttle_t *t = &s_throttle[i];
        if (t->in_use && memcmp(t->tag, sender, 8) == 0) {
            slot = t;
        } else if (!t->in_use && !free_slot) {
            free_slot = t;
        }
        if (t->last_ms < oldest->last_ms) {
            oldest = t;
        }
    }
    if (slot) {
        if (now - slot->last_ms < ANNOUNCE_MIN_INTERVAL_MS) {
            return true;
        }
        slot->last_ms = now;
        return false;
    }
    slot = free_slot ? free_slot : oldest;
    slot->in_use = true;
    memcpy(slot->tag, sender, 8);
    slot->last_ms = now;
    return false;
}

/* Admission + governor for one whole encoded packet. Caller holds s_gov_mux,
 * which couples the policy state change to the scheduler admission. */
static bool trunk_admit_locked(const uint8_t *data, uint16_t len)
{
    if (len < PKT_MIN_LEN) {
        return false;
    }
    uint8_t type = data[PKT_TYPE_OFF];
    bool ota = (type >= 0xA0 && type <= 0xA3);
    bool announce = (type == BITCHAT_MSG_ANNOUNCE || type == BITCHAT_MSG_NOISE_IDENTITY_ANNOUNCE);
    /* Message-class traffic is user-driven, rare, and time-critical: a Noise
     * handshake, DM, courier envelope, or receipt must never be dropped for
     * airtime budget. Only the automatic, periodic announce/beacon traffic is
     * governed. At SF10 one handshake message is several seconds on air, so
     * governing message traffic would let a single DM exhaust the budget and
     * drop its own follow-up frames. */
    bool governed = announce;

    /* OTA image transfer is enormous on air; opt-in only. */
    if (ota && !s_ota_over_trunk) {
        return false;
    }

    /* Self-originated session-init and gossip requestSync are suppressed at the
     * source for broadcast links (see bitle_link_is_broadcast), so the trunk
     * does not filter self-originated traffic here: a node's own directed
     * replies (handshake responses, encrypted messages, receipts) — sent when
     * it is itself the DM target reached over LoRa — must cross. */

    /* Total airtime across every fragment this packet becomes. */
    uint8_t total = (uint8_t)((len + TRUNK_CHUNK_TX - 1) / TRUNK_CHUNK_TX);
    uint32_t airtime = 0;
    for (uint8_t i = 0; i < total; ++i) {
        uint16_t off = (uint16_t)i * TRUNK_CHUNK_TX;
        uint16_t chunk = len - off < TRUNK_CHUNK_TX ? len - off : TRUNK_CHUNK_TX;
        airtime += trunk_airtime_ms(LORA_TRUNK_V3_HEADER_LEN + chunk);
    }

    /* Reading the clock under the lock prevents another producer from
     * advancing s_gov_last_ms past this sample. */
    uint64_t now = esp_timer_get_time() / 1000ULL;
    /* Refill the shared airtime credit. */
    s_gov_credit_ms += (double)(now - s_gov_last_ms) * s_gov_refill_frac;
    if (s_gov_credit_ms > GOV_BURST_MS) {
        s_gov_credit_ms = GOV_BURST_MS;
    }
    s_gov_last_ms = now;
    /* Governed (announce) traffic yields when the budget is exhausted; it is
     * periodic and will re-announce. Message traffic always passes but still
     * debits, so a busy DM session naturally suppresses announces until the
     * channel frees up. Check the budget before the per-origin throttle records
     * a timestamp, so a budget-deferred announce does not suppress this
     * origin's next transmittable announce. */
    if (governed) {
        if (s_gov_credit_ms < (double)airtime) {
            ESP_LOGD(TAG, "airtime budget low; deferring announce");
            return false;
        }
        if (announce_throttled(data + PKT_SENDER_OFF, now)) {
            return false;
        }
    }
    s_gov_credit_ms -= airtime;
    if (s_gov_credit_ms < -GOV_BURST_MS) {
        s_gov_credit_ms = -GOV_BURST_MS;
    }
    return true;
}

/* Reassembly stays statically bounded. Progress and absolute deadlines are
 * profile-derived per transfer; the completed cache answers a sender that
 * missed COMPLETE without delivering the BitChat packet twice. */
typedef struct {
    bool in_use;
    bool addressed;
    uint8_t version;
    uint8_t src[LORA_TRUNK_V3_NODE_ID_LEN];
    uint8_t transfer_id[LORA_TRUNK_V3_TRANSFER_ID_LEN];
    uint16_t capabilities;
    uint8_t total;
    uint8_t have_mask;
    uint64_t started_ms;
    uint64_t progress_deadline_ms;
    uint64_t absolute_deadline_ms;
    uint16_t part_len[TRUNK_MAX_FRAGS];
    uint8_t part[TRUNK_MAX_FRAGS][TRUNK_CHUNK_RX_MAX];
} rx_slot_t;

#define RX_SLOTS 2
#define COMPLETED_SLOTS 6

typedef struct {
    bool in_use;
    bool addressed;
    uint8_t version;
    uint8_t src[LORA_TRUNK_V3_NODE_ID_LEN];
    uint8_t transfer_id[LORA_TRUNK_V3_TRANSFER_ID_LEN];
    uint8_t total;
    uint64_t expires_ms;
} completed_slot_t;

static rx_slot_t s_rx_slots[RX_SLOTS];
static completed_slot_t s_completed_slots[COMPLETED_SLOTS];

static void abort_rx_slot(rx_slot_t *slot, uint8_t reason);

static void IRAM_ATTR dio1_isr(void *arg)
{
    BaseType_t woken = pdFALSE;
    vTaskNotifyGiveFromISR((TaskHandle_t)arg, &woken);
    portYIELD_FROM_ISR(woken);
}

static bool recover_radio(const char *reason)
{
    ESP_LOGW(TAG, "radio recovery requested: %s", reason);
    for (size_t i = 0; i < RX_SLOTS; ++i) {
        abort_rx_slot(
            &s_rx_slots[i], LORA_TRUNK_ABORT_RADIO_RESET);
    }
    esp_err_t err = sx1262_recover();
    if (err == ESP_OK) {
        return true;
    }
    s_active = false;
    ESP_LOGE(TAG, "radio recovery failed: %s", esp_err_to_name(err));
    return false;
}

static bool resume_rx_or_recover(const char *reason)
{
    esp_err_t err = sx1262_resume_rx();
    if (err == ESP_OK) {
        return true;
    }
    ESP_LOGW(TAG, "resume RX failed: %s", esp_err_to_name(err));
    return recover_radio(reason);
}

/* True length of the self-describing BitChat packet, dropping any trailing
 * MessagePadding (phones pad handshakes/DMs to 256 B for BLE traffic-analysis
 * resistance — a pure BLE-MTU artifact that just bloats scarce LoRa airtime).
 * Header: version|type|ttl|ts(8)|flags|payloadLen(2)|sender(8)|[recipient(8) if
 * flags&0x01]|payload|[sig(64) if flags&0x02]. Padding is appended AFTER the
 * signature, so trimming to true length never touches signed/encrypted bytes;
 * receivers read payloadLen and already accept unpadded packets. Returns len
 * unchanged if the header does not parse or claims more than we received. */
static uint16_t trunk_true_len(const uint8_t *data, uint16_t len)
{
    if (len < 14) {
        return len;
    }
    uint8_t flags = data[11];
    uint16_t payload_len = ((uint16_t)data[12] << 8) | data[13];
    uint32_t real = 22u + payload_len;          /* header(22) + payload */
    if (flags & 0x01) {
        real += 8;                              /* recipient id */
    }
    if (flags & 0x02) {
        real += 64;                             /* Ed25519 signature */
    }
    return (real <= len) ? (uint16_t)real : len;
}

static lora_tx_priority_t trunk_priority(uint8_t type)
{
    switch (type) {
    case BITCHAT_MSG_NOISE_HANDSHAKE:
    case BITCHAT_MSG_LEAVE:
    case BITCHAT_MSG_REQUEST_SYNC:
    case BITLE_MSG_OTA_MANIFEST:
    case BITLE_MSG_OTA_REQ:
    case BITLE_MSG_OTA_STATUS:
        return LORA_TX_PRIORITY_CONTROL;
    case BITCHAT_MSG_ANNOUNCE:
    case BITCHAT_MSG_NOISE_IDENTITY_ANNOUNCE:
    case BITCHAT_MSG_PREKEY_BUNDLE:
        return LORA_TX_PRIORITY_DISCOVERY;
    case BITLE_MSG_OTA_CHUNK:
        return LORA_TX_PRIORITY_BULK;
    default:
        return LORA_TX_PRIORITY_USER;
    }
}

static bitle_link_send_result_t lora_link_reserve(
    uint16_t handle, uint8_t packet_type, uintptr_t *out_token)
{
    (void)handle;
    if (!s_active || !out_token) {
        return BITLE_LINK_SEND_FAILED;
    }
    lora_tx_priority_t priority = trunk_priority(packet_type);
    lora_tx_handle_t reserved = LORA_TX_HANDLE_INVALID;

    taskENTER_CRITICAL(&s_gov_mux);
    lora_tx_admit_result_t result = lora_tx_scheduler_reserve(
        &s_tx_scheduler, priority, &reserved);
    if (result == LORA_TX_ADMIT_DEFERRED) {
        s_diag.queue_full++;
    }
    diag_sync_scheduler_locked();
    taskEXIT_CRITICAL(&s_gov_mux);

    if (result != LORA_TX_ADMIT_ACCEPTED) {
        return result == LORA_TX_ADMIT_DEFERRED
                   ? BITLE_LINK_SEND_DEFERRED
                   : BITLE_LINK_SEND_FAILED;
    }
    *out_token = reserved;
    return BITLE_LINK_SEND_ACCEPTED;
}

static void lora_link_cancel(uint16_t handle, uintptr_t token)
{
    (void)handle;
    if (token >= LORA_TX_PACKET_POOL_SIZE) {
        return;
    }
    taskENTER_CRITICAL(&s_gov_mux);
    memset(&s_tx_context[token], 0, sizeof(s_tx_context[token]));
    lora_tx_scheduler_cancel(
        &s_tx_scheduler, (lora_tx_handle_t)token);
    diag_sync_scheduler_locked();
    taskEXIT_CRITICAL(&s_gov_mux);
}

static bitle_link_send_result_t lora_link_commit(
    uint16_t handle, uintptr_t token, const uint8_t *data, uint16_t len)
{
    (void)handle;
    if (!data || len == 0 || len > BITCHAT_BLE_MAX_PACKET_SIZE ||
        token >= LORA_TX_PACKET_POOL_SIZE) {
        lora_link_cancel(handle, token);
        return BITLE_LINK_SEND_FAILED;
    }
    len = trunk_true_len(data, len);
    if (len < PKT_MIN_LEN) {
        lora_link_cancel(handle, token);
        return BITLE_LINK_SEND_FAILED;
    }

    uint8_t type = data[PKT_TYPE_OFF];
    lora_tx_priority_t priority = trunk_priority(type);
    lora_tx_handle_t reserved = (lora_tx_handle_t)token;
    uint32_t transfer_counter = 0;
    uint8_t transfer_id[LORA_TRUNK_V3_TRANSFER_ID_LEN] = {0};
    uint8_t destination[LORA_TRUNK_V3_NODE_ID_LEN] = {0};
    bool ack_requested = false;
    bool committed = false;

    taskENTER_CRITICAL(&s_gov_mux);
    const lora_tx_packet_t *reservation =
        lora_tx_scheduler_packet(&s_tx_scheduler, reserved);
    if (!s_active || !reservation || reservation->len != 0 ||
        reservation->priority != priority) {
        lora_tx_scheduler_cancel(&s_tx_scheduler, reserved);
        diag_sync_scheduler_locked();
        taskEXIT_CRITICAL(&s_gov_mux);
        return BITLE_LINK_SEND_FAILED;
    }
    if (!trunk_admit_locked(data, len)) {
        s_diag.policy_drops++;
        lora_tx_scheduler_cancel(&s_tx_scheduler, reserved);
        diag_sync_scheduler_locked();
        taskEXIT_CRITICAL(&s_gov_mux);
        return BITLE_LINK_SEND_POLICY_DROPPED;
    }
    transfer_counter = s_transfer_counter + 1;
    if (transfer_counter == 0) {
        lora_tx_scheduler_cancel(&s_tx_scheduler, reserved);
        diag_sync_scheduler_locked();
        taskEXIT_CRITICAL(&s_gov_mux);
        return BITLE_LINK_SEND_FAILED;
    }
    lora_trunk_make_transfer_id(
        s_boot_epoch, transfer_counter, transfer_id);

    /* BitChat recipient starts immediately after the fixed 22-byte packet
     * header. Only a fresh authenticated announce may supply a directed route;
     * unknown routes stay reachable as unacknowledged broadcasts. */
    if ((data[11] & 0x01u) != 0 && len >= 30) {
        uint16_t route_capabilities = 0;
        uint64_t now_ms = esp_timer_get_time() / 1000ULL;
        if (lora_trunk_neighbor_route(
                &s_neighbors, data + 22, now_ms, 180000ULL,
                destination, &route_capabilities) &&
            (route_capabilities & LORA_TRUNK_V3_CAP_PROTOCOL) != 0) {
            ack_requested = true;
        } else {
            memset(destination, 0, sizeof(destination));
        }
    }
    committed = lora_tx_scheduler_commit(
        &s_tx_scheduler, reserved, data, len, type,
        (uint16_t)transfer_counter);
    if (committed) {
        tx_trunk_context_t *context = &s_tx_context[reserved];
        context->valid = true;
        context->ack_requested = ack_requested;
        memcpy(context->destination, destination, sizeof(destination));
        memcpy(context->transfer_id, transfer_id, sizeof(transfer_id));
        s_transfer_counter = transfer_counter;
    } else {
        memset(&s_tx_context[reserved], 0, sizeof(s_tx_context[reserved]));
        lora_tx_scheduler_cancel(&s_tx_scheduler, reserved);
    }
    diag_sync_scheduler_locked();
    taskEXIT_CRITICAL(&s_gov_mux);

    if (!committed) {
        return BITLE_LINK_SEND_FAILED;
    }
    uint8_t total =
        (uint8_t)((len + TRUNK_CHUNK_TX - 1) / TRUNK_CHUNK_TX);
    ESP_LOGI(TAG,
             "trunk accepted type=0x%02X len=%u frags=%u priority=%u "
             "addressed=%d transfer=%lu",
             type, len, total, priority, ack_requested,
             (unsigned long)transfer_counter);
    bitle_stats_note_activity(BITLE_LANE_TRUNK, 1);
    if (s_task) {
        xTaskNotifyGive(s_task);
    }
    return BITLE_LINK_SEND_ACCEPTED;
}

/* Mesh -> trunk convenience path. Reservation happens before policy state or
 * sequence assignment changes, and commit publishes the whole packet once. */
static bitle_link_send_result_t lora_link_send(
    uint16_t handle, const uint8_t *data, uint16_t len)
{
    if (!data || len <= PKT_TYPE_OFF) {
        return BITLE_LINK_SEND_FAILED;
    }
    uintptr_t token = 0;
    bitle_link_send_result_t result =
        lora_link_reserve(handle, data[PKT_TYPE_OFF], &token);
    if (result != BITLE_LINK_SEND_ACCEPTED) {
        return result;
    }
    return lora_link_commit(handle, token, data, len);
}

static bool tx_scheduler_dequeue(lora_tx_handle_t *out_handle)
{
    taskENTER_CRITICAL(&s_gov_mux);
    bool dequeued =
        lora_tx_scheduler_dequeue(&s_tx_scheduler, out_handle);
    diag_sync_scheduler_locked();
    taskEXIT_CRITICAL(&s_gov_mux);
    return dequeued;
}

static void tx_scheduler_release(lora_tx_handle_t handle)
{
    if (handle == LORA_TX_HANDLE_INVALID) {
        return;
    }
    taskENTER_CRITICAL(&s_gov_mux);
    memset(&s_tx_context[handle], 0, sizeof(s_tx_context[handle]));
    lora_tx_scheduler_release(&s_tx_scheduler, handle);
    diag_sync_scheduler_locked();
    taskEXIT_CRITICAL(&s_gov_mux);
    s_expected_control_valid = false;
}

static bool tx_scheduler_has_queued(void)
{
    taskENTER_CRITICAL(&s_gov_mux);
    bool queued = lora_tx_scheduler_queued(&s_tx_scheduler) != 0;
    taskEXIT_CRITICAL(&s_gov_mux);
    return queued;
}

static bool build_tx_fragment(lora_tx_handle_t handle, uint8_t idx,
                              lora_frame_t *frame, uint8_t *out_total)
{
    const lora_tx_packet_t *packet =
        lora_tx_scheduler_packet(&s_tx_scheduler, handle);
    if (!packet || !frame || !out_total ||
        handle >= LORA_TX_PACKET_POOL_SIZE ||
        !s_tx_context[handle].valid) {
        return false;
    }
    uint8_t total =
        (uint8_t)((packet->len + TRUNK_CHUNK_TX - 1) / TRUNK_CHUNK_TX);
    if (idx >= total) {
        return false;
    }
    uint16_t off = (uint16_t)idx * TRUNK_CHUNK_TX;
    uint16_t remaining = packet->len - off;
    uint16_t chunk =
        remaining < TRUNK_CHUNK_TX ? remaining : TRUNK_CHUNK_TX;
    const tx_trunk_context_t *context = &s_tx_context[handle];
    lora_trunk_frame_t trunk = {
        .version = LORA_TRUNK_V3_VERSION,
        .kind = LORA_TRUNK_KIND_DATA,
        .flags = context->ack_requested
                     ? LORA_TRUNK_V3_FLAG_ACK_REQUESTED
                     : LORA_TRUNK_V3_FLAG_BROADCAST,
        .capabilities = LORA_TRUNK_V3_CAP_PROTOCOL,
        .fragment_index = idx,
        .fragment_total = total,
        .payload = packet->data + off,
        .payload_len = chunk,
    };
    memcpy(trunk.source, s_node_id, sizeof(trunk.source));
    memcpy(trunk.destination, context->destination,
           sizeof(trunk.destination));
    memcpy(trunk.transfer_id, context->transfer_id,
           sizeof(trunk.transfer_id));
    size_t encoded_len = 0;
    if (!lora_trunk_v3_encode(
            &trunk, frame->data, sizeof(frame->data), &encoded_len)) {
        return false;
    }
    frame->len = (uint16_t)encoded_len;
    frame->want_ack = context->ack_requested;
    s_expected_control_valid = frame->want_ack;
    if (s_expected_control_valid) {
        s_expected_control_data = trunk;
    }
    *out_total = total;
    return true;
}

/* Packet controls bypass the data queue. Cumulative bitmaps for the same
 * transfer coalesce, and terminal COMPLETE/ABORT controls replace a pending
 * bitmap so the bounded outbox cannot fill with per-fragment acknowledgements. */
#define ACK_OUTBOX 6
typedef struct {
    uint8_t version;
    uint8_t dst[LORA_TRUNK_V3_NODE_ID_LEN];
    uint8_t transfer_id[LORA_TRUNK_V3_TRANSFER_ID_LEN];
    lora_trunk_kind_t kind;
    uint8_t value;
    uint8_t total;
} ack_slot_t;
static ack_slot_t s_ack_outbox[ACK_OUTBOX];
static int s_ack_head, s_ack_count;

static unsigned control_rank(lora_trunk_kind_t kind)
{
    switch (kind) {
    case LORA_TRUNK_KIND_COMPLETE:
        return 3;
    case LORA_TRUNK_KIND_ABORT:
        return 2;
    case LORA_TRUNK_KIND_BITMAP_ACK:
        return 1;
    default:
        return 0;
    }
}

static void queue_control_fields(
    uint8_t version,
    const uint8_t dst[LORA_TRUNK_V3_NODE_ID_LEN],
    const uint8_t transfer_id[LORA_TRUNK_V3_TRANSFER_ID_LEN],
    uint8_t total, lora_trunk_kind_t kind, uint8_t value)
{
    if (!dst || !transfer_id) {
        return;
    }
    if (version == LORA_TRUNK_V3_VERSION) {
        for (int offset = 0; offset < s_ack_count; ++offset) {
            ack_slot_t *queued =
                &s_ack_outbox[(s_ack_head + offset) % ACK_OUTBOX];
            if (queued->version != version || queued->total != total ||
                memcmp(queued->dst, dst, sizeof(queued->dst)) != 0 ||
                memcmp(queued->transfer_id, transfer_id,
                       sizeof(queued->transfer_id)) != 0) {
                continue;
            }
            if (kind == LORA_TRUNK_KIND_BITMAP_ACK &&
                queued->kind == LORA_TRUNK_KIND_BITMAP_ACK) {
                queued->value |= value;
            } else if (control_rank(kind) >
                       control_rank(queued->kind)) {
                queued->kind = kind;
                queued->value = value;
            }
            return;
        }
    }
    if (s_ack_count >= ACK_OUTBOX) {
        ESP_LOGW(TAG, "control outbox full");
        return;
    }
    ack_slot_t *a = &s_ack_outbox[(s_ack_head + s_ack_count) % ACK_OUTBOX];
    memset(a, 0, sizeof(*a));
    a->version = version;
    memcpy(a->dst, dst, sizeof(a->dst));
    memcpy(a->transfer_id, transfer_id, sizeof(a->transfer_id));
    a->kind = kind;
    a->value = value;
    a->total = total;
    s_ack_count++;
}

static void queue_ack(const lora_trunk_frame_t *data)
{
    if (!data) {
        return;
    }
    if (data->version == LORA_TRUNK_V2_VERSION) {
        queue_control_fields(
            data->version, data->source, data->transfer_id,
            data->fragment_total, LORA_TRUNK_KIND_BITMAP_ACK,
            data->fragment_index);
    }
}

static void queue_v3_control(
    const lora_trunk_frame_t *data, lora_trunk_kind_t kind,
    uint8_t value)
{
    if (!data || data->version != LORA_TRUNK_V3_VERSION) {
        return;
    }
    queue_control_fields(
        data->version, data->source, data->transfer_id,
        data->fragment_total, kind, value);
}

static bool transmit_ack_now(void)
{
    if (s_ack_count == 0) {
        return false;
    }
    ack_slot_t *a = &s_ack_outbox[s_ack_head];
    uint8_t f[LORA_TRUNK_V3_HEADER_LEN] = {0};
    size_t frame_len = 0;
    if (a->version == LORA_TRUNK_V2_VERSION) {
        f[0] = LORA_TRUNK_MAGIC0;
        f[1] = LORA_TRUNK_MAGIC1;
        f[2] = LORA_TRUNK_V2_VERSION;
        f[3] = 0x01;
        memcpy(f + 4, s_node_id, 4);
        memcpy(f + 8, a->dst, 4);
        f[12] = a->transfer_id[10];
        f[13] = a->transfer_id[11];
        f[14] = a->value;
        f[15] = a->total;
        frame_len = LORA_TRUNK_V2_HEADER_LEN;
    } else {
        lora_trunk_frame_t control = {
            .version = LORA_TRUNK_V3_VERSION,
            .kind = a->kind,
            .capabilities = LORA_TRUNK_V3_CAP_PROTOCOL,
            .fragment_index = a->value,
            .fragment_total = a->total,
        };
        memcpy(control.source, s_node_id, sizeof(control.source));
        memcpy(control.destination, a->dst, sizeof(control.destination));
        memcpy(control.transfer_id, a->transfer_id,
               sizeof(control.transfer_id));
        if (!lora_trunk_v3_encode(
                &control, f, sizeof(f), &frame_len)) {
            s_ack_head = (s_ack_head + 1) % ACK_OUTBOX;
            s_ack_count--;
            return false;
        }
    }
    s_ack_head = (s_ack_head + 1) % ACK_OUTBOX;
    s_ack_count--;
    if (sx1262_transmit(f, frame_len) == ESP_OK) {
        diag_inc(&s_diag.tx_attempts);
        diag_inc(&s_diag.ack_tx);
        if (a->version == LORA_TRUNK_V3_VERSION) {
            if (a->kind == LORA_TRUNK_KIND_BITMAP_ACK) {
                diag_inc(&s_diag.bitmap_acks);
            } else if (a->kind == LORA_TRUNK_KIND_COMPLETE) {
                diag_inc(&s_diag.complete_acks);
            } else if (a->kind == LORA_TRUNK_KIND_ABORT) {
                diag_inc(&s_diag.transfer_aborts_tx);
            }
        }
        ESP_LOGI(TAG, "v%u control TX kind=%u value=0x%02x",
                 a->version, a->kind, a->value);
        return true;
    }
    recover_radio("ACK transmit command");
    return false;
}

static void learn_authenticated_neighbor(
    const lora_trunk_frame_t *frame, const uint8_t *packet_data,
    uint16_t packet_len, uint64_t now_ms)
{
    if (frame->version != LORA_TRUNK_V3_VERSION) {
        return;
    }
    bitchat_packet_t packet;
    if (!bitchat_packet_decode(packet_data, packet_len, &packet)) {
        return;
    }
    uint8_t signing_key[LORA_TRUNK_SIGNING_KEY_LEN];
    if (memcmp(packet.sender_id, frame->source,
               LORA_TRUNK_V3_NODE_ID_LEN) == 0 &&
        noise_verify_announce_identity(&packet, signing_key)) {
        uint32_t neighbor_count = 0;
        taskENTER_CRITICAL(&s_gov_mux);
        lora_trunk_neighbor_result_t result =
            lora_trunk_neighbor_learn_authenticated(
                &s_neighbors, frame->source, packet.sender_id, signing_key,
                frame->capabilities, now_ms);
        if (result == LORA_TRUNK_NEIGHBOR_COLLISION) {
            s_diag.neighbor_collisions++;
        }
        s_diag.neighbor_count =
            (uint32_t)lora_trunk_neighbor_count(&s_neighbors);
        neighbor_count = s_diag.neighbor_count;
        taskEXIT_CRITICAL(&s_gov_mux);
        ESP_LOGI(TAG, "authenticated neighbor result=%u count=%lu",
                 result, (unsigned long)neighbor_count);
    }
    bitchat_packet_free(&packet);
}

static bool same_transfer(
    uint8_t version, const uint8_t *source, const uint8_t *transfer_id,
    const lora_trunk_frame_t *frame)
{
    return version == frame->version &&
           memcmp(source, frame->source, LORA_TRUNK_V3_NODE_ID_LEN) == 0 &&
           memcmp(transfer_id, frame->transfer_id,
                  LORA_TRUNK_V3_TRANSFER_ID_LEN) == 0;
}

static completed_slot_t *completed_transfer(
    const lora_trunk_frame_t *frame, uint64_t now_ms)
{
    for (size_t i = 0; i < COMPLETED_SLOTS; ++i) {
        completed_slot_t *completed = &s_completed_slots[i];
        if (completed->in_use && now_ms >= completed->expires_ms) {
            completed->in_use = false;
        }
        if (completed->in_use &&
            same_transfer(
                completed->version, completed->src,
                completed->transfer_id, frame)) {
            return completed;
        }
    }
    return NULL;
}

static void remember_completed_transfer(
    const lora_trunk_frame_t *frame, bool addressed,
    uint64_t expires_ms)
{
    completed_slot_t *slot = NULL;
    for (size_t i = 0; i < COMPLETED_SLOTS; ++i) {
        completed_slot_t *candidate = &s_completed_slots[i];
        if (!candidate->in_use) {
            slot = candidate;
            break;
        }
        if (!slot || candidate->expires_ms < slot->expires_ms) {
            slot = candidate;
        }
    }
    memset(slot, 0, sizeof(*slot));
    slot->in_use = true;
    slot->addressed = addressed;
    slot->version = frame->version;
    memcpy(slot->src, frame->source, sizeof(slot->src));
    memcpy(slot->transfer_id, frame->transfer_id,
           sizeof(slot->transfer_id));
    slot->total = frame->fragment_total;
    slot->expires_ms = expires_ms;
}

static void abort_rx_slot(rx_slot_t *slot, uint8_t reason)
{
    if (!slot || !slot->in_use) {
        return;
    }
    if (slot->addressed &&
        slot->version == LORA_TRUNK_V3_VERSION) {
        queue_control_fields(
            slot->version, slot->src, slot->transfer_id, slot->total,
            LORA_TRUNK_KIND_ABORT, reason);
    }
    memset(slot, 0, sizeof(*slot));
}

static void expire_reassembly(uint64_t now_ms)
{
    for (size_t i = 0; i < RX_SLOTS; ++i) {
        rx_slot_t *slot = &s_rx_slots[i];
        if (slot->in_use &&
            (now_ms >= slot->progress_deadline_ms ||
             now_ms >= slot->absolute_deadline_ms)) {
            abort_rx_slot(slot, LORA_TRUNK_ABORT_RETRY_EXHAUSTED);
            diag_inc(&s_diag.reassembly_expiry);
        }
    }
}

static void reassemble_data(
    const lora_trunk_frame_t *frame, bool addressed_to_us,
    int16_t rssi, int8_t snr)
{
    if (!frame || frame->payload_len == 0 ||
        frame->payload_len > TRUNK_CHUNK_RX_MAX ||
        frame->fragment_total > TRUNK_MAX_FRAGS) {
        return;
    }
    if (frame->version == LORA_TRUNK_V3_VERSION &&
        frame->fragment_index + 1u < frame->fragment_total &&
        frame->payload_len != TRUNK_CHUNK_TX) {
        queue_v3_control(
            frame, LORA_TRUNK_KIND_ABORT,
            LORA_TRUNK_ABORT_INVALID_LENGTH);
        diag_inc(&s_diag.invalid_reassemblies);
        return;
    }

    uint64_t now = esp_timer_get_time() / 1000ULL;
    lora_reliability_timing_t timing;
    if (!trunk_reliability_timing(frame->fragment_total, &timing)) {
        return;
    }
    expire_reassembly(now);

    completed_slot_t *completed = completed_transfer(frame, now);
    if (completed) {
        if (completed->total != frame->fragment_total) {
            if (addressed_to_us &&
                frame->version == LORA_TRUNK_V3_VERSION) {
                queue_v3_control(
                    frame, LORA_TRUNK_KIND_ABORT,
                    LORA_TRUNK_ABORT_INVALID_LENGTH);
            }
            diag_inc(&s_diag.invalid_reassemblies);
            return;
        }
        diag_inc(&s_diag.duplicate_transfers);
        if (completed->addressed && addressed_to_us &&
            frame->version == LORA_TRUNK_V3_VERSION) {
            queue_v3_control(
                frame, LORA_TRUNK_KIND_COMPLETE,
                lora_fragment_mask(frame->fragment_total));
        } else if (
            frame->version == LORA_TRUNK_V2_VERSION &&
            (frame->flags & LORA_TRUNK_V3_FLAG_ACK_REQUESTED) != 0) {
            queue_ack(frame);
        }
        return;
    }

    rx_slot_t *slot = NULL;
    rx_slot_t *free_slot = NULL;
    uint8_t slots_in_use = 0;
    for (size_t i = 0; i < RX_SLOTS; ++i) {
        rx_slot_t *candidate = &s_rx_slots[i];
        if (candidate->in_use) {
            slots_in_use++;
            if (same_transfer(
                    candidate->version, candidate->src,
                    candidate->transfer_id, frame)) {
                slot = candidate;
            }
        } else if (!free_slot) {
            free_slot = candidate;
        }
    }
    if (!slot) {
        if (!free_slot ||
            !lora_reassembly_admit(
                addressed_to_us, slots_in_use, RX_SLOTS)) {
            if (addressed_to_us &&
                frame->version == LORA_TRUNK_V3_VERSION) {
                queue_v3_control(
                    frame, LORA_TRUNK_KIND_ABORT,
                    LORA_TRUNK_ABORT_RESOURCE_PRESSURE);
            }
            diag_inc(&s_diag.resource_aborts);
            return;
        }
        slot = free_slot;
        memset(slot, 0, sizeof(*slot));
        slot->in_use = true;
        slot->addressed = addressed_to_us;
        slot->version = frame->version;
        memcpy(slot->src, frame->source, sizeof(slot->src));
        memcpy(slot->transfer_id, frame->transfer_id,
               sizeof(slot->transfer_id));
        slot->capabilities = frame->capabilities;
        slot->total = frame->fragment_total;
        slot->started_ms = now;
        slot->progress_deadline_ms =
            now + timing.progress_timeout_ms;
        slot->absolute_deadline_ms =
            now + timing.absolute_timeout_ms;
    }
    if (slot->total != frame->fragment_total ||
        slot->capabilities != frame->capabilities ||
        slot->addressed != addressed_to_us) {
        abort_rx_slot(slot, LORA_TRUNK_ABORT_INVALID_LENGTH);
        diag_inc(&s_diag.invalid_reassemblies);
        return;
    }

    uint8_t bit = (uint8_t)(1u << frame->fragment_index);
    if ((slot->have_mask & bit) != 0) {
        diag_inc(&s_diag.duplicate_fragments);
        if (slot->part_len[frame->fragment_index] != frame->payload_len ||
            memcmp(slot->part[frame->fragment_index], frame->payload,
                   frame->payload_len) != 0) {
            abort_rx_slot(slot, LORA_TRUNK_ABORT_INVALID_LENGTH);
            diag_inc(&s_diag.invalid_reassemblies);
            return;
        }
    } else {
        slot->part_len[frame->fragment_index] = frame->payload_len;
        memcpy(slot->part[frame->fragment_index], frame->payload,
               frame->payload_len);
        slot->have_mask |= bit;
        uint64_t refreshed = now + timing.progress_timeout_ms;
        slot->progress_deadline_ms =
            refreshed < slot->absolute_deadline_ms
                ? refreshed
                : slot->absolute_deadline_ms;
    }

    uint8_t wanted = lora_fragment_mask(frame->fragment_total);
    if ((slot->have_mask & wanted) != wanted) {
        if (addressed_to_us &&
            frame->version == LORA_TRUNK_V3_VERSION) {
            queue_v3_control(
                frame, LORA_TRUNK_KIND_BITMAP_ACK, slot->have_mask);
        } else if (
            frame->version == LORA_TRUNK_V2_VERSION &&
            (frame->flags & LORA_TRUNK_V3_FLAG_ACK_REQUESTED) != 0) {
            queue_ack(frame);
        }
        return;
    }

    static uint8_t packet[BITCHAT_BLE_MAX_PACKET_SIZE];
    uint16_t packet_len = 0;
    for (uint8_t index = 0; index < frame->fragment_total; ++index) {
        if (packet_len + slot->part_len[index] > sizeof(packet)) {
            abort_rx_slot(slot, LORA_TRUNK_ABORT_INVALID_LENGTH);
            diag_inc(&s_diag.invalid_reassemblies);
            return;
        }
        memcpy(packet + packet_len, slot->part[index],
               slot->part_len[index]);
        packet_len += slot->part_len[index];
    }
    if (!lora_bitchat_packet_length_valid(
            packet, packet_len, sizeof(packet))) {
        abort_rx_slot(slot, LORA_TRUNK_ABORT_INVALID_LENGTH);
        diag_inc(&s_diag.invalid_reassemblies);
        return;
    }

    remember_completed_transfer(
        frame, addressed_to_us,
        now + timing.completed_retention_ms);
    memset(slot, 0, sizeof(*slot));
    if (addressed_to_us &&
        frame->version == LORA_TRUNK_V3_VERSION) {
        queue_v3_control(
            frame, LORA_TRUNK_KIND_COMPLETE, wanted);
    } else if (
        frame->version == LORA_TRUNK_V2_VERSION &&
        (frame->flags & LORA_TRUNK_V3_FLAG_ACK_REQUESTED) != 0) {
        queue_ack(frame);
    }

    learn_authenticated_neighbor(frame, packet, packet_len, now);
    diag_inc(&s_diag.completed_packets);
    ESP_LOGI(TAG, "trunk v%u RX packet len=%u rssi=%d snr=%d frags=%u",
             frame->version, packet_len, rssi, snr,
             frame->fragment_total);
    bitle_mesh_inbound(BITLE_LORA_LINK_HANDLE, packet, packet_len);
}

static void rx_frame(const uint8_t *f, uint16_t len, int16_t rssi, int8_t snr)
{
    lora_trunk_frame_t frame;
    lora_trunk_parse_result_t parsed = lora_trunk_parse(f, len, &frame);
    if (parsed != LORA_TRUNK_PARSE_OK) {
        if (parsed == LORA_TRUNK_PARSE_MALFORMED) {
            diag_inc(&s_diag.malformed_frames);
        } else if (parsed == LORA_TRUNK_PARSE_UNSUPPORTED_VERSION) {
            diag_inc(&s_diag.unsupported_versions);
        }
        return;
    }
    size_t source_len =
        frame.version == LORA_TRUNK_V2_VERSION ? 4 : sizeof(s_node_id);
    if (memcmp(frame.source, s_node_id, source_len) == 0) {
        return;
    }

    diag_inc(&s_diag.raw_rx_frames);
    ESP_LOGI(TAG, "trunk v%u raw RX len=%u rssi=%d snr=%d kind=%u",
             frame.version, len, rssi, snr, frame.kind);

    if (frame.kind != LORA_TRUNK_KIND_DATA) {
        /* Shared-channel controls for other senders are normal. A control
         * addressed to us must match the selected peer and the complete
         * transfer tuple before it can mutate selective-repeat state. */
        if (frame.version == LORA_TRUNK_V3_VERSION &&
            memcmp(frame.destination, s_node_id, sizeof(s_node_id)) == 0) {
            if (s_expected_control_valid &&
                lora_trunk_v3_control_matches(
                    &s_expected_control_data, &frame)) {
                bool accepted = false;
                if (frame.kind == LORA_TRUNK_KIND_BITMAP_ACK) {
                    accepted = lora_selective_tx_apply_bitmap(
                        &s_selective_tx, frame.fragment_index);
                } else if (frame.kind == LORA_TRUNK_KIND_COMPLETE) {
                    accepted = lora_selective_tx_apply_complete(
                        &s_selective_tx, frame.fragment_index);
                } else if (frame.kind == LORA_TRUNK_KIND_ABORT) {
                    lora_selective_tx_apply_abort(
                        &s_selective_tx, frame.fragment_index);
                    diag_inc(&s_diag.transfer_aborts_rx);
                    accepted = true;
                }
                if (accepted) {
                    s_feedback_seen = true;
                    diag_inc(&s_diag.ack_rx);
                    ESP_LOGI(TAG,
                             "v3 control RX kind=%u value=0x%02x",
                             frame.kind, frame.fragment_index);
                }
            } else {
                diag_inc(&s_diag.rejected_acks);
            }
        }
        return;
    }

    bool broadcast =
        frame.version == LORA_TRUNK_V3_VERSION
            ? (frame.flags & LORA_TRUNK_V3_FLAG_BROADCAST) != 0
            : memcmp(frame.destination,
                     (uint8_t[LORA_TRUNK_V3_NODE_ID_LEN]){0},
                     4) == 0;
    size_t destination_len =
        frame.version == LORA_TRUNK_V2_VERSION ? 4 : sizeof(s_node_id);
    bool addressed_to_us =
        !broadcast &&
        memcmp(frame.destination, s_node_id, destination_len) == 0;
    if (!broadcast && !addressed_to_us) {
        return;
    }

    reassemble_data(&frame, addressed_to_us, rssi, snr);
}

/* Neighbor discovery: our signed announce over the trunk, so two nodes
 * with no phone in sight still find and verify each other. */
#define BEACON_FIRST_MS    5000ULL
#define BEACON_INTERVAL_MS 60000ULL
#define BEACON_START_JITTER_MS 10000U
#define BEACON_INTERVAL_JITTER_MS 30000U

static void drop_tx_packet(lora_tx_handle_t *handle, bool *have_pending)
{
    tx_scheduler_release(*handle);
    *handle = LORA_TX_HANDLE_INVALID;
    *have_pending = false;
}

static void queue_sender_abort(uint8_t reason)
{
    if (!s_expected_control_valid) {
        return;
    }
    queue_control_fields(
        LORA_TRUNK_V3_VERSION,
        s_expected_control_data.destination,
        s_expected_control_data.transfer_id,
        s_expected_control_data.fragment_total,
        LORA_TRUNK_KIND_ABORT, reason);
}

static void abort_tx_packet(
    lora_tx_handle_t *handle, bool *have_pending, uint8_t reason)
{
    queue_sender_abort(reason);
    drop_tx_packet(handle, have_pending);
}

/* Broadcasts retain one-pass fragment sequencing. Addressed transfers select
 * fragments through the portable cumulative-bitmap state machine. */
static bool advance_tx_packet(lora_tx_handle_t *handle, uint8_t *fragment_idx,
                              uint8_t fragment_total, lora_frame_t *frame)
{
    (*fragment_idx)++;
    if (*fragment_idx >= fragment_total) {
        tx_scheduler_release(*handle);
        *handle = LORA_TX_HANDLE_INVALID;
        return false;
    }
    uint8_t checked_total = 0;
    if (!build_tx_fragment(*handle, *fragment_idx, frame, &checked_total) ||
        checked_total != fragment_total) {
        tx_scheduler_release(*handle);
        *handle = LORA_TX_HANDLE_INVALID;
        return false;
    }
    return true;
}

static bool prepare_selective_fragment(
    lora_tx_handle_t handle, lora_frame_t *frame,
    uint8_t expected_total, uint8_t *out_index)
{
    int next = lora_selective_tx_next_fragment(&s_selective_tx);
    if (next < 0) {
        return false;
    }
    uint8_t checked_total = 0;
    if (!build_tx_fragment(
            handle, (uint8_t)next, frame, &checked_total) ||
        checked_total != expected_total) {
        return false;
    }
    *out_index = (uint8_t)next;
    return true;
}

static void lora_task(void *arg)
{
    (void)arg;
    lora_frame_t pending;
    lora_tx_handle_t packet_handle = LORA_TX_HANDLE_INVALID;
    uint8_t fragment_idx = 0;
    uint8_t fragment_total = 0;
    bool have_pending = false;
    int cad_tries = 0;
    bool awaiting_tx_done = false;
    bool tx_is_ack = false;
    bool awaiting_cad = false;
    bool awaiting_ack = false;
    unsigned ack_burst = 0;
    uint64_t tx_watchdog_deadline = 0;
    uint64_t ack_deadline = 0;
    uint64_t transfer_deadline = 0;
    lora_reliability_timing_t transfer_timing = {0};
    uint64_t next_beacon_ms =
        BEACON_FIRST_MS + (esp_random() % BEACON_START_JITTER_MS);
    uint64_t next_diag_ms = 60000ULL;
#if CONFIG_BITLE_LORA_DIAGNOSTIC_SMOKE
    static const uint16_t smoke_lengths[] = {100, 180, 300, 420, 520};
    size_t smoke_index = 0;
    uint64_t next_smoke_ms = 12000ULL;
#endif
#if CONFIG_BITLE_LORA_DIAGNOSTIC_SUPPRESS_TX_DONE_ONCE
    bool suppressed_tx_done = false;
#endif

    while (true) {
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(50));

        uint64_t now = esp_timer_get_time() / 1000ULL;
        expire_reassembly(now);
        if (now >= next_beacon_ms) {
            next_beacon_ms =
                now + BEACON_INTERVAL_MS -
                (BEACON_INTERVAL_JITTER_MS / 2U) +
                (esp_random() % BEACON_INTERVAL_JITTER_MS);
            if (noise_announce_link(BITLE_LORA_LINK_HANDLE)) {
                ESP_LOGI(TAG, "trunk beacon sent");
            }
        }

#if CONFIG_BITLE_LORA_DIAGNOSTIC_SMOKE
        if (smoke_index < sizeof(smoke_lengths) / sizeof(smoke_lengths[0]) &&
            now >= next_smoke_ms) {
            static uint8_t probe[BITCHAT_BLE_MAX_PACKET_SIZE];
            uint16_t probe_len = smoke_lengths[smoke_index];
            uint8_t recipient[LORA_TRUNK_V3_NODE_ID_LEN] = {0};
            bool addressed = false;
            taskENTER_CRITICAL(&s_gov_mux);
            const lora_trunk_neighbor_t *freshest = NULL;
            for (size_t i = 0; i < LORA_TRUNK_NEIGHBOR_CAPACITY; ++i) {
                const lora_trunk_neighbor_t *entry =
                    &s_neighbors.entries[i];
                if (entry->in_use && !entry->quarantined &&
                    now >= entry->last_seen_ms &&
                    now - entry->last_seen_ms <= 180000ULL &&
                    (!freshest ||
                     entry->last_seen_ms > freshest->last_seen_ms)) {
                    freshest = entry;
                }
            }
            if (freshest) {
                memcpy(recipient, freshest->reachable_peer,
                       sizeof(recipient));
                addressed = true;
            }
            taskEXIT_CRITICAL(&s_gov_mux);
            if (!addressed) {
                ESP_LOGI(TAG,
                         "diagnostic smoke waiting for authenticated neighbor");
                next_smoke_ms = now + 3000ULL;
            } else {
                memset(probe, 0xA5, probe_len);
                probe[0] = 1;
                probe[1] = BITCHAT_MSG_MESSAGE;
                probe[2] = 0;
                probe[11] = 0x01;
                const uint16_t packet_header_len = 30;
                uint16_t payload_len = probe_len - packet_header_len;
                probe[12] = payload_len >> 8;
                probe[13] = payload_len & 0xFF;
                memcpy(probe + PKT_SENDER_OFF,
                       noise_get_local_peer_id(), 8);
                memcpy(probe + 22, recipient, sizeof(recipient));
                bitle_link_send_result_t result =
                    lora_link_send(
                        BITLE_LORA_LINK_HANDLE, probe, probe_len);
                if (result == BITLE_LINK_SEND_ACCEPTED) {
                    ESP_LOGI(
                        TAG,
                        "diagnostic smoke enqueue len=%u expected_frags=%u "
                        "addressed=1",
                        probe_len,
                        (probe_len + TRUNK_CHUNK_TX - 1) /
                            TRUNK_CHUNK_TX);
                    smoke_index++;
                } else {
                    ESP_LOGW(
                        TAG,
                        "diagnostic smoke deferred len=%u result=%u",
                        probe_len, result);
                }
                next_smoke_ms = now + 3000ULL;
            }
        }
#endif

        if (now >= next_diag_ms) {
            bitle_lora_diag_t diag;
            bitle_lora_get_diag(&diag);
            ESP_LOGI(TAG,
                     "diag raw_rx=%lu crc=%lu tx=%lu tmo=%lu ack_rx=%lu ack_tx=%lu "
                     "ack_miss=%lu retry=%lu exhausted=%lu q_full=%lu q=%lu/%lu "
                     "rx_expire=%lu complete=%lu cfg_reject=%lu radio_err=%lu "
                     "busy_tmo=%lu recover=%lu/%lu tx_watchdog=%lu "
                     "admit=%lu/%lu/%lu/%lu defer=%lu/%lu/%lu/%lu "
                     "policy=%lu release=%lu cancel=%lu malformed=%lu "
                     "unsupported=%lu ack_reject=%lu neighbors=%lu collision=%lu "
                     "bitmap=%lu final=%lu dup=%lu/%lu abort=%lu/%lu "
                     "invalid=%lu resource=%lu",
                     (unsigned long)diag.raw_rx_frames,
                     (unsigned long)diag.crc_errors,
                     (unsigned long)diag.tx_attempts,
                     (unsigned long)diag.tx_timeouts,
                     (unsigned long)diag.ack_rx,
                     (unsigned long)diag.ack_tx,
                     (unsigned long)diag.ack_misses,
                     (unsigned long)diag.retries,
                     (unsigned long)diag.retry_exhaustion,
                     (unsigned long)diag.queue_full,
                     (unsigned long)diag.queue_depth,
                     (unsigned long)diag.queue_high_water,
                     (unsigned long)diag.reassembly_expiry,
                     (unsigned long)diag.completed_packets,
                     (unsigned long)diag.config_rejections,
                     (unsigned long)diag.radio_command_errors,
                     (unsigned long)diag.radio_busy_timeouts,
                     (unsigned long)diag.radio_recoveries,
                     (unsigned long)diag.radio_recovery_failures,
                     (unsigned long)diag.tx_watchdog_recoveries,
                     (unsigned long)diag.packet_accepted[LORA_TX_PRIORITY_CONTROL],
                     (unsigned long)diag.packet_accepted[LORA_TX_PRIORITY_USER],
                     (unsigned long)diag.packet_accepted[LORA_TX_PRIORITY_DISCOVERY],
                     (unsigned long)diag.packet_accepted[LORA_TX_PRIORITY_BULK],
                     (unsigned long)diag.packet_deferred[LORA_TX_PRIORITY_CONTROL],
                     (unsigned long)diag.packet_deferred[LORA_TX_PRIORITY_USER],
                     (unsigned long)diag.packet_deferred[LORA_TX_PRIORITY_DISCOVERY],
                     (unsigned long)diag.packet_deferred[LORA_TX_PRIORITY_BULK],
                     (unsigned long)diag.policy_drops,
                     (unsigned long)diag.packet_released,
                     (unsigned long)diag.packet_cancelled,
                     (unsigned long)diag.malformed_frames,
                     (unsigned long)diag.unsupported_versions,
                     (unsigned long)diag.rejected_acks,
                     (unsigned long)diag.neighbor_count,
                     (unsigned long)diag.neighbor_collisions,
                     (unsigned long)diag.bitmap_acks,
                     (unsigned long)diag.complete_acks,
                     (unsigned long)diag.duplicate_fragments,
                     (unsigned long)diag.duplicate_transfers,
                     (unsigned long)diag.transfer_aborts_tx,
                     (unsigned long)diag.transfer_aborts_rx,
                     (unsigned long)diag.invalid_reassemblies,
                     (unsigned long)diag.resource_aborts);
            next_diag_ms = now + 60000ULL;
        }

        sx1262_event_t evt;
        while ((evt = sx1262_poll_event()) != SX1262_EVT_NONE) {
            switch (evt) {
            case SX1262_EVT_RX_DONE: {
                static uint8_t buf[SX1262_MAX_PAYLOAD];
                int16_t rssi = 0;
                int8_t snr = 0;
                uint16_t n = sx1262_read_packet(buf, sizeof(buf), &rssi, &snr);
                if (n) {
                    rx_frame(buf, n, rssi, snr);
                }
                break;
            }
            case SX1262_EVT_TX_DONE:
#if CONFIG_BITLE_LORA_DIAGNOSTIC_SUPPRESS_TX_DONE_ONCE
                if (!suppressed_tx_done) {
                    suppressed_tx_done = true;
                    ESP_LOGW(TAG, "diagnostic: suppressed one TX_DONE event");
                    break;
                }
#endif
                awaiting_tx_done = false;
                tx_watchdog_deadline = 0;
                if (!resume_rx_or_recover("TX_DONE resume RX")) {
                    tx_is_ack = false;
                    if (have_pending) {
                        abort_tx_packet(
                            &packet_handle, &have_pending,
                            LORA_TRUNK_ABORT_RADIO_RESET);
                    }
                    break;
                }
                if (tx_is_ack) {
                    /* A local control delayed packet feedback processing. */
                    tx_is_ack = false;
                    if (awaiting_ack) {
                        ack_deadline +=
                            trunk_airtime_ms(LORA_TRUNK_V3_HEADER_LEN) + 300;
                    }
                } else if (have_pending && pending.want_ack) {
                    if (prepare_selective_fragment(
                            packet_handle, &pending, fragment_total,
                            &fragment_idx)) {
                        cad_tries = 0;
                    } else {
                        awaiting_ack = true;
                        ack_deadline =
                            esp_timer_get_time() / 1000ULL +
                            transfer_timing.feedback_wait_ms;
                    }
                } else {
                    have_pending = advance_tx_packet(
                        &packet_handle, &fragment_idx, fragment_total,
                        &pending);
                    cad_tries = 0;
                }
                break;
            case SX1262_EVT_CAD_CLEAR:
                awaiting_cad = false;
                if (s_ack_count > 0 &&
                    (!(have_pending || tx_scheduler_has_queued()) ||
                     ack_burst < ACK_BURST_MAX)) {
                    /* ACKs preempt boundedly; after four, queued packet
                     * traffic gets one transmission opportunity. */
                    if (transmit_ack_now()) {
                        ack_burst++;
                        awaiting_tx_done = true;
                        tx_is_ack = true;
                        tx_watchdog_deadline =
                            esp_timer_get_time() / 1000ULL +
                            sx1262_tx_watchdog_ms(
                                LORA_TRUNK_V3_HEADER_LEN);
                    }
                } else if (have_pending) {
                    if (sx1262_transmit(pending.data, pending.len) == ESP_OK) {
                        diag_inc(&s_diag.tx_attempts);
                        if (pending.want_ack &&
                            s_selective_tx.round_index > 0) {
                            diag_inc(&s_diag.retries);
                        }
                        if (pending.want_ack &&
                            !lora_selective_tx_note_sent(
                                &s_selective_tx, fragment_idx)) {
                            abort_tx_packet(
                                &packet_handle, &have_pending,
                                LORA_TRUNK_ABORT_INVALID_LENGTH);
                            resume_rx_or_recover(
                                "selective state resume RX");
                            break;
                        }
                        awaiting_tx_done = true;
                        tx_is_ack = false;
                        tx_watchdog_deadline =
                            esp_timer_get_time() / 1000ULL +
                            sx1262_tx_watchdog_ms(pending.len);
                        ack_burst = 0;
                    } else {
                        abort_tx_packet(
                            &packet_handle, &have_pending,
                            LORA_TRUNK_ABORT_RADIO_RESET);
                        recover_radio("data transmit command");
                    }
                }
                break;
            case SX1262_EVT_CAD_BUSY:
                awaiting_cad = false;
                if (have_pending &&
                    (pending.want_ack || ++cad_tries <= CAD_RETRIES)) {
                    /* An addressed transfer owns a bounded absolute deadline;
                     * temporary channel occupancy must not discard it after a
                     * small fixed number of CAD results. Return to RX during
                     * backoff so packet feedback remains observable, then
                     * retry until COMPLETE, ABORT, or the transfer deadline. */
                    if (!resume_rx_or_recover(
                            "CAD busy backoff resume RX")) {
                        abort_tx_packet(
                            &packet_handle, &have_pending,
                            LORA_TRUNK_ABORT_RADIO_RESET);
                        break;
                    }
                    vTaskDelay(pdMS_TO_TICKS(CAD_BACKOFF_MIN +
                                             (esp_random() % CAD_BACKOFF_SPAN)));
                    if (sx1262_start_cad() == ESP_OK) {
                        awaiting_cad = true;
                    } else {
                        abort_tx_packet(
                            &packet_handle, &have_pending,
                            LORA_TRUNK_ABORT_RADIO_RESET);
                        recover_radio("CAD retry command");
                    }
                } else {
                    /* Channel persistently busy: reject the complete packet;
                     * sending only its earlier fragments cannot complete. */
                    if (have_pending) {
                        abort_tx_packet(
                            &packet_handle, &have_pending,
                            LORA_TRUNK_ABORT_RESOURCE_PRESSURE);
                    }
                    resume_rx_or_recover("CAD busy resume RX");
                }
                break;
            case SX1262_EVT_TIMEOUT:
                {
                bool timed_out_ack = tx_is_ack;
                bool data_was_waiting = awaiting_ack;
                diag_inc(&s_diag.tx_timeouts);
                awaiting_tx_done = false;
                tx_watchdog_deadline = 0;
                tx_is_ack = false;
                awaiting_ack = false;
                if (!resume_rx_or_recover("radio TX timeout")) {
                    if (have_pending) {
                        abort_tx_packet(
                            &packet_handle, &have_pending,
                            LORA_TRUNK_ABORT_RADIO_RESET);
                    }
                } else if (timed_out_ack && data_was_waiting) {
                    awaiting_ack = true;
                    ack_deadline +=
                        transfer_timing.feedback_wait_ms;
                } else if (!timed_out_ack && have_pending &&
                           pending.want_ack) {
                    if (!prepare_selective_fragment(
                            packet_handle, &pending, fragment_total,
                            &fragment_idx)) {
                        awaiting_ack = true;
                        ack_deadline =
                            esp_timer_get_time() / 1000ULL +
                            transfer_timing.feedback_wait_ms;
                    }
                } else if (!timed_out_ack && have_pending) {
                    drop_tx_packet(&packet_handle, &have_pending);
                }
                break;
                }
            case SX1262_EVT_RX_CRC_ERROR:
                diag_inc(&s_diag.crc_errors);
                /* Logged for link-quality visibility: a frame arrived but
                 * was corrupted in flight. */
                ESP_LOGI(TAG, "trunk RX CRC error");
                break;
            case SX1262_EVT_ERROR:
                awaiting_tx_done = false;
                awaiting_cad = false;
                awaiting_ack = false;
                tx_is_ack = false;
                tx_watchdog_deadline = 0;
                if (have_pending) {
                    abort_tx_packet(
                        &packet_handle, &have_pending,
                        LORA_TRUNK_ABORT_RADIO_RESET);
                }
                recover_radio("IRQ status command");
                break;
            default:
                break;
            }
        }

        /* Acks fly the moment the radio is free — no CAD, no queueing: the
         * peer is listening right after its TX and is waiting on us. */
        bool data_waiting = have_pending || tx_scheduler_has_queued();
        if (s_ack_count > 0 && !awaiting_tx_done && !awaiting_cad &&
            (!data_waiting || ack_burst < ACK_BURST_MAX)) {
            if (transmit_ack_now()) {
                ack_burst++;
                awaiting_tx_done = true;
                tx_is_ack = true;
                tx_watchdog_deadline =
                    esp_timer_get_time() / 1000ULL +
                    sx1262_tx_watchdog_ms(LORA_TRUNK_V3_HEADER_LEN);
            }
        }

        /* Independent of DIO1 and the radio's own timeout IRQ. If TX_DONE is
         * lost, the task must not remain permanently stuck in its TX state. */
        uint64_t watchdog_now = esp_timer_get_time() / 1000ULL;
        if (awaiting_tx_done && tx_watchdog_deadline != 0 &&
            watchdog_now >= tx_watchdog_deadline) {
            diag_inc(&s_diag.tx_watchdog_recoveries);
            ESP_LOGW(TAG, "TX watchdog expired; resetting radio");
            awaiting_tx_done = false;
            awaiting_cad = false;
            awaiting_ack = false;
            tx_is_ack = false;
            tx_watchdog_deadline = 0;
            if (have_pending) {
                abort_tx_packet(
                    &packet_handle, &have_pending,
                    LORA_TRUNK_ABORT_RADIO_RESET);
            }
            recover_radio("software TX watchdog");
        }

        /* Packet-level selective repeat resolves cumulative feedback only
         * after sending every currently missing fragment in the round. */
        if (have_pending && pending.want_ack &&
            (s_selective_tx.complete || s_selective_tx.aborted)) {
            if (s_selective_tx.complete) {
                ESP_LOGI(TAG, "trunk transfer COMPLETE rounds=%u",
                         s_selective_tx.round_index + 1u);
            } else {
                ESP_LOGW(TAG, "trunk transfer ABORT reason=%u",
                         s_selective_tx.abort_reason);
            }
            awaiting_ack = false;
            awaiting_cad = false;
            s_feedback_seen = false;
            drop_tx_packet(&packet_handle, &have_pending);
        } else if (awaiting_ack && have_pending) {
            uint64_t now2 = esp_timer_get_time() / 1000ULL;
            if (now2 >= ack_deadline) {
                if (!s_feedback_seen) {
                    diag_inc(&s_diag.ack_misses);
                }
                s_feedback_seen = false;
                awaiting_ack = false;
                if (lora_selective_tx_next_round(
                        &s_selective_tx,
                        LORA_SELECTIVE_REPEAT_ROUNDS) &&
                    prepare_selective_fragment(
                        packet_handle, &pending, fragment_total,
                        &fragment_idx)) {
                    cad_tries = 0;
                } else {
                    diag_inc(&s_diag.retry_exhaustion);
                    abort_tx_packet(
                        &packet_handle, &have_pending,
                        LORA_TRUNK_ABORT_RETRY_EXHAUSTED);
                }
            }
        }

        uint64_t transfer_now = esp_timer_get_time() / 1000ULL;
        if (have_pending && pending.want_ack &&
            transfer_deadline != 0 &&
            transfer_now >= transfer_deadline) {
            diag_inc(&s_diag.retry_exhaustion);
            awaiting_ack = false;
            awaiting_cad = false;
            abort_tx_packet(
                &packet_handle, &have_pending,
                LORA_TRUNK_ABORT_RETRY_EXHAUSTED);
        }

        /* Re-arm a pending data frame that was stranded idle in every wait
         * state — happens when an ack preempted its CAD result (CAD_CLEAR
         * with s_ack_count>0), or when an ack transmit returned an error.
         * Without this the frame sits forever with have_pending=true, which
         * also blocks the dequeue below and half-deadlocks outbound TX. */
        if (have_pending && !awaiting_cad && !awaiting_tx_done && !awaiting_ack) {
            if (sx1262_start_cad() == ESP_OK) {
                awaiting_cad = true;
            } else {
                abort_tx_packet(
                    &packet_handle, &have_pending,
                    LORA_TRUNK_ABORT_RADIO_RESET);
                recover_radio("pending CAD command");
            }
        }

        if (!have_pending && !awaiting_tx_done && !awaiting_cad && !awaiting_ack &&
            tx_scheduler_dequeue(&packet_handle)) {
            fragment_idx = 0;
            have_pending = build_tx_fragment(
                packet_handle, fragment_idx, &pending, &fragment_total);
            if (!have_pending) {
                drop_tx_packet(&packet_handle, &have_pending);
                continue;
            }
            if (pending.want_ack &&
                (!lora_selective_tx_init(
                     &s_selective_tx, fragment_total) ||
                 !trunk_reliability_timing(
                     fragment_total, &transfer_timing))) {
                abort_tx_packet(
                    &packet_handle, &have_pending,
                    LORA_TRUNK_ABORT_INVALID_LENGTH);
                continue;
            }
            cad_tries = 0;
            s_feedback_seen = false;
            transfer_deadline =
                pending.want_ack
                    ? esp_timer_get_time() / 1000ULL +
                          transfer_timing.absolute_timeout_ms
                    : 0;
            if (sx1262_start_cad() == ESP_OK) {
                awaiting_cad = true;
            } else {
                abort_tx_packet(
                    &packet_handle, &have_pending,
                    LORA_TRUNK_ABORT_RADIO_RESET);
                recover_radio("dequeue CAD command");
            }
        }
    }
}

bool bitle_lora_active(void)
{
    return s_active;
}

void bitle_lora_get_diag(bitle_lora_diag_t *out)
{
    if (!out) {
        return;
    }
    taskENTER_CRITICAL(&s_gov_mux);
    diag_sync_scheduler_locked();
    *out = s_diag;
    taskEXIT_CRITICAL(&s_gov_mux);
    sx1262_diag_t radio_diag;
    sx1262_get_diag(&radio_diag);
    out->radio_command_errors = radio_diag.command_errors;
    out->radio_busy_timeouts = radio_diag.busy_timeouts;
    out->radio_recoveries = radio_diag.recoveries;
    out->radio_recovery_failures = radio_diag.recovery_failures;
}

void bitle_lora_shutdown(void)
{
    s_active = false;
    bitle_link_unregister(BITLE_LORA_LINK_HANDLE);
    TaskHandle_t task = s_task;
    s_task = NULL;
    if (task) {
        vTaskDelete(task);
    }
    taskENTER_CRITICAL(&s_gov_mux);
    lora_tx_scheduler_cancel_all(&s_tx_scheduler);
    memset(s_tx_context, 0, sizeof(s_tx_context));
    diag_sync_scheduler_locked();
    taskEXIT_CRITICAL(&s_gov_mux);
    memset(s_rx_slots, 0, sizeof(s_rx_slots));
    memset(s_completed_slots, 0, sizeof(s_completed_slots));
    memset(&s_selective_tx, 0, sizeof(s_selective_tx));
    s_expected_control_valid = false;
    s_feedback_seen = false;
    s_ack_head = 0;
    s_ack_count = 0;
}

esp_err_t bitle_lora_init(void)
{
    const lora_region_profile_t *default_profile =
        lora_region_profile(LORA_DEFAULT_REGION);
    sx1262_config_t cfg = {
        .pin_sck = LORA_PIN_SCK,
        .pin_miso = LORA_PIN_MISO,
        .pin_mosi = LORA_PIN_MOSI,
        .pin_cs = LORA_PIN_CS,
        .pin_reset = LORA_PIN_RESET,
        .pin_busy = LORA_PIN_BUSY,
        .pin_dio1 = LORA_PIN_DIO1,
        .pin_rxen = LORA_PIN_RXEN,
        .freq_hz = default_profile->default_hz,
        .sf = LORA_DEFAULT_SF,
        .bw_hz = 125000,
        .cr = 5,
        .preamble_symbols = LORA_PREAMBLE_SYMBOLS,
        .tx_dbm = 22,
        .region = LORA_DEFAULT_REGION,
    };

    /* NVS overrides (namespace "lora"): u8 region, u32 freq, u8 sf,
     * u8 enabled, u8 duty_pct (1..50, default 25), and u8 ota_trunk.
     * A region/frequency mismatch is rejected as a pair. Legacy stores with
     * only a frequency infer their regional profile from that frequency. */
    uint8_t duty_pct = 25;
    nvs_handle_t nvs;
    if (nvs_open("lora", NVS_READONLY, &nvs) == ESP_OK) {
        uint8_t enabled = 1;
        nvs_get_u8(nvs, "enabled", &enabled);

        uint8_t stored_region = 0;
        uint32_t freq = 0;
        esp_err_t region_status = nvs_get_u8(nvs, "region", &stored_region);
        esp_err_t freq_status = nvs_get_u32(nvs, "freq", &freq);
        bool stored_config_readable =
            (region_status == ESP_OK || region_status == ESP_ERR_NVS_NOT_FOUND) &&
            (freq_status == ESP_OK || freq_status == ESP_ERR_NVS_NOT_FOUND);
        if (!stored_config_readable) {
            diag_inc(&s_diag.config_rejections);
            ESP_LOGE(TAG, "rejected malformed NVS LoRa region/frequency value");
        } else if (region_status == ESP_OK && freq_status == ESP_OK) {
            if (stored_region < LORA_REGION_COUNT &&
                lora_region_frequency_valid((lora_region_id_t)stored_region, freq)) {
                cfg.region = (lora_region_id_t)stored_region;
                cfg.freq_hz = freq;
            } else {
                diag_inc(&s_diag.config_rejections);
                ESP_LOGE(TAG, "rejected invalid NVS LoRa region/frequency pair");
            }
        } else if (region_status == ESP_OK) {
            const lora_region_profile_t *stored_profile =
                lora_region_profile((lora_region_id_t)stored_region);
            if (stored_profile) {
                cfg.region = stored_profile->id;
                cfg.freq_hz = stored_profile->default_hz;
            } else {
                diag_inc(&s_diag.config_rejections);
                ESP_LOGE(TAG, "rejected invalid NVS LoRa region");
            }
        } else if (freq_status == ESP_OK) {
            lora_region_id_t inferred;
            if (lora_region_infer(freq, &inferred)) {
                cfg.region = inferred;
                cfg.freq_hz = freq;
            } else {
                diag_inc(&s_diag.config_rejections);
                ESP_LOGE(TAG, "rejected out-of-profile NVS LoRa frequency");
            }
        }

        uint8_t sf = 0;
        esp_err_t sf_status = nvs_get_u8(nvs, "sf", &sf);
        if (sf_status == ESP_OK) {
            if (sf >= 7 && sf <= 12) {
                cfg.sf = sf;
            } else {
                diag_inc(&s_diag.config_rejections);
                ESP_LOGE(TAG, "rejected invalid NVS spreading factor");
            }
        } else if (sf_status != ESP_ERR_NVS_NOT_FOUND) {
            diag_inc(&s_diag.config_rejections);
            ESP_LOGE(TAG, "rejected malformed NVS spreading factor");
        }
        uint8_t d = 0;
        if (nvs_get_u8(nvs, "duty_pct", &d) == ESP_OK && d >= 1 && d <= 50) {
            duty_pct = d;
        }
        uint8_t ota = 0;
        nvs_get_u8(nvs, "ota_trunk", &ota);
        s_ota_over_trunk = ota != 0;
        nvs_close(nvs);
        if (!enabled) {
            ESP_LOGI(TAG, "trunk disabled via NVS");
            return ESP_OK;
        }
    }

#if defined(CONFIG_BITLE_LORA_VEXT_PIN) && CONFIG_BITLE_LORA_VEXT_PIN >= 0
    /* Boards like the Heltec V3 gate the radio behind a switchable
     * peripheral rail ("Vext"); the SX1262 is inert until Vext is on. Give
     * the rail a moment to settle before the scratch-register probe below. */
    gpio_reset_pin(CONFIG_BITLE_LORA_VEXT_PIN);
    gpio_set_direction(CONFIG_BITLE_LORA_VEXT_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(CONFIG_BITLE_LORA_VEXT_PIN, 1);
    vTaskDelay(pdMS_TO_TICKS(20));
#endif

    if (!sx1262_detect(&cfg)) {
        ESP_LOGI(TAG, "no SX1262 radio; running BLE-only");
        return ESP_OK;
    }

    memcpy(s_node_id, noise_get_local_peer_id(), sizeof(s_node_id));
    for (size_t offset = 0; offset < sizeof(s_boot_epoch);
         offset += sizeof(uint32_t)) {
        uint32_t random_word = esp_random();
        memcpy(s_boot_epoch + offset, &random_word, sizeof(random_word));
    }
    s_transfer_counter = 0;
    memset(s_tx_context, 0, sizeof(s_tx_context));
    memset(s_rx_slots, 0, sizeof(s_rx_slots));
    memset(s_completed_slots, 0, sizeof(s_completed_slots));
    lora_trunk_neighbor_table_init(&s_neighbors);
    s_expected_control_valid = false;
    s_feedback_seen = false;
    memset(&s_selective_tx, 0, sizeof(s_selective_tx));
    s_ack_head = 0;
    s_ack_count = 0;

    /* Modem params for the airtime governor; start the bucket full so a
     * quiet node can transmit immediately. */
    s_sf = cfg.sf;
    s_bw = cfg.bw_hz;
    s_cr = cfg.cr;
    s_preamble_symbols = cfg.preamble_symbols;
    s_gov_refill_frac = duty_pct / 100.0;
    s_gov_credit_ms = GOV_BURST_MS;
    s_gov_last_ms = esp_timer_get_time() / 1000ULL;

    lora_tx_scheduler_init(&s_tx_scheduler);
    if (xTaskCreate(lora_task, "bitle_lora", 6144, NULL, tskIDLE_PRIORITY + 4, &s_task) != pdTRUE) {
        return ESP_ERR_NO_MEM;
    }

    esp_err_t err = sx1262_init(&cfg, dio1_isr, s_task);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "radio init failed: %s", esp_err_to_name(err));
        vTaskDelete(s_task);
        s_task = NULL;
        taskENTER_CRITICAL(&s_gov_mux);
        lora_tx_scheduler_cancel_all(&s_tx_scheduler);
        diag_sync_scheduler_locked();
        taskEXIT_CRITICAL(&s_gov_mux);
        return err;
    }

    s_active = true;
    err = bitle_link_register_reservable(
        BITLE_LORA_LINK_HANDLE, BITLE_LINK_LORA, lora_link_send,
        lora_link_reserve, lora_link_commit, lora_link_cancel);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "trunk link registration failed: %s",
                 esp_err_to_name(err));
        bitle_lora_shutdown();
        return err;
    }
    const lora_region_profile_t *active_profile = lora_region_profile(cfg.region);
    ESP_LOGI(TAG,
             "trunk up: region=%s %.3f MHz SF%u BW%lu preamble=%u +%ddBm "
             "duty=%u%% ota_trunk=%d",
             active_profile->name, cfg.freq_hz / 1e6, cfg.sf,
             (unsigned long)cfg.bw_hz, cfg.preamble_symbols, cfg.tx_dbm,
             duty_pct, s_ota_over_trunk);
    return ESP_OK;
}
