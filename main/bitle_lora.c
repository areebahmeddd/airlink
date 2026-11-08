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
#include "lora_channel_policy.h"
#include "lora_forwarding.h"
#include "lora_link_adaptation.h"
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
 * offsets (see packet_codec): [0]=version, [1]=type, [11]=flags, sender id
 * at [14..21] in v1 packets and [16..23] in v2 (4-byte payload length). */
#define PKT_TYPE_OFF    1
#define PKT_FLAGS_OFF   11
#define PKT_MIN_LEN     22

static bool pkt_identity_offsets(
    const uint8_t *data, uint16_t len,
    size_t *out_sender, size_t *out_recipient)
{
    if (!data || (data[0] != 1 && data[0] != 2)) {
        return false;
    }
    size_t sender = data[0] >= 2 ? 16u : 14u;
    if (len < sender + 8u) {
        return false;
    }
    if (out_sender) {
        *out_sender = sender;
    }
    if (out_recipient) {
        *out_recipient = sender + 8u;
    }
    return true;
}

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
#define LORA_BOARD_NAME "heltec-v3"
#define LORA_PIN_SCK   9
#define LORA_PIN_MISO  11
#define LORA_PIN_MOSI  10
#define LORA_PIN_CS    8
#define LORA_PIN_RESET 12
#define LORA_PIN_BUSY  13
#define LORA_PIN_DIO1  14
#define LORA_PIN_RXEN  -1  /* DIO2 keys the RF switch; no board RXEN */
#elif CONFIG_BITLE_LORA_BOARD_XIAO_WIO_SX1262
#define LORA_BOARD_NAME "xiao-wio-sx1262"
#define LORA_PIN_SCK   7
#define LORA_PIN_MISO  8
#define LORA_PIN_MOSI  9
#define LORA_PIN_CS    41
#define LORA_PIN_RESET 42
#define LORA_PIN_BUSY  40
#define LORA_PIN_DIO1  39
#define LORA_PIN_RXEN  38
#else
#define LORA_BOARD_NAME "none"
#define LORA_PIN_SCK   -1
#define LORA_PIN_MISO  -1
#define LORA_PIN_MOSI  -1
#define LORA_PIN_CS    -1
#define LORA_PIN_RESET -1
#define LORA_PIN_BUSY  -1
#define LORA_PIN_DIO1  -1
#define LORA_PIN_RXEN  -1
#endif

#ifdef CONFIG_BITLE_LORA_CODING_RATE
#define LORA_CODING_RATE CONFIG_BITLE_LORA_CODING_RATE
#else
#define LORA_CODING_RATE 5
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
#define TRUNK_CHUNK_TX LORA_LINK_CHUNK_STABLE
#define TRUNK_MAX_FRAGS \
    ((BITLE_PACKET_MAX_ROUTED + LORA_LINK_CHUNK_WEAK - 1) / \
     LORA_LINK_CHUNK_WEAK)

_Static_assert(
    TRUNK_MAX_FRAGS <= LORA_SELECTIVE_REPEAT_MAX_FRAGMENTS,
    "adaptive chunks must fit the selective-repeat bitmap");

/* Channel access: CAD (listen-before-talk) + random backoff before TX. */
#define CAD_RETRIES 5

#if CONFIG_BITLE_LORA_DIAGNOSTIC_SMOKE || \
    CONFIG_BITLE_LORA_DIAGNOSTIC_QUIET
static const uint8_t DIAGNOSTIC_MARKER[8] = {
    0x42, 0x49, 0x54, 0x4C, 0x45, 0x4C, 0x4F, 0x52,
};

static bool trunk_is_diagnostic_probe(
    const uint8_t *data, uint16_t len)
{
    return data && len >= 11 &&
           data[PKT_TYPE_OFF] == BITCHAT_MSG_MESSAGE &&
           memcmp(data + 3, DIAGNOSTIC_MARKER,
                  sizeof(DIAGNOSTIC_MARKER)) == 0;
}
#endif

typedef struct {
    uint16_t len;
    bool want_ack;
    uint8_t data[SX1262_MAX_PAYLOAD];
} lora_frame_t;

_Static_assert(BITLE_PACKET_MAX_ROUTED <= LORA_TX_PACKET_MAX_LEN,
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
    bool announcement;
    bool forwarded;
    bool relayed_broadcast;
    bool suppressed;
    uint8_t hop_limit;
    uint8_t hop_count;
    uint16_t fragment_size;
    uint8_t maximum_rounds;
    uint8_t retry_count;
    uint8_t announce_sender[8];
    uint8_t destination[LORA_TRUNK_V3_NODE_ID_LEN];
    uint8_t transfer_id[LORA_TRUNK_V3_TRANSFER_ID_LEN];
    uint64_t forward_fingerprint;
    uint64_t forward_not_before_ms;
    uint64_t started_ms;
} tx_trunk_context_t;
static tx_trunk_context_t s_tx_context[LORA_TX_PACKET_POOL_SIZE];

/* Packet-level feedback is consumed on the LoRa task. RX and TX state are
 * therefore serialized without another lock. */
static bool s_feedback_seen;
static bool s_expected_control_valid;
static lora_trunk_frame_t s_expected_control_data;
static lora_selective_tx_t s_selective_tx;
static lora_trunk_neighbor_table_t s_neighbors;
static lora_forward_cache_t s_forward_cache;
static lora_link_adaptation_t s_link_adaptation;

typedef struct {
    bool active;
    uint8_t hop_limit;
    uint8_t hop_count;
    int8_t snr;
    uint64_t fingerprint;
} relay_ingress_t;
static relay_ingress_t s_relay_ingress;

/* Modem params (for airtime), governor, and throttle state — shared
 * between relay callers and the beacon path, guarded by a spinlock. */
static uint8_t s_sf;
static uint32_t s_bw;
static uint8_t s_cr;             /* denominator 5..8 => 4/5..4/8 */
static uint16_t s_preamble_symbols;
static lora_region_id_t s_region;
static bool s_ota_over_trunk;    /* OTA image chunks on the trunk (default off) */
static bitle_lora_diag_t s_diag;

static portMUX_TYPE s_gov_mux = portMUX_INITIALIZER_UNLOCKED;
static double s_gov_credit_ms;
static double s_gov_refill_frac; /* airtime allowed per ms of wall time */
static uint64_t s_gov_last_ms;

typedef struct {
    bool in_use;
    bool pending;
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
    uint8_t fragment_total, uint16_t fragment_size,
    uint8_t maximum_rounds, lora_reliability_timing_t *out)
{
    if (!lora_link_fragment_size_valid(fragment_size) ||
        maximum_rounds < LORA_LINK_ROUNDS_STABLE ||
        maximum_rounds > LORA_LINK_ROUNDS_WEAK) {
        return false;
    }
    uint32_t maximum_airtime =
        trunk_airtime_ms(LORA_TRUNK_V3_HEADER_LEN + fragment_size);
    lora_contention_window_t contention;
    if (!lora_contention_window(
            maximum_airtime, CAD_RETRIES, false, &contention)) {
        return false;
    }
    return lora_reliability_timing(
        maximum_airtime,
        trunk_airtime_ms(LORA_TRUNK_V3_HEADER_LEN),
        fragment_total,
        maximum_rounds,
        contention.maximum_ms,
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

/* Caller holds s_gov_mux. Mark every not-yet-transmitted broadcast relay of
 * this logical BitChat packet. The LoRa task releases queued or active entries
 * before their next CAD/TX opportunity. */
static uint32_t suppress_relay_fingerprint_locked(
    uint64_t fingerprint)
{
    if (fingerprint == 0) {
        return 0;
    }
    uint32_t suppressed = 0;
    for (lora_tx_handle_t handle = 0;
         handle < LORA_TX_PACKET_POOL_SIZE; ++handle) {
        tx_trunk_context_t *context = &s_tx_context[handle];
        if (context->valid && context->relayed_broadcast &&
            !context->suppressed &&
            context->forward_fingerprint == fingerprint) {
            context->suppressed = true;
            suppressed++;
        }
    }
    s_diag.forward_suppressed += suppressed;
    return suppressed;
}

/* Per-origin announce throttle. Admission marks one pending copy; only a
 * fully transmitted packet advances last_ms. Caller holds s_gov_mux. */
static throttle_t *announce_slot_locked(
    const uint8_t *sender, bool create)
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
    if (!slot && create) {
        slot = free_slot ? free_slot : oldest;
        memset(slot, 0, sizeof(*slot));
        slot->in_use = true;
        memcpy(slot->tag, sender, sizeof(slot->tag));
    }
    return slot;
}

static bool announce_allowed_locked(const uint8_t *sender, uint64_t now)
{
    throttle_t *slot = announce_slot_locked(sender, false);
    return !slot ||
           (!slot->pending &&
            (slot->last_ms == 0 || now < slot->last_ms ||
             now - slot->last_ms >= ANNOUNCE_MIN_INTERVAL_MS));
}

static void announce_mark_pending_locked(const uint8_t *sender)
{
    throttle_t *slot = announce_slot_locked(sender, true);
    if (slot) {
        slot->pending = true;
    }
}

static void announce_finish_locked(
    const uint8_t *sender, bool transmitted, uint64_t now)
{
    throttle_t *slot = announce_slot_locked(sender, false);
    if (!slot) {
        return;
    }
    slot->pending = false;
    if (transmitted) {
        slot->last_ms = now;
        s_diag.announce_tx++;
    } else if (slot->last_ms == 0) {
        memset(slot, 0, sizeof(*slot));
    }
}

/* Admission + governor for one whole encoded packet. Caller holds s_gov_mux,
 * which couples the policy state change to the scheduler admission. */
static void governor_refill_locked(uint64_t now)
{
    if (now < s_gov_last_ms) {
        s_gov_last_ms = now;
        return;
    }
    s_gov_credit_ms += (double)(now - s_gov_last_ms) * s_gov_refill_frac;
    if (s_gov_credit_ms > GOV_BURST_MS) {
        s_gov_credit_ms = GOV_BURST_MS;
    }
    s_gov_last_ms = now;
}

static bool governor_debit_locked(uint32_t airtime, bool governed)
{
    uint64_t now = esp_timer_get_time() / 1000ULL;
    governor_refill_locked(now);
    if (governed && s_gov_credit_ms < (double)airtime) {
        return false;
    }
    s_gov_credit_ms -= airtime;
    if (s_gov_credit_ms < -GOV_BURST_MS) {
        s_gov_credit_ms = -GOV_BURST_MS;
    }
    return true;
}

static bool beacon_budget_admit(uint16_t encoded_len)
{
    bool admitted;
    taskENTER_CRITICAL(&s_gov_mux);
    admitted = governor_debit_locked(
        trunk_airtime_ms(encoded_len), true);
    if (!admitted) {
        s_diag.beacon_budget_deferred++;
    }
    taskEXIT_CRITICAL(&s_gov_mux);
    return admitted;
}

static bool trunk_admit_locked(
    const uint8_t *data, uint16_t len, bool forwarded,
    uint16_t fragment_size)
{
    if (len < PKT_MIN_LEN ||
        !lora_link_fragment_size_valid(fragment_size)) {
        return false;
    }
    size_t sender_off = 0;
    if (!pkt_identity_offsets(data, len, &sender_off, NULL)) {
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

#if CONFIG_BITLE_LORA_DIAGNOSTIC_SMOKE || \
    CONFIG_BITLE_LORA_DIAGNOSTIC_QUIET
    if (!announce && !trunk_is_diagnostic_probe(data, len)) {
        return false;
    }
#endif
#if CONFIG_BITLE_LORA_DIAGNOSTIC_QUIET
    if (announce) {
        return false;
    }
#endif

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
    uint8_t total =
        (uint8_t)((len + fragment_size - 1) / fragment_size);
    uint32_t airtime = 0;
    for (uint8_t i = 0; i < total; ++i) {
        uint16_t off = (uint16_t)i * fragment_size;
        uint16_t chunk =
            len - off < fragment_size
                ? len - off
                : fragment_size;
        airtime += trunk_airtime_ms(LORA_TRUNK_V3_HEADER_LEN + chunk);
    }

    uint64_t now = esp_timer_get_time() / 1000ULL;
    governor_refill_locked(now);
    /* Governed (announce) traffic yields when the budget is exhausted; it is
     * periodic and will re-announce. Message traffic always passes but still
     * debits, so a busy DM session naturally suppresses announces until the
     * channel frees up. Check the budget before the per-origin throttle records
     * a timestamp, so a budget-deferred announce does not suppress this
     * origin's next transmittable announce. */
    if (governed) {
        /* A relayed signed announce is the route-discovery mechanism, not a
         * new local periodic advertisement. It may consume the remaining
         * bounded burst credit so one route copy can cross a weak mesh, while
         * the per-origin throttle and network dedup still prevent storms.
         * The resulting negative credit delays later local announcements and
         * beacons until the channel budget refills. */
        if (!forwarded && s_gov_credit_ms < (double)airtime) {
            ESP_LOGD(TAG, "airtime budget low; deferring announce");
            return false;
        }
        if (!announce_allowed_locked(data + sender_off, now)) {
            return false;
        }
    }
    return governor_debit_locked(airtime, false);
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
    uint16_t fragment_size;
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
 * Layout: version|type|ttl|ts(8)|flags|payloadLen(2 in v1, 4 in v2)|sender(8)|
 * [recipient(8) if flags&0x01]|[route count(1)+N*8 if v2 && flags&0x08]|
 * payload|[sig(64) if flags&0x02]. Padding is appended AFTER the signature,
 * so trimming to true length never touches signed/encrypted bytes; receivers
 * read payloadLen and already accept unpadded packets. Returns len unchanged
 * if the header does not parse or claims more than we received. */
static uint16_t trunk_true_len(const uint8_t *data, uint16_t len)
{
    if (len < 14) {
        return len;
    }
    uint8_t version = data[0];
    uint8_t flags = data[PKT_FLAGS_OFF];
    uint32_t payload_len;
    uint32_t real;
    if (version == 2) {
        if (len < 24) {
            return len;
        }
        payload_len =
            ((uint32_t)data[12] << 24) |
            ((uint32_t)data[13] << 16) |
            ((uint32_t)data[14] << 8) |
            data[15];
        real = 24u;
    } else if (version == 1) {
        payload_len =
            ((uint16_t)data[12] << 8) | data[13];
        real = 22u;
    } else {
        return len;
    }
    if (flags & 0x01) {
        real += 8;                              /* recipient id */
    }
    if (version == 2 && (flags & 0x08)) {
        if (real >= len) {
            return len;
        }
        real += 1u + (uint32_t)data[real] * 8u;
    }
    real += payload_len;
    if (flags & 0x02) {
        real += 64;                             /* Ed25519 signature */
    }
    return (real <= len) ? (uint16_t)real : len;
}

/*
 * Production addressed traffic requires an authenticated route. A quiet
 * diagnostic sender may additionally address a marked smoke probe directly
 * to a fresh beacon source. This keeps a 60-second RF measurement focused on
 * link adaptation even when simultaneous signed announcements collide. The
 * fallback is compiled out unless both diagnostic options are enabled and is
 * never available to application traffic.
 */
static bool trunk_route_locked(
    const uint8_t recipient[LORA_TRUNK_V3_NODE_ID_LEN],
    uint64_t now_ms, uint64_t max_age_ms,
    bool allow_diagnostic_beacon,
    uint8_t out_node_id[LORA_TRUNK_V3_NODE_ID_LEN],
    uint16_t *out_capabilities)
{
    if (lora_trunk_neighbor_route(
            &s_neighbors, recipient, now_ms, max_age_ms,
            out_node_id, out_capabilities)) {
        return true;
    }
#if CONFIG_BITLE_LORA_DIAGNOSTIC_SMOKE && \
    CONFIG_BITLE_LORA_DIAGNOSTIC_QUIET
    if (allow_diagnostic_beacon) {
        for (size_t i = 0;
             i < LORA_TRUNK_NEIGHBOR_CAPACITY; ++i) {
            const lora_trunk_neighbor_t *entry =
                &s_neighbors.entries[i];
            if (!entry->in_use || entry->quarantined ||
                entry->identity_authenticated ||
                memcmp(entry->node_id, recipient,
                       LORA_TRUNK_V3_NODE_ID_LEN) != 0 ||
                now_ms < entry->last_seen_ms ||
                now_ms - entry->last_seen_ms > max_age_ms ||
                (entry->capabilities &
                 LORA_TRUNK_V3_CAP_PROTOCOL) == 0) {
                continue;
            }
            memcpy(
                out_node_id, entry->node_id,
                LORA_TRUNK_V3_NODE_ID_LEN);
            if (out_capabilities) {
                *out_capabilities = entry->capabilities;
            }
            return true;
        }
    }
#else
    (void)allow_diagnostic_beacon;
#endif
    return false;
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

static bitle_link_send_result_t lora_link_commit_internal(
    uint16_t handle, uintptr_t token, const uint8_t *data, uint16_t len,
    bool same_medium_relay)
{
    (void)handle;
    if (!data || len == 0 || len > BITLE_PACKET_MAX_ROUTED ||
        token >= LORA_TX_PACKET_POOL_SIZE) {
        lora_link_cancel(handle, token);
        return BITLE_LINK_SEND_FAILED;
    }
    len = trunk_true_len(data, len);
    if (len < PKT_MIN_LEN) {
        lora_link_cancel(handle, token);
        return BITLE_LINK_SEND_FAILED;
    }
    size_t sender_off = 0;
    size_t recipient_off = 0;
    if (!pkt_identity_offsets(
            data, len, &sender_off, &recipient_off)) {
        lora_link_cancel(handle, token);
        return BITLE_LINK_SEND_FAILED;
    }

    uint8_t type = data[PKT_TYPE_OFF];
    lora_tx_priority_t priority = trunk_priority(type);
    lora_tx_handle_t reserved = (lora_tx_handle_t)token;
    uint32_t transfer_counter = 0;
    uint8_t transfer_id[LORA_TRUNK_V3_TRANSFER_ID_LEN] = {0};
    uint8_t destination[LORA_TRUNK_V3_NODE_ID_LEN] = {0};
    lora_link_policy_t link_policy = {
        .fragment_size = LORA_LINK_CHUNK_STABLE,
        .maximum_rounds = LORA_LINK_ROUNDS_DEFAULT,
        .profile = LORA_LINK_PROFILE_UNKNOWN,
    };
    bool ack_requested = false;
    bool announcement =
        type == BITCHAT_MSG_ANNOUNCE ||
        type == BITCHAT_MSG_NOISE_IDENTITY_ANNOUNCE;
    relay_ingress_t ingress = s_relay_ingress;
    bool forwarded = same_medium_relay && ingress.active;
    uint64_t forward_fingerprint =
        lora_forward_fingerprint(data, len);
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
    if (same_medium_relay &&
        (!forwarded ||
         !lora_forward_hop_allowed(
             ingress.hop_limit, ingress.hop_count))) {
        s_diag.hop_limit_drops++;
        s_diag.policy_drops++;
        lora_tx_scheduler_cancel(&s_tx_scheduler, reserved);
        diag_sync_scheduler_locked();
        taskEXIT_CRITICAL(&s_gov_mux);
        return BITLE_LINK_SEND_POLICY_DROPPED;
    }

    /* Only a fresh authenticated announce may supply a directed route;
     * unknown routes stay reachable as unacknowledged broadcasts. Adaptation
     * is strictly per next hop and changes only fragmentation/retry bounds. */
    if ((data[PKT_FLAGS_OFF] & 0x01u) != 0 &&
        len >= recipient_off + LORA_TRUNK_V3_NODE_ID_LEN) {
        uint16_t route_capabilities = 0;
        uint64_t now_ms = esp_timer_get_time() / 1000ULL;
        bool allow_diagnostic_beacon = false;
#if CONFIG_BITLE_LORA_DIAGNOSTIC_SMOKE && \
    CONFIG_BITLE_LORA_DIAGNOSTIC_QUIET
        allow_diagnostic_beacon =
            trunk_is_diagnostic_probe(data, len);
#endif
        if (trunk_route_locked(
                data + recipient_off, now_ms, 180000ULL,
                allow_diagnostic_beacon, destination,
                &route_capabilities) &&
            (route_capabilities & LORA_TRUNK_V3_CAP_PROTOCOL) != 0) {
            ack_requested = true;
            link_policy = lora_link_adaptation_policy(
                &s_link_adaptation, destination);
        } else {
            memset(destination, 0, sizeof(destination));
        }
    }
    if (!trunk_admit_locked(
            data, len, forwarded, link_policy.fragment_size)) {
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

    committed = lora_tx_scheduler_commit(
        &s_tx_scheduler, reserved, data, len, type,
        (uint16_t)transfer_counter);
    if (committed) {
        tx_trunk_context_t *context = &s_tx_context[reserved];
        context->valid = true;
        context->ack_requested = ack_requested;
        context->announcement = announcement;
        context->forwarded = forwarded;
        context->relayed_broadcast =
            !ack_requested &&
            (forwarded ||
             memcmp(
                 data + sender_off, s_node_id,
                 sizeof(s_node_id)) != 0);
        context->hop_limit =
            forwarded ? ingress.hop_limit
                      : LORA_FORWARD_DEFAULT_HOP_LIMIT;
        context->hop_count =
            forwarded ? (uint8_t)(ingress.hop_count + 1u) : 0;
        context->fragment_size = link_policy.fragment_size;
        context->maximum_rounds = link_policy.maximum_rounds;
        context->forward_fingerprint =
            context->relayed_broadcast
                ? forward_fingerprint
                : 0;
        if (forwarded && context->relayed_broadcast) {
            uint16_t first_chunk =
                len < context->fragment_size
                    ? len
                    : context->fragment_size;
            context->forward_not_before_ms =
                esp_timer_get_time() / 1000ULL +
                lora_forward_delay_ms(
                    trunk_airtime_ms(
                        LORA_TRUNK_V3_HEADER_LEN + first_chunk),
                    ingress.snr, esp_random());
        }
        if (announcement) {
            memcpy(
                context->announce_sender,
                data + sender_off,
                sizeof(context->announce_sender));
            announce_mark_pending_locked(
                context->announce_sender);
        }
        memcpy(context->destination, destination, sizeof(destination));
        memcpy(context->transfer_id, transfer_id, sizeof(transfer_id));
        if (!forwarded && forward_fingerprint != 0) {
            (void)lora_forward_cache_observe(
                &s_forward_cache, data + sender_off,
                forward_fingerprint, 0, 12,
                esp_timer_get_time() / 1000ULL);
        }
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
    uint8_t total = (uint8_t)(
        (len + link_policy.fragment_size - 1) /
        link_policy.fragment_size);
    ESP_LOGI(TAG,
             "trunk accepted type=0x%02X len=%u frags=%u priority=%u "
             "addressed=%d transfer=%lu hops=%u/%u forwarded=%d "
             "link=%u chunk=%u rounds=%u",
             type, len, total, priority, ack_requested,
             (unsigned long)transfer_counter,
             forwarded ? (unsigned)(ingress.hop_count + 1u) : 0u,
             forwarded ? (unsigned)ingress.hop_limit
                       : LORA_FORWARD_DEFAULT_HOP_LIMIT,
             forwarded, (unsigned)link_policy.profile,
             link_policy.fragment_size,
             link_policy.maximum_rounds);
    bitle_stats_note_activity(BITLE_LANE_TRUNK, 1);
    if (s_task) {
        xTaskNotifyGive(s_task);
    }
    return BITLE_LINK_SEND_ACCEPTED;
}

static bitle_link_send_result_t lora_link_commit(
    uint16_t handle, uintptr_t token, const uint8_t *data, uint16_t len)
{
    return lora_link_commit_internal(
        handle, token, data, len, false);
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

static bitle_link_send_result_t lora_link_relay_send(
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
    return lora_link_commit_internal(
        handle, token, data, len, true);
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

static void tx_scheduler_release(
    lora_tx_handle_t handle, bool transmitted)
{
    if (handle == LORA_TX_HANDLE_INVALID) {
        return;
    }
    lora_link_metrics_snapshot_t metrics;
    bool have_metrics = false;
    taskENTER_CRITICAL(&s_gov_mux);
    tx_trunk_context_t context = s_tx_context[handle];
    uint64_t now = esp_timer_get_time() / 1000ULL;
    if (context.announcement) {
        announce_finish_locked(
            context.announce_sender, transmitted, now);
    }
    if (transmitted && context.forwarded) {
        s_diag.forwarded_packets++;
    } else if (!transmitted && context.ack_requested) {
        size_t removed =
            lora_trunk_neighbor_forget_next_hop(
                &s_neighbors, context.destination);
        if (removed > 0) {
            s_diag.route_failures += (uint32_t)removed;
            s_diag.neighbor_count =
                (uint32_t)lora_trunk_neighbor_count(
                    &s_neighbors);
        }
    }
    if (context.valid && context.ack_requested &&
        context.started_ms != 0) {
        uint64_t elapsed =
            now >= context.started_ms
                ? now - context.started_ms
                : 0;
        lora_link_adaptation_note_delivery(
            &s_link_adaptation, context.destination, transmitted,
            context.retry_count,
            elapsed > UINT32_MAX ? UINT32_MAX : (uint32_t)elapsed,
            now);
        have_metrics = lora_link_adaptation_snapshot(
            &s_link_adaptation, context.destination, &metrics);
    }
    memset(&s_tx_context[handle], 0, sizeof(s_tx_context[handle]));
    lora_tx_scheduler_release(&s_tx_scheduler, handle);
    diag_sync_scheduler_locked();
    taskEXIT_CRITICAL(&s_gov_mux);
    s_expected_control_valid = false;
    if (have_metrics) {
        ESP_LOGI(
            TAG,
            "link metrics profile=%u rssi_x10=%d snr_x10=%d "
            "data=%u ack=%u retries_x100=%u latency_ms=%lu "
            "samples=%u/%u/%u",
            (unsigned)metrics.profile, metrics.rssi_x10,
            metrics.snr_x10, metrics.data_success_pct,
            metrics.ack_success_pct, metrics.retries_x100,
            (unsigned long)metrics.latency_ms,
            metrics.signal_samples, metrics.data_samples,
            metrics.ack_samples);
    }
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
    const tx_trunk_context_t *context = &s_tx_context[handle];
    if (!lora_link_fragment_size_valid(context->fragment_size)) {
        return false;
    }
    uint8_t total = (uint8_t)(
        (packet->len + context->fragment_size - 1) /
        context->fragment_size);
    if (idx >= total) {
        return false;
    }
    uint16_t off = (uint16_t)idx * context->fragment_size;
    uint16_t remaining = packet->len - off;
    uint16_t chunk =
        remaining < context->fragment_size
            ? remaining
            : context->fragment_size;
    lora_trunk_frame_t trunk = {
        .version = LORA_TRUNK_V3_VERSION,
        .kind = LORA_TRUNK_KIND_DATA,
        .flags = context->ack_requested
                     ? LORA_TRUNK_V3_FLAG_ACK_REQUESTED
                     : LORA_TRUNK_V3_FLAG_BROADCAST,
        .capabilities = LORA_TRUNK_V3_CAP_PROTOCOL,
        .hop_limit = context->hop_limit,
        .hop_count = context->hop_count,
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
    if (noise_verify_announce_identity(&packet, signing_key)) {
        bool direct_identity =
            memcmp(packet.sender_id, frame->source,
                   LORA_TRUNK_V3_NODE_ID_LEN) == 0;
        uint32_t neighbor_count = 0;
        taskENTER_CRITICAL(&s_gov_mux);
        lora_trunk_neighbor_result_t result =
            lora_trunk_neighbor_learn_authenticated(
                &s_neighbors, frame->source, packet.sender_id, signing_key,
                direct_identity, frame->capabilities, now_ms);
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
    if (frame->version == LORA_TRUNK_V3_VERSION) {
        bool non_final =
            frame->fragment_index + 1u < frame->fragment_total;
        if (frame->payload_len > LORA_LINK_CHUNK_STABLE ||
            (non_final &&
             !lora_link_fragment_size_valid(frame->payload_len))) {
            queue_v3_control(
                frame, LORA_TRUNK_KIND_ABORT,
                LORA_TRUNK_ABORT_INVALID_LENGTH);
            diag_inc(&s_diag.invalid_reassemblies);
            return;
        }
    }

    uint64_t now = esp_timer_get_time() / 1000ULL;
    lora_reliability_timing_t timing;
    if (!trunk_reliability_timing(
            frame->fragment_total, LORA_LINK_CHUNK_STABLE,
            LORA_LINK_ROUNDS_WEAK, &timing)) {
        return;
    }
    if (frame->version == LORA_TRUNK_V3_VERSION) {
        taskENTER_CRITICAL(&s_gov_mux);
        lora_link_adaptation_note_signal(
            &s_link_adaptation, frame->source, rssi, snr, now);
        taskEXIT_CRITICAL(&s_gov_mux);
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

    bool non_final =
        frame->fragment_index + 1u < frame->fragment_total;
    if (frame->version == LORA_TRUNK_V3_VERSION && non_final) {
        if (slot->fragment_size == 0) {
            slot->fragment_size = frame->payload_len;
        } else if (slot->fragment_size != frame->payload_len) {
            abort_rx_slot(slot, LORA_TRUNK_ABORT_INVALID_LENGTH);
            diag_inc(&s_diag.invalid_reassemblies);
            return;
        }
        uint8_t final_index =
            (uint8_t)(frame->fragment_total - 1u);
        if ((slot->have_mask & (1u << final_index)) != 0 &&
            slot->part_len[final_index] > slot->fragment_size) {
            abort_rx_slot(slot, LORA_TRUNK_ABORT_INVALID_LENGTH);
            diag_inc(&s_diag.invalid_reassemblies);
            return;
        }
    } else if (
        frame->version == LORA_TRUNK_V3_VERSION &&
        frame->fragment_total > 1 &&
        slot->fragment_size != 0 &&
        frame->payload_len > slot->fragment_size) {
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

    static uint8_t packet[BITLE_PACKET_MAX_ROUTED];
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
    if (frame->version == LORA_TRUNK_V3_VERSION &&
        frame->fragment_total > 1 &&
        (slot->fragment_size == 0 ||
         packet_len <=
             (uint16_t)(
                 slot->fragment_size *
                 (frame->fragment_total - 1u)))) {
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

    uint64_t forward_fingerprint =
        lora_forward_fingerprint(packet, packet_len);
    size_t packet_sender_off = 0;
    if (!pkt_identity_offsets(
            packet, packet_len, &packet_sender_off, NULL)) {
        diag_inc(&s_diag.invalid_reassemblies);
        return;
    }
    lora_forward_observation_t observation;
    uint32_t suppressed = 0;
    taskENTER_CRITICAL(&s_gov_mux);
    observation = lora_forward_cache_observe(
        &s_forward_cache, packet + packet_sender_off,
        forward_fingerprint, frame->hop_count, snr, now);
    if (observation != LORA_FORWARD_NEW) {
        s_diag.forward_duplicates++;
        suppressed = suppress_relay_fingerprint_locked(
            forward_fingerprint);
    }
    taskEXIT_CRITICAL(&s_gov_mux);
    if (observation == LORA_FORWARD_NEW ||
        observation == LORA_FORWARD_BETTER_COPY) {
        /* Only a first or objectively better signed path may replace a route.
         * A later weaker duplicate still suppresses redundant forwarding but
         * cannot steer the neighbor table. */
        learn_authenticated_neighbor(
            frame, packet, packet_len, now);
    }
    if (observation != LORA_FORWARD_NEW) {
        ESP_LOGI(
            TAG,
            "trunk duplicate network packet suppressed=%lu better=%d",
            (unsigned long)suppressed,
            observation == LORA_FORWARD_BETTER_COPY);
        return;
    }

    diag_inc(&s_diag.completed_packets);
    ESP_LOGI(TAG,
             "trunk v%u RX packet len=%u rssi=%d snr=%d frags=%u "
             "hops=%u/%u",
             frame->version, packet_len, rssi, snr,
             frame->fragment_total, frame->hop_count,
             frame->hop_limit);
    s_relay_ingress.active =
        frame->version == LORA_TRUNK_V3_VERSION;
    s_relay_ingress.hop_limit = frame->hop_limit;
    s_relay_ingress.hop_count = frame->hop_count;
    s_relay_ingress.snr = snr;
    s_relay_ingress.fingerprint = forward_fingerprint;
    bitle_mesh_inbound(BITLE_LORA_LINK_HANDLE, packet, packet_len);
    memset(&s_relay_ingress, 0, sizeof(s_relay_ingress));
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

    if (frame.kind == LORA_TRUNK_KIND_BEACON) {
        uint8_t region = 0;
        uint32_t freshness = 0;
        if (!lora_trunk_beacon_fields(
                &frame, &region, &freshness) ||
            region != (uint8_t)s_region) {
            return;
        }
        lora_trunk_neighbor_result_t result;
        taskENTER_CRITICAL(&s_gov_mux);
        result = lora_trunk_neighbor_learn_beacon(
            &s_neighbors, frame.source, frame.transfer_id,
            freshness, region, frame.capabilities,
            esp_timer_get_time() / 1000ULL);
        s_diag.beacon_rx++;
        if (result == LORA_TRUNK_NEIGHBOR_STALE) {
            s_diag.beacon_stale++;
        } else if (result == LORA_TRUNK_NEIGHBOR_COLLISION) {
            s_diag.neighbor_collisions++;
        }
        s_diag.neighbor_count =
            (uint32_t)lora_trunk_neighbor_count(&s_neighbors);
        taskEXIT_CRITICAL(&s_gov_mux);
        ESP_LOGI(
            TAG, "trunk beacon RX freshness=%lu result=%u",
            (unsigned long)freshness, result);
        return;
    }

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
                    uint64_t now_ms =
                        esp_timer_get_time() / 1000ULL;
                    taskENTER_CRITICAL(&s_gov_mux);
                    lora_link_adaptation_note_signal(
                        &s_link_adaptation, frame.source,
                        rssi, snr, now_ms);
                    lora_link_adaptation_note_ack(
                        &s_link_adaptation, frame.source,
                        true, now_ms);
                    taskEXIT_CRITICAL(&s_gov_mux);
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

/* Minimum viable radio-neighbor discovery is intentionally separate from the
 * signed BitChat/Noise identity announce. A compact beacon is repeated without
 * ACKs; the signed application announce follows its own randomized cadence. */
#define BEACON_FIRST_MS    5000ULL
#define BEACON_INTERVAL_MS 60000ULL
#define BEACON_START_JITTER_MS 10000U
#define BEACON_INTERVAL_JITTER_MS 30000U
#define BEACON_REPEAT_MIN_MS 1000U
#define BEACON_REPEAT_SPAN_MS 4000U
#if CONFIG_BITLE_LORA_DIAGNOSTIC_QUIET
#define TRUNK_BEACON_REPETITIONS 1U
#else
#define TRUNK_BEACON_REPETITIONS LORA_CHANNEL_BEACON_REPETITIONS
#endif

typedef struct {
    uint32_t freshness;
    uint8_t remaining;
    uint64_t next_burst_ms;
    uint64_t next_repeat_ms;
} beacon_schedule_t;

static void beacon_schedule_begin(
    beacon_schedule_t *schedule, uint64_t now)
{
    schedule->next_burst_ms =
        now + BEACON_INTERVAL_MS -
        (BEACON_INTERVAL_JITTER_MS / 2U) +
        (esp_random() % BEACON_INTERVAL_JITTER_MS);
    if (schedule->remaining != 0) {
        return;
    }
    schedule->freshness++;
    if (schedule->freshness == 0) {
        schedule->freshness = 1;
    }
    schedule->remaining = TRUNK_BEACON_REPETITIONS;
    schedule->next_repeat_ms =
        now + (esp_random() % BEACON_START_JITTER_MS);
}

static void beacon_schedule_finish_attempt(
    beacon_schedule_t *schedule, bool *have_pending,
    bool *pending_is_beacon, uint64_t now)
{
    if (schedule->remaining > 0) {
        schedule->remaining--;
    }
    schedule->next_repeat_ms =
        schedule->remaining == 0
            ? UINT64_MAX
            : now + BEACON_REPEAT_MIN_MS +
                  (esp_random() % BEACON_REPEAT_SPAN_MS);
    *have_pending = false;
    *pending_is_beacon = false;
}

static bool build_beacon_frame(
    uint32_t freshness, lora_frame_t *frame)
{
    lora_trunk_frame_t beacon;
    if (!lora_trunk_beacon_init(
            &beacon, s_node_id, s_boot_epoch, freshness,
            (uint8_t)s_region, LORA_TRUNK_V3_CAP_PROTOCOL)) {
        return false;
    }
    size_t encoded_len = 0;
    if (!lora_trunk_v3_encode(
            &beacon, frame->data, sizeof(frame->data),
            &encoded_len)) {
        return false;
    }
    frame->len = (uint16_t)encoded_len;
    frame->want_ack = false;
    return encoded_len == LORA_TRUNK_V3_HEADER_LEN;
}

static bool schedule_contention_backoff(
    const lora_frame_t *frame, uint8_t busy_attempt,
    bool relayed_broadcast, uint64_t *deadline)
{
    lora_contention_window_t window;
    if (!frame || !deadline ||
        !lora_contention_window(
            trunk_airtime_ms(frame->len), busy_attempt,
            relayed_broadcast, &window)) {
        return false;
    }
    if (!resume_rx_or_recover("contention backoff resume RX")) {
        return false;
    }
    *deadline =
        esp_timer_get_time() / 1000ULL +
        lora_contention_delay(&window, esp_random());
    diag_inc(&s_diag.channel_backoffs);
    return true;
}

static void drop_tx_packet(lora_tx_handle_t *handle, bool *have_pending)
{
    tx_scheduler_release(*handle, false);
    *handle = LORA_TX_HANDLE_INVALID;
    *have_pending = false;
}

static void complete_tx_packet(
    lora_tx_handle_t *handle, bool *have_pending)
{
    tx_scheduler_release(*handle, true);
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
        tx_scheduler_release(*handle, true);
        *handle = LORA_TX_HANDLE_INVALID;
        return false;
    }
    uint8_t checked_total = 0;
    if (!build_tx_fragment(*handle, *fragment_idx, frame, &checked_total) ||
        checked_total != fragment_total) {
        tx_scheduler_release(*handle, false);
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
    bool awaiting_backoff = false;
    bool awaiting_ack = false;
    bool pending_is_beacon = false;
    bool pending_relayed_broadcast = false;
    unsigned ack_burst = 0;
    uint64_t tx_watchdog_deadline = 0;
    uint64_t backoff_deadline = 0;
    uint64_t pending_forward_not_before_ms = 0;
    uint64_t ack_deadline = 0;
    uint64_t transfer_deadline = 0;
    lora_reliability_timing_t transfer_timing = {0};
    beacon_schedule_t beacon_schedule = {
        .next_burst_ms =
            BEACON_FIRST_MS +
            (esp_random() % BEACON_START_JITTER_MS),
        .next_repeat_ms = UINT64_MAX,
    };
    uint64_t next_identity_announce_ms =
        BEACON_FIRST_MS +
        (esp_random() % BEACON_START_JITTER_MS);
    uint64_t next_diag_ms =
#if CONFIG_BITLE_LORA_DIAGNOSTIC_SMOKE
        30000ULL;
#else
        60000ULL;
#endif
#if CONFIG_BITLE_LORA_DIAGNOSTIC_SMOKE
    static const uint16_t smoke_lengths[] = {
        100, 100, 100, 100, 180,
        300, 420, 520, 100, 480,
    };
    size_t smoke_index = 0;
    uint8_t forwarding_smoke_count =
#if CONFIG_BITLE_LORA_DIAGNOSTIC_QUIET
        3;
#else
        0;
#endif
    bool smoke_waiting_completion = false;
    bool smoke_route_selected = false;
    uint16_t smoke_expected_data_samples = 0;
    uint8_t smoke_recipient[LORA_TRUNK_V3_NODE_ID_LEN] = {0};
    uint8_t smoke_next_hop[LORA_TRUNK_V3_NODE_ID_LEN] = {0};
    uint64_t next_smoke_ms = 3000ULL;
#endif
#if CONFIG_BITLE_LORA_DIAGNOSTIC_SUPPRESS_TX_DONE_ONCE
    bool suppressed_tx_done = false;
#endif

    while (true) {
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(50));

        uint64_t now = esp_timer_get_time() / 1000ULL;
        expire_reassembly(now);
        if (now >= beacon_schedule.next_burst_ms) {
            beacon_schedule_begin(&beacon_schedule, now);
        }
        if (now >= next_identity_announce_ms) {
            next_identity_announce_ms =
                now + BEACON_INTERVAL_MS -
                (BEACON_INTERVAL_JITTER_MS / 2U) +
                (esp_random() % BEACON_INTERVAL_JITTER_MS);
            if (noise_announce_link(BITLE_LORA_LINK_HANDLE)) {
                ESP_LOGI(TAG, "signed identity announce admitted");
            }
        }

#if CONFIG_BITLE_LORA_DIAGNOSTIC_SMOKE
        if (smoke_waiting_completion) {
            lora_link_metrics_snapshot_t metrics;
            taskENTER_CRITICAL(&s_gov_mux);
            bool have_metrics = lora_link_adaptation_snapshot(
                &s_link_adaptation, smoke_next_hop, &metrics);
            taskEXIT_CRITICAL(&s_gov_mux);
            if (have_metrics &&
                metrics.data_samples >=
                    smoke_expected_data_samples) {
                smoke_waiting_completion = false;
                next_smoke_ms = now + 100ULL;
            }
        }
        if (forwarding_smoke_count < 3 &&
            now >= next_smoke_ms) {
            static uint8_t forwarding_probe[100];
            memset(
                forwarding_probe, 0xA5,
                sizeof(forwarding_probe));
            forwarding_probe[0] = 1;
            forwarding_probe[1] = BITCHAT_MSG_MESSAGE;
            forwarding_probe[2] = BITLE_ORIGIN_TTL;
            memcpy(
                forwarding_probe + 3, DIAGNOSTIC_MARKER,
                sizeof(DIAGNOSTIC_MARKER));
            forwarding_probe[11] = 0;
            uint16_t payload_len =
                sizeof(forwarding_probe) - PKT_MIN_LEN;
            forwarding_probe[12] = payload_len >> 8;
            forwarding_probe[13] = payload_len & 0xFF;
            memcpy(
                forwarding_probe +
                    (forwarding_probe[0] >= 2 ? 16 : 14),
                noise_get_local_peer_id(), 8);
            forwarding_probe[PKT_MIN_LEN] =
                forwarding_smoke_count;
            bitle_link_send_result_t result =
                lora_link_send(
                    BITLE_LORA_LINK_HANDLE,
                    forwarding_probe,
                    sizeof(forwarding_probe));
            if (result == BITLE_LINK_SEND_ACCEPTED) {
                ESP_LOGI(
                    TAG,
                    "diagnostic forwarding smoke enqueue len=%u "
                    "expected_frags=1 sequence=%u",
                    (unsigned)sizeof(forwarding_probe),
                    forwarding_smoke_count);
                forwarding_smoke_count++;
            } else {
                ESP_LOGW(
                    TAG,
                    "diagnostic forwarding smoke deferred result=%u",
                    result);
            }
            next_smoke_ms = now + 1200ULL;
        } else if (
            !smoke_waiting_completion &&
            smoke_index <
                sizeof(smoke_lengths) / sizeof(smoke_lengths[0]) &&
            now >= next_smoke_ms) {
            static uint8_t probe[BITLE_PACKET_MAX_ROUTED];
            uint16_t probe_len = smoke_lengths[smoke_index];
            uint8_t recipient[LORA_TRUNK_V3_NODE_ID_LEN] = {0};
            lora_link_policy_t smoke_policy = {
                .fragment_size = LORA_LINK_CHUNK_STABLE,
                .maximum_rounds = LORA_LINK_ROUNDS_DEFAULT,
                .profile = LORA_LINK_PROFILE_UNKNOWN,
            };
            uint8_t next_hop[LORA_TRUNK_V3_NODE_ID_LEN] = {0};
            bool addressed = false;
            taskENTER_CRITICAL(&s_gov_mux);
            if (smoke_route_selected) {
                memcpy(
                    recipient, smoke_recipient,
                    sizeof(recipient));
                uint16_t capabilities = 0;
                addressed = trunk_route_locked(
                    recipient, now, 180000ULL, true,
                    next_hop, &capabilities);
                if (addressed &&
                    memcmp(
                        next_hop, smoke_next_hop,
                        sizeof(next_hop)) != 0) {
                    addressed = false;
                }
                if (addressed) {
                    smoke_policy = lora_link_adaptation_policy(
                        &s_link_adaptation, smoke_next_hop);
                }
            } else {
                const lora_trunk_neighbor_t *freshest = NULL;
                for (size_t i = 0;
                     i < LORA_TRUNK_NEIGHBOR_CAPACITY; ++i) {
                    const lora_trunk_neighbor_t *entry =
                        &s_neighbors.entries[i];
                    bool direct_candidate =
                        entry->identity_authenticated &&
                        entry->direct_identity;
#if CONFIG_BITLE_LORA_DIAGNOSTIC_QUIET
                    direct_candidate =
                        direct_candidate ||
                        !entry->identity_authenticated;
#endif
                    if (entry->in_use &&
                        direct_candidate &&
                        !entry->quarantined &&
                        now >= entry->last_seen_ms &&
                        now - entry->last_seen_ms <= 180000ULL &&
                        (!freshest ||
                         entry->last_seen_ms >
                             freshest->last_seen_ms)) {
                        freshest = entry;
                    }
                }
                if (freshest) {
                    const uint8_t *reachable =
                        freshest->identity_authenticated
                            ? freshest->reachable_peer
                            : freshest->node_id;
                    memcpy(recipient, reachable,
                           sizeof(recipient));
                    uint16_t capabilities = 0;
                    addressed = trunk_route_locked(
                        recipient, now, 180000ULL, true,
                        next_hop, &capabilities);
                    if (addressed &&
                        memcmp(
                            next_hop, freshest->node_id,
                            sizeof(next_hop)) != 0) {
                        addressed = false;
                    }
                    if (addressed) {
                        memcpy(
                            smoke_recipient, recipient,
                            sizeof(smoke_recipient));
                        memcpy(
                            smoke_next_hop, next_hop,
                            sizeof(smoke_next_hop));
                        smoke_route_selected = true;
                        smoke_policy =
                            lora_link_adaptation_policy(
                                &s_link_adaptation,
                                smoke_next_hop);
                    }
                }
            }
            taskEXIT_CRITICAL(&s_gov_mux);
            if (!addressed) {
                ESP_LOGI(TAG,
                         "diagnostic smoke waiting for authenticated neighbor");
                next_smoke_ms = now + 500ULL;
            } else {
                memset(probe, 0xA5, probe_len);
                probe[0] = 1;
                probe[1] = BITCHAT_MSG_MESSAGE;
                probe[2] = 0;
                memcpy(
                    probe + 3, DIAGNOSTIC_MARKER,
                    sizeof(DIAGNOSTIC_MARKER));
                probe[11] = 0x01;
                const uint16_t packet_header_len = 30;
                uint16_t payload_len = probe_len - packet_header_len;
                probe[12] = payload_len >> 8;
                probe[13] = payload_len & 0xFF;
                memcpy(probe + (probe[0] >= 2 ? 16 : 14),
                       noise_get_local_peer_id(), 8);
                memcpy(probe + 22, recipient, sizeof(recipient));
                probe[packet_header_len] = (uint8_t)smoke_index;
                bitle_link_send_result_t result =
                    lora_link_send(
                        BITLE_LORA_LINK_HANDLE, probe, probe_len);
                if (result == BITLE_LINK_SEND_ACCEPTED) {
                    lora_link_metrics_snapshot_t metrics;
                    uint16_t data_samples = 0;
                    taskENTER_CRITICAL(&s_gov_mux);
                    if (lora_link_adaptation_snapshot(
                            &s_link_adaptation, next_hop,
                            &metrics)) {
                        data_samples = metrics.data_samples;
                    }
                    taskEXIT_CRITICAL(&s_gov_mux);
                    memcpy(
                        smoke_next_hop, next_hop,
                        sizeof(smoke_next_hop));
                    smoke_expected_data_samples =
                        data_samples == UINT16_MAX
                            ? UINT16_MAX
                            : (uint16_t)(data_samples + 1u);
                    smoke_waiting_completion = true;
                    ESP_LOGI(
                        TAG,
                        "diagnostic smoke enqueue len=%u expected_frags=%u "
                        "addressed=1 chunk=%u rounds=%u link=%u",
                        probe_len,
                        (probe_len + smoke_policy.fragment_size - 1) /
                            smoke_policy.fragment_size,
                        smoke_policy.fragment_size,
                        smoke_policy.maximum_rounds,
                        (unsigned)smoke_policy.profile);
                    smoke_index++;
                } else {
                    ESP_LOGW(
                        TAG,
                        "diagnostic smoke deferred len=%u result=%u",
                        probe_len, result);
                }
                next_smoke_ms = now + 100ULL;
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
                     "invalid=%lu resource=%lu beacon=%lu/%lu stale=%lu "
                     "budget=%lu backoff=%lu announce_tx=%lu "
                     "forward=%lu suppress=%lu dup_net=%lu hop_drop=%lu "
                     "route_fail=%lu",
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
                     (unsigned long)diag.resource_aborts,
                     (unsigned long)diag.beacon_tx,
                     (unsigned long)diag.beacon_rx,
                     (unsigned long)diag.beacon_stale,
                     (unsigned long)diag.beacon_budget_deferred,
                     (unsigned long)diag.channel_backoffs,
                     (unsigned long)diag.announce_tx,
                     (unsigned long)diag.forwarded_packets,
                     (unsigned long)diag.forward_suppressed,
                     (unsigned long)diag.forward_duplicates,
                     (unsigned long)diag.hop_limit_drops,
                     (unsigned long)diag.route_failures);
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
                        if (pending_is_beacon) {
                            beacon_schedule_finish_attempt(
                                &beacon_schedule, &have_pending,
                                &pending_is_beacon,
                                esp_timer_get_time() / 1000ULL);
                        } else {
                            abort_tx_packet(
                                &packet_handle, &have_pending,
                                LORA_TRUNK_ABORT_RADIO_RESET);
                        }
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
                } else if (pending_is_beacon) {
                    diag_inc(&s_diag.beacon_tx);
                    ESP_LOGI(
                        TAG,
                        "trunk beacon TX freshness=%lu repeat=%u",
                        (unsigned long)beacon_schedule.freshness,
                        (unsigned)(
                            TRUNK_BEACON_REPETITIONS -
                            beacon_schedule.remaining + 1u));
                    beacon_schedule_finish_attempt(
                        &beacon_schedule, &have_pending,
                        &pending_is_beacon,
                        esp_timer_get_time() / 1000ULL);
                    cad_tries = 0;
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
                     ack_burst < LORA_CHANNEL_ACK_BURST_MAX)) {
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
                            taskENTER_CRITICAL(&s_gov_mux);
                            tx_trunk_context_t *context =
                                &s_tx_context[packet_handle];
                            if (context->valid &&
                                context->retry_count < UINT8_MAX) {
                                context->retry_count++;
                            }
                            taskEXIT_CRITICAL(&s_gov_mux);
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
                        if (pending_is_beacon) {
                            beacon_schedule_finish_attempt(
                                &beacon_schedule, &have_pending,
                                &pending_is_beacon,
                                esp_timer_get_time() / 1000ULL);
                        } else {
                            abort_tx_packet(
                                &packet_handle, &have_pending,
                                LORA_TRUNK_ABORT_RADIO_RESET);
                        }
                        recover_radio("data transmit command");
                    }
                }
                break;
            case SX1262_EVT_CAD_BUSY:
                awaiting_cad = false;
                if (have_pending && cad_tries < UINT8_MAX) {
                    cad_tries++;
                }
                if (have_pending &&
                    (pending.want_ack || cad_tries <= CAD_RETRIES)) {
                    /* An addressed transfer owns a bounded absolute deadline;
                     * temporary channel occupancy must not discard it after a
                     * small fixed number of CAD results. Return to RX during
                     * backoff so packet feedback remains observable, then
                     * retry until COMPLETE, ABORT, or the transfer deadline. */
                    if (schedule_contention_backoff(
                            &pending, (uint8_t)cad_tries,
                            pending_relayed_broadcast,
                            &backoff_deadline)) {
                        awaiting_backoff = true;
                    } else {
                        if (pending_is_beacon) {
                            beacon_schedule_finish_attempt(
                                &beacon_schedule, &have_pending,
                                &pending_is_beacon,
                                esp_timer_get_time() / 1000ULL);
                        } else {
                            abort_tx_packet(
                                &packet_handle, &have_pending,
                                LORA_TRUNK_ABORT_RADIO_RESET);
                        }
                    }
                } else {
                    /* Channel persistently busy: reject the complete packet;
                     * sending only its earlier fragments cannot complete. */
                    if (have_pending) {
                        if (pending_is_beacon) {
                            beacon_schedule_finish_attempt(
                                &beacon_schedule, &have_pending,
                                &pending_is_beacon,
                                esp_timer_get_time() / 1000ULL);
                        } else {
                            abort_tx_packet(
                                &packet_handle, &have_pending,
                                LORA_TRUNK_ABORT_RESOURCE_PRESSURE);
                        }
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
                awaiting_backoff = false;
                if (!resume_rx_or_recover("radio TX timeout")) {
                    if (have_pending) {
                        if (pending_is_beacon) {
                            beacon_schedule_finish_attempt(
                                &beacon_schedule, &have_pending,
                                &pending_is_beacon,
                                esp_timer_get_time() / 1000ULL);
                        } else {
                            abort_tx_packet(
                                &packet_handle, &have_pending,
                                LORA_TRUNK_ABORT_RADIO_RESET);
                        }
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
                } else if (!timed_out_ack && pending_is_beacon) {
                    beacon_schedule_finish_attempt(
                        &beacon_schedule, &have_pending,
                        &pending_is_beacon,
                        esp_timer_get_time() / 1000ULL);
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
                awaiting_backoff = false;
                awaiting_ack = false;
                tx_is_ack = false;
                tx_watchdog_deadline = 0;
                if (have_pending) {
                    if (pending_is_beacon) {
                        beacon_schedule_finish_attempt(
                            &beacon_schedule, &have_pending,
                            &pending_is_beacon,
                            esp_timer_get_time() / 1000ULL);
                    } else {
                        abort_tx_packet(
                            &packet_handle, &have_pending,
                            LORA_TRUNK_ABORT_RADIO_RESET);
                    }
                }
                recover_radio("IRQ status command");
                break;
            default:
                break;
            }
        }

        if (have_pending && !pending_is_beacon &&
            packet_handle != LORA_TX_HANDLE_INVALID &&
            s_tx_context[packet_handle].suppressed &&
            !awaiting_tx_done && !awaiting_cad) {
            awaiting_backoff = false;
            awaiting_ack = false;
            drop_tx_packet(&packet_handle, &have_pending);
            ESP_LOGI(TAG, "suppressed pending duplicate rebroadcast");
        }

        /* Acks fly the moment the radio is free — no CAD, no queueing: the
         * peer is listening right after its TX and is waiting on us. */
        bool data_waiting = have_pending || tx_scheduler_has_queued();
        if (s_ack_count > 0 && !awaiting_tx_done && !awaiting_cad &&
            (!data_waiting ||
             ack_burst < LORA_CHANNEL_ACK_BURST_MAX)) {
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
            awaiting_backoff = false;
            awaiting_ack = false;
            tx_is_ack = false;
            tx_watchdog_deadline = 0;
            if (have_pending) {
                if (pending_is_beacon) {
                    beacon_schedule_finish_attempt(
                        &beacon_schedule, &have_pending,
                        &pending_is_beacon, watchdog_now);
                } else {
                    abort_tx_packet(
                        &packet_handle, &have_pending,
                        LORA_TRUNK_ABORT_RADIO_RESET);
                }
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
            awaiting_backoff = false;
            s_feedback_seen = false;
            if (s_selective_tx.complete) {
                complete_tx_packet(&packet_handle, &have_pending);
            } else {
                drop_tx_packet(&packet_handle, &have_pending);
            }
        } else if (awaiting_ack && have_pending) {
            uint64_t now2 = esp_timer_get_time() / 1000ULL;
            if (now2 >= ack_deadline) {
                if (!s_feedback_seen) {
                    diag_inc(&s_diag.ack_misses);
                    taskENTER_CRITICAL(&s_gov_mux);
                    const tx_trunk_context_t *context =
                        &s_tx_context[packet_handle];
                    if (context->valid &&
                        context->ack_requested) {
                        lora_link_adaptation_note_ack(
                            &s_link_adaptation,
                            context->destination, false, now2);
                    }
                    taskEXIT_CRITICAL(&s_gov_mux);
                }
                s_feedback_seen = false;
                awaiting_ack = false;
                if (lora_selective_tx_next_round(
                        &s_selective_tx,
                        s_tx_context[packet_handle]
                            .maximum_rounds) &&
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
            awaiting_backoff = false;
            abort_tx_packet(
                &packet_handle, &have_pending,
                LORA_TRUNK_ABORT_RETRY_EXHAUSTED);
        }

        /* Backoff is a task deadline, not a blocking delay: the radio remains
         * in continuous RX and controls may preempt while the deadline runs.
         * CAD is rechecked immediately before every actual transmission. */
        uint64_t channel_now = esp_timer_get_time() / 1000ULL;
        if (awaiting_backoff && channel_now >= backoff_deadline &&
            !awaiting_tx_done && !awaiting_cad && !awaiting_ack) {
            awaiting_backoff = false;
            if (sx1262_start_cad() == ESP_OK) {
                awaiting_cad = true;
            } else {
                if (pending_is_beacon) {
                    beacon_schedule_finish_attempt(
                        &beacon_schedule, &have_pending,
                        &pending_is_beacon, channel_now);
                } else if (have_pending) {
                    abort_tx_packet(
                        &packet_handle, &have_pending,
                        LORA_TRUNK_ABORT_RADIO_RESET);
                }
                recover_radio("post-backoff CAD command");
            }
        }

        if (!have_pending && !awaiting_tx_done && !awaiting_cad &&
            !awaiting_backoff && !awaiting_ack) {
            if (beacon_schedule.remaining > 0 &&
                channel_now >= beacon_schedule.next_repeat_ms) {
                if (build_beacon_frame(
                        beacon_schedule.freshness, &pending) &&
                    beacon_budget_admit(pending.len)) {
                    packet_handle = LORA_TX_HANDLE_INVALID;
                    fragment_idx = 0;
                    fragment_total = 1;
                    have_pending = true;
                    pending_is_beacon = true;
                    pending_relayed_broadcast = false;
                    pending_forward_not_before_ms = 0;
                    s_expected_control_valid = false;
                } else {
                    beacon_schedule.next_repeat_ms =
                        channel_now + BEACON_REPEAT_MIN_MS +
                        (esp_random() % BEACON_REPEAT_SPAN_MS);
                }
            }

            if (!have_pending &&
                tx_scheduler_dequeue(&packet_handle)) {
                fragment_idx = 0;
                pending_is_beacon = false;
                if (s_tx_context[packet_handle].suppressed) {
                    drop_tx_packet(
                        &packet_handle, &have_pending);
                    continue;
                }
                taskENTER_CRITICAL(&s_gov_mux);
                s_tx_context[packet_handle].started_ms =
                    channel_now;
                taskEXIT_CRITICAL(&s_gov_mux);
                pending_relayed_broadcast =
                    s_tx_context[packet_handle].relayed_broadcast;
                pending_forward_not_before_ms =
                    s_tx_context[packet_handle]
                        .forward_not_before_ms;
                have_pending = build_tx_fragment(
                    packet_handle, fragment_idx, &pending,
                    &fragment_total);
                if (!have_pending) {
                    drop_tx_packet(
                        &packet_handle, &have_pending);
                    continue;
                }
                if (pending.want_ack &&
                    (!lora_selective_tx_init(
                         &s_selective_tx, fragment_total) ||
                     !trunk_reliability_timing(
                         fragment_total,
                         s_tx_context[packet_handle]
                             .fragment_size,
                         s_tx_context[packet_handle]
                             .maximum_rounds,
                         &transfer_timing))) {
                    abort_tx_packet(
                        &packet_handle, &have_pending,
                        LORA_TRUNK_ABORT_INVALID_LENGTH);
                    continue;
                }
                cad_tries = 0;
                s_feedback_seen = false;
                transfer_deadline =
                    pending.want_ack
                        ? channel_now +
                              transfer_timing.absolute_timeout_ms
                        : 0;
            }
        }

        /* A newly selected fragment, a selective-repeat round, or a frame
         * whose CAD was preempted by control traffic all enter a fresh
         * airtime-scaled contention window. */
        if (have_pending && !awaiting_tx_done && !awaiting_cad &&
            !awaiting_backoff && !awaiting_ack) {
            cad_tries = 0;
            if (schedule_contention_backoff(
                    &pending, 0, pending_relayed_broadcast,
                    &backoff_deadline)) {
                if (pending_forward_not_before_ms >
                    backoff_deadline) {
                    backoff_deadline =
                        pending_forward_not_before_ms;
                }
                awaiting_backoff = true;
            } else {
                if (pending_is_beacon) {
                    beacon_schedule_finish_attempt(
                        &beacon_schedule, &have_pending,
                        &pending_is_beacon, channel_now);
                } else {
                    abort_tx_packet(
                        &packet_handle, &have_pending,
                        LORA_TRUNK_ABORT_RADIO_RESET);
                }
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
    memset(s_throttle, 0, sizeof(s_throttle));
    diag_sync_scheduler_locked();
    taskEXIT_CRITICAL(&s_gov_mux);
    memset(s_rx_slots, 0, sizeof(s_rx_slots));
    memset(s_completed_slots, 0, sizeof(s_completed_slots));
    memset(&s_selective_tx, 0, sizeof(s_selective_tx));
    lora_forward_cache_init(&s_forward_cache);
    lora_link_adaptation_init(&s_link_adaptation);
    memset(&s_relay_ingress, 0, sizeof(s_relay_ingress));
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
        .cr = LORA_CODING_RATE,
        .preamble_symbols = LORA_PREAMBLE_SYMBOLS,
        .tx_dbm = 22,
        .region = LORA_DEFAULT_REGION,
    };
    const sx1262_config_t build_default_cfg = cfg;

    /* NVS overrides (namespace "lora"): u8 region, u32 freq, u8 sf,
     * u8 enabled, u8 duty_pct (1..50, default 25), and u8 ota_trunk.
     * A region/frequency mismatch is rejected as a pair. Legacy stores with
     * only a frequency infer their regional profile from that frequency. */
    uint8_t duty_pct = 25;
    bool persisted_profile_rejected = false;
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
            persisted_profile_rejected = true;
            diag_inc(&s_diag.config_rejections);
            ESP_LOGE(TAG, "rejected malformed NVS LoRa region/frequency value");
        } else if (region_status == ESP_OK && freq_status == ESP_OK) {
            if (stored_region < LORA_REGION_COUNT &&
                lora_region_frequency_valid((lora_region_id_t)stored_region, freq)) {
                cfg.region = (lora_region_id_t)stored_region;
                cfg.freq_hz = freq;
            } else {
                persisted_profile_rejected = true;
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
                persisted_profile_rejected = true;
                diag_inc(&s_diag.config_rejections);
                ESP_LOGE(TAG, "rejected invalid NVS LoRa region");
            }
        } else if (freq_status == ESP_OK) {
            lora_region_id_t inferred;
            if (lora_region_infer(freq, &inferred)) {
                cfg.region = inferred;
                cfg.freq_hz = freq;
            } else {
                persisted_profile_rejected = true;
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
                persisted_profile_rejected = true;
                diag_inc(&s_diag.config_rejections);
                ESP_LOGE(TAG, "rejected invalid NVS spreading factor");
            }
        } else if (sf_status != ESP_ERR_NVS_NOT_FOUND) {
            persisted_profile_rejected = true;
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
    if (persisted_profile_rejected) {
        cfg = build_default_cfg;
        ESP_LOGE(
            TAG,
            "discarded persisted LoRa profile; restoring build defaults");
    }

    lora_phy_profile_t selected_profile = {
        .region = cfg.region,
        .frequency_hz = cfg.freq_hz,
        .spreading_factor = cfg.sf,
        .bandwidth_hz = cfg.bw_hz,
        .coding_rate = cfg.cr,
        .preamble_symbols = cfg.preamble_symbols,
        .sync_word = LORA_PRIVATE_SYNC_WORD,
        .tx_dbm = cfg.tx_dbm,
    };
    if (!lora_phy_profile_valid(&selected_profile)) {
        diag_inc(&s_diag.config_rejections);
        ESP_LOGE(
            TAG,
            "rejected incompatible LoRa profile; restoring build defaults");
        cfg = build_default_cfg;
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
    memset(s_throttle, 0, sizeof(s_throttle));
    memset(s_rx_slots, 0, sizeof(s_rx_slots));
    memset(s_completed_slots, 0, sizeof(s_completed_slots));
    lora_trunk_neighbor_table_init(&s_neighbors);
    lora_forward_cache_init(&s_forward_cache);
    lora_link_adaptation_init(&s_link_adaptation);
    memset(&s_relay_ingress, 0, sizeof(s_relay_ingress));
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
    s_region = cfg.region;
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
    err = bitle_link_register_reservable_relay(
        BITLE_LORA_LINK_HANDLE, BITLE_LINK_LORA, lora_link_send,
        lora_link_relay_send, lora_link_reserve, lora_link_commit,
        lora_link_cancel);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "trunk link registration failed: %s",
                 esp_err_to_name(err));
        bitle_lora_shutdown();
        return err;
    }
    const lora_region_profile_t *active_profile = lora_region_profile(cfg.region);
    ESP_LOGI(TAG,
             "trunk up: board=%s region=%s %.3f MHz SF%u BW%lu "
             "CR4/%u preamble=%u sync=0x%04x +%ddBm "
             "duty=%u%% ota_trunk=%d phy_verified=1",
             LORA_BOARD_NAME,
             active_profile->name, cfg.freq_hz / 1e6, cfg.sf,
             (unsigned long)cfg.bw_hz, cfg.cr,
             cfg.preamble_symbols, LORA_PRIVATE_SYNC_WORD, cfg.tx_dbm,
             duty_pct, s_ota_over_trunk);
    return ESP_OK;
}
