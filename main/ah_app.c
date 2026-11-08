// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The mesh task's event loop, the ops table the core reaches the device
// through, and the status snapshot it publishes.
#include "ah_app.h"

#include <assert.h>
#include <string.h>

#include "esp_check.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_pm.h"
#include "esp_system.h"
#include "esp_task_wdt.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "sdkconfig.h"

#include "ah_ble.h"
#include "ah_clock.h"
#include "ah_display.h"
#include "ah_mailbox.h"
#include "ah_ota.h"
#include "ah_relay.h"

static const char *TAG = "ah_app";

typedef enum {
    EV_LINK_UP,
    EV_LINK_DOWN,
    EV_MTU,
    EV_READY,
    EV_FRAME,
} event_kind_t;

typedef struct {
    uint8_t kind;
    uint8_t link_kind;
    uint16_t len;
    uint32_t handle;
    uint16_t max_write;
    uint8_t data[AH_FRAME_BUF_MAX];
} event_t;

// A BLE write without response has no completion event: a link the host
// refused is polled until it takes writes again. LoRa reports `ready` itself.
#define BUSY_POLL_MS 10
#define SNAPSHOT_MS 1000
#define STATS_LOG_MS (10LL * 60 * 1000)
#define MAX_WAIT_MS 100
// The longest the loop handles events before its timers run and it feeds the
// task watchdog, however fast they keep arriving: a pass then takes this plus
// one event and one tick (docs/ARCHITECTURE.md has the worst case, and
// `status` the longest pass seen).
#define DRAIN_MS 250
// The mesh task outranks the idle task on its core, which the task watchdog
// also watches (ESP_TASK_WDT_CHECK_IDLE_TASK_CPUn) and which a queue that never
// empties would starve: the task sleeps one tick this often, a 1 % cost.
#define IDLE_YIELD_MS 1000
// Tables at least this large go to PSRAM where the board has it.
#define PSRAM_THRESHOLD 4096u
// A Bluetooth link that has never bound and has carried no frame for this
// long is dropped, so a client that connects and idles cannot hold a slot for
// good. Silence, not the missing binding, is the test: a node whose clock is
// unsynced never announces, so its links never bind, yet it relays.
#define UNBOUND_SILENCE_MS 45000
// Queue slots a frame never takes, so a link coming, going or becoming ready
// is never lost to a flood of frames. More of those than this during a stall
// can still be lost; reconcile_ble and reconcile_lora repair a link one left wrong.
#define CONTROL_RESERVE 4u
// How long a control event may wait for a slot. Bounded, so a poster that the
// mesh task itself is waiting on never deadlocks it.
#define CONTROL_WAIT_MS 50

static QueueHandle_t s_queue;
static ah_node_t *s_node;
static ah_screen_lora_t s_lora;
// Posted to from several tasks: updated atomically.
static uint32_t s_dropped;
static bool s_busy[CONFIG_AH_LINKS];
// LoRa links the trunk has been told are bound, so it is told once.
static bool s_lora_bound[CONFIG_AH_LINKS];
// Per link: bound at least once (never dropped as silent after that), and
// when a frame last arrived on it (its opening counts).
static bool s_ever_bound[CONFIG_AH_LINKS];
static int64_t s_heard_ms[CONFIG_AH_LINKS];
static portMUX_TYPE s_status_mux = portMUX_INITIALIZER_UNLOCKED;
static ah_app_status_t s_status;
// The longest gap between two watchdog feeds since boot, on the mesh task only.
static int64_t s_longest_pass_ms;
// Held while the mesh task works and released before it blocks, so the CPU
// runs at full speed for relaying and signature checks and drops to the
// frequency scaler's floor between them.
static esp_pm_lock_handle_t s_cpu_lock;

static int64_t now_ms(void)
{
    return esp_timer_get_time() / 1000;
}

static void post(const event_t *ev)
{
    // A LoRa frame was acknowledged to its sender, which will not send it
    // again, so it waits for a slot and may take the reserve as a control
    // event does. A few a minute at most never crowd those out.
    const bool bluetooth_frame = ev->kind == EV_FRAME && ev->link_kind == AH_LINK_BLE;
    const TickType_t wait = bluetooth_frame ? 0 : pdMS_TO_TICKS(CONTROL_WAIT_MS);
    if (s_queue == NULL || (bluetooth_frame && uxQueueSpacesAvailable(s_queue) <= CONTROL_RESERVE) ||
            xQueueSend(s_queue, ev, wait) != pdTRUE) {
        __atomic_fetch_add(&s_dropped, 1u, __ATOMIC_RELAXED);
    }
}

void ah_app_post_link_up(ah_link_kind_t kind, uint32_t handle, uint16_t max_write, const uint8_t *node)
{
    event_t ev = {.kind = EV_LINK_UP, .link_kind = (uint8_t)kind, .handle = handle, .max_write = max_write};
    if (node != NULL) {
        memcpy(ev.data, node, AH_TRUNK_NODE_LEN);
        ev.len = AH_TRUNK_NODE_LEN;
    }
    post(&ev);
}

void ah_app_post_link_down(ah_link_kind_t kind, uint32_t handle)
{
    const event_t ev = {.kind = EV_LINK_DOWN, .link_kind = (uint8_t)kind, .handle = handle};
    post(&ev);
}

void ah_app_post_mtu(ah_link_kind_t kind, uint32_t handle, uint16_t max_write)
{
    const event_t ev = {.kind = EV_MTU, .link_kind = (uint8_t)kind, .handle = handle, .max_write = max_write};
    post(&ev);
}

void ah_app_post_ready(ah_link_kind_t kind, uint32_t handle)
{
    const event_t ev = {.kind = EV_READY, .link_kind = (uint8_t)kind, .handle = handle};
    post(&ev);
}

void ah_app_post_frame(ah_link_kind_t kind, uint32_t handle, const uint8_t *data, size_t len)
{
    if (len == 0 || len > AH_FRAME_BUF_MAX) {
        return;
    }
    // On the caller's stack: the BLE host task and the LoRa task post at
    // once, and the queue copies the event before this returns.
    event_t ev = {.kind = EV_FRAME, .link_kind = (uint8_t)kind, .handle = handle, .len = (uint16_t)len};
    memcpy(ev.data, data, len);
    post(&ev);
}

void ah_app_status(ah_app_status_t *out)
{
    taskENTER_CRITICAL(&s_status_mux);
    *out = s_status;
    taskEXIT_CRITICAL(&s_status_mux);
}

// The node's operations (ah_node_ops_t), all called on the mesh task.

static ah_write_t node_write(void *ctx, ah_link_kind_t kind, uint32_t handle, const uint8_t *frame, size_t len,
                             uint8_t prio)
{
    (void)ctx;
    if (kind == AH_LINK_LORA) {
        switch (ah_lora_send(handle, frame, len, prio)) {
        case AH_LORA_SEND_OK:
            return AH_WRITE_OK;
        case AH_LORA_SEND_BUSY:
            return AH_WRITE_BUSY;
        default:
            return AH_WRITE_GONE;
        }
    }
    switch (ah_ble_write(handle, frame, len)) {
    case AH_BLE_WRITE_OK:
        return AH_WRITE_OK;
    case AH_BLE_WRITE_UNSUBSCRIBED:
        // Not polled: the subscription posts `ready`.
        return AH_WRITE_BUSY;
    case AH_BLE_WRITE_BUSY: {
        const uint16_t link = ah_node_link_by_handle(s_node, kind, handle);
        if (link < CONFIG_AH_LINKS) {
            s_busy[link] = true;
        }
        return AH_WRITE_BUSY;
    }
    default:
        return AH_WRITE_GONE;
    }
}

static void node_mail_put(void *ctx, uint32_t record, uint64_t depositor, const uint8_t *env, size_t len)
{
    (void)ctx;
    ah_mailbox_put(record, depositor, env, len);
}

static void node_mail_delete(void *ctx, uint32_t record)
{
    (void)ctx;
    ah_mailbox_delete(record);
}

static void node_clock_save(void *ctx, uint64_t wall_ms)
{
    (void)ctx;
    ah_settings_save_clock(wall_ms);
}

static void *node_alloc(void *ctx, size_t bytes)
{
    (void)ctx;
    void *p = NULL;
    if (bytes >= PSRAM_THRESHOLD) {
        p = heap_caps_calloc(1, bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    }
    return p != NULL ? p : heap_caps_calloc(1, bytes, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
}

// One depositor's share of the hourly flash budget holds its largest envelope.
static_assert((uint64_t)CONFIG_AH_MAIL_FLASH_KIB_PER_HOUR * 1024u * CONFIG_AH_MAIL_PER_DEPOSITOR / CONFIG_AH_MAIL_SLOTS >=
              CONFIG_AH_BIG_SEND_KIB * 1024u + AH_MAIL_RECORD_OVERHEAD,
              "AH_MAIL_FLASH_KIB_PER_HOUR is too small for AH_MAIL_PER_DEPOSITOR over AH_MAIL_SLOTS");

static ah_node_config_t config_from_kconfig(void)
{
    return (ah_node_config_t) {
        .links = CONFIG_AH_LINKS,
        .queue_per_link = CONFIG_AH_QUEUE_PER_LINK,
        .frame_buffers = CONFIG_AH_FRAME_BUFFERS,
        .peers = CONFIG_AH_PEERS,
        .peer_pins = CONFIG_AH_PEER_PINS,
        .dedup_message_slots = CONFIG_AH_DEDUP_MESSAGE_SLOTS,
        .dedup_fragment_slots = CONFIG_AH_DEDUP_FRAGMENT_SLOTS,
        .dedup_live_slots = CONFIG_AH_DEDUP_LIVE_SLOTS,
        .sync = {
            .entries = {
                CONFIG_AH_SYNC_ANNOUNCES, CONFIG_AH_SYNC_MESSAGES, CONFIG_AH_SYNC_GROUPS,
                CONFIG_AH_SYNC_BOARD
            },
            .bytes = {
                CONFIG_AH_SYNC_ANNOUNCE_KIB * 1024u, CONFIG_AH_SYNC_MESSAGE_KIB * 1024u,
                CONFIG_AH_SYNC_GROUP_KIB * 1024u, CONFIG_AH_SYNC_BOARD_KIB * 1024u
            },
            .declined = CONFIG_AH_SYNC_DECLINED,
        },
        .mail_slots = CONFIG_AH_MAIL_SLOTS,
        .mail_bytes = CONFIG_AH_MAIL_KIB * 1024u,
        .mail_per_depositor = CONFIG_AH_MAIL_PER_DEPOSITOR,
        .mail_flash_bytes_per_hour = CONFIG_AH_MAIL_FLASH_KIB_PER_HOUR * 1024u,
        .reassembly_slots = CONFIG_AH_REASSEMBLY_SLOTS,
        .reassembly_bytes = CONFIG_AH_BIG_SEND_KIB * 1024u,
        .relay_slots = CONFIG_AH_RELAY_SLOTS,
        .reply_backlog = CONFIG_AH_SYNC_REPLY_BACKLOG,
        .verify_per_second = CONFIG_AH_VERIFY_PER_SECOND,
        .inflate_bytes_per_second = CONFIG_AH_INFLATE_KIB_PER_SECOND * 1024u,
        .inflate_window = CONFIG_AH_INFLATE_WINDOW_KIB * 1024u,
        .trunk_announce_interval_ms = CONFIG_AH_TRUNK_ANNOUNCE_INTERVAL_S * 1000u,
        .big_send_bytes = CONFIG_AH_BIG_SEND_KIB * 1024u,
        .sessions = CONFIG_AH_SESSIONS,
    };
}

// A LoRa link the mesh has just bound: the trunk then keeps that neighbor
// over unverified ones when its table fills.
static void note_lora_binding(uint16_t link)
{
    ah_node_link_info_t info;
    if (link < CONFIG_AH_LINKS && !s_lora_bound[link] && ah_node_link_info(s_node, link, &info) &&
            info.kind == AH_LINK_LORA && info.peer_id != NULL) {
        s_lora_bound[link] = ah_lora_set_bound(info.handle);
    }
}

// `node`, for a LoRa link, is the node the trunk authenticated it to: only
// that node's own announce may bind it.
static void open_link(ah_link_kind_t kind, uint32_t handle, uint16_t max_write, const uint8_t *node, int64_t now)
{
    const uint16_t opened = ah_node_link_up(s_node, kind, handle, max_write, node, now);
    if (opened < CONFIG_AH_LINKS) {
        // The core may have closed this slot's last link itself (a write that
        // found it gone), so nothing here is inherited from it.
        s_ever_bound[opened] = false;
        s_busy[opened] = false;
        s_lora_bound[opened] = false;
        s_heard_ms[opened] = now;
    } else if (opened == AH_LINK_NONE && kind == AH_LINK_BLE) {
        ah_ble_drop(handle);
    }
}

static void close_link(uint16_t link)
{
    ah_node_link_down(s_node, link);
    if (link < CONFIG_AH_LINKS) {
        s_busy[link] = false;
        s_lora_bound[link] = false;
    }
}

static void handle_event(const event_t *ev, int64_t now)
{
    const ah_link_kind_t kind = (ah_link_kind_t)ev->link_kind;
    const uint16_t link = ah_node_link_by_handle(s_node, kind, ev->handle);
    switch (ev->kind) {
    case EV_LINK_UP:
        if (link == AH_LINK_NONE) {
            open_link(kind, ev->handle, ev->max_write, ev->len == AH_TRUNK_NODE_LEN ? ev->data : NULL, now);
        }
        break;
    case EV_LINK_DOWN:
        if (link != AH_LINK_NONE) {
            close_link(link);
        }
        break;
    case EV_MTU:
        if (link != AH_LINK_NONE) {
            ah_node_link_mtu(s_node, link, ev->max_write);
        }
        break;
    case EV_READY:
        if (link != AH_LINK_NONE) {
            if (link < CONFIG_AH_LINKS) {
                s_busy[link] = false;
            }
            ah_node_link_ready(s_node, link, now);
        }
        break;
    case EV_FRAME:
        if (link == AH_LINK_NONE) {
            break;
        }
        if (link < CONFIG_AH_LINKS) {
            s_heard_ms[link] = now;
        }
        // OTA is node to node over one link and never enters the mesh.
        if (ev->len > 1 && ah_is_ota(ev->data[1])) {
            ah_ota_on_frame(s_node, link, ev->data, ev->len, now);
            break;
        }
        ah_node_on_frame(s_node, link, ev->data, ev->len, now);
        if (kind == AH_LINK_LORA) {
            note_lora_binding(link);
        }
#if CONFIG_AH_BLE_CODED_PHY
        ah_node_link_info_t info;
        if (kind == AH_LINK_BLE && ah_node_link_info(s_node, link, &info) && info.peer_is_node) {
            ah_ble_prefer_coded_phy(ev->handle);
        }
#endif
        break;
    default:
        break;
    }
}

static void publish(int64_t now)
{
    ah_app_status_t st = {
        .node = *ah_node_stats(s_node),
        .dropped_events = __atomic_load_n(&s_dropped, __ATOMIC_RELAXED),
        .uptime_ms = now,
        .longest_pass_ms = (uint32_t)s_longest_pass_ms,
    };
    if (s_lora == AH_SCREEN_LORA_UP) {
        ah_lora_status(&st.lora);
    }
    taskENTER_CRITICAL(&s_status_mux);
    s_status = st;
    taskEXIT_CRITICAL(&s_status_mux);

    ah_screen_model_t m = {
        .links = st.node.links_open,
        .bound = st.node.links_bound,
        .peers = st.node.peers_known,
        .received = st.node.rx,
        .relayed = st.node.relayed,
        .clock_synced = st.node.clock_state == AH_CLOCK_SYNCED,
        .lora = s_lora,
        .lora_neighbors = st.lora.neighbors,
        .airtime_per_mille =
        st.lora.budget_ms > 0 ? (uint16_t)((uint64_t)st.lora.airtime_ms * 1000u / st.lora.budget_ms) : 0,
    };
    ah_display_update(&m);
}

// See UNBOUND_SILENCE_MS.
static void drop_silent_unbound(int64_t now)
{
    for (uint16_t i = 0; i < CONFIG_AH_LINKS; ++i) {
        ah_node_link_info_t info;
        if (s_ever_bound[i] || !ah_node_link_info(s_node, i, &info) || info.kind != AH_LINK_BLE) {
            continue;
        }
        if (info.peer_id != NULL) {
            s_ever_bound[i] = true;
        } else if (now - s_heard_ms[i] >= UNBOUND_SILENCE_MS) {
            ah_ble_drop_unbound(info.handle);
            // Asked once a window: the link's down event follows.
            s_heard_ms[i] = now;
        }
    }
}

// A control event lost to a full queue (CONTROL_WAIT_MS passed during a stall)
// would strand a connection: one whose link never opened has its frames
// dropped and is never timed out, and one whose subscription went unheard is
// never written to again. Once a second the Bluetooth links are set right
// from the transport's own table. Each step is one an event would have taken,
// so an event still queued finds its work done and changes nothing.
static void reconcile_ble(int64_t now)
{
    ah_ble_conn_t conns[CONFIG_BT_NIMBLE_MAX_CONNECTIONS];
    const size_t n = ah_ble_connections(conns, CONFIG_BT_NIMBLE_MAX_CONNECTIONS);
    for (size_t i = 0; i < n; ++i) {
        if (!conns[i].open) {
            continue;
        }
        const uint16_t link = ah_node_link_by_handle(s_node, AH_LINK_BLE, conns[i].handle);
        if (link == AH_LINK_NONE) {
            open_link(AH_LINK_BLE, conns[i].handle, conns[i].max_write, NULL, now);
            continue;
        }
        ah_node_link_mtu(s_node, link, conns[i].max_write);
        if (conns[i].writable) {
            ah_node_link_ready(s_node, link, now);
        }
    }
    for (uint16_t link = 0; link < CONFIG_AH_LINKS; ++link) {
        ah_node_link_info_t info;
        if (!ah_node_link_info(s_node, link, &info) || info.kind != AH_LINK_BLE) {
            continue;
        }
        bool live = false;
        for (size_t i = 0; i < n && !live; ++i) {
            live = conns[i].handle == info.handle;
        }
        if (!live) {
            close_link(link);
        }
    }
}

// The same for LoRa links, from the trunk's neighbor table: a lost `ready`
// would leave a link busy for good (the trunk posts it once), a lost link_up
// a neighbor whose packets reach no link, a lost link_down a link to nobody.
static void reconcile_lora(int64_t now)
{
    ah_lora_link_t live[AH_TRUNK_NEIGHBORS];
    size_t n = 0;
    if (!ah_lora_links(live, &n)) {
        return;
    }
    for (size_t i = 0; i < n; ++i) {
        const uint16_t link = ah_node_link_by_handle(s_node, AH_LINK_LORA, live[i].handle);
        if (link == AH_LINK_NONE) {
            open_link(AH_LINK_LORA, live[i].handle, AH_TRUNK_PACKET_MAX, live[i].node, now);
        } else if (live[i].room) {
            ah_node_link_ready(s_node, link, now);
        }
    }
    for (uint16_t link = 0; link < CONFIG_AH_LINKS; ++link) {
        ah_node_link_info_t info;
        if (!ah_node_link_info(s_node, link, &info) || info.kind != AH_LINK_LORA) {
            continue;
        }
        bool found = false;
        for (size_t i = 0; i < n && !found; ++i) {
            found = live[i].handle == info.handle;
        }
        if (!found) {
            close_link(link);
        } else {
            // A binding the trunk did not hear of (its lock was busy) is told again.
            note_lora_binding(link);
        }
    }
}

static void hold_full_speed(bool hold)
{
    if (hold) {
        esp_pm_lock_acquire(s_cpu_lock);
    } else {
        esp_pm_lock_release(s_cpu_lock);
    }
}

static void log_stats(void)
{
    ah_app_status_t st;
    ah_app_status(&st);
    const ah_node_stats_t *s = &st.node;
    ESP_LOGI(TAG,
             "links=%u/%u peers=%u rx=%lu dup=%lu bad=%lu refused=%lu relayed=%lu tx=%lu txdrop=%lu sync=%lu/%lu "
             "mail=%lu/%lu clock=%u heap=%lu min=%lu events_dropped=%lu",
             s->links_bound, s->links_open, s->peers_known, (unsigned long)s->rx, (unsigned long)s->rx_duplicate,
             (unsigned long)s->rx_malformed, (unsigned long)s->rx_refused, (unsigned long)s->relayed,
             (unsigned long)s->tx, (unsigned long)s->tx_dropped, (unsigned long)s->sync_stored,
             (unsigned long)s->sync_served, (unsigned long)s->mail_stored, (unsigned long)s->mail_delivered,
             s->clock_state, (unsigned long)esp_get_free_heap_size(), (unsigned long)esp_get_minimum_free_heap_size(),
             (unsigned long)st.dropped_events);
    if (st.lora.budget_ms > 0) {
        const ah_lora_status_t *l = &st.lora;
        ESP_LOGI(TAG,
                 "lora neighbors=%u air=%lu/%lu ms tx=%lu rx=%lu bad=%lu unknown=%lu ok=%lu failed=%lu "
                 "deferred=%lu cad=%lu/%lu yields=%lu holds=%lu",
                 l->neighbors, (unsigned long)l->airtime_ms, (unsigned long)l->budget_ms,
                 (unsigned long)l->trunk.frames_tx, (unsigned long)l->trunk.frames_rx,
                 (unsigned long)l->trunk.frames_bad, (unsigned long)l->trunk.frames_unknown,
                 (unsigned long)l->trunk.transfers_ok, (unsigned long)l->trunk.transfers_failed,
                 (unsigned long)l->trunk.duty_deferred, (unsigned long)l->cad_busy, (unsigned long)l->cad_forced,
                 (unsigned long)l->rx_yields, (unsigned long)l->trunk.holds);
    }
}

static void mesh_task(void *arg)
{
    (void)arg;
    ESP_ERROR_CHECK(esp_task_wdt_add(NULL));
    static event_t ev;
    int64_t next_tick = 0;
    int64_t next_busy_poll = 0;
    int64_t next_snapshot = 0;
    int64_t next_stats = now_ms() + 60000;
    int64_t next_yield = now_ms() + IDLE_YIELD_MS;
    int64_t fed_ms = now_ms();
    bool any_busy = false;
    for (;;) {
        int64_t wait = next_tick - now_ms();
        const int64_t most = any_busy ? BUSY_POLL_MS : MAX_WAIT_MS;
        wait = wait < 0 ? 0 : wait > most ? most : wait;
        // Round up, so a wait shorter than a tick sleeps one rather than spinning.
        const TickType_t ticks = (TickType_t)((wait + portTICK_PERIOD_MS - 1) / portTICK_PERIOD_MS);
        const bool got = xQueueReceive(s_queue, &ev, ticks) == pdTRUE;
        hold_full_speed(true);
        if (got) {
            const int64_t drain_until = now_ms() + DRAIN_MS;
            handle_event(&ev, now_ms());
            // Drain what is already waiting before the timers run, for DRAIN_MS at most.
            while (now_ms() < drain_until && xQueueReceive(s_queue, &ev, 0) == pdTRUE) {
                handle_event(&ev, now_ms());
            }
            // An event can schedule work sooner than the last deadline (a relay
            // jittered by milliseconds): the tick runs now and says when next.
            next_tick = 0;
        }
        const int64_t now = now_ms();
        if (now >= next_busy_poll) {
            next_busy_poll = now + BUSY_POLL_MS;
            for (uint16_t i = 0; i < CONFIG_AH_LINKS; ++i) {
                if (s_busy[i]) {
                    s_busy[i] = false;
                    ah_node_link_ready(s_node, i, now);
                }
            }
        }
        any_busy = false;
        for (uint16_t i = 0; i < CONFIG_AH_LINKS; ++i) {
            any_busy = any_busy || s_busy[i];
        }
        if (now >= next_tick) {
            next_tick = ah_node_tick(s_node, now);
            ah_ble_scan_tick(now);
        }
        ah_ota_tick(s_node, now);
        if (now >= next_snapshot) {
            next_snapshot = now + SNAPSHOT_MS;
            publish(now);
            reconcile_ble(now);
            reconcile_lora(now);
            drop_silent_unbound(now);
        }
        if (now >= next_stats) {
            next_stats = now + STATS_LOG_MS;
            log_stats();
        }
        esp_task_wdt_reset();
        const int64_t fed = now_ms();
        s_longest_pass_ms = fed - fed_ms > s_longest_pass_ms ? fed - fed_ms : s_longest_pass_ms;
        fed_ms = fed;
        hold_full_speed(false);
        if (now >= next_yield) {
            next_yield = now + IDLE_YIELD_MS;
            vTaskDelay(1);
        }
    }
}

esp_err_t ah_app_init(void)
{
    s_queue = xQueueCreate(CONFIG_AH_EVENT_QUEUE, sizeof(event_t));
    ESP_RETURN_ON_FALSE(s_queue != NULL, ESP_ERR_NO_MEM, TAG, "queue");
    return ESP_OK;
}

esp_err_t ah_app_start(const ah_settings_t *settings, ah_screen_lora_t lora)
{
    ESP_RETURN_ON_FALSE(s_queue != NULL, ESP_ERR_INVALID_STATE, TAG, "ah_app_init first");
    s_lora = lora;
    ESP_RETURN_ON_ERROR(esp_pm_lock_create(ESP_PM_CPU_FREQ_MAX, 0, "mesh", &s_cpu_lock), TAG, "pm lock");
    ah_node_config_t cfg = config_from_kconfig();
    // Presence crosses the trunk less often where the duty budget is tight: every
    // origin's announce once per interval at 10 % of the air or more, four times
    // as long at India's 2.5 %, ten times at Southeast Asia's 1 %.
    const ah_lora_region_t *region = ah_lora_region(settings->region);
    if (region != NULL && region->duty_per_mille < 100u) {
        cfg.trunk_announce_interval_ms = cfg.trunk_announce_interval_ms * 100u / region->duty_per_mille;
    }
    const ah_node_ops_t ops = {
        .write = node_write,
        .mail_put = node_mail_put,
        .mail_delete = node_mail_delete,
        .clock_save = node_clock_save,
        .alloc = node_alloc,
    };
    s_node = ah_node_create(&cfg, &settings->identity, &ops, settings->clock_floor_ms);
    ESP_RETURN_ON_FALSE(s_node != NULL, ESP_ERR_NO_MEM, TAG, "node tables");
    ah_mailbox_restore(s_node);
    ESP_LOGI(TAG, "node ready: heap %lu free, largest block %lu, PSRAM %lu free",
             (unsigned long)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
             (unsigned long)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL),
             (unsigned long)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    // Core 0 of a dual-core chip runs the Bluetooth host and the LoRa task.
    const BaseType_t core = portNUM_PROCESSORS > 1 ? 1 : 0;
    ESP_RETURN_ON_FALSE(xTaskCreatePinnedToCore(mesh_task, "mesh", CONFIG_AH_MESH_TASK_STACK, NULL,
                                                CONFIG_AH_MESH_TASK_PRIORITY, NULL, core) == pdPASS,
                        ESP_ERR_NO_MEM, TAG, "mesh task");
    return ESP_OK;
}
