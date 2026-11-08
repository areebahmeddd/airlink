// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// NimBLE glue for the BLE transport: connection slots whose handles carry a
// generation, the GATT access and discovery callbacks, and the scan's deny list.
#include "ah_ble.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

#include "ah_wire.h"

static const char *TAG = "ah_ble";

// The GAP name every node advertises in its scan response, and how one node
// recognizes another. The same on every node, so it names no one; a node
// built with another would neither find the fleet nor be found by it.
#define NODE_NAME "airlink-node"
#define MAX_CONNECTIONS CONFIG_BT_NIMBLE_MAX_CONNECTIONS
// The ATT header a write or notification spends of the MTU.
#define ATT_OVERHEAD 3u
// Nodes not dialed again for a while: one whose setup failed, or one that
// never proved who it is.
#define DENY_ENTRIES 4u
#define DENY_MS 120000
#define HANDLE_CONN_MASK 0xFFFFu

typedef struct {
    bool in_use;
    bool we_dialed;
    bool writable;          // subscribed (peripheral) or CCCD written (central)
    bool phy_asked;
    uint16_t conn;
    uint16_t generation;
    uint16_t remote_value;  // the peer's characteristic, on links we dialed
    uint16_t remote_end;    // the end of the peer's service, where its CCCD search stops
    uint16_t mtu;
    ble_addr_t addr;
} conn_t;

static conn_t s_conns[MAX_CONNECTIONS];
// Guards s_conns (written on the host task, snapshotted on the mesh task) and
// s_deny (written from both). The host task sets a connection's MTU and remote
// handles without it: each is one aligned 16-bit store, read whole.
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
static ah_ble_events_t s_events;
static ah_ble_config_t s_cfg;
static uint16_t s_value_handle;
static uint8_t s_own_addr_type;
static uint8_t s_own_addr[6];
static bool s_synced;
static int64_t s_next_scan_ms;
static uint16_t s_generation;
static struct {
    ble_addr_t addr;
    int64_t until_ms;
} s_deny[DENY_ENTRIES];

static const ble_uuid128_t s_service_uuid = BLE_UUID128_INIT(AH_BLE_SERVICE_UUID128);
static const ble_uuid128_t s_char_uuid = BLE_UUID128_INIT(AH_BLE_CHARACTERISTIC_UUID128);

static int gap_event(struct ble_gap_event *event, void *arg);

static int64_t now_ms(void)
{
    return esp_timer_get_time() / 1000;
}

static uint32_t handle_of(const conn_t *c)
{
    return (uint32_t)c->generation << 16 | c->conn;
}

static conn_t *find(uint16_t conn)
{
    for (size_t i = 0; i < MAX_CONNECTIONS; ++i) {
        if (s_conns[i].in_use && s_conns[i].conn == conn) {
            return &s_conns[i];
        }
    }
    return NULL;
}

// The live connection a mesh handle names, or NULL once it has gone, even if
// its connection handle now belongs to another link.
static conn_t *find_handle(uint32_t handle)
{
    conn_t *c = find((uint16_t)(handle & HANDLE_CONN_MASK));
    return c != NULL && handle_of(c) == handle ? c : NULL;
}

static size_t count(bool dialed_only)
{
    size_t n = 0;
    for (size_t i = 0; i < MAX_CONNECTIONS; ++i) {
        n += s_conns[i].in_use && (!dialed_only || s_conns[i].we_dialed) ? 1u : 0u;
    }
    return n;
}

static uint16_t max_write_of(uint16_t mtu)
{
    const uint16_t w = mtu > ATT_OVERHEAD ? (uint16_t)(mtu - ATT_OVERHEAD) : 0;
    return w > AH_BLE_FRAME_MAX ? (uint16_t)AH_BLE_FRAME_MAX : w;
}

// ---- GATT server: the bitchat characteristic ----

static int characteristic_access(uint16_t conn, uint16_t attr, struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)attr;
    (void)arg;
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        // bitchat-ios declares the property; nothing is ever served by reading it.
        return 0;
    }
    if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) {
        return BLE_ATT_ERR_UNLIKELY;
    }
    // One complete frame per write, as bitchat-ios writes them.
    const uint16_t len = OS_MBUF_PKTLEN(ctxt->om);
    if (len == 0 || len > AH_BLE_FRAME_MAX) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }
    uint8_t buf[AH_BLE_FRAME_MAX];
    uint16_t copied = 0;
    if (ble_hs_mbuf_to_flat(ctxt->om, buf, sizeof(buf), &copied) != 0 || copied != len) {
        return BLE_ATT_ERR_UNLIKELY;
    }
    const conn_t *c = find(conn);
    if (c != NULL) {
        s_events.frame(handle_of(c), buf, copied);
    }
    return 0;
}

static const struct ble_gatt_svc_def s_services[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &s_service_uuid.u,
        .characteristics =
            (struct ble_gatt_chr_def[])
        {
            {
                .uuid = &s_char_uuid.u,
                .access_cb = characteristic_access,
                .val_handle = &s_value_handle,
                // As bitchat-ios declares it: read, write, write without
                // response, notify. Never indicate, which would serialize
                // every frame behind a round trip.
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP |
                         BLE_GATT_CHR_F_NOTIFY,
            },
            {0},
        },
    },
    {0},
};

// ---- advertising ----

static void advertise(void)
{
    if (!s_synced || ble_gap_adv_active() || count(false) >= MAX_CONNECTIONS) {
        return;
    }
    // The service UUID in the advertisement, as phones scan for it; the name
    // in the scan response (both together pass 31 bytes), which is how one
    // node recognizes another.
    struct ble_hs_adv_fields fields = {0};
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.uuids128 = (ble_uuid128_t *)&s_service_uuid;
    fields.num_uuids128 = 1;
    fields.uuids128_is_complete = 1;
    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv fields rc=%d", rc);
        return;
    }
    struct ble_hs_adv_fields rsp = {0};
    rsp.name = (const uint8_t *)NODE_NAME;
    rsp.name_len = (uint8_t)(sizeof(NODE_NAME) - 1u);
    rsp.name_is_complete = 1;
    rc = ble_gap_adv_rsp_set_fields(&rsp);
    if (rc != 0) {
        ESP_LOGE(TAG, "scan response rc=%d", rc);
        return;
    }
    const uint16_t interval = (uint16_t)(s_cfg.adv_interval_ms * 1000u / 625u);
    struct ble_gap_adv_params params = {
        .conn_mode = BLE_GAP_CONN_MODE_UND,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
        .itvl_min = interval,
        .itvl_max = (uint16_t)(interval + interval / 4u),
    };
    rc = ble_gap_adv_start(s_own_addr_type, NULL, BLE_HS_FOREVER, &params, gap_event, NULL);
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        ESP_LOGW(TAG, "adv start rc=%d", rc);
    }
}

// ---- central: other nodes ----

static bool denied(const ble_addr_t *addr)
{
    const int64_t now = now_ms();
    bool found = false;
    taskENTER_CRITICAL(&s_lock);
    for (size_t i = 0; i < DENY_ENTRIES && !found; ++i) {
        found = now < s_deny[i].until_ms && ble_addr_cmp(&s_deny[i].addr, addr) == 0;
    }
    taskEXIT_CRITICAL(&s_lock);
    return found;
}

static void deny(const ble_addr_t *addr)
{
    const int64_t until = now_ms() + DENY_MS;
    taskENTER_CRITICAL(&s_lock);
    size_t victim = 0;
    for (size_t i = 1; i < DENY_ENTRIES; ++i) {
        if (s_deny[i].until_ms < s_deny[victim].until_ms) {
            victim = i;
        }
    }
    s_deny[victim].addr = *addr;
    s_deny[victim].until_ms = until;
    taskEXIT_CRITICAL(&s_lock);
}

static void central_failed(uint16_t conn, const char *stage, int rc)
{
    ESP_LOGW(TAG, "conn=%u %s failed rc=%d", conn, stage, rc);
    conn_t *c = find(conn);
    // Out of host buffers is this node's own state: the peer is not set aside.
    if (c != NULL && rc != BLE_HS_ENOMEM) {
        deny(&c->addr);
    }
    ble_gap_terminate(conn, BLE_ERR_REM_USER_CONN_TERM);
}

static int on_cccd_written(uint16_t conn, const struct ble_gatt_error *error, struct ble_gatt_attr *attr, void *arg)
{
    (void)attr;
    (void)arg;
    if (error->status != 0) {
        central_failed(conn, "subscribe", error->status);
        return 0;
    }
    conn_t *c = find(conn);
    if (c == NULL) {
        return 0;
    }
    taskENTER_CRITICAL(&s_lock);
    c->writable = true;
    taskEXIT_CRITICAL(&s_lock);
    s_events.link_up(handle_of(c), max_write_of(c->mtu));
    return 0;
}

static int on_descriptor(uint16_t conn, const struct ble_gatt_error *error, uint16_t chr,
                         const struct ble_gatt_dsc *dsc, void *arg)
{
    (void)chr;
    (void)arg;
    if (error->status == 0 && dsc != NULL &&
            ble_uuid_cmp(&dsc->uuid.u, BLE_UUID16_DECLARE(BLE_GATT_DSC_CLT_CFG_UUID16)) == 0) {
        static const uint8_t notify_on[2] = {0x01, 0x00};
        const int rc = ble_gattc_write_flat(conn, dsc->handle, notify_on, sizeof(notify_on), on_cccd_written, NULL);
        if (rc != 0) {
            central_failed(conn, "subscribe start", rc);
        }
        return BLE_HS_EDONE;
    }
    // Returning BLE_HS_EDONE above ends the discovery with no further call,
    // so BLE_HS_EDONE here means the characteristic has no CCCD: a peer we
    // can never subscribe to, which would otherwise hold its slot for good.
    if (error->status != 0) {
        central_failed(conn, "descriptor discovery", error->status);
    }
    return 0;
}

static int on_characteristic(uint16_t conn, const struct ble_gatt_error *error, const struct ble_gatt_chr *chr,
                             void *arg)
{
    (void)arg;
    conn_t *c = find(conn);
    if (c == NULL) {
        return 0;
    }
    if (error->status == 0 && chr != NULL) {
        c->remote_value = chr->val_handle;
        return 0;
    }
    if (error->status != BLE_HS_EDONE || c->remote_value == 0) {
        central_failed(conn, "characteristic discovery", error->status);
        return 0;
    }
    const int rc = ble_gattc_disc_all_dscs(conn, c->remote_value, c->remote_end, on_descriptor, NULL);
    if (rc != 0) {
        central_failed(conn, "descriptor discovery start", rc);
    }
    return 0;
}

static int on_service(uint16_t conn, const struct ble_gatt_error *error, const struct ble_gatt_svc *svc, void *arg)
{
    (void)arg;
    conn_t *c = find(conn);
    if (c == NULL) {
        return 0;
    }
    if (error->status == 0 && svc != NULL) {
        c->remote_end = svc->end_handle;
        const int rc = ble_gattc_disc_chrs_by_uuid(conn, svc->start_handle, svc->end_handle, &s_char_uuid.u,
                                                   on_characteristic, NULL);
        if (rc != 0) {
            central_failed(conn, "characteristic discovery start", rc);
        }
        return BLE_HS_EDONE;
    }
    if (error->status != BLE_HS_EDONE || c->remote_end == 0) {
        central_failed(conn, "service discovery", error->status);
    }
    return 0;
}

// Two nodes in range would otherwise dial each other at once and hold two
// links; only the one with the lower address dials.
static bool we_should_dial(const ble_addr_t *peer)
{
    for (int i = 5; i >= 0; --i) {
        if (s_own_addr[i] != peer->val[i]) {
            return s_own_addr[i] < peer->val[i];
        }
    }
    return false;
}

static bool linked_to(const ble_addr_t *addr)
{
    for (size_t i = 0; i < MAX_CONNECTIONS; ++i) {
        if (s_conns[i].in_use && ble_addr_cmp(&s_conns[i].addr, addr) == 0) {
            return true;
        }
    }
    return false;
}

// Whether one more node could be dialed. Phones already connected use up
// their reservation; a dial must leave free only the reserved slots no phone
// holds yet.
static bool can_dial(void)
{
    const size_t total = count(false);
    const size_t dialed = count(true);
    const size_t inbound = total - dialed;
    const size_t still_reserved = inbound >= s_cfg.reserved_for_phones ? 0 : s_cfg.reserved_for_phones - inbound;
    return dialed < s_cfg.max_node_links && total + 1u + still_reserved <= MAX_CONNECTIONS;
}

static void consider(const struct ble_gap_disc_desc *disc)
{
    struct ble_hs_adv_fields fields;
    if (ble_hs_adv_parse_fields(&fields, disc->data, disc->length_data) != 0) {
        return;
    }
    // Phones connect to us; we dial only other nodes, known by their GAP name.
    const size_t name_len = sizeof(NODE_NAME) - 1u;
    if (fields.name == NULL || fields.name_len != name_len || memcmp(fields.name, NODE_NAME, name_len) != 0) {
        return;
    }
    if (!we_should_dial(&disc->addr) || denied(&disc->addr) || linked_to(&disc->addr) || !can_dial()) {
        return;
    }
    ble_gap_disc_cancel();
    const int rc = ble_gap_connect(s_own_addr_type, &disc->addr, 10000, NULL, gap_event, NULL);
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        ESP_LOGW(TAG, "dial rc=%d", rc);
    }
}

void ah_ble_scan_tick(int64_t now)
{
    // No scan while nothing found could be dialed: it would cost receive
    // time for no link.
    if (!s_synced || now < s_next_scan_ms || !can_dial()) {
        return;
    }
    s_next_scan_ms = now + (int64_t)s_cfg.scan_every_ms;
    // 50 ms interval, 30 ms window, in 0.625 ms units.
    const struct ble_gap_disc_params params = {
        .itvl = 0x0050,
        .window = 0x0030,
        .filter_duplicates = 1,
        .passive = 0, // active: the name is in the scan response
    };
    const int rc = ble_gap_disc(s_own_addr_type, (int32_t)s_cfg.scan_for_ms, &params, gap_event, NULL);
    if (rc != 0 && rc != BLE_HS_EALREADY) {
        ESP_LOGD(TAG, "scan rc=%d", rc);
    }
}

// ---- GAP events (host task: copy, post, return) ----

static void connected(uint16_t conn)
{
    struct ble_gap_conn_desc desc;
    if (ble_gap_conn_find(conn, &desc) != 0) {
        return;
    }
    conn_t *slot = NULL;
    for (size_t i = 0; i < MAX_CONNECTIONS && slot == NULL; ++i) {
        if (!s_conns[i].in_use) {
            slot = &s_conns[i];
        }
    }
    if (slot == NULL) {
        ble_gap_terminate(conn, BLE_ERR_REM_USER_CONN_TERM);
        return;
    }
    taskENTER_CRITICAL(&s_lock);
    memset(slot, 0, sizeof(*slot));
    slot->in_use = true;
    slot->conn = conn;
    slot->generation = ++s_generation;
    slot->addr = desc.peer_id_addr;
    slot->we_dialed = desc.role == BLE_GAP_ROLE_MASTER;
    slot->mtu = BLE_ATT_MTU_DFLT;
    taskEXIT_CRITICAL(&s_lock);
    if (slot->we_dialed) {
        // A node link left at the 23-byte default carries no frame at all.
        int rc = ble_gattc_exchange_mtu(conn, NULL, NULL);
        if (rc == 0) {
            rc = ble_gattc_disc_svc_by_uuid(conn, &s_service_uuid.u, on_service, NULL);
        }
        if (rc != 0) {
            central_failed(conn, "mtu exchange or service discovery start", rc);
        }
    } else {
        // A phone may write the moment it connects; our notifications wait
        // for its subscription (`ready`).
        s_events.link_up(handle_of(slot), max_write_of(slot->mtu));
    }
}

static int gap_event(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            connected(event->connect.conn_handle);
        }
        advertise();
        return 0;
    case BLE_GAP_EVENT_DISCONNECT: {
        conn_t *c = find(event->disconnect.conn.conn_handle);
        if (c != NULL) {
            const uint32_t handle = handle_of(c);
            taskENTER_CRITICAL(&s_lock);
            c->in_use = false;
            taskEXIT_CRITICAL(&s_lock);
            s_events.link_down(handle);
        }
        advertise();
        return 0;
    }
    case BLE_GAP_EVENT_SUBSCRIBE: {
        conn_t *c = find(event->subscribe.conn_handle);
        if (c != NULL && event->subscribe.attr_handle == s_value_handle) {
            taskENTER_CRITICAL(&s_lock);
            c->writable = event->subscribe.cur_notify != 0;
            taskEXIT_CRITICAL(&s_lock);
            if (c->writable) {
                s_events.ready(handle_of(c));
            }
        }
        return 0;
    }
    case BLE_GAP_EVENT_MTU: {
        conn_t *c = find(event->mtu.conn_handle);
        if (c != NULL) {
            c->mtu = event->mtu.value;
            s_events.mtu(handle_of(c), max_write_of(c->mtu));
        }
        return 0;
    }
    case BLE_GAP_EVENT_NOTIFY_RX: {
        const conn_t *c = find(event->notify_rx.conn_handle);
        const uint16_t len = OS_MBUF_PKTLEN(event->notify_rx.om);
        uint8_t buf[AH_BLE_FRAME_MAX];
        uint16_t copied = 0;
        // Only the bitchat characteristic of a node we dialed carries frames: a
        // notification or indication from any other attribute (Service
        // Changed, say) is not one.
        if (c != NULL && c->we_dialed && event->notify_rx.attr_handle == c->remote_value && len > 0 &&
                len <= sizeof(buf) &&
                ble_hs_mbuf_to_flat(event->notify_rx.om, buf, sizeof(buf), &copied) == 0) {
            s_events.frame(handle_of(c), buf, copied);
        }
        return 0;
    }
    case BLE_GAP_EVENT_DISC:
        consider(&event->disc);
        return 0;
    case BLE_GAP_EVENT_DISC_COMPLETE:
    case BLE_GAP_EVENT_ADV_COMPLETE:
        // A scan or an advertising set ended, freeing a controller activity:
        // advertising that could not start before starts now.
        advertise();
        return 0;
    case BLE_GAP_EVENT_PHY_UPDATE_COMPLETE:
        ESP_LOGI(TAG, "conn=%u phy tx=%u rx=%u status=%d", event->phy_updated.conn_handle,
                 event->phy_updated.tx_phy, event->phy_updated.rx_phy, event->phy_updated.status);
        return 0;
    default:
        return 0;
    }
}

ah_ble_write_t ah_ble_write(uint32_t handle, const uint8_t *frame, size_t len)
{
    taskENTER_CRITICAL(&s_lock);
    const conn_t *c = find_handle(handle);
    const bool present = c != NULL;
    const bool writable = present && c->writable;
    const bool dialed = present && c->we_dialed;
    const uint16_t remote = present ? c->remote_value : 0;
    const uint16_t limit = present ? max_write_of(c->mtu) : 0;
    taskEXIT_CRITICAL(&s_lock);
    if (!present || len > limit) {
        return AH_BLE_WRITE_GONE;
    }
    if (!writable) {
        return AH_BLE_WRITE_UNSUBSCRIBED;
    }
    const uint16_t conn = (uint16_t)(handle & HANDLE_CONN_MASK);
    int rc;
    if (dialed) {
        rc = ble_gattc_write_no_rsp_flat(conn, remote, frame, (uint16_t)len);
    } else {
        struct os_mbuf *om = ble_hs_mbuf_from_flat(frame, (uint16_t)len);
        if (om == NULL) {
            return AH_BLE_WRITE_BUSY;
        }
        // Consumes the mbuf whatever it returns.
        rc = ble_gatts_notify_custom(conn, s_value_handle, om);
    }
    if (rc == 0) {
        return AH_BLE_WRITE_OK;
    }
    return rc == BLE_HS_ENOTCONN ? AH_BLE_WRITE_GONE : AH_BLE_WRITE_BUSY;
}

void ah_ble_prefer_coded_phy(uint32_t handle)
{
    taskENTER_CRITICAL(&s_lock);
    conn_t *c = find_handle(handle);
    const bool ask = c != NULL && !c->phy_asked;
    if (ask) {
        c->phy_asked = true;
    }
    taskEXIT_CRITICAL(&s_lock);
    if (!ask) {
        return;
    }
    const uint16_t conn = (uint16_t)(handle & HANDLE_CONN_MASK);
    // A preference, not a command: either controller may decline and the link
    // stays on the PHY it has. The coding (S=2 or S=8) is the link layer's call.
    const int rc =
        ble_gap_set_prefered_le_phy(conn, BLE_GAP_LE_PHY_CODED_MASK, BLE_GAP_LE_PHY_CODED_MASK,
                                    BLE_GAP_LE_PHY_CODED_ANY);
    if (rc != 0) {
        ESP_LOGD(TAG, "conn=%u coded phy declined locally rc=%d", conn, rc);
    }
}

void ah_ble_drop(uint32_t handle)
{
    taskENTER_CRITICAL(&s_lock);
    const bool present = find_handle(handle) != NULL;
    taskEXIT_CRITICAL(&s_lock);
    if (present) {
        ble_gap_terminate((uint16_t)(handle & HANDLE_CONN_MASK), BLE_ERR_REM_USER_CONN_TERM);
    }
}

size_t ah_ble_connections(ah_ble_conn_t *out, size_t cap)
{
    size_t n = 0;
    taskENTER_CRITICAL(&s_lock);
    for (size_t i = 0; i < MAX_CONNECTIONS && n < cap; ++i) {
        const conn_t *c = &s_conns[i];
        if (c->in_use) {
            out[n++] = (ah_ble_conn_t) {
                .handle = handle_of(c),
                .max_write = max_write_of(c->mtu),
                // As link_up is posted: see connected and on_cccd_written.
                .open = !c->we_dialed || c->writable,
                .writable = c->writable,
            };
        }
    }
    taskEXIT_CRITICAL(&s_lock);
    return n;
}

void ah_ble_drop_unbound(uint32_t handle)
{
    ble_addr_t addr = {0};
    taskENTER_CRITICAL(&s_lock);
    const conn_t *c = find_handle(handle);
    const bool present = c != NULL;
    const bool dialed = present && c->we_dialed;
    if (present) {
        addr = c->addr;
    }
    taskEXIT_CRITICAL(&s_lock);
    if (!present) {
        return;
    }
    if (dialed) {
        deny(&addr);
    }
    ESP_LOGW(TAG, "conn=%u never proved its peer; dropped", (unsigned)(handle & HANDLE_CONN_MASK));
    ble_gap_terminate((uint16_t)(handle & HANDLE_CONN_MASK), BLE_ERR_REM_USER_CONN_TERM);
}

static void on_sync(void)
{
    if (ble_hs_id_infer_auto(0, &s_own_addr_type) != 0) {
        ESP_LOGE(TAG, "no usable address");
        return;
    }
    ble_hs_id_copy_addr(s_own_addr_type, s_own_addr, NULL);
    s_synced = true;
    advertise();
}

static void on_reset(int reason)
{
    s_synced = false;
    ESP_LOGW(TAG, "host reset reason=%d", reason);
}

static void host_task(void *arg)
{
    (void)arg;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

esp_err_t ah_ble_start(const ah_ble_config_t *config, const ah_ble_events_t *events)
{
    s_cfg = *config;
    s_events = *events;
    memset(s_conns, 0, sizeof(s_conns));
    if (nimble_port_init() != ESP_OK) {
        return ESP_FAIL;
    }
    ble_hs_cfg.reset_cb = on_reset;
    ble_hs_cfg.sync_cb = on_sync;
    ble_svc_gap_init();
    ble_svc_gatt_init();
    ble_svc_gap_device_name_set(NODE_NAME);
    if (ble_gatts_count_cfg(s_services) != 0 || ble_gatts_add_svcs(s_services) != 0) {
        return ESP_FAIL;
    }
    nimble_port_freertos_init(host_task);
    return ESP_OK;
}
