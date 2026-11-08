// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Node-to-node updates: offering, requesting, writing and checking an image, and
// the rollback trial.
#include "ah_ota.h"

#include <stdio.h>
#include <string.h>

#include "esp_app_desc.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "nvs.h"
#include "sdkconfig.h"

#include "ah_bytes.h"
#include "ah_crypto.h"
#include "ah_frame.h"
#include "ah_ota_manifest.h"
#include "ah_wire.h"

static const char *TAG = "ah_ota";

// REQUEST: version(4) offset(4) length(2). CHUNK: version(4) offset(4) data.
#define REQUEST_LEN 10u
#define CHUNK_HEADER 8u
// What an OTA packet adds around its payload: the v2 header and both IDs.
#define FRAME_OVERHEAD (AH_V2_HEADER_LEN + 2u * AH_PEER_ID_LEN)
// The most one Bluetooth frame carries; piece_cap holds each piece to what
// its own link takes.
#define CHUNK_MAX (AH_BLE_FRAME_MAX - FRAME_OVERHEAD - CHUNK_HEADER)
// Stop and wait: a lost piece costs one timeout, and forty in a row (a link
// gone quiet for over two minutes) end the transfer.
#define REQUEST_TIMEOUT_MS 4000
#define REQUEST_RETRIES 40u
// The slowest transfer kept past its first minute: an honest one moves several
// KiB a second, even at a small MTU.
#define MIN_BYTES_PER_S 512
#define MIN_RATE_GRACE_MS 60000
#define OFFER_INTERVAL_MS 60000
// A manifest costs an Ed25519 check before anything else about it is known,
// and a peer that merely claims to be a node can send one in every frame, so a
// link gets one checked per this long: a flood then costs at most
// CONFIG_AH_LINKS checks per window, beside the core's own budget. Honest
// neighbors offer once a minute (OFFER_INTERVAL_MS).
#define MANIFEST_INTERVAL_MS 10000
#define REBOOT_DELAY_MS 3000
#define STATUS_APPLIED 0x00
#define STATUS_HASH_MISMATCH 0xE1
#define STATUS_FLASH_FAILED 0xE2

// Each app slot's manifest is kept under the slot's label, so one that rolls
// back still serves the image it returned to.
#define NVS_NAMESPACE "ah_ota"
// The highest version this board rolled back from. The bootloader's own record
// goes as soon as the next transfer starts (esp_ota_begin erases the
// rolled-back slot's OTA data entry, and the first write its image), and the
// node would then take the image that failed again.
#define KEY_REFUSED "refused"
// The rolled-back version last judged; each install clears it, so the next
// rollback of any version is judged afresh.
#define KEY_JUDGED "judged"
// How many trials of one version a power cut or a restart has ended.
#define KEY_RETRY_VERSION "retry_ver"
#define KEY_RETRIES "retries"
// A trial a fault ended (a panic or a watchdog) says the image is bad. One a
// power cut, a brownout or a restart ended says nothing of it, and a solar
// node at dusk can lose power inside its trial: the version is tried
// again, but no more than this many times, since an image that browns the
// board out ends its trial the same way.
#define TRIAL_ATTEMPTS 3u
#define TRIAL_RETRY_MS 10000
// An image fetched whole and then refused (its hash, or the bootloader's
// checks) is not fetched again for this long: the same manifest comes back
// with every offer, and each fetch erases and rewrites a slot.
#define FAILED_BACKOFF_MS (60LL * 60 * 1000)
// A manifest flashed beside the image, for a node flashed by wire.
#define MANIFEST_PARTITION_SUBTYPE 0x40

typedef struct {
    uint32_t version;
    uint32_t size;
    uint8_t sha256[AH_SHA256_LEN];
    uint8_t raw[AH_OTA_MANIFEST_LEN];
} manifest_t;

static struct {
    bool enabled;
    uint8_t owner[AH_KEY_LEN];
    uint8_t self[AH_PEER_ID_LEN];
    char board[AH_OTA_BOARD_LEN + 1];
    uint32_t running;
    // Versions up to this one, which the bootloader rolled back from, are refused.
    uint32_t refused;
    bool serving;
    manifest_t serve;
    bool on_trial;
    int64_t trial_retry_ms; // when to try marking the image kept again
    // The last manifest for our own version found not to match this image:
    // hashing the image takes about a second, so a replay is not hashed again.
    uint8_t mismatched[AH_SHA256_LEN];
    // The last image fetched and refused, and when, and the node it came from.
    uint8_t failed[AH_SHA256_LEN];
    uint8_t failed_from[AH_PEER_ID_LEN];
    int64_t failed_ms;
    int64_t reboot_at_ms;
    int64_t offered_ms[CONFIG_AH_LINKS];
    // When each link last had a manifest checked; kept across a reconnect, so
    // dropping and rejoining earns no extra check.
    int64_t manifest_ms[CONFIG_AH_LINKS];
    // The transfer in progress.
    bool active;
    manifest_t rx;
    uint16_t link;
    uint32_t offset;
    esp_ota_handle_t handle;
    const esp_partition_t *part;
    ah_sha256_ctx_t sha;
    int64_t asked_ms;
    uint32_t retries;
    uint16_t want;                    // the piece size last asked for
    int64_t started_ms;
    uint8_t server[AH_PEER_ID_LEN];   // the node the transfer is from
} s_ota;

static uint32_t parse_version(const char *v)
{
    unsigned major = 0;
    unsigned minor = 0;
    unsigned patch = 0;
    // "1.0.0", or a git describe such as "v1.0.0-3-gabc": the leading digits.
    if (*v == 'v') {
        ++v;
    }
    if (sscanf(v, "%u.%u.%u", &major, &minor, &patch) < 1 || major > 0xFF || minor > 0xFF || patch > 0xFF) {
        return 0;
    }
    return (uint32_t)major << 16 | (uint32_t)minor << 8 | patch;
}

uint32_t ah_ota_running_version(void)
{
    return parse_version(esp_app_get_description()->version);
}

static bool parse_manifest(const uint8_t *data, size_t len, manifest_t *out)
{
    ah_ota_manifest_t m;
    // Another fleet's image, another board's, or a forgery: never fetched.
    if (!s_ota.enabled || !ah_ota_manifest_check(data, len, s_ota.owner, s_ota.board, &m)) {
        return false;
    }
    out->version = m.version;
    out->size = m.size;
    memcpy(out->sha256, m.sha256, sizeof(out->sha256));
    memcpy(out->raw, data, AH_OTA_MANIFEST_LEN);
    return true;
}

static bool matches_running_image(const manifest_t *m)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (running == NULL || m->size > running->size) {
        return false;
    }
    ah_sha256_ctx_t ctx;
    ah_sha256_begin(&ctx);
    uint8_t buf[1024];
    for (uint32_t off = 0; off < m->size; off += sizeof(buf)) {
        const size_t n = m->size - off < sizeof(buf) ? m->size - off : sizeof(buf);
        if (esp_partition_read(running, off, buf, n) != ESP_OK) {
            uint8_t discard[AH_SHA256_LEN];
            ah_sha256_finish(&ctx, discard);
            return false;
        }
        ah_sha256_update(&ctx, buf, n);
    }
    uint8_t digest[AH_SHA256_LEN];
    return ah_sha256_finish(&ctx, digest) && memcmp(digest, m->sha256, sizeof(digest)) == 0;
}

static void store_manifest(const manifest_t *m, const esp_partition_t *slot)
{
    nvs_handle_t h;
    if (slot != NULL && nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        if (nvs_set_blob(h, slot->label, m->raw, AH_OTA_MANIFEST_LEN) == ESP_OK) {
            nvs_commit(h);
        }
        nvs_close(h);
    }
}

// The manifest that lets this node serve its own image: one received with an
// update, or one flashed beside a wired image. Either must describe the image
// actually running.
static void find_serve_manifest(void)
{
    uint8_t raw[AH_OTA_MANIFEST_LEN];
    manifest_t m;
    nvs_handle_t h;
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (running != NULL && nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) == ESP_OK) {
        size_t len = sizeof(raw);
        const bool found = nvs_get_blob(h, running->label, raw, &len) == ESP_OK;
        nvs_close(h);
        if (found && parse_manifest(raw, len, &m) && m.version == s_ota.running && matches_running_image(&m)) {
            s_ota.serve = m;
            s_ota.serving = true;
            return;
        }
    }
    const esp_partition_t *p =
        esp_partition_find_first(ESP_PARTITION_TYPE_DATA, MANIFEST_PARTITION_SUBTYPE, NULL);
    if (p != NULL && esp_partition_read(p, 0, raw, sizeof(raw)) == ESP_OK && parse_manifest(raw, sizeof(raw), &m) &&
            m.version == s_ota.running && matches_running_image(&m)) {
        s_ota.serve = m;
        s_ota.serving = true;
        store_manifest(&m, running);
    }
}

static bool fault_reset(void)
{
    switch (esp_reset_reason()) {
    case ESP_RST_PANIC:
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
    case ESP_RST_WDT:
    case ESP_RST_CPU_LOCKUP:
        return true;
    default:
        return false;
    }
}

// The version a rollback from `rolled_back` (0 for none) refuses, or 0:
// judged once, at the boot the rollback brought, from the reset that ended
// the trial; any boot after it finds the same rollback already judged.
static uint32_t judge_rollback(uint32_t rolled_back)
{
    nvs_handle_t h;
    if (rolled_back == 0 || nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        return rolled_back;
    }
    uint32_t judged = 0;
    nvs_get_u32(h, KEY_JUDGED, &judged);
    uint32_t refuse = 0;
    if (judged != rolled_back) {
        uint32_t retry_version = 0;
        uint8_t attempts = 0;
        nvs_get_u32(h, KEY_RETRY_VERSION, &retry_version);
        nvs_get_u8(h, KEY_RETRIES, &attempts);
        attempts = retry_version == rolled_back && attempts < UINT8_MAX ? (uint8_t)(attempts + 1u) : 1u;
        refuse = fault_reset() || attempts >= TRIAL_ATTEMPTS ? rolled_back : 0;
        // The refusal is written before the rollback is marked judged: a
        // power cut between the two judges it again, never forgets it.
        uint32_t refused = 0;
        nvs_get_u32(h, KEY_REFUSED, &refused);
        if (refuse > refused) {
            nvs_set_u32(h, KEY_REFUSED, refuse);
        }
        nvs_set_u32(h, KEY_JUDGED, rolled_back);
        nvs_set_u32(h, KEY_RETRY_VERSION, rolled_back);
        nvs_set_u8(h, KEY_RETRIES, attempts);
        nvs_commit(h);
        ESP_LOGW(TAG, "trial %u of image %06lx ended by %s", attempts, (unsigned long)rolled_back,
                 refuse != 0 ? "a fault or too many resets: refused" : "a power cut or restart: offered again");
    }
    nvs_close(h);
    return refuse;
}

// A new image is installed: its rollback, if one comes, is judged afresh.
static void clear_judged(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
        if (nvs_erase_key(h, KEY_JUDGED) == ESP_OK) {
            nvs_commit(h);
        }
        nvs_close(h);
    }
}

// Read the stored refusal, and raise it to `rolled_back` (0 for none). Only
// ever raised: a lower version than one refused is no safer.
static uint32_t remember_refused(uint32_t rolled_back)
{
    uint32_t refused = 0;
    nvs_handle_t h;
    if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) {
        return rolled_back;
    }
    nvs_get_u32(h, KEY_REFUSED, &refused);
    if (rolled_back > refused) {
        refused = rolled_back;
        if (nvs_set_u32(h, KEY_REFUSED, refused) == ESP_OK) {
            nvs_commit(h);
        }
    }
    nvs_close(h);
    return refused;
}

esp_err_t ah_ota_init(const ah_settings_t *settings, const char *board)
{
    memset(&s_ota, 0, sizeof(s_ota));
    s_ota.running = ah_ota_running_version();
    snprintf(s_ota.board, sizeof(s_ota.board), "%s", board);
    memcpy(s_ota.self, settings->identity.peer_id, sizeof(s_ota.self));
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t state;
    if (running != NULL && esp_ota_get_state_partition(running, &state) == ESP_OK &&
            state == ESP_OTA_IMG_PENDING_VERIFY) {
        s_ota.on_trial = true;
        ESP_LOGW(TAG, "image %06lx on trial until it proves itself", (unsigned long)s_ota.running);
    }
    const esp_partition_t *invalid = esp_ota_get_last_invalid_partition();
    esp_app_desc_t desc;
    uint32_t rolled_back = 0;
    if (invalid != NULL && esp_ota_get_partition_description(invalid, &desc) == ESP_OK) {
        rolled_back = parse_version(desc.version);
        ESP_LOGW(TAG, "image %06lx rolled back", (unsigned long)rolled_back);
    }
    s_ota.refused = remember_refused(judge_rollback(rolled_back));
    if (s_ota.refused != 0) {
        ESP_LOGW(TAG, "versions up to %06lx are refused", (unsigned long)s_ota.refused);
    }
    s_ota.enabled = settings->has_owner_key;
    if (!s_ota.enabled) {
        ESP_LOGI(TAG, "no owner key: updates off");
        return ESP_OK;
    }
    memcpy(s_ota.owner, settings->owner_key, sizeof(s_ota.owner));
    find_serve_manifest();
    ESP_LOGI(TAG, "firmware %06lx for %s, %s", (unsigned long)s_ota.running, s_ota.board,
             s_ota.serving ? "serving it" : "receive only");
    return ESP_OK;
}

static void send(ah_node_t *n, uint16_t link, uint8_t type, const uint8_t *payload, size_t len, int64_t now)
{
    ah_node_link_info_t info;
    if (!ah_node_link_info(n, link, &info) || info.peer_id == NULL) {
        return;
    }
    uint64_t wall = 0;
    ah_node_wall_time(n, now, &wall);
    const ah_frame_fields_t f = {
        .type = type,
        .ttl = 0,
        .timestamp_ms = wall,
        .sender = s_ota.self,
        .recipient = info.peer_id,
        .payload = payload,
        .payload_len = len,
    };
    uint8_t frame[AH_FRAME_BUF_MAX];
    const size_t flen = ah_frame_encode(&f, false, frame, sizeof(frame));
    if (flen > 0) {
        ah_node_send_raw(n, link, frame, flen, now);
    }
}

// The largest piece one packet carries on this link.
static uint32_t piece_cap(const ah_node_t *n, uint16_t link)
{
    ah_node_link_info_t info;
    if (!ah_node_link_info(n, link, &info) || info.max_write <= FRAME_OVERHEAD + CHUNK_HEADER) {
        return 0;
    }
    const uint32_t cap = info.max_write - FRAME_OVERHEAD - CHUNK_HEADER;
    return cap < CHUNK_MAX ? cap : CHUNK_MAX;
}

static void request(ah_node_t *n, int64_t now)
{
    const uint32_t left = s_ota.rx.size - s_ota.offset;
    uint32_t want = piece_cap(n, s_ota.link);
    want = want < left ? want : left;
    uint8_t p[REQUEST_LEN];
    ah_put_be32(p, s_ota.rx.version);
    ah_put_be32(p + 4, s_ota.offset);
    ah_put_be16(p + 8, (uint16_t)want);
    s_ota.want = (uint16_t)want;
    send(n, s_ota.link, AH_TYPE_OTA_REQUEST, p, sizeof(p), now);
    s_ota.asked_ms = now;
}

static void end_transfer(void)
{
    if (s_ota.active) {
        esp_ota_abort(s_ota.handle);
        uint8_t discard[AH_SHA256_LEN];
        ah_sha256_finish(&s_ota.sha, discard);
    }
    s_ota.active = false;
}

// The image given up on is held off from the node that served it.
static void hold_off_failed(int64_t now)
{
    memcpy(s_ota.failed, s_ota.rx.sha256, AH_SHA256_LEN);
    memcpy(s_ota.failed_from, s_ota.server, AH_PEER_ID_LEN);
    s_ota.failed_ms = now;
}

// Whether the transfer has moved slower than MIN_BYTES_PER_S since it began.
static bool too_slow(int64_t now)
{
    return (int64_t)s_ota.offset < (now - s_ota.started_ms) * MIN_BYTES_PER_S / 1000;
}

static void status(ah_node_t *n, uint16_t link, uint8_t code, int64_t now)
{
    send(n, link, AH_TYPE_OTA_STATUS, &code, 1, now);
}

static void on_manifest(ah_node_t *n, uint16_t link, const uint8_t *p, size_t len, int64_t now)
{
    manifest_t m;
    if (!parse_manifest(p, len, &m)) {
        return;
    }
    if (m.version == s_ota.running) {
        // A manifest for this very image: serve it, if it describes it.
        if (s_ota.serving || memcmp(m.sha256, s_ota.mismatched, AH_SHA256_LEN) == 0) {
            return;
        }
        if (matches_running_image(&m)) {
            s_ota.serve = m;
            s_ota.serving = true;
            store_manifest(&m, esp_ota_get_running_partition());
        } else {
            memcpy(s_ota.mismatched, m.sha256, AH_SHA256_LEN);
        }
        return;
    }
    // Strictly newer only: never a downgrade, never the same version twice,
    // never one that already failed here. Nothing once an image waits to boot:
    // the next update slot is then the one it was just written to.
    // A failed image is held off from its server alone, so a node serving
    // garbage cannot keep an honest copy of the same release away.
    const uint8_t *server = ah_node_link_peer(n, link);
    if (server == NULL || s_ota.reboot_at_ms != 0 || m.version < s_ota.running || m.version <= s_ota.refused ||
            (s_ota.active && m.version <= s_ota.rx.version) ||
            (s_ota.failed_ms != 0 && now - s_ota.failed_ms < FAILED_BACKOFF_MS &&
             memcmp(m.sha256, s_ota.failed, AH_SHA256_LEN) == 0 &&
             memcmp(server, s_ota.failed_from, AH_PEER_ID_LEN) == 0)) {
        return;
    }
    end_transfer();
    const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
    if (part == NULL || m.size > part->size || piece_cap(n, link) == 0 ||
            esp_ota_begin(part, OTA_WITH_SEQUENTIAL_WRITES, &s_ota.handle) != ESP_OK) {
        ESP_LOGW(TAG, "cannot take image %06lx (%lu bytes)", (unsigned long)m.version, (unsigned long)m.size);
        return;
    }
    s_ota.active = true;
    s_ota.rx = m;
    s_ota.part = part;
    s_ota.link = link;
    s_ota.offset = 0;
    s_ota.retries = 0;
    s_ota.started_ms = now;
    memcpy(s_ota.server, server, AH_PEER_ID_LEN);
    ah_sha256_begin(&s_ota.sha);
    ESP_LOGI(TAG, "fetching image %06lx, %lu bytes", (unsigned long)m.version, (unsigned long)m.size);
    request(n, now);
}

static void finish(ah_node_t *n, int64_t now)
{
    uint8_t digest[AH_SHA256_LEN];
    const bool hashed = ah_sha256_finish(&s_ota.sha, digest);
    s_ota.active = false;
    if (!hashed || memcmp(digest, s_ota.rx.sha256, sizeof(digest)) != 0) {
        esp_ota_abort(s_ota.handle);
        ESP_LOGE(TAG, "image hash mismatch; discarded");
        hold_off_failed(now);
        status(n, s_ota.link, STATUS_HASH_MISMATCH, now);
        return;
    }
    // esp_ota_end checks the image itself (and its Secure Boot signature
    // when enabled) before it can be made bootable.
    if (esp_ota_end(s_ota.handle) != ESP_OK || esp_ota_set_boot_partition(s_ota.part) != ESP_OK) {
        ESP_LOGE(TAG, "image refused by the bootloader checks");
        hold_off_failed(now);
        status(n, s_ota.link, STATUS_FLASH_FAILED, now);
        return;
    }
    clear_judged();
    store_manifest(&s_ota.rx, s_ota.part);
    status(n, s_ota.link, STATUS_APPLIED, now);
    ESP_LOGI(TAG, "image %06lx ready; rebooting into it", (unsigned long)s_ota.rx.version);
    s_ota.reboot_at_ms = now + REBOOT_DELAY_MS;
}

static void on_chunk(ah_node_t *n, uint16_t link, const uint8_t *p, size_t len, int64_t now)
{
    if (!s_ota.active || link != s_ota.link || len <= CHUNK_HEADER || ah_be32(p) != s_ota.rx.version ||
            ah_be32(p + 4) != s_ota.offset) {
        // A duplicate or a stray: the timeout asks again for what is missing.
        return;
    }
    // Exactly the piece asked for, so a server cannot trickle bytes and hold
    // the transfer for months.
    const size_t data_len = len - CHUNK_HEADER;
    if (data_len != s_ota.want) {
        return;
    }
    if (esp_ota_write(s_ota.handle, p + CHUNK_HEADER, data_len) != ESP_OK) {
        ESP_LOGE(TAG, "flash write failed at %lu", (unsigned long)s_ota.offset);
        status(n, link, STATUS_FLASH_FAILED, now);
        end_transfer();
        return;
    }
    ah_sha256_update(&s_ota.sha, p + CHUNK_HEADER, data_len);
    s_ota.offset += (uint32_t)data_len;
    s_ota.retries = 0;
    if (s_ota.offset == s_ota.rx.size) {
        finish(n, now);
    } else {
        request(n, now);
    }
}

static void on_request(ah_node_t *n, uint16_t link, const uint8_t *p, size_t len, int64_t now)
{
    if (!s_ota.serving || len != REQUEST_LEN || ah_be32(p) != s_ota.serve.version) {
        return;
    }
    const uint32_t offset = ah_be32(p + 4);
    if (offset >= s_ota.serve.size) {
        return;
    }
    uint32_t n_bytes = ah_be16(p + 8);
    const uint32_t cap = piece_cap(n, link);
    n_bytes = n_bytes < cap ? n_bytes : cap;
    n_bytes = n_bytes < s_ota.serve.size - offset ? n_bytes : s_ota.serve.size - offset;
    if (n_bytes == 0) {
        return;
    }
    uint8_t out[CHUNK_HEADER + CHUNK_MAX];
    ah_put_be32(out, s_ota.serve.version);
    ah_put_be32(out + 4, offset);
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (running != NULL && esp_partition_read(running, offset, out + CHUNK_HEADER, n_bytes) == ESP_OK) {
        send(n, link, AH_TYPE_OTA_CHUNK, out, CHUNK_HEADER + n_bytes, now);
    }
}

void ah_ota_on_frame(ah_node_t *n, uint16_t link, const uint8_t *bytes, size_t len, int64_t now_ms)
{
    ah_node_link_info_t info;
    ah_frame_t f;
    // Only from the node bound to this very link, addressed to us: an OTA
    // packet that crossed anything else is not ours to act on.
    if (!s_ota.enabled || !ah_node_link_info(n, link, &info) || info.kind != AH_LINK_BLE || !info.peer_is_node ||
            !ah_frame_parse(bytes, len, &f) || f.compressed || !ah_frame_is_for(&f, s_ota.self) ||
            memcmp(f.sender, info.peer_id, AH_PEER_ID_LEN) != 0) {
        return;
    }
    switch (f.type) {
    case AH_TYPE_OTA_MANIFEST:
        if (s_ota.manifest_ms[link] != 0 && now_ms - s_ota.manifest_ms[link] < MANIFEST_INTERVAL_MS) {
            break;
        }
        s_ota.manifest_ms[link] = now_ms;
        on_manifest(n, link, f.payload, f.payload_len, now_ms);
        break;
    case AH_TYPE_OTA_REQUEST:
        on_request(n, link, f.payload, f.payload_len, now_ms);
        break;
    case AH_TYPE_OTA_CHUNK:
        on_chunk(n, link, f.payload, f.payload_len, now_ms);
        break;
    case AH_TYPE_OTA_STATUS:
        ESP_LOGI(TAG, "neighbor reports update status 0x%02x", f.payload_len > 0 ? f.payload[0] : 0xFF);
        break;
    default:
        break;
    }
}

static void offer(ah_node_t *n, int64_t now)
{
    for (uint16_t i = 0; i < CONFIG_AH_LINKS; ++i) {
        ah_node_link_info_t info;
        if (!ah_node_link_info(n, i, &info) || info.kind != AH_LINK_BLE || !info.peer_is_node ||
                info.peer_firmware == 0 || info.peer_firmware >= s_ota.serve.version ||
                (s_ota.offered_ms[i] != 0 && now - s_ota.offered_ms[i] < OFFER_INTERVAL_MS)) {
            continue;
        }
        s_ota.offered_ms[i] = now;
        send(n, i, AH_TYPE_OTA_MANIFEST, s_ota.serve.raw, AH_OTA_MANIFEST_LEN, now);
    }
}

void ah_ota_tick(ah_node_t *n, int64_t now_ms)
{
    if (s_ota.on_trial && now_ms >= s_ota.trial_retry_ms) {
        // Healthy once it has run past what a bad image fails at a few minutes
        // in (the first clock save, deposit, beacon or sync round) and a
        // neighbor's announce has verified over a live link; or after a long
        // uptime with no crash, so a site with no one around keeps it.
        const bool proven = now_ms >= CONFIG_AH_OTA_TRIAL_MIN * 60000LL && ah_node_stats(n)->links_bound > 0;
        if (proven || now_ms > CONFIG_AH_OTA_TRIAL_FALLBACK_MIN * 60000LL) {
            // Until it is marked, the image stays on trial: esp_ota_begin
            // refuses every update, and a reset rolls it back.
            if (esp_ota_mark_app_valid_cancel_rollback() == ESP_OK) {
                s_ota.on_trial = false;
                ESP_LOGI(TAG, "image %06lx kept (%s)", (unsigned long)s_ota.running,
                         proven ? "verified link" : "uptime");
            } else {
                s_ota.trial_retry_ms = now_ms + TRIAL_RETRY_MS;
                ESP_LOGW(TAG, "image %06lx could not be marked kept; trying again", (unsigned long)s_ota.running);
            }
        }
    }
    if (s_ota.reboot_at_ms != 0 && now_ms >= s_ota.reboot_at_ms) {
        esp_restart();
    }
    // A server answering just inside each timeout would hold the transfer for
    // hours: below this rate it is given up and held off as a failed one is.
    if (s_ota.active && now_ms - s_ota.started_ms > MIN_RATE_GRACE_MS && too_slow(now_ms)) {
        ESP_LOGW(TAG, "update from a slow server given up at %lu of %lu bytes", (unsigned long)s_ota.offset,
                 (unsigned long)s_ota.rx.size);
        hold_off_failed(now_ms);
        end_transfer();
    }
    if (s_ota.active && now_ms - s_ota.asked_ms >= REQUEST_TIMEOUT_MS) {
        ah_node_link_info_t info;
        if (++s_ota.retries > REQUEST_RETRIES || !ah_node_link_info(n, s_ota.link, &info) || !info.peer_is_node) {
            ESP_LOGW(TAG, "update abandoned at %lu of %lu bytes", (unsigned long)s_ota.offset,
                     (unsigned long)s_ota.rx.size);
            // A server that drops the link before the rate check, and offers
            // again, would otherwise hold the update off for good.
            if (too_slow(now_ms)) {
                hold_off_failed(now_ms);
            }
            end_transfer();
        } else {
            request(n, now_ms);
        }
    }
    // An image on trial is not offered on: it spreads only once kept.
    if (s_ota.serving && !s_ota.on_trial && !s_ota.active && s_ota.reboot_at_ms == 0) {
        offer(n, now_ms);
    }
}
