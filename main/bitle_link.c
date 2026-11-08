#include "bitle_link.h"

#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "bitle_route.h"

static const char *TAG = "bitle_link";

typedef struct {
    bool in_use;
    uint16_t handle;
    bitle_link_type_t type;
    bitle_link_send_fn_t send_fn;
    bitle_link_relay_fn_t relay_fn;
    bitle_link_reserve_fn_t reserve_fn;
    bitle_link_commit_fn_t commit_fn;
    bitle_link_cancel_fn_t cancel_fn;
} link_entry_t;

static link_entry_t s_links[BITLE_LINK_MAX];
static SemaphoreHandle_t s_lock;

esp_err_t bitle_link_init(void)
{
    s_lock = xSemaphoreCreateMutex();
    return s_lock ? ESP_OK : ESP_ERR_NO_MEM;
}

static link_entry_t *find_locked(uint16_t handle)
{
    for (size_t i = 0; i < BITLE_LINK_MAX; ++i) {
        if (s_links[i].in_use && s_links[i].handle == handle) {
            return &s_links[i];
        }
    }
    return NULL;
}

esp_err_t bitle_link_register(uint16_t handle, bitle_link_type_t type, bitle_link_send_fn_t send_fn)
{
    return bitle_link_register_reservable(
        handle, type, send_fn, NULL, NULL, NULL);
}

esp_err_t bitle_link_register_reservable(
    uint16_t handle, bitle_link_type_t type, bitle_link_send_fn_t send_fn,
    bitle_link_reserve_fn_t reserve_fn, bitle_link_commit_fn_t commit_fn,
    bitle_link_cancel_fn_t cancel_fn)
{
    return bitle_link_register_reservable_relay(
        handle, type, send_fn, NULL, reserve_fn, commit_fn,
        cancel_fn);
}

esp_err_t bitle_link_register_reservable_relay(
    uint16_t handle, bitle_link_type_t type, bitle_link_send_fn_t send_fn,
    bitle_link_relay_fn_t relay_fn,
    bitle_link_reserve_fn_t reserve_fn, bitle_link_commit_fn_t commit_fn,
    bitle_link_cancel_fn_t cancel_fn)
{
    bool incomplete_reservation =
        (reserve_fn || commit_fn || cancel_fn) &&
        !(reserve_fn && commit_fn && cancel_fn);
    if (!send_fn || handle == BITLE_LINK_NONE || incomplete_reservation) {
        return ESP_ERR_INVALID_ARG;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    link_entry_t *e = find_locked(handle);
    if (!e) {
        for (size_t i = 0; i < BITLE_LINK_MAX; ++i) {
            if (!s_links[i].in_use) {
                e = &s_links[i];
                break;
            }
        }
    }
    if (!e) {
        xSemaphoreGive(s_lock);
        ESP_LOGW(TAG, "link table full; cannot register handle=%u", handle);
        return ESP_ERR_NO_MEM;
    }
    e->in_use = true;
    e->handle = handle;
    e->type = type;
    e->send_fn = send_fn;
    e->relay_fn = relay_fn;
    e->reserve_fn = reserve_fn;
    e->commit_fn = commit_fn;
    e->cancel_fn = cancel_fn;
    xSemaphoreGive(s_lock);
    ESP_LOGI(TAG, "link up handle=%u type=%s", handle, type == BITLE_LINK_BLE ? "ble" : "lora");
    return ESP_OK;
}

void bitle_link_unregister(uint16_t handle)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    link_entry_t *e = find_locked(handle);
    if (e) {
        memset(e, 0, sizeof(*e));
    }
    xSemaphoreGive(s_lock);
    /* Any peer-ID -> link mapping through this handle is now dangling. */
    bitle_route_link_down(handle);
}

bool bitle_link_ready(uint16_t handle)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool ready = find_locked(handle) != NULL;
    xSemaphoreGive(s_lock);
    return ready;
}

int bitle_link_type_of(uint16_t handle)
{
    int type = -1;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    link_entry_t *e = find_locked(handle);
    if (e) {
        type = e->type;
    }
    xSemaphoreGive(s_lock);
    return type;
}

bitle_link_send_result_t bitle_link_send_detailed(
    uint16_t handle, const uint8_t *data, uint16_t len)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    link_entry_t *e = find_locked(handle);
    bitle_link_send_fn_t fn = e ? e->send_fn : NULL;
    xSemaphoreGive(s_lock);
    if (!fn) {
        return BITLE_LINK_SEND_FAILED;
    }
    /* Send outside the lock: transport sends may block briefly. */
    return fn(handle, data, len);
}

bitle_link_send_result_t bitle_link_reserve_send(
    uint16_t handle, uint8_t packet_type, bitle_link_reservation_t *out)
{
    if (!out) {
        return BITLE_LINK_SEND_FAILED;
    }
    memset(out, 0, sizeof(*out));
    xSemaphoreTake(s_lock, portMAX_DELAY);
    link_entry_t *entry = find_locked(handle);
    bitle_link_reserve_fn_t reserve_fn =
        entry ? entry->reserve_fn : NULL;
    bitle_link_commit_fn_t commit_fn =
        entry ? entry->commit_fn : NULL;
    bitle_link_cancel_fn_t cancel_fn =
        entry ? entry->cancel_fn : NULL;
    xSemaphoreGive(s_lock);
    if (!reserve_fn || !commit_fn || !cancel_fn) {
        return BITLE_LINK_SEND_FAILED;
    }

    uintptr_t token = 0;
    bitle_link_send_result_t result =
        reserve_fn(handle, packet_type, &token);
    if (result == BITLE_LINK_SEND_ACCEPTED) {
        out->handle = handle;
        out->token = token;
        out->commit_fn = commit_fn;
        out->cancel_fn = cancel_fn;
        out->active = true;
    }
    return result;
}

bitle_link_send_result_t bitle_link_commit_send(
    bitle_link_reservation_t *reservation, const uint8_t *data, uint16_t len)
{
    if (!reservation || !reservation->active ||
        !reservation->commit_fn) {
        return BITLE_LINK_SEND_FAILED;
    }
    bitle_link_commit_fn_t commit_fn = reservation->commit_fn;
    uint16_t handle = reservation->handle;
    uintptr_t token = reservation->token;
    reservation->active = false;
    return commit_fn(handle, token, data, len);
}

void bitle_link_cancel_send(bitle_link_reservation_t *reservation)
{
    if (!reservation || !reservation->active ||
        !reservation->cancel_fn) {
        return;
    }
    bitle_link_cancel_fn_t cancel_fn = reservation->cancel_fn;
    uint16_t handle = reservation->handle;
    uintptr_t token = reservation->token;
    reservation->active = false;
    cancel_fn(handle, token);
}

esp_err_t bitle_link_send(uint16_t handle, const uint8_t *data, uint16_t len)
{
    switch (bitle_link_send_detailed(handle, data, len)) {
    case BITLE_LINK_SEND_ACCEPTED:
        return ESP_OK;
    case BITLE_LINK_SEND_DEFERRED:
        return ESP_ERR_TIMEOUT;
    case BITLE_LINK_SEND_POLICY_DROPPED:
        return ESP_ERR_NOT_SUPPORTED;
    case BITLE_LINK_SEND_FAILED:
    default:
        return ESP_FAIL;
    }
}

int bitle_link_broadcast(uint16_t exclude_a, uint16_t exclude_b, const uint8_t *data, uint16_t len)
{
    /* Snapshot under the lock, send outside it. */
    struct {
        uint16_t handle;
        bitle_link_send_fn_t fn;
    } targets[BITLE_LINK_MAX];
    size_t n = 0;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (size_t i = 0; i < BITLE_LINK_MAX; ++i) {
        if (s_links[i].in_use && s_links[i].handle != exclude_a && s_links[i].handle != exclude_b) {
            targets[n].handle = s_links[i].handle;
            targets[n].fn = s_links[i].send_fn;
            n++;
        }
    }
    xSemaphoreGive(s_lock);

    int sent = 0;
    for (size_t i = 0; i < n; ++i) {
        bitle_link_send_result_t result =
            targets[i].fn(targets[i].handle, data, len);
        if (result == BITLE_LINK_SEND_ACCEPTED) {
            sent++;
        } else if (result == BITLE_LINK_SEND_POLICY_DROPPED) {
            ESP_LOGD(TAG, "broadcast policy drop handle=%u",
                     targets[i].handle);
        } else {
            ESP_LOGW(TAG, "broadcast send not accepted handle=%u result=%d",
                     targets[i].handle, result);
        }
    }
    return sent;
}

int bitle_link_rebroadcast(
    uint16_t source_handle, uint16_t exclude_handle,
    const uint8_t *data, uint16_t len)
{
    struct {
        uint16_t handle;
        bitle_link_send_fn_t fn;
    } targets[BITLE_LINK_MAX];
    size_t count = 0;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (size_t index = 0; index < BITLE_LINK_MAX; ++index) {
        if (!s_links[index].in_use) {
            continue;
        }
        if (s_links[index].handle == exclude_handle) {
            continue;
        }
        bitle_link_send_fn_t fn = s_links[index].send_fn;
        if (s_links[index].handle == source_handle) {
            fn = s_links[index].relay_fn;
        }
        if (fn) {
            targets[count].handle = s_links[index].handle;
            targets[count].fn = fn;
            count++;
        }
    }
    xSemaphoreGive(s_lock);

    int sent = 0;
    for (size_t index = 0; index < count; ++index) {
        bitle_link_send_result_t result =
            targets[index].fn(
                targets[index].handle, data, len);
        if (result == BITLE_LINK_SEND_ACCEPTED) {
            sent++;
        } else if (result == BITLE_LINK_SEND_POLICY_DROPPED) {
            ESP_LOGD(
                TAG, "rebroadcast policy drop handle=%u",
                targets[index].handle);
        } else {
            ESP_LOGW(
                TAG,
                "rebroadcast send not accepted handle=%u result=%d",
                targets[index].handle, result);
        }
    }
    return sent;
}
