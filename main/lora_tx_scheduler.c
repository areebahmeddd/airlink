#include "lora_tx_scheduler.h"

#include <string.h>

/* Six selections bound starvation while favoring latency-sensitive traffic.
 * ACK frames remain outside this scheduler and are bounded separately. */
static const lora_tx_priority_t SCHEDULE[] = {
    LORA_TX_PRIORITY_CONTROL,
    LORA_TX_PRIORITY_USER,
    LORA_TX_PRIORITY_CONTROL,
    LORA_TX_PRIORITY_DISCOVERY,
    LORA_TX_PRIORITY_USER,
    LORA_TX_PRIORITY_BULK,
};

void lora_tx_scheduler_init(lora_tx_scheduler_t *scheduler)
{
    if (scheduler) {
        memset(scheduler, 0, sizeof(*scheduler));
    }
}

static bool priority_valid(lora_tx_priority_t priority)
{
    return priority >= LORA_TX_PRIORITY_CONTROL &&
           priority < LORA_TX_PRIORITY_COUNT;
}

lora_tx_admit_result_t lora_tx_scheduler_reserve(
    lora_tx_scheduler_t *scheduler,
    lora_tx_priority_t priority,
    lora_tx_handle_t *out_handle)
{
    if (out_handle) {
        *out_handle = LORA_TX_HANDLE_INVALID;
    }
    if (!scheduler || !priority_valid(priority)) {
        return LORA_TX_ADMIT_INVALID;
    }

    lora_tx_handle_t handle = LORA_TX_HANDLE_INVALID;
    for (lora_tx_handle_t i = 0; i < LORA_TX_PACKET_POOL_SIZE; ++i) {
        if (!scheduler->in_use[i]) {
            handle = i;
            break;
        }
    }
    if (handle == LORA_TX_HANDLE_INVALID) {
        scheduler->metrics.deferred[priority]++;
        return LORA_TX_ADMIT_DEFERRED;
    }

    scheduler->in_use[handle] = true;
    memset(&scheduler->packets[handle], 0,
           sizeof(scheduler->packets[handle]));
    scheduler->packets[handle].priority = priority;
    scheduler->metrics.in_use++;
    if (scheduler->metrics.in_use > scheduler->metrics.high_water) {
        scheduler->metrics.high_water = scheduler->metrics.in_use;
    }
    if (out_handle) {
        *out_handle = handle;
    }
    return LORA_TX_ADMIT_ACCEPTED;
}

bool lora_tx_scheduler_commit(
    lora_tx_scheduler_t *scheduler,
    lora_tx_handle_t handle,
    const uint8_t *data,
    uint16_t len,
    uint8_t type,
    uint16_t sequence)
{
    if (!scheduler || handle >= LORA_TX_PACKET_POOL_SIZE ||
        !scheduler->in_use[handle] || !data || len == 0 ||
        len > LORA_TX_PACKET_MAX_LEN ||
        scheduler->packets[handle].len != 0) {
        return false;
    }
    lora_tx_packet_t *packet = &scheduler->packets[handle];
    packet->len = len;
    packet->sequence = sequence;
    packet->type = type;
    memcpy(packet->data, data, len);

    lora_tx_priority_t priority = packet->priority;
    lora_tx_handle_t *queue = scheduler->queues[priority];
    queue[scheduler->queue_tail[priority]] = handle;
    scheduler->queue_tail[priority] =
        (scheduler->queue_tail[priority] + 1) % LORA_TX_PACKET_POOL_SIZE;
    scheduler->queue_count[priority]++;
    scheduler->metrics.accepted[priority]++;
    return true;
}

lora_tx_admit_result_t lora_tx_scheduler_admit(
    lora_tx_scheduler_t *scheduler,
    const uint8_t *data,
    uint16_t len,
    uint8_t type,
    lora_tx_priority_t priority,
    uint16_t sequence,
    lora_tx_handle_t *out_handle)
{
    if (!scheduler || !data || len == 0 || len > LORA_TX_PACKET_MAX_LEN ||
        !priority_valid(priority)) {
        if (out_handle) {
            *out_handle = LORA_TX_HANDLE_INVALID;
        }
        return LORA_TX_ADMIT_INVALID;
    }
    lora_tx_admit_result_t result =
        lora_tx_scheduler_reserve(scheduler, priority, out_handle);
    if (result != LORA_TX_ADMIT_ACCEPTED) {
        return result;
    }
    if (!lora_tx_scheduler_commit(
            scheduler, *out_handle, data, len, type, sequence)) {
        lora_tx_scheduler_cancel(scheduler, *out_handle);
        *out_handle = LORA_TX_HANDLE_INVALID;
        return LORA_TX_ADMIT_INVALID;
    }
    return LORA_TX_ADMIT_ACCEPTED;
}

bool lora_tx_scheduler_dequeue(lora_tx_scheduler_t *scheduler,
                               lora_tx_handle_t *out_handle)
{
    if (!scheduler || !out_handle) {
        return false;
    }
    *out_handle = LORA_TX_HANDLE_INVALID;
    const size_t schedule_len = sizeof(SCHEDULE) / sizeof(SCHEDULE[0]);
    for (size_t checked = 0; checked < schedule_len; ++checked) {
        lora_tx_priority_t priority = SCHEDULE[scheduler->schedule_cursor];
        scheduler->schedule_cursor =
            (scheduler->schedule_cursor + 1) % schedule_len;
        if (scheduler->queue_count[priority] == 0) {
            continue;
        }
        lora_tx_handle_t *queue = scheduler->queues[priority];
        *out_handle = queue[scheduler->queue_head[priority]];
        scheduler->queue_head[priority] =
            (scheduler->queue_head[priority] + 1) % LORA_TX_PACKET_POOL_SIZE;
        scheduler->queue_count[priority]--;
        return true;
    }
    return false;
}

const lora_tx_packet_t *lora_tx_scheduler_packet(
    const lora_tx_scheduler_t *scheduler, lora_tx_handle_t handle)
{
    if (!scheduler || handle >= LORA_TX_PACKET_POOL_SIZE ||
        !scheduler->in_use[handle]) {
        return NULL;
    }
    return &scheduler->packets[handle];
}

bool lora_tx_scheduler_release(lora_tx_scheduler_t *scheduler,
                               lora_tx_handle_t handle)
{
    if (!scheduler || handle >= LORA_TX_PACKET_POOL_SIZE ||
        !scheduler->in_use[handle]) {
        return false;
    }
    scheduler->in_use[handle] = false;
    memset(&scheduler->packets[handle], 0, sizeof(scheduler->packets[handle]));
    scheduler->metrics.in_use--;
    scheduler->metrics.released++;
    return true;
}

bool lora_tx_scheduler_cancel(lora_tx_scheduler_t *scheduler,
                              lora_tx_handle_t handle)
{
    if (!scheduler || handle >= LORA_TX_PACKET_POOL_SIZE ||
        !scheduler->in_use[handle] ||
        scheduler->packets[handle].len != 0) {
        return false;
    }
    scheduler->in_use[handle] = false;
    memset(&scheduler->packets[handle], 0,
           sizeof(scheduler->packets[handle]));
    scheduler->metrics.in_use--;
    scheduler->metrics.cancelled++;
    return true;
}

size_t lora_tx_scheduler_cancel_all(lora_tx_scheduler_t *scheduler)
{
    if (!scheduler) {
        return 0;
    }
    size_t cancelled = 0;
    for (lora_tx_handle_t handle = 0;
         handle < LORA_TX_PACKET_POOL_SIZE; ++handle) {
        if (scheduler->in_use[handle]) {
            scheduler->in_use[handle] = false;
            memset(&scheduler->packets[handle], 0,
                   sizeof(scheduler->packets[handle]));
            cancelled++;
        }
    }
    memset(scheduler->queues, 0, sizeof(scheduler->queues));
    memset(scheduler->queue_head, 0, sizeof(scheduler->queue_head));
    memset(scheduler->queue_tail, 0, sizeof(scheduler->queue_tail));
    memset(scheduler->queue_count, 0, sizeof(scheduler->queue_count));
    scheduler->schedule_cursor = 0;
    scheduler->metrics.in_use = 0;
    scheduler->metrics.cancelled += cancelled;
    return cancelled;
}

uint8_t lora_tx_scheduler_depth(const lora_tx_scheduler_t *scheduler)
{
    return scheduler ? scheduler->metrics.in_use : 0;
}

uint8_t lora_tx_scheduler_queued(const lora_tx_scheduler_t *scheduler)
{
    if (!scheduler) {
        return 0;
    }
    uint8_t queued = 0;
    for (size_t priority = 0; priority < LORA_TX_PRIORITY_COUNT; ++priority) {
        queued += scheduler->queue_count[priority];
    }
    return queued;
}

void lora_tx_scheduler_metrics(const lora_tx_scheduler_t *scheduler,
                               lora_tx_scheduler_metrics_t *out)
{
    if (scheduler && out) {
        *out = scheduler->metrics;
    }
}
