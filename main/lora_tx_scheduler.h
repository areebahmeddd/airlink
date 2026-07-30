#ifndef LORA_TX_SCHEDULER_H
#define LORA_TX_SCHEDULER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LORA_TX_PACKET_POOL_SIZE 12
#define LORA_TX_PACKET_MAX_LEN   587
#define LORA_TX_HANDLE_INVALID   UINT8_MAX

typedef uint8_t lora_tx_handle_t;

typedef enum {
    LORA_TX_PRIORITY_CONTROL = 0,
    LORA_TX_PRIORITY_USER,
    LORA_TX_PRIORITY_DISCOVERY,
    LORA_TX_PRIORITY_BULK,
    LORA_TX_PRIORITY_COUNT,
} lora_tx_priority_t;

typedef enum {
    LORA_TX_ADMIT_ACCEPTED = 0,
    LORA_TX_ADMIT_DEFERRED,
    LORA_TX_ADMIT_INVALID,
} lora_tx_admit_result_t;

typedef struct {
    uint16_t len;
    uint16_t sequence;
    uint8_t type;
    lora_tx_priority_t priority;
    uint8_t data[LORA_TX_PACKET_MAX_LEN];
} lora_tx_packet_t;

typedef struct {
    uint32_t accepted[LORA_TX_PRIORITY_COUNT];
    uint32_t deferred[LORA_TX_PRIORITY_COUNT];
    uint32_t released;
    uint32_t cancelled;
    uint8_t in_use;
    uint8_t high_water;
} lora_tx_scheduler_metrics_t;

typedef struct {
    bool in_use[LORA_TX_PACKET_POOL_SIZE];
    lora_tx_packet_t packets[LORA_TX_PACKET_POOL_SIZE];
    lora_tx_handle_t queues[LORA_TX_PRIORITY_COUNT][LORA_TX_PACKET_POOL_SIZE];
    uint8_t queue_head[LORA_TX_PRIORITY_COUNT];
    uint8_t queue_tail[LORA_TX_PRIORITY_COUNT];
    uint8_t queue_count[LORA_TX_PRIORITY_COUNT];
    uint8_t schedule_cursor;
    lora_tx_scheduler_metrics_t metrics;
} lora_tx_scheduler_t;

void lora_tx_scheduler_init(lora_tx_scheduler_t *scheduler);

/* Reserves one pool slot before a producer irreversibly advances protocol
 * state. The slot is invisible to the consumer until committed. */
lora_tx_admit_result_t lora_tx_scheduler_reserve(
    lora_tx_scheduler_t *scheduler,
    lora_tx_priority_t priority,
    lora_tx_handle_t *out_handle);

bool lora_tx_scheduler_commit(
    lora_tx_scheduler_t *scheduler,
    lora_tx_handle_t handle,
    const uint8_t *data,
    uint16_t len,
    uint8_t type,
    uint16_t sequence);

/* Copies one complete packet into the static pool and makes it visible to the
 * consumer atomically. A deferred result consumes no pool or queue entry. */
lora_tx_admit_result_t lora_tx_scheduler_admit(
    lora_tx_scheduler_t *scheduler,
    const uint8_t *data,
    uint16_t len,
    uint8_t type,
    lora_tx_priority_t priority,
    uint16_t sequence,
    lora_tx_handle_t *out_handle);

/* Weighted scheduling gives control/user traffic more service while every
 * continuously non-empty priority is selected within one schedule rotation. */
bool lora_tx_scheduler_dequeue(lora_tx_scheduler_t *scheduler,
                               lora_tx_handle_t *out_handle);

const lora_tx_packet_t *lora_tx_scheduler_packet(
    const lora_tx_scheduler_t *scheduler, lora_tx_handle_t handle);

/* Release after all fragments complete or after terminal failure. */
bool lora_tx_scheduler_release(lora_tx_scheduler_t *scheduler,
                               lora_tx_handle_t handle);

/* Cancels a producer reservation that was never committed. */
bool lora_tx_scheduler_cancel(lora_tx_scheduler_t *scheduler,
                              lora_tx_handle_t handle);

/* Cancel queued and in-flight slots during shutdown. Returns slots released. */
size_t lora_tx_scheduler_cancel_all(lora_tx_scheduler_t *scheduler);

uint8_t lora_tx_scheduler_depth(const lora_tx_scheduler_t *scheduler);
uint8_t lora_tx_scheduler_queued(const lora_tx_scheduler_t *scheduler);
void lora_tx_scheduler_metrics(const lora_tx_scheduler_t *scheduler,
                               lora_tx_scheduler_metrics_t *out);

#ifdef __cplusplus
}
#endif

#endif /* LORA_TX_SCHEDULER_H */
