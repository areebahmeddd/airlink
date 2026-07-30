#include "lora_tx_scheduler.h"

#include <assert.h>
#include <pthread.h>
#include <string.h>

static lora_tx_handle_t admit(lora_tx_scheduler_t *scheduler,
                              uint8_t marker, lora_tx_priority_t priority)
{
    uint8_t packet[64];
    memset(packet, marker, sizeof(packet));
    lora_tx_handle_t handle = LORA_TX_HANDLE_INVALID;
    assert(lora_tx_scheduler_admit(
               scheduler, packet, sizeof(packet), marker, priority,
               marker, &handle) == LORA_TX_ADMIT_ACCEPTED);
    assert(handle != LORA_TX_HANDLE_INVALID);
    return handle;
}

typedef struct {
    lora_tx_scheduler_t *scheduler;
    pthread_mutex_t *lock;
    uint8_t marker;
    lora_tx_priority_t priority;
    unsigned attempts;
    unsigned *accepted;
    unsigned *deferred;
} producer_args_t;

static void *run_producer(void *opaque)
{
    producer_args_t *args = opaque;
    for (unsigned attempt = 0; attempt < args->attempts; ++attempt) {
        uint8_t packet[64];
        memset(packet, args->marker, sizeof(packet));
        lora_tx_handle_t handle = LORA_TX_HANDLE_INVALID;
        pthread_mutex_lock(args->lock);
        lora_tx_admit_result_t result = lora_tx_scheduler_admit(
            args->scheduler, packet, sizeof(packet), args->marker,
            args->priority, (uint16_t)(args->marker * 100 + attempt),
            &handle);
        if (result == LORA_TX_ADMIT_ACCEPTED) {
            (*args->accepted)++;
        } else {
            assert(result == LORA_TX_ADMIT_DEFERRED);
            (*args->deferred)++;
            assert(handle == LORA_TX_HANDLE_INVALID);
        }
        pthread_mutex_unlock(args->lock);
    }
    return NULL;
}

int main(void)
{
    lora_tx_scheduler_t scheduler;
    lora_tx_scheduler_init(&scheduler);

    /* Saturation is atomic: the rejected producer consumes no slot and no
     * fragment-like partial state, regardless of packet size. */
    for (uint8_t i = 0; i < LORA_TX_PACKET_POOL_SIZE; ++i) {
        admit(&scheduler, i, (lora_tx_priority_t)(i % LORA_TX_PRIORITY_COUNT));
    }
    uint8_t maximum_packet[LORA_TX_PACKET_MAX_LEN] = {0};
    lora_tx_handle_t rejected = 0;
    assert(lora_tx_scheduler_admit(
               &scheduler, maximum_packet, sizeof(maximum_packet), 0xA2,
               LORA_TX_PRIORITY_BULK, 99, &rejected) ==
           LORA_TX_ADMIT_DEFERRED);
    assert(rejected == LORA_TX_HANDLE_INVALID);
    assert(lora_tx_scheduler_depth(&scheduler) == LORA_TX_PACKET_POOL_SIZE);
    assert(lora_tx_scheduler_cancel_all(&scheduler) == LORA_TX_PACKET_POOL_SIZE);
    assert(lora_tx_scheduler_depth(&scheduler) == 0);
    assert(lora_tx_scheduler_queued(&scheduler) == 0);

    /* A pre-encryption reservation owns capacity without exposing a partial
     * packet. Commit publishes it once; cancellation returns the slot. */
    lora_tx_handle_t reservation = LORA_TX_HANDLE_INVALID;
    assert(lora_tx_scheduler_reserve(
               &scheduler, LORA_TX_PRIORITY_USER, &reservation) ==
           LORA_TX_ADMIT_ACCEPTED);
    assert(lora_tx_scheduler_depth(&scheduler) == 1);
    assert(lora_tx_scheduler_queued(&scheduler) == 0);
    uint8_t reserved_packet[64];
    memset(reserved_packet, 0x51, sizeof(reserved_packet));
    assert(lora_tx_scheduler_commit(
        &scheduler, reservation, reserved_packet, sizeof(reserved_packet),
        0x11, 77));
    assert(lora_tx_scheduler_queued(&scheduler) == 1);
    assert(lora_tx_scheduler_dequeue(&scheduler, &rejected));
    assert(rejected == reservation);
    assert(lora_tx_scheduler_release(&scheduler, reservation));

    assert(lora_tx_scheduler_reserve(
               &scheduler, LORA_TX_PRIORITY_CONTROL, &reservation) ==
           LORA_TX_ADMIT_ACCEPTED);
    assert(lora_tx_scheduler_cancel(&scheduler, reservation));
    assert(lora_tx_scheduler_depth(&scheduler) == 0);

    /* FIFO ordering is preserved within each class. */
    lora_tx_handle_t user_a = admit(&scheduler, 10, LORA_TX_PRIORITY_USER);
    lora_tx_handle_t user_b = admit(&scheduler, 11, LORA_TX_PRIORITY_USER);
    lora_tx_handle_t dequeued = LORA_TX_HANDLE_INVALID;
    assert(lora_tx_scheduler_dequeue(&scheduler, &dequeued));
    assert(dequeued == user_a);
    assert(lora_tx_scheduler_release(&scheduler, dequeued));
    assert(lora_tx_scheduler_dequeue(&scheduler, &dequeued));
    assert(dequeued == user_b);
    assert(lora_tx_scheduler_release(&scheduler, dequeued));

    /* Concurrent producer classes all receive service inside one six-entry
     * schedule rotation; none can be starved by a full higher-priority class. */
    lora_tx_scheduler_init(&scheduler);
    bool served[LORA_TX_PRIORITY_COUNT] = {false};
    for (uint8_t priority = 0; priority < LORA_TX_PRIORITY_COUNT; ++priority) {
        admit(&scheduler, 20 + priority, (lora_tx_priority_t)priority);
    }
    for (size_t i = 0; i < 6; ++i) {
        if (!lora_tx_scheduler_dequeue(&scheduler, &dequeued)) {
            break;
        }
        const lora_tx_packet_t *packet =
            lora_tx_scheduler_packet(&scheduler, dequeued);
        assert(packet);
        served[packet->priority] = true;
        assert(lora_tx_scheduler_release(&scheduler, dequeued));
    }
    for (size_t priority = 0; priority < LORA_TX_PRIORITY_COUNT; ++priority) {
        assert(served[priority]);
    }

    /* Cancellation after an in-flight dequeue returns every pool slot. */
    lora_tx_scheduler_init(&scheduler);
    admit(&scheduler, 30, LORA_TX_PRIORITY_CONTROL);
    admit(&scheduler, 31, LORA_TX_PRIORITY_DISCOVERY);
    assert(lora_tx_scheduler_dequeue(&scheduler, &dequeued));
    assert(lora_tx_scheduler_cancel_all(&scheduler) == 2);
    lora_tx_scheduler_metrics_t metrics;
    lora_tx_scheduler_metrics(&scheduler, &metrics);
    assert(metrics.in_use == 0);
    assert(metrics.cancelled == 2);

    /* Two producers racing for the final slot get exactly one acceptance and
     * one pre-transmission backpressure result. */
    lora_tx_scheduler_init(&scheduler);
    for (uint8_t i = 0; i < LORA_TX_PACKET_POOL_SIZE - 1; ++i) {
        admit(&scheduler, 40 + i, LORA_TX_PRIORITY_USER);
    }
    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    unsigned accepted = 0;
    unsigned deferred = 0;
    producer_args_t final_slot[] = {
        {&scheduler, &lock, 0x61, LORA_TX_PRIORITY_CONTROL, 1,
         &accepted, &deferred},
        {&scheduler, &lock, 0x62, LORA_TX_PRIORITY_USER, 1,
         &accepted, &deferred},
    };
    pthread_t final_threads[2];
    for (size_t i = 0; i < 2; ++i) {
        assert(pthread_create(
                   &final_threads[i], NULL, run_producer,
                   &final_slot[i]) == 0);
    }
    for (size_t i = 0; i < 2; ++i) {
        assert(pthread_join(final_threads[i], NULL) == 0);
    }
    assert(accepted == 1);
    assert(deferred == 1);
    assert(lora_tx_scheduler_depth(&scheduler) ==
           LORA_TX_PACKET_POOL_SIZE);
    assert(lora_tx_scheduler_cancel_all(&scheduler) ==
           LORA_TX_PACKET_POOL_SIZE);

    /* Five real producer classes contend through the firmware's locking
     * contract: BLE relay, Noise response, beacon, courier, and sync. Exactly
     * the bounded pool is accepted; every visible packet is a complete copy. */
    lora_tx_scheduler_init(&scheduler);
    accepted = 0;
    deferred = 0;
    producer_args_t producers[] = {
        {&scheduler, &lock, 0x02, LORA_TX_PRIORITY_USER, 8,
         &accepted, &deferred},     /* BLE relay */
        {&scheduler, &lock, 0x11, LORA_TX_PRIORITY_USER, 8,
         &accepted, &deferred},     /* Noise response */
        {&scheduler, &lock, 0x01, LORA_TX_PRIORITY_DISCOVERY, 8,
         &accepted, &deferred},     /* beacon */
        {&scheduler, &lock, 0x04, LORA_TX_PRIORITY_USER, 8,
         &accepted, &deferred},     /* courier */
        {&scheduler, &lock, 0x21, LORA_TX_PRIORITY_CONTROL, 8,
         &accepted, &deferred},     /* sync */
    };
    pthread_t threads[sizeof(producers) / sizeof(producers[0])];
    for (size_t i = 0; i < sizeof(threads) / sizeof(threads[0]); ++i) {
        assert(pthread_create(
                   &threads[i], NULL, run_producer, &producers[i]) == 0);
    }
    for (size_t i = 0; i < sizeof(threads) / sizeof(threads[0]); ++i) {
        assert(pthread_join(threads[i], NULL) == 0);
    }
    assert(accepted == LORA_TX_PACKET_POOL_SIZE);
    assert(deferred ==
           (sizeof(producers) / sizeof(producers[0])) * 8 -
               LORA_TX_PACKET_POOL_SIZE);
    assert(lora_tx_scheduler_depth(&scheduler) ==
           LORA_TX_PACKET_POOL_SIZE);
    while (lora_tx_scheduler_dequeue(&scheduler, &dequeued)) {
        const lora_tx_packet_t *packet =
            lora_tx_scheduler_packet(&scheduler, dequeued);
        assert(packet && packet->len == 64);
        for (size_t i = 0; i < packet->len; ++i) {
            assert(packet->data[i] == packet->type);
        }
        assert(lora_tx_scheduler_release(&scheduler, dequeued));
    }
    assert(lora_tx_scheduler_depth(&scheduler) == 0);
    assert(pthread_mutex_destroy(&lock) == 0);
    return 0;
}
