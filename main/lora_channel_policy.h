#ifndef LORA_CHANNEL_POLICY_H
#define LORA_CHANNEL_POLICY_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LORA_CHANNEL_ACK_BURST_MAX 4
#define LORA_CHANNEL_BEACON_REPETITIONS 3

typedef struct {
    uint32_t minimum_ms;
    uint32_t maximum_ms;
} lora_contention_window_t;

/* Derive a bounded software-backoff window from the frame's actual airtime.
 * Relayed broadcasts receive an additional randomized defer so receivers of
 * the same frame do not rebroadcast in lockstep. */
bool lora_contention_window(
    uint32_t airtime_ms, uint8_t busy_attempt, bool relayed_broadcast,
    lora_contention_window_t *out);

uint32_t lora_contention_delay(
    const lora_contention_window_t *window, uint32_t entropy);

/* Serial-number comparison for 32-bit freshness counters. Equal values and
 * values at the ambiguous half-range are not newer. */
bool lora_freshness_newer(uint32_t candidate, uint32_t current);

#ifdef __cplusplus
}
#endif

#endif
