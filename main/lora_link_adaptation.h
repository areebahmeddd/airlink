#ifndef LORA_LINK_ADAPTATION_H
#define LORA_LINK_ADAPTATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LORA_LINK_ADAPTATION_NODE_ID_LEN 8
#define LORA_LINK_ADAPTATION_CAPACITY 12

#define LORA_LINK_CHUNK_WEAK 104
#define LORA_LINK_CHUNK_BALANCED 112
#define LORA_LINK_CHUNK_STABLE 120

#define LORA_LINK_ROUNDS_STABLE 6
#define LORA_LINK_ROUNDS_DEFAULT 8
#define LORA_LINK_ROUNDS_WEAK 10

typedef enum {
    LORA_LINK_PROFILE_UNKNOWN = 0,
    LORA_LINK_PROFILE_BALANCED,
    LORA_LINK_PROFILE_WEAK,
    LORA_LINK_PROFILE_STABLE,
} lora_link_profile_t;

typedef struct {
    uint16_t fragment_size;
    uint8_t maximum_rounds;
    lora_link_profile_t profile;
} lora_link_policy_t;

typedef struct {
    bool in_use;
    uint8_t node_id[LORA_LINK_ADAPTATION_NODE_ID_LEN];
    uint64_t last_update_ms;
    uint16_t signal_samples;
    uint16_t data_samples;
    uint16_t ack_samples;
    int32_t rssi_q8;
    int32_t snr_q8;
    int32_t data_success_q8;
    int32_t ack_success_q8;
    int32_t retries_q8;
    int32_t latency_ms_q8;
    uint8_t healthy_streak;
    uint8_t poor_streak;
    uint8_t stable_streak;
    lora_link_profile_t profile;
} lora_link_metrics_t;

typedef struct {
    lora_link_metrics_t entries[LORA_LINK_ADAPTATION_CAPACITY];
} lora_link_adaptation_t;

typedef struct {
    uint16_t signal_samples;
    uint16_t data_samples;
    uint16_t ack_samples;
    int16_t rssi_x10;
    int16_t snr_x10;
    uint8_t data_success_pct;
    uint8_t ack_success_pct;
    uint16_t retries_x100;
    uint32_t latency_ms;
    lora_link_profile_t profile;
} lora_link_metrics_snapshot_t;

void lora_link_adaptation_init(lora_link_adaptation_t *state);

void lora_link_adaptation_note_signal(
    lora_link_adaptation_t *state,
    const uint8_t node_id[LORA_LINK_ADAPTATION_NODE_ID_LEN],
    int16_t rssi_dbm, int8_t snr_db, uint64_t now_ms);

void lora_link_adaptation_note_ack(
    lora_link_adaptation_t *state,
    const uint8_t node_id[LORA_LINK_ADAPTATION_NODE_ID_LEN],
    bool success, uint64_t now_ms);

void lora_link_adaptation_note_delivery(
    lora_link_adaptation_t *state,
    const uint8_t node_id[LORA_LINK_ADAPTATION_NODE_ID_LEN],
    bool success, uint8_t retries, uint32_t latency_ms,
    uint64_t now_ms);

lora_link_policy_t lora_link_adaptation_policy(
    const lora_link_adaptation_t *state,
    const uint8_t node_id[LORA_LINK_ADAPTATION_NODE_ID_LEN]);

bool lora_link_adaptation_snapshot(
    const lora_link_adaptation_t *state,
    const uint8_t node_id[LORA_LINK_ADAPTATION_NODE_ID_LEN],
    lora_link_metrics_snapshot_t *out);

size_t lora_link_adaptation_count(
    const lora_link_adaptation_t *state);

bool lora_link_fragment_size_valid(uint16_t fragment_size);

#ifdef __cplusplus
}
#endif

#endif /* LORA_LINK_ADAPTATION_H */
