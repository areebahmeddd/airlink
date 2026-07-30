#include "lora_link_adaptation.h"

#include <limits.h>
#include <string.h>

#define EWMA_SCALE 256
#define PERCENT_SCALE 100
#define MAX_TRACKED_LATENCY_MS 3600000U

static uint16_t increment_sample(uint16_t value)
{
    return value == UINT16_MAX ? value : (uint16_t)(value + 1u);
}

static uint8_t increment_streak(uint8_t value)
{
    return value == UINT8_MAX ? value : (uint8_t)(value + 1u);
}

static int32_t ewma_q8(
    int32_t current, int32_t sample, uint16_t prior_samples)
{
    if (prior_samples == 0) {
        return sample * EWMA_SCALE;
    }
    int64_t accumulated =
        (int64_t)current * 3 + (int64_t)sample * EWMA_SCALE;
    return (int32_t)(accumulated / 4);
}

static lora_link_metrics_t *find_entry(
    lora_link_adaptation_t *state,
    const uint8_t node_id[LORA_LINK_ADAPTATION_NODE_ID_LEN],
    bool create, uint64_t now_ms)
{
    if (!state || !node_id) {
        return NULL;
    }
    lora_link_metrics_t *free_entry = NULL;
    lora_link_metrics_t *oldest = NULL;
    for (size_t index = 0;
         index < LORA_LINK_ADAPTATION_CAPACITY; ++index) {
        lora_link_metrics_t *entry = &state->entries[index];
        if (entry->in_use &&
            memcmp(
                entry->node_id, node_id,
                LORA_LINK_ADAPTATION_NODE_ID_LEN) == 0) {
            return entry;
        }
        if (!entry->in_use && !free_entry) {
            free_entry = entry;
        }
        if (entry->in_use &&
            (!oldest ||
             entry->last_update_ms < oldest->last_update_ms)) {
            oldest = entry;
        }
    }
    if (!create) {
        return NULL;
    }
    lora_link_metrics_t *entry =
        free_entry ? free_entry : oldest;
    if (!entry) {
        return NULL;
    }
    memset(entry, 0, sizeof(*entry));
    entry->in_use = true;
    entry->last_update_ms = now_ms;
    memcpy(
        entry->node_id, node_id,
        LORA_LINK_ADAPTATION_NODE_ID_LEN);
    return entry;
}

static const lora_link_metrics_t *find_const_entry(
    const lora_link_adaptation_t *state,
    const uint8_t node_id[LORA_LINK_ADAPTATION_NODE_ID_LEN])
{
    if (!state || !node_id) {
        return NULL;
    }
    for (size_t index = 0;
         index < LORA_LINK_ADAPTATION_CAPACITY; ++index) {
        const lora_link_metrics_t *entry =
            &state->entries[index];
        if (entry->in_use &&
            memcmp(
                entry->node_id, node_id,
                LORA_LINK_ADAPTATION_NODE_ID_LEN) == 0) {
            return entry;
        }
    }
    return NULL;
}

void lora_link_adaptation_init(lora_link_adaptation_t *state)
{
    if (state) {
        memset(state, 0, sizeof(*state));
    }
}

void lora_link_adaptation_note_signal(
    lora_link_adaptation_t *state,
    const uint8_t node_id[LORA_LINK_ADAPTATION_NODE_ID_LEN],
    int16_t rssi_dbm, int8_t snr_db, uint64_t now_ms)
{
    lora_link_metrics_t *entry =
        find_entry(state, node_id, true, now_ms);
    if (!entry) {
        return;
    }
    entry->rssi_q8 =
        ewma_q8(entry->rssi_q8, rssi_dbm, entry->signal_samples);
    entry->snr_q8 =
        ewma_q8(entry->snr_q8, snr_db, entry->signal_samples);
    entry->signal_samples =
        increment_sample(entry->signal_samples);
    entry->last_update_ms = now_ms;
}

void lora_link_adaptation_note_ack(
    lora_link_adaptation_t *state,
    const uint8_t node_id[LORA_LINK_ADAPTATION_NODE_ID_LEN],
    bool success, uint64_t now_ms)
{
    lora_link_metrics_t *entry =
        find_entry(state, node_id, true, now_ms);
    if (!entry) {
        return;
    }
    entry->ack_success_q8 =
        ewma_q8(
            entry->ack_success_q8, success ? 1 : 0,
            entry->ack_samples);
    entry->ack_samples = increment_sample(entry->ack_samples);
    entry->last_update_ms = now_ms;
}

static bool signal_is_poor(const lora_link_metrics_t *entry)
{
    return entry->signal_samples >= 2 &&
           (entry->snr_q8 <= -8 * EWMA_SCALE ||
            entry->rssi_q8 <= -115 * EWMA_SCALE);
}

static bool signal_is_stable(const lora_link_metrics_t *entry)
{
    return entry->signal_samples >= 4 &&
           entry->snr_q8 >= 2 * EWMA_SCALE &&
           entry->rssi_q8 >= -105 * EWMA_SCALE;
}

static bool ack_is_stable(const lora_link_metrics_t *entry)
{
    return entry->ack_samples < 3 ||
           entry->ack_success_q8 >=
               (90 * EWMA_SCALE) / PERCENT_SCALE;
}

void lora_link_adaptation_note_delivery(
    lora_link_adaptation_t *state,
    const uint8_t node_id[LORA_LINK_ADAPTATION_NODE_ID_LEN],
    bool success, uint8_t retries, uint32_t latency_ms,
    uint64_t now_ms)
{
    lora_link_metrics_t *entry =
        find_entry(state, node_id, true, now_ms);
    if (!entry) {
        return;
    }
    uint16_t prior_samples = entry->data_samples;
    uint32_t bounded_latency =
        latency_ms > MAX_TRACKED_LATENCY_MS
            ? MAX_TRACKED_LATENCY_MS
            : latency_ms;
    entry->data_success_q8 =
        ewma_q8(
            entry->data_success_q8, success ? 1 : 0,
            prior_samples);
    entry->retries_q8 =
        ewma_q8(entry->retries_q8, retries, prior_samples);
    entry->latency_ms_q8 =
        ewma_q8(
            entry->latency_ms_q8, (int32_t)bounded_latency,
            prior_samples);
    entry->data_samples = increment_sample(prior_samples);
    entry->last_update_ms = now_ms;

    /* Delivery timeout already captures a missing terminal ACK. Do not feed
     * the historical ACK EWMA back into the poor/healthy streaks: doing so
     * would keep a recovered link weak long after four consecutive successful
     * deliveries. The ACK EWMA remains a separate metric and a guard on entry
     * to the stable throughput profile. */
    bool poor =
        !success || retries >= 2 || signal_is_poor(entry);
    bool healthy =
        success && retries <= 1 && !signal_is_poor(entry);
    bool stable =
        success && retries == 0 && signal_is_stable(entry) &&
        ack_is_stable(entry) &&
        entry->data_success_q8 >=
            (94 * EWMA_SCALE) / PERCENT_SCALE &&
        entry->retries_q8 <= EWMA_SCALE / 2;

    entry->poor_streak =
        poor ? increment_streak(entry->poor_streak) : 0;
    entry->healthy_streak =
        healthy ? increment_streak(entry->healthy_streak) : 0;
    entry->stable_streak =
        stable ? increment_streak(entry->stable_streak) : 0;

    if (entry->poor_streak >= 2) {
        entry->profile = LORA_LINK_PROFILE_WEAK;
    } else if (
        entry->profile == LORA_LINK_PROFILE_WEAK &&
        entry->healthy_streak >= 4) {
        entry->profile = LORA_LINK_PROFILE_BALANCED;
    } else if (
        entry->data_samples >= 8 &&
        entry->stable_streak >= 6) {
        entry->profile = LORA_LINK_PROFILE_STABLE;
    } else if (
        entry->profile == LORA_LINK_PROFILE_STABLE && poor) {
        entry->profile = LORA_LINK_PROFILE_BALANCED;
    } else if (
        entry->profile == LORA_LINK_PROFILE_UNKNOWN &&
        entry->data_samples >= 4) {
        entry->profile = LORA_LINK_PROFILE_BALANCED;
    }
}

lora_link_policy_t lora_link_adaptation_policy(
    const lora_link_adaptation_t *state,
    const uint8_t node_id[LORA_LINK_ADAPTATION_NODE_ID_LEN])
{
    lora_link_policy_t policy = {
        .fragment_size = LORA_LINK_CHUNK_STABLE,
        .maximum_rounds = LORA_LINK_ROUNDS_DEFAULT,
        .profile = LORA_LINK_PROFILE_UNKNOWN,
    };
    const lora_link_metrics_t *entry =
        find_const_entry(state, node_id);
    if (!entry) {
        return policy;
    }
    policy.profile = entry->profile;
    if (entry->profile == LORA_LINK_PROFILE_WEAK) {
        policy.fragment_size = LORA_LINK_CHUNK_WEAK;
        policy.maximum_rounds = LORA_LINK_ROUNDS_WEAK;
    } else if (entry->profile == LORA_LINK_PROFILE_BALANCED) {
        policy.fragment_size = LORA_LINK_CHUNK_BALANCED;
    } else if (entry->profile == LORA_LINK_PROFILE_STABLE) {
        policy.maximum_rounds = LORA_LINK_ROUNDS_STABLE;
    }
    return policy;
}

static int16_t q8_to_x10(int32_t value)
{
    int32_t converted = (value * 10) / EWMA_SCALE;
    if (converted > INT16_MAX) {
        return INT16_MAX;
    }
    if (converted < INT16_MIN) {
        return INT16_MIN;
    }
    return (int16_t)converted;
}

static uint8_t q8_to_percent(int32_t value)
{
    int32_t converted =
        (value * PERCENT_SCALE + EWMA_SCALE / 2) / EWMA_SCALE;
    if (converted < 0) {
        return 0;
    }
    if (converted > 100) {
        return 100;
    }
    return (uint8_t)converted;
}

bool lora_link_adaptation_snapshot(
    const lora_link_adaptation_t *state,
    const uint8_t node_id[LORA_LINK_ADAPTATION_NODE_ID_LEN],
    lora_link_metrics_snapshot_t *out)
{
    const lora_link_metrics_t *entry =
        find_const_entry(state, node_id);
    if (!entry || !out) {
        return false;
    }
    *out = (lora_link_metrics_snapshot_t) {
        .signal_samples = entry->signal_samples,
        .data_samples = entry->data_samples,
        .ack_samples = entry->ack_samples,
        .rssi_x10 = q8_to_x10(entry->rssi_q8),
        .snr_x10 = q8_to_x10(entry->snr_q8),
        .data_success_pct =
            q8_to_percent(entry->data_success_q8),
        .ack_success_pct =
            q8_to_percent(entry->ack_success_q8),
        .retries_x100 =
            (uint16_t)(
                entry->retries_q8 > 0
                    ? ((int64_t)entry->retries_q8 * 100 +
                       EWMA_SCALE / 2) /
                          EWMA_SCALE
                    : 0),
        .latency_ms =
            entry->latency_ms_q8 > 0
                ? (uint32_t)(
                      (entry->latency_ms_q8 + EWMA_SCALE / 2) /
                      EWMA_SCALE)
                : 0,
        .profile = entry->profile,
    };
    return true;
}

size_t lora_link_adaptation_count(
    const lora_link_adaptation_t *state)
{
    if (!state) {
        return 0;
    }
    size_t count = 0;
    for (size_t index = 0;
         index < LORA_LINK_ADAPTATION_CAPACITY; ++index) {
        if (state->entries[index].in_use) {
            count++;
        }
    }
    return count;
}

bool lora_link_fragment_size_valid(uint16_t fragment_size)
{
    return fragment_size == LORA_LINK_CHUNK_WEAK ||
           fragment_size == LORA_LINK_CHUNK_BALANCED ||
           fragment_size == LORA_LINK_CHUNK_STABLE;
}
