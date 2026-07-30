#include "lora_packet_reliability.h"

#include <limits.h>
#include <string.h>

static bool add_u32(uint32_t left, uint32_t right, uint32_t *out)
{
    if (UINT32_MAX - left < right) {
        return false;
    }
    *out = left + right;
    return true;
}

static bool multiply_u32(uint32_t value, uint32_t count, uint32_t *out)
{
    if (count != 0 && value > UINT32_MAX / count) {
        return false;
    }
    *out = value * count;
    return true;
}

uint8_t lora_fragment_mask(uint8_t fragment_total)
{
    if (fragment_total == 0 ||
        fragment_total > LORA_SELECTIVE_REPEAT_MAX_FRAGMENTS) {
        return 0;
    }
    return (uint8_t)((1u << fragment_total) - 1u);
}

bool lora_selective_tx_init(
    lora_selective_tx_t *state, uint8_t fragment_total)
{
    if (!state || lora_fragment_mask(fragment_total) == 0) {
        return false;
    }
    memset(state, 0, sizeof(*state));
    state->fragment_total = fragment_total;
    return true;
}

int lora_selective_tx_next_fragment(const lora_selective_tx_t *state)
{
    if (!state || state->complete || state->aborted) {
        return -1;
    }
    uint8_t wanted = lora_fragment_mask(state->fragment_total);
    if (wanted == 0) {
        return -1;
    }
    uint8_t missing = (uint8_t)(wanted & ~state->acknowledged_mask);
    if (missing == 0) {
        missing = (uint8_t)(1u << (state->fragment_total - 1u));
    }
    uint8_t useful =
        (uint8_t)(missing & ~state->sent_this_round_mask);
    for (uint8_t index = 0; index < state->fragment_total; ++index) {
        if ((useful & (1u << index)) != 0) {
            return index;
        }
    }
    return -1;
}

bool lora_selective_tx_note_sent(
    lora_selective_tx_t *state, uint8_t fragment_index)
{
    if (!state || fragment_index >= state->fragment_total ||
        state->complete || state->aborted) {
        return false;
    }
    state->sent_this_round_mask |= (uint8_t)(1u << fragment_index);
    return true;
}

bool lora_selective_tx_apply_bitmap(
    lora_selective_tx_t *state, uint8_t received_mask)
{
    uint8_t wanted =
        state ? lora_fragment_mask(state->fragment_total) : 0;
    if (!state || wanted == 0 || received_mask == 0 ||
        (received_mask & ~wanted) != 0 || state->complete ||
        state->aborted) {
        return false;
    }
    state->acknowledged_mask |= received_mask;
    return true;
}

bool lora_selective_tx_apply_complete(
    lora_selective_tx_t *state, uint8_t received_mask)
{
    uint8_t wanted =
        state ? lora_fragment_mask(state->fragment_total) : 0;
    if (!state || wanted == 0 || received_mask != wanted ||
        state->aborted) {
        return false;
    }
    state->acknowledged_mask = wanted;
    state->complete = true;
    return true;
}

void lora_selective_tx_apply_abort(
    lora_selective_tx_t *state, uint8_t reason)
{
    if (!state || reason == 0 || state->complete) {
        return;
    }
    state->aborted = true;
    state->abort_reason = reason;
}

bool lora_selective_tx_next_round(
    lora_selective_tx_t *state, uint8_t maximum_rounds)
{
    if (!state || maximum_rounds == 0 || state->complete ||
        state->aborted ||
        (uint8_t)(state->round_index + 1u) >= maximum_rounds) {
        return false;
    }
    state->round_index++;
    state->sent_this_round_mask = 0;
    return true;
}

bool lora_reassembly_admit(
    bool addressed, uint8_t slots_in_use, uint8_t slot_capacity)
{
    if (slot_capacity == 0 || slots_in_use >= slot_capacity) {
        return false;
    }
    return addressed || (uint8_t)(slots_in_use + 1u) < slot_capacity;
}

bool lora_reliability_timing(
    uint32_t maximum_data_airtime_ms,
    uint32_t control_airtime_ms,
    uint8_t fragment_total,
    uint8_t maximum_rounds,
    uint32_t contention_allowance_ms,
    lora_reliability_timing_t *out)
{
    if (!out || maximum_data_airtime_ms == 0 ||
        control_airtime_ms == 0 ||
        lora_fragment_mask(fragment_total) == 0 ||
        maximum_rounds == 0) {
        return false;
    }

    uint32_t data_opportunity = 0;
    uint32_t control_opportunity = 0;
    uint32_t data_round = 0;
    uint32_t round = 0;
    uint32_t progress = 0;
    uint32_t lifetime = 0;
    uint32_t retention = 0;
    if (!add_u32(maximum_data_airtime_ms,
                 contention_allowance_ms, &data_opportunity) ||
        !add_u32(control_airtime_ms,
                 contention_allowance_ms, &control_opportunity) ||
        !multiply_u32(data_opportunity, fragment_total, &data_round) ||
        !add_u32(data_round, control_opportunity, &round) ||
        !multiply_u32(round, 2, &progress) ||
        !multiply_u32(round, maximum_rounds, &lifetime) ||
        !add_u32(lifetime, round, &retention)) {
        return false;
    }

    out->feedback_wait_ms = control_opportunity;
    out->round_ms = round;
    out->progress_timeout_ms = progress;
    out->absolute_timeout_ms = lifetime;
    out->completed_retention_ms = retention;
    return true;
}

bool lora_bitchat_packet_length_valid(
    const uint8_t *packet, uint16_t packet_len,
    uint16_t maximum_packet_len)
{
    if (!packet || packet_len < 22 ||
        packet_len > maximum_packet_len) {
        return false;
    }
    uint8_t version = packet[0];
    uint8_t flags = packet[11];
    uint32_t payload_len = 0;
    uint32_t expected = 0;
    if (version == 1) {
        payload_len =
            ((uint16_t)packet[12] << 8) | packet[13];
        expected = 22u;
    } else if (version == 2 && packet_len >= 24) {
        payload_len =
            ((uint32_t)packet[12] << 24) |
            ((uint32_t)packet[13] << 16) |
            ((uint32_t)packet[14] << 8) |
            packet[15];
        expected = 24u;
    } else {
        return false;
    }
    if ((flags & 0x01u) != 0) {
        expected += 8;
    }
    if (version == 2 && (flags & 0x08u) != 0) {
        if (expected >= packet_len) {
            return false;
        }
        uint8_t route_count = packet[expected];
        expected += 1u + (uint32_t)route_count * 8u;
    }
    expected += payload_len;
    if ((flags & 0x02u) != 0) {
        expected += 64;
    }
    return expected == packet_len;
}
