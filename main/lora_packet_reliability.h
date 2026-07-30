#ifndef LORA_PACKET_RELIABILITY_H
#define LORA_PACKET_RELIABILITY_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LORA_SELECTIVE_REPEAT_MAX_FRAGMENTS 8
#define LORA_SELECTIVE_REPEAT_ROUNDS 8

typedef struct {
    uint8_t fragment_total;
    uint8_t acknowledged_mask;
    uint8_t sent_this_round_mask;
    uint8_t round_index;
    bool complete;
    bool aborted;
    uint8_t abort_reason;
} lora_selective_tx_t;

typedef struct {
    uint32_t feedback_wait_ms;
    uint32_t round_ms;
    uint32_t progress_timeout_ms;
    uint32_t absolute_timeout_ms;
    uint32_t completed_retention_ms;
} lora_reliability_timing_t;

uint8_t lora_fragment_mask(uint8_t fragment_total);

bool lora_selective_tx_init(
    lora_selective_tx_t *state, uint8_t fragment_total);

/* Returns the next useful fragment in this round, or -1 after every currently
 * missing fragment has been sent. When only COMPLETE is missing, the final
 * fragment is used as a bounded completion probe. */
int lora_selective_tx_next_fragment(const lora_selective_tx_t *state);

bool lora_selective_tx_note_sent(
    lora_selective_tx_t *state, uint8_t fragment_index);

bool lora_selective_tx_apply_bitmap(
    lora_selective_tx_t *state, uint8_t received_mask);

bool lora_selective_tx_apply_complete(
    lora_selective_tx_t *state, uint8_t received_mask);

void lora_selective_tx_apply_abort(
    lora_selective_tx_t *state, uint8_t reason);

/* Starts another bounded selective-repeat round. False means the retry budget
 * has been exhausted and the caller must abort the transfer. */
bool lora_selective_tx_next_round(
    lora_selective_tx_t *state, uint8_t maximum_rounds);

/* Keep one bounded reassembly slot available for addressed traffic. Addressed
 * transfers may use every slot; broadcast transfers must leave one free. */
bool lora_reassembly_admit(
    bool addressed, uint8_t slots_in_use, uint8_t slot_capacity);

/* Airtime inputs already include SF, bandwidth, coding rate, preamble, and
 * frame length. The resulting deadlines therefore scale with both the active
 * PHY and the transfer's fragment count. */
bool lora_reliability_timing(
    uint32_t maximum_data_airtime_ms,
    uint32_t control_airtime_ms,
    uint8_t fragment_total,
    uint8_t maximum_rounds,
    uint32_t contention_allowance_ms,
    lora_reliability_timing_t *out);

/* Allocation-free exact-length validation for an encoded BitChat v1/v2 packet.
 * This is intentionally narrower than decoding: COMPLETE depends only on the
 * authenticated wire length, not on allocating or interpreting its payload. */
bool lora_bitchat_packet_length_valid(
    const uint8_t *packet, uint16_t packet_len,
    uint16_t maximum_packet_len);

#ifdef __cplusplus
}
#endif

#endif
