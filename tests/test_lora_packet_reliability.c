#include "lora_airtime.h"
#include "lora_packet_reliability.h"

#include <assert.h>
#include <stdio.h>

static uint32_t frame_airtime(uint8_t sf, uint16_t length)
{
    lora_airtime_params_t params = {
        .spreading_factor = sf,
        .bandwidth_hz = 125000,
        .coding_rate = 5,
        .preamble_symbols = 16,
        .explicit_header = true,
        .crc_enabled = true,
    };
    return lora_airtime_ms(&params, length);
}

static void test_selective_repeat(void)
{
    lora_selective_tx_t state;
    assert(lora_selective_tx_init(&state, 5));
    for (int expected = 0; expected < 5; ++expected) {
        assert(lora_selective_tx_next_fragment(&state) == expected);
        assert(lora_selective_tx_note_sent(
            &state, (uint8_t)expected));
    }
    assert(lora_selective_tx_next_fragment(&state) == -1);

    assert(lora_selective_tx_apply_bitmap(&state, 0x15));
    assert(lora_selective_tx_next_round(
        &state, LORA_SELECTIVE_REPEAT_ROUNDS));
    assert(lora_selective_tx_next_fragment(&state) == 1);
    assert(lora_selective_tx_note_sent(&state, 1));
    assert(lora_selective_tx_next_fragment(&state) == 3);
    assert(lora_selective_tx_note_sent(&state, 3));
    assert(lora_selective_tx_next_fragment(&state) == -1);

    assert(lora_selective_tx_apply_bitmap(&state, 0x1F));
    assert(lora_selective_tx_next_round(
        &state, LORA_SELECTIVE_REPEAT_ROUNDS));
    assert(lora_selective_tx_next_fragment(&state) == 4);
    assert(lora_selective_tx_note_sent(&state, 4));
    assert(lora_selective_tx_apply_complete(&state, 0x1F));
    assert(state.complete);
    assert(lora_selective_tx_next_fragment(&state) == -1);
}

static void test_abort_and_round_bound(void)
{
    lora_selective_tx_t state;
    assert(lora_selective_tx_init(&state, 1));
    for (unsigned round = 1;
         round < LORA_SELECTIVE_REPEAT_ROUNDS; ++round) {
        assert(lora_selective_tx_next_round(
            &state, LORA_SELECTIVE_REPEAT_ROUNDS));
    }
    assert(!lora_selective_tx_next_round(
        &state, LORA_SELECTIVE_REPEAT_ROUNDS));

    assert(lora_selective_tx_init(&state, 3));
    lora_selective_tx_apply_abort(&state, 2);
    assert(state.aborted);
    assert(state.abort_reason == 2);
    assert(lora_selective_tx_next_fragment(&state) == -1);
}

static void test_reassembly_admission(void)
{
    assert(!lora_reassembly_admit(false, 0, 0));
    assert(lora_reassembly_admit(true, 0, 2));
    assert(lora_reassembly_admit(true, 1, 2));
    assert(!lora_reassembly_admit(true, 2, 2));
    assert(lora_reassembly_admit(false, 0, 2));
    assert(!lora_reassembly_admit(false, 1, 2));
    assert(!lora_reassembly_admit(false, 2, 2));
    assert(!lora_reassembly_admit(false, 0, 1));
}

static void test_timing_all_spreading_factors(void)
{
    uint32_t previous = 0;
    for (uint8_t sf = 7; sf <= 12; ++sf) {
        for (uint8_t fragments = 1; fragments <= 5; ++fragments) {
            lora_reliability_timing_t timing;
            assert(lora_reliability_timing(
                frame_airtime(sf, 164),
                frame_airtime(sf, 44),
                fragments,
                LORA_SELECTIVE_REPEAT_ROUNDS,
                1950,
                &timing));
            assert(timing.feedback_wait_ms >
                   frame_airtime(sf, 44));
            assert(timing.round_ms >
                   timing.feedback_wait_ms);
            assert(timing.progress_timeout_ms ==
                   timing.round_ms * 2);
            assert(timing.absolute_timeout_ms ==
                   timing.round_ms *
                       LORA_SELECTIVE_REPEAT_ROUNDS);
            assert(timing.completed_retention_ms >
                   timing.absolute_timeout_ms);
        }
        lora_reliability_timing_t max_timing;
        assert(lora_reliability_timing(
            frame_airtime(sf, 164),
            frame_airtime(sf, 44),
            5,
            LORA_SELECTIVE_REPEAT_ROUNDS,
            1950,
            &max_timing));
        assert(max_timing.absolute_timeout_ms > previous);
        previous = max_timing.absolute_timeout_ms;
    }
}

static void test_exact_bitchat_length(void)
{
    uint8_t packet[100] = {0};
    packet[0] = 1;
    packet[11] = 0x01;
    packet[12] = 0;
    packet[13] = 70;
    assert(lora_bitchat_packet_length_valid(
        packet, sizeof(packet), sizeof(packet)));
    assert(!lora_bitchat_packet_length_valid(
        packet, sizeof(packet) - 1, sizeof(packet)));
    packet[11] = 0x03;
    assert(!lora_bitchat_packet_length_valid(
        packet, sizeof(packet), sizeof(packet)));
    packet[13] = 6;
    assert(lora_bitchat_packet_length_valid(
        packet, sizeof(packet), sizeof(packet)));
    packet[0] = 2;
    assert(!lora_bitchat_packet_length_valid(
        packet, sizeof(packet), sizeof(packet)));
}

int main(void)
{
    test_selective_repeat();
    test_abort_and_round_bound();
    test_reassembly_admission();
    test_timing_all_spreading_factors();
    test_exact_bitchat_length();
    puts("lora_packet_reliability: ok");
    return 0;
}
