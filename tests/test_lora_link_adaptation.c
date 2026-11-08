#include "lora_link_adaptation.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void node_id(uint8_t out[8], uint8_t value)
{
    memset(out, value, 8);
}

static void test_default_and_bounds(void)
{
    lora_link_adaptation_t state;
    uint8_t peer[8];
    node_id(peer, 1);
    lora_link_adaptation_init(&state);

    lora_link_policy_t policy =
        lora_link_adaptation_policy(&state, peer);
    assert(policy.profile == LORA_LINK_PROFILE_UNKNOWN);
    assert(policy.fragment_size == LORA_LINK_CHUNK_STABLE);
    assert(policy.maximum_rounds == LORA_LINK_ROUNDS_DEFAULT);
    assert(lora_link_fragment_size_valid(LORA_LINK_CHUNK_WEAK));
    assert(lora_link_fragment_size_valid(LORA_LINK_CHUNK_BALANCED));
    assert(lora_link_fragment_size_valid(LORA_LINK_CHUNK_STABLE));
    assert(!lora_link_fragment_size_valid(103));
    assert(!lora_link_fragment_size_valid(121));
}

static void test_weak_link_and_recovery(void)
{
    lora_link_adaptation_t state;
    uint8_t peer[8];
    node_id(peer, 2);
    lora_link_adaptation_init(&state);

    for (uint64_t sample = 0; sample < 2; ++sample) {
        lora_link_adaptation_note_signal(
            &state, peer, -121, -12, sample * 100);
        lora_link_adaptation_note_ack(
            &state, peer, false, sample * 100 + 1);
        lora_link_adaptation_note_delivery(
            &state, peer, false, 3, 5000,
            sample * 100 + 2);
    }
    lora_link_policy_t policy =
        lora_link_adaptation_policy(&state, peer);
    assert(policy.profile == LORA_LINK_PROFILE_WEAK);
    assert(policy.fragment_size == LORA_LINK_CHUNK_WEAK);
    assert(policy.maximum_rounds == LORA_LINK_ROUNDS_WEAK);

    for (uint64_t sample = 0; sample < 3; ++sample) {
        lora_link_adaptation_note_signal(
            &state, peer, -92, 8, 1000 + sample * 100);
        lora_link_adaptation_note_ack(
            &state, peer, true, 1001 + sample * 100);
        lora_link_adaptation_note_delivery(
            &state, peer, true, 1, 900,
            1002 + sample * 100);
    }
    policy = lora_link_adaptation_policy(&state, peer);
    assert(policy.profile == LORA_LINK_PROFILE_WEAK);

    lora_link_adaptation_note_signal(&state, peer, -92, 8, 1300);
    lora_link_adaptation_note_ack(&state, peer, true, 1301);
    lora_link_adaptation_note_delivery(
        &state, peer, true, 1, 900, 1302);
    policy = lora_link_adaptation_policy(&state, peer);
    assert(policy.profile == LORA_LINK_PROFILE_BALANCED);
    assert(policy.fragment_size == LORA_LINK_CHUNK_BALANCED);
    assert(policy.maximum_rounds == LORA_LINK_ROUNDS_DEFAULT);
}

static void test_stable_link_recovers_throughput(void)
{
    lora_link_adaptation_t state;
    uint8_t peer[8];
    node_id(peer, 3);
    lora_link_adaptation_init(&state);

    for (uint64_t sample = 0; sample < 10; ++sample) {
        lora_link_adaptation_note_signal(
            &state, peer, -88, 9, sample * 50);
        lora_link_adaptation_note_ack(
            &state, peer, true, sample * 50 + 1);
        lora_link_adaptation_note_delivery(
            &state, peer, true, 0, 700,
            sample * 50 + 2);
    }
    lora_link_policy_t policy =
        lora_link_adaptation_policy(&state, peer);
    assert(policy.profile == LORA_LINK_PROFILE_STABLE);
    assert(policy.fragment_size == LORA_LINK_CHUNK_STABLE);
    assert(policy.maximum_rounds == LORA_LINK_ROUNDS_STABLE);

    lora_link_metrics_snapshot_t metrics;
    assert(lora_link_adaptation_snapshot(
        &state, peer, &metrics));
    assert(metrics.signal_samples == 10);
    assert(metrics.data_samples == 10);
    assert(metrics.ack_samples == 10);
    assert(metrics.rssi_x10 == -880);
    assert(metrics.snr_x10 == 90);
    assert(metrics.data_success_pct == 100);
    assert(metrics.ack_success_pct == 100);
    assert(metrics.retries_x100 == 0);
    assert(metrics.latency_ms == 700);

    lora_link_adaptation_note_delivery(
        &state, peer, false, 2, 5000, 1000);
    policy = lora_link_adaptation_policy(&state, peer);
    assert(policy.profile == LORA_LINK_PROFILE_BALANCED);
    assert(policy.fragment_size == LORA_LINK_CHUNK_BALANCED);
    assert(policy.maximum_rounds == LORA_LINK_ROUNDS_DEFAULT);
}

static void test_balanced_hysteresis(void)
{
    lora_link_adaptation_t state;
    uint8_t peer[8];
    node_id(peer, 4);
    lora_link_adaptation_init(&state);

    for (uint64_t sample = 0; sample < 4; ++sample) {
        lora_link_adaptation_note_signal(
            &state, peer, -108, -3, sample * 50);
        lora_link_adaptation_note_ack(
            &state, peer, true, sample * 50 + 1);
        lora_link_adaptation_note_delivery(
            &state, peer, true, 1, 1600,
            sample * 50 + 2);
    }
    lora_link_policy_t policy =
        lora_link_adaptation_policy(&state, peer);
    assert(policy.profile == LORA_LINK_PROFILE_BALANCED);
    assert(policy.fragment_size == LORA_LINK_CHUNK_BALANCED);
    assert(policy.maximum_rounds == LORA_LINK_ROUNDS_DEFAULT);

    lora_link_adaptation_note_delivery(
        &state, peer, false, 4, 5000, 1000);
    policy = lora_link_adaptation_policy(&state, peer);
    assert(policy.profile == LORA_LINK_PROFILE_BALANCED);
    lora_link_adaptation_note_delivery(
        &state, peer, false, 4, 5000, 1100);
    policy = lora_link_adaptation_policy(&state, peer);
    assert(policy.profile == LORA_LINK_PROFILE_WEAK);
}

static void test_bounded_lru_table(void)
{
    lora_link_adaptation_t state;
    lora_link_adaptation_init(&state);
    uint8_t peer[8];
    for (uint8_t value = 1;
         value <= LORA_LINK_ADAPTATION_CAPACITY; ++value) {
        node_id(peer, value);
        lora_link_adaptation_note_signal(
            &state, peer, -100, 0, value);
    }
    assert(lora_link_adaptation_count(&state) ==
           LORA_LINK_ADAPTATION_CAPACITY);

    uint8_t oldest[8];
    node_id(oldest, 1);
    uint8_t replacement[8];
    node_id(replacement, 99);
    lora_link_adaptation_note_signal(
        &state, replacement, -90, 5, 1000);
    assert(lora_link_adaptation_count(&state) ==
           LORA_LINK_ADAPTATION_CAPACITY);
    lora_link_metrics_snapshot_t metrics;
    assert(!lora_link_adaptation_snapshot(
        &state, oldest, &metrics));
    assert(lora_link_adaptation_snapshot(
        &state, replacement, &metrics));
}

int main(void)
{
    test_default_and_bounds();
    test_weak_link_and_recovery();
    test_stable_link_recovers_throughput();
    test_balanced_hysteresis();
    test_bounded_lru_table();
    puts("lora_link_adaptation: ok");
    return 0;
}
