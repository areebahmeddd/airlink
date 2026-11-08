#include "lora_channel_policy.h"

#include <limits.h>

static uint32_t clamp_u32(uint64_t value, uint32_t maximum)
{
    return value > maximum ? maximum : (uint32_t)value;
}

bool lora_contention_window(
    uint32_t airtime_ms, uint8_t busy_attempt, bool relayed_broadcast,
    lora_contention_window_t *out)
{
    if (!out || airtime_ms == 0) {
        return false;
    }

    uint64_t minimum = airtime_ms / 4u;
    if (minimum < 30u) {
        minimum = 30u;
    }
    minimum += (uint64_t)busy_attempt * (airtime_ms / 8u);
    if (relayed_broadcast) {
        minimum += airtime_ms / 2u;
    }

    uint64_t spread = airtime_ms;
    if (spread < 120u) {
        spread = 120u;
    }
    spread += (uint64_t)busy_attempt * (airtime_ms / 4u);
    if (relayed_broadcast) {
        spread += airtime_ms / 2u;
    }

    out->minimum_ms = clamp_u32(minimum, 15000u);
    out->maximum_ms =
        clamp_u32(minimum + spread, 20000u);
    if (out->maximum_ms < out->minimum_ms) {
        out->maximum_ms = out->minimum_ms;
    }
    return true;
}

uint32_t lora_contention_delay(
    const lora_contention_window_t *window, uint32_t entropy)
{
    if (!window || window->maximum_ms < window->minimum_ms) {
        return 0;
    }
    uint32_t span = window->maximum_ms - window->minimum_ms;
    if (span == UINT32_MAX) {
        return entropy;
    }
    return window->minimum_ms + entropy % (span + 1u);
}

bool lora_freshness_newer(uint32_t candidate, uint32_t current)
{
    uint32_t distance = candidate - current;
    return distance != 0 && distance < 0x80000000u;
}
