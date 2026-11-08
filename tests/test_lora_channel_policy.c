#include "lora_channel_policy.h"

#include <assert.h>
#include <stdio.h>

int main(void)
{
    lora_contention_window_t short_frame;
    lora_contention_window_t long_frame;
    assert(!lora_contention_window(0, 0, false, &short_frame));
    assert(lora_contention_window(100, 0, false, &short_frame));
    assert(lora_contention_window(1500, 0, false, &long_frame));
    assert(long_frame.minimum_ms > short_frame.minimum_ms);
    assert(long_frame.maximum_ms > short_frame.maximum_ms);

    lora_contention_window_t retry;
    lora_contention_window_t relay;
    assert(lora_contention_window(1500, 2, false, &retry));
    assert(lora_contention_window(1500, 2, true, &relay));
    assert(retry.minimum_ms > long_frame.minimum_ms);
    assert(relay.minimum_ms > retry.minimum_ms);
    assert(lora_contention_delay(&relay, 0) == relay.minimum_ms);
    assert(lora_contention_delay(&relay, UINT32_MAX) >=
           relay.minimum_ms);
    assert(lora_contention_delay(&relay, UINT32_MAX) <=
           relay.maximum_ms);

    assert(lora_freshness_newer(2, 1));
    assert(!lora_freshness_newer(1, 1));
    assert(lora_freshness_newer(0, UINT32_MAX));
    assert(!lora_freshness_newer(UINT32_MAX, 0));
    assert(!lora_freshness_newer(0x80000000u, 0));

    puts("lora_channel_policy: ok");
    return 0;
}
