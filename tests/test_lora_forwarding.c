#include "lora_forwarding.h"

#include <assert.h>
#include <string.h>

int main(void)
{
    uint8_t packet[64];
    memset(packet, 0xA5, sizeof(packet));
    packet[2] = 7;
    uint64_t fingerprint =
        lora_forward_fingerprint(packet, sizeof(packet));
    packet[2] = 2;
    assert(lora_forward_fingerprint(packet, sizeof(packet)) ==
           fingerprint);
    packet[3] ^= 1;
    assert(lora_forward_fingerprint(packet, sizeof(packet)) !=
           fingerprint);

    assert(lora_forward_hop_allowed(3, 0));
    assert(lora_forward_hop_allowed(3, 2));
    assert(!lora_forward_hop_allowed(3, 3));
    assert(!lora_forward_hop_allowed(0, 0));
    assert(!lora_forward_hop_allowed(
        LORA_FORWARD_MAX_HOP_LIMIT + 1, 0));

    uint32_t strong =
        lora_forward_delay_ms(1000, 10, 17);
    uint32_t weak =
        lora_forward_delay_ms(1000, -12, 17);
    assert(strong < weak);
    assert(lora_forward_delay_ms(2000, 10, 17) > strong);
    assert(lora_forward_delay_ms(0, 0, 0) == 0);

    lora_forward_cache_t cache;
    lora_forward_cache_init(&cache);
    uint8_t source_a[8] = {1};
    uint8_t source_b[8] = {2};
    assert(lora_forward_cache_observe(
               &cache, source_a, fingerprint, 2, -8, 1000) ==
           LORA_FORWARD_NEW);
    assert(lora_forward_cache_observe(
               &cache, source_a, fingerprint, 2, -10, 1100) ==
           LORA_FORWARD_DUPLICATE);
    assert(lora_forward_cache_observe(
               &cache, source_a, fingerprint, 1, 2, 1200) ==
           LORA_FORWARD_BETTER_COPY);
    assert(lora_forward_cache_observe(
               &cache, source_b, fingerprint, 1, 2, 1300) ==
           LORA_FORWARD_NEW);
    assert(lora_forward_cache_observe(
               &cache, source_a, fingerprint, 0, 5,
               1000 + LORA_FORWARD_CACHE_RETENTION_MS) ==
           LORA_FORWARD_NEW);

    for (uint64_t index = 0;
         index < LORA_FORWARD_CACHE_CAPACITY + 8; ++index) {
        uint8_t source[8] = {0};
        source[0] = (uint8_t)(index + 3);
        assert(lora_forward_cache_observe(
                   &cache, source, index + 11, 1, 0,
                   2000 + index) == LORA_FORWARD_NEW);
    }
    return 0;
}
