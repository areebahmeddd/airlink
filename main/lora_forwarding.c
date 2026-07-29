#include "lora_forwarding.h"

#include <limits.h>
#include <string.h>

void lora_forward_cache_init(lora_forward_cache_t *cache)
{
    if (cache) {
        memset(cache, 0, sizeof(*cache));
    }
}

uint64_t lora_forward_fingerprint(const uint8_t *packet, size_t len)
{
    if (!packet || len == 0) {
        return 0;
    }
    uint64_t hash = 1469598103934665603ULL;
    for (size_t index = 0; index < len; ++index) {
        if (index == 2) {
            continue;
        }
        hash ^= packet[index];
        hash *= 1099511628211ULL;
    }
    return hash == 0 ? 1 : hash;
}

lora_forward_observation_t lora_forward_cache_observe(
    lora_forward_cache_t *cache, const uint8_t source[8],
    uint64_t transfer_fingerprint, uint8_t hop_count, int8_t snr,
    uint64_t now_ms)
{
    if (!cache || !source || transfer_fingerprint == 0) {
        return LORA_FORWARD_DUPLICATE;
    }

    lora_forward_cache_entry_t *free_entry = NULL;
    lora_forward_cache_entry_t *oldest = NULL;
    for (size_t index = 0; index < LORA_FORWARD_CACHE_CAPACITY; ++index) {
        lora_forward_cache_entry_t *entry = &cache->entries[index];
        if (entry->in_use && now_ms >= entry->expires_ms) {
            memset(entry, 0, sizeof(*entry));
        }
        if (!entry->in_use) {
            if (!free_entry) {
                free_entry = entry;
            }
            continue;
        }
        if (memcmp(entry->source, source, sizeof(entry->source)) == 0 &&
            entry->transfer_fingerprint == transfer_fingerprint) {
            bool better =
                hop_count < entry->best_hop_count ||
                (hop_count == entry->best_hop_count &&
                 snr > entry->best_snr);
            if (better) {
                entry->best_hop_count = hop_count;
                entry->best_snr = snr;
                return LORA_FORWARD_BETTER_COPY;
            }
            return LORA_FORWARD_DUPLICATE;
        }
        if (!oldest || entry->expires_ms < oldest->expires_ms) {
            oldest = entry;
        }
    }

    lora_forward_cache_entry_t *entry =
        free_entry ? free_entry : oldest;
    if (!entry) {
        return LORA_FORWARD_DUPLICATE;
    }
    memset(entry, 0, sizeof(*entry));
    entry->in_use = true;
    memcpy(entry->source, source, sizeof(entry->source));
    entry->transfer_fingerprint = transfer_fingerprint;
    entry->expires_ms =
        UINT64_MAX - now_ms < LORA_FORWARD_CACHE_RETENTION_MS
            ? UINT64_MAX
            : now_ms + LORA_FORWARD_CACHE_RETENTION_MS;
    entry->best_hop_count = hop_count;
    entry->best_snr = snr;
    return LORA_FORWARD_NEW;
}

bool lora_forward_hop_allowed(uint8_t hop_limit, uint8_t hop_count)
{
    return hop_limit > 0 &&
           hop_limit <= LORA_FORWARD_MAX_HOP_LIMIT &&
           hop_count < hop_limit;
}

uint32_t lora_forward_delay_ms(
    uint32_t frame_airtime_ms, int8_t snr, uint32_t entropy)
{
    if (frame_airtime_ms == 0) {
        return 0;
    }
    int quality = snr;
    if (quality < -20) {
        quality = -20;
    } else if (quality > 12) {
        quality = 12;
    }

    uint64_t base = frame_airtime_ms / 2u;
    if (base < 100u) {
        base = 100u;
    }
    uint64_t quality_penalty =
        (uint64_t)(12 - quality) * frame_airtime_ms / 16u;
    uint32_t spread =
        frame_airtime_ms < 200u ? 200u : frame_airtime_ms;
    uint64_t delay =
        base + quality_penalty + entropy % (spread + 1u);
    return delay > 20000u ? 20000u : (uint32_t)delay;
}
