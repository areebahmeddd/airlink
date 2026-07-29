#ifndef LORA_FORWARDING_H
#define LORA_FORWARDING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LORA_FORWARD_DEFAULT_HOP_LIMIT 3
#define LORA_FORWARD_MAX_HOP_LIMIT 4
#define LORA_FORWARD_CACHE_CAPACITY 32
#define LORA_FORWARD_CACHE_RETENTION_MS 300000ULL

typedef struct {
    bool in_use;
    uint8_t source[8];
    uint64_t transfer_fingerprint;
    uint64_t expires_ms;
    uint8_t best_hop_count;
    int8_t best_snr;
} lora_forward_cache_entry_t;

typedef struct {
    lora_forward_cache_entry_t entries[LORA_FORWARD_CACHE_CAPACITY];
} lora_forward_cache_t;

typedef enum {
    LORA_FORWARD_NEW = 0,
    LORA_FORWARD_DUPLICATE,
    LORA_FORWARD_BETTER_COPY,
} lora_forward_observation_t;

void lora_forward_cache_init(lora_forward_cache_t *cache);

/* Stable application-transfer identity. The BitChat TTL byte is deliberately
 * omitted because each network hop decrements it. */
uint64_t lora_forward_fingerprint(const uint8_t *packet, size_t len);

/* Expiring bounded dedup keyed by the BitChat source and stable packet
 * fingerprint. A better duplicate may suppress a weaker scheduled relay, but
 * is still a duplicate for application delivery. */
lora_forward_observation_t lora_forward_cache_observe(
    lora_forward_cache_t *cache, const uint8_t source[8],
    uint64_t transfer_fingerprint, uint8_t hop_count, int8_t snr,
    uint64_t now_ms);

bool lora_forward_hop_allowed(uint8_t hop_limit, uint8_t hop_count);

/* Stronger receptions receive a smaller quality penalty; actual airtime sets
 * both the base and randomized spread. */
uint32_t lora_forward_delay_ms(
    uint32_t frame_airtime_ms, int8_t snr, uint32_t entropy);

#ifdef __cplusplus
}
#endif

#endif
