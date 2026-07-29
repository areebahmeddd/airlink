#ifndef LORA_AIRTIME_H
#define LORA_AIRTIME_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Portable LoRa time-on-air inputs. The calculation is deliberately kept
 * independent of ESP-IDF so the exact firmware math can be exercised by the
 * host reliability suite. Coding rate is the denominator in 4/5 .. 4/8. */
typedef struct {
    uint8_t spreading_factor;
    uint32_t bandwidth_hz;
    uint8_t coding_rate;
    uint16_t preamble_symbols;
    bool explicit_header;
    bool crc_enabled;
} lora_airtime_params_t;

bool lora_airtime_params_valid(const lora_airtime_params_t *params);

/* Returns rounded milliseconds, or 0 for invalid parameters/payloads. */
uint32_t lora_airtime_ms(const lora_airtime_params_t *params, uint16_t payload_len);

#ifdef __cplusplus
}
#endif

#endif /* LORA_AIRTIME_H */
