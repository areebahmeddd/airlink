#ifndef LORA_REGION_H
#define LORA_REGION_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    LORA_REGION_US915 = 0,
    LORA_REGION_EU868 = 1,
    LORA_REGION_COUNT,
} lora_region_id_t;

typedef struct {
    lora_region_id_t id;
    const char *name;
    uint32_t minimum_hz;
    uint32_t maximum_hz;
    uint32_t default_hz;
    uint8_t image_calibration[2];
} lora_region_profile_t;

#define LORA_PRIVATE_SYNC_WORD 0x1424

typedef struct {
    lora_region_id_t region;
    uint32_t frequency_hz;
    uint8_t spreading_factor;
    uint32_t bandwidth_hz;
    uint8_t coding_rate;
    uint16_t preamble_symbols;
    uint16_t sync_word;
    int8_t tx_dbm;
} lora_phy_profile_t;

const lora_region_profile_t *lora_region_profile(lora_region_id_t id);
bool lora_region_frequency_valid(lora_region_id_t id, uint32_t frequency_hz);
bool lora_region_infer(uint32_t frequency_hz, lora_region_id_t *out);
bool lora_region_image_calibration(uint32_t frequency_hz, uint8_t out[2]);
bool lora_phy_profile_valid(const lora_phy_profile_t *profile);

/* Every field that changes demodulation must match. TX power may differ
 * without stranding peers and is therefore intentionally not compared. */
bool lora_phy_profiles_compatible(
    const lora_phy_profile_t *left,
    const lora_phy_profile_t *right);

#ifdef __cplusplus
}
#endif

#endif /* LORA_REGION_H */
