#include "lora_region.h"

#include <stddef.h>

static const lora_region_profile_t PROFILES[] = {
    {
        .id = LORA_REGION_US915,
        .name = "US915",
        .minimum_hz = 902000000,
        .maximum_hz = 928000000,
        .default_hz = 911500000,
        .image_calibration = {0xE1, 0xE9},
    },
    {
        .id = LORA_REGION_EU868,
        .name = "EU868",
        .minimum_hz = 863000000,
        .maximum_hz = 870000000,
        .default_hz = 869525000,
        .image_calibration = {0xD7, 0xDB},
    },
};

const lora_region_profile_t *lora_region_profile(lora_region_id_t id)
{
    for (size_t i = 0; i < sizeof(PROFILES) / sizeof(PROFILES[0]); ++i) {
        if (PROFILES[i].id == id) {
            return &PROFILES[i];
        }
    }
    return NULL;
}

bool lora_region_frequency_valid(lora_region_id_t id, uint32_t frequency_hz)
{
    const lora_region_profile_t *profile = lora_region_profile(id);
    return profile && frequency_hz >= profile->minimum_hz &&
           frequency_hz <= profile->maximum_hz;
}

bool lora_region_infer(uint32_t frequency_hz, lora_region_id_t *out)
{
    for (size_t i = 0; i < sizeof(PROFILES) / sizeof(PROFILES[0]); ++i) {
        if (frequency_hz >= PROFILES[i].minimum_hz &&
            frequency_hz <= PROFILES[i].maximum_hz) {
            if (out) {
                *out = PROFILES[i].id;
            }
            return true;
        }
    }
    return false;
}

bool lora_region_image_calibration(uint32_t frequency_hz, uint8_t out[2])
{
    lora_region_id_t id;
    if (!out || !lora_region_infer(frequency_hz, &id)) {
        return false;
    }
    const lora_region_profile_t *profile = lora_region_profile(id);
    out[0] = profile->image_calibration[0];
    out[1] = profile->image_calibration[1];
    return true;
}

bool lora_phy_profile_valid(const lora_phy_profile_t *profile)
{
    return profile &&
           lora_region_frequency_valid(
               profile->region, profile->frequency_hz) &&
           profile->spreading_factor >= 7 &&
           profile->spreading_factor <= 12 &&
           (profile->bandwidth_hz == 125000 ||
            profile->bandwidth_hz == 250000 ||
            profile->bandwidth_hz == 500000) &&
           profile->coding_rate >= 5 &&
           profile->coding_rate <= 8 &&
           profile->preamble_symbols >= 8 &&
           profile->preamble_symbols <= 64 &&
           profile->sync_word == LORA_PRIVATE_SYNC_WORD &&
           profile->tx_dbm >= -9 &&
           profile->tx_dbm <= 22;
}

bool lora_phy_profiles_compatible(
    const lora_phy_profile_t *left,
    const lora_phy_profile_t *right)
{
    return lora_phy_profile_valid(left) &&
           lora_phy_profile_valid(right) &&
           left->region == right->region &&
           left->frequency_hz == right->frequency_hz &&
           left->spreading_factor == right->spreading_factor &&
           left->bandwidth_hz == right->bandwidth_hz &&
           left->coding_rate == right->coding_rate &&
           left->preamble_symbols == right->preamble_symbols &&
           left->sync_word == right->sync_word;
}
