#include "lora_region.h"

#include <assert.h>
#include <stdint.h>

int main(void)
{
    const lora_region_profile_t *us = lora_region_profile(LORA_REGION_US915);
    const lora_region_profile_t *eu = lora_region_profile(LORA_REGION_EU868);
    assert(us && eu);
    assert(lora_region_frequency_valid(us->id, us->default_hz));
    assert(lora_region_frequency_valid(eu->id, eu->default_hz));
    assert(lora_region_frequency_valid(us->id, us->minimum_hz));
    assert(lora_region_frequency_valid(us->id, us->maximum_hz));
    assert(lora_region_frequency_valid(eu->id, eu->minimum_hz));
    assert(lora_region_frequency_valid(eu->id, eu->maximum_hz));
    assert(!lora_region_frequency_valid(us->id, eu->default_hz));
    assert(!lora_region_frequency_valid(eu->id, us->default_hz));
    assert(!lora_region_frequency_valid(LORA_REGION_COUNT, us->default_hz));

    uint8_t calibration[2] = {0};
    assert(lora_region_image_calibration(us->default_hz, calibration));
    assert(calibration[0] == 0xE1 && calibration[1] == 0xE9);
    assert(lora_region_image_calibration(eu->default_hz, calibration));
    assert(calibration[0] == 0xD7 && calibration[1] == 0xDB);
    assert(!lora_region_image_calibration(700000000, calibration));

    lora_region_id_t inferred = LORA_REGION_COUNT;
    assert(lora_region_infer(902000000, &inferred));
    assert(inferred == LORA_REGION_US915);
    assert(lora_region_infer(870000000, &inferred));
    assert(inferred == LORA_REGION_EU868);

    lora_phy_profile_t base = {
        .region = LORA_REGION_US915,
        .frequency_hz = 911500000,
        .spreading_factor = 10,
        .bandwidth_hz = 125000,
        .coding_rate = 5,
        .preamble_symbols = 16,
        .sync_word = LORA_PRIVATE_SYNC_WORD,
        .tx_dbm = 22,
    };
    assert(lora_phy_profile_valid(&base));
    lora_phy_profile_t peer = base;
    peer.tx_dbm = 14;
    assert(lora_phy_profiles_compatible(&base, &peer));
    peer.coding_rate = 6;
    assert(lora_phy_profile_valid(&peer));
    assert(!lora_phy_profiles_compatible(&base, &peer));
    peer = base;
    peer.frequency_hz = 869525000;
    assert(!lora_phy_profile_valid(&peer));
    peer = base;
    peer.sync_word = 0x2444;
    assert(!lora_phy_profile_valid(&peer));
    peer = base;
    peer.preamble_symbols = 65;
    assert(!lora_phy_profile_valid(&peer));
    return 0;
}
