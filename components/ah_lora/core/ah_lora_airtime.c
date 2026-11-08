// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Time on air by AN1200.13's formula, in integer arithmetic, so every build
// charges the duty budget the same.
#include "ah_lora_airtime.h"

#include <stddef.h>

bool ah_lora_phy_valid(const ah_lora_phy_t *phy)
{
    return phy != NULL && phy->spreading_factor >= 7 && phy->spreading_factor <= 12 && phy->coding_rate >= 5 &&
           phy->coding_rate <= 8 && phy->preamble_symbols >= 4 &&
           (phy->bandwidth_hz == 125000u || phy->bandwidth_hz == 250000u || phy->bandwidth_hz == 500000u);
}

bool ah_lora_low_data_rate(const ah_lora_phy_t *phy)
{
    return (phy->spreading_factor >= 11 && phy->bandwidth_hz == 125000u) ||
           (phy->spreading_factor >= 12 && phy->bandwidth_hz == 250000u);
}

// Time on air in quarter microseconds, or 0 for an invalid PHY or length.
static uint64_t quarter_us(const ah_lora_phy_t *phy, uint16_t len)
{
    if (!ah_lora_phy_valid(phy) || len == 0 || len > 255) {
        return 0;
    }
    const int32_t sf = phy->spreading_factor;
    // Every bandwidth divides 2^SF seconds into whole microseconds.
    const uint64_t symbol_us = ((uint64_t)1000000u << sf) / phy->bandwidth_hz;
    // 8 PL - 4 SF + 28, plus 16 for the CRC; an explicit header subtracts nothing.
    const int32_t numerator = 8 * (int32_t)len - 4 * sf + 28 + 16;
    const int32_t denominator = 4 * (sf - (ah_lora_low_data_rate(phy) ? 2 : 0));
    const int32_t blocks = numerator > 0 ? (numerator + denominator - 1) / denominator : 0;
    const uint64_t payload_symbols = 8u + (uint64_t)blocks * phy->coding_rate;
    // The preamble's 4.25 extra symbols, counted in quarter symbols.
    const uint64_t quarters = 4u * phy->preamble_symbols + 17u + 4u * payload_symbols;
    return quarters * symbol_us;
}

uint32_t ah_lora_airtime_ms(const ah_lora_phy_t *phy, uint16_t len)
{
    return (uint32_t)((quarter_us(phy, len) + 2000u) / 4000u);
}

uint32_t ah_lora_airtime_charge_ms(const ah_lora_phy_t *phy, uint16_t len)
{
    return (uint32_t)((quarter_us(phy, len) + 3999u) / 4000u);
}
