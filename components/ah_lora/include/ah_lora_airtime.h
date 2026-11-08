// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// LoRa time on air: Semtech AN1200.13, as the SX1261/2 datasheet (6.1.4)
// states it, for an explicit header with CRC on, which is how the trunk always
// runs. Integer arithmetic, so the duty budget is charged identically on the
// host and the chip.
#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint8_t spreading_factor;  // 7 to 12; SF5 and SF6 take another formula
    uint32_t bandwidth_hz;     // 125, 250 or 500 kHz
    uint8_t coding_rate;       // denominator: 5 to 8 for 4/5 to 4/8
    uint16_t preamble_symbols;
} ah_lora_phy_t;

bool ah_lora_phy_valid(const ah_lora_phy_t *phy);

// Low data rate optimization: required once a symbol lasts 16 ms or more (datasheet 6.1.1.4).
bool ah_lora_low_data_rate(const ah_lora_phy_t *phy);

// Milliseconds on air for a frame of `len` bytes, rounded; 0 for an invalid PHY or length.
uint32_t ah_lora_airtime_ms(const ah_lora_phy_t *phy, uint16_t len);

// The same rounded up: what the duty budget is charged, so rounding never
// lets the airtime spent pass the limit.
uint32_t ah_lora_airtime_charge_ms(const ah_lora_phy_t *phy, uint16_t len);
