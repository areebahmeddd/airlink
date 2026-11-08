// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The region profiles; docs/LORA.md cites the rule behind every number.
#include "ah_lora_region.h"

#include <string.h>

static const ah_lora_region_t s_regions[] = {
    {
        .id = AH_LORA_REGION_US915,
        .code = "us",
        // Between LoRaWAN US915's highest uplink channel (914.9 MHz) and its
        // lowest downlink (923.3 MHz), so the 500 kHz channel overlaps neither.
        .frequency_hz = 919000000u,
        .bandwidth_hz = 500000u,
        // SF12 at 500 kHz has about the sensitivity of SF10 at 125 kHz, the
        // EU profile's, with a 255-byte frame of 1.93 s rather than 2.30 s.
        .spreading_factor = 12,
        // 15.247(e)'s 8 dBm in any 3 kHz binds before 15.247(b)(3)'s 1 W:
        // spread flat over 500 kHz, 30 dBm is 7.8 dBm in 3 kHz, with nothing
        // to spare for the chirp spectrum's ripple. 28 dBm conducted keeps
        // 2 dB under it, and antenna gain over 6 dBi comes off that
        // (15.247(b)(4)): 34 dBm e.i.r.p. at most.
        .eirp_limit_ddbm = 340,
        .conducted_limit_ddbm = 280,
        .duty_per_mille = 250,
        .duty_window_s = 3600,
        .adaptive_power = false,
    },
    {
        .id = AH_LORA_REGION_EU868,
        .code = "eu",
        // The center of 869.40 to 869.65 MHz: 62.5 kHz of margin each side at 125 kHz.
        .frequency_hz = 869525000u,
        .bandwidth_hz = 125000u,
        .spreading_factor = 10,
        // 500 mW e.r.p. = 27.0 dBm e.r.p. = 29.15 dBm e.i.r.p.
        .eirp_limit_ddbm = 291,
        .duty_per_mille = 100,
        .duty_window_s = 3600,
        .adaptive_power = false,
    },
    {
        .id = AH_LORA_REGION_IN865,
        .code = "in",
        // Between the RFID channels at 866.3 and 866.9 MHz, inside both the
        // 2008 band (865 to 867 MHz) and the 2021 one (865 to 868 MHz).
        .frequency_hz = 866600000u,
        .bandwidth_hz = 125000u,
        .spreading_factor = 10,
        .eirp_limit_ddbm = 291,
        .duty_per_mille = 25,
        .duty_window_s = 3600,
        .adaptive_power = true,
    },
    {
        .id = AH_LORA_REGION_ANZ915,
        .code = "anz",
        // The US channel and modulation: clear of the AU915 sub-band and the
        // AS923 channels networks there use, and of the downlink channels.
        // 30 dBm over 500 kHz is 7.8 dBm in 3 kHz, under the 14 dBm (25 mW)
        // spectral density limit, read as the US profile's is.
        .frequency_hz = 919000000u,
        .bandwidth_hz = 500000u,
        .spreading_factor = 12,
        .eirp_limit_ddbm = 300,
        .duty_per_mille = 250,
        .duty_window_s = 3600,
        .adaptive_power = false,
    },
    {
        .id = AH_LORA_REGION_SEA922,
        .code = "sea",
        // Inside the 920 to 923 MHz all five countries open, and below
        // Malaysia's 923 to 924 MHz, which asks for listen before talk.
        .frequency_hz = 922000000u,
        .bandwidth_hz = 125000u,
        // A 1 % budget is 36 s an hour: SF9 halves SF10's airtime for 2.5 dB
        // of sensitivity.
        .spreading_factor = 9,
        // 25 mW e.r.p. = 13.98 dBm e.r.p. = 16.13 dBm e.i.r.p.
        .eirp_limit_ddbm = 161,
        .duty_per_mille = 10,
        .duty_window_s = 3600,
        .adaptive_power = false,
    },
};

const ah_lora_region_t *ah_lora_region(ah_lora_region_id_t id)
{
    for (size_t i = 0; i < sizeof(s_regions) / sizeof(s_regions[0]); ++i) {
        if (s_regions[i].id == id) {
            return &s_regions[i];
        }
    }
    return NULL;
}

ah_lora_region_id_t ah_lora_region_from_code(const char *code)
{
    for (size_t i = 0; code != NULL && i < sizeof(s_regions) / sizeof(s_regions[0]); ++i) {
        if (strcmp(s_regions[i].code, code) == 0) {
            return s_regions[i].id;
        }
    }
    return AH_LORA_REGION_NONE;
}

int8_t ah_lora_power_limit(const ah_lora_region_t *region, int16_t antenna_gain_ddbi, int8_t board_max_dbm)
{
    if (region == NULL) {
        return 0;
    }
    int32_t limit_ddbm = (int32_t)region->eirp_limit_ddbm - antenna_gain_ddbi;
    if (region->conducted_limit_ddbm != 0 && limit_ddbm > region->conducted_limit_ddbm) {
        limit_ddbm = region->conducted_limit_ddbm;
    }
    // Rounded down, below zero too, so rounding never passes the limit.
    int32_t dbm = limit_ddbm >= 0 ? limit_ddbm / 10 : (limit_ddbm - 9) / 10;
    if (dbm > board_max_dbm) {
        dbm = board_max_dbm;
    }
    return (int8_t)dbm;
}
