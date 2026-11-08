// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Where and how loudly the trunk may transmit, by region. Each profile is a
// single fixed channel, the strictest reading of the rule it meets;
// docs/LORA.md cites the clause behind every number, and a new profile is
// cited there before it is added.
//
//   us  47 CFR 15.247(a)(2): a digitally modulated system needs a 6 dB
//       bandwidth of at least 500 kHz, so the trunk runs LoRa at 500 kHz.
//       A fixed 125 kHz channel with 2.3 s frames meets neither the DTS rule
//       nor the hopping one (50 channels, 0.4 s dwell). No duty limit in the
//       rule; the trunk keeps itself to a quarter of the air to share it.
//   eu  ERC/REC 70-03 band h1.7, EU 2025/105 band 54: 869.40 to 869.65 MHz,
//       500 mW e.r.p., at most 10 % duty over an hour, every emission counted.
//   in  GSR 853(E) of 2021, Table II: 865 to 868 MHz, 500 mW e.r.p., adaptive
//       power control, at most 2.5 % duty for a device that is not a network
//       access point, bandwidth at most 200 kHz.
//   anz Australia, LIPD Class Licence 2025: 915 to 928 MHz, digital
//       modulation, 1 W e.i.r.p., at most 25 mW e.i.r.p. in any 3 kHz; New
//       Zealand's SRD GURL allows 1 W e.i.r.p. there for any modulation. No
//       duty rule; the trunk keeps the US fair share.
//   sea One profile legal as configured in Singapore, Malaysia, Thailand,
//       Indonesia and Vietnam, all of which open 920 to 923 MHz: the strictest
//       of their rules, Vietnam's 25 mW e.r.p. without a license and the 1 %
//       duty Singapore, Indonesia and Vietnam set for an end device.
//
// There is no default region: an unprovisioned node never transmits on LoRa,
// so no build is silently illegal somewhere.
#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    AH_LORA_REGION_NONE = 0,
    AH_LORA_REGION_US915 = 1,
    AH_LORA_REGION_EU868 = 2,
    AH_LORA_REGION_IN865 = 3,
    AH_LORA_REGION_ANZ915 = 4,
    AH_LORA_REGION_SEA922 = 5,
} ah_lora_region_id_t;

typedef struct {
    const char *code;         // "us", "eu", "in", "anz", "sea": what provisioning types
    ah_lora_region_id_t id;
    uint32_t frequency_hz;
    uint32_t bandwidth_hz;
    uint32_t duty_window_s;
    // Effective isotropic radiated power the rule allows, in tenths of a dBm
    // (EU, India and Vietnam state e.r.p.; e.i.r.p. = e.r.p. + 2.15 dB).
    int16_t eirp_limit_ddbm;
    // The conducted power the rule allows on its own, in tenths of a dBm; 0
    // where the rule states radiated power alone.
    int16_t conducted_limit_ddbm;
    uint16_t duty_per_mille;  // of the rolling window; regulatory or, for us and anz, a fair share
    uint8_t spreading_factor;
    bool adaptive_power;      // required in India; the trunk applies it wherever it is set
} ah_lora_region_t;

// The profile for a region, or NULL for AH_LORA_REGION_NONE and anything unknown.
const ah_lora_region_t *ah_lora_region(ah_lora_region_id_t id);

// The region a provisioning code names, or AH_LORA_REGION_NONE.
ah_lora_region_id_t ah_lora_region_from_code(const char *code);

// The conducted power to configure, in whole dBm rounded down: the region's
// e.i.r.p. limit less the antenna's gain (`antenna_gain_ddbi`, in tenths of a
// dBi), capped by the region's conducted limit and by `board_max_dbm`, the
// most the board's RF path delivers at its antenna port.
int8_t ah_lora_power_limit(const ah_lora_region_t *region, int16_t antenna_gain_ddbi, int8_t board_max_dbm);
