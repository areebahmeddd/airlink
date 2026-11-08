// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The board the firmware was built for: its radio wiring, power rails, RF
// front end and display, chosen in Kconfig (one profile per build).
#pragma once

#include <stdbool.h>

#include "esp_err.h"

#include "ah_lora.h"

typedef enum {
    AH_DISPLAY_NONE = 0,
    AH_DISPLAY_SSD1306,
    AH_DISPLAY_SH1106,
} ah_display_kind_t;

typedef struct {
    // The build's board name (scripts/build.sh), at most 16 characters: OTA
    // manifests name the board their image is for.
    const char *name;
    bool has_lora;
    ah_lora_radio_t radio;     // valid when has_lora
    ah_display_kind_t display;
    int display_sda;
    int display_scl;
    int display_rst;           // -1 none
    int button;                // active low; -1 none
} ah_board_t;

// Power the board's rails and identify its RF front end, which stays powered
// down until ah_board_radio_power. Call once, from app_main, before the radio
// or the display starts.
esp_err_t ah_board_init(void);

// Power the radio's front end up for the trunk, or down again (a radio that
// did not answer). Nothing to do on a board without one.
esp_err_t ah_board_radio_power(bool on);

// The board profile; valid after ah_board_init.
const ah_board_t *ah_board(void);
