// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The status screen, drawn into a 128 x 64 monochrome frame laid out as the
// SSD1306 and SH1106 hold it: 8 pages of 128 columns, each byte a vertical
// strip of 8 pixels, bit 0 at the top. Pure C, no ESP-IDF.
#pragma once

#include <stdbool.h>
#include <stdint.h>

#define AH_SCREEN_W 128
#define AH_SCREEN_H 64
#define AH_SCREEN_FB_BYTES (AH_SCREEN_W * AH_SCREEN_H / 8)
#define AH_SCREEN_NICK_MAX 24

typedef enum {
    AH_SCREEN_LORA_ABSENT = 0, // no radio on this board, or none answered
    AH_SCREEN_LORA_NO_REGION,  // a radio, but no region provisioned
    AH_SCREEN_LORA_UP,
} ah_screen_lora_t;

typedef struct {
    char nickname[AH_SCREEN_NICK_MAX + 1];
    uint16_t links;
    uint16_t bound;
    uint16_t peers;
    uint32_t received;
    uint32_t relayed;
    bool clock_synced;
    ah_screen_lora_t lora;
    uint8_t lora_neighbors;
    uint16_t airtime_per_mille; // of the duty budget
    // Relays per second, oldest first: the activity trace along the bottom.
    uint8_t activity[AH_SCREEN_W];
} ah_screen_model_t;

void ah_screen_render(uint8_t fb[AH_SCREEN_FB_BYTES], const ah_screen_model_t *m);

// The splash shown for a moment at boot.
void ah_screen_render_boot(uint8_t fb[AH_SCREEN_FB_BYTES], const char *nickname);
