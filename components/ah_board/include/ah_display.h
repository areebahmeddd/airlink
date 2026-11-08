// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The board's OLED, if it has one: found on I2C at boot, lit at boot and on a
// button press, dark otherwise.
#pragma once

#include "esp_err.h"

#include "ah_board.h"
#include "ah_screen.h"

// Probe for the display and start its task. Returns ESP_OK with no display
// present, too: the node runs headless.
esp_err_t ah_display_start(const ah_board_t *board, const char *nickname);

// Publish the latest counts. Call once a second, from one task: each call adds
// the relays since the last one to the activity trace. The nickname and the
// trace are the display's own, so the caller leaves both empty.
void ah_display_update(const ah_screen_model_t *model);
