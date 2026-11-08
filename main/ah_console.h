// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The serial console: status, the last crash, and provisioning (region,
// nickname, OTA owner key, factory reset) until `lock` closes it for good.
// Settings and a factory reset take effect at the next boot; the lock at once.
#pragma once

#include "esp_err.h"

#include "ah_settings.h"

// Start the REPL on the build's console port (UART or USB Serial/JTAG).
esp_err_t ah_console_start(const ah_settings_t *settings, const char *board);

// What reset the chip before this boot, in words, for the boot log and `status`.
const char *ah_console_reset_reason(void);
