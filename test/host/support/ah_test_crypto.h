// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Hooks into the host crypto backend: randomness a failing scenario replays
// exactly, and a SHA-256 that fails on demand, as the device's can.
#pragma once

#include <stdbool.h>
#include <stdint.h>

void ah_test_random_seed(uint64_t seed);

// While set, every SHA-256 (and so every HMAC) fails as the device backend does.
void ah_test_sha256_fail(bool fail);
