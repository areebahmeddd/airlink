// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The device's streaming SHA-256 context: a PSA hash operation, which the SHA
// peripheral's driver backs.
#pragma once

#include "psa/crypto.h"

typedef struct {
    psa_hash_operation_t op;
} ah_sha256_ctx_t;
