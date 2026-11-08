// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The host tests' streaming SHA-256 context: OpenSSL's.
#pragma once

// SHA256_* is deprecated in OpenSSL 3 but is the plainest streaming API, and
// only host tests build against it.
#ifndef OPENSSL_SUPPRESS_DEPRECATED
#define OPENSSL_SUPPRESS_DEPRECATED
#endif
#include <openssl/sha.h>

typedef struct {
    SHA256_CTX ctx;
} ah_sha256_ctx_t;
