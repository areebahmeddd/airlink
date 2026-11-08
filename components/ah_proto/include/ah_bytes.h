// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Big-endian reads and writes, the byte order of every multi-byte field on the
// wire. The caller has bounds-checked the span.
#pragma once

#include <stdint.h>

static inline uint16_t ah_be16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static inline uint32_t ah_be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static inline uint64_t ah_be64(const uint8_t *p)
{
    return (uint64_t)ah_be32(p) << 32 | ah_be32(p + 4);
}

static inline void ah_put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void ah_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline void ah_put_be64(uint8_t *p, uint64_t v)
{
    ah_put_be32(p, (uint32_t)(v >> 32));
    ah_put_be32(p + 4, (uint32_t)v);
}
