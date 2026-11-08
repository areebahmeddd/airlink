// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Selective-repeat bookkeeping for one transfer, as bitmaps of the pieces sent
// and the pieces the receiver holds.
#include "ah_trunk_arq.h"

#include <string.h>

#include "ah_trunk_frame.h"

bool ah_trunk_arq_init(ah_trunk_arq_t *a, uint8_t total)
{
    memset(a, 0, sizeof(*a));
    if (ah_trunk_frame_mask(total) == 0) {
        return false;
    }
    a->total = total;
    return true;
}

static uint8_t missing(const ah_trunk_arq_t *a)
{
    return (uint8_t)(ah_trunk_frame_mask(a->total) & ~a->held);
}

int ah_trunk_arq_next(const ah_trunk_arq_t *a)
{
    const uint8_t todo = (uint8_t)(missing(a) & ~a->sent);
    for (uint8_t i = 0; i < a->total; ++i) {
        if (todo & (1u << i)) {
            return i;
        }
    }
    return -1;
}

int ah_trunk_arq_probe(const ah_trunk_arq_t *a)
{
    const uint8_t gaps = missing(a);
    unsigned count = 0;
    for (uint8_t i = 0; i < a->total; ++i) {
        count += (gaps >> i) & 1u;
    }
    if (count == 0) {
        return -1;
    }
    unsigned skip = a->round % count;
    for (uint8_t i = 0; i < a->total; ++i) {
        if (gaps & (1u << i)) {
            if (skip == 0) {
                return i;
            }
            skip--;
        }
    }
    return -1;
}

void ah_trunk_arq_sent(ah_trunk_arq_t *a, uint8_t index)
{
    if (index < a->total) {
        a->sent |= (uint8_t)(1u << index);
    }
}

void ah_trunk_arq_hold(ah_trunk_arq_t *a, uint8_t held)
{
    a->held = (uint8_t)(held & ah_trunk_frame_mask(a->total));
}

bool ah_trunk_arq_next_round(ah_trunk_arq_t *a, uint8_t rounds)
{
    if ((unsigned)a->round + 1u >= rounds) {
        return false;
    }
    a->round++;
    a->sent = 0;
    return true;
}
