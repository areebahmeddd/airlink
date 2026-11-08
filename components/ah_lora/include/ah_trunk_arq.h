// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Selective repeat for one transfer: which pieces a round sends, and which one
// probes after a silent round. A receiver's bitmap is what it holds now and
// replaces what it said before, so a receiver that lost its state (a reboot,
// an evicted or expired slot) is sent every piece it lacks again. A transfer
// to several receivers keeps each one's bitmap and gives this the pieces all
// of them hold (ah_trunk_arq_hold), so a round sends what any one lacks.
#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint8_t total;
    uint8_t held;  // the pieces every receiver still waiting holds
    uint8_t sent;  // the pieces sent this round
    uint8_t round;
} ah_trunk_arq_t;

bool ah_trunk_arq_init(ah_trunk_arq_t *a, uint8_t total);

// The next piece this round, or -1 once every missing piece has gone.
int ah_trunk_arq_next(const ah_trunk_arq_t *a);

// The piece a probe carries after a silent round: one missing piece, a
// different one each round, so every missing piece is resent even while
// every answer is lost. -1 when none is missing.
int ah_trunk_arq_probe(const ah_trunk_arq_t *a);

void ah_trunk_arq_sent(ah_trunk_arq_t *a, uint8_t index);

// The pieces every receiver still waiting holds, replacing what they held
// before; bits past the transfer are ignored.
void ah_trunk_arq_hold(ah_trunk_arq_t *a, uint8_t held);

// Start another round. Returns false once `rounds` have been used.
bool ah_trunk_arq_next_round(ah_trunk_arq_t *a, uint8_t rounds);
