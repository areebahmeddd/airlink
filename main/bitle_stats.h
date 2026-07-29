#ifndef BITLE_STATS_H
#define BITLE_STATS_H

#include <stdbool.h>
#include <stdint.h>

#include "bitle_screen.h"

/* Runtime activity bookkeeping for the status display: a ring of recent
 * packet events and a table of unique peers seen announcing, fed by the
 * mesh/relay paths. Cheap enough to keep unconditional (a few stores per
 * packet); only the display task reads it. */

#define BITLE_STATS_MAX_EVENTS BITLE_SCREEN_MAX_EVENTS
#define BITLE_STATS_SEEN_SLOTS 32
#define BITLE_STATS_SEEN_TTL_MS (10 * 60 * 1000)

typedef struct {
    uint32_t rx_total;
    uint32_t tx_total;
    int peers_seen;
    int event_count;                                /* newest first */
    bitle_screen_event_t events[BITLE_STATS_MAX_EVENTS];
} bitle_stats_t;

void bitle_stats_init(void);

/* lane: BITLE_LANE_*; dir: 0 = inbound, 1 = outbound */
void bitle_stats_note_activity(uint8_t lane, uint8_t dir);

/* Record a unique packet arrival (rx_total) or a relay onward (tx_total). */
void bitle_stats_note_rx(void);
void bitle_stats_note_tx(void);

/* Announce observed from this sender (direct or relayed). */
void bitle_stats_note_peer(const uint8_t peer_id[8]);

void bitle_stats_get(bitle_stats_t *out);

#endif /* BITLE_STATS_H */
