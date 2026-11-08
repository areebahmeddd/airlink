#ifndef BITLE_SCREEN_H
#define BITLE_SCREEN_H_INCLUDED

#include <stdbool.h>
#include <stdint.h>

#define BITLE_SCREEN_W 128
#define BITLE_SCREEN_H 64
#define BITLE_SCREEN_FB_BYTES (BITLE_SCREEN_W * BITLE_SCREEN_H / 8)

/* Activity tape lanes */
#define BITLE_LANE_BLE   0  /* packets received over BLE */
#define BITLE_LANE_TRUNK 1  /* LoRa trunk traffic, either direction */
#define BITLE_LANE_FWD   2  /* packets relayed onward */

#define BITLE_SCREEN_MAX_EVENTS 48

typedef struct {
    uint8_t lane;       /* BITLE_LANE_* */
    uint8_t dir;        /* 0 = inbound, 1 = outbound */
    uint8_t _pad[2];
    uint32_t age_ms;    /* ms since the event, relative to model now_ms */
} bitle_screen_event_t;

typedef struct {
    char nickname[24];
    int ble_links;          /* direct BLE connections */
    int peers_seen;         /* unique peers discovered via announces */
    bool trunk_up;
    uint32_t rx_total;      /* lifetime packet counters */
    uint32_t tx_total;
    uint32_t now_ms;
    int event_count;        /* events[], newest first */
    bitle_screen_event_t events[BITLE_SCREEN_MAX_EVENTS];
} bitle_screen_model_t;

void bitle_screen_render(uint8_t *fb, const bitle_screen_model_t *model);

/* Splash shown briefly at boot before the live dashboard. */
void bitle_screen_render_boot(uint8_t *fb, const bitle_screen_model_t *model);

#endif /* BITLE_SCREEN_H */
