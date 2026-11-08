// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The name large, three lines of counts, and an activity trace. No large lit
// areas: they sag the OLED's charge pump and dim the whole panel.
#include "ah_screen.h"

#include <stdio.h>
#include <string.h>

#include "ah_font.h"

#define ADVANCE (AH_FONT_W + 1)
#define TITLE_Y 1
#define LINE1_Y 19
#define LINE2_Y 28
#define LINE3_Y 37
#define TRACE_TOP 47
#define TRACE_H (AH_SCREEN_H - TRACE_TOP)
#define TITLE_CHARS 10

static void pixel(uint8_t *fb, int x, int y)
{
    if (x >= 0 && x < AH_SCREEN_W && y >= 0 && y < AH_SCREEN_H) {
        fb[(y >> 3) * AH_SCREEN_W + x] |= (uint8_t)(1u << (y & 7));
    }
}

static void glyph(uint8_t *fb, int x, int y, char ch, int scale)
{
    const uint8_t *g = ah_font_glyph(ch);
    for (int cx = 0; cx < AH_FONT_W; ++cx) {
        for (int cy = 0; cy < AH_FONT_H; ++cy) {
            if ((g[cx] >> cy) & 1u) {
                for (int s = 0; s < scale * scale; ++s) {
                    pixel(fb, x + cx * scale + s % scale, y + cy * scale + s / scale);
                }
            }
        }
    }
}

static void text(uint8_t *fb, int x, int y, const char *s, int scale)
{
    for (; *s != '\0' && x < AH_SCREEN_W; ++s, x += ADVANCE * scale) {
        glyph(fb, x, y, *s, scale);
    }
}

static void text_centered(uint8_t *fb, int y, const char *s, int scale)
{
    const int w = (int)strlen(s) * ADVANCE * scale - scale;
    text(fb, w < AH_SCREEN_W ? (AH_SCREEN_W - w) / 2 : 0, y, s, scale);
}

// Relays per second as bars, scaled to the busiest second shown, with a
// dotted baseline so an idle node still reads as alive.
static void trace(uint8_t *fb, const uint8_t *activity)
{
    uint8_t peak = 1;
    for (int x = 0; x < AH_SCREEN_W; ++x) {
        peak = activity[x] > peak ? activity[x] : peak;
    }
    for (int x = 0; x < AH_SCREEN_W; ++x) {
        const int h = (activity[x] * (TRACE_H - 1) + peak - 1) / peak;
        for (int y = 0; y < h; ++y) {
            pixel(fb, x, AH_SCREEN_H - 1 - y);
        }
        if (h == 0 && x % 2 == 0) {
            pixel(fb, x, AH_SCREEN_H - 1);
        }
    }
}

void ah_screen_render(uint8_t fb[AH_SCREEN_FB_BYTES], const ah_screen_model_t *m)
{
    memset(fb, 0, AH_SCREEN_FB_BYTES);
    // Wider than the 21 characters a line shows: text() clips at the edge.
    char line[64];
    snprintf(line, sizeof(line), "%.*s", TITLE_CHARS, m->nickname);
    text(fb, 1, TITLE_Y, line, 2);

    snprintf(line, sizeof(line), "LINKS %u/%u PEERS %u", m->bound, m->links, m->peers);
    text(fb, 0, LINE1_Y, line, 1);
    snprintf(line, sizeof(line), "RX %lu RELAY %lu", (unsigned long)m->received, (unsigned long)m->relayed);
    text(fb, 0, LINE2_Y, line, 1);
    switch (m->lora) {
    case AH_SCREEN_LORA_UP:
        snprintf(line, sizeof(line), "LORA %u AIR %u%% %s", m->lora_neighbors, (m->airtime_per_mille + 5u) / 10u,
                 m->clock_synced ? "" : "NOCLK");
        break;
    case AH_SCREEN_LORA_NO_REGION:
        snprintf(line, sizeof(line), "LORA NO REGION %s", m->clock_synced ? "" : "NOCLK");
        break;
    default:
        snprintf(line, sizeof(line), "BLE ONLY %s", m->clock_synced ? "" : "NOCLK");
        break;
    }
    text(fb, 0, LINE3_Y, line, 1);
    trace(fb, m->activity);
}

void ah_screen_render_boot(uint8_t fb[AH_SCREEN_FB_BYTES], const char *nickname)
{
    memset(fb, 0, AH_SCREEN_FB_BYTES);
    text_centered(fb, 10, "AIRLINK", 3);
    text_centered(fb, 44, nickname, 1);
}
