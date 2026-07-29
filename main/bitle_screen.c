/* Status screen renderer for the SSD1306 128x64 OLED. Portable: no ESP-IDF
 * dependencies — the same translation unit drives the firmware display task
 * and the host-side simulator (tools/screen_sim.c), so what the simulator
 * draws is byte-identical to what the device shows.
 *
 * Framebuffer layout matches the SSD1306 GDDRAM: 8 pages x 128 columns,
 * each byte a vertical strip of 8 pixels, bit0 = topmost pixel. */

#include "bitle_screen.h"

#include <string.h>

#include "bitle_font.h"

/* Vertical layout */
#define TITLE_Y      0    /* 2x nickname, 16 px tall */
#define STATS_Y      18   /* link / seen line */
#define TRUNK_Y      27   /* trunk state + counters */
#define TAPE_Y       37   /* activity tape top */
#define LANE_H       9    /* pixels per lane */
#define LANE_GAP     1
#define TAPE_LANES   3

#define GUTTER_W     7    /* lane label gutter on the left */
#define TAPE_W       (BITLE_SCREEN_W - GUTTER_W)

/* Tape time scale: milliseconds of history per pixel column. */
#define MS_PER_COL   115

static void px(uint8_t *fb, int x, int y, bool on)
{
    if (x < 0 || x >= BITLE_SCREEN_W || y < 0 || y >= BITLE_SCREEN_H) {
        return;
    }
    uint8_t *b = &fb[(y >> 3) * BITLE_SCREEN_W + x];
    uint8_t mask = (uint8_t)(1u << (y & 7));
    if (on) {
        *b |= mask;
    } else {
        *b &= (uint8_t)~mask;
    }
}

static void draw_char_ink(uint8_t *fb, int x, int y, char ch, int scale, bool ink)
{
    const uint8_t *g = bitle_font_glyph(ch);
    for (int cx = 0; cx < BITLE_FONT_W; ++cx) {
        for (int cy = 0; cy < BITLE_FONT_H; ++cy) {
            if (g[cx] & (1u << cy)) {
                for (int sx = 0; sx < scale; ++sx) {
                    for (int sy = 0; sy < scale; ++sy) {
                        px(fb, x + cx * scale + sx, y + cy * scale + sy, ink);
                    }
                }
            }
        }
    }
}

static void draw_char(uint8_t *fb, int x, int y, char ch, int scale)
{
    draw_char_ink(fb, x, y, ch, scale, true);
}

static void draw_text(uint8_t *fb, int x, int y, const char *s, int scale)
{
    int advance = (BITLE_FONT_W + 1) * scale;
    while (*s) {
        draw_char(fb, x, y, *s++, scale);
        x += advance;
    }
}

/* Small 8x8 antenna glyph, top right. Waves drawn when the trunk is up,
 * tip dot while a trunk event is fresh. */
static void draw_trunk_glyph(uint8_t *fb, const bitle_screen_model_t *m, bool fresh)
{
    const int gx = BITLE_SCREEN_W - 9;
    const int gy = 4;
    static const uint8_t mast[8] = { 0x08, 0x08, 0x2A, 0x1C, 0x08, 0x08, 0x3E, 0x00 };
    for (int cx = 0; cx < 8; ++cx) {
        for (int cy = 0; cy < 8; ++cy) {
            if (mast[cx] & (1u << cy)) {
                px(fb, gx + cx, gy + cy, true);
            }
        }
    }
    if (m->trunk_up) {
        /* radiating arcs either side of the mast tip */
        px(fb, gx + 1, gy + 1, true); px(fb, gx + 6, gy + 1, true);
        px(fb, gx + 0, gy + 2, true); px(fb, gx + 7, gy + 2, true);
    }
    if (fresh) {
        px(fb, gx + 3, gy + 0, true); px(fb, gx + 4, gy + 0, true);
        px(fb, gx + 3, gy + 1, true); px(fb, gx + 4, gy + 1, true);
    }
}

static void draw_tape(uint8_t *fb, const bitle_screen_model_t *m)
{
    static const char lane_label[TAPE_LANES] = { 'B', 'T', 'F' };

    for (int lane = 0; lane < TAPE_LANES; ++lane) {
        int top = TAPE_Y + lane * (LANE_H + LANE_GAP);
        int mid = top + LANE_H / 2;

        draw_char(fb, 0, top + 1, lane_label[lane], 1);

        /* dotted baseline */
        for (int x = GUTTER_W; x < BITLE_SCREEN_W; x += 2) {
            px(fb, x, mid, true);
        }
    }

    /* events: newest at the right edge, scrolling left with age */
    for (int i = 0; i < m->event_count; ++i) {
        const bitle_screen_event_t *e = &m->events[i];
        if (e->lane >= TAPE_LANES) {
            continue;
        }
        int off = (int)(e->age_ms / MS_PER_COL);
        int x = BITLE_SCREEN_W - 1 - off;
        if (x < GUTTER_W) {
            continue;
        }
        int top = TAPE_Y + e->lane * (LANE_H + LANE_GAP);
        int mid = top + LANE_H / 2;
        /* blip: 2 columns wide; rx hangs below the baseline, tx rises above;
         * height decays with age like a phosphor trace */
        int amp = 5 - (int)(e->age_ms / 3000);
        if (amp < 2) {
            amp = 2;
        }
        int y0 = e->dir ? mid - amp : mid;
        int y1 = e->dir ? mid : mid + amp;
        for (int y = y0; y <= y1; ++y) {
            px(fb, x, y, true);
            px(fb, x - 1, y, true);
        }
    }

    /* sweep cursor at the right edge; breathes when idle */
    bool idle = m->event_count == 0;
    bool on = idle ? ((m->now_ms / 900) % 2 == 0) : true;
    if (on) {
        for (int y = TAPE_Y; y < TAPE_Y + TAPE_LANES * (LANE_H + LANE_GAP) - 1; y += 2) {
            px(fb, BITLE_SCREEN_W - 1, y, true);
        }
    }
}

static void draw_text_centered(uint8_t *fb, int y, const char *s, int scale)
{
    int w = (int)strlen(s) * (BITLE_FONT_W + 1) * scale - scale;
    int x = (BITLE_SCREEN_W - w) / 2;
    if (x < 0) {
        x = 0;
    }
    draw_text(fb, x, y, s, scale);
}

void bitle_screen_render_boot(uint8_t *fb, const bitle_screen_model_t *m)
{
    memset(fb, 0, BITLE_SCREEN_FB_BYTES);
    draw_text_centered(fb, 8, "BITLE", 3);
    draw_text_centered(fb, 40, m->nickname, 1);
    draw_text_centered(fb, 52, m->trunk_up ? "TRUNK UP" : "BLE NODE", 1);
}

void bitle_screen_render(uint8_t *fb, const bitle_screen_model_t *m)
{
    memset(fb, 0, BITLE_SCREEN_FB_BYTES);

    /* title: nickname, 2x (11px advance so 10 chars clear the trunk
     * glyph). No inverted bar here: large lit areas sag the SSD1306 charge
     * pump and dim the whole display. */
    char nick[11];
    size_t n = strlen(m->nickname);
    if (n > 10) {
        n = 10;
    }
    memcpy(nick, m->nickname, n);
    nick[n] = '\0';
    {
        int x = 1;
        for (const char *s = nick; *s; ++s) {
            draw_char_ink(fb, x, TITLE_Y + 1, *s, 2, true);
            x += 11;
        }
    }

    bool trunk_fresh = false;
    for (int i = 0; i < m->event_count; ++i) {
        if (m->events[i].lane == BITLE_LANE_TRUNK && m->events[i].age_ms < 600) {
            trunk_fresh = true;
            break;
        }
    }
    draw_trunk_glyph(fb, m, trunk_fresh);

    char line[24];
    const char *hex = "0123456789ABCDEF";

    /* stats line: "LNK 2  SEEN 7" */
    char *p = line;
    memcpy(p, "LNK ", 4); p += 4;
    *p++ = (char)('0' + (m->ble_links % 10));
    *p++ = ' '; *p++ = ' ';
    memcpy(p, "SEEN ", 5); p += 5;
    if (m->peers_seen >= 100) {
        *p++ = hex[(m->peers_seen / 100) % 16];
    }
    if (m->peers_seen >= 10) {
        *p++ = (char)('0' + (m->peers_seen / 10) % 10);
    }
    *p++ = (char)('0' + m->peers_seen % 10);
    *p = '\0';
    draw_text(fb, 0, STATS_Y, line, 1);

    /* trunk line: "TRK UP  RX 1234 TX 56" style */
    p = line;
    memcpy(p, "TRK ", 4); p += 4;
    if (m->trunk_up) {
        memcpy(p, "UP  ", 4);
    } else {
        memcpy(p, "--  ", 4);
    }
    p += 4;
    memcpy(p, "RX ", 3); p += 3;
    uint32_t v = m->rx_total;
    char num[11];
    int ni = 0;
    do {
        num[ni++] = (char)('0' + v % 10);
        v /= 10;
    } while (v && ni < 10);
    while (ni) {
        *p++ = num[--ni];
    }
    memcpy(p, " TX ", 4); p += 4;
    v = m->tx_total;
    ni = 0;
    do {
        num[ni++] = (char)('0' + v % 10);
        v /= 10;
    } while (v && ni < 10);
    while (ni) {
        *p++ = num[--ni];
    }
    *p = '\0';
    draw_text(fb, 0, TRUNK_Y, line, 1);

    draw_tape(fb, m);
}
