/* Host-side simulator for the bitle status screen. Renders the exact
 * framebuffer the firmware would produce and writes PNG frames for visual
 * inspection. Build:
 *   cc -O2 -I../main screen_sim.c ../main/bitle_screen.c -lz -o screen_sim
 * Usage:
 *   ./screen_sim          writes frame_00.png ... (activity scenario)
 *   ./screen_sim font     writes font.png (full glyph table) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "bitle_screen.h"
#include "bitle_font.h"

#define SCALE 4

static uint32_t png_crc(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b) {
            crc = (crc >> 1) ^ (0xEDB88320 & (0u - (crc & 1)));
        }
    }
    return ~crc;
}

static void png_chunk(FILE *f, const char type[4], const uint8_t *data, size_t len)
{
    uint8_t hdr[8];
    hdr[0] = (uint8_t)(len >> 24); hdr[1] = (uint8_t)(len >> 16);
    hdr[2] = (uint8_t)(len >> 8);  hdr[3] = (uint8_t)len;
    memcpy(hdr + 4, type, 4);
    fwrite(hdr, 1, 8, f);
    if (len) {
        fwrite(data, 1, len, f);
    }
    uint8_t *buf = malloc(len + 4);
    memcpy(buf, type, 4);
    memcpy(buf + 4, data, len);
    uint32_t crc = png_crc(buf, len + 4);
    free(buf);
    uint8_t c[4] = { (uint8_t)(crc >> 24), (uint8_t)(crc >> 16),
                     (uint8_t)(crc >> 8), (uint8_t)crc };
    fwrite(c, 1, 4, f);
}

static int write_png(const char *path, const uint8_t *fb)
{
    const int w = BITLE_SCREEN_W * SCALE, h = BITLE_SCREEN_H * SCALE;
    uint8_t *raw = malloc((size_t)(w + 1) * h);
    for (int y = 0; y < h; ++y) {
        raw[y * (w + 1)] = 0; /* filter: none */
        for (int x = 0; x < w; ++x) {
            int sx = x / SCALE, sy = y / SCALE;
            bool on = fb[(sy >> 3) * BITLE_SCREEN_W + sx] & (1u << (sy & 7));
            raw[y * (w + 1) + 1 + x] = on ? 0xFF : 0x00;
        }
    }
    uLongf clen = compressBound((uLong)((size_t)(w + 1) * h));
    uint8_t *comp = malloc(clen);
    if (compress2(comp, &clen, raw, (uLong)((size_t)(w + 1) * h), 9) != Z_OK) {
        return -1;
    }
    FILE *f = fopen(path, "wb");
    if (!f) {
        return -1;
    }
    static const uint8_t sig[8] = { 137, 80, 78, 71, 13, 10, 26, 10 };
    fwrite(sig, 1, 8, f);
    uint8_t ihdr[13];
    ihdr[0] = (uint8_t)(w >> 24); ihdr[1] = (uint8_t)(w >> 16);
    ihdr[2] = (uint8_t)(w >> 8);  ihdr[3] = (uint8_t)w;
    ihdr[4] = (uint8_t)(h >> 24); ihdr[5] = (uint8_t)(h >> 16);
    ihdr[6] = (uint8_t)(h >> 8);  ihdr[7] = (uint8_t)h;
    ihdr[8] = 8; ihdr[9] = 0; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
    png_chunk(f, "IHDR", ihdr, 13);
    png_chunk(f, "IDAT", comp, clen);
    png_chunk(f, "IEND", NULL, 0);
    fclose(f);
    free(raw);
    free(comp);
    return 0;
}

/* --- scenario -------------------------------------------------------------
 * 30 simulated seconds: boot with no peers, phones connect, announces flow,
 * a DM session bursts through the relay, trunk beacons tick. */

typedef struct {
    uint32_t at_ms;
    uint8_t lane;
    uint8_t dir;
} script_event_t;

static const script_event_t SCRIPT[] = {
    {  1200, BITLE_LANE_BLE,   0 },
    {  1350, BITLE_LANE_FWD,   1 },
    {  2600, BITLE_LANE_BLE,   0 },
    {  2780, BITLE_LANE_FWD,   1 },
    {  5000, BITLE_LANE_TRUNK, 1 },
    {  6400, BITLE_LANE_TRUNK, 0 },
    {  6550, BITLE_LANE_FWD,   1 },
    {  8200, BITLE_LANE_BLE,   0 },
    {  8310, BITLE_LANE_BLE,   0 },
    {  8420, BITLE_LANE_BLE,   0 },
    {  8560, BITLE_LANE_FWD,   1 },
    {  8700, BITLE_LANE_FWD,   1 },
    { 10000, BITLE_LANE_TRUNK, 1 },
    { 11300, BITLE_LANE_BLE,   0 },
    { 11480, BITLE_LANE_TRUNK, 1 },
    { 13000, BITLE_LANE_TRUNK, 0 },
    { 13120, BITLE_LANE_BLE,   1 },
    { 15000, BITLE_LANE_TRUNK, 1 },
    { 16400, BITLE_LANE_BLE,   0 },
    { 16560, BITLE_LANE_FWD,   1 },
    { 16700, BITLE_LANE_FWD,   1 },
    { 18200, BITLE_LANE_TRUNK, 0 },
    { 20000, BITLE_LANE_TRUNK, 1 },
    { 21500, BITLE_LANE_BLE,   0 },
    { 21630, BITLE_LANE_BLE,   0 },
    { 21800, BITLE_LANE_FWD,   1 },
    { 23400, BITLE_LANE_TRUNK, 0 },
    { 23550, BITLE_LANE_TRUNK, 1 },
    { 25000, BITLE_LANE_TRUNK, 1 },
    { 26800, BITLE_LANE_BLE,   0 },
    { 26960, BITLE_LANE_FWD,   1 },
    { 28400, BITLE_LANE_BLE,   0 },
    { 28520, BITLE_LANE_FWD,   1 },
};

static void build_model(bitle_screen_model_t *m, uint32_t now_ms)
{
    memset(m, 0, sizeof(*m));
    strcpy(m->nickname, "Bitle-9550");
    m->ble_links = now_ms < 2500 ? 0 : (now_ms < 8000 ? 1 : 2);
    m->peers_seen = now_ms < 2500 ? 0 : (now_ms < 8000 ? 1 : (now_ms < 15000 ? 3 : 7));
    m->trunk_up = now_ms >= 4500;
    m->now_ms = now_ms;

    uint32_t rx = 0, tx = 0;
    int count = 0;
    for (size_t i = 0; i < sizeof(SCRIPT) / sizeof(SCRIPT[0]); ++i) {
        if (SCRIPT[i].at_ms > now_ms) {
            break;
        }
        if (SCRIPT[i].dir) { tx++; } else { rx++; }
        if (count < BITLE_SCREEN_MAX_EVENTS) {
            /* newest first: iterate script backwards when filling */
            count++;
        }
    }
    int filled = 0;
    for (int i = (int)(sizeof(SCRIPT) / sizeof(SCRIPT[0])) - 1; i >= 0; --i) {
        if (SCRIPT[i].at_ms <= now_ms && filled < count) {
            m->events[filled].lane = SCRIPT[i].lane;
            m->events[filled].dir = SCRIPT[i].dir;
            m->events[filled].age_ms = now_ms - SCRIPT[i].at_ms;
            filled++;
        }
    }
    m->event_count = filled;
    m->rx_total = rx;
    m->tx_total = tx;
}

int main(int argc, char **argv)
{
    static uint8_t fb[BITLE_SCREEN_FB_BYTES];

    if (argc > 1 && strcmp(argv[1], "font") == 0) {
        /* render the full glyph table across several rows */
        bitle_screen_model_t m;
        memset(&m, 0, sizeof(m));
        memset(fb, 0, sizeof(fb));
        int x = 0, y = 0;
        for (unsigned i = 0; i < BITLE_FONT_GLYPH_COUNT; ++i) {
            x = (int)(i % 16) * 8;
            y = (int)(i / 16) * 10;
            const uint8_t *g = bitle_font_glyph(BITLE_FONT[i].ch);
            for (int cx = 0; cx < BITLE_FONT_W; ++cx) {
                for (int cy = 0; cy < BITLE_FONT_H; ++cy) {
                    if (g[cx] & (1u << cy)) {
                        fb[((y + cy) >> 3) * BITLE_SCREEN_W + (x + cx)] |=
                            (uint8_t)(1u << ((y + cy) & 7));
                    }
                }
            }
        }
        return write_png("font.png", fb);
    }

    static const uint32_t ticks[] = { 3000, 9000, 13000, 17500, 22000, 27500 };
    {
        bitle_screen_model_t m;
        build_model(&m, 1000);
        bitle_screen_render_boot(fb, &m);
        if (write_png("boot.png", fb) != 0) {
            fprintf(stderr, "failed to write boot.png\n");
            return 1;
        }
        printf("wrote boot.png\n");
    }
    for (size_t i = 0; i < sizeof(ticks) / sizeof(ticks[0]); ++i) {
        bitle_screen_model_t m;
        build_model(&m, ticks[i]);
        bitle_screen_render(fb, &m);
        char path[32];
        snprintf(path, sizeof(path), "frame_%02zu.png", i);
        if (write_png(path, fb) != 0) {
            fprintf(stderr, "failed to write %s\n", path);
            return 1;
        }
        printf("wrote %s (t=%ums)\n", path, ticks[i]);
    }
    return 0;
}
