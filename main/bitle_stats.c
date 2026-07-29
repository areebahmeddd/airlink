#include "bitle_stats.h"

#include <string.h>

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

typedef struct {
    uint8_t peer_id[8];
    uint64_t last_ms;
} seen_peer_t;

static SemaphoreHandle_t s_lock;
static uint32_t s_rx_total;
static uint32_t s_tx_total;

static struct {
    uint8_t lane;
    uint8_t dir;
    uint64_t at_ms;
} s_events[BITLE_STATS_MAX_EVENTS];
static size_t s_events_head; /* next slot to overwrite (oldest) */
static size_t s_events_used;

static seen_peer_t s_seen[BITLE_STATS_SEEN_SLOTS];

static uint64_t now_ms(void)
{
    return esp_timer_get_time() / 1000ULL;
}

void bitle_stats_init(void)
{
    s_lock = xSemaphoreCreateMutex();
}

void bitle_stats_note_rx(void)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_rx_total++;
    xSemaphoreGive(s_lock);
}

void bitle_stats_note_tx(void)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_tx_total++;
    xSemaphoreGive(s_lock);
}

void bitle_stats_note_activity(uint8_t lane, uint8_t dir)
{
    if (!s_lock) {
        return;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_events[s_events_head].lane = lane;
    s_events[s_events_head].dir = dir;
    s_events[s_events_head].at_ms = now_ms();
    s_events_head = (s_events_head + 1) % BITLE_STATS_MAX_EVENTS;
    if (s_events_used < BITLE_STATS_MAX_EVENTS) {
        s_events_used++;
    }
    xSemaphoreGive(s_lock);
}

void bitle_stats_note_peer(const uint8_t peer_id[8])
{
    if (!s_lock) {
        return;
    }
    uint64_t now = now_ms();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    size_t slot = BITLE_STATS_SEEN_SLOTS;
    size_t oldest = 0;
    for (size_t i = 0; i < BITLE_STATS_SEEN_SLOTS; ++i) {
        seen_peer_t *p = &s_seen[i];
        if (p->last_ms == 0 || now - p->last_ms > BITLE_STATS_SEEN_TTL_MS) {
            if (slot == BITLE_STATS_SEEN_SLOTS) {
                slot = i; /* reusable slot, but an exact match still wins */
            }
            continue;
        }
        if (memcmp(p->peer_id, peer_id, 8) == 0) {
            p->last_ms = now;
            xSemaphoreGive(s_lock);
            return;
        }
        if (p->last_ms < s_seen[oldest].last_ms) {
            oldest = i;
        }
    }
    if (slot == BITLE_STATS_SEEN_SLOTS) {
        slot = oldest;
    }
    memcpy(s_seen[slot].peer_id, peer_id, 8);
    s_seen[slot].last_ms = now;
    xSemaphoreGive(s_lock);
}

void bitle_stats_get(bitle_stats_t *out)
{
    uint64_t now = now_ms();
    memset(out, 0, sizeof(*out));
    xSemaphoreTake(s_lock, portMAX_DELAY);
    out->rx_total = s_rx_total;
    out->tx_total = s_tx_total;
    for (size_t i = 0; i < BITLE_STATS_SEEN_SLOTS; ++i) {
        if (s_seen[i].last_ms && now - s_seen[i].last_ms <= BITLE_STATS_SEEN_TTL_MS) {
            out->peers_seen++;
        }
    }
    /* unwind the ring newest-first */
    size_t n = s_events_used;
    for (size_t k = 0; k < n; ++k) {
        size_t idx = (s_events_head + BITLE_STATS_MAX_EVENTS - 1 - k) % BITLE_STATS_MAX_EVENTS;
        out->events[k].lane = s_events[idx].lane;
        out->events[k].dir = s_events[idx].dir;
        out->events[k].age_ms = (uint32_t)(now - s_events[idx].at_ms);
    }
    out->event_count = (int)n;
    xSemaphoreGive(s_lock);
}
