#include "bitle_route.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "bitle_link.h"

static const char *TAG = "bitle_route";

/* BLE allows at most BITLE_LINK_MAX simultaneous direct peers, but broadcast
 * media (the LoRa trunk) fronts further neighbors, so the table is wider. */
#define DIRECT_MAX 16

/* Topology learned from gossip TLVs; sized for the small meshes these nodes
 * serve, LRU-evicted under pressure. */
#define GRAPH_MAX 24

/* Neighbors heard over broadcast media never get a link-down event, so their
 * direct mappings lapse unless refreshed by periodic announces (LoRa beacons
 * run every 60 s; upstream's stale-peer timeout is 180 s). */
#define DIRECT_BROADCAST_MAX_AGE_MS (180 * 1000ULL)

typedef struct {
    bool in_use;
    uint8_t peer_id[8];
    uint16_t link;
    uint64_t last_ms;
} direct_entry_t;

typedef struct {
    bool in_use;
    uint8_t peer_id[8];
    uint64_t timestamp_ms;   /* announce's own (attacker-controlled) timestamp */
    uint64_t updated_ms;     /* local monotonic, for LRU eviction only */
    uint8_t count;
    uint8_t neighbors[BITLE_ROUTE_MAX_NEIGHBORS][8];
} graph_entry_t;

static SemaphoreHandle_t s_lock;
static direct_entry_t s_direct[DIRECT_MAX];
static graph_entry_t s_graph[GRAPH_MAX];

esp_err_t bitle_route_init(void)
{
    s_lock = xSemaphoreCreateMutex();
    return s_lock ? ESP_OK : ESP_ERR_NO_MEM;
}

static uint64_t now_ms(void)
{
    return esp_timer_get_time() / 1000ULL;
}

static bool id_eq(const uint8_t a[8], const uint8_t b[8])
{
    return memcmp(a, b, 8) == 0;
}

/* Point-to-point mappings die with their link; broadcast-media mappings
 * lapse without refreshes. Must be called with s_lock held. */
static bool direct_entry_live_locked(direct_entry_t *e)
{
    if (!e->in_use) {
        return false;
    }
    if (bitle_link_is_broadcast(e->link) &&
        now_ms() - e->last_ms > DIRECT_BROADCAST_MAX_AGE_MS) {
        e->in_use = false;
        return false;
    }
    return true;
}

void bitle_route_note_direct(const uint8_t peer_id[8], uint16_t link)
{
    if (!s_lock) {
        return;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    direct_entry_t *slot = NULL;
    direct_entry_t *oldest = &s_direct[0];
    for (size_t i = 0; i < DIRECT_MAX; ++i) {
        direct_entry_t *e = &s_direct[i];
        direct_entry_live_locked(e);
        if (e->in_use && id_eq(e->peer_id, peer_id)) {
            slot = e;
            break;
        }
        if (!e->in_use && !slot) {
            slot = e;
        }
        if (e->last_ms < oldest->last_ms) {
            oldest = e;
        }
    }
    if (!slot) {
        slot = oldest;
    }
    slot->in_use = true;
    memcpy(slot->peer_id, peer_id, 8);
    slot->link = link;
    slot->last_ms = now_ms();
    xSemaphoreGive(s_lock);
}

void bitle_route_link_down(uint16_t link)
{
    if (!s_lock) {
        return;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (size_t i = 0; i < DIRECT_MAX; ++i) {
        if (s_direct[i].in_use && s_direct[i].link == link) {
            s_direct[i].in_use = false;
        }
    }
    xSemaphoreGive(s_lock);
}

uint16_t bitle_route_link_for(const uint8_t peer_id[8])
{
    if (!s_lock) {
        return BITLE_LINK_NONE;
    }
    uint16_t link = BITLE_LINK_NONE;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (size_t i = 0; i < DIRECT_MAX; ++i) {
        direct_entry_t *e = &s_direct[i];
        if (direct_entry_live_locked(e) && id_eq(e->peer_id, peer_id)) {
            link = e->link;
            break;
        }
    }
    xSemaphoreGive(s_lock);
    return link;
}

bool bitle_route_is_direct(const uint8_t peer_id[8])
{
    return bitle_route_link_for(peer_id) != BITLE_LINK_NONE;
}

int bitle_route_direct_peers(uint8_t out[][8], int max)
{
    if (!s_lock || !out || max <= 0) {
        return 0;
    }
    int n = 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (size_t i = 0; i < DIRECT_MAX && n < max; ++i) {
        direct_entry_t *e = &s_direct[i];
        if (!direct_entry_live_locked(e)) {
            continue;
        }
        bool dup = false;
        for (int j = 0; j < n; ++j) {
            if (id_eq(out[j], e->peer_id)) {
                dup = true;
                break;
            }
        }
        if (!dup) {
            memcpy(out[n++], e->peer_id, 8);
        }
    }
    xSemaphoreGive(s_lock);
    return n;
}

void bitle_route_note_neighbors(const uint8_t peer_id[8], const uint8_t neighbors[][8],
                                int count, uint64_t timestamp_ms)
{
    if (!s_lock || count < 0) {
        return;
    }
    if (count > BITLE_ROUTE_MAX_NEIGHBORS) {
        count = BITLE_ROUTE_MAX_NEIGHBORS;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    graph_entry_t *entry = NULL;
    graph_entry_t *oldest = &s_graph[0];
    for (size_t i = 0; i < GRAPH_MAX; ++i) {
        graph_entry_t *g = &s_graph[i];
        if (g->in_use && id_eq(g->peer_id, peer_id)) {
            entry = g;
            break;
        }
        if (!g->in_use && !entry) {
            entry = g;
        }
        if (g->updated_ms < oldest->updated_ms) {
            oldest = g;
        }
    }
    if (entry && entry->in_use && timestamp_ms <= entry->timestamp_ms) {
        /* Only strictly newer claims replace what we already know. */
        xSemaphoreGive(s_lock);
        return;
    }
    if (!entry) {
        entry = oldest;
    }
    memset(entry->neighbors, 0, sizeof(entry->neighbors));
    entry->in_use = true;
    memcpy(entry->peer_id, peer_id, 8);
    entry->timestamp_ms = timestamp_ms;
    entry->updated_ms = now_ms();
    entry->count = 0;
    for (int i = 0; i < count; ++i) {
        if (id_eq(neighbors[i], peer_id)) {
            continue; /* self-loop claims carry no topology */
        }
        bool dup = false;
        for (int j = 0; j < entry->count; ++j) {
            if (id_eq(entry->neighbors[j], neighbors[i])) {
                dup = true;
                break;
            }
        }
        if (!dup && entry->count < BITLE_ROUTE_MAX_NEIGHBORS) {
            memcpy(entry->neighbors[entry->count++], neighbors[i], 8);
        }
    }
    xSemaphoreGive(s_lock);
}

/* Neighbor set of one BFS node: our own neighborhood is the direct-peer
 * table (which only holds verified direct links); everyone else's is their
 * gossiped claim. Must be called with s_lock held. */
static int neighbors_of_locked(const uint8_t peer_id[8], const uint8_t src[8],
                               uint8_t out[][8], int max)
{
    int n = 0;
    if (id_eq(peer_id, src)) {
        for (size_t i = 0; i < DIRECT_MAX && n < max; ++i) {
            direct_entry_t *e = &s_direct[i];
            if (direct_entry_live_locked(e)) {
                memcpy(out[n++], e->peer_id, 8);
            }
        }
        return n;
    }
    for (size_t i = 0; i < GRAPH_MAX; ++i) {
        graph_entry_t *g = &s_graph[i];
        if (g->in_use && id_eq(g->peer_id, peer_id)) {
            n = g->count < max ? g->count : max;
            memcpy(out, g->neighbors, (size_t)n * 8);
            return n;
        }
    }
    return 0;
}

/* A routable edge exists only when both sides announced each other
 * (upstream MeshGraphService "confirmed edge"). Caller holds s_lock. */
static bool edge_confirmed_locked(const uint8_t a[8], const uint8_t b[8], const uint8_t src[8])
{
    uint8_t tmp[BITLE_ROUTE_MAX_NEIGHBORS + DIRECT_MAX][8];
    int na = neighbors_of_locked(a, src, tmp, sizeof(tmp) / sizeof(tmp[0]));
    bool a_lists_b = false;
    for (int i = 0; i < na; ++i) {
        if (id_eq(tmp[i], b)) {
            a_lists_b = true;
            break;
        }
    }
    if (!a_lists_b) {
        return false;
    }
    int nb = neighbors_of_locked(b, src, tmp, sizeof(tmp) / sizeof(tmp[0]));
    for (int i = 0; i < nb; ++i) {
        if (id_eq(tmp[i], a)) {
            return true;
        }
    }
    return false;
}

#define BFS_MAX_NODES (1 + DIRECT_MAX + GRAPH_MAX + 1)

int bitle_route_compute(const uint8_t src[8], const uint8_t dest[8],
                        uint8_t out_hops[][8], int max_hops)
{
    if (!s_lock || !src || !dest || !out_hops || max_hops <= 0) {
        return -1;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);

    /* A currently-connected direct neighbor needs no route. */
    for (size_t i = 0; i < DIRECT_MAX; ++i) {
        if (direct_entry_live_locked(&s_direct[i]) && id_eq(s_direct[i].peer_id, dest)) {
            xSemaphoreGive(s_lock);
            return 0;
        }
    }

    uint8_t ids[BFS_MAX_NODES][8];
    int n_ids = 0;
    memcpy(ids[n_ids++], src, 8);
    for (size_t i = 0; i < DIRECT_MAX && n_ids < BFS_MAX_NODES; ++i) {
        if (!direct_entry_live_locked(&s_direct[i])) {
            continue;
        }
        bool seen = id_eq(s_direct[i].peer_id, src);
        for (int j = 0; j < n_ids && !seen; ++j) {
            seen = id_eq(ids[j], s_direct[i].peer_id);
        }
        if (!seen) {
            memcpy(ids[n_ids++], s_direct[i].peer_id, 8);
        }
    }
    for (size_t i = 0; i < GRAPH_MAX && n_ids < BFS_MAX_NODES; ++i) {
        if (!s_graph[i].in_use) {
            continue;
        }
        bool seen = false;
        for (int j = 0; j < n_ids && !seen; ++j) {
            seen = id_eq(ids[j], s_graph[i].peer_id);
        }
        if (!seen) {
            memcpy(ids[n_ids++], s_graph[i].peer_id, 8);
        }
    }
    int dest_idx = -1;
    for (int i = 0; i < n_ids; ++i) {
        if (id_eq(ids[i], dest)) {
            dest_idx = i;
            break;
        }
    }
    if (dest_idx < 0) {
        /* The destination never announced its neighborhood, so no confirmed
         * edge can terminate there. */
        xSemaphoreGive(s_lock);
        return -1;
    }

    int8_t parent[BFS_MAX_NODES];
    uint8_t queue[BFS_MAX_NODES];
    memset(parent, -1, sizeof(parent));
    parent[0] = 0;
    size_t head = 0, tail = 0;
    queue[tail++] = 0;
    while (head < tail && parent[dest_idx] < 0) {
        uint8_t cur = queue[head++];
        uint8_t nbr[BITLE_ROUTE_MAX_NEIGHBORS + DIRECT_MAX][8];
        int n = neighbors_of_locked(ids[cur], src, nbr, sizeof(nbr) / sizeof(nbr[0]));
        for (int i = 0; i < n; ++i) {
            int ni = -1;
            for (int j = 0; j < n_ids; ++j) {
                if (id_eq(ids[j], nbr[i])) {
                    ni = j;
                    break;
                }
            }
            if (ni < 0 || parent[ni] >= 0) {
                continue;
            }
            if (!edge_confirmed_locked(ids[cur], ids[ni], src)) {
                continue;
            }
            parent[ni] = (int8_t)cur;
            queue[tail++] = (uint8_t)ni;
            if (ni == dest_idx) {
                break;
            }
        }
    }

    int result = -1;
    if (parent[dest_idx] >= 0) {
        /* Walk dest -> src, then reverse into hop order. */
        uint8_t path[BFS_MAX_NODES];
        int path_len = 0;
        for (int at = dest_idx; at != 0 && path_len < BFS_MAX_NODES; at = parent[at]) {
            path[path_len++] = (uint8_t)at;
        }
        /* path holds [dest, ..., first hop] (src excluded); intermediates
         * are everything but dest, emitted sender-to-recipient order. */
        int intermediates = path_len - 1;
        if (intermediates >= 1 && intermediates <= max_hops) {
            for (int i = 0; i < intermediates; ++i) {
                memcpy(out_hops[i], ids[path[path_len - 1 - i]], 8);
            }
            result = intermediates;
        } else if (intermediates > max_hops) {
            ESP_LOGW(TAG, "confirmed path too long (%d hops); not routing", intermediates);
        }
    }
    xSemaphoreGive(s_lock);
    return result;
}
