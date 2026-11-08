// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Node lifecycle, links, fanout, the relay scheduler, origination and timers.
// Ingress lives in ah_node_rx.c, sync in ah_node_sync.c, courier mail in
// ah_node_mail.c and direct messages in ah_dm.c.
#include <string.h>

#include "ah_announce.h"
#include "ah_crypto.h"
#include "ah_node_priv.h"

// bitchat-ios BLEMaintenancePolicy: 15 s +/- 4 s with fewer than six links,
// 30 s +/- 8 s at six or more.
#define ANNOUNCE_SPARSE_MS 15000u
#define ANNOUNCE_SPARSE_JITTER_MS 4000u
#define ANNOUNCE_DENSE_MS 30000u
#define ANNOUNCE_DENSE_JITTER_MS 8000u
// A new link gets our announce this soon after it opens (bitchat-ios: 0.05 s
// as central, 0.4 s as peripheral). Until the clock allows one, or while the
// link is too small to carry it (no MTU exchange yet), it is asked for again
// this often.
#define ANNOUNCE_ON_LINK_MS 300
#define ANNOUNCE_RETRY_MS 2000
#define MAINTENANCE_MS 1000
#define CLOCK_SAVE_MS (10LL * 60 * 1000)
// A cut of up to this many pieces is queued at once; a longer one goes
// through the streamed cut, which carries one frame at a time.
#define IMMEDIATE_PIECES 8u
// A signature check for the node's own use leaves a quarter of its link's
// share, and of the budget, to the checks that decide whether a packet is relayed.
#define VERIFY_RELAY_SHARE 4u
// The shared budgets' window, and how recently a link must have asked to be
// held its whole share: one that asked this second or the last keeps it
// through a flood on another link, and a quiet one is still held its floor.
#define SHARE_WINDOW_MS 1000
#define SHARE_ACTIVE_MS 2000

static void *alloc_zeroed(ah_node_t *n, size_t bytes)
{
    void *p = n->ops.alloc(n->ops.ctx, bytes);
    if (p != NULL) {
        memset(p, 0, bytes);
    }
    return p;
}

ah_node_t *ah_node_create(const ah_node_config_t *config, const ah_identity_t *identity, const ah_node_ops_t *ops,
                          uint64_t restored_wall_ms)
{
    ah_node_t *n = ops->alloc(ops->ctx, sizeof(ah_node_t));
    if (n == NULL) {
        return NULL;
    }
    memset(n, 0, sizeof(*n));
    n->cfg = *config;
    n->id = *identity;
    n->ops = *ops;
    n->rx_link = AH_LINK_NONE;
    n->started_ms = -1;
    n->saved_floor_ms = restored_wall_ms;
    ah_clock_init(&n->clock, restored_wall_ms);

    void *inflater = alloc_zeroed(n, ah_inflater_size(config->inflate_window));
    const uint32_t windows[3] = {300u, 300u, 150u};
    const uint32_t slots[3] = {config->dedup_message_slots, config->dedup_fragment_slots, config->dedup_live_slots};
    void *dedup[3];
    for (size_t i = 0; i < 3u; ++i) {
        dedup[i] = alloc_zeroed(n, ah_dedup_storage_size(slots[i]));
    }
    ah_peer_t *peers = alloc_zeroed(n, sizeof(ah_peer_t) * config->peers);
    ah_peer_pin_t *pins = config->peer_pins > 0 ? alloc_zeroed(n, sizeof(ah_peer_pin_t) * config->peer_pins) : NULL;
    ah_link_t *links = alloc_zeroed(n, sizeof(ah_link_t) * config->links);
    ah_queued_t *queues = alloc_zeroed(n, sizeof(ah_queued_t) * config->links * config->queue_per_link);
    ah_frame_buf_t *bufs = alloc_zeroed(n, sizeof(ah_frame_buf_t) * config->frame_buffers);
    n->extra = alloc_zeroed(n, sizeof(ah_link_extra_t) * config->links);
    ah_sync_ref_t *backlog = alloc_zeroed(n, sizeof(ah_sync_ref_t) * config->links * config->reply_backlog);
    ah_assembly_t *assemblies = alloc_zeroed(n, sizeof(ah_assembly_t) * config->reassembly_slots);
    uint8_t *reassembly_arena = alloc_zeroed(n, (size_t)config->reassembly_slots * config->reassembly_bytes);
    void *sync_mem = alloc_zeroed(n, ah_sync_memory(&config->sync));
    ah_mail_t *mail = alloc_zeroed(n, sizeof(ah_mail_t) * config->mail_slots);
    uint8_t *mail_arena = alloc_zeroed(n, config->mail_bytes);
    n->relays = alloc_zeroed(n, sizeof(ah_pending_relay_t) * config->relay_slots);
    n->sessions = alloc_zeroed(n, sizeof(ah_session_t) * config->sessions);
    n->big.bytes = alloc_zeroed(n, config->big_send_bytes);
    n->big.preimage = alloc_zeroed(n, (size_t)config->big_send_bytes + AH_PAD_MAX);

    if (inflater == NULL || dedup[0] == NULL || dedup[1] == NULL || dedup[2] == NULL || peers == NULL ||
            (pins == NULL && config->peer_pins > 0) || links == NULL || queues == NULL || bufs == NULL ||
            n->extra == NULL || backlog == NULL || assemblies == NULL || reassembly_arena == NULL || sync_mem == NULL ||
            mail == NULL || mail_arena == NULL || n->relays == NULL || n->sessions == NULL || n->big.bytes == NULL ||
            n->big.preimage == NULL) {
        return NULL;
    }
    n->inflater = ah_inflater_init(inflater, config->inflate_window);
    for (size_t i = 0; i < 3u; ++i) {
        ah_dedup_init(&n->dedup[i], dedup[i], slots[i], windows[i]);
    }
    ah_peers_init(&n->peers, peers, config->peers, pins, config->peer_pins);
    ah_links_init(&n->links, links, config->links, queues, config->queue_per_link, bufs, config->frame_buffers);
    for (uint16_t i = 0; i < config->links; ++i) {
        n->extra[i].backlog.refs = backlog + (size_t)i * config->reply_backlog;
    }
    ah_reassembly_init(&n->reassembly, assemblies, config->reassembly_slots, reassembly_arena,
                       config->reassembly_bytes);
    ah_sync_init(&n->sync, &config->sync, sync_mem);
    ah_courier_init(&n->courier, mail, config->mail_slots, mail_arena, config->mail_bytes,
                    config->mail_per_depositor, ah_node_mail_gone, n);
    ah_trunk_policy_init(&n->trunk, config->trunk_announce_interval_ms);
    return n;
}

bool ah_node_budget_take(ah_budget_t *b, int64_t now_ms, uint32_t cost, uint32_t limit, int64_t window_ms)
{
    if (now_ms - b->window_start_ms >= window_ms || now_ms < b->window_start_ms) {
        b->window_start_ms = now_ms;
        b->used = 0;
    }
    if (b->used + cost > limit) {
        return false;
    }
    b->used += cost;
    return true;
}

static bool share_link(const ah_node_t *n, uint16_t link)
{
    return link < n->links.capacity && n->links.links[link].in_use;
}

bool ah_node_share_ask(ah_node_t *n, ah_share_t which, uint16_t link, uint32_t cost, uint32_t full, uint32_t floor,
                       uint32_t reserve_div, int64_t now_ms)
{
    ah_budget_t *total = &n->shares[which];
    if (now_ms - total->window_start_ms >= SHARE_WINDOW_MS || now_ms < total->window_start_ms) {
        total->window_start_ms = now_ms;
        total->used = 0;
    }
    uint32_t open = 0;
    for (uint16_t i = 0; i < n->links.capacity; ++i) {
        open += n->links.links[i].in_use ? 1u : 0u;
    }
    // At least one a link: a budget smaller than the links open is then
    // first come among them, but no one link takes more than one.
    const uint32_t even = open > 0 ? full / open : full;
    const uint32_t share = even > 0 ? even : 1u;
    const uint32_t quiet = floor < share ? floor : share;
    uint64_t held = 0;
    uint64_t mine = 0;
    for (uint16_t i = 0; i < n->links.capacity; ++i) {
        if (!n->links.links[i].in_use) {
            continue;
        }
        const ah_budget_t *d = &n->extra[i].drawn[which];
        const bool active = d->window_start_ms != 0 && now_ms - d->window_start_ms < SHARE_ACTIVE_MS;
        const uint32_t want = active ? share : quiet;
        const uint32_t got = d->window_start_ms == total->window_start_ms ? d->used : 0u;
        held += want > got ? want - got : 0u;
        if (i == link) {
            const uint32_t usable = reserve_div > 0 ? want - want / reserve_div : want;
            mine = usable > got ? usable - got : 0u;
        }
    }
    const uint64_t committed = (uint64_t)total->used + held;
    const uint64_t spare = committed < full ? full - committed : 0u;
    const uint64_t keep = reserve_div > 0 ? (full + reserve_div - 1u) / reserve_div : 0u;
    const uint64_t open_to_me = mine + (spare > keep ? spare - keep : 0u);
    // Asking marks the link as one that wants its share, granted or not.
    if (share_link(n, link)) {
        ah_budget_t *d = &n->extra[link].drawn[which];
        if (d->window_start_ms != total->window_start_ms) {
            d->window_start_ms = total->window_start_ms;
            d->used = 0;
        }
    }
    return (uint64_t)total->used + cost <= full && cost <= open_to_me;
}

void ah_node_share_spend(ah_node_t *n, ah_share_t which, uint16_t link, uint32_t cost)
{
    ah_budget_t *total = &n->shares[which];
    total->used += cost;
    if (share_link(n, link)) {
        ah_budget_t *d = &n->extra[link].drawn[which];
        if (d->window_start_ms != total->window_start_ms) {
            d->window_start_ms = total->window_start_ms;
            d->used = 0;
        }
        d->used += cost;
    }
}

bool ah_node_verify_budget(ah_node_t *n, bool before_relay, int64_t now_ms)
{
    const uint32_t full = n->cfg.verify_per_second;
    const uint32_t reserve_div = before_relay ? 0u : VERIFY_RELAY_SHARE;
    if (!ah_node_share_ask(n, AH_SHARE_VERIFY, n->rx_link, 1, full, 1, reserve_div, now_ms)) {
        n->stats.verify_skipped++;
        return false;
    }
    ah_node_share_spend(n, AH_SHARE_VERIFY, n->rx_link, 1);
    return true;
}

bool ah_node_wall_time(const ah_node_t *n, int64_t now_ms, uint64_t *out)
{
    return ah_clock_now(&n->clock, now_ms, out);
}

uint32_t ah_node_degree(const ah_node_t *n)
{
    uint32_t degree = 0;
    for (uint16_t i = 0; i < n->links.capacity; ++i) {
        const ah_link_t *l = &n->links.links[i];
        // The phones' degree is Bluetooth neighbors, one per bound peer: a peer
        // on two links (dual-role BLE) is one, and trunk neighbors share no air.
        if (l->in_use && l->kind == AH_LINK_BLE && l->peer != AH_PEER_NONE &&
                n->peers.slots[l->peer].direct_link == i) {
            degree++;
        }
    }
    return degree;
}

const ah_node_stats_t *ah_node_stats(ah_node_t *n)
{
    n->stats.links_open = 0;
    n->stats.links_bound = 0;
    for (uint16_t i = 0; i < n->links.capacity; ++i) {
        const ah_link_t *l = &n->links.links[i];
        n->stats.links_open += l->in_use ? 1u : 0u;
        n->stats.links_bound += l->in_use && l->peer != AH_PEER_NONE ? 1u : 0u;
    }
    n->stats.peers_known = 0;
    for (uint16_t i = 0; i < n->peers.capacity; ++i) {
        n->stats.peers_known += n->peers.slots[i].key != 0 ? 1u : 0u;
    }
    n->stats.buffers_in_use = n->links.pool.in_use;
    n->stats.tx_dropped = n->links.dropped;
    n->stats.dedup_evicted = 0;
    for (size_t i = 0; i < 3u; ++i) {
        n->stats.dedup_evicted += n->dedup[i].evicted_live;
    }
    n->stats.buffers_exhausted = n->links.pool.exhausted;
    n->stats.peers_evicted = n->peers.evicted;
    n->stats.mail_refused = n->courier.refused;
    n->stats.reassembly_evicted = n->reassembly.evicted;
    n->stats.clock_rejected = n->clock.rejected;
    n->stats.clock_state = (uint8_t)n->clock.state;
    n->stats.clock_confirmed = ah_clock_confirmed(&n->clock);
    return &n->stats;
}

const uint8_t *ah_node_link_peer(const ah_node_t *n, uint16_t link)
{
    if (link >= n->links.capacity || !n->links.links[link].in_use || n->links.links[link].peer == AH_PEER_NONE) {
        return NULL;
    }
    return n->peers.slots[n->links.links[link].peer].peer_id;
}

uint16_t ah_node_link_by_handle(const ah_node_t *n, ah_link_kind_t kind, uint32_t handle)
{
    return ah_links_by_handle(&n->links, kind, handle);
}

bool ah_node_send_raw(ah_node_t *n, uint16_t link, const uint8_t *frame, size_t len, int64_t now_ms)
{
    if (link >= n->links.capacity || !n->links.links[link].in_use || len > n->links.links[link].max_write) {
        return false;
    }
    const uint16_t buf = ah_pool_copy(&n->links.pool, frame, len, 0);
    if (buf == AH_BUF_NONE) {
        return false;
    }
    const bool queued = ah_links_enqueue(&n->links, link, buf, AH_PRIO_BULK, 0, 0, now_ms);
    ah_pool_unref(&n->links.pool, buf);
    ah_node_drain(n, link, now_ms);
    return queued;
}

bool ah_node_link_info(const ah_node_t *n, uint16_t link, ah_node_link_info_t *out)
{
    if (link >= n->links.capacity || !n->links.links[link].in_use) {
        return false;
    }
    const ah_link_t *l = &n->links.links[link];
    *out = (ah_node_link_info_t) {
        .kind = l->kind, .handle = l->handle, .max_write = l->max_write
    };
    if (l->peer != AH_PEER_NONE) {
        const ah_peer_t *p = &n->peers.slots[l->peer];
        out->peer_id = p->peer_id;
        out->peer_is_node = (p->relay_flags & AH_RELAY_FLAG_DEDICATED) != 0;
        out->peer_firmware = p->firmware;
    }
    return true;
}

// ---- links ----

uint16_t ah_node_link_up(ah_node_t *n, ah_link_kind_t kind, uint32_t handle, uint16_t max_write,
                         const uint8_t expected_peer[AH_PEER_ID_LEN], int64_t now_ms)
{
    const uint16_t link = ah_links_open(&n->links, kind, handle, max_write, expected_peer);
    if (link == AH_LINK_NONE) {
        return link;
    }
    ah_link_extra_t *x = &n->extra[link];
    ah_sync_ref_t *refs = x->backlog.refs;
    memset(x, 0, sizeof(*x));
    x->backlog.refs = refs;
    // A new link needs our announce soon: it is what binds the link on the far side.
    x->announce_due_ms = now_ms + ANNOUNCE_ON_LINK_MS;
    return link;
}

void ah_node_link_mtu(ah_node_t *n, uint16_t link, uint16_t max_write)
{
    if (link < n->links.capacity && n->links.links[link].in_use) {
        n->links.links[link].max_write = max_write > AH_FRAME_BUF_MAX ? AH_FRAME_BUF_MAX : max_write;
    }
}

void ah_node_link_down(ah_node_t *n, uint16_t link)
{
    if (link >= n->links.capacity || !n->links.links[link].in_use) {
        return;
    }
    ah_link_t *l = &n->links.links[link];
    // The peer's other links, if any, carry its traffic again once its next
    // direct announce binds one; none inherits the direct link before, since
    // a link bound only by a repeated announce proves nothing.
    if (l->peer != AH_PEER_NONE && n->peers.slots[l->peer].direct_link == link) {
        n->peers.slots[l->peer].direct_link = AH_LINK_NONE;
    }
    if (n->big.active && n->big.link == link) {
        n->big.active = false;
    }
    ah_dm_link_gone(n, link);
    // The slot is reused lowest first, and a stream verified here vouches for no newcomer.
    for (size_t i = 0; i < AH_LIVE_VERIFIED_SLOTS; ++i) {
        if (n->live[i].link == link) {
            n->live[i] = (ah_live_verified_t) {
                .link = AH_LINK_NONE
            };
        }
    }
    for (uint16_t i = 0; i < n->cfg.relay_slots; ++i) {
        // A relay scheduled from this link keeps going; only its exclusion is stale.
        if (n->relays[i].in_use && n->relays[i].from_link == link) {
            n->relays[i].from_link = AH_LINK_NONE;
        }
    }
    ah_links_close(&n->links, link);
}

void ah_node_link_ready(ah_node_t *n, uint16_t link, int64_t now_ms)
{
    if (link < n->links.capacity && n->links.links[link].in_use) {
        n->links.links[link].busy = false;
        ah_node_drain(n, link, now_ms);
    }
}

// ---- writing ----

// One piece of a cut, pooled and queued; it dedups in the fragment set like
// everyone else's, so its echo is never relayed back.
static bool queue_piece(ah_node_t *n, uint16_t link, const uint8_t *piece, size_t len, ah_prio_t prio,
                        int64_t deadline_ms, uint32_t token, int64_t now_ms)
{
    const uint16_t pb = ah_pool_copy(&n->links.pool, piece, len, 0);
    if (pb == AH_BUF_NONE) {
        return false;
    }
    ah_frame_t pf;
    uint8_t id[AH_PACKET_ID_LEN];
    if (ah_frame_parse(piece, len, &pf) && ah_packet_id(&pf, NULL, id)) {
        ah_dedup_add(&n->dedup[AH_DEDUP_FRAGMENT], id, (uint32_t)(now_ms / 1000));
    }
    const bool queued = ah_links_enqueue(&n->links, link, pb, prio, deadline_ms, token, now_ms);
    ah_pool_unref(&n->links.pool, pb);
    return queued;
}

// Queue the next pieces of the streamed cut while its link has room, and say
// whether any went.
static bool pump_big(ah_node_t *n, int64_t now_ms)
{
    ah_big_send_t *j = &n->big;
    const ah_link_t *l = &n->links.links[j->link];
    bool queued = false;
    while (j->active && l->in_use && l->queued + 1u < l->queue_cap) {
        uint8_t piece[AH_FRAME_BUF_MAX];
        const size_t len = ah_fragmenter_next(&j->cutter, piece, sizeof(piece));
        if (len == 0) {
            j->active = false;
            break;
        }
        const bool last = j->cutter.next == j->cutter.total;
        if (!queue_piece(n, j->link, piece, len, (ah_prio_t)j->prio, 0, j->token, now_ms)) {
            // Out of buffers: step back and try this piece again on the next drain.
            j->cutter.next--;
            break;
        }
        j->progress_ms = now_ms;
        queued = true;
        if (last) {
            j->active = false;
        }
    }
    return queued;
}

void ah_node_drain(ah_node_t *n, uint16_t link, int64_t now_ms)
{
    ah_link_t *l = &n->links.links[link];
    for (;;) {
        while (l->in_use && !l->busy) {
            const ah_queued_t q = ah_links_dequeue(&n->links, link, now_ms);
            if (q.buf == AH_BUF_NONE) {
                break;
            }
            const ah_frame_buf_t *b = ah_pool_get(&n->links.pool, q.buf);
            const ah_write_t r = n->ops.write(n->ops.ctx, l->kind, l->handle, b->data, b->len, q.prio);
            if (r == AH_WRITE_OK) {
                n->stats.tx++;
                ah_pool_unref(&n->links.pool, q.buf);
                if (q.token != 0) {
                    ah_node_mail_written(n, q.token);
                }
            } else if (r == AH_WRITE_BUSY) {
                l->busy = true;
                ah_links_requeue(&n->links, link, &q);
            } else {
                ah_pool_unref(&n->links.pool, q.buf);
                ah_node_link_down(n, link);
                return;
            }
        }
        if (!l->in_use || l->busy) {
            return;
        }
        // The queue is empty and the link still takes writes: refill it from
        // the planned sync replies and the streamed cut, then write again.
        const uint8_t before = l->queued;
        ah_node_sync_drain(n, link, now_ms);
        const bool cut = n->big.active && n->big.link == link && pump_big(n, now_ms);
        if (l->queued == before && !cut) {
            return;
        }
    }
}

bool ah_node_big_send(ah_node_t *n, uint16_t link, const uint8_t *frame, size_t len, ah_prio_t prio, uint32_t token,
                      int64_t now_ms)
{
    if (n->big.active || len > n->cfg.big_send_bytes || link == AH_LINK_NONE) {
        return false;
    }
    // A frame the caller built in place is already in the buffer.
    if (frame != n->big.bytes) {
        memcpy(n->big.bytes, frame, len);
    }
    ah_frame_t copy;
    if (!ah_frame_parse(n->big.bytes, len, &copy)) {
        return false;
    }
    uint8_t stream_id[AH_FRAGMENT_STREAM_ID_LEN];
    ah_random(stream_id, sizeof(stream_id));
    if (!ah_fragmenter_init(&n->big.cutter, &copy, n->big.bytes, len, n->links.links[link].max_write, stream_id)) {
        return false;
    }
    n->big.active = true;
    n->big.link = link;
    n->big.prio = (uint8_t)prio;
    n->big.token = token;
    n->big.progress_ms = now_ms;
    // Every piece carries the token: what it marks is done only once all of
    // them are written, since a piece lost in the queue leaves nothing to rebuild.
    if (token != 0) {
        ah_node_mail_cut(n, token, n->big.cutter.total);
    }
    ah_node_drain(n, link, now_ms);
    return true;
}

// Cut a frame too large for one link into pieces queued at once, when they are
// few and the queue and the pool have room for all of them.
static bool enqueue_cut(ah_node_t *n, uint16_t link, uint16_t buf, ah_prio_t prio, int64_t deadline_ms, uint32_t token,
                        int64_t now_ms)
{
    const ah_frame_buf_t *b = ah_pool_get(&n->links.pool, buf);
    ah_frame_t f;
    if (!ah_frame_parse(b->data, b->len, &f)) {
        return false;
    }
    uint8_t stream_id[AH_FRAGMENT_STREAM_ID_LEN];
    ah_random(stream_id, sizeof(stream_id));
    ah_fragmenter_t cutter;
    if (!ah_fragmenter_init(&cutter, &f, b->data, b->len, n->links.links[link].max_write, stream_id)) {
        return false;
    }
    if (cutter.total > IMMEDIATE_PIECES || ah_pool_free(&n->links.pool) < cutter.total + AH_POOL_RESERVE ||
            ah_links_room(&n->links, link) < cutter.total) {
        return ah_node_big_send(n, link, b->data, b->len, prio, token, now_ms);
    }
    if (token != 0) {
        ah_node_mail_cut(n, token, cutter.total);
    }
    uint8_t piece[AH_FRAME_BUF_MAX];
    size_t len;
    while ((len = ah_fragmenter_next(&cutter, piece, sizeof(piece))) > 0) {
        if (!queue_piece(n, link, piece, len, prio, deadline_ms, token, now_ms)) {
            return false;
        }
    }
    return true;
}

// Queue a pooled frame on one link, cut when it is too large for one write,
// and say whether the frame or its cut was queued.
static bool enqueue_on(ah_node_t *n, uint16_t link, uint16_t buf, ah_prio_t prio, int64_t deadline_ms, uint32_t token,
                       int64_t now_ms)
{
    const ah_link_t *l = &n->links.links[link];
    const bool queued = ah_pool_get(&n->links.pool, buf)->len > l->max_write
                        ? enqueue_cut(n, link, buf, prio, deadline_ms, token, now_ms)
                        : ah_links_enqueue(&n->links, link, buf, prio, deadline_ms, token, now_ms);
    ah_node_drain(n, link, now_ms);
    return queued;
}

// Whether this frame may go out on LoRa, asked once per frame so a throttle
// or a token is spent once however many trunk neighbors there are.
static bool trunk_allows(ah_node_t *n, const ah_frame_t *f, int64_t now_ms)
{
    uint8_t inner = 0;
    uint16_t total = 0;
    if (f->type == AH_TYPE_FRAGMENT) {
        size_t len = 0;
        ah_fragment_t frag;
        if (!ah_payload_decode(f, n->inflater, n->scratch, sizeof(n->scratch), &len) ||
                !ah_fragment_parse(n->scratch, len, &frag)) {
            return false;
        }
        inner = frag.inner_type;
        total = frag.total;
    }
    if (!ah_trunk_policy_admit(&n->trunk, f, inner, total, now_ms)) {
        n->stats.trunk_refused++;
        return false;
    }
    return true;
}

// Whether a message must take its sender's announce across the trunk: none
// went first recently, so far-side receivers lack the key it verifies against
// (PROTOCOLS section 10.2).
static bool needs_announce_ahead(const ah_node_t *n, const ah_frame_t *f, int64_t now_ms)
{
    return f->type != AH_TYPE_ANNOUNCE && f->type != AH_TYPE_FRAGMENT &&
           ah_trunk_policy_needs_announce(&n->trunk, f->sender, now_ms);
}

// Types a far-side phone verifies against the signing key its sender's
// announce carries: a public message, a location channel message, a leave.
static bool verified_by_announce(uint8_t type)
{
    return type == AH_TYPE_CHANNEL_MSG || type == AH_TYPE_CHANNEL_MSG_AIRHOP || type == AH_TYPE_LEAVE;
}

// Queue the sender's stored announce first on one trunk link, carried on like
// any relay at one hop less than it arrived with, and say whether it went.
static bool trunk_announce_ahead(ah_node_t *n, const ah_frame_t *f, uint16_t link, int64_t now_ms)
{
    size_t len = 0;
    const uint8_t *stored = ah_sync_latest_announce(&n->sync, f->sender, &len);
    if (stored == NULL || len > AH_FRAME_BUF_MAX || stored[AH_OFF_TTL] <= 1u) {
        return false;
    }
    const uint16_t buf = ah_pool_copy(&n->links.pool, stored, len, AH_POOL_RESERVE);
    if (buf == AH_BUF_NONE) {
        return false;
    }
    ah_pool_get(&n->links.pool, buf)->data[AH_OFF_TTL]--;
    const bool queued = ah_links_enqueue(&n->links, link, buf, AH_PRIO_ANNOUNCE, 0, 0, now_ms);
    ah_pool_unref(&n->links.pool, buf);
    return queued;
}

// Fan a pooled frame out as a relay or an origination, and count the links it
// was queued on. `own_announce` sends the node's own announce on every link:
// it is what binds them.
static size_t fanout(ah_node_t *n, uint16_t buf, uint16_t from_link, uint16_t from_peer, ah_prio_t prio,
                     int64_t deadline_ms, bool own_announce, uint32_t token, int64_t now_ms)
{
    const ah_frame_buf_t *b = ah_pool_get(&n->links.pool, buf);
    ah_frame_t f;
    if (!ah_frame_parse(b->data, b->len, &f)) {
        return 0;
    }
    // A source route naming us goes to the hop after us alone, as Airhop and
    // bitchat follow one; failing that, a directed packet whose recipient is
    // one of our neighbors goes to that neighbor alone, as bitchat-ios's
    // fanout sends it. A hop we cannot reach floods, which heals the break.
    uint16_t only = AH_LINK_NONE;
    if (!own_announce) {
        const uint8_t *targets[2] = {NULL, ah_frame_is_broadcast(&f) ? NULL : f.recipient};
        ah_frame_next_hop(&f, n->id.peer_id, &targets[0]);
        for (size_t t = 0; t < 2u && only == AH_LINK_NONE; ++t) {
            const uint16_t to = targets[t] != NULL ? ah_peers_find(&n->peers, targets[t]) : AH_PEER_NONE;
            if (to != AH_PEER_NONE && n->peers.slots[to].direct_link != AH_LINK_NONE && to != from_peer &&
                    n->peers.slots[to].direct_link != from_link) {
                only = n->peers.slots[to].direct_link;
            }
        }
    }
    // A phone's announce on the trunk is presence, behind text; the node's
    // own, and one carried ahead of a message, go first.
    const ah_prio_t trunk_prio = f.type == AH_TYPE_ANNOUNCE && !own_announce ? AH_PRIO_PRESENCE : prio;
    // Asked at the first trunk link, once for all of them: -1 until then.
    int trunk = -1;
    int ahead = -1;
    bool carried_ahead = false;
    bool own_on_trunk = false;
    size_t queued = 0;
    for (uint16_t i = 0; i < n->links.capacity; ++i) {
        const ah_link_t *l = &n->links.links[i];
        if (!l->in_use || i == from_link || (only != AH_LINK_NONE && i != only)) {
            continue;
        }
        if (l->peer != AH_PEER_NONE && !own_announce) {
            if (l->peer == from_peer) {
                continue;
            }
            // One copy per neighbor, on its direct link while it has one.
            const uint16_t direct = n->peers.slots[l->peer].direct_link;
            if (direct != AH_LINK_NONE && direct != i) {
                continue;
            }
        }
        ah_prio_t link_prio = prio;
        if (l->kind == AH_LINK_LORA) {
            // A trunk neighbor nobody has verified gets our own announce and
            // nothing else, not every packet: any radio can make an identity
            // and beacon under it. The trunk sends it in one round with no
            // probe, within a share of the budget for all unverified
            // neighbors, so a new identity costs one announce frame. It
            // keeps going at each interval while the link lasts, so two
            // nodes that both missed the other's first never wait on each other.
            if (l->peer == AH_PEER_NONE && !own_announce) {
                continue;
            }
            if (trunk < 0) {
                trunk = trunk_allows(n, &f, now_ms) ? 1 : 0;
            }
            if (trunk == 0) {
                continue;
            }
            if (ahead < 0) {
                ahead = needs_announce_ahead(n, &f, now_ms) ? 1 : 0;
            }
            if (ahead == 1) {
                if (trunk_announce_ahead(n, &f, i, now_ms)) {
                    carried_ahead = true;
                } else if (verified_by_announce(f.type)) {
                    // With no announce of its sender to go ahead (a made-up
                    // sender has none), the far side would drop it.
                    n->stats.trunk_refused++;
                    continue;
                }
            }
            link_prio = trunk_prio;
        }
        if (enqueue_on(n, i, buf, link_prio, deadline_ms, token, now_ms)) {
            queued++;
            if (own_announce) {
                n->links.links[i].announced = true;
                own_on_trunk = own_on_trunk || l->kind == AH_LINK_LORA;
            }
        }
    }
    if (carried_ahead) {
        ah_trunk_policy_note_ahead(&n->trunk, f.sender, now_ms);
    }
    if (own_on_trunk) {
        ah_trunk_policy_note_ahead(&n->trunk, n->id.peer_id, now_ms);
    }
    return queued;
}

bool ah_node_originate(ah_node_t *n, const ah_frame_fields_t *fields, bool sign, uint16_t link, int64_t now_ms,
                       uint32_t token)
{
    uint8_t *frame = n->frame_out;
    size_t len = ah_frame_encode(fields, sign, frame, AH_FRAME_BUF_MAX);
    if (len == 0) {
        return false;
    }
    if (sign) {
        ah_frame_t view;
        size_t pre_len = 0;
        if (!ah_frame_parse(frame, len, &view) ||
                !ah_frame_signing_preimage(&view, n->scratch, sizeof(n->scratch), &pre_len)) {
            return false;
        }
        uint8_t signature[AH_SIGNATURE_LEN];
        ah_ed25519_sign(n->id.signing_secret, n->scratch, pre_len, signature);
        ah_frame_attach_signature(frame, len, signature);
    }
    if (ah_frame_pads_on_air(fields->type)) {
        len = ah_pad(frame, len, sizeof(n->frame_out));
    }
    ah_frame_t view;
    if (!ah_frame_parse(frame, len, &view)) {
        return false;
    }
    uint8_t id[AH_PACKET_ID_LEN];
    if (ah_packet_id(&view, NULL, id)) {
        // Our own packet echoed back is never relayed or handled again.
        ah_dedup_add(&n->dedup[ah_dedup_class_of(fields->type)], id, (uint32_t)(now_ms / 1000));
    }
    if (len > AH_FRAME_BUF_MAX) {
        return link != AH_LINK_NONE && ah_node_big_send(n, link, frame, len, ah_priority_of(&view), token, now_ms);
    }
    const uint16_t buf = ah_pool_copy(&n->links.pool, frame, len, 0);
    if (buf == AH_BUF_NONE) {
        return false;
    }
    const ah_prio_t prio = ah_priority_of(&view);
    const bool queued = link != AH_LINK_NONE
                        ? enqueue_on(n, link, buf, prio, 0, token, now_ms)
                        : fanout(n, buf, AH_LINK_NONE, AH_PEER_NONE, prio, 0, fields->type == AH_TYPE_ANNOUNCE, token,
                                 now_ms) > 0;
    ah_pool_unref(&n->links.pool, buf);
    return queued;
}

bool ah_node_originate_big(ah_node_t *n, const ah_frame_fields_t *fields, uint16_t link, uint32_t token,
                           int64_t now_ms)
{
    if (n->big.active || link == AH_LINK_NONE) {
        return false;
    }
    const size_t len = ah_frame_encode(fields, true, n->big.bytes, n->cfg.big_send_bytes);
    ah_frame_t view;
    size_t pre_len = 0;
    if (len == 0 || !ah_frame_parse(n->big.bytes, len, &view) ||
            !ah_frame_signing_preimage(&view, n->big.preimage, (size_t)n->cfg.big_send_bytes + AH_PAD_MAX, &pre_len)) {
        return false;
    }
    uint8_t signature[AH_SIGNATURE_LEN];
    ah_ed25519_sign(n->id.signing_secret, n->big.preimage, pre_len, signature);
    ah_frame_attach_signature(n->big.bytes, len, signature);
    uint8_t id[AH_PACKET_ID_LEN];
    if (ah_packet_id(&view, NULL, id)) {
        ah_dedup_add(&n->dedup[ah_dedup_class_of(fields->type)], id, (uint32_t)(now_ms / 1000));
    }
    return ah_node_big_send(n, link, n->big.bytes, len, ah_priority_of(&view), token, now_ms);
}

static void send_announce(ah_node_t *n, uint16_t link, int64_t now_ms)
{
    uint64_t wall;
    if (!ah_clock_synced(&n->clock) || !ah_clock_now(&n->clock, now_ms, &wall)) {
        return;
    }
    uint8_t payload[160];
    const size_t len = ah_announce_encode(n->id.nickname, n->id.nickname_len, n->id.noise_public,
                                          n->id.signing_public, n->id.firmware_version, AH_RELAY_FLAG_DEDICATED,
                                          payload, sizeof(payload));
    if (len == 0) {
        return;
    }
    const ah_frame_fields_t fields = {
        .type = AH_TYPE_ANNOUNCE,
        .ttl = AH_TTL_DEFAULT,
        .timestamp_ms = wall,
        .sender = n->id.peer_id,
        .recipient = NULL,
        .payload = payload,
        .payload_len = len,
    };
    // Every link that took it is marked announced: here for one link, in the
    // fanout for all of them.
    if (!ah_node_originate(n, &fields, true, link, now_ms, 0)) {
        return;
    }
    if (link != AH_LINK_NONE) {
        n->links.links[link].announced = true;
        if (n->links.links[link].kind == AH_LINK_LORA) {
            // A trunk neighbor is told directly, outside the periodic throttle.
            ah_trunk_policy_note_ahead(&n->trunk, n->id.peer_id, now_ms);
        }
    }
}

// ---- relay scheduler ----

static void fire_relays(ah_node_t *n, int64_t now_ms)
{
    for (uint16_t i = 0; i < n->cfg.relay_slots; ++i) {
        ah_pending_relay_t *r = &n->relays[i];
        if (!r->in_use || r->due_ms > now_ms) {
            continue;
        }
        r->in_use = false;
        if (r->deadline_ms == 0 || now_ms <= r->deadline_ms) {
            fanout(n, r->buf, r->from_link, r->from_peer, (ah_prio_t)r->prio, r->deadline_ms, false, 0, now_ms);
        }
        ah_pool_unref(&n->links.pool, r->buf);
    }
}

bool ah_node_schedule_relay(ah_node_t *n, const uint8_t *frame, size_t len, uint8_t ttl, uint32_t jitter_min_ms,
                            uint32_t jitter_max_ms, uint16_t from_link, uint16_t from_peer, ah_prio_t prio,
                            int64_t deadline_ms, int64_t now_ms)
{
    for (uint16_t i = 0; i < n->cfg.relay_slots; ++i) {
        ah_pending_relay_t *r = &n->relays[i];
        if (r->in_use) {
            continue;
        }
        // The relayed copy is the received frame byte for byte, its padding
        // included, with only the TTL changed (PROTOCOLS section 2.2: a relay
        // never re-encodes). It leaves the pool's reserve to the node's own.
        const uint16_t buf = ah_pool_copy(&n->links.pool, frame, len, AH_POOL_RESERVE);
        if (buf == AH_BUF_NONE) {
            break;
        }
        ah_pool_get(&n->links.pool, buf)->data[AH_OFF_TTL] = ttl;
        r->in_use = true;
        r->buf = buf;
        r->due_ms = now_ms + (int64_t)ah_random_range(jitter_min_ms, jitter_max_ms);
        r->from_link = from_link;
        r->from_peer = from_peer;
        r->prio = (uint8_t)prio;
        r->deadline_ms = deadline_ms;
        n->stats.relayed++;
        return true;
    }
    n->stats.relay_dropped++;
    return false;
}

static int64_t next_relay_due(const ah_node_t *n, int64_t horizon)
{
    for (uint16_t i = 0; i < n->cfg.relay_slots; ++i) {
        if (n->relays[i].in_use && n->relays[i].due_ms < horizon) {
            horizon = n->relays[i].due_ms;
        }
    }
    return horizon;
}

// ---- timers ----

static int64_t announce_interval(const ah_node_t *n)
{
    const bool dense = ah_node_degree(n) >= AH_DEGREE_DENSE;
    const uint32_t base = dense ? ANNOUNCE_DENSE_MS : ANNOUNCE_SPARSE_MS;
    const uint32_t jitter = dense ? ANNOUNCE_DENSE_JITTER_MS : ANNOUNCE_SPARSE_JITTER_MS;
    return (int64_t)ah_random_range(base - jitter, base + jitter);
}

static void maintenance(ah_node_t *n, int64_t now_ms)
{
    ah_reassembly_expire(&n->reassembly, now_ms);
    ah_dm_expire(n, now_ms);
    ah_courier_expire_held(&n->courier, now_ms);
    // Pruning history and expiring mail by the clock wait for two phones to
    // agree; serving and filtering hold each entry to its window anyway.
    // Before then, the restored floor plus uptime is a time real time is
    // surely past: mail expires by it and the floor climbs with it, so a node
    // rebooted nightly with no two phones in reach still frees its mailbox.
    uint64_t wall;
    uint64_t lower = 0;
    const bool bounded = ah_clock_lower_bound(&n->clock, n->started_ms, now_ms, &lower);
    uint64_t floor = lower;
    bool have_floor = bounded;
    if (ah_clock_confirmed(&n->clock) && ah_clock_now(&n->clock, now_ms, &wall)) {
        ah_sync_prune(&n->sync, wall);
        ah_node_mail_expire(n, now_ms);
        uint64_t confirmed;
        if (ah_clock_floor(&n->clock, now_ms, &confirmed) && confirmed > floor) {
            floor = confirmed;
            have_floor = true;
        }
    } else if (bounded) {
        ah_courier_expire(&n->courier, lower);
    }
    // Saved only when it moved.
    if (have_floor && floor != n->saved_floor_ms && now_ms >= n->next_clock_save_ms && n->ops.clock_save != NULL) {
        n->ops.clock_save(n->ops.ctx, floor);
        n->saved_floor_ms = floor;
        n->next_clock_save_ms = now_ms + CLOCK_SAVE_MS;
    }
}

int64_t ah_node_tick(ah_node_t *n, int64_t now_ms)
{
    if (n->started_ms < 0) {
        n->started_ms = now_ms;
    }
    fire_relays(n, now_ms);
    int64_t next = now_ms + MAINTENANCE_MS;
    if (n->big.active && now_ms - n->big.progress_ms > AH_LINK_STALE_MS) {
        // A cut nothing has moved for this long is given up, so one slow link
        // cannot hold every other link's handovers and long replies.
        n->big.active = false;
    }

    bool any_link = false;
    for (uint16_t i = 0; i < n->links.capacity; ++i) {
        ah_link_t *l = &n->links.links[i];
        if (!l->in_use) {
            continue;
        }
        any_link = true;
        ah_link_extra_t *x = &n->extra[i];
        if (x->announce_due_ms != 0 && now_ms >= x->announce_due_ms) {
            send_announce(n, i, now_ms);
            x->announce_due_ms = l->announced ? 0 : now_ms + ANNOUNCE_RETRY_MS;
        }
        if (x->announce_due_ms != 0 && x->announce_due_ms < next) {
            next = x->announce_due_ms;
        }
        if (x->next_round_ms != 0 && now_ms >= x->next_round_ms) {
            ah_node_sync_round(n, i, now_ms);
        }
        if (x->next_round_ms != 0 && x->next_round_ms < next) {
            next = x->next_round_ms;
        }
        // A link the transport keeps busy still lets go of what went stale.
        ah_links_expire(&n->links, i, now_ms);
        if (!l->busy && (l->queued > 0 || ah_node_sync_pending(n, i) || (n->big.active && n->big.link == i))) {
            ah_node_drain(n, i, now_ms);
        }
    }

    if (any_link && now_ms >= n->next_announce_ms) {
        send_announce(n, AH_LINK_NONE, now_ms);
        n->next_announce_ms = now_ms + announce_interval(n);
    }
    if (any_link && n->next_announce_ms < next) {
        next = n->next_announce_ms;
    }
    if (now_ms >= n->next_maintenance_ms) {
        maintenance(n, now_ms);
        n->next_maintenance_ms = now_ms + MAINTENANCE_MS;
    }
    return next_relay_due(n, next);
}
