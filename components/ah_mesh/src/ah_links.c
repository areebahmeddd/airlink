// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Link slots, the reference-counted frame pool with its reserve, and each link's
// priority queue.
#include "ah_links.h"

#include <string.h>

// A queue's share of the pool, and the least a queue gets on a small pool:
// enough for a frame cut in three and an announce beside it.
#define POOL_SHARE_DIVISOR 4u
#define QUEUE_FLOOR 4u

ah_prio_t ah_priority_of(const ah_frame_t *frame)
{
    if (frame->flags & AH_FLAG_IS_RSR) {
        return AH_PRIO_SYNC;
    }
    switch (frame->type) {
    case AH_TYPE_ANNOUNCE:
        return AH_PRIO_ANNOUNCE;
    case AH_TYPE_NOISE_HANDSHAKE:
    case AH_TYPE_PING:
    case AH_TYPE_PONG:
        return AH_PRIO_HANDSHAKE;
    case AH_TYPE_NOISE_ENCRYPTED:
    case AH_TYPE_DR_ENCRYPTED:
    case AH_TYPE_COURIER_ENV:
    case AH_TYPE_NOSTR_CARRIER:
        return AH_PRIO_DIRECTED;
    case AH_TYPE_CHANNEL_MSG:
    case AH_TYPE_CHANNEL_MSG_AIRHOP:
    case AH_TYPE_CHANNEL_ENC:
    case AH_TYPE_GROUP_MESSAGE:
    case AH_TYPE_BOARD_POST:
    case AH_TYPE_LEAVE:
    case AH_TYPE_REQUEST_SYNC:
        return AH_PRIO_PUBLIC;
    case AH_TYPE_VOICE_FRAME:
    case AH_TYPE_VIDEO_FRAME:
        return AH_PRIO_LIVE;
    default:
        return AH_PRIO_BULK;
    }
}

void ah_links_init(ah_links_t *t, ah_link_t *links, uint16_t capacity, ah_queued_t *queue_storage, uint8_t queue_cap,
                   ah_frame_buf_t *bufs, uint16_t buf_count)
{
    memset(links, 0, sizeof(*links) * capacity);
    t->links = links;
    t->capacity = capacity;
    t->seq = 0;
    t->dropped = 0;
    size_t share = buf_count / POOL_SHARE_DIVISOR;
    share = share < QUEUE_FLOOR ? QUEUE_FLOOR : share;
    const uint8_t cap = share < queue_cap ? (uint8_t)share : queue_cap;
    for (uint16_t i = 0; i < capacity; ++i) {
        links[i].queue = queue_storage + (size_t)i * queue_cap;
        links[i].queue_cap = cap;
        links[i].peer = AH_PEER_NONE;
    }
    t->pool.bufs = bufs;
    t->pool.capacity = buf_count;
    t->pool.in_use = 0;
    t->pool.exhausted = 0;
    for (uint16_t i = 0; i < buf_count; ++i) {
        bufs[i].refs = 0;
        bufs[i].len = 0;
        bufs[i].next_free = i + 1u < buf_count ? (uint16_t)(i + 1u) : AH_BUF_NONE;
    }
    t->pool.free_head = buf_count > 0 ? 0 : AH_BUF_NONE;
}

uint16_t ah_pool_free(const ah_pool_t *pool)
{
    return (uint16_t)(pool->capacity - pool->in_use);
}

uint16_t ah_pool_copy(ah_pool_t *pool, const uint8_t *frame, size_t len, uint16_t keep_free)
{
    if (len > AH_FRAME_BUF_MAX || pool->free_head == AH_BUF_NONE || ah_pool_free(pool) <= keep_free) {
        pool->exhausted++;
        return AH_BUF_NONE;
    }
    const uint16_t i = pool->free_head;
    ah_frame_buf_t *b = &pool->bufs[i];
    pool->free_head = b->next_free;
    b->next_free = AH_BUF_NONE;
    b->refs = 1;
    b->len = (uint16_t)len;
    memcpy(b->data, frame, len);
    pool->in_use++;
    return i;
}

static void pool_ref(ah_pool_t *pool, uint16_t buf)
{
    pool->bufs[buf].refs++;
}

void ah_pool_unref(ah_pool_t *pool, uint16_t buf)
{
    ah_frame_buf_t *b = &pool->bufs[buf];
    if (b->refs == 0) {
        return;
    }
    if (--b->refs == 0) {
        b->next_free = pool->free_head;
        pool->free_head = buf;
        pool->in_use--;
    }
}

ah_frame_buf_t *ah_pool_get(ah_pool_t *pool, uint16_t buf)
{
    return &pool->bufs[buf];
}

uint16_t ah_links_open(ah_links_t *t, ah_link_kind_t kind, uint32_t handle, uint16_t max_write,
                       const uint8_t expected[AH_PEER_ID_LEN])
{
    for (uint16_t i = 0; i < t->capacity; ++i) {
        ah_link_t *l = &t->links[i];
        if (!l->in_use) {
            ah_queued_t *queue = l->queue;
            const uint8_t cap = l->queue_cap;
            memset(l, 0, sizeof(*l));
            l->queue = queue;
            l->queue_cap = cap;
            l->in_use = true;
            l->kind = kind;
            l->handle = handle;
            l->max_write = max_write > AH_FRAME_BUF_MAX ? AH_FRAME_BUF_MAX : max_write;
            l->peer = AH_PEER_NONE;
            if (expected != NULL) {
                l->has_expected = true;
                memcpy(l->expected, expected, AH_PEER_ID_LEN);
            }
            return i;
        }
    }
    return AH_LINK_NONE;
}

void ah_links_close(ah_links_t *t, uint16_t link)
{
    ah_link_t *l = &t->links[link];
    for (uint8_t i = 0; i < l->queued; ++i) {
        ah_pool_unref(&t->pool, l->queue[i].buf);
    }
    l->queued = 0;
    l->in_use = false;
    l->peer = AH_PEER_NONE;
}

uint16_t ah_links_by_handle(const ah_links_t *t, ah_link_kind_t kind, uint32_t handle)
{
    for (uint16_t i = 0; i < t->capacity; ++i) {
        const ah_link_t *l = &t->links[i];
        if (l->in_use && l->kind == kind && l->handle == handle) {
            return i;
        }
    }
    return AH_LINK_NONE;
}

bool ah_links_may_bind(const ah_link_t *l, const uint8_t peer_id[AH_PEER_ID_LEN])
{
    return !l->has_expected || memcmp(l->expected, peer_id, AH_PEER_ID_LEN) == 0;
}

// The entry to give up when the queue is full: lowest priority, newest within it.
static uint8_t victim_of(const ah_link_t *l)
{
    uint8_t v = 0;
    for (uint8_t i = 1; i < l->queued; ++i) {
        const ah_queued_t *a = &l->queue[i];
        const ah_queued_t *b = &l->queue[v];
        if (a->prio > b->prio || (a->prio == b->prio && a->seq > b->seq)) {
            v = i;
        }
    }
    return v;
}

static void remove_at(ah_link_t *l, uint8_t i)
{
    l->queue[i] = l->queue[l->queued - 1u];
    l->queued--;
}

bool ah_links_enqueue(ah_links_t *t, uint16_t link, uint16_t buf, ah_prio_t prio, int64_t deadline_ms,
                      uint32_t token, int64_t now_ms)
{
    ah_link_t *l = &t->links[link];
    if (!l->in_use) {
        return false;
    }
    if (l->queued == l->queue_cap) {
        const uint8_t v = victim_of(l);
        t->dropped++;
        if (l->queue[v].prio <= (uint8_t)prio) {
            return false;
        }
        ah_pool_unref(&t->pool, l->queue[v].buf);
        remove_at(l, v);
    }
    ah_queued_t *q = &l->queue[l->queued++];
    q->buf = buf;
    q->prio = (uint8_t)prio;
    const int64_t stale_ms = l->kind == AH_LINK_LORA ? AH_LINK_STALE_LORA_MS : AH_LINK_STALE_MS;
    q->deadline_ms = deadline_ms != 0 ? deadline_ms : now_ms + stale_ms;
    q->seq = ++t->seq;
    q->token = token;
    pool_ref(&t->pool, buf);
    return true;
}

uint8_t ah_links_room(const ah_links_t *t, uint16_t link)
{
    const ah_link_t *l = &t->links[link];
    return (uint8_t)(l->queue_cap - l->queued);
}

ah_queued_t ah_links_dequeue(ah_links_t *t, uint16_t link, int64_t now_ms)
{
    ah_link_t *l = &t->links[link];
    while (l->queued > 0) {
        uint8_t best = 0;
        for (uint8_t i = 1; i < l->queued; ++i) {
            const ah_queued_t *a = &l->queue[i];
            const ah_queued_t *b = &l->queue[best];
            if (a->prio < b->prio || (a->prio == b->prio && a->seq < b->seq)) {
                best = i;
            }
        }
        const ah_queued_t q = l->queue[best];
        remove_at(l, best);
        if (now_ms > q.deadline_ms) {
            ah_pool_unref(&t->pool, q.buf);
            t->dropped++;
            continue;
        }
        return q;
    }
    return (ah_queued_t) {
        .buf = AH_BUF_NONE
    };
}

void ah_links_requeue(ah_links_t *t, uint16_t link, const ah_queued_t *entry)
{
    ah_link_t *l = &t->links[link];
    if (!l->in_use || l->queued == l->queue_cap) {
        ah_pool_unref(&t->pool, entry->buf);
        t->dropped++;
        return;
    }
    // Sequence 0 sorts it ahead of everything else at its priority. The
    // queue's reference is the one the dequeue handed over.
    ah_queued_t *q = &l->queue[l->queued++];
    *q = *entry;
    q->seq = 0;
}

void ah_links_expire(ah_links_t *t, uint16_t link, int64_t now_ms)
{
    ah_link_t *l = &t->links[link];
    for (uint8_t i = 0; i < l->queued;) {
        if (now_ms > l->queue[i].deadline_ms) {
            ah_pool_unref(&t->pool, l->queue[i].buf);
            remove_at(l, i);
            t->dropped++;
        } else {
            ++i;
        }
    }
}
