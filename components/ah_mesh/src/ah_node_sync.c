// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Gossip sync over a link: asking each bound neighbor in the phones' rounds,
// and answering a neighbor's request from the stores (PROTOCOLS section 5).
#include <string.h>

#include "ah_node_priv.h"

// The message round every 15 s (announces, public, group and location-channel
// messages), the board alone every fourth, the first round included.
#define MESSAGE_ROUND_TYPES \
    ((1ull << AH_SYNC_BIT_ANNOUNCE) | (1ull << AH_SYNC_BIT_MESSAGE) | (1ull << AH_SYNC_BIT_GROUP) | \
     (1ull << AH_SYNC_BIT_CHANNEL_AIRHOP))
#define BOARD_ROUND_TYPES (1ull << AH_SYNC_BIT_BOARD)
// A request is a 400-byte filter plus its TLVs.
#define REQUEST_PAYLOAD_MAX (AH_GCS_MAX_BYTES + 64u)
// Replies leave this many queue slots, and this many buffers beyond the
// pool's reserve, to anything more urgent.
#define REPLY_QUEUE_HEADROOM 2u
#define REPLY_POOL_HEADROOM 4u

bool ah_node_sync_reply_expected(const ah_node_t *n, uint16_t link, int64_t now_ms)
{
    const ah_link_extra_t *x = &n->extra[link];
    return n->links.links[link].peer != AH_PEER_NONE && x->request_sent_ms != 0 &&
           now_ms - x->request_sent_ms <= (int64_t)AH_SYNC_PENDING_REQUEST_MS;
}

bool ah_node_sync_pending(const ah_node_t *n, uint16_t link)
{
    const ah_reply_backlog_t *b = &n->extra[link].backlog;
    return b->next < b->count;
}

// The oldest of the last eight answers bounds the rate: 8 per 30 s per link.
static bool request_budget_left(const ah_link_extra_t *x, int64_t now_ms)
{
    const int64_t oldest = x->answered_ms[x->answered_next];
    return oldest == 0 || now_ms - oldest >= (int64_t)AH_SYNC_RESPONSE_WINDOW_MS;
}

static void spend_request_budget(ah_link_extra_t *x, int64_t now_ms)
{
    x->answered_ms[x->answered_next] = now_ms;
    x->answered_next = (uint8_t)((x->answered_next + 1u) % AH_SYNC_RESPONSES_PER_WINDOW);
}

static bool same_ref(const ah_sync_ref_t *a, const ah_sync_ref_t *b)
{
    return a->store == b->store && a->slot == b->slot && a->seq == b->seq;
}

// Plan the reply to a request behind whatever of the last reply is still to
// go: the phones ask for the message and board rounds back to back, and the
// second must not cut the first short.
static void plan_reply(ah_node_t *n, ah_reply_backlog_t *b, const ah_sync_request_t *req, uint64_t wall)
{
    const uint16_t left = (uint16_t)(b->count - b->next);
    memmove(b->refs, b->refs + b->next, (size_t)left * sizeof(*b->refs));
    const size_t planned = ah_sync_plan_reply(&n->sync, req, wall, b->refs + left, n->cfg.reply_backlog - left);
    uint16_t count = left;
    for (size_t i = 0; i < planned; ++i) {
        const ah_sync_ref_t r = b->refs[left + i];
        bool queued = false;
        for (uint16_t j = 0; j < left && !queued; ++j) {
            queued = same_ref(&b->refs[j], &r);
        }
        if (!queued) {
            b->refs[count++] = r;
        }
    }
    b->count = count;
    b->next = 0;
}

void ah_node_sync_on_request(ah_node_t *n, uint16_t link, const ah_frame_t *f, int64_t now_ms)
{
    const ah_link_t *l = &n->links.links[link];
    // Answered only when it is plainly the link peer's own: TTL 0, from the
    // peer bound to this link, signed by them, and for us or for no one. Sync
    // is a Bluetooth exchange, as the trunk policy keeps sync off LoRa and the
    // node asks no LoRa neighbor itself; answering there would cost up to a
    // backlog of transfers of airtime.
    if (f->ttl != 0 || l->kind != AH_LINK_BLE || l->peer == AH_PEER_NONE ||
            (f->recipient != NULL && !ah_frame_is_broadcast(f) && !ah_frame_is_for(f, n->id.peer_id))) {
        return;
    }
    const ah_peer_t *p = &n->peers.slots[l->peer];
    ah_link_extra_t *x = &n->extra[link];
    uint64_t wall;
    // A request past the rate would be refused once it decoded, so it is
    // refused before its signature costs a check.
    if (memcmp(p->peer_id, f->sender, AH_PEER_ID_LEN) != 0 || !ah_clock_synced(&n->clock) ||
            !ah_clock_now(&n->clock, now_ms, &wall) || !request_budget_left(x, now_ms) ||
            ah_node_verify(n, f, p->signing_key, false, now_ms) != AH_VERIFIED) {
        return;
    }
    size_t len = 0;
    ah_sync_request_t req;
    if (ah_node_decode(n, f, n->scratch, sizeof(n->scratch), &len, now_ms) != AH_VERIFIED ||
            !ah_sync_request_decode(n->scratch, len, &req)) {
        return;
    }
    // Only a request that decodes spends the budget (bitchat-ios).
    spend_request_budget(x, now_ms);
    plan_reply(n, &x->backlog, &req, wall);
    ah_node_drain(n, link, now_ms);
}

void ah_node_sync_drain(ah_node_t *n, uint16_t link, int64_t now_ms)
{
    ah_link_t *l = &n->links.links[link];
    ah_reply_backlog_t *b = &n->extra[link].backlog;
    // Replies take the lowest priority and leave room in the queue, so
    // anything live or more urgent still gets in.
    while (b->next < b->count && l->in_use && l->queued + REPLY_QUEUE_HEADROOM < l->queue_cap &&
            ah_pool_free(&n->links.pool) > AH_POOL_RESERVE + REPLY_POOL_HEADROOM) {
        size_t len = 0;
        const uint8_t *bytes = ah_sync_entry_bytes(&n->sync, b->refs[b->next], &len);
        if (bytes == NULL) {
            b->next++;
            continue;
        }
        if (len > l->max_write) {
            uint8_t *copy = n->big.bytes;
            if (len > n->cfg.big_send_bytes) {
                // Never sendable: passed over rather than stalling the reply.
                b->next++;
                continue;
            }
            if (n->big.active) {
                // One streamed cut at a time; this one waits for the next drain.
                return;
            }
            memcpy(copy, bytes, len);
            copy[AH_OFF_TTL] = 0;
            copy[AH_OFF_FLAGS] |= AH_FLAG_IS_RSR;
            // Passed whether or not the cut starts: one that cannot never could,
            // and waiting on it would stall the rest of the reply.
            b->next++;
            if (ah_node_big_send(n, link, copy, len, AH_PRIO_SYNC, 0, now_ms)) {
                n->stats.sync_served++;
            }
            return;
        }
        const uint16_t buf = ah_pool_copy(&n->links.pool, bytes, len, 0);
        if (buf == AH_BUF_NONE) {
            return;
        }
        // TTL 0 and IS_RSR are both outside the signing preimage, so the
        // original signature still verifies (PROTOCOLS section 5.1).
        ah_frame_buf_t *fb = ah_pool_get(&n->links.pool, buf);
        fb->data[AH_OFF_TTL] = 0;
        fb->data[AH_OFF_FLAGS] |= AH_FLAG_IS_RSR;
        ah_links_enqueue(&n->links, link, buf, AH_PRIO_SYNC, 0, 0, now_ms);
        ah_pool_unref(&n->links.pool, buf);
        b->next++;
        n->stats.sync_served++;
    }
}

static void send_request(ah_node_t *n, uint16_t link, uint64_t types, uint64_t wall, int64_t now_ms)
{
    const ah_link_t *l = &n->links.links[link];
    uint8_t payload[REQUEST_PAYLOAD_MAX];
    const size_t len = ah_sync_build_request(&n->sync, types, wall, payload, sizeof(payload));
    if (len == 0) {
        return;
    }
    const ah_frame_fields_t fields = {
        .type = AH_TYPE_REQUEST_SYNC,
        .ttl = 0,
        .timestamp_ms = wall,
        .sender = n->id.peer_id,
        .recipient = n->peers.slots[l->peer].peer_id,
        .payload = payload,
        .payload_len = len,
    };
    // Registered before the send, so a reply racing the write is still ours.
    n->extra[link].request_sent_ms = now_ms;
    ah_node_originate(n, &fields, true, link, now_ms, 0);
}

void ah_node_sync_round(ah_node_t *n, uint16_t link, int64_t now_ms)
{
    const ah_link_t *l = &n->links.links[link];
    ah_link_extra_t *x = &n->extra[link];
    x->next_round_ms = now_ms + AH_SYNC_ROUND_MS;
    uint64_t wall;
    // A peer verifies our request against our announce, so ask only once it went out.
    if (l->kind != AH_LINK_BLE || l->peer == AH_PEER_NONE || !l->announced || !ah_clock_synced(&n->clock) ||
            !ah_clock_now(&n->clock, now_ms, &wall)) {
        return;
    }
    // A store that gave up entries for room asks only above the newest it
    // lost. Asked in one request with stores that have room, that cursor
    // would hold their history back too, so those go in a request of their
    // own: at most seven requests in any 30 s with the board's, inside the
    // eight a phone answers.
    const uint64_t evicted = ah_sync_evicted_types(&n->sync, MESSAGE_ROUND_TYPES);
    if (evicted != 0 && evicted != MESSAGE_ROUND_TYPES) {
        send_request(n, link, MESSAGE_ROUND_TYPES & ~evicted, wall, now_ms);
        send_request(n, link, evicted, wall, now_ms);
    } else {
        send_request(n, link, MESSAGE_ROUND_TYPES, wall, now_ms);
    }
    if (x->round % AH_SYNC_BOARD_EVERY_ROUNDS == 0) {
        send_request(n, link, BOARD_ROUND_TYPES, wall, now_ms);
    }
    x->round++;
}
