// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The simulated world: a clock, links with their MTUs, phones that sign and
// verify, and nodes running the real core.
#include "sim.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ah_announce.h"
#include "ah_bytes.h"
#include "ah_crypto.h"
#include "ah_frame.h"
#include "ah_payload.h"
#include "ah_test_crypto.h"

typedef struct {
    sim_world_t *w;
    int index;
} node_ctx_t;

static node_ctx_t s_ctx[SIM_MAX_NODES];
static int64_t s_next_tick[SIM_MAX_NODES];

ah_node_config_t sim_config(void)
{
    return (ah_node_config_t) {
        .links = 12,
        .queue_per_link = 24,
        .frame_buffers = 192,
        .peers = 64,
        .peer_pins = 128,
        .dedup_message_slots = 2048,
        .dedup_fragment_slots = 2048,
        .dedup_live_slots = 4096,
        .sync = {.entries = {64, 128, 32, 64}, .bytes = {16384, 65536, 16384, 32768}, .declined = 64},
        .mail_slots = 16,
        .mail_bytes = 65536,
        .mail_per_depositor = 4,
        .mail_flash_bytes_per_hour = 64u << 20,
        .reassembly_slots = 4,
        .reassembly_bytes = 17408,
        .relay_slots = 96,
        .reply_backlog = 128,
        .verify_per_second = 200,
        .inflate_bytes_per_second = 1u << 20,
        .inflate_window = AH_INFLATE_WINDOW_FULL,
        .trunk_announce_interval_ms = 300000,
        .big_send_bytes = 17408,
        .sessions = 6,
    };
}

void sim_init(sim_world_t *w, uint64_t seed)
{
    memset(w, 0, sizeof(*w));
    ah_test_random_seed(seed);
    memset(s_next_tick, 0, sizeof(s_next_tick));
    // Simulated wall time starts mid-2026, nothing special about it.
    w->wall_offset_ms = 1780000000000ull;
    w->now_ms = 1000;
}

uint64_t sim_wall(const sim_world_t *w)
{
    return w->wall_offset_ms + (uint64_t)w->now_ms;
}

void sim_make_identity(ah_identity_t *id, const char *name)
{
    memset(id, 0, sizeof(*id));
    ah_random(id->noise_secret, sizeof(id->noise_secret));
    ah_x25519_public(id->noise_secret, id->noise_public);
    uint8_t seed[32];
    ah_random(seed, sizeof(seed));
    ah_ed25519_keypair(seed, id->signing_secret, id->signing_public);
    ah_peer_id_of(id->noise_public, id->peer_id);
    const size_t len = strlen(name) > AH_NICKNAME_MAX ? AH_NICKNAME_MAX : strlen(name);
    memcpy(id->nickname, name, len);
    id->nickname_len = (uint8_t)len;
    id->firmware_version = 0x010000;
}

static sim_link_t *link_of_handle(sim_world_t *w, uint32_t handle)
{
    return handle < (uint32_t)w->link_count ? &w->links[handle] : NULL;
}

static ah_write_t node_write(void *ctx, ah_link_kind_t kind, uint32_t handle, const uint8_t *frame, size_t len,
                             uint8_t prio)
{
    (void)kind;
    node_ctx_t *c = ctx;
    sim_world_t *w = c->w;
    sim_link_t *l = link_of_handle(w, handle);
    if (l == NULL || !l->up) {
        return AH_WRITE_GONE;
    }
    if (len > l->max_write) {
        fprintf(stderr, "sim: node %d wrote %zu bytes on a %u-byte link\n", c->index, len, l->max_write);
        abort();
    }
    if (l->write_budget == 0 || w->inflight_count == SIM_MAX_INFLIGHT) {
        return AH_WRITE_BUSY;
    }
    if (l->write_budget > 0) {
        l->write_budget--;
    }
    ah_frame_t view;
    if (w->write_logged < SIM_WRITE_LOG && ah_frame_parse(frame, len, &view)) {
        sim_write_t *log = &w->write_log[w->write_logged++];
        *log = (sim_write_t) {
            .link = (int)handle, .node = c->index, .type = view.type, .prio = prio
        };
        memcpy(log->sender, view.sender, AH_PEER_ID_LEN);
    }
    const bool from_a = l->a_node == c->index;
    __typeof__(w->inflight[0]) *f = &w->inflight[w->inflight_count++];
    f->link = (int)handle;
    f->to_b = from_a;
    f->at_ms = w->now_ms + l->latency_ms;
    memcpy(f->bytes, frame, len);
    f->len = len;
    return AH_WRITE_OK;
}

static void *node_alloc(void *ctx, size_t bytes)
{
    node_ctx_t *c = ctx;
    void *p = calloc(1, bytes);
    if (p != NULL && c->w->allocation_count[c->index] < 32) {
        c->w->allocations[c->index][c->w->allocation_count[c->index]++] = p;
    }
    return p;
}

static void free_node(sim_world_t *w, int index)
{
    for (int i = 0; i < w->allocation_count[index]; ++i) {
        free(w->allocations[index][i]);
    }
    w->allocation_count[index] = 0;
    w->nodes[index] = NULL;
}

void sim_free(sim_world_t *w)
{
    for (int i = 0; i < w->node_count; ++i) {
        free_node(w, i);
    }
}

static void node_mail_put(void *ctx, uint32_t record, uint64_t depositor, const uint8_t *env, size_t len)
{
    node_ctx_t *c = ctx;
    // A record written again replaces itself, as an NVS key does.
    size_t at = 16;
    for (size_t i = 0; i < 16; ++i) {
        const __typeof__(c->w->mail[0][0]) *m = &c->w->mail[c->index][i];
        if (m->live && m->record == record) {
            at = i;
            break;
        }
        if (!m->live && at == 16) {
            at = i;
        }
    }
    if (at == 16) {
        return;
    }
    __typeof__(c->w->mail[0][0]) *m = &c->w->mail[c->index][at];
    m->live = true;
    m->record = record;
    m->depositor = depositor;
    memcpy(m->bytes, env, len);
    m->len = len;
}

static void node_mail_delete(void *ctx, uint32_t record)
{
    node_ctx_t *c = ctx;
    for (size_t i = 0; i < 16; ++i) {
        if (c->w->mail[c->index][i].live && c->w->mail[c->index][i].record == record) {
            c->w->mail[c->index][i].live = false;
        }
    }
}

static void node_clock_save(void *ctx, uint64_t wall_ms)
{
    node_ctx_t *c = ctx;
    c->w->saved_clock[c->index] = wall_ms;
}

static void create_node(sim_world_t *w, int index)
{
    const ah_node_ops_t ops = {
        .ctx = &s_ctx[index],
        .write = node_write,
        .mail_put = node_mail_put,
        .mail_delete = node_mail_delete,
        .clock_save = node_clock_save,
        .alloc = node_alloc,
    };
    w->nodes[index] = ah_node_create(&w->node_cfg[index], &w->node_ids[index], &ops, w->saved_clock[index]);
    s_next_tick[index] = w->now_ms;
}

int sim_add_node(sim_world_t *w, const ah_node_config_t *cfg, const char *name)
{
    const int index = w->node_count++;
    s_ctx[index] = (node_ctx_t) {
        .w = w, .index = index
    };
    sim_make_identity(&w->node_ids[index], name);
    w->node_cfg[index] = *cfg;
    create_node(w, index);
    return index;
}

void sim_reboot(sim_world_t *w, int node)
{
    free_node(w, node);
    // Frames in flight to the old instance are lost with its power.
    for (size_t i = 0; i < w->inflight_count;) {
        const sim_link_t *l = &w->links[w->inflight[i].link];
        const int to = w->inflight[i].to_b ? l->b_node : l->a_node;
        if (to == node) {
            w->inflight[i] = w->inflight[--w->inflight_count];
        } else {
            ++i;
        }
    }
    create_node(w, node);
    for (size_t i = 0; i < 16; ++i) {
        const __typeof__(w->mail[0][0]) *m = &w->mail[node][i];
        if (m->live) {
            ah_node_restore_mail(w->nodes[node], m->record, m->depositor, m->bytes, m->len);
        }
    }
    for (int i = 0; i < w->link_count; ++i) {
        sim_link_t *l = &w->links[i];
        if (!l->up) {
            continue;
        }
        const ah_link_kind_t kind = l->lora ? AH_LINK_LORA : AH_LINK_BLE;
        if (l->a_node == node) {
            l->a_link = ah_node_link_up(w->nodes[node], kind, (uint32_t)i, l->max_write,
                                        l->lora ? w->node_ids[l->b_node].peer_id : NULL, w->now_ms);
        }
        if (l->b_node == node) {
            l->b_link = ah_node_link_up(w->nodes[node], kind, (uint32_t)i, l->max_write,
                                        l->lora ? w->node_ids[l->a_node].peer_id : NULL, w->now_ms);
        }
    }
}

int sim_add_peer(sim_world_t *w, const char *name)
{
    const int index = w->peer_count++;
    sim_make_identity(&w->peers[index].id, name);
    return index;
}

int sim_connect_peer(sim_world_t *w, int node, int peer, uint16_t max_write)
{
    const int index = w->link_count++;
    sim_link_t *l = &w->links[index];
    *l = (sim_link_t) {
        .up = true, .a_node = node, .a_peer = -1, .b_node = -1, .b_peer = peer, .max_write = max_write,
        .latency_ms = 5, .write_budget = -1
    };
    l->a_link = ah_node_link_up(w->nodes[node], AH_LINK_BLE, (uint32_t)index, max_write, NULL, w->now_ms);
    return index;
}

int sim_connect_nodes(sim_world_t *w, int a, int b, bool lora, uint16_t max_write)
{
    const int index = w->link_count++;
    sim_link_t *l = &w->links[index];
    *l = (sim_link_t) {
        .up = true, .lora = lora, .a_node = a, .a_peer = -1, .b_node = b, .b_peer = -1,
        .max_write = max_write, .latency_ms = lora ? 400 : 5, .write_budget = -1
    };
    const ah_link_kind_t kind = lora ? AH_LINK_LORA : AH_LINK_BLE;
    // A trunk neighbor is known by its node ID before it ever announces.
    l->a_link = ah_node_link_up(w->nodes[a], kind, (uint32_t)index, max_write, lora ? w->node_ids[b].peer_id : NULL,
                                w->now_ms);
    l->b_link = ah_node_link_up(w->nodes[b], kind, (uint32_t)index, max_write, lora ? w->node_ids[a].peer_id : NULL,
                                w->now_ms);
    return index;
}

void sim_disconnect(sim_world_t *w, int link)
{
    sim_link_t *l = &w->links[link];
    if (!l->up) {
        return;
    }
    l->up = false;
    if (l->a_node >= 0) {
        ah_node_link_down(w->nodes[l->a_node], l->a_link);
    }
    if (l->b_node >= 0) {
        ah_node_link_down(w->nodes[l->b_node], l->b_link);
    }
}

void sim_throttle(sim_world_t *w, int link, int32_t writes)
{
    w->links[link].write_budget = writes;
}

void sim_release(sim_world_t *w, int link)
{
    sim_link_t *l = &w->links[link];
    l->write_budget = -1;
    if (!l->up) {
        return;
    }
    if (l->a_node >= 0) {
        ah_node_link_ready(w->nodes[l->a_node], l->a_link, w->now_ms);
    }
    if (l->b_node >= 0) {
        ah_node_link_ready(w->nodes[l->b_node], l->b_link, w->now_ms);
    }
}

void sim_peer_send(sim_world_t *w, int peer, int link, const uint8_t *frame, size_t len)
{
    (void)peer;
    sim_link_t *l = &w->links[link];
    if (!l->up || w->inflight_count == SIM_MAX_INFLIGHT) {
        return;
    }
    __typeof__(w->inflight[0]) *f = &w->inflight[w->inflight_count++];
    f->link = link;
    f->to_b = false;
    f->at_ms = w->now_ms + l->latency_ms;
    memcpy(f->bytes, frame, len);
    f->len = len;
}

static void deliver(sim_world_t *w, size_t i)
{
    __typeof__(w->inflight[0]) f = w->inflight[i];
    w->inflight[i] = w->inflight[--w->inflight_count];
    sim_link_t *l = &w->links[f.link];
    if (!l->up) {
        return;
    }
    const int node = f.to_b ? l->b_node : l->a_node;
    const int peer = f.to_b ? l->b_peer : l->a_peer;
    if (node >= 0) {
        ah_node_on_frame(w->nodes[node], f.to_b ? l->b_link : l->a_link, f.bytes, f.len, w->now_ms);
        s_next_tick[node] = w->now_ms;
    } else if (peer >= 0) {
        sim_peer_t *p = &w->peers[peer];
        if (p->received < SIM_INBOX) {
            memcpy(p->inbox[p->received].bytes, f.bytes, f.len);
            p->inbox[p->received].len = f.len;
            p->received++;
        }
    }
}

void sim_run(sim_world_t *w, int64_t ms)
{
    const int64_t end = w->now_ms + ms;
    for (;;) {
        int64_t next = end;
        for (size_t i = 0; i < w->inflight_count; ++i) {
            if (w->inflight[i].at_ms < next) {
                next = w->inflight[i].at_ms;
            }
        }
        for (int i = 0; i < w->node_count; ++i) {
            if (s_next_tick[i] < next) {
                next = s_next_tick[i];
            }
        }
        if (next > end) {
            next = end;
        }
        if (next > w->now_ms) {
            w->now_ms = next;
        }
        bool delivered = true;
        while (delivered) {
            delivered = false;
            for (size_t i = 0; i < w->inflight_count; ++i) {
                if (w->inflight[i].at_ms <= w->now_ms) {
                    deliver(w, i);
                    delivered = true;
                    break;
                }
            }
        }
        for (int i = 0; i < w->node_count; ++i) {
            if (s_next_tick[i] <= w->now_ms) {
                s_next_tick[i] = ah_node_tick(w->nodes[i], w->now_ms);
                if (s_next_tick[i] <= w->now_ms) {
                    s_next_tick[i] = w->now_ms + 1;
                }
            }
        }
        if (w->now_ms >= end) {
            return;
        }
    }
}

size_t sim_frame(const sim_peer_t *p, uint8_t type, uint8_t ttl, uint64_t ts_ms, const uint8_t *recipient,
                 const uint8_t *payload, size_t payload_len, bool sign, uint8_t *out, size_t cap)
{
    const ah_frame_fields_t fields = {
        .type = type,
        .ttl = ttl,
        .timestamp_ms = ts_ms,
        .sender = p->id.peer_id,
        .recipient = recipient,
        .payload = payload,
        .payload_len = payload_len,
    };
    const size_t len = ah_frame_encode(&fields, sign, out, cap);
    if (len == 0 || !sign) {
        return len;
    }
    ah_frame_t view;
    // The longest frame a test signs is a deposit of the largest envelope, padded.
    uint8_t pre[AH_COURIER_MAX_CIPHERTEXT + 1024u];
    size_t pre_len = 0;
    if (!ah_frame_parse(out, len, &view) || !ah_frame_signing_preimage(&view, pre, sizeof(pre), &pre_len)) {
        return 0;
    }
    uint8_t sig[AH_SIGNATURE_LEN];
    ah_ed25519_sign(p->id.signing_secret, pre, pre_len, sig);
    ah_frame_attach_signature(out, len, sig);
    return len;
}

// A v1 frame, the form bitchat-ios emits for its core broadcasts.
static size_t v1_frame(const sim_peer_t *p, uint8_t type, uint8_t ttl, uint64_t ts_ms, const uint8_t *payload,
                       size_t payload_len, uint8_t *out, size_t cap)
{
    const size_t len = AH_V1_HEADER_LEN + AH_PEER_ID_LEN + payload_len + AH_SIGNATURE_LEN;
    if (len > cap || payload_len > UINT16_MAX) {
        return 0;
    }
    size_t off = 0;
    out[off++] = AH_VERSION_1;
    out[off++] = type;
    out[off++] = ttl;
    ah_put_be64(out + off, ts_ms);
    off += 8;
    out[off++] = AH_FLAG_HAS_SIGNATURE;
    ah_put_be16(out + off, (uint16_t)payload_len);
    off += 2;
    memcpy(out + off, p->id.peer_id, AH_PEER_ID_LEN);
    off += AH_PEER_ID_LEN;
    memcpy(out + off, payload, payload_len);
    off += payload_len;
    memset(out + off, 0, AH_SIGNATURE_LEN);
    ah_frame_t view;
    uint8_t pre[AH_FRAME_BUF_MAX + AH_PAD_MAX];
    size_t pre_len = 0;
    if (!ah_frame_parse(out, len, &view) || !ah_frame_signing_preimage(&view, pre, sizeof(pre), &pre_len)) {
        return 0;
    }
    ah_ed25519_sign(p->id.signing_secret, pre, pre_len, out + off);
    return len;
}

size_t sim_announce(const sim_peer_t *p, uint64_t ts_ms, uint8_t *out, size_t cap)
{
    uint8_t payload[128];
    size_t off = 0;
    payload[off++] = AH_ANNOUNCE_TLV_NICKNAME;
    payload[off++] = p->id.nickname_len;
    memcpy(payload + off, p->id.nickname, p->id.nickname_len);
    off += p->id.nickname_len;
    payload[off++] = AH_ANNOUNCE_TLV_NOISE_KEY;
    payload[off++] = AH_KEY_LEN;
    memcpy(payload + off, p->id.noise_public, AH_KEY_LEN);
    off += AH_KEY_LEN;
    payload[off++] = AH_ANNOUNCE_TLV_SIGNING_KEY;
    payload[off++] = AH_KEY_LEN;
    memcpy(payload + off, p->id.signing_public, AH_KEY_LEN);
    off += AH_KEY_LEN;
    return v1_frame(p, AH_TYPE_ANNOUNCE, AH_TTL_DEFAULT, ts_ms, payload, off, out, cap);
}

size_t sim_message(const sim_peer_t *p, uint8_t type, const char *text, uint8_t ttl, uint64_t ts_ms, uint8_t *out,
                   size_t cap)
{
    return v1_frame(p, type, ttl, ts_ms, (const uint8_t *)text, strlen(text), out, cap);
}

size_t sim_count(const sim_peer_t *p, uint8_t type, bool rsr_only)
{
    size_t n = 0;
    for (size_t i = 0; i < p->received; ++i) {
        ah_frame_t f;
        if (ah_frame_parse(p->inbox[i].bytes, p->inbox[i].len, &f) && f.type == type &&
                (!rsr_only || (f.flags & AH_FLAG_IS_RSR))) {
            n++;
        }
    }
    return n;
}

int sim_find(const sim_peer_t *p, uint8_t type, const uint8_t *sender)
{
    for (size_t i = 0; i < p->received; ++i) {
        ah_frame_t f;
        if (ah_frame_parse(p->inbox[i].bytes, p->inbox[i].len, &f) && f.type == type &&
                (sender == NULL || memcmp(f.sender, sender, AH_PEER_ID_LEN) == 0)) {
            return (int)i;
        }
    }
    return -1;
}

size_t sim_count_from(const sim_peer_t *p, uint8_t type, const uint8_t *sender)
{
    size_t n = 0;
    for (size_t i = 0; i < p->received; ++i) {
        ah_frame_t f;
        if (ah_frame_parse(p->inbox[i].bytes, p->inbox[i].len, &f) && f.type == type &&
                memcmp(f.sender, sender, AH_PEER_ID_LEN) == 0) {
            n++;
        }
    }
    return n;
}
