// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Noise sessions with peers that talk to the node directly: answering a
// handshake addressed to it, proving its Noise key on a link before a courier
// handover or spray, and a short auto-reply to a DM, since a bitchat user can
// message a relay (Airhop hides the button for a 0xB1 peer).
//
// One session per peer ID, whatever link carries it, in memory only. A failed
// decrypt never costs a session; a replay is refused by the window.
#include <string.h>

#include "ah_announce.h"
#include "ah_crypto.h"
#include "ah_dm_wire.h"
#include "ah_node_priv.h"

#define HANDSHAKE_TIMEOUT_MS 30000
#define SESSION_IDLE_MS (60LL * 60 * 1000)
// Airhop's handshake budgets (HandshakeRateLimiter), each checked before
// either is spent: 10 messages a minute per claimed peer, and 30 a minute
// across everyone for the unauthenticated ones that create state, an inbound
// msg1 or a session opened because sealed traffic arrived without one.
#define HANDSHAKES_PER_PEER 10u
#define HANDSHAKES_PER_MINUTE 30u
#define HANDSHAKE_WINDOW_MS 60000
#define AUTO_REPLY_EVERY_MS (10LL * 60 * 1000)
#define PLAIN_MAX 600u

static const char s_auto_reply[] = "This is an Airhop relay node, not a person. It carries messages for the people "
                                   "around it without reading them, and nobody here will see what you send.";
_Static_assert(sizeof(s_auto_reply) - 1u <= 255u, "a private message field is at most 255 bytes");

static ah_session_t *find(ah_node_t *n, const uint8_t peer_id[AH_PEER_ID_LEN])
{
    for (uint8_t i = 0; i < n->cfg.sessions; ++i) {
        if (n->sessions[i].in_use && memcmp(n->sessions[i].peer_id, peer_id, AH_PEER_ID_LEN) == 0) {
            return &n->sessions[i];
        }
    }
    return NULL;
}

static void wipe(ah_session_t *s)
{
    ah_wipe(s, sizeof(*s));
}

// The peer's session, or the least recently used one wiped for it. Called
// only once the budgets allow, so a refused attempt evicts nobody.
static ah_session_t *take(ah_node_t *n, const uint8_t peer_id[AH_PEER_ID_LEN], int64_t now_ms)
{
    ah_session_t *s = find(n, peer_id);
    if (s != NULL) {
        return s;
    }
    ah_session_t *victim = &n->sessions[0];
    for (uint8_t i = 0; i < n->cfg.sessions; ++i) {
        if (!n->sessions[i].in_use) {
            victim = &n->sessions[i];
            break;
        }
        if (n->sessions[i].used_ms < victim->used_ms) {
            victim = &n->sessions[i];
        }
    }
    wipe(victim);
    victim->in_use = true;
    memcpy(victim->peer_id, peer_id, AH_PEER_ID_LEN);
    victim->used_ms = now_ms;
    victim->link = AH_LINK_NONE;
    return victim;
}

// The per-peer budget of a claimed peer ID. A full table gives up the entry
// whose window started longest ago; the global budget keeps inbound
// initiations below the table's size each window, so that is never a peer
// still being limited by a flood of them.
static ah_budget_t *peer_budget(ah_node_t *n, const uint8_t peer_id[AH_PEER_ID_LEN], int64_t now_ms)
{
    const uint64_t key = ah_peer_slot_key(peer_id);
    ah_handshake_peer_t *victim = &n->handshake_peers[0];
    for (size_t i = 0; i < AH_HANDSHAKE_PEERS; ++i) {
        ah_handshake_peer_t *e = &n->handshake_peers[i];
        if (e->key == key) {
            return &e->budget;
        }
        if (e->key == 0 || (victim->key != 0 && e->budget.window_start_ms < victim->budget.window_start_ms)) {
            victim = e;
        }
    }
    victim->key = key;
    victim->budget = (ah_budget_t) {
        .window_start_ms = now_ms
    };
    return &victim->budget;
}

static bool budget_allows(const ah_budget_t *b, uint32_t limit, int64_t now_ms)
{
    return now_ms - b->window_start_ms >= HANDSHAKE_WINDOW_MS || now_ms < b->window_start_ms || b->used < limit;
}

static void budget_spend(ah_budget_t *b, uint32_t limit, int64_t now_ms)
{
    ah_node_budget_take(b, now_ms, 1, limit, HANDSHAKE_WINDOW_MS);
}

// Whether a handshake message may be processed or sent now; both budgets are
// checked before either is spent, so a refusal by one never costs the other.
static bool handshake_allowed(ah_node_t *n, const uint8_t peer_id[AH_PEER_ID_LEN], bool creates_state, int64_t now_ms)
{
    ah_budget_t *peer = peer_budget(n, peer_id, now_ms);
    if (!budget_allows(peer, HANDSHAKES_PER_PEER, now_ms) ||
            (creates_state && !budget_allows(&n->handshake_budget, HANDSHAKES_PER_MINUTE, now_ms))) {
        return false;
    }
    budget_spend(peer, HANDSHAKES_PER_PEER, now_ms);
    if (creates_state) {
        budget_spend(&n->handshake_budget, HANDSHAKES_PER_MINUTE, now_ms);
    }
    return true;
}

static bool synced_wall(const ah_node_t *n, int64_t now_ms, uint64_t *wall)
{
    return ah_clock_synced(&n->clock) && ah_clock_now(&n->clock, now_ms, wall);
}

static void send_handshake(ah_node_t *n, const ah_session_t *s, const uint8_t *msg, size_t len, uint64_t wall,
                           int64_t now_ms)
{
    const ah_frame_fields_t fields = {
        .type = AH_TYPE_NOISE_HANDSHAKE,
        .ttl = AH_TTL_DEFAULT,
        .timestamp_ms = wall,
        .sender = n->id.peer_id,
        .recipient = s->peer_id,
        .payload = msg,
        .payload_len = len,
    };
    // Unsigned, as bitchat sends handshakes: the handshake authenticates itself.
    ah_node_originate(n, &fields, false, AH_LINK_NONE, now_ms, 0);
}

static void begin(ah_node_t *n, ah_session_t *s, bool initiator, bool direct, int64_t now_ms)
{
    uint8_t seed[32];
    ah_random(seed, sizeof(seed));
    ah_noise_handshake_init(&s->hs, initiator, n->id.noise_secret, n->id.noise_public, seed);
    ah_wipe(seed, sizeof(seed));
    s->hs_active = true;
    s->hs_started_ms = now_ms;
    s->hs_direct = direct;
}

static void complete(ah_node_t *n, ah_session_t *s, uint16_t link, bool direct, int64_t now_ms)
{
    uint8_t remote[32];
    ah_noise_sender_t tx;
    ah_noise_receiver_t rx;
    const bool ok = ah_noise_split(&s->hs, &tx, &rx, remote);
    s->hs_active = false;
    // A session counts only when its static key is the one the peer ID derives from.
    if (!ok || !ah_announce_binds(s->peer_id, remote)) {
        ah_wipe(&tx, sizeof(tx));
        ah_wipe(&rx, sizeof(rx));
        return;
    }
    s->tx = tx;
    s->rx = rx;
    s->established = true;
    s->link = link;
    s->direct = s->hs_direct && direct;
    s->used_ms = now_ms;
    ah_wipe(&tx, sizeof(tx));
    ah_wipe(&rx, sizeof(rx));
    ah_wipe(remote, sizeof(remote));
    // A session proven on a direct link is what lets mail be handed over or sprayed.
    const uint16_t peer = ah_peers_find(&n->peers, s->peer_id);
    if (s->direct && peer != AH_PEER_NONE) {
        ah_node_mail_on_announce(n, peer, true, now_ms);
    }
}

uint16_t ah_dm_proven_link(const ah_node_t *n, const uint8_t peer_id[AH_PEER_ID_LEN], uint16_t peer)
{
    // The link the session was proven on, while it is still bound to the
    // peer, direct link or not: a phone on two connections may answer on either.
    for (uint8_t i = 0; i < n->cfg.sessions; ++i) {
        const ah_session_t *s = &n->sessions[i];
        if (s->in_use && s->established && s->direct && s->link < n->links.capacity &&
                n->links.links[s->link].in_use && n->links.links[s->link].peer == peer &&
                memcmp(s->peer_id, peer_id, AH_PEER_ID_LEN) == 0) {
            return s->link;
        }
    }
    return AH_LINK_NONE;
}

void ah_dm_on_handshake(ah_node_t *n, uint16_t link, const ah_frame_t *f, const uint8_t *payload, size_t len,
                        int64_t now_ms)
{
    uint64_t wall;
    if (!synced_wall(n, now_ms, &wall)) {
        return;
    }
    const ah_link_t *l = &n->links.links[link];
    const bool direct = f->ttl == AH_TTL_DEFAULT && l->peer != AH_PEER_NONE &&
                        memcmp(n->peers.slots[l->peer].peer_id, f->sender, AH_PEER_ID_LEN) == 0;
    uint8_t msg[AH_NOISE_MSG2_LEN];
    if (len == AH_NOISE_MSG1_LEN) {
        // Crossed initiations: the lower peer ID keeps its own attempt (bitchat-ios).
        const ah_session_t *mine = find(n, f->sender);
        if (mine != NULL && mine->hs_active && mine->hs.initiator &&
                memcmp(n->id.peer_id, f->sender, AH_PEER_ID_LEN) < 0) {
            return;
        }
        // The unauthenticated message that creates state: budgets first, before any DH.
        if (!handshake_allowed(n, f->sender, true, now_ms)) {
            return;
        }
        ah_session_t *s = take(n, f->sender, now_ms);
        begin(n, s, false, direct, now_ms);
        const size_t out = ah_noise_read(&s->hs, payload, len) ? ah_noise_write(&s->hs, msg, sizeof(msg)) : 0;
        if (out == 0) {
            ah_noise_handshake_wipe(&s->hs);
            s->hs_active = false;
            return;
        }
        send_handshake(n, s, msg, out, wall, now_ms);
        return;
    }
    ah_session_t *s = find(n, f->sender);
    if (s == NULL || !s->hs_active || !handshake_allowed(n, f->sender, false, now_ms)) {
        return;
    }
    // Read on a copy, so one forged or garbled reply cannot end a genuine
    // handshake: the pending one is replaced only by a completed session.
    ah_noise_handshake_t attempt = s->hs;
    if (len == AH_NOISE_MSG2_LEN && attempt.initiator && ah_noise_read(&attempt, payload, len)) {
        const size_t out = ah_noise_write(&attempt, msg, sizeof(msg));
        if (out == AH_NOISE_MSG3_LEN) {
            s->hs = attempt;
            send_handshake(n, s, msg, out, wall, now_ms);
            complete(n, s, link, direct, now_ms);
        }
    } else if (len == AH_NOISE_MSG3_LEN && !attempt.initiator && ah_noise_read(&attempt, payload, len)) {
        s->hs = attempt;
        complete(n, s, link, direct, now_ms);
    }
    ah_noise_handshake_wipe(&attempt);
}

static void send_sealed(ah_node_t *n, ah_session_t *s, const uint8_t *plain, size_t len, uint64_t wall,
                        int64_t now_ms)
{
    uint8_t sealed[PLAIN_MAX + AH_NOISE_NONCE_PREFIX + AH_AEAD_TAG_LEN];
    const size_t out = ah_noise_seal(&s->tx, plain, len, sealed, sizeof(sealed));
    if (out == 0) {
        return;
    }
    const ah_frame_fields_t fields = {
        .type = AH_TYPE_NOISE_ENCRYPTED,
        .ttl = AH_TTL_DEFAULT,
        .timestamp_ms = wall,
        .sender = n->id.peer_id,
        .recipient = s->peer_id,
        .payload = sealed,
        .payload_len = out,
    };
    // Signed, as Airhop signs its own Noise transport; the session's AEAD is
    // what authenticates it either way.
    ah_node_originate(n, &fields, true, AH_LINK_NONE, now_ms, 0);
}

// An uppercase UUID string, the message ID form bitchat-ios uses.
static size_t uuid_string(char out[37])
{
    uint8_t b[16];
    ah_random(b, sizeof(b));
    b[6] = (uint8_t)((b[6] & 0x0Fu) | 0x40u);
    b[8] = (uint8_t)((b[8] & 0x3Fu) | 0x80u);
    static const char hex[] = "0123456789ABCDEF";
    size_t o = 0;
    for (size_t i = 0; i < 16u; ++i) {
        if (i == 4u || i == 6u || i == 8u || i == 10u) {
            out[o++] = '-';
        }
        out[o++] = hex[b[i] >> 4];
        out[o++] = hex[b[i] & 0x0Fu];
    }
    out[o] = '\0';
    return o;
}

// Open a session as the initiator. `creates_state` charges the global budget
// too, for a start nothing authenticated asked for.
static void start(ah_node_t *n, uint16_t peer, bool creates_state, int64_t now_ms)
{
    uint64_t wall;
    if (peer == AH_PEER_NONE || !synced_wall(n, now_ms, &wall)) {
        return;
    }
    const ah_peer_t *p = &n->peers.slots[peer];
    const ah_session_t *pending = find(n, p->peer_id);
    if ((pending != NULL && pending->hs_active && now_ms - pending->hs_started_ms < HANDSHAKE_TIMEOUT_MS) ||
            !handshake_allowed(n, p->peer_id, creates_state, now_ms)) {
        return;
    }
    ah_session_t *s = take(n, p->peer_id, now_ms);
    begin(n, s, true, p->direct_link != AH_LINK_NONE, now_ms);
    uint8_t msg[AH_NOISE_MSG1_LEN];
    const size_t out = ah_noise_write(&s->hs, msg, sizeof(msg));
    if (out == 0) {
        s->hs_active = false;
        ah_noise_handshake_wipe(&s->hs);
        return;
    }
    send_handshake(n, s, msg, out, wall, now_ms);
}

void ah_dm_on_encrypted(ah_node_t *n, const ah_frame_t *f, const uint8_t *payload, size_t len, int64_t now_ms)
{
    uint64_t wall;
    if (!synced_wall(n, now_ms, &wall)) {
        return;
    }
    ah_session_t *s = find(n, f->sender);
    if (s == NULL || !s->established) {
        // Sealed traffic from an announced peer with no session here (the
        // node rebooted): answer with a handshake. A peer that never announced
        // gets nothing, and the sender ID is unauthenticated, so the start
        // is charged like an inbound msg1.
        start(n, ah_peers_find(&n->peers, f->sender), true, now_ms);
        return;
    }
    uint8_t plain[PLAIN_MAX];
    const size_t plain_len = ah_noise_open(&s->rx, payload, len, plain, sizeof(plain));
    if (plain_len == SIZE_MAX || plain_len == 0) {
        return;
    }
    s->used_ms = now_ms;
    ah_private_message_t pm;
    if (plain[0] != AH_NOISE_PAYLOAD_PRIVATE_MESSAGE || !ah_private_message_decode(plain + 1, plain_len - 1u, &pm)) {
        ah_wipe(plain, sizeof(plain));
        return;
    }
    uint8_t id[255];
    const uint8_t id_len = pm.message_id_len;
    memcpy(id, pm.message_id, id_len);
    ah_wipe(plain, sizeof(plain));

    uint8_t out[PLAIN_MAX];
    size_t out_len = ah_delivered_encode(id, id_len, out, sizeof(out));
    if (out_len > 0) {
        send_sealed(n, s, out, out_len, wall, now_ms);
    }
    if (s->replied_ms != 0 && now_ms - s->replied_ms < AUTO_REPLY_EVERY_MS) {
        return;
    }
    s->replied_ms = now_ms;
    char reply_id[37];
    const size_t reply_id_len = uuid_string(reply_id);
    out_len = ah_private_message_encode((const uint8_t *)reply_id, reply_id_len, (const uint8_t *)s_auto_reply,
                                        sizeof(s_auto_reply) - 1u, out, sizeof(out));
    if (out_len > 0) {
        send_sealed(n, s, out, out_len, wall, now_ms);
    }
}

void ah_dm_start(ah_node_t *n, uint16_t peer, int64_t now_ms)
{
    start(n, peer, false, now_ms);
}

void ah_dm_link_gone(ah_node_t *n, uint16_t link)
{
    for (uint8_t i = 0; i < n->cfg.sessions; ++i) {
        ah_session_t *s = &n->sessions[i];
        if (s->in_use && s->link == link) {
            // The session still decrypts, but it proves nothing about whoever
            // holds this link next.
            s->link = AH_LINK_NONE;
            s->direct = false;
        }
    }
}

void ah_dm_forget(ah_node_t *n, const uint8_t peer_id[AH_PEER_ID_LEN])
{
    ah_session_t *s = find(n, peer_id);
    if (s != NULL) {
        wipe(s);
    }
}

void ah_dm_expire(ah_node_t *n, int64_t now_ms)
{
    for (uint8_t i = 0; i < n->cfg.sessions; ++i) {
        ah_session_t *s = &n->sessions[i];
        if (!s->in_use) {
            continue;
        }
        if (s->hs_active && now_ms - s->hs_started_ms > HANDSHAKE_TIMEOUT_MS) {
            ah_noise_handshake_wipe(&s->hs);
            s->hs_active = false;
        }
        if (!s->hs_active && now_ms - s->used_ms > SESSION_IDLE_MS) {
            wipe(s);
        }
    }
}
