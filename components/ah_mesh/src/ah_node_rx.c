// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Ingress: every frame a link delivers, in the order Airhop's router takes one:
//
//   1. Parse; anything malformed is dropped and counted, never a crash.
//   2. REQUEST_SYNC, OTA and sync replies take their own link-local paths.
//   3. Packet ID, a compressed payload charged what it inflated to; a
//      duplicate is dropped before any signature check, so a packet heard
//      from several neighbors costs one.
//   4. The pre-relay checks bitchat-ios applies to LEAVE, FILE_TRANSFER,
//      BOARD_POST and live voice, and Airhop to live video. A failure is
//      dropped before its ID is recorded, so a forgery arriving first cannot
//      shadow the genuine packet.
//   5. Record the ID, schedule the relay, then handle it locally if it is
//      inside the freshness window.
//
// Forwarding needs no roster entry and no signature for everything else; what
// the node verifies is what it stores or acts on. A check put off for lack of
// budget is neither a pass nor a failure: before the relay decision, for a
// sync reply, or for a deposit, nothing is recorded against the packet, so its
// next copy is checked again. Signature checks and inflation are charged to
// the link the frame came over, which is held its share of each second's
// budget, so a flood on one link never spends another's.
#include <string.h>

#include "ah_announce.h"
#include "ah_board_post.h"
#include "ah_crypto.h"
#include "ah_dm_wire.h"
#include "ah_node_priv.h"

#define LIVE_VERIFIED_MS 60000

ah_verify_t ah_node_verify(ah_node_t *n, const ah_frame_t *f, const uint8_t key[AH_KEY_LEN], bool before_relay,
                           int64_t now_ms)
{
    if (f->signature == NULL || key == NULL) {
        return AH_VERIFY_FAILED;
    }
    // A preimage is the frame plus its padding, so a deposit too large for the
    // scratch buffer borrows the big-send preimage. A cut under way reads only
    // the big-send bytes: the preimage is in use within one call alone.
    uint8_t *buf = n->scratch;
    size_t cap = sizeof(n->scratch);
    if (f->len + AH_PAD_MAX > cap) {
        buf = n->big.preimage;
        cap = (size_t)n->cfg.big_send_bytes + AH_PAD_MAX;
    }
    if (!ah_node_verify_budget(n, before_relay, now_ms)) {
        return AH_VERIFY_DEFERRED;
    }
    size_t len = 0;
    if (!ah_frame_signing_preimage(f, buf, cap, &len)) {
        return AH_VERIFY_FAILED;
    }
    return ah_ed25519_verify(key, buf, len, f->signature) ? AH_VERIFIED : AH_VERIFY_FAILED;
}

// A quiet link is still held this much inflation a second: any control payload.
#define INFLATE_FLOOR AH_CAP_CONTROL

// A decoded payload's copy, counting what the stream produced.
typedef struct {
    uint8_t *out;
    size_t cap;
    size_t len;
} metered_t;

static bool metered_sink(void *ctx, const uint8_t *data, size_t len)
{
    metered_t *m = ctx;
    if (len > m->cap - m->len) {
        return false;
    }
    memcpy(m->out + m->len, data, len);
    m->len += len;
    return true;
}

// A compressed payload is let in on the size it claims, then charged the
// bytes it inflated to: a stream that fails at once costs next to nothing,
// however much it claimed.
static bool inflate_allowed(ah_node_t *n, const ah_frame_t *f, int64_t now_ms)
{
    const uint32_t full = n->cfg.inflate_bytes_per_second;
    if (!ah_node_share_ask(n, AH_SHARE_INFLATE, n->rx_link, f->original_size, full, INFLATE_FLOOR, 0, now_ms)) {
        n->stats.inflate_skipped++;
        return false;
    }
    return true;
}

static bool inflate_metered(ah_node_t *n, const ah_frame_t *f, metered_t *m)
{
    const bool ok = ah_inflate(n->inflater, f->payload, f->payload_len, f->original_size, metered_sink, m);
    ah_node_share_spend(n, AH_SHARE_INFLATE, n->rx_link, (uint32_t)m->len);
    return ok;
}

// The packet ID of PROTOCOLS section 2.3, inflating once and charging the
// bytes inflated.
ah_verify_t ah_node_packet_id(ah_node_t *n, const ah_frame_t *f, uint8_t id[AH_PACKET_ID_LEN], int64_t now_ms)
{
    if (!f->compressed) {
        return ah_packet_id(f, NULL, id) ? AH_VERIFIED : AH_VERIFY_FAILED;
    }
    if (!inflate_allowed(n, f, now_ms)) {
        return AH_VERIFY_DEFERRED;
    }
    size_t inflated = 0;
    const bool ok = ah_packet_id_counted(f, n->inflater, id, &inflated);
    ah_node_share_spend(n, AH_SHARE_INFLATE, n->rx_link, (uint32_t)inflated);
    return ok ? AH_VERIFIED : AH_VERIFY_FAILED;
}

ah_verify_t ah_node_decode(ah_node_t *n, const ah_frame_t *f, uint8_t *out, size_t cap, size_t *len, int64_t now_ms)
{
    // Refused before any inflation when it claims more than fits.
    if (!f->compressed || f->original_size > cap) {
        return ah_payload_decode(f, NULL, out, cap, len) ? AH_VERIFIED : AH_VERIFY_FAILED;
    }
    if (!inflate_allowed(n, f, now_ms)) {
        return AH_VERIFY_DEFERRED;
    }
    metered_t m = {.out = out, .cap = cap};
    const bool inflated = inflate_metered(n, f, &m);
    *len = m.len;
    return inflated ? AH_VERIFIED : AH_VERIFY_FAILED;
}

// Live voice and video are signed per packet, but once a stream's first packet
// verifies over a link, the rest of it over that link is relayed on its shape
// alone: 40 Ed25519 checks a second would not fit the budget, and the phones
// still verify every packet. The link is part of the key because the sender
// and stream ID travel in clear.
static bool live_verified(const ah_node_t *n, const uint8_t sender[AH_PEER_ID_LEN], const uint8_t *stream,
                          int64_t now_ms)
{
    const uint64_t key = ah_peer_key(sender);
    for (size_t i = 0; i < AH_LIVE_VERIFIED_SLOTS; ++i) {
        const ah_live_verified_t *v = &n->live[i];
        if (v->sender == key && v->link == n->rx_link && memcmp(v->stream, stream, AH_LIVE_STREAM_ID_LEN) == 0 &&
                now_ms - v->at_ms < LIVE_VERIFIED_MS) {
            return true;
        }
    }
    return false;
}

static void note_live_verified(ah_node_t *n, const uint8_t sender[AH_PEER_ID_LEN], const uint8_t *stream,
                               int64_t now_ms)
{
    size_t victim = 0;
    for (size_t i = 0; i < AH_LIVE_VERIFIED_SLOTS; ++i) {
        if (n->live[i].at_ms < n->live[victim].at_ms) {
            victim = i;
        }
    }
    n->live[victim].sender = ah_peer_key(sender);
    n->live[victim].link = n->rx_link;
    memcpy(n->live[victim].stream, stream, AH_LIVE_STREAM_ID_LEN);
    n->live[victim].at_ms = now_ms;
}

// Decode a payload no larger than a control frame into the scratch buffer.
static bool small_payload(ah_node_t *n, const ah_frame_t *f, size_t *len)
{
    return ah_payload_decode(f, n->inflater, n->scratch, AH_CAP_CONTROL, len);
}

// The checks a relay applies before the relay decision (PROTOCOLS section
// 3.6), also applied to a packet the node takes some other way (a sync reply,
// a reassembled whole), where `before_relay` is false. Relaying never depends
// on the clock: the age bounds apply only once the clock is synced.
static ah_verify_t pre_relay_check(ah_node_t *n, const ah_frame_t *f, bool before_relay, bool synced, uint64_t wall,
                                   int64_t now_ms, bool *urgent)
{
    *urgent = false;
    switch (f->type) {
    case AH_TYPE_LEAVE:
    case AH_TYPE_FILE_TRANSFER:
        return ah_node_verify(n, f, ah_peers_signing_key(&n->peers, f->sender), before_relay, now_ms);
    case AH_TYPE_VOICE_FRAME:
    case AH_TYPE_VIDEO_FRAME: {
        if (!ah_frame_is_broadcast(f) || memcmp(f->sender, n->id.peer_id, AH_PEER_ID_LEN) == 0) {
            return AH_VERIFY_FAILED;
        }
        if (synced && wall > f->timestamp_ms && wall - f->timestamp_ms > (uint64_t)AH_LIVE_MAX_AGE_MS) {
            return AH_VERIFY_FAILED;
        }
        size_t len = 0;
        if (!small_payload(n, f, &len)) {
            return AH_VERIFY_FAILED;
        }
        const bool shaped = f->type == AH_TYPE_VOICE_FRAME ? ah_voice_valid(len)
                            : ah_video_valid(n->scratch, len);
        if (!shaped) {
            return AH_VERIFY_FAILED;
        }
        uint8_t stream[AH_LIVE_STREAM_ID_LEN];
        memcpy(stream, n->scratch, sizeof(stream));
        if (live_verified(n, f->sender, stream, now_ms)) {
            return AH_VERIFIED;
        }
        const ah_verify_t v = ah_node_verify(n, f, ah_peers_signing_key(&n->peers, f->sender), before_relay, now_ms);
        if (v == AH_VERIFIED) {
            note_live_verified(n, f->sender, stream, now_ms);
        }
        return v;
    }
    case AH_TYPE_BOARD_POST: {
        size_t len = 0;
        ah_board_post_t board;
        if (!small_payload(n, f, &len)) {
            return AH_VERIFY_FAILED;
        }
        if (!ah_node_verify_budget(n, before_relay, now_ms)) {
            return AH_VERIFY_DEFERRED;
        }
        if (!ah_board_post_check(n->scratch, len, &board) || (synced && !ah_board_post_is_live(&board, wall))) {
            return AH_VERIFY_FAILED;
        }
        *urgent = board.urgent;
        return AH_VERIFIED;
    }
    default:
        return AH_VERIFIED;
    }
}

// A link is bound once, to the first verified identity announced directly
// over it, and stays bound for the connection's life: a device that signs
// announces for many identities over one connection is one peer to the node.
// Only a new announce makes it the peer's direct link; a repeat of one proves
// nothing about who is at the far end, even with no direct link held.
static void bind_link(ah_node_t *n, uint16_t link, uint16_t peer, bool take_direct, int64_t now_ms)
{
    ah_link_t *l = &n->links.links[link];
    const bool first = l->peer != peer;
    l->peer = peer;
    if (take_direct) {
        n->peers.slots[peer].direct_link = link;
    }
    if (first && l->kind == AH_LINK_BLE) {
        // The phones' first round, one second after the link binds.
        n->extra[link].next_round_ms = now_ms + AH_SYNC_FIRST_ROUND_DELAY_MS;
        n->extra[link].round = 0;
    }
    if (first && l->kind == AH_LINK_LORA) {
        // The neighbor holds our key now (its announce came tagged for us),
        // but ours, sent as the link opened, most often arrived before our
        // beacon and was dropped: send it again rather than wait minutes.
        n->extra[link].announce_due_ms = now_ms;
    }
}

// A verified announce: learn its keys, bind the link it came over directly,
// take its time, keep it for sync, and let the mailbox act on it.
static void on_announce(ah_node_t *n, uint16_t link, const ah_frame_t *f, const uint8_t id[AH_PACKET_ID_LEN],
                        bool sync_reply, int64_t now_ms)
{
    if (memcmp(f->sender, n->id.peer_id, AH_PEER_ID_LEN) == 0) {
        return;
    }
    size_t len = 0;
    ah_announce_t a;
    if (!small_payload(n, f, &len) || !ah_announce_decode(n->scratch, len, &a) ||
            !ah_announce_binds(f->sender, a.noise_key)) {
        return;
    }
    // ah_node_verify reuses the scratch buffer the TLVs were decoded into, so
    // what points into it is copied out first.
    uint8_t signing_key[AH_KEY_LEN];
    memcpy(signing_key, a.signing_key, sizeof(signing_key));
    uint8_t noise_key[AH_KEY_LEN];
    memcpy(noise_key, a.noise_key, sizeof(noise_key));
    const ah_verify_t v = ah_node_verify(n, f, signing_key, false, now_ms);
    if (v != AH_VERIFIED) {
        if (v == AH_VERIFY_FAILED) {
            n->stats.rx_refused++;
        }
        if (sync_reply) {
            // Offered again next round, when there is budget for it; and a
            // forged copy, which shares the genuine announce's ID, never
            // leaves it seen.
            ah_dedup_forget(&n->dedup[AH_DEDUP_MESSAGE], id);
        }
        return;
    }
    uint16_t peer = AH_PEER_NONE;
    const uint16_t known = ah_peers_find(&n->peers, f->sender);
    const bool newer = known == AH_PEER_NONE || f->timestamp_ms > n->peers.slots[known].announce_ts_ms;
    const ah_peer_learn_t learned =
        ah_peers_learn(&n->peers, f->sender, noise_key, signing_key, f->timestamp_ms, now_ms, &peer);
    if (learned == AH_PEER_CONFLICT) {
        n->stats.rx_refused++;
        return;
    }
    ah_peer_t *p = &n->peers.slots[peer];
    const bool is_node = (a.relay_flags & AH_RELAY_FLAG_DEDICATED) != 0;
    if (f->timestamp_ms >= p->announce_ts_ms) {
        p->relay_flags = a.relay_flags;
        p->firmware = a.has_firmware ? a.firmware_version : 0;
    }
    if (learned == AH_PEER_LEARNED) {
        ah_sync_undecline(&n->sync, f->sender);
        // A slot taken over from an evicted peer: links still bound to that
        // peer are unbound.
        for (uint16_t i = 0; i < n->links.capacity; ++i) {
            if (n->links.links[i].in_use && n->links.links[i].peer == peer) {
                n->links.links[i].peer = AH_PEER_NONE;
                ah_dm_link_gone(n, i);
            }
        }
    }

    // TTL 7 on arrival means the sender is the far end of this link: a relay
    // always forwards one less. Only an announce newer than any held of its
    // peer binds, so a replay, even of the newest once the dedup window has
    // passed, claims no link and casts no vote: phones date every announce
    // afresh, and an exact repeat inside the window is bind_second_link's.
    // Only an unbound link (or one already the sender's) is claimed, and a
    // link the transport named a peer for binds to that peer alone. Only nodes
    // speak the trunk, so a LoRa link binds only to an announce that says it
    // is a node: one naming a phone never takes that phone's DMs or speaks for
    // it to the clock, whatever source the trunk was given.
    const ah_link_t *l = &n->links.links[link];
    const bool direct = !sync_reply && f->ttl == AH_TTL_DEFAULT && newer &&
                        (l->peer == AH_PEER_NONE || l->peer == peer) && ah_links_may_bind(l, f->sender) &&
                        (l->kind != AH_LINK_LORA || is_node);
    if (direct) {
        bind_link(n, link, peer, true, now_ms);
        ah_clock_sample(&n->clock, (uint32_t)link + 1u, ah_peer_key(f->sender), is_node, f->timestamp_ms, now_ms);
    }
    uint64_t wall;
    if (ah_clock_synced(&n->clock) && ah_clock_now(&n->clock, now_ms, &wall)) {
        ah_sync_track(&n->sync, f, id, wall);
        if (!sync_reply) {
            ah_node_mail_on_announce(n, peer, direct, now_ms);
        }
    }
}

// A public message is kept once it verifies against its author's announced key.
// A group message is sealed to its group, so nobody outside it can check one,
// bitchat-ios included; a board post's author signature was checked before
// the relay decision.
static ah_verify_t check_public(ah_node_t *n, const ah_frame_t *f, int64_t now_ms)
{
    if (f->type == AH_TYPE_GROUP_MESSAGE || f->type == AH_TYPE_BOARD_POST) {
        return AH_VERIFIED;
    }
    return ah_node_verify(n, f, ah_peers_signing_key(&n->peers, f->sender), false, now_ms);
}

// A sync reply that failed its check. From an author whose announce never
// reached us, it goes in the declined list, so our filters stop drawing it
// until that announce arrives (ah_sync_undecline). Against a key we hold, it
// is forged or corrupt: the packet ID does not cover the signature, so
// declining it would hide the genuine packet for as long as its type is kept.
// It is only forgotten, and the next round may bring the real one.
static void refuse_reply(ah_node_t *n, const ah_frame_t *f, const uint8_t id[AH_PACKET_ID_LEN])
{
    if (ah_peers_signing_key(&n->peers, f->sender) == NULL) {
        ah_sync_decline(&n->sync, f, id);
    } else {
        ah_dedup_forget(&n->dedup[AH_DEDUP_MESSAGE], id);
    }
}

static void on_public(ah_node_t *n, const ah_frame_t *f, const uint8_t id[AH_PACKET_ID_LEN], bool sync_reply,
                      int64_t now_ms)
{
    uint64_t wall;
    if (!ah_clock_synced(&n->clock) || !ah_clock_now(&n->clock, now_ms, &wall) || !ah_frame_is_broadcast(f)) {
        return;
    }
    const ah_verify_t v = check_public(n, f, now_ms);
    if (v == AH_VERIFIED) {
        n->stats.sync_stored += ah_sync_track(&n->sync, f, id, wall) ? 1u : 0u;
    } else if (sync_reply && v == AH_VERIFY_DEFERRED) {
        // A burst of history past the budget: offered again next round.
        ah_dedup_forget(&n->dedup[AH_DEDUP_MESSAGE], id);
    } else if (sync_reply) {
        refuse_reply(n, f, id);
    }
}

// A sync reply carrying a packet the node relayed but never kept: its own
// check was put off, or it came stale or before the clock synced. A reply is
// never relayed, so keeping it now sends nothing out again. Its ID stays
// recorded for the copy that was relayed, so a check put off here is taken
// up by the next round's reply.
static void keep_relayed_reply(ah_node_t *n, const ah_frame_t *f, const uint8_t id[AH_PACKET_ID_LEN], uint64_t wall,
                               int64_t now_ms)
{
    switch (f->type) {
    case AH_TYPE_CHANNEL_MSG:
    case AH_TYPE_CHANNEL_MSG_AIRHOP:
    case AH_TYPE_GROUP_MESSAGE:
    case AH_TYPE_BOARD_POST:
        break;
    default:
        return;
    }
    bool urgent = false;
    if (!ah_frame_is_broadcast(f) || ah_sync_holds(&n->sync, f->type, id) ||
            pre_relay_check(n, f, false, true, wall, now_ms, &urgent) != AH_VERIFIED) {
        return;
    }
    const ah_verify_t v = check_public(n, f, now_ms);
    if (v == AH_VERIFIED) {
        n->stats.sync_stored += ah_sync_track(&n->sync, f, id, wall) ? 1u : 0u;
    } else if (v == AH_VERIFY_FAILED && ah_peers_signing_key(&n->peers, f->sender) == NULL) {
        // From an author we hold no key for: declined until their announce
        // comes. Against a key we hold it is a forged copy, and the ID stays
        // recorded for the genuine one already relayed.
        ah_sync_decline(&n->sync, f, id);
    }
}

static void on_leave(ah_node_t *n, const ah_frame_t *f)
{
    const uint16_t peer = ah_peers_find(&n->peers, f->sender);
    if (peer == AH_PEER_NONE) {
        return;
    }
    for (uint16_t i = 0; i < n->links.capacity; ++i) {
        if (n->links.links[i].in_use && n->links.links[i].peer == peer) {
            n->links.links[i].peer = AH_PEER_NONE;
        }
    }
    ah_dm_forget(n, f->sender);
    ah_sync_purge_sender(&n->sync, f->sender);
    ah_peers_forget(&n->peers, peer);
}

static void on_ping(ah_node_t *n, uint16_t link, const ah_frame_t *f, int64_t now_ms)
{
    // bitchat-ios answers a few pings per window per ingress link, and only
    // one addressed to it exactly.
    ah_link_extra_t *x = &n->extra[link];
    size_t len = 0;
    uint64_t wall;
    if (!ah_frame_is_for(f, n->id.peer_id) || !small_payload(n, f, &len) || len < AH_PING_LEN ||
            !ah_clock_synced(&n->clock) || !ah_clock_now(&n->clock, now_ms, &wall)) {
        return;
    }
    if (now_ms - x->ping_answered[x->ping_next] < AH_PING_WINDOW_MS && x->ping_answered[x->ping_next] != 0) {
        return;
    }
    x->ping_answered[x->ping_next] = now_ms;
    x->ping_next = (uint8_t)((x->ping_next + 1u) % AH_PINGS_PER_WINDOW);
    uint8_t pong[AH_PING_LEN];
    memcpy(pong, n->scratch, AH_PING_NONCE_LEN);
    pong[AH_PING_NONCE_LEN] = AH_TTL_DEFAULT;
    const ah_frame_fields_t fields = {
        .type = AH_TYPE_PONG,
        .ttl = AH_TTL_DEFAULT,
        .timestamp_ms = wall,
        .sender = n->id.peer_id,
        .recipient = f->sender,
        .payload = pong,
        .payload_len = sizeof(pong),
    };
    // Unsigned, as bitchat leaves pings and pongs: the echoed nonce binds it.
    ah_node_originate(n, &fields, false, AH_LINK_NONE, now_ms, 0);
}

// Outside the freshness window by a synced clock: dated more than the skew
// before `since` or after `wall`. An announce is held to it only once the
// clock is confirmed: until then the time rests on one phone's word or on
// other nodes', and the announces of phones that disagree with it are what
// lets them bind and outvote it.
static bool stale_since(const ah_node_t *n, const ah_frame_t *f, bool synced, uint64_t wall, uint64_t since)
{
    if (!synced || (f->type == AH_TYPE_ANNOUNCE && !ah_clock_confirmed(&n->clock))) {
        return false;
    }
    const uint64_t skew = (uint64_t)(f->type == AH_TYPE_ANNOUNCE ? AH_ANNOUNCE_MAX_SKEW_MS : AH_MAX_SKEW_MS);
    return f->timestamp_ms + skew < since || f->timestamp_ms > wall + skew;
}

static bool stale(const ah_node_t *n, const ah_frame_t *f, bool synced, uint64_t wall)
{
    return stale_since(n, f, synced, wall, wall);
}

// A piece of a stream already being assembled is held to the future bound
// alone (PROTOCOLS section 5.1): pieces are stamped when cut, and a slow
// transfer outlasts the window; the rebuilt packet is then judged on its own.
static bool continues_stream(ah_node_t *n, const ah_frame_t *f, bool synced, uint64_t wall)
{
    size_t len = 0;
    ah_fragment_t frag;
    return f->type == AH_TYPE_FRAGMENT && synced && f->timestamp_ms <= wall + (uint64_t)AH_MAX_SKEW_MS &&
           ah_payload_decode(f, n->inflater, n->scratch, AH_CAP_FRAGMENT, &len) &&
           ah_fragment_parse(n->scratch, len, &frag) && ah_reassembly_holds(&n->reassembly, f->sender, frag.stream_id);
}

static void handle_local(ah_node_t *n, uint16_t link, const ah_frame_t *f, const uint8_t id[AH_PACKET_ID_LEN],
                         bool sync_reply, int64_t now_ms);

// Fragments the node rebuilds for its own use; everything else it only relays.
static bool wants(const ah_node_t *n, const ah_frame_t *f, uint8_t inner, bool sync_reply)
{
    const bool to_me = ah_frame_is_for(f, n->id.peer_id);
    switch (inner) {
    case AH_TYPE_COURIER_ENV:
    case AH_TYPE_NOISE_HANDSHAKE:
    case AH_TYPE_NOISE_ENCRYPTED:
        return to_me;
    case AH_TYPE_ANNOUNCE:
    case AH_TYPE_CHANNEL_MSG:
    case AH_TYPE_CHANNEL_MSG_AIRHOP:
    case AH_TYPE_GROUP_MESSAGE:
    case AH_TYPE_BOARD_POST:
        // A sync reply's pieces may be addressed to us, the requester.
        return ah_frame_is_broadcast(f) || (sync_reply && to_me);
    default:
        return false;
    }
}

static void on_fragment(ah_node_t *n, uint16_t link, const ah_frame_t *f, bool sync_reply, int64_t now_ms)
{
    size_t len = 0;
    ah_fragment_t frag;
    if (!ah_payload_decode(f, n->inflater, n->scratch, AH_CAP_FRAGMENT, &len) ||
            !ah_fragment_parse(n->scratch, len, &frag) || !wants(n, f, frag.inner_type, sync_reply)) {
        return;
    }
    ah_reassembled_t whole;
    if (ah_reassembly_add(&n->reassembly, f->sender, &frag, link, now_ms, &whole) != AH_REASM_DONE) {
        return;
    }
    ah_frame_t inner;
    if (!ah_frame_parse(whole.bytes, whole.len, &inner) || inner.type != whole.inner_type ||
            memcmp(inner.sender, f->sender, AH_PEER_ID_LEN) != 0) {
        n->stats.rx_malformed++;
        return;
    }
    // A reply is honored only when every piece came over the link we asked.
    if (sync_reply && !whole.one_link) {
        return;
    }
    uint8_t id[AH_PACKET_ID_LEN];
    if (ah_node_packet_id(n, &inner, id, now_ms) != AH_VERIFIED) {
        return;
    }
    ah_dedup_t *set = &n->dedup[ah_dedup_class_of(inner.type)];
    const uint32_t now_s = (uint32_t)(now_ms / 1000);
    uint64_t wall = 0;
    const bool synced = ah_clock_synced(&n->clock) && ah_clock_now(&n->clock, now_ms, &wall);
    if (ah_dedup_seen(set, id, now_s)) {
        if (sync_reply && synced) {
            keep_relayed_reply(n, &inner, id, wall, now_ms);
        }
        return;
    }
    // Judged as a whole packet would be, and never relayed: its pieces were.
    bool urgent = false;
    if (pre_relay_check(n, &inner, false, synced, wall, now_ms, &urgent) != AH_VERIFIED) {
        return;
    }
    ah_dedup_add(set, id, now_s);
    // Solicited only when its pieces came as a reply to our request: an old
    // packet wrapped in fresh fragments by anyone else, IS_RSR or not, is
    // held to its own time (PROTOCOLS section 5.1). That time is judged from
    // the first piece's arrival, so a slow transfer of a packet stamped as it
    // was cut still passes.
    const bool solicited = sync_reply;
    const uint64_t since = wall - (uint64_t)(now_ms - whole.first_ms);
    if (!solicited && stale_since(n, &inner, synced, wall, since)) {
        n->stats.rx_stale++;
        return;
    }
    handle_local(n, link, &inner, id, solicited, now_ms);
}

static void handle_local(ah_node_t *n, uint16_t link, const ah_frame_t *f, const uint8_t id[AH_PACKET_ID_LEN],
                         bool sync_reply, int64_t now_ms)
{
    switch (f->type) {
    case AH_TYPE_ANNOUNCE:
        on_announce(n, link, f, id, sync_reply, now_ms);
        break;
    case AH_TYPE_CHANNEL_MSG:
    case AH_TYPE_CHANNEL_MSG_AIRHOP:
    case AH_TYPE_GROUP_MESSAGE:
    case AH_TYPE_BOARD_POST:
        on_public(n, f, id, sync_reply, now_ms);
        break;
    case AH_TYPE_LEAVE:
        if (!sync_reply) {
            on_leave(n, f);
        }
        break;
    case AH_TYPE_FRAGMENT:
        on_fragment(n, link, f, sync_reply, now_ms);
        break;
    default:
        break;
    }
    if (sync_reply || !ah_frame_is_for(f, n->id.peer_id)) {
        return;
    }
    // Addressed to this node.
    size_t len = 0;
    switch (f->type) {
    case AH_TYPE_NOISE_HANDSHAKE:
        if (small_payload(n, f, &len)) {
            ah_dm_on_handshake(n, link, f, n->scratch, len, now_ms);
        }
        break;
    case AH_TYPE_NOISE_ENCRYPTED:
        if (small_payload(n, f, &len)) {
            ah_dm_on_encrypted(n, f, n->scratch, len, now_ms);
        }
        break;
    case AH_TYPE_COURIER_ENV: {
        // Sealed ciphertext does not compress, so a deposit is read in place;
        // one that did arrive compressed is decoded into the idle big-send buffer.
        bool put_off = false;
        if (!f->compressed) {
            put_off = ah_node_mail_on_deposit(n, link, f, f->payload, f->payload_len, now_ms);
        } else if (!n->big.active &&
                   ah_payload_decode(f, n->inflater, n->big.bytes, n->cfg.big_send_bytes, &len)) {
            put_off = ah_node_mail_on_deposit(n, link, f, n->big.bytes, len, now_ms);
        }
        if (put_off) {
            // Its check put off, nothing judged it, and a deposit is addressed
            // to the node, so never relayed: another copy is taken as new.
            ah_dedup_forget(&n->dedup[ah_dedup_class_of(f->type)], id);
        }
        break;
    }
    case AH_TYPE_PING:
        on_ping(n, link, f, now_ms);
        break;
    default:
        break;
    }
}

// A packet tagged IS_RSR: judged on the sync rules alone, fresh or not
// (PROTOCOLS section 5.1), and never relayed.
static void on_sync_reply(ah_node_t *n, uint16_t link, const ah_frame_t *f, int64_t now_ms)
{
    uint64_t wall;
    if (f->ttl != 0 || !ah_node_sync_reply_expected(n, link, now_ms) || !ah_clock_synced(&n->clock) ||
            !ah_clock_now(&n->clock, now_ms, &wall) || !ah_sync_reply_in_window(f->type, f->timestamp_ms, wall)) {
        return;
    }
    uint8_t id[AH_PACKET_ID_LEN];
    if (ah_node_packet_id(n, f, id, now_ms) != AH_VERIFIED) {
        return;
    }
    ah_dedup_t *set = &n->dedup[ah_dedup_class_of(f->type)];
    const uint32_t now_s = (uint32_t)(now_ms / 1000);
    if (ah_dedup_seen(set, id, now_s)) {
        keep_relayed_reply(n, f, id, wall, now_ms);
        return;
    }
    bool urgent = false;
    if (f->type != AH_TYPE_FRAGMENT && pre_relay_check(n, f, false, true, wall, now_ms, &urgent) != AH_VERIFIED) {
        return;
    }
    ah_dedup_add(set, id, now_s);
    handle_local(n, link, f, id, true, now_ms);
}

// A second link to a peer already bound elsewhere (dual-role BLE): its direct
// announce is a duplicate by ID, but still what binds this link.
static void bind_second_link(ah_node_t *n, uint16_t link, const ah_frame_t *f, int64_t now_ms)
{
    const uint16_t peer = ah_peers_find(&n->peers, f->sender);
    const ah_link_t *l = &n->links.links[link];
    if (peer == AH_PEER_NONE || l->peer != AH_PEER_NONE || !ah_links_may_bind(l, f->sender) ||
            (l->kind == AH_LINK_LORA && (n->peers.slots[peer].relay_flags & AH_RELAY_FLAG_DEDICATED) == 0)) {
        return;
    }
    // A second link joins the peer but never becomes its direct link, not even
    // once the first has dropped, so a replayed announce on someone else's
    // connection diverts nothing: the peer's next announce binds one.
    if (ah_node_verify(n, f, n->peers.slots[peer].signing_key, false, now_ms) == AH_VERIFIED) {
        bind_link(n, link, peer, false, now_ms);
    }
}

static void on_frame(ah_node_t *n, uint16_t link, const uint8_t *bytes, size_t len, int64_t now_ms);

void ah_node_on_frame(ah_node_t *n, uint16_t link, const uint8_t *bytes, size_t len, int64_t now_ms)
{
    if (link >= n->links.capacity || !n->links.links[link].in_use) {
        return;
    }
    // What the frame costs in signature checks and inflation is its link's.
    n->rx_link = link;
    on_frame(n, link, bytes, len, now_ms);
    n->rx_link = AH_LINK_NONE;
}

static void on_frame(ah_node_t *n, uint16_t link, const uint8_t *bytes, size_t len, int64_t now_ms)
{
    n->stats.rx++;
    ah_frame_t f;
    if (!ah_frame_parse(bytes, len, &f)) {
        n->stats.rx_malformed++;
        return;
    }
    if (f.type == AH_TYPE_REQUEST_SYNC) {
        ah_node_sync_on_request(n, link, &f, now_ms);
        return;
    }
    if (ah_is_ota(f.type)) {
        // Node-to-node over one link; the OTA task owns it (ah_node_ops_t has
        // no say), and the core never forwards it.
        return;
    }
    if (f.flags & AH_FLAG_IS_RSR) {
        on_sync_reply(n, link, &f, now_ms);
        return;
    }
    uint8_t id[AH_PACKET_ID_LEN];
    const ah_verify_t identified = ah_node_packet_id(n, &f, id, now_ms);
    if (identified != AH_VERIFIED) {
        n->stats.rx_malformed += identified == AH_VERIFY_FAILED ? 1u : 0u;
        return;
    }
    ah_dedup_t *set = &n->dedup[ah_dedup_class_of(f.type)];
    const uint32_t now_s = (uint32_t)(now_ms / 1000);
    if (ah_dedup_seen(set, id, now_s)) {
        n->stats.rx_duplicate++;
        if (f.type == AH_TYPE_ANNOUNCE && f.ttl == AH_TTL_DEFAULT) {
            bind_second_link(n, link, &f, now_ms);
        }
        return;
    }

    uint64_t wall = 0;
    const bool synced = ah_clock_synced(&n->clock) && ah_clock_now(&n->clock, now_ms, &wall);
    bool urgent = false;
    const ah_verify_t checked = pre_relay_check(n, &f, true, synced, wall, now_ms, &urgent);
    if (checked != AH_VERIFIED) {
        n->stats.rx_refused += checked == AH_VERIFY_FAILED ? 1u : 0u;
        return;
    }
    ah_dedup_add(set, id, now_s);

    const ah_relay_decision_t d = ah_relay_decide(&f, ah_node_degree(n), n->id.peer_id, urgent);
    if (d.relay) {
        const ah_prio_t prio = ah_priority_of(&f);
        const int64_t deadline = ah_is_live(f.type) ? now_ms + AH_LIVE_WRITE_DEADLINE_MS : 0;
        ah_node_schedule_relay(n, bytes, len, d.ttl, d.jitter_min_ms, d.jitter_max_ms, link,
                               n->links.links[link].peer, prio, deadline, now_ms);
    }
    // Outside the freshness window a packet is still relayed, but the node
    // never acts on it (PROTOCOLS section 5.1): a replay ages out of every use
    // but passing on.
    if (stale(n, &f, synced, wall) && !continues_stream(n, &f, synced, wall)) {
        n->stats.rx_stale++;
        return;
    }
    handle_local(n, link, &f, id, false, now_ms);
}
