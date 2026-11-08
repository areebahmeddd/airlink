// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Courier mail through the node (PROTOCOLS section 6.1, bitchat-ios BLEService
// courier paths): taking deposits, and on each verified announce handing a
// peer its own mail, spraying half the budget of other mail to it, or flooding
// mail toward a recipient heard only through relays. Every write to the
// mailbox's flash copy is charged to an hourly budget.
#include <string.h>

#include "ah_courier_wire.h"
#include "ah_node_priv.h"

// A handover whose writes do not all land (the link dropped, or a piece was
// pushed out of its queue) is given up after this, so the envelope is carried
// on, and tried again whole, rather than held forever.
#define HANDOVER_GIVE_UP_MS 60000
// The bytes a re-encoded envelope may gain over the one deposited: the copies
// TLV a spray budget adds (unknown TLVs are dropped, never added).
#define ENVELOPE_GROWTH 4u
// The flash budget's window (AH_MAIL_FLASH_KIB_PER_HOUR).
#define FLASH_WINDOW_MS (60LL * 60 * 1000)

void ah_node_mail_gone(void *ctx, uint32_t record)
{
    const ah_node_t *n = ctx;
    if (n->ops.mail_delete != NULL) {
        n->ops.mail_delete(n->ops.ctx, record);
    }
}

// Whether this hour's flash budget has room for a record of `len` envelope
// bytes. Every write to the mailbox's flash passes here, so however fast
// deposits come, the partition wears at no more than the budget (MEMORY.md).
static bool flash_room(ah_node_t *n, size_t len, int64_t now_ms)
{
    ah_budget_t *b = &n->mail_flash_budget;
    if (now_ms - b->window_start_ms >= FLASH_WINDOW_MS || now_ms < b->window_start_ms) {
        b->window_start_ms = now_ms;
        b->used = 0;
    }
    return (uint64_t)b->used + len + AH_MAIL_RECORD_OVERHEAD <= n->cfg.mail_flash_bytes_per_hour;
}

// Each depositor may write its quota's share of the hourly flash budget.
// Envelopes that expire or are delivered free its quota, so without a share
// one identity sending short-lived mail, or mail to itself, would spend the
// hour for everyone.
static ah_budget_t *writer_of(ah_node_t *n, uint64_t depositor, int64_t now_ms)
{
    ah_mail_writer_t *victim = &n->mail_writers[0];
    for (size_t i = 0; i < AH_MAIL_WRITERS; ++i) {
        ah_mail_writer_t *w = &n->mail_writers[i];
        if (w->depositor == depositor) {
            return &w->budget;
        }
        if (w->depositor == 0 || (victim->depositor != 0 && w->budget.window_start_ms < victim->budget.window_start_ms)) {
            victim = w;
        }
    }
    victim->depositor = depositor;
    victim->budget = (ah_budget_t) {
        .window_start_ms = now_ms
    };
    return &victim->budget;
}

static bool writer_room(const ah_node_t *n, ah_budget_t *b, size_t len, int64_t now_ms)
{
    if (now_ms - b->window_start_ms >= FLASH_WINDOW_MS || now_ms < b->window_start_ms) {
        b->window_start_ms = now_ms;
        b->used = 0;
    }
    const uint64_t share = (uint64_t)n->cfg.mail_flash_bytes_per_hour * n->cfg.mail_per_depositor / n->cfg.mail_slots;
    return (uint64_t)b->used + len + AH_MAIL_RECORD_OVERHEAD <= share;
}

// Write a record within the budget flash_room just allowed.
static void flash_put(ah_node_t *n, const ah_mail_t *m, const uint8_t *envelope, size_t len)
{
    n->mail_flash_budget.used += (uint32_t)len + AH_MAIL_RECORD_OVERHEAD;
    if (n->ops.mail_put != NULL) {
        n->ops.mail_put(n->ops.ctx, m->record, m->depositor, envelope, len);
    }
}

// Write a held envelope back with the budget it holds now, so a reboot
// neither brings back copies already sprayed nor loses a merged rise. Over
// the flash budget it stays as it was: the RAM copy is right until a reboot.
static bool persist_budget(ah_node_t *n, uint16_t slot, int64_t now_ms)
{
    const ah_mail_t *m = &n->courier.mail[slot];
    // Built in the big-send preimage buffer, idle between calls (send_envelope).
    uint8_t *out = n->big.preimage;
    const size_t len = ah_courier_encode(&n->courier, slot, m->copies, out, n->cfg.big_send_bytes);
    if (len == 0 || !flash_room(n, len, now_ms)) {
        return false;
    }
    flash_put(n, m, out, len);
    return true;
}

bool ah_node_mail_on_deposit(ah_node_t *n, uint16_t link, const ah_frame_t *f, const uint8_t *payload, size_t len,
                             int64_t now_ms)
{
    const ah_link_t *l = &n->links.links[link];
    uint64_t wall;
    // A deposit comes straight from its depositor, never through relays, and
    // is signed by them; the expiry is judged on a clock we trust.
    if (l->peer == AH_PEER_NONE || !ah_clock_synced(&n->clock) || !ah_clock_now(&n->clock, now_ms, &wall)) {
        return false;
    }
    const ah_peer_t *p = &n->peers.slots[l->peer];
    if (memcmp(p->peer_id, f->sender, AH_PEER_ID_LEN) != 0) {
        n->stats.rx_refused++;
        return false;
    }
    ah_budget_t *writer = writer_of(n, ah_peer_slot_key(f->sender), now_ms);
    if (!flash_room(n, len, now_ms) || !writer_room(n, writer, len, now_ms)) {
        // Past this hour's flash budget, or the depositor's share of it:
        // refused before a signature is spent on it.
        n->courier.refused++;
        return false;
    }
    const ah_verify_t v = ah_node_verify(n, f, p->signing_key, false, now_ms);
    if (v != AH_VERIFIED) {
        n->stats.rx_refused += v == AH_VERIFY_FAILED ? 1u : 0u;
        return v == AH_VERIFY_DEFERRED;
    }
    ah_envelope_t env;
    const size_t handover_frame = AH_V2_HEADER_LEN + 2u * AH_PEER_ID_LEN + len + ENVELOPE_GROWTH + AH_SIGNATURE_LEN;
    if (!ah_envelope_decode(payload, len, &env) || handover_frame > n->cfg.big_send_bytes) {
        // Larger than the node can hand over again in one cut: not taken.
        n->stats.rx_refused++;
        return false;
    }
    if (ah_courier_tag_matches(n->id.noise_public, wall, env.tag)) {
        // Mail for the node itself has nobody to read it.
        return false;
    }
    uint16_t slot = AH_MAIL_NONE;
    const ah_deposit_t d = ah_courier_deposit(&n->courier, payload, len, f->sender, wall, &slot);
    if (d == AH_DEPOSIT_STORED) {
        writer->used += (uint32_t)len + AH_MAIL_RECORD_OVERHEAD;
        flash_put(n, &n->courier.mail[slot], payload, len);
        n->stats.mail_stored++;
    } else if (d == AH_DEPOSIT_RAISED && persist_budget(n, slot, now_ms)) {
        // A rise rewrites the record, so it spends the depositor's share too.
        writer->used += (uint32_t)len + AH_MAIL_RECORD_OVERHEAD;
    }
    return false;
}

void ah_node_restore_mail(ah_node_t *n, uint32_t record, uint64_t depositor, const uint8_t *envelope, size_t len)
{
    // Restored before the clock is known: expiry is checked again once it is.
    if (!ah_courier_restore(&n->courier, record, envelope, len, depositor, 0) && n->ops.mail_delete != NULL) {
        n->ops.mail_delete(n->ops.ctx, record);
    }
}

// A fresh handover token, never 0 (no token). Fresh per attempt, so a piece
// of an attempt given up that is written late counts toward no other.
static uint32_t next_token(ah_node_t *n)
{
    n->mail_token = n->mail_token == UINT32_MAX ? 1u : n->mail_token + 1u;
    return n->mail_token;
}

// A COURIER_ENV from this node to `to`, carrying `copies` of the budget.
static bool send_envelope(ah_node_t *n, uint16_t slot, const uint8_t to[AH_PEER_ID_LEN], uint8_t copies,
                          uint16_t link, uint32_t token, uint64_t wall, int64_t now_ms)
{
    // The payload is built in the big-send preimage buffer, which only
    // ah_node_originate_big signs into, and only once ah_frame_encode has
    // copied the payload out. A cut under way reads only the big-send bytes.
    uint8_t *payload = n->big.preimage;
    const size_t len = ah_courier_encode(&n->courier, slot, copies, payload, n->cfg.big_send_bytes);
    if (len == 0) {
        return false;
    }
    const ah_frame_fields_t fields = {
        .type = AH_TYPE_COURIER_ENV,
        .ttl = AH_TTL_DEFAULT,
        .timestamp_ms = wall,
        .sender = n->id.peer_id,
        .recipient = to,
        .payload = payload,
        .payload_len = len,
    };
    const size_t frame_len = AH_V2_HEADER_LEN + 2u * AH_PEER_ID_LEN + len + AH_SIGNATURE_LEN;
    if (frame_len <= AH_FRAME_BUF_MAX) {
        return ah_node_originate(n, &fields, true, link, now_ms, token);
    }
    if (link == AH_LINK_NONE) {
        // A flood goes to every link, and a packet this large needs a cut per link.
        return false;
    }
    if (n->links.links[link].kind == AH_LINK_LORA) {
        // The trunk carries text: a cut this large would take minutes of its
        // duty budget, past what its own policy lets cross.
        return false;
    }
    return ah_node_originate_big(n, &fields, link, token, now_ms);
}

void ah_node_mail_on_announce(ah_node_t *n, uint16_t peer, bool direct, int64_t now_ms)
{
    uint64_t wall;
    if (!ah_clock_now(&n->clock, now_ms, &wall)) {
        return;
    }
    const ah_peer_t *p = &n->peers.slots[peer];
    uint8_t tags[AH_COURIER_CANDIDATE_TAGS][AH_COURIER_TAG_LEN];
    // A failed hash matches no envelope: nothing is handed to whoever asks.
    const bool tagged = ah_courier_candidate_tags(p->noise_key, wall, tags);
    const uint16_t link = direct ? p->direct_link : AH_LINK_NONE;
    // A handover or a spray only over a link the peer proved its Noise key
    // on, as bitchat-ios requires: anyone can pair a victim's public Noise key
    // with a signing key of their own and announce as them. Without the proof
    // the node opens a session, and acts when it completes (ah_dm.c).
    const uint16_t proven = direct ? ah_dm_proven_link(n, p->peer_id, peer) : AH_LINK_NONE;
    const uint64_t carrier = ah_peer_key(p->peer_id);
    bool wants_session = false;
    for (uint16_t i = 0; i < n->courier.cap; ++i) {
        ah_mail_t *m = &n->courier.mail[i];
        if (!m->in_use) {
            continue;
        }
        if (m->handing_over) {
            if (now_ms - m->handover_ms > HANDOVER_GIVE_UP_MS) {
                m->handing_over = false;
            }
            continue;
        }
        if (m->expiry_ms <= wall) {
            // Expired by our clock, so a phone would drop it on arrival:
            // nothing goes. Deleting it waits for a confirmed clock.
            continue;
        }
        if (tagged && ah_courier_is_for(&n->courier, i, tags)) {
            if (proven != AH_LINK_NONE) {
                // Marked before the send: its writes can land, and retire the
                // envelope, before send_envelope returns. One write unless the
                // frame is cut (ah_node_mail_cut).
                m->handing_over = true;
                m->handover_ms = now_ms;
                m->handover_token = next_token(n);
                m->pieces = 1;
                m->landed = 0;
                const uint32_t token = m->handover_token;
                if (!send_envelope(n, i, p->peer_id, m->copies, proven, token, wall, now_ms) &&
                        m->handover_token == token) {
                    m->handing_over = false;
                }
                continue;
            }
            wants_session = wants_session || direct;
            // Nothing acknowledges a flood, so it never retires the envelope.
            if (!m->flooded || now_ms - m->flooded_ms >= AH_COURIER_REMOTE_COOLDOWN_MS) {
                if (send_envelope(n, i, p->peer_id, 1, link, 0, wall, now_ms)) {
                    m->flooded = true;
                    m->flooded_ms = now_ms;
                }
            }
            continue;
        }
        // Spray: half the budget of anyone else's mail, once per carrier,
        // never back to its depositor, only to a neighbor that proved its
        // Noise key on its direct link, as bitchat-ios requires. Unproven,
        // anyone announcing a neighbor's key would take the copies meant for
        // that neighbor and leave it marked as sprayed. The carrier is
        // remembered, and the budget left persisted, once the envelope went out.
        if (direct && (link != AH_LINK_NONE || proven != AH_LINK_NONE) && m->copies > 1u && m->depositor != carrier &&
                !ah_courier_sprayed_to(&n->courier, i, p->peer_id)) {
            if (proven == AH_LINK_NONE) {
                wants_session = true;
                continue;
            }
            const uint8_t given = ah_courier_spray_share(&n->courier, i);
            if (send_envelope(n, i, p->peer_id, given, proven, 0, wall, now_ms)) {
                ah_courier_spray_commit(&n->courier, i, p->peer_id, given);
                persist_budget(n, i, now_ms);
            }
        }
    }
    if (wants_session) {
        ah_dm_start(n, peer, now_ms);
    }
}

// The envelope a handover with this token is under way for, or AH_MAIL_NONE.
static uint16_t handing_over(const ah_node_t *n, uint32_t token)
{
    for (uint16_t i = 0; i < n->courier.cap; ++i) {
        const ah_mail_t *m = &n->courier.mail[i];
        if (m->in_use && m->handing_over && m->handover_token == token) {
            return i;
        }
    }
    return AH_MAIL_NONE;
}

void ah_node_mail_cut(ah_node_t *n, uint32_t token, uint16_t pieces)
{
    const uint16_t i = handing_over(n, token);
    if (i != AH_MAIL_NONE) {
        n->courier.mail[i].pieces = pieces;
    }
}

void ah_node_mail_written(ah_node_t *n, uint32_t token)
{
    // Retired only once every piece is out. A piece dropped from the queue
    // (pushed out for something more urgent, or past its deadline) never
    // lands, so the envelope stays until the handover is given up and tried
    // again whole: the recipient cannot rebuild a cut with a piece missing.
    const uint16_t i = handing_over(n, token);
    if (i != AH_MAIL_NONE && ++n->courier.mail[i].landed >= n->courier.mail[i].pieces) {
        ah_courier_retire(&n->courier, i);
        n->stats.mail_delivered++;
    }
}

void ah_node_mail_expire(ah_node_t *n, int64_t now_ms)
{
    uint64_t wall;
    if (ah_clock_now(&n->clock, now_ms, &wall)) {
        ah_courier_expire(&n->courier, wall);
    }
}
