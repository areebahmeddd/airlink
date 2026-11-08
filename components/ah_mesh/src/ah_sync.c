// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The sync stores, the filters a request carries, and the replies planned from them.
#include "ah_sync.h"

#include <string.h>

#include "ah_gcs.h"
#include "ah_mesh_ids.h"

// Values a decoded peer filter may hold: bitchat-ios refuses data past 1024
// bytes, and at the P of 7 every sender uses, a value costs at least 8 bits.
#define DECODE_VALUES 1024u

typedef ah_sync_candidate_t candidate_t;

// The SyncTypeFlags bit a type is served under, or -1 when it is not synced.
static int bit_of(uint8_t type)
{
    switch (type) {
    case AH_TYPE_ANNOUNCE:
        return AH_SYNC_BIT_ANNOUNCE;
    case AH_TYPE_CHANNEL_MSG:
        return AH_SYNC_BIT_MESSAGE;
    case AH_TYPE_BOARD_POST:
        return AH_SYNC_BIT_BOARD;
    case AH_TYPE_GROUP_MESSAGE:
        return AH_SYNC_BIT_GROUP;
    case AH_TYPE_CHANNEL_MSG_AIRHOP:
        return AH_SYNC_BIT_CHANNEL_AIRHOP;
    default:
        return -1;
    }
}

// How long a type stays worth offering (announces 60 s, messages 6 h, board 7 days).
static int64_t max_age_ms(uint8_t type)
{
    switch (type) {
    case AH_TYPE_ANNOUNCE:
        return AH_SYNC_ANNOUNCE_MAX_AGE_MS;
    case AH_TYPE_CHANNEL_MSG:
    case AH_TYPE_CHANNEL_MSG_AIRHOP:
    case AH_TYPE_GROUP_MESSAGE:
        return AH_SYNC_MESSAGE_MAX_AGE_MS;
    case AH_TYPE_BOARD_POST:
        return AH_SYNC_BOARD_MAX_AGE_MS;
    default:
        return -1;
    }
}

static int store_of(uint8_t type)
{
    switch (type) {
    case AH_TYPE_ANNOUNCE:
        return AH_STORE_ANNOUNCE;
    case AH_TYPE_CHANNEL_MSG:
    case AH_TYPE_CHANNEL_MSG_AIRHOP:
        return AH_STORE_MESSAGE;
    case AH_TYPE_GROUP_MESSAGE:
        return AH_STORE_GROUP;
    case AH_TYPE_BOARD_POST:
        return AH_STORE_BOARD;
    default:
        return -1;
    }
}

// What a store serves, as SyncTypeFlags bits.
static uint64_t store_types(size_t store)
{
    switch (store) {
    case AH_STORE_ANNOUNCE:
        return 1ull << AH_SYNC_BIT_ANNOUNCE;
    case AH_STORE_MESSAGE:
        return (1ull << AH_SYNC_BIT_MESSAGE) | (1ull << AH_SYNC_BIT_CHANNEL_AIRHOP);
    case AH_STORE_GROUP:
        return 1ull << AH_SYNC_BIT_GROUP;
    default:
        return 1ull << AH_SYNC_BIT_BOARD;
    }
}

// How long what a store holds stays worth offering.
static int64_t store_max_age_ms(size_t store)
{
    switch (store) {
    case AH_STORE_ANNOUNCE:
        return AH_SYNC_ANNOUNCE_MAX_AGE_MS;
    case AH_STORE_BOARD:
        return AH_SYNC_BOARD_MAX_AGE_MS;
    default:
        return AH_SYNC_MESSAGE_MAX_AGE_MS;
    }
}

static bool in_types(uint8_t type, uint64_t types)
{
    const int bit = bit_of(type);
    return bit >= 0 && ((types >> bit) & 1u) != 0;
}

static bool age_within(uint64_t ts_ms, uint64_t now_ms, int64_t max_age)
{
    const int64_t age = (int64_t)(now_ms - ts_ms);
    return max_age >= 0 && age >= -AH_MAX_SKEW_MS && age <= max_age;
}

// Worth advertising or offering: inside its type's window, and not dated past
// the skew ahead, since a future stamp would pin an entry at the head forever.
static bool in_sync_window(uint8_t type, uint64_t ts_ms, uint64_t now_ms)
{
    return age_within(ts_ms, now_ms, max_age_ms(type));
}

bool ah_sync_reply_in_window(uint8_t type, uint64_t ts_ms, uint64_t now_ms)
{
    // A reply's fragments carry the packet inside's own timestamp, so they get
    // the longest window and the reassembled packet meets its own.
    return type == AH_TYPE_FRAGMENT ? age_within(ts_ms, now_ms, AH_SYNC_BOARD_MAX_AGE_MS)
           : in_sync_window(type, ts_ms, now_ms);
}

// Only the newest that could ever fit a 400-byte filter are worth hashing
// (GCSFilter.estimateMaxElements at P = 7).
#define FILTER_PICK ((AH_GCS_MAX_BYTES * 8u) / (AH_GCS_P + 2u))

// Candidates for our own filter: never more than one filter holds, and
// never more than the stores and the declined list can offer.
static size_t pick_cap(const ah_sync_sizes_t *sizes)
{
    size_t held = sizes->declined;
    for (size_t i = 0; i < AH_STORE_COUNT; ++i) {
        held += sizes->entries[i];
    }
    return held < FILTER_PICK ? held : FILTER_PICK;
}

size_t ah_sync_memory(const ah_sync_sizes_t *sizes)
{
    size_t total = 0;
    for (size_t i = 0; i < AH_STORE_COUNT; ++i) {
        total += sizes->entries[i] * sizeof(ah_sync_entry_t) + ((sizes->bytes[i] + 7u) & ~(size_t)7u);
    }
    total += sizes->declined * sizeof(ah_sync_declined_t);
    total += pick_cap(sizes) * (sizeof(candidate_t) + sizeof(uint64_t) + sizeof(uint32_t));
    total += DECODE_VALUES * sizeof(uint32_t);
    // Slack for aligning `mem` to eight bytes.
    return total + 16u;
}

void ah_sync_init(ah_sync_t *sync, const ah_sync_sizes_t *sizes, void *mem)
{
    memset(sync, 0, sizeof(*sync));
    uint8_t *p = (uint8_t *)(((uintptr_t)mem + 7u) & ~(uintptr_t)7u);
    for (size_t i = 0; i < AH_STORE_COUNT; ++i) {
        ah_sync_store_t *s = &sync->stores[i];
        s->entries = (ah_sync_entry_t *)(void *)p;
        s->cap = sizes->entries[i];
        p += s->cap * sizeof(ah_sync_entry_t);
        s->arena = p;
        s->arena_size = sizes->bytes[i];
        p += (sizes->bytes[i] + 7u) & ~(size_t)7u;
    }
    sync->declined = (ah_sync_declined_t *)(void *)p;
    sync->declined_cap = sizes->declined;
    memset(sync->declined, 0, sizes->declined * sizeof(ah_sync_declined_t));
    p += sizes->declined * sizeof(ah_sync_declined_t);
    sync->pick_cap = pick_cap(sizes);
    sync->pick = (candidate_t *)(void *)p;
    p += sync->pick_cap * sizeof(candidate_t);
    sync->hashes = (uint64_t *)(void *)p;
    p += sync->pick_cap * sizeof(uint64_t);
    sync->encode = (uint32_t *)(void *)p;
    p += sync->pick_cap * sizeof(uint32_t);
    sync->values = (uint32_t *)(void *)p;
}

static ah_sync_entry_t *entry_at(ah_sync_store_t *s, uint16_t i)
{
    return &s->entries[(s->head + i) % s->cap];
}

static void drop_head(ah_sync_store_t *s)
{
    s->head = (uint16_t)((s->head + 1u) % s->cap);
    s->count--;
    if (s->count == 0) {
        s->tail = 0;
    }
}

// Give up the oldest entry to make room, remembering how recent what was
// lost is when it was still live.
static void evict_head(ah_sync_store_t *s)
{
    const ah_sync_entry_t *e = entry_at(s, 0);
    if (!e->dead && e->ts_ms > s->evicted_newest_ms) {
        s->evicted_newest_ms = e->ts_ms;
    }
    drop_head(s);
}

// Where `len` bytes fit without overwriting a live entry, evicting from the
// head as needed; UINT32_MAX when the frame can never fit.
//
// The live bytes run from the head entry's offset to `tail`, wrapping at the
// end of the arena. With entries held, `tail` equal to the head's offset can
// only mean the ring is exactly full, never empty.
static uint32_t reserve(ah_sync_store_t *s, size_t len)
{
    if (len > s->arena_size) {
        return UINT32_MAX;
    }
    for (;;) {
        if (s->count == s->cap) {
            evict_head(s);
            continue;
        }
        if (s->count == 0) {
            s->tail = 0;
            return 0;
        }
        const uint32_t head_off = entry_at(s, 0)->offset;
        if (s->tail > head_off) {
            if (s->arena_size - s->tail >= len) {
                return s->tail;
            }
            if (head_off >= len) {
                return 0;
            }
        } else if (head_off - s->tail >= len) {
            return s->tail;
        }
        evict_head(s);
    }
}

bool ah_sync_track(ah_sync_t *sync, const ah_frame_t *frame, const uint8_t id[AH_PACKET_ID_LEN], uint64_t now_ms)
{
    const int kind = store_of(frame->type);
    if (kind < 0 || !ah_frame_is_broadcast(frame) || !in_sync_window(frame->type, frame->timestamp_ms, now_ms)) {
        return false;
    }
    ah_sync_store_t *s = &sync->stores[kind];
    if (s->cap == 0) {
        return false;
    }
    const uint64_t sender = ah_peer_key(frame->sender);
    for (uint16_t i = 0; i < s->count; ++i) {
        ah_sync_entry_t *e = entry_at(s, i);
        if (e->dead) {
            continue;
        }
        if (memcmp(e->id, id, AH_PACKET_ID_LEN) == 0) {
            return false;
        }
        if (kind == AH_STORE_ANNOUNCE && e->sender == sender) {
            if (e->ts_ms >= frame->timestamp_ms) {
                return false;
            }
            e->dead = true;
        }
    }
    const uint32_t off = reserve(s, frame->len);
    if (off == UINT32_MAX) {
        return false;
    }
    memcpy(s->arena + off, frame->bytes, frame->len);
    ah_sync_entry_t *e = &s->entries[(s->head + s->count) % s->cap];
    s->count++;
    s->tail = off + (uint32_t)frame->len;
    e->offset = off;
    e->len = (uint32_t)frame->len;
    e->type = frame->type;
    e->dead = false;
    e->ts_ms = frame->timestamp_ms;
    e->sender = sender;
    memcpy(e->id, id, AH_PACKET_ID_LEN);
    e->seq = ++sync->seq;

    for (uint16_t i = 0; i < sync->declined_cap; ++i) {
        if (memcmp(sync->declined[i].id, id, AH_PACKET_ID_LEN) == 0) {
            memset(&sync->declined[i], 0, sizeof(sync->declined[i]));
        }
    }
    return true;
}

bool ah_sync_holds(const ah_sync_t *sync, uint8_t type, const uint8_t id[AH_PACKET_ID_LEN])
{
    const int kind = store_of(type);
    if (kind < 0) {
        return false;
    }
    const ah_sync_store_t *s = &sync->stores[kind];
    for (uint16_t i = 0; i < s->count; ++i) {
        const ah_sync_entry_t *e = &s->entries[(s->head + i) % s->cap];
        if (!e->dead && memcmp(e->id, id, AH_PACKET_ID_LEN) == 0) {
            return true;
        }
    }
    return false;
}

void ah_sync_decline(ah_sync_t *sync, const ah_frame_t *frame, const uint8_t id[AH_PACKET_ID_LEN])
{
    if (sync->declined_cap == 0 || bit_of(frame->type) < 0) {
        return;
    }
    ah_sync_declined_t *d = &sync->declined[sync->declined_next];
    sync->declined_next = (uint16_t)((sync->declined_next + 1u) % sync->declined_cap);
    memcpy(d->id, id, AH_PACKET_ID_LEN);
    d->type = frame->type;
    d->ts_ms = frame->timestamp_ms;
    d->sender = ah_peer_key(frame->sender);
}

void ah_sync_undecline(ah_sync_t *sync, const uint8_t sender[AH_PEER_ID_LEN])
{
    const uint64_t key = ah_peer_key(sender);
    for (uint16_t i = 0; i < sync->declined_cap; ++i) {
        if (sync->declined[i].type != 0 && sync->declined[i].sender == key) {
            memset(&sync->declined[i], 0, sizeof(sync->declined[i]));
        }
    }
}

void ah_sync_purge_sender(ah_sync_t *sync, const uint8_t sender[AH_PEER_ID_LEN])
{
    // Their presence goes; what they said stays, which is what a node holds
    // history for (bitchat-ios purges it too, after 60 s of silence).
    const uint64_t key = ah_peer_key(sender);
    ah_sync_store_t *s = &sync->stores[AH_STORE_ANNOUNCE];
    for (uint16_t i = 0; i < s->count; ++i) {
        ah_sync_entry_t *e = entry_at(s, i);
        if (e->sender == key) {
            e->dead = true;
        }
    }
}

const uint8_t *ah_sync_latest_announce(const ah_sync_t *sync, const uint8_t sender[AH_PEER_ID_LEN], size_t *len)
{
    const ah_sync_store_t *s = &sync->stores[AH_STORE_ANNOUNCE];
    const uint64_t key = ah_peer_key(sender);
    for (uint16_t i = 0; i < s->count; ++i) {
        // An announce replaces its sender's older one, so one is live at most.
        const ah_sync_entry_t *e = &s->entries[(s->head + i) % s->cap];
        if (!e->dead && e->sender == key) {
            *len = e->len;
            return s->arena + e->offset;
        }
    }
    return NULL;
}

void ah_sync_prune(ah_sync_t *sync, uint64_t now_ms)
{
    for (size_t k = 0; k < AH_STORE_COUNT; ++k) {
        ah_sync_store_t *s = &sync->stores[k];
        for (uint16_t i = 0; i < s->count; ++i) {
            ah_sync_entry_t *e = entry_at(s, i);
            if (!in_sync_window(e->type, e->ts_ms, now_ms)) {
                e->dead = true;
            }
        }
        // Reclaim dead entries that reached the head.
        while (s->count > 0 && entry_at(s, 0)->dead) {
            drop_head(s);
        }
        // What was given up has aged out everywhere: no peer offers it again.
        if (s->evicted_newest_ms != 0 && !age_within(s->evicted_newest_ms, now_ms, store_max_age_ms(k))) {
            s->evicted_newest_ms = 0;
        }
    }
    for (uint16_t i = 0; i < sync->declined_cap; ++i) {
        ah_sync_declined_t *d = &sync->declined[i];
        if (d->type != 0 && !in_sync_window(d->type, d->ts_ms, now_ms)) {
            memset(d, 0, sizeof(*d));
        }
    }
}

// Min-heap on timestamp over the first `n` candidates, so the newest K of a
// large set are kept in O(n log K) without allocating.
static void sift_down(candidate_t *heap, size_t n, size_t i)
{
    for (;;) {
        size_t smallest = i;
        const size_t l = 2u * i + 1u;
        const size_t r = l + 1u;
        if (l < n && heap[l].ts < heap[smallest].ts) {
            smallest = l;
        }
        if (r < n && heap[r].ts < heap[smallest].ts) {
            smallest = r;
        }
        if (smallest == i) {
            return;
        }
        const candidate_t t = heap[i];
        heap[i] = heap[smallest];
        heap[smallest] = t;
        i = smallest;
    }
}

static void consider(candidate_t *heap, size_t *n, size_t k, uint64_t ts, const uint8_t id[AH_PACKET_ID_LEN],
                     size_t *total)
{
    (*total)++;
    if (*n < k) {
        heap[(*n)++] = (candidate_t) {
            .ts = ts, .hash = ah_gcs_hash(id)
        };
        if (*n == k) {
            for (size_t i = k / 2u + 1u; i-- > 0;) {
                sift_down(heap, k, i);
            }
        }
        return;
    }
    if (ts > heap[0].ts) {
        heap[0] = (candidate_t) {
            .ts = ts, .hash = ah_gcs_hash(id)
        };
        sift_down(heap, k, 0);
    }
}

size_t ah_sync_build_request(ah_sync_t *sync, uint64_t types, uint64_t now_ms, uint8_t *out, size_t cap)
{
    candidate_t *cand = sync->pick;
    const size_t k = sync->pick_cap;
    size_t n = 0;
    size_t total = 0;
    for (size_t s = 0; s < AH_STORE_COUNT; ++s) {
        const ah_sync_store_t *store = &sync->stores[s];
        for (uint16_t i = 0; i < store->count; ++i) {
            const ah_sync_entry_t *e = &store->entries[(store->head + i) % store->cap];
            if (!e->dead && in_types(e->type, types) && in_sync_window(e->type, e->ts_ms, now_ms)) {
                consider(cand, &n, k, e->ts_ms, e->id, &total);
            }
        }
    }
    for (uint16_t i = 0; i < sync->declined_cap; ++i) {
        const ah_sync_declined_t *d = &sync->declined[i];
        if (d->type != 0 && in_types(d->type, types) && in_sync_window(d->type, d->ts_ms, now_ms)) {
            consider(cand, &n, k, d->ts_ms, d->id, &total);
        }
    }
    if (n > 0 && n < k) {
        for (size_t i = n / 2u + 1u; i-- > 0;) {
            sift_down(cand, n, i);
        }
    }
    // Heap-sort: moving the oldest to the end each pass leaves the array newest first.
    for (size_t end = n; end > 1u; --end) {
        const candidate_t t = cand[0];
        cand[0] = cand[end - 1u];
        cand[end - 1u] = t;
        sift_down(cand, end - 1u, 0);
    }
    for (size_t i = 0; i < n; ++i) {
        sync->hashes[i] = cand[i].hash;
    }
    uint8_t data[AH_GCS_MAX_BYTES];
    ah_gcs_built_t built;
    ah_gcs_build(sync->hashes, n, data, sizeof(data), sync->encode, &built);

    ah_sync_request_t req = {
        .p = built.p,
        .m = built.m,
        .data = data,
        .data_len = built.data_len,
        .has_types = true,
        .types = types,
    };
    // The cursor says how far back the filter reaches, and only when it does
    // not reach everything: sent unconditionally it would tell every peer to
    // withhold the history a newcomer came for (PROTOCOLS section 5.1). A
    // store that gave up entries for room asks for nothing at or before the
    // newest it lost, or each peer would offer it again every round; once
    // that has aged out, the store asks for everything again.
    if (built.included > 0 && built.included < total) {
        req.has_since = true;
        req.since_ms = cand[built.included - 1u].ts;
    }
    for (size_t s = 0; s < AH_STORE_COUNT; ++s) {
        const uint64_t lost = sync->stores[s].evicted_newest_ms;
        if ((store_types(s) & types) != 0 && lost != 0 && (!req.has_since || lost + 1u > req.since_ms)) {
            req.has_since = true;
            req.since_ms = lost + 1u;
        }
    }
    return ah_sync_request_encode(&req, out, cap);
}

uint64_t ah_sync_evicted_types(const ah_sync_t *sync, uint64_t types)
{
    uint64_t evicted = 0;
    for (size_t s = 0; s < AH_STORE_COUNT; ++s) {
        if (sync->stores[s].evicted_newest_ms != 0) {
            evicted |= store_types(s) & types;
        }
    }
    return evicted;
}

size_t ah_sync_plan_reply(ah_sync_t *sync, const ah_sync_request_t *req, uint64_t now_ms, ah_sync_ref_t *refs,
                          size_t cap)
{
    const size_t count = ah_gcs_decode(req->p, req->m, req->data, req->data_len, sync->values, DECODE_VALUES);
    // A request without types predates them: announces and public messages only.
    const uint64_t types =
        req->has_types ? req->types : ((1ull << AH_SYNC_BIT_ANNOUNCE) | (1ull << AH_SYNC_BIT_MESSAGE));
    size_t n = 0;
    for (size_t s = 0; s < AH_STORE_COUNT && n < cap; ++s) {
        const ah_sync_store_t *store = &sync->stores[s];
        // Newest first within each store; announces come first of all so a
        // receiver holds the keys before the messages that need them.
        for (uint16_t i = store->count; i-- > 0 && n < cap;) {
            const ah_sync_entry_t *e = &store->entries[(store->head + i) % store->cap];
            if (e->dead || !in_types(e->type, types) || !in_sync_window(e->type, e->ts_ms, now_ms)) {
                continue;
            }
            // Announces are served past the cursor, as bitchat-ios serves them:
            // they carry the keys the rest is verified against.
            if (req->has_since && e->ts_ms < req->since_ms && s != AH_STORE_ANNOUNCE) {
                continue;
            }
            const uint32_t bucket = ah_gcs_bucket(ah_gcs_hash(e->id), req->m);
            if (req->m > 1u && ah_gcs_contains(sync->values, count, bucket)) {
                continue;
            }
            refs[n++] = (ah_sync_ref_t) {
                .store = (uint8_t)s, .slot = (uint16_t)((store->head + i) % store->cap),
                .seq = e->seq
            };
        }
    }
    return n;
}

const uint8_t *ah_sync_entry_bytes(const ah_sync_t *sync, ah_sync_ref_t ref, size_t *len)
{
    const ah_sync_store_t *s = &sync->stores[ref.store];
    if (ref.slot >= s->cap) {
        return NULL;
    }
    const ah_sync_entry_t *e = &s->entries[ref.slot];
    if (e->seq != ref.seq || e->dead) {
        return NULL;
    }
    // A dropped entry keeps its seq, so its slot must also lie inside the ring.
    const uint16_t pos = (uint16_t)((ref.slot + s->cap - s->head) % s->cap);
    if (pos >= s->count) {
        return NULL;
    }
    *len = e->len;
    return s->arena + e->offset;
}
