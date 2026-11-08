// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Wall time for a node with no RTC.
//
// Every phone drops a packet more than two minutes off its own clock, so the
// node originates nothing time-checked until it knows the time. It learns it
// only from the timestamps of signature-verified announces that arrived
// directly (TTL 7 on a link bound to their sender), the median of several,
// with outliers set aside. One voice per link and one per identity, whichever
// is fewer: a phone on two connections, or back on a new one, is one voice.
//
// Phones are the authority. Another relay node's announce (0xB1 bit 0) is a
// voice only while no phone voice is fresh, so a node with no phones beside it
// can still keep time from its neighbors; the first fresh phone voice takes
// over from them. The flag can only demote a voice, so claiming it gains a
// hostile device nothing.
//
//   UNSYNCED   no source yet; restored time only as a lower bound
//   TENTATIVE  a time, but no agreeing majority, or one source not yet consistent
//   SYNCED     two agreeing sources, or one consistent across 30 s
//
// Separately, the clock is `confirmed` once two agreeing phone voices have
// backed it since boot. Only a confirmed clock may destroy anything on the
// strength of the time (expire mail, prune the gossip stores, persist the
// floor), since one phone with a wrong clock, or a node's second-hand time,
// reaches SYNCED on its own. An unconfirmed SYNCED clock that no fresh phone
// voice backs gives way to the phones in reach, so one wrong phone never shuts
// out the honest ones that come after it.
//
// Once synced, the clock moves no faster than a crystal drifts, and once
// confirmed it never jumps: a majority of links may all be one device's, so
// no run of announces walks a confirmed time away. How far off a voice may be
// grows with the drift since a phone last agreed, so a node left alone for
// weeks is still pulled back by the first honest phone.
//
// Relaying never depends on this clock.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_wire.h"

typedef enum {
    AH_CLOCK_UNSYNCED = 0,
    AH_CLOCK_TENTATIVE,
    AH_CLOCK_SYNCED,
} ah_clock_state_t;

#define AH_CLOCK_SOURCES 8u

typedef struct {
    uint64_t voice;          // the identity the samples came from
    int64_t offset_ms;       // peer time minus our monotonic time at arrival
    int64_t at_ms;           // monotonic time of the latest sample
    int64_t consistent_from; // monotonic time this source's samples began agreeing
    uint32_t source;         // the link they came over, plus one; 0 a free slot
    uint16_t consistent;     // samples in a row within the consistency bound
    bool node;               // a relay node's voice: heard only while no phone's is fresh
    bool under_floor;        // its time is behind the floor: no voice unless phones behind it outnumber the rest
} ah_clock_source_t;

typedef struct {
    ah_clock_state_t state;
    bool confirmed;           // two agreeing phone voices have backed the time since boot
    int64_t offset_ms;        // wall = monotonic + offset
    int64_t slew_ms;          // how far a synced clock may still move
    int64_t slew_at_ms;       // monotonic time slew_ms last grew to
    int64_t backed_ms;        // monotonic time a phone voice last agreed with the clock, or it last synced
    int64_t first_ms;         // monotonic time of the first sample since boot; -1 before it
    uint64_t floor_wall_ms;   // last confirmed time saved before a reboot; 0 when none, or once overruled
    ah_clock_source_t sources[AH_CLOCK_SOURCES];
    uint32_t rejected;        // samples refused as outliers or before the floor
} ah_clock_t;

// Start UNSYNCED, with the last confirmed time saved before this boot (0 for
// none) as the floor no sample may fall far behind, unless phones agreeing
// behind it outnumber the rest: they overrule it, so a floor saved from a
// wrong time never holds the node away from the honest phones for good.
void ah_clock_init(ah_clock_t *clock, uint64_t restored_wall_ms);

// Feed the timestamp of a verified announce heard directly. `source` is the
// link it came over plus one, `voice` its sender's identity, `node` whether
// it carries 0xB1 bit 0, and `mono_ms` the monotonic time it arrived.
void ah_clock_sample(ah_clock_t *clock, uint32_t source, uint64_t voice, bool node, uint64_t peer_ts_ms,
                     int64_t mono_ms);

// The wall time now; false, with `*out` 0, while UNSYNCED.
bool ah_clock_now(const ah_clock_t *clock, int64_t mono_ms, uint64_t *out);

// Whether time-checked packets (announce, sync request, pong, mail) may be originated.
bool ah_clock_synced(const ah_clock_t *clock);

// Whether the time may be trusted to destroy something: SYNCED and confirmed by phones.
bool ah_clock_confirmed(const ah_clock_t *clock);

// The floor to persist now; false, with `*out` 0, until the clock is
// confirmed. Never later than the restored floor plus the time since the
// first sample, at the slowest real time could have passed, so a time set or
// walked ahead by hostile links leaves no floor that refuses honest phones
// after the next boot. With no restored floor there is nothing to measure
// from, and the first confirmed time is taken as it is; a majority of phones
// at a later boot overrules it if it was wrong.
bool ah_clock_floor(const ah_clock_t *clock, int64_t mono_ms, uint64_t *out);

// A time real time is surely past: the restored floor plus the time since
// `since_ms` (the node's start), counted as a fast crystal would. It rests on
// no phone's word, so it may expire mail and be saved as the floor while the
// clock is unconfirmed. False, with `*out` 0, with no floor or once phones
// overruled it.
bool ah_clock_lower_bound(const ah_clock_t *clock, int64_t since_ms, int64_t mono_ms, uint64_t *out);
