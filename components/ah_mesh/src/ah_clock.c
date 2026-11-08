// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Voting on wall time: one sample per link and per identity, outliers set
// aside, node voices only while no phone is fresh, confirmation by two
// agreeing phones, and corrections no faster than a crystal drifts.
#include "ah_clock.h"

#include <string.h>

// A sample older than this no longer speaks for the present.
#define SOURCE_FRESH_MS (10LL * 60 * 1000)
// Two NTP-disciplined phones and one BLE hop agree well inside this.
#define AGREE_MS 5000LL
// One phone's successive announces agree inside this.
#define CONSISTENT_MS 1000LL
// A lone source confirms itself only across this long and this many samples.
#define LONE_SPAN_MS 30000LL
#define LONE_SAMPLES 3u
// Once synced, the clock moves no faster than a crystal drifts: 50 ppm,
// comfortably above a 20 ppm part. The allowance starts at 0.5 s at a sync,
// for a phone's own jitter, grows at the drift rate and is spent by every
// step, and never holds more than drift_bound, so no run of samples moves
// the clock further than that plus the drift over the run.
#define DRIFT_PPM 50LL
#define MIN_STEP_MS 500LL
// A sample further than this behind the persisted floor is a rewind, refused
// unless phones agreeing on it outnumber the rest.
#define FLOOR_SLACK_MS (60LL * 1000)
// No honest clock comes near it, and below it every offset, its sums and its
// differences stay far inside int64_t.
#define WALL_MAX_MS ((uint64_t)INT64_MAX / 4u)

void ah_clock_init(ah_clock_t *clock, uint64_t restored_wall_ms)
{
    memset(clock, 0, sizeof(*clock));
    clock->floor_wall_ms = restored_wall_ms;
    clock->first_ms = -1;
}

static int64_t abs64(int64_t v)
{
    return v < 0 ? -v : v;
}

// The source an identity's sample over a link speaks through: its own if it
// has one, else the link's, so neither two links nor two identities make one
// device two voices. A link that changes hands, or a phone that turns node,
// starts a new voice.
static ah_clock_source_t *source_for(ah_clock_t *clock, uint32_t key, uint64_t voice, bool node)
{
    ah_clock_source_t *by_voice = NULL;
    ah_clock_source_t *by_link = NULL;
    ah_clock_source_t *oldest = &clock->sources[0];
    for (size_t i = 0; i < AH_CLOCK_SOURCES; ++i) {
        ah_clock_source_t *s = &clock->sources[i];
        if (s->source != 0 && s->voice == voice) {
            by_voice = s;
        } else if (s->source == key) {
            by_link = s;
        }
        if (s->source == 0 || s->at_ms < oldest->at_ms) {
            oldest = s;
        }
    }
    if (by_voice != NULL && by_link != NULL) {
        // The identity is back over a link another voice held: one voice for both.
        memset(by_link, 0, sizeof(*by_link));
    }
    ah_clock_source_t *s = by_voice != NULL ? by_voice : by_link;
    if (s == NULL || s->voice != voice || s->node != node) {
        s = s != NULL ? s : oldest;
        memset(s, 0, sizeof(*s));
    }
    s->source = key;
    s->voice = voice;
    s->node = node;
    return s;
}

static bool fresh_source(const ah_clock_source_t *s, int64_t mono_ms)
{
    return s->source != 0 && mono_ms - s->at_ms <= SOURCE_FRESH_MS;
}

static bool phone_fresh(const ah_clock_t *clock, int64_t mono_ms)
{
    for (size_t i = 0; i < AH_CLOCK_SOURCES; ++i) {
        const ah_clock_source_t *s = &clock->sources[i];
        if (!s->node && !s->under_floor && fresh_source(s, mono_ms)) {
            return true;
        }
    }
    return false;
}

// Whether a fresh phone voice agrees with the clock's own time.
static bool phone_backs(const ah_clock_t *clock, int64_t mono_ms)
{
    for (size_t i = 0; i < AH_CLOCK_SOURCES; ++i) {
        const ah_clock_source_t *s = &clock->sources[i];
        if (!s->node && !s->under_floor && fresh_source(s, mono_ms) &&
                abs64(s->offset_ms - clock->offset_ms) <= AGREE_MS) {
            return true;
        }
    }
    return false;
}

// Median offset over the fresh sources of one kind, how many of them agree
// with it, and how many there are; those behind the floor only when `under`.
static bool median_offset(const ah_clock_t *clock, bool nodes, bool under, int64_t mono_ms, int64_t *median,
                          size_t *agreeing, size_t *count)
{
    int64_t offsets[AH_CLOCK_SOURCES];
    size_t n = 0;
    for (size_t i = 0; i < AH_CLOCK_SOURCES; ++i) {
        const ah_clock_source_t *s = &clock->sources[i];
        if (s->node == nodes && (under || !s->under_floor) && fresh_source(s, mono_ms)) {
            offsets[n++] = s->offset_ms;
        }
    }
    if (n == 0) {
        return false;
    }
    for (size_t i = 1; i < n; ++i) {
        const int64_t v = offsets[i];
        size_t j = i;
        while (j > 0 && offsets[j - 1u] > v) {
            offsets[j] = offsets[j - 1u];
            j--;
        }
        offsets[j] = v;
    }
    *median = offsets[n / 2u];
    *count = n;
    *agreeing = 0;
    for (size_t i = 0; i < n; ++i) {
        const int64_t d = offsets[i] - *median;
        if (d <= AGREE_MS && d >= -AGREE_MS) {
            (*agreeing)++;
        }
    }
    return true;
}

// The floor stops one phone, or a node's second-hand time, taking the clock
// back. Phones behind it that agree, and outnumber every other fresh phone,
// overrule it, and it is gone for this boot: a floor saved from a wrong time,
// as a hostile majority at a fresh node's first boot could plant, would
// otherwise hold the node ahead of every honest phone across every reboot.
// Such a majority could as well set the time at boot, so this gives it nothing.
static bool floor_overruled(ah_clock_t *clock, int64_t mono_ms)
{
    int64_t median = 0;
    size_t agreeing = 0;
    size_t count = 0;
    if (!median_offset(clock, false, true, mono_ms, &median, &agreeing, &count) || agreeing < 2u ||
            agreeing * 2u <= count || median + mono_ms + FLOOR_SLACK_MS >= (int64_t)clock->floor_wall_ms) {
        return false;
    }
    clock->floor_wall_ms = 0;
    for (size_t i = 0; i < AH_CLOCK_SOURCES; ++i) {
        clock->sources[i].under_floor = false;
    }
    return true;
}

// A sync: the time is taken as it is, and the slew allowance starts over.
static void set_offset(ah_clock_t *clock, int64_t offset, int64_t mono_ms)
{
    clock->offset_ms = offset;
    clock->slew_ms = MIN_STEP_MS;
    clock->slew_at_ms = mono_ms;
    clock->backed_ms = mono_ms;
}

// How far a voice may sit from the clock and still be heard, and the most the
// allowance holds: what two phones may differ by, plus the drift since a phone
// last agreed. A node alone for days can then still be pulled back, while a
// phone that keeps agreeing walks it no faster than the drift rate.
static int64_t drift_bound(const ah_clock_t *clock, int64_t mono_ms)
{
    const int64_t since = mono_ms > clock->backed_ms ? mono_ms - clock->backed_ms : 0;
    return AGREE_MS + since * DRIFT_PPM / 1000000LL;
}

// The allowance now. It grows in whole milliseconds, its start moving on by
// exactly the time they took, so samples a few milliseconds apart lose none
// of it to rounding.
static int64_t slew_allowance(ah_clock_t *clock, int64_t mono_ms, int64_t bound)
{
    const int64_t grown = (mono_ms - clock->slew_at_ms) * DRIFT_PPM / 1000000LL;
    if (grown > 0) {
        clock->slew_at_ms += grown * 1000000LL / DRIFT_PPM;
        clock->slew_ms = clock->slew_ms + grown > bound ? bound : clock->slew_ms + grown;
    }
    return clock->slew_ms;
}

// The SYNCED clock against a new median. When most voices agree it is wrong,
// an unconfirmed clock re-syncs; a confirmed one never jumps, since the links
// that outvote it may all be one device's. Otherwise one voice past the drift
// bound is set aside, and the clock slews toward the median within the
// allowance.
static void correct(ah_clock_t *clock, int64_t sample_offset, int64_t median, bool majority, int64_t mono_ms)
{
    const int64_t error = median - clock->offset_ms;
    const bool outvoted = majority && abs64(error) > AGREE_MS;
    if (outvoted && !clock->confirmed) {
        set_offset(clock, median, mono_ms);
        return;
    }
    const int64_t bound = drift_bound(clock, mono_ms);
    if (!outvoted && abs64(sample_offset - clock->offset_ms) > bound) {
        clock->rejected++;
        return;
    }
    const int64_t allowance = slew_allowance(clock, mono_ms, bound);
    const int64_t step = error > allowance ? allowance : (error < -allowance ? -allowance : error);
    clock->offset_ms += step;
    clock->slew_ms -= abs64(step);
}

void ah_clock_sample(ah_clock_t *clock, uint32_t source, uint64_t voice, bool node, uint64_t peer_ts_ms,
                     int64_t mono_ms)
{
    if (clock->first_ms < 0) {
        clock->first_ms = mono_ms;
    }
    if (source == 0 || peer_ts_ms > WALL_MAX_MS) {
        clock->rejected++;
        return;
    }
    const int64_t offset = (int64_t)peer_ts_ms - mono_ms;
    ah_clock_source_t *s = source_for(clock, source, voice, node);
    if (s->consistent > 0 && abs64(offset - s->offset_ms) <= CONSISTENT_MS) {
        s->consistent++;
    } else {
        s->consistent = 1;
        s->consistent_from = mono_ms;
    }
    s->offset_ms = offset;
    s->at_ms = mono_ms;
    s->under_floor = clock->floor_wall_ms != 0 && peer_ts_ms + (uint64_t)FLOOR_SLACK_MS < clock->floor_wall_ms;
    if (s->under_floor && (node || !floor_overruled(clock, mono_ms))) {
        clock->rejected++;
        return;
    }

    const bool nodes = !phone_fresh(clock, mono_ms);
    if (node && !nodes) {
        // Kept for when the phones go, but no voice while one is fresh.
        return;
    }
    int64_t median = 0;
    size_t agreeing = 0;
    size_t count = 0;
    if (!median_offset(clock, nodes, false, mono_ms, &median, &agreeing, &count)) {
        return;
    }
    if (!nodes && clock->state == AH_CLOCK_SYNCED && !clock->confirmed && abs64(median - clock->offset_ms) > AGREE_MS &&
            !phone_backs(clock, mono_ms)) {
        // An unconfirmed time no fresh phone backs (second-hand, or a phone's
        // that has gone) gives way to the phones in reach: their time is
        // followed, and trusted, as it would be after a boot.
        clock->state = AH_CLOCK_TENTATIVE;
    }
    // Two voices that agree, and more than half of all of them: an even split
    // never wins, whichever half the median falls in.
    const bool majority = agreeing >= 2u && agreeing * 2u > count;
    const bool lone_confirmed = s->consistent >= LONE_SAMPLES && mono_ms - s->consistent_from >= LONE_SPAN_MS;

    switch (clock->state) {
    case AH_CLOCK_UNSYNCED:
        set_offset(clock, median, mono_ms);
        clock->state = majority ? AH_CLOCK_SYNCED : AH_CLOCK_TENTATIVE;
        break;
    case AH_CLOCK_TENTATIVE:
        // Not yet trusted, so it follows the median freely until confirmed.
        set_offset(clock, median, mono_ms);
        if (majority || (count == 1u && lone_confirmed)) {
            clock->state = AH_CLOCK_SYNCED;
        }
        break;
    case AH_CLOCK_SYNCED:
        correct(clock, offset, median, majority, mono_ms);
        break;
    }
    if (!nodes && majority && clock->state == AH_CLOCK_SYNCED && abs64(median - clock->offset_ms) <= AGREE_MS) {
        clock->confirmed = true;
    }
    if (!node && clock->state == AH_CLOCK_SYNCED && abs64(offset - clock->offset_ms) <= AGREE_MS) {
        clock->backed_ms = mono_ms;
    }
}

bool ah_clock_now(const ah_clock_t *clock, int64_t mono_ms, uint64_t *out)
{
    if (clock->state == AH_CLOCK_UNSYNCED) {
        *out = 0;
        return false;
    }
    const int64_t wall = mono_ms + clock->offset_ms;
    *out = wall < 0 ? 0 : (uint64_t)wall;
    return true;
}

bool ah_clock_synced(const ah_clock_t *clock)
{
    return clock->state == AH_CLOCK_SYNCED;
}

bool ah_clock_confirmed(const ah_clock_t *clock)
{
    return clock->state == AH_CLOCK_SYNCED && clock->confirmed;
}

bool ah_clock_floor(const ah_clock_t *clock, int64_t mono_ms, uint64_t *out)
{
    uint64_t wall = 0;
    if (!ah_clock_confirmed(clock) || !ah_clock_now(clock, mono_ms, &wall)) {
        *out = 0;
        return false;
    }
    if (clock->floor_wall_ms != 0) {
        // Real time has run at least this long since the restored floor was
        // saved: since the first sample, as a crystal 50 ppm fast counts it.
        const int64_t ran = mono_ms - clock->first_ms;
        const uint64_t ceiling = clock->floor_wall_ms + (uint64_t)(ran - ran * DRIFT_PPM / 1000000LL);
        if (wall > ceiling) {
            wall = ceiling;
        }
    }
    *out = wall;
    return true;
}

bool ah_clock_lower_bound(const ah_clock_t *clock, int64_t since_ms, int64_t mono_ms, uint64_t *out)
{
    if (clock->floor_wall_ms == 0 || mono_ms < since_ms) {
        *out = 0;
        return false;
    }
    const int64_t ran = mono_ms - since_ms;
    *out = clock->floor_wall_ms + (uint64_t)(ran - ran * DRIFT_PPM / 1000000LL);
    return true;
}
