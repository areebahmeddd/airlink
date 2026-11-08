// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// Golomb-Coded Set encoding and decoding, bit for bit as bitchat-ios writes them.
#include "ah_gcs.h"

#include "ah_bytes.h"
#include "ah_crypto.h"

// GCSFilter.estimateMaxElements, floors included: about 8 * bytes / (P + 2)
// values fit, and never fewer than one, so a filter over any hash has the
// M = n << P a peer accepts (M > 1) however small its budget.
static size_t gcs_estimate(size_t bytes, size_t p)
{
    const size_t bits = bytes * 8u > 8u ? bytes * 8u : 8u;
    const size_t per = p + 2u > 3u ? p + 2u : 3u;
    return bits / per > 1u ? bits / per : 1u;
}

uint64_t ah_gcs_hash(const uint8_t packet_id[AH_PACKET_ID_LEN])
{
    uint8_t digest[AH_SHA256_LEN];
    (void)ah_sha256(packet_id, AH_PACKET_ID_LEN, digest);
    return ah_be64(digest) & 0x7FFFFFFFFFFFFFFFull;
}

uint32_t ah_gcs_bucket(uint64_t hash, uint32_t m)
{
    if (m == 0) {
        return 1;
    }
    const uint32_t v = (uint32_t)(hash % m);
    return v == 0 ? 1u : v;
}

typedef struct {
    const uint8_t *data;
    size_t bits;
    size_t pos;
} bit_reader_t;

static int read_bit(bit_reader_t *r)
{
    if (r->pos >= r->bits) {
        return -1;
    }
    const int bit = (r->data[r->pos >> 3] >> (7u - (r->pos & 7u))) & 1;
    r->pos++;
    return bit;
}

size_t ah_gcs_decode(uint8_t p, uint32_t m, const uint8_t *data, size_t len, uint32_t *values, size_t cap)
{
    if (p < 1u || p > AH_GCS_P_MAX || m <= 1u || data == NULL) {
        return 0;
    }
    bit_reader_t r = {.data = data, .bits = len * 8u, .pos = 0};
    uint64_t acc = 0;
    size_t count = 0;
    while (count < cap) {
        uint64_t q = 0;
        int bit;
        while ((bit = read_bit(&r)) == 1) {
            q++;
            // A quotient this large already passes M; the stream is junk.
            if ((q << p) >= m) {
                return count;
            }
        }
        if (bit < 0) {
            return count;
        }
        uint64_t rem = 0;
        for (uint8_t i = 0; i < p; ++i) {
            bit = read_bit(&r);
            if (bit < 0) {
                return count;
            }
            rem = rem << 1 | (uint64_t)bit;
        }
        acc += (q << p) + rem + 1u;
        if (acc >= m) {
            return count;
        }
        values[count++] = (uint32_t)acc;
    }
    return count;
}

bool ah_gcs_contains(const uint32_t *values, size_t count, uint32_t bucket)
{
    size_t lo = 0;
    size_t hi = count;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2u;
        if (values[mid] == bucket) {
            return true;
        }
        if (values[mid] < bucket) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    return false;
}

typedef struct {
    uint8_t *out;
    size_t cap;
    size_t bit;
    bool overflow;
} bit_writer_t;

static void write_bit(bit_writer_t *w, unsigned bit)
{
    const size_t byte = w->bit >> 3;
    if (byte >= w->cap) {
        w->overflow = true;
        return;
    }
    if ((w->bit & 7u) == 0) {
        w->out[byte] = 0;
    }
    if (bit) {
        w->out[byte] |= (uint8_t)(0x80u >> (w->bit & 7u));
    }
    w->bit++;
}

static void sort_unique(uint32_t *v, size_t *n)
{
    // Insertion sort: at most a few hundred values, no recursion, no allocation.
    for (size_t i = 1; i < *n; ++i) {
        const uint32_t key = v[i];
        size_t j = i;
        while (j > 0 && v[j - 1u] > key) {
            v[j] = v[j - 1u];
            j--;
        }
        v[j] = key;
    }
    size_t out = 0;
    for (size_t i = 0; i < *n; ++i) {
        if (out == 0 || v[i] > v[out - 1u]) {
            v[out++] = v[i];
        }
    }
    *n = out;
}

// Encodes the first `count` hashes; returns the byte length, or SIZE_MAX on overflow.
static size_t encode_first(const uint64_t *hashes, size_t count, uint8_t p, uint32_t m, uint8_t *out, size_t cap,
                           uint32_t *scratch)
{
    for (size_t i = 0; i < count; ++i) {
        scratch[i] = ah_gcs_bucket(hashes[i], m);
    }
    size_t n = count;
    sort_unique(scratch, &n);
    bit_writer_t w = {.out = out, .cap = cap, .bit = 0, .overflow = false};
    uint32_t prev = 0;
    for (size_t i = 0; i < n && !w.overflow; ++i) {
        const uint32_t x = scratch[i] - prev - 1u;
        prev = scratch[i];
        for (uint32_t q = x >> p; q > 0 && !w.overflow; --q) {
            write_bit(&w, 1);
        }
        write_bit(&w, 0);
        for (int b = (int)p - 1; b >= 0; --b) {
            write_bit(&w, (x >> b) & 1u);
        }
    }
    return w.overflow ? SIZE_MAX : (w.bit + 7u) / 8u;
}

bool ah_gcs_build(const uint64_t *hashes, size_t count, uint8_t *out, size_t cap, uint32_t *scratch,
                  ah_gcs_built_t *built)
{
    built->p = AH_GCS_P;
    built->m = 1;
    built->data_len = 0;
    built->included = 0;
    if (cap == 0) {
        return false;
    }
    if (count == 0) {
        return true;
    }
    size_t n = count;
    const size_t estimate = gcs_estimate(cap, AH_GCS_P);
    if (n > estimate) {
        n = estimate;
    }
    const uint64_t raw_m = (uint64_t)n << AH_GCS_P;
    built->m = raw_m > UINT32_MAX ? UINT32_MAX : (uint32_t)raw_m;

    size_t len = encode_first(hashes, n, AH_GCS_P, built->m, out, cap, scratch);
    while (len == SIZE_MAX && n > 1u) {
        n = (n * 9u) / 10u;
        if (n == 0) {
            n = 1;
        }
        len = encode_first(hashes, n, AH_GCS_P, built->m, out, cap, scratch);
    }
    if (len == SIZE_MAX) {
        return true;
    }
    built->data_len = len;
    built->included = n;
    return true;
}
