// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// A zero-copy view of one packet frame (PROTOCOLS section 2), and the few
// byte-level operations a relay performs on it.
//
// The node never re-encodes a packet it received. It forwards the frame it was
// handed with one byte changed (the TTL), tags a stored packet as a sync reply
// by changing two (TTL and the IS_RSR flag), and builds the signing preimage
// from the received bytes. Re-encoding would re-compress and re-pad, which
// changes the preimage and breaks the signature for every node downstream
// (PROTOCOLS section 2.2).
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ah_wire.h"

// Pointers alias the parsed buffer, which must outlive the view.
typedef struct {
    const uint8_t *bytes;     // start of the frame
    size_t len;               // canonical length: header through signature, no padding or trailing bytes
    uint8_t version;          // 1 or 2
    uint8_t type;
    uint8_t ttl;
    uint8_t flags;            // as received
    uint64_t timestamp_ms;
    const uint8_t *sender;    // AH_PEER_ID_LEN bytes
    const uint8_t *recipient; // AH_PEER_ID_LEN bytes, or NULL when the field is absent
    const uint8_t *route;     // route_count * 8 bytes, or NULL
    uint8_t route_count;
    bool route_field;         // v2 HAS_ROUTE with its count byte present (count may be 0)
    const uint8_t *payload;   // payload as carried: compressed bytes when compressed
    size_t payload_len;
    bool compressed;
    uint32_t original_size;   // declared decompressed size when compressed, else payload_len
    const uint8_t *signature; // AH_SIGNATURE_LEN bytes, or NULL
} ah_frame_t;

// Parse a frame as bitchat's BinaryProtocol.decode and Airhop's decoder
// accept one. Bytes past the computed frame end are ignored, so a padded frame
// decodes as it is: stripping the padding and parsing again, as both decoders
// do after a failure, can never succeed where this failed, since no check
// here passes on fewer bytes. Every length is checked against the buffer and
// against the type's payload ceiling (PROTOCOLS section 4) before anything is
// read: an uncompressed payload must fit the ceiling, and a compressed one
// must declare an original size from 1 byte to the ceiling and within
// AH_DEFLATE_MAX_RATIO of its compressed length. Pure; callable from any
// context. False when refused, the view then partly filled.
bool ah_frame_parse(const uint8_t *buf, size_t len, ah_frame_t *out);

// Broadcast in any of its three spellings: no recipient, all zeros, all 0xFF.
bool ah_frame_is_broadcast(const ah_frame_t *frame);

// Whether the recipient field names `peer_id`.
bool ah_frame_is_for(const ah_frame_t *frame, const uint8_t peer_id[AH_PEER_ID_LEN]);

// The next hop of a source route that names `self`: the next name in the
// route, or the recipient after the last one (PROTOCOLS section 2.3), with
// `*next` pointing into the frame.
//
// False for anything less than an unambiguous instruction to this node: no
// route, a v1 frame, a route not naming `self`, one naming it twice (a loop),
// or a broadcast after the last hop. The caller floods then, which heals
// around a bad hop where a guessed unicast would lose the packet.
bool ah_frame_next_hop(const ah_frame_t *frame, const uint8_t self[AH_PEER_ID_LEN], const uint8_t **next);

// Build the Ed25519 signing preimage from a received frame, as bitchat's
// toBinaryDataForSigning re-encodes it: TTL 0; IS_RSR, the signature flag and
// any flag outside the defined set cleared; no signature; the route flag
// cleared on a v1 frame, and an empty v2 route dropped with its flag; then
// PKCS#7-padded. The payload stays exactly as carried (PROTOCOLS section
// 2.2), so a packet compressed by any implementation verifies against what
// its author signed.
//
// Writes the preimage to `out` and its length to `*out_len`. False when `cap`
// is short of the unpadded preimage plus AH_PAD_MAX, so frame->len +
// AH_PAD_MAX always suffices.
bool ah_frame_signing_preimage(const ah_frame_t *frame, uint8_t *out, size_t cap, size_t *out_len);

// The smallest PKCS#7 block that holds `len` plus the AEAD allowance, or `len`
// itself when none does (PROTOCOLS section 2.1).
size_t ah_pad_target(size_t len);

// Append PKCS#7 padding in place up to ah_pad_target(len). Returns the new
// length, which stays `len` when no block fits, over 255 bytes would be
// needed, or `cap` is short.
size_t ah_pad(uint8_t *buf, size_t len, size_t cap);

// Whether a type's outbound frame is padded: the Noise handshake and transport
// frames, whose length would otherwise give away the plaintext's, as
// bitchat-ios BLEOutboundPacketPolicy.padsBLEFrame pads (PROTOCOLS section 2.1).
bool ah_frame_pads_on_air(uint8_t type);

// Fields of a packet this node originates.
typedef struct {
    uint8_t type;
    uint8_t ttl;
    uint64_t timestamp_ms;
    const uint8_t *sender;    // AH_PEER_ID_LEN
    const uint8_t *recipient; // AH_PEER_ID_LEN, or NULL for a broadcast
    const uint8_t *payload;   // uncompressed; the node never compresses what it originates
    size_t payload_len;
    bool is_rsr;
} ah_frame_fields_t;

// Encode a v2 frame without a signature, leaving room for one when
// `signed_frame` is set (the caller signs the preimage and writes the
// signature with ah_frame_attach_signature). The node originates uncompressed
// v2 frames, which every bitchat client decodes (PROTOCOLS section 2): it
// links no DEFLATE encoder at all, and its payloads are short control records
// that compression would barely shrink. Returns the encoded length, or 0 when
// `cap` is too small or the payload is over AH_CAP_FRAMED_FILE.
size_t ah_frame_encode(const ah_frame_fields_t *fields, bool signed_frame, uint8_t *out, size_t cap);

// Write a signature into the last 64 bytes of a frame from ah_frame_encode(signed_frame=true).
void ah_frame_attach_signature(uint8_t *frame, size_t len, const uint8_t signature[AH_SIGNATURE_LEN]);
