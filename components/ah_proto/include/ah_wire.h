// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The protocol's constants, grouped by the section of Airhop's
// docs/spec/PROTOCOLS.md that states them: the contract this firmware honors,
// with bitchat-ios the reference behind it. Layouts PROTOCOLS leaves to
// bitchat-ios or docs/OTA.md (a board post's TLVs, a live video packet's
// bounds, the OTA manifest) stay in their codecs. Key and signature sizes
// come from ah_crypto.h.
#pragma once

#include <assert.h>
#include <stdint.h>

#include "ah_crypto.h"

// ---- Section 1: BLE identifiers ----

// F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C and A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D,
// little-endian as NimBLE's BLE_UUID128_INIT takes them. Changing either
// partitions the mesh.
#define AH_BLE_SERVICE_UUID128 \
    0x5c, 0x4b, 0x3a, 0x2c, 0x1d, 0x8e, 0x3f, 0x9b, 0x5a, 0x4c, 0x9e, 0x4a, 0x2d, 0x5e, 0x7b, 0xf4
#define AH_BLE_CHARACTERISTIC_UUID128 \
    0x5d, 0x4c, 0x3b, 0x2a, 0x1f, 0x0e, 0x9d, 0x8c, 0x5b, 0x4a, 0xf6, 0xe5, 0xd4, 0xc3, 0xb2, 0xa1

// ---- Section 2: packet frame ----

enum {
    AH_VERSION_1 = 1,
    AH_VERSION_2 = 2,
};

#define AH_V1_HEADER_LEN 14u
#define AH_V2_HEADER_LEN 16u
#define AH_PEER_ID_LEN 8u
#define AH_PACKET_ID_LEN 16u

// Fixed-header offsets, identical in v1 and v2 up to the length field.
#define AH_OFF_VERSION 0u
#define AH_OFF_TYPE 1u
#define AH_OFF_TTL 2u
#define AH_OFF_TIMESTAMP 3u
#define AH_OFF_FLAGS 11u
#define AH_OFF_LENGTH 12u

// Shortest decodable frame: the v1 header plus a sender ID.
#define AH_MIN_FRAME_LEN (AH_V1_HEADER_LEN + AH_PEER_ID_LEN)

enum {
    AH_FLAG_HAS_RECIPIENT = 0x01,
    AH_FLAG_HAS_SIGNATURE = 0x02,
    AH_FLAG_IS_COMPRESSED = 0x04,
    AH_FLAG_HAS_ROUTE = 0x08,
    AH_FLAG_IS_RSR = 0x10,
};

// Section 2.1: PKCS#7 blocks. A frame is padded to the smallest block that
// holds it plus 16 bytes, and left alone when that would need over 255 bytes.
#define AH_PAD_OVERHEAD 16u
#define AH_PAD_MAX 255u
#define AH_PAD_BLOCK_MAX 2048u

// Section 2.2 and bitchat-ios PacketPayloadLimits.maxDeflateRatio: a declared
// size beyond this multiple of the compressed bytes cannot be a real DEFLATE
// stream (a 258-byte match costs at least two bits).
#define AH_DEFLATE_MAX_RATIO 1032u

// bitchat-ios Constants.compressionThresholdBytes. bitchat-ios rebuilds a
// signing preimage by re-encoding the packet, which compresses a payload of
// this many bytes or more whenever DEFLATE shrinks it, while the node signs
// its payloads uncompressed. So a payload the node signs stays under this or
// is one DEFLATE cannot shrink, or bitchat-ios refuses its signature. Only
// the announce could cross (AH_NICKNAME_MAX); sync filters, sealed DMs and
// courier ciphertext are already at their entropy.
#define AH_COMPRESS_THRESHOLD 100u

// Section 3.4: the whole encoded frame must fit one ATT attribute value.
#define AH_BLE_FRAME_MAX 512u

// Section 4: an announce, a directed packet and the default all leave at 7.
#define AH_TTL_DEFAULT 7u

// ---- Section 3: packet types ----

typedef enum {
    AH_TYPE_ANNOUNCE = 0x01,
    AH_TYPE_CHANNEL_MSG = 0x02,
    AH_TYPE_LEAVE = 0x03,
    AH_TYPE_COURIER_ENV = 0x04,
    AH_TYPE_NOISE_HANDSHAKE = 0x10,
    AH_TYPE_NOISE_ENCRYPTED = 0x11,
    AH_TYPE_DR_ENCRYPTED = 0x12,
    AH_TYPE_FRAGMENT = 0x20,
    AH_TYPE_REQUEST_SYNC = 0x21,
    AH_TYPE_FILE_TRANSFER = 0x22,
    AH_TYPE_BOARD_POST = 0x23,
    AH_TYPE_PREKEY_BUNDLE = 0x24,
    AH_TYPE_GROUP_MESSAGE = 0x25,
    AH_TYPE_PING = 0x26,
    AH_TYPE_PONG = 0x27,
    AH_TYPE_NOSTR_CARRIER = 0x28,
    AH_TYPE_VOICE_FRAME = 0x29,
    AH_TYPE_ANNOUNCE_V2 = 0x2C,
    AH_TYPE_VIDEO_FRAME = 0x2D,
    AH_TYPE_CHANNEL_ENC = 0x50,
    AH_TYPE_CHANNEL_MSG_AIRHOP = 0x51,
    // Relay firmware's own range, registered in PROTOCOLS section 3 so no client takes it.
    // Link-local between nodes only: TTL 0, never relayed.
    AH_TYPE_OTA_MANIFEST = 0xA0,
    AH_TYPE_OTA_REQUEST = 0xA1,
    AH_TYPE_OTA_CHUNK = 0xA2,
    AH_TYPE_OTA_STATUS = 0xA3,
} ah_packet_type_t;

// Per-type ceilings on the declared and the decompressed payload, as
// bitchat-ios PacketPayloadLimits (PROTOCOLS section 4, "Max payload length").
#define AH_CAP_FRAGMENT 1280u
#define AH_CAP_CONTROL (4u * 1024u)
#define AH_CAP_REQUEST_SYNC (8u * 1024u)
#define AH_CAP_ENVELOPE (64u * 1024u)
#define AH_CAP_TWICE_V1 (128u * 1024u)
// bitchat-ios FileTransferLimits.maxFramedFileBytes: 1 MiB of content plus the
// TLV and binary envelopes.
#define AH_CAP_FRAMED_FILE 1179760u

// ---- Section 3.4: fragments ----

// [stream ID 8][index u16][total u16][inner type u8]
#define AH_FRAGMENT_STREAM_ID_LEN 8u
#define AH_FRAGMENT_HEADER_LEN (AH_FRAGMENT_STREAM_ID_LEN + 2u + 2u + 1u)
#define AH_FRAGMENT_MIN_CHUNK 64u
#define AH_FRAGMENT_MAX_TOTAL 10000u

// ---- Section 3.5 and 10.1: announce TLVs ----

enum {
    AH_ANNOUNCE_TLV_NICKNAME = 0x01,
    AH_ANNOUNCE_TLV_NOISE_KEY = 0x02,
    AH_ANNOUNCE_TLV_SIGNING_KEY = 0x03,
    AH_ANNOUNCE_TLV_NEIGHBORS = 0x04, // never emitted (PROTOCOLS section 2.3)
    AH_ANNOUNCE_TLV_FIRMWARE = 0xB0,
    AH_ANNOUNCE_TLV_RELAY_FLAGS = 0xB1,
};

// The longest nickname the node announces: its announce, with both keys and
// the 0xB0 and 0xB1 TLVs, is then 99 bytes, under AH_COMPRESS_THRESHOLD.
#define AH_NICKNAME_MAX 20u
// 0xB1 bit 0: a dedicated relay, drawn as equipment by Airhop. Anyone can
// claim it (PROTOCOLS section 10.1), so it only ever restricts: a LoRa link
// binds only to a node, and a node is a clock voice only while no phone's is
// fresh. The other bits are reserved, never set and never read.
#define AH_RELAY_FLAG_DEDICATED 0x01u

// ---- Section 4: routing ----

// Six or more direct neighbors make a dense graph, where relay caps and
// announce pacing tighten.
#define AH_DEGREE_DENSE 6u

// Section 5.1: a packet dated further than this from the receiver's clock is
// refused. Once the node's clock is confirmed an announce gets 15 minutes,
// where the phones hold it to 2 as well (PROTOCOLS section 10), so a phone a
// few minutes off still binds and gets its mail and sync. A replay inside it
// refreshes its peer and at most sends its mail on, once in ten minutes.
#define AH_MAX_SKEW_MS (2LL * 60 * 1000)
#define AH_ANNOUNCE_MAX_SKEW_MS (15LL * 60 * 1000)
// Sections 3 and 3.6: a live frame older than this is refused before relay.
#define AH_LIVE_MAX_AGE_MS (30LL * 1000)
// Section 4: a live write still queued after this is dropped unsent.
#define AH_LIVE_WRITE_DEADLINE_MS 1500u

// ---- Section 5: gossip sync ----

enum {
    AH_SYNC_TLV_P = 0x01,
    AH_SYNC_TLV_M = 0x02,
    AH_SYNC_TLV_DATA = 0x03,
    AH_SYNC_TLV_TYPES = 0x04,
    AH_SYNC_TLV_SINCE = 0x05,
};

enum {
    AH_SYNC_BIT_ANNOUNCE = 0,
    AH_SYNC_BIT_MESSAGE = 1,
    AH_SYNC_BIT_BOARD = 8,
    AH_SYNC_BIT_GROUP = 10,
    AH_SYNC_BIT_CHANNEL_AIRHOP = 24,
};

#define AH_GCS_P 7u
#define AH_GCS_P_MAX 32u
#define AH_GCS_MAX_BYTES 400u
#define AH_SYNC_ANNOUNCE_MAX_AGE_MS (60LL * 1000)
#define AH_SYNC_MESSAGE_MAX_AGE_MS (6LL * 60 * 60 * 1000)
#define AH_SYNC_BOARD_MAX_AGE_MS (7LL * 24 * 60 * 60 * 1000)
#define AH_SYNC_RESPONSES_PER_WINDOW 8u
#define AH_SYNC_RESPONSE_WINDOW_MS 30000u
#define AH_SYNC_PENDING_REQUEST_MS 30000u
#define AH_SYNC_ROUND_MS 15000u
#define AH_SYNC_BOARD_EVERY_ROUNDS 4u
#define AH_SYNC_FIRST_ROUND_DELAY_MS 1000u

// ---- Section 6: courier ----

enum {
    AH_COURIER_TLV_TAG = 0x01,
    AH_COURIER_TLV_EXPIRY = 0x02,
    AH_COURIER_TLV_CIPHERTEXT = 0x03,
    AH_COURIER_TLV_COPIES = 0x04,
    AH_COURIER_TLV_PREKEY_ID = 0x05,
};

#define AH_COURIER_TAG_LEN 16u
#define AH_COURIER_LIFETIME_MS (24LL * 60 * 60 * 1000)
#define AH_COURIER_EXPIRY_SLACK_MS (60LL * 60 * 1000)
#define AH_COURIER_MAX_CIPHERTEXT (16u * 1024u)
#define AH_COURIER_MAX_COPIES 8u
#define AH_COURIER_REMOTE_COOLDOWN_MS (10LL * 60 * 1000)

// ---- Board posts (bitchat-ios BoardPackets) ----

#define AH_BOARD_MAX_LIFETIME_MS (7LL * 24 * 60 * 60 * 1000)
#define AH_BOARD_CLOCK_SKEW_MS (60LL * 60 * 1000)

static_assert(AH_V2_HEADER_LEN == AH_V1_HEADER_LEN + 2, "v2 widens only the length field");
static_assert(AH_FRAGMENT_HEADER_LEN == 13u, "PROTOCOLS section 3.4: a 13-byte fragment header");
static_assert(AH_V2_HEADER_LEN + 2 * AH_PEER_ID_LEN + AH_FRAGMENT_HEADER_LEN + 467u == AH_BLE_FRAME_MAX,
              "PROTOCOLS section 3.4: 467 data bytes per fragment");
