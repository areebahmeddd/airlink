// SPDX-FileCopyrightText: 2026 Areeb Ahmed
// SPDX-License-Identifier: MIT

// The few payloads the node reads or writes for a peer that talks to it
// directly: the typed Noise plaintext and its private message (PROTOCOLS
// section 3.3), and the mesh ping (bitchat MeshPingPayload).
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// The first byte of a Noise transport plaintext: the two types the node reads or writes.
enum {
    AH_NOISE_PAYLOAD_PRIVATE_MESSAGE = 0x01,
    AH_NOISE_PAYLOAD_DELIVERED = 0x03,
};

#define AH_PING_NONCE_LEN 8u
#define AH_PING_LEN (AH_PING_NONCE_LEN + 1u)

typedef struct {
    const uint8_t *message_id;
    uint8_t message_id_len;
    const uint8_t *content;
    uint8_t content_len;
} ah_private_message_t;

// PrivateMessagePacket: 0x00 len messageID, 0x01 len content, one-byte
// lengths. A TLV of any other type refuses it, as Airhop and bitchat-ios
// refuse it; one trailing byte is ignored.
bool ah_private_message_decode(const uint8_t *body, size_t len, ah_private_message_t *out);

// Encode a typed Noise plaintext carrying a private message, 0x01 || 0x00 len
// id || 0x01 len content. Returns bytes written, or 0 when a field is over 255
// bytes or `cap` is short.
size_t ah_private_message_encode(const uint8_t *message_id, size_t id_len, const uint8_t *content, size_t content_len,
                                 uint8_t *out, size_t cap);

// Encode a typed Noise plaintext of DELIVERED for `message_id`, 0x03 || id.
// Returns bytes written, or 0 when `cap` is short.
size_t ah_delivered_encode(const uint8_t *message_id, size_t id_len, uint8_t *out, size_t cap);
