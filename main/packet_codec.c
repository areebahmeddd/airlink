#include "packet_codec.h"

#include "esp_log.h"
#include "esp_heap_caps.h"
#include <string.h>

#include "miniz.h"

#include "bitchat_ble.h"

static const char *TAG = "packet_codec";

/* Apple's COMPRESSION_ZLIB emits raw DEFLATE (RFC 1951, no zlib wrapper);
 * the ESP32-C3 ROM ships tinfl, so inflation costs no flash. */
static tinfl_decompressor s_inflator;

static uint8_t *inflate_payload(const uint8_t *in, size_t in_len, size_t out_len)
{
    uint8_t *out = heap_caps_malloc(out_len, MALLOC_CAP_8BIT);
    if (!out) {
        return NULL;
    }
    tinfl_init(&s_inflator);
    size_t consumed = in_len;
    size_t produced = out_len;
    tinfl_status status = tinfl_decompress(&s_inflator, in, &consumed, out, out, &produced,
                                           TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
    if (status != TINFL_STATUS_DONE || produced != out_len) {
        heap_caps_free(out);
        return NULL;
    }
    return out;
}

static uint8_t read_u8(const uint8_t *data, size_t len, size_t *offset, bool *ok)
{
    if (*offset + 1 > len) {
        *ok = false;
        return 0;
    }
    return data[(*offset)++];
}

static uint16_t read_u16_be(const uint8_t *data, size_t len, size_t *offset, bool *ok)
{
    if (*offset + 2 > len) {
        *ok = false;
        return 0;
    }
    uint16_t value = (data[*offset] << 8) | data[*offset + 1];
    *offset += 2;
    return value;
}

static uint64_t read_u64_be(const uint8_t *data, size_t len, size_t *offset, bool *ok)
{
    if (*offset + 8 > len) {
        *ok = false;
        return 0;
    }
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | data[*offset + i];
    }
    *offset += 8;
    return value;
}

/* Header flag bits (upstream BinaryProtocol.Flags; 0x10 is Bitle-private). */
#define FLAG_HAS_RECIPIENT  0x01
#define FLAG_HAS_SIGNATURE  0x02
#define FLAG_IS_COMPRESSED  0x04
#define FLAG_HAS_ROUTE      0x08
#define FLAG_IS_RSR         0x10

bool bitchat_packet_decode(const uint8_t *data, size_t len, bitchat_packet_t *out_packet)
{
    if (!data || !out_packet || len == 0) {
        return false;
    }
    memset(out_packet, 0, sizeof(*out_packet));
    size_t offset = 0;
    bool ok = true;

    out_packet->version = read_u8(data, len, &offset, &ok);
    out_packet->type = read_u8(data, len, &offset, &ok);
    out_packet->ttl = read_u8(data, len, &offset, &ok);
    out_packet->timestamp_ms = read_u64_be(data, len, &offset, &ok);
    uint8_t flags = read_u8(data, len, &offset, &ok);

    /* v1: 2-byte payload length; v2 (source routing): 4-byte payload length. */
    uint32_t payload_len = 0;
    if (ok && out_packet->version == 1) {
        payload_len = read_u16_be(data, len, &offset, &ok);
    } else if (ok && out_packet->version == 2) {
        if (offset + 4 > len) {
            ok = false;
        } else {
            payload_len = ((uint32_t)data[offset] << 24) | ((uint32_t)data[offset + 1] << 16) |
                          ((uint32_t)data[offset + 2] << 8) | data[offset + 3];
            offset += 4;
        }
    }

    if (!ok || (out_packet->version != 1 && out_packet->version != 2)) {
        ESP_LOGW(TAG, "Invalid packet header");
        return false;
    }

    if (offset + sizeof(out_packet->sender_id) > len) {
        ESP_LOGW(TAG, "Missing sender id bytes");
        return false;
    }
    memcpy(out_packet->sender_id, data + offset, sizeof(out_packet->sender_id));
    offset += 8;

    /* zlib-compressed payload (flag 0x04): we cannot inflate it locally, but
     * the header and raw bytes stay usable for time sync and relaying. */
    out_packet->is_compressed = (flags & FLAG_IS_COMPRESSED) != 0;
    out_packet->is_rsr = (flags & FLAG_IS_RSR) != 0;

    if (flags & FLAG_HAS_RECIPIENT) {
        out_packet->has_recipient = true;
        if (offset + sizeof(out_packet->recipient_id) > len) {
            ESP_LOGW(TAG, "Missing recipient id bytes");
            return false;
        }
        memcpy(out_packet->recipient_id, data + offset, sizeof(out_packet->recipient_id));
        offset += 8;
    }

    /* Source route (v2+, flag 0x08): 1-byte hop count + N*8 peer IDs, after
     * recipient, before payload. Longer routes than we can store are kept
     * marked-truncated so the relay floods instead of mis-forwarding. */
    if (out_packet->version >= 2 && (flags & FLAG_HAS_ROUTE)) {
        if (offset + 1 > len) {
            ESP_LOGW(TAG, "Missing route count byte");
            return false;
        }
        uint8_t count = data[offset++];
        if (count > 0) {
            if (offset + (size_t)count * 8 > len) {
                ESP_LOGW(TAG, "Route bytes exceed buffer");
                return false;
            }
            out_packet->has_route = true;
            out_packet->route_count = count < BITLE_ROUTE_MAX_HOPS ? count : BITLE_ROUTE_MAX_HOPS;
            out_packet->route_truncated = count > BITLE_ROUTE_MAX_HOPS;
            for (uint8_t i = 0; i < out_packet->route_count; ++i) {
                memcpy(out_packet->route[i], data + offset + (size_t)i * 8, 8);
            }
            offset += (size_t)count * 8;
        }
    }

    if (payload_len > len - offset) {
        ESP_LOGW(TAG, "Payload length exceeds buffer");
        return false;
    }

    if (payload_len > UINT16_MAX) {
        ESP_LOGW(TAG, "Payload too large");
        return false;
    }

    if (payload_len > 0) {
        out_packet->payload = heap_caps_malloc(payload_len, MALLOC_CAP_8BIT);
        if (!out_packet->payload) {
            ESP_LOGE(TAG, "Failed to allocate payload");
            return false;
        }
        memcpy(out_packet->payload, data + offset, payload_len);
    }
    out_packet->payload_len = (uint16_t)payload_len;
    offset += payload_len;

    /* Compressed payload: [original size BE][raw deflate], 2-byte size in v1,
     * 4-byte in v2. On success the packet becomes a normal one; on failure it
     * stays marked compressed and is handled relay-only. */
    size_t size_field = out_packet->version >= 2 ? 4 : 2;
    if (out_packet->is_compressed && payload_len > size_field) {
        uint32_t original_len = 0;
        for (size_t i = 0; i < size_field; ++i) {
            original_len = (original_len << 8) | out_packet->payload[i];
        }
        if (original_len > 0 && original_len <= UINT16_MAX) {
            uint8_t *inflated = inflate_payload(out_packet->payload + size_field,
                                                payload_len - size_field, original_len);
            if (inflated) {
                heap_caps_free(out_packet->payload);
                out_packet->payload = inflated;
                out_packet->payload_len = (uint16_t)original_len;
                out_packet->is_compressed = false;
            } else {
                ESP_LOGW(TAG, "Failed to inflate payload (%lu -> %lu)",
                         (unsigned long)payload_len, (unsigned long)original_len);
            }
        }
    }

    if (flags & FLAG_HAS_SIGNATURE) {
        out_packet->has_signature = true;
        if (offset + 64 > len) {
            ESP_LOGW(TAG, "Missing signature bytes");
            bitchat_packet_free(out_packet);
            return false;
        }
        memcpy(out_packet->signature, data + offset, 64);
        offset += 64;
    }

    return true;
}

bool bitchat_packet_encode(const bitchat_packet_t *packet, uint8_t *out_buf, size_t *out_len, size_t max_len)
{
    if (!packet || !out_buf || !out_len) {
        return false;
    }
    size_t offset = 0;

    /* A route forces version 2, like upstream applyRouteIfAvailable. */
    bool routed = packet->has_route && packet->route_count > 0;
    uint8_t version = routed && packet->version < 2 ? 2 : packet->version;
    bool v2 = version >= 2;
    uint8_t route_count = routed && v2 ? packet->route_count : 0;

    size_t header_len = 1 /*version*/ + 1 /*type*/ + 1 /*ttl*/ + 8 /*timestamp*/ + 1 /*flags*/
                        + (v2 ? 4 : 2) /*payload len*/ + 8 /*sender*/
                        + (packet->has_recipient ? 8 : 0)
                        + (route_count ? 1 + (size_t)route_count * 8 : 0);
    size_t total_len = header_len + packet->payload_len + (packet->has_signature ? 64 : 0);
    if (total_len > max_len) {
        return false;
    }

    out_buf[offset++] = version;
    out_buf[offset++] = packet->type;
    out_buf[offset++] = packet->ttl;

    for (int i = 7; i >= 0; --i) {
        out_buf[offset++] = (packet->timestamp_ms >> (i * 8)) & 0xFF;
    }

    uint8_t flags = 0;
    if (packet->has_recipient) {
        flags |= FLAG_HAS_RECIPIENT;
    }
    if (packet->has_signature) {
        flags |= FLAG_HAS_SIGNATURE;
    }
    if (route_count) {
        flags |= FLAG_HAS_ROUTE;
    }
    if (packet->is_rsr) {
        flags |= FLAG_IS_RSR;
    }
    out_buf[offset++] = flags;

    if (v2) {
        out_buf[offset++] = (packet->payload_len >> 24) & 0xFF;
        out_buf[offset++] = (packet->payload_len >> 16) & 0xFF;
    }
    out_buf[offset++] = (packet->payload_len >> 8) & 0xFF;
    out_buf[offset++] = packet->payload_len & 0xFF;

    memcpy(out_buf + offset, packet->sender_id, 8);
    offset += 8;

    if (packet->has_recipient) {
        memcpy(out_buf + offset, packet->recipient_id, 8);
        offset += 8;
    }

    if (route_count) {
        out_buf[offset++] = route_count;
        for (uint8_t i = 0; i < route_count; ++i) {
            memcpy(out_buf + offset, packet->route[i], 8);
            offset += 8;
        }
    }

    if (packet->payload_len > 0) {
        if (!packet->payload) {
            return false;
        }
        memcpy(out_buf + offset, packet->payload, packet->payload_len);
        offset += packet->payload_len;
    }

    if (packet->has_signature) {
        memcpy(out_buf + offset, packet->signature, 64);
        offset += 64;
    }

    *out_len = offset;
    return true;
}

void bitchat_packet_free(bitchat_packet_t *packet)
{
    if (packet->payload) {
        heap_caps_free(packet->payload);
    }
    memset(packet, 0, sizeof(*packet));
}

bool packet_codec_self_test(void)
{
    const uint8_t payload[] = {0x01, 0x02, 0x03, 0x04};
    const uint8_t recipient[8] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    const uint8_t signature[64] = {
        0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1,
        0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9,
        0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1,
        0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9,
        0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1,
        0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9,
        0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1,
        0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9,
    };

    bitchat_packet_t packet = {0};
    packet.version = 1;
    packet.type = BITCHAT_MSG_NOISE_ENCRYPTED;
    packet.ttl = 7;
    packet.timestamp_ms = 0x0102030405060708ULL;
    memcpy(packet.sender_id, (uint8_t[]){0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27}, sizeof(packet.sender_id));
    memcpy(packet.recipient_id, recipient, sizeof(packet.recipient_id));
    packet.has_recipient = true;
    packet.payload = (uint8_t *)payload;
    packet.payload_len = sizeof(payload);
    memcpy(packet.signature, signature, sizeof(packet.signature));
    packet.has_signature = true;

    uint8_t encoded[BITCHAT_BLE_MAX_PACKET_SIZE];
    size_t encoded_len = sizeof(encoded);
    if (!bitchat_packet_encode(&packet, encoded, &encoded_len, sizeof(encoded))) {
        return false;
    }

    bitchat_packet_t decoded;
    if (!bitchat_packet_decode(encoded, encoded_len, &decoded)) {
        return false;
    }

    bool ok = decoded.version == packet.version &&
              decoded.type == packet.type &&
              decoded.ttl == packet.ttl &&
              decoded.timestamp_ms == packet.timestamp_ms &&
              decoded.has_recipient == packet.has_recipient &&
              decoded.payload_len == packet.payload_len &&
              decoded.has_signature == packet.has_signature &&
              memcmp(decoded.sender_id, packet.sender_id, sizeof(packet.sender_id)) == 0 &&
              memcmp(decoded.recipient_id, packet.recipient_id, sizeof(packet.recipient_id)) == 0 &&
              memcmp(decoded.payload, packet.payload, packet.payload_len) == 0 &&
              memcmp(decoded.signature, packet.signature, sizeof(packet.signature)) == 0;

    bitchat_packet_free(&decoded);
    if (!ok) {
        return false;
    }

    /* v2 source-route round trip: route survives encode/decode byte-exact. */
    bitchat_packet_t routed = {0};
    routed.version = 2;
    routed.type = BITCHAT_MSG_NOISE_ENCRYPTED;
    routed.ttl = 5;
    routed.timestamp_ms = packet.timestamp_ms;
    memcpy(routed.sender_id, packet.sender_id, sizeof(routed.sender_id));
    memcpy(routed.recipient_id, recipient, sizeof(routed.recipient_id));
    routed.has_recipient = true;
    routed.has_route = true;
    routed.route_count = 2;
    memcpy(routed.route[0], (uint8_t[]){0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37}, 8);
    memcpy(routed.route[1], (uint8_t[]){0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47}, 8);
    routed.payload = (uint8_t *)payload;
    routed.payload_len = sizeof(payload);
    memcpy(routed.signature, signature, sizeof(routed.signature));
    routed.has_signature = true;

    encoded_len = sizeof(encoded);
    if (!bitchat_packet_encode(&routed, encoded, &encoded_len, sizeof(encoded))) {
        return false;
    }
    bitchat_packet_t decoded_routed;
    if (!bitchat_packet_decode(encoded, encoded_len, &decoded_routed)) {
        return false;
    }
    ok = decoded_routed.version == 2 &&
         decoded_routed.has_route && !decoded_routed.route_truncated &&
         decoded_routed.route_count == 2 &&
         memcmp(decoded_routed.route[0], routed.route[0], 8) == 0 &&
         memcmp(decoded_routed.route[1], routed.route[1], 8) == 0 &&
         decoded_routed.ttl == routed.ttl &&
         decoded_routed.payload_len == routed.payload_len &&
         memcmp(decoded_routed.payload, routed.payload, routed.payload_len) == 0 &&
         decoded_routed.has_signature &&
         memcmp(decoded_routed.signature, routed.signature, 64) == 0;
    bitchat_packet_free(&decoded_routed);
    return ok;
}

