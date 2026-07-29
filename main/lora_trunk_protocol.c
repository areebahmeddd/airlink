#include "lora_trunk_protocol.h"
#include "lora_channel_policy.h"

#include <string.h>

#define V2_FLAG_ACK 0x01u
#define V2_FLAG_ACK_REQUESTED 0x02u
#define V2_FLAG_MASK (V2_FLAG_ACK | V2_FLAG_ACK_REQUESTED)
#define V3_FLAG_MASK \
    (LORA_TRUNK_V3_FLAG_ACK_REQUESTED | LORA_TRUNK_V3_FLAG_BROADCAST)

static bool all_zero(const uint8_t *value, size_t len)
{
    uint8_t combined = 0;
    for (size_t i = 0; i < len; ++i) {
        combined |= value[i];
    }
    return combined == 0;
}

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static void write_be16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static uint16_t crc16_ccitt_false(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= (uint16_t)data[i] << 8;
        for (unsigned bit = 0; bit < 8; ++bit) {
            crc = (crc & 0x8000u) != 0
                      ? (uint16_t)((crc << 1) ^ 0x1021u)
                      : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

static bool fragment_valid(uint8_t index, uint8_t total)
{
    return total > 0 && total <= LORA_TRUNK_MAX_FRAGMENTS && index < total;
}

static bool v3_semantics_valid(const lora_trunk_frame_t *frame)
{
    if (!frame || frame->version != LORA_TRUNK_V3_VERSION ||
        (frame->flags & ~V3_FLAG_MASK) != 0 ||
        all_zero(frame->source, sizeof(frame->source)) ||
        all_zero(frame->transfer_id, sizeof(frame->transfer_id)) ||
        frame->payload_len > LORA_TRUNK_V3_MAX_PAYLOAD ||
        frame->hop_count > frame->hop_limit) {
        return false;
    }

    bool destination_zero =
        all_zero(frame->destination, sizeof(frame->destination));
    bool broadcast = (frame->flags & LORA_TRUNK_V3_FLAG_BROADCAST) != 0;
    bool ack_requested =
        (frame->flags & LORA_TRUNK_V3_FLAG_ACK_REQUESTED) != 0;

    if (frame->kind == LORA_TRUNK_KIND_DATA) {
        if (frame->fragment_total == 0 ||
            frame->fragment_total > LORA_TRUNK_MAX_FRAGMENTS) {
            return false;
        }
        if (frame->payload_len == 0 || !frame->payload) {
            return false;
        }
        if (!fragment_valid(
                frame->fragment_index, frame->fragment_total)) {
            return false;
        }
        if (broadcast != destination_zero || (broadcast && ack_requested)) {
            return false;
        }
        return true;
    }
    if (frame->kind == LORA_TRUNK_KIND_BEACON) {
        return frame->flags == LORA_TRUNK_V3_FLAG_BROADCAST &&
               destination_zero && !ack_requested &&
               frame->capabilities != 0 &&
               frame->hop_limit < LORA_TRUNK_BEACON_REGION_COUNT &&
               frame->hop_count == 0 &&
               frame->fragment_index == 0 &&
               frame->fragment_total == 0 &&
               frame->payload_len == 0 && !frame->payload;
    }
    if (frame->fragment_total == 0 ||
        frame->fragment_total > LORA_TRUNK_MAX_FRAGMENTS) {
        return false;
    }
    bool control_base =
        frame->flags == 0 && frame->payload_len == 0 &&
        !frame->payload && !destination_zero &&
        frame->hop_limit == 0 && frame->hop_count == 0;
    if (!control_base) {
        return false;
    }
    uint8_t wanted =
        (uint8_t)((1u << frame->fragment_total) - 1u);
    if (frame->kind == LORA_TRUNK_KIND_BITMAP_ACK) {
        return frame->fragment_index != 0 &&
               (frame->fragment_index & ~wanted) == 0;
    }
    if (frame->kind == LORA_TRUNK_KIND_COMPLETE) {
        return frame->fragment_index == wanted;
    }
    if (frame->kind == LORA_TRUNK_KIND_ABORT) {
        return frame->fragment_index >=
                   LORA_TRUNK_ABORT_RETRY_EXHAUSTED &&
               frame->fragment_index <=
                   LORA_TRUNK_ABORT_RADIO_RESET;
    }
    return false;
}

static lora_trunk_parse_result_t parse_v2(
    const uint8_t *data, size_t len, lora_trunk_frame_t *out)
{
    if (len < LORA_TRUNK_V2_HEADER_LEN ||
        (data[3] & ~V2_FLAG_MASK) != 0 ||
        (data[3] & V2_FLAG_MASK) == V2_FLAG_MASK) {
        return LORA_TRUNK_PARSE_MALFORMED;
    }

    bool is_ack = (data[3] & V2_FLAG_ACK) != 0;
    uint8_t index = data[14];
    uint8_t total = data[15];
    size_t payload_len = len - LORA_TRUNK_V2_HEADER_LEN;
    if (!fragment_valid(index, total) || all_zero(data + 4, 4) ||
        (is_ack && (payload_len != 0 || all_zero(data + 8, 4))) ||
        (!is_ack && payload_len == 0)) {
        return LORA_TRUNK_PARSE_MALFORMED;
    }

    out->version = LORA_TRUNK_V2_VERSION;
    out->kind = is_ack ? LORA_TRUNK_KIND_BITMAP_ACK
                       : LORA_TRUNK_KIND_DATA;
    out->flags = (data[3] & V2_FLAG_ACK_REQUESTED) != 0
                     ? LORA_TRUNK_V3_FLAG_ACK_REQUESTED
                     : 0;
    memcpy(out->source, data + 4, 4);
    memcpy(out->destination, data + 8, 4);
    out->transfer_id[10] = data[12];
    out->transfer_id[11] = data[13];
    out->fragment_index = index;
    out->fragment_total = total;
    out->payload = payload_len != 0
                       ? data + LORA_TRUNK_V2_HEADER_LEN
                       : NULL;
    out->payload_len = (uint16_t)payload_len;
    return LORA_TRUNK_PARSE_OK;
}

static lora_trunk_parse_result_t parse_v3(
    const uint8_t *data, size_t len, lora_trunk_frame_t *out)
{
    if (len < LORA_TRUNK_V3_HEADER_LEN ||
        data[5] != LORA_TRUNK_V3_HEADER_LEN) {
        return LORA_TRUNK_PARSE_MALFORMED;
    }
    uint16_t payload_len = read_be16(data + 10);
    if (payload_len > LORA_TRUNK_V3_MAX_PAYLOAD ||
        len != (size_t)LORA_TRUNK_V3_HEADER_LEN + payload_len ||
        read_be16(data + 42) != crc16_ccitt_false(data, 42)) {
        return LORA_TRUNK_PARSE_MALFORMED;
    }

    out->version = LORA_TRUNK_V3_VERSION;
    out->kind = (lora_trunk_kind_t)data[3];
    out->flags = data[4];
    out->capabilities = read_be16(data + 6);
    out->hop_limit = data[8];
    out->hop_count = data[9];
    memcpy(out->source, data + 12, sizeof(out->source));
    memcpy(out->destination, data + 20, sizeof(out->destination));
    memcpy(out->transfer_id, data + 28, sizeof(out->transfer_id));
    out->fragment_index = data[40];
    out->fragment_total = data[41];
    out->payload =
        payload_len != 0 ? data + LORA_TRUNK_V3_HEADER_LEN : NULL;
    out->payload_len = payload_len;

    return v3_semantics_valid(out) ? LORA_TRUNK_PARSE_OK
                                   : LORA_TRUNK_PARSE_MALFORMED;
}

lora_trunk_parse_result_t lora_trunk_parse(
    const uint8_t *data, size_t len, lora_trunk_frame_t *out)
{
    if (!data || !out || len < 3) {
        return LORA_TRUNK_PARSE_MALFORMED;
    }
    memset(out, 0, sizeof(*out));
    if (data[0] != LORA_TRUNK_MAGIC0 || data[1] != LORA_TRUNK_MAGIC1) {
        return LORA_TRUNK_PARSE_FOREIGN;
    }
    if (data[2] == LORA_TRUNK_V2_VERSION) {
        return parse_v2(data, len, out);
    }
    if (data[2] == LORA_TRUNK_V3_VERSION) {
        return parse_v3(data, len, out);
    }
    return LORA_TRUNK_PARSE_UNSUPPORTED_VERSION;
}

bool lora_trunk_v3_encode(
    const lora_trunk_frame_t *frame, uint8_t *out, size_t capacity,
    size_t *out_len)
{
    if (!out || !out_len || !v3_semantics_valid(frame)) {
        return false;
    }
    size_t total_len = LORA_TRUNK_V3_HEADER_LEN + frame->payload_len;
    if (capacity < total_len) {
        return false;
    }

    memset(out, 0, LORA_TRUNK_V3_HEADER_LEN);
    out[0] = LORA_TRUNK_MAGIC0;
    out[1] = LORA_TRUNK_MAGIC1;
    out[2] = LORA_TRUNK_V3_VERSION;
    out[3] = (uint8_t)frame->kind;
    out[4] = frame->flags;
    out[5] = LORA_TRUNK_V3_HEADER_LEN;
    write_be16(out + 6, frame->capabilities);
    out[8] = frame->hop_limit;
    out[9] = frame->hop_count;
    write_be16(out + 10, frame->payload_len);
    memcpy(out + 12, frame->source, sizeof(frame->source));
    memcpy(out + 20, frame->destination, sizeof(frame->destination));
    memcpy(out + 28, frame->transfer_id, sizeof(frame->transfer_id));
    out[40] = frame->fragment_index;
    out[41] = frame->fragment_total;
    write_be16(out + 42, crc16_ccitt_false(out, 42));
    if (frame->payload_len != 0) {
        memcpy(out + LORA_TRUNK_V3_HEADER_LEN, frame->payload,
               frame->payload_len);
    }
    *out_len = total_len;
    return true;
}

bool lora_trunk_v3_control_matches(
    const lora_trunk_frame_t *data,
    const lora_trunk_frame_t *control)
{
    return data && control &&
           data->version == LORA_TRUNK_V3_VERSION &&
           control->version == LORA_TRUNK_V3_VERSION &&
           data->kind == LORA_TRUNK_KIND_DATA &&
           (control->kind == LORA_TRUNK_KIND_BITMAP_ACK ||
            control->kind == LORA_TRUNK_KIND_COMPLETE ||
            control->kind == LORA_TRUNK_KIND_ABORT) &&
           (data->flags & LORA_TRUNK_V3_FLAG_ACK_REQUESTED) != 0 &&
           memcmp(control->source, data->destination,
                  LORA_TRUNK_V3_NODE_ID_LEN) == 0 &&
           memcmp(control->destination, data->source,
                  LORA_TRUNK_V3_NODE_ID_LEN) == 0 &&
           memcmp(control->transfer_id, data->transfer_id,
                  LORA_TRUNK_V3_TRANSFER_ID_LEN) == 0 &&
           control->fragment_total == data->fragment_total;
}

void lora_trunk_make_transfer_id(
    const uint8_t boot_epoch[8], uint32_t counter,
    uint8_t out[LORA_TRUNK_V3_TRANSFER_ID_LEN])
{
    memcpy(out, boot_epoch, 8);
    out[8] = (uint8_t)(counter >> 24);
    out[9] = (uint8_t)(counter >> 16);
    out[10] = (uint8_t)(counter >> 8);
    out[11] = (uint8_t)counter;
}

bool lora_trunk_beacon_init(
    lora_trunk_frame_t *frame,
    const uint8_t node_id[LORA_TRUNK_V3_NODE_ID_LEN],
    const uint8_t boot_epoch[8], uint32_t freshness,
    uint8_t region, uint16_t capabilities)
{
    if (!frame || !node_id || !boot_epoch ||
        all_zero(boot_epoch, 8) || freshness == 0 ||
        region >= LORA_TRUNK_BEACON_REGION_COUNT || capabilities == 0) {
        return false;
    }
    memset(frame, 0, sizeof(*frame));
    frame->version = LORA_TRUNK_V3_VERSION;
    frame->kind = LORA_TRUNK_KIND_BEACON;
    frame->flags = LORA_TRUNK_V3_FLAG_BROADCAST;
    frame->capabilities = capabilities;
    frame->hop_limit = region;
    memcpy(frame->source, node_id, sizeof(frame->source));
    lora_trunk_make_transfer_id(
        boot_epoch, freshness, frame->transfer_id);
    return v3_semantics_valid(frame);
}

bool lora_trunk_beacon_fields(
    const lora_trunk_frame_t *frame, uint8_t *out_region,
    uint32_t *out_freshness)
{
    if (!out_region || !out_freshness ||
        !v3_semantics_valid(frame) ||
        frame->kind != LORA_TRUNK_KIND_BEACON) {
        return false;
    }
    *out_region = frame->hop_limit;
    *out_freshness = read_be32(frame->transfer_id + 8);
    return *out_freshness != 0;
}

void lora_trunk_neighbor_table_init(lora_trunk_neighbor_table_t *table)
{
    if (table) {
        memset(table, 0, sizeof(*table));
    }
}

lora_trunk_neighbor_result_t lora_trunk_neighbor_learn_beacon(
    lora_trunk_neighbor_table_t *table,
    const uint8_t node_id[LORA_TRUNK_V3_NODE_ID_LEN],
    const uint8_t boot_epoch[8], uint32_t freshness,
    uint8_t region, uint16_t capabilities, uint64_t now_ms)
{
    if (!table || !node_id || !boot_epoch ||
        all_zero(node_id, LORA_TRUNK_V3_NODE_ID_LEN) ||
        all_zero(boot_epoch, 8) || freshness == 0 ||
        region >= LORA_TRUNK_BEACON_REGION_COUNT || capabilities == 0) {
        return LORA_TRUNK_NEIGHBOR_COLLISION;
    }

    lora_trunk_neighbor_t *same_node = NULL;
    lora_trunk_neighbor_t *free_entry = NULL;
    lora_trunk_neighbor_t *oldest = NULL;
    for (size_t i = 0; i < LORA_TRUNK_NEIGHBOR_CAPACITY; ++i) {
        lora_trunk_neighbor_t *entry = &table->entries[i];
        if (!entry->in_use) {
            if (!free_entry) {
                free_entry = entry;
            }
            continue;
        }
        if (memcmp(entry->node_id, node_id,
                   LORA_TRUNK_V3_NODE_ID_LEN) == 0) {
            same_node = entry;
        }
        if (!entry->quarantined &&
            (!oldest || entry->last_seen_ms < oldest->last_seen_ms)) {
            oldest = entry;
        }
    }

    if (same_node) {
        if (same_node->quarantined) {
            return LORA_TRUNK_NEIGHBOR_COLLISION;
        }
        bool same_boot =
            memcmp(same_node->boot_epoch, boot_epoch, 8) == 0;
        if (same_boot &&
            !lora_freshness_newer(
                freshness, same_node->freshness)) {
            return LORA_TRUNK_NEIGHBOR_STALE;
        }
        memcpy(same_node->boot_epoch, boot_epoch, 8);
        same_node->freshness = freshness;
        same_node->region = region;
        same_node->capabilities = capabilities;
        same_node->last_seen_ms = now_ms;
        return LORA_TRUNK_NEIGHBOR_REFRESHED;
    }

    lora_trunk_neighbor_t *entry = free_entry ? free_entry : oldest;
    if (!entry) {
        return LORA_TRUNK_NEIGHBOR_COLLISION;
    }
    lora_trunk_neighbor_result_t result =
        free_entry ? LORA_TRUNK_NEIGHBOR_LEARNED
                   : LORA_TRUNK_NEIGHBOR_EVICTED;
    memset(entry, 0, sizeof(*entry));
    entry->in_use = true;
    memcpy(entry->node_id, node_id, LORA_TRUNK_V3_NODE_ID_LEN);
    memcpy(entry->boot_epoch, boot_epoch, 8);
    entry->freshness = freshness;
    entry->region = region;
    entry->capabilities = capabilities;
    entry->last_seen_ms = now_ms;
    return result;
}

lora_trunk_neighbor_result_t lora_trunk_neighbor_learn_authenticated(
    lora_trunk_neighbor_table_t *table,
    const uint8_t node_id[LORA_TRUNK_V3_NODE_ID_LEN],
    const uint8_t reachable_peer[LORA_TRUNK_V3_NODE_ID_LEN],
    const uint8_t signing_key[LORA_TRUNK_SIGNING_KEY_LEN],
    uint16_t capabilities, uint64_t now_ms)
{
    if (!table || !node_id || !reachable_peer || !signing_key ||
        all_zero(node_id, LORA_TRUNK_V3_NODE_ID_LEN) ||
        all_zero(reachable_peer, LORA_TRUNK_V3_NODE_ID_LEN) ||
        all_zero(signing_key, LORA_TRUNK_SIGNING_KEY_LEN)) {
        return LORA_TRUNK_NEIGHBOR_COLLISION;
    }

    lora_trunk_neighbor_t *free_entry = NULL;
    lora_trunk_neighbor_t *oldest = NULL;
    lora_trunk_neighbor_t *same_route = NULL;
    lora_trunk_neighbor_t *unauthenticated_node = NULL;
    bool collision = false;
    for (size_t i = 0; i < LORA_TRUNK_NEIGHBOR_CAPACITY; ++i) {
        lora_trunk_neighbor_t *entry = &table->entries[i];
        if (!entry->in_use) {
            if (!free_entry) {
                free_entry = entry;
            }
            continue;
        }
        if (!entry->quarantined &&
            (!oldest || entry->last_seen_ms < oldest->last_seen_ms)) {
            oldest = entry;
        }
        bool same_node =
            memcmp(entry->node_id, node_id,
                   LORA_TRUNK_V3_NODE_ID_LEN) == 0;
        if (same_node && entry->identity_authenticated &&
            memcmp(entry->signing_key, signing_key,
                   LORA_TRUNK_SIGNING_KEY_LEN) != 0) {
            entry->quarantined = true;
            collision = true;
        }
        if (same_node && !entry->identity_authenticated) {
            unauthenticated_node = entry;
        }
        if (entry->identity_authenticated &&
            memcmp(entry->reachable_peer, reachable_peer,
                   LORA_TRUNK_V3_NODE_ID_LEN) == 0 &&
            memcmp(entry->signing_key, signing_key,
                   LORA_TRUNK_SIGNING_KEY_LEN) == 0) {
            same_route = entry;
        }
    }
    if (collision) {
        return LORA_TRUNK_NEIGHBOR_COLLISION;
    }
    if (same_route) {
        if (same_route->quarantined) {
            return LORA_TRUNK_NEIGHBOR_COLLISION;
        }
        memcpy(same_route->node_id, node_id, LORA_TRUNK_V3_NODE_ID_LEN);
        same_route->capabilities = capabilities;
        same_route->last_seen_ms = now_ms;
        return LORA_TRUNK_NEIGHBOR_REFRESHED;
    }

    lora_trunk_neighbor_t *entry =
        unauthenticated_node
            ? unauthenticated_node
            : (free_entry ? free_entry : oldest);
    if (!entry) {
        return LORA_TRUNK_NEIGHBOR_COLLISION;
    }
    lora_trunk_neighbor_result_t result =
        unauthenticated_node || free_entry
            ? LORA_TRUNK_NEIGHBOR_LEARNED
            : LORA_TRUNK_NEIGHBOR_EVICTED;
    if (!unauthenticated_node) {
        memset(entry, 0, sizeof(*entry));
    }
    entry->in_use = true;
    entry->identity_authenticated = true;
    memcpy(entry->node_id, node_id, LORA_TRUNK_V3_NODE_ID_LEN);
    memcpy(entry->reachable_peer, reachable_peer,
           LORA_TRUNK_V3_NODE_ID_LEN);
    memcpy(entry->signing_key, signing_key, LORA_TRUNK_SIGNING_KEY_LEN);
    entry->capabilities = capabilities;
    entry->last_seen_ms = now_ms;
    return result;
}

bool lora_trunk_neighbor_route(
    const lora_trunk_neighbor_table_t *table,
    const uint8_t reachable_peer[LORA_TRUNK_V3_NODE_ID_LEN],
    uint64_t now_ms, uint64_t max_age_ms,
    uint8_t out_node_id[LORA_TRUNK_V3_NODE_ID_LEN],
    uint16_t *out_capabilities)
{
    if (!table || !reachable_peer || !out_node_id) {
        return false;
    }
    const lora_trunk_neighbor_t *freshest = NULL;
    for (size_t i = 0; i < LORA_TRUNK_NEIGHBOR_CAPACITY; ++i) {
        const lora_trunk_neighbor_t *entry = &table->entries[i];
        if (!entry->in_use || entry->quarantined ||
            !entry->identity_authenticated ||
            memcmp(entry->reachable_peer, reachable_peer,
                   LORA_TRUNK_V3_NODE_ID_LEN) != 0 ||
            now_ms < entry->last_seen_ms ||
            now_ms - entry->last_seen_ms > max_age_ms) {
            continue;
        }
        if (!freshest || entry->last_seen_ms > freshest->last_seen_ms) {
            freshest = entry;
        }
    }
    if (!freshest) {
        return false;
    }
    memcpy(out_node_id, freshest->node_id, LORA_TRUNK_V3_NODE_ID_LEN);
    if (out_capabilities) {
        *out_capabilities = freshest->capabilities;
    }
    return true;
}

size_t lora_trunk_neighbor_count(const lora_trunk_neighbor_table_t *table)
{
    if (!table) {
        return 0;
    }
    size_t count = 0;
    for (size_t i = 0; i < LORA_TRUNK_NEIGHBOR_CAPACITY; ++i) {
        count += table->entries[i].in_use ? 1u : 0u;
    }
    return count;
}
