#ifndef LORA_TRUNK_PROTOCOL_H
#define LORA_TRUNK_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LORA_TRUNK_MAGIC0 0xB7
#define LORA_TRUNK_MAGIC1 0x1E

#define LORA_TRUNK_V2_VERSION 2
#define LORA_TRUNK_V2_HEADER_LEN 16

#define LORA_TRUNK_V3_VERSION 3
#define LORA_TRUNK_V3_HEADER_LEN 44
#define LORA_TRUNK_V3_NODE_ID_LEN 8
#define LORA_TRUNK_V3_TRANSFER_ID_LEN 12
#define LORA_TRUNK_V3_MAX_FRAME_LEN 255
#define LORA_TRUNK_V3_MAX_PAYLOAD \
    (LORA_TRUNK_V3_MAX_FRAME_LEN - LORA_TRUNK_V3_HEADER_LEN)
#define LORA_TRUNK_MAX_FRAGMENTS 5
#define LORA_TRUNK_BEACON_REGION_COUNT 2

#define LORA_TRUNK_V3_CAP_PROTOCOL 0x0001u

typedef enum {
    LORA_TRUNK_KIND_DATA = 1,
    LORA_TRUNK_KIND_BITMAP_ACK = 2,
    LORA_TRUNK_KIND_COMPLETE = 3,
    LORA_TRUNK_KIND_ABORT = 4,
    LORA_TRUNK_KIND_BEACON = 5,
} lora_trunk_kind_t;

typedef enum {
    LORA_TRUNK_ABORT_RETRY_EXHAUSTED = 1,
    LORA_TRUNK_ABORT_INVALID_LENGTH = 2,
    LORA_TRUNK_ABORT_RESOURCE_PRESSURE = 3,
    LORA_TRUNK_ABORT_RADIO_RESET = 4,
} lora_trunk_abort_reason_t;

typedef enum {
    LORA_TRUNK_V3_FLAG_ACK_REQUESTED = 0x01,
    LORA_TRUNK_V3_FLAG_BROADCAST = 0x02,
} lora_trunk_v3_flag_t;

typedef enum {
    LORA_TRUNK_PARSE_OK = 0,
    LORA_TRUNK_PARSE_FOREIGN,
    LORA_TRUNK_PARSE_UNSUPPORTED_VERSION,
    LORA_TRUNK_PARSE_MALFORMED,
} lora_trunk_parse_result_t;

typedef struct {
    uint8_t version;
    lora_trunk_kind_t kind;
    uint8_t flags;
    uint16_t capabilities;
    uint8_t hop_limit;
    uint8_t hop_count;
    uint8_t source[LORA_TRUNK_V3_NODE_ID_LEN];
    uint8_t destination[LORA_TRUNK_V3_NODE_ID_LEN];
    uint8_t transfer_id[LORA_TRUNK_V3_TRANSFER_ID_LEN];
    uint8_t fragment_index;
    uint8_t fragment_total;
    const uint8_t *payload;
    uint16_t payload_len;
} lora_trunk_frame_t;

/* Parses v2 and v3 without allocating or retaining pointers beyond the input
 * frame. Only LORA_TRUNK_PARSE_OK may be used to mutate protocol state. */
lora_trunk_parse_result_t lora_trunk_parse(
    const uint8_t *data, size_t len, lora_trunk_frame_t *out);

/* Encodes a validated v3 frame and its header CRC. */
bool lora_trunk_v3_encode(
    const lora_trunk_frame_t *frame, uint8_t *out, size_t capacity,
    size_t *out_len);

/* Exact v3 packet-control predicate. A bitmap ACK, COMPLETE, or ABORT must
 * reverse source/destination and match the full transfer tuple. */
bool lora_trunk_v3_control_matches(
    const lora_trunk_frame_t *data,
    const lora_trunk_frame_t *control);

/* 96-bit transfer ID: unpredictable 64-bit boot epoch plus BE counter. */
void lora_trunk_make_transfer_id(
    const uint8_t boot_epoch[8], uint32_t counter,
    uint8_t out[LORA_TRUNK_V3_TRANSFER_ID_LEN]);

/* Compact beacon: the ordinary v3 header carries version, capabilities, node
 * ID, boot epoch, and freshness. hop_limit carries the one-byte region ID, so
 * the complete beacon remains one 44-byte frame with no application payload. */
bool lora_trunk_beacon_init(
    lora_trunk_frame_t *frame,
    const uint8_t node_id[LORA_TRUNK_V3_NODE_ID_LEN],
    const uint8_t boot_epoch[8], uint32_t freshness,
    uint8_t region, uint16_t capabilities);

bool lora_trunk_beacon_fields(
    const lora_trunk_frame_t *frame, uint8_t *out_region,
    uint32_t *out_freshness);

#define LORA_TRUNK_NEIGHBOR_CAPACITY 12
#define LORA_TRUNK_SIGNING_KEY_LEN 32

typedef struct {
    bool in_use;
    bool quarantined;
    bool identity_authenticated;
    uint8_t node_id[LORA_TRUNK_V3_NODE_ID_LEN];
    uint8_t reachable_peer[LORA_TRUNK_V3_NODE_ID_LEN];
    uint8_t signing_key[LORA_TRUNK_SIGNING_KEY_LEN];
    uint8_t boot_epoch[8];
    uint32_t freshness;
    uint8_t region;
    uint16_t capabilities;
    uint64_t last_seen_ms;
} lora_trunk_neighbor_t;

typedef struct {
    lora_trunk_neighbor_t entries[LORA_TRUNK_NEIGHBOR_CAPACITY];
} lora_trunk_neighbor_table_t;

typedef enum {
    LORA_TRUNK_NEIGHBOR_LEARNED = 0,
    LORA_TRUNK_NEIGHBOR_REFRESHED,
    LORA_TRUNK_NEIGHBOR_EVICTED,
    LORA_TRUNK_NEIGHBOR_COLLISION,
    LORA_TRUNK_NEIGHBOR_STALE,
} lora_trunk_neighbor_result_t;

void lora_trunk_neighbor_table_init(lora_trunk_neighbor_table_t *table);

/* Learns minimum viable radio reachability without treating the beacon as a
 * BitChat identity proof. Repeated freshness values are ignored, and a new
 * boot epoch starts a new freshness sequence. */
lora_trunk_neighbor_result_t lora_trunk_neighbor_learn_beacon(
    lora_trunk_neighbor_table_t *table,
    const uint8_t node_id[LORA_TRUNK_V3_NODE_ID_LEN],
    const uint8_t boot_epoch[8], uint32_t freshness,
    uint8_t region, uint16_t capabilities, uint64_t now_ms);

/* Caller supplies identity data from a successfully verified signed announce.
 * A node ID observed with a different signing identity is quarantined. */
lora_trunk_neighbor_result_t lora_trunk_neighbor_learn_authenticated(
    lora_trunk_neighbor_table_t *table,
    const uint8_t node_id[LORA_TRUNK_V3_NODE_ID_LEN],
    const uint8_t reachable_peer[LORA_TRUNK_V3_NODE_ID_LEN],
    const uint8_t signing_key[LORA_TRUNK_SIGNING_KEY_LEN],
    uint16_t capabilities, uint64_t now_ms);

/* Returns the freshest non-expired, non-quarantined route for a BitChat peer. */
bool lora_trunk_neighbor_route(
    const lora_trunk_neighbor_table_t *table,
    const uint8_t reachable_peer[LORA_TRUNK_V3_NODE_ID_LEN],
    uint64_t now_ms, uint64_t max_age_ms,
    uint8_t out_node_id[LORA_TRUNK_V3_NODE_ID_LEN],
    uint16_t *out_capabilities);

size_t lora_trunk_neighbor_count(const lora_trunk_neighbor_table_t *table);

#ifdef __cplusplus
}
#endif

#endif
