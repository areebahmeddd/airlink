#ifndef BITLE_LORA_H
#define BITLE_LORA_H

/* LoRa trunk: kilometer-scale node-to-node backhaul.
 *
 * The trunk registers one bitle_link (handle BITLE_LORA_LINK_HANDLE) for
 * the whole medium once an SX1262 is detected, so the mesh core relays
 * BLE<->LoRa with no special cases. Encoded BitChat packets are carried in
 * fragments under a 16-byte trunk header, with per-frame acknowledgement;
 * frames from foreign LoRa protocols fail the magic check and are dropped
 * before touching the mesh.
 *
 * Boards without the radio (every C3, an S3 without the Wio module)
 * probe at boot, find nothing, and run BLE-only — one firmware for all
 * node types.
 */

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BITLE_LORA_LINK_HANDLE 0x4000

/* Detects the radio and, if present, brings up the trunk. Never fails
 * the boot: absence of a radio is a supported configuration. */
esp_err_t bitle_lora_init(void);

bool bitle_lora_active(void);

typedef struct {
    uint32_t raw_rx_frames;
    uint32_t crc_errors;
    uint32_t tx_attempts;
    uint32_t tx_timeouts;
    uint32_t ack_rx;
    uint32_t ack_tx;
    uint32_t ack_misses;
    uint32_t retries;
    uint32_t retry_exhaustion;
    uint32_t queue_full;
    uint32_t reassembly_expiry;
    uint32_t completed_packets;
    uint32_t queue_depth;
    uint32_t queue_high_water;
} bitle_lora_diag_t;

/* Snapshot transport diagnostics. All counters are monotonic for the boot.
 * Safe before radio initialization; the returned structure will be zeroed. */
void bitle_lora_get_diag(bitle_lora_diag_t *out);

#ifdef __cplusplus
}
#endif

#endif // BITLE_LORA_H
