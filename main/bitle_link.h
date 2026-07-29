#ifndef BITLE_LINK_H
#define BITLE_LINK_H

/* Transport-agnostic link registry.
 *
 * A "link" is any peer connection that can carry encoded BitChat packets:
 * a BLE connection today, a LoRa neighbor tomorrow. Transports register a
 * link when the peer becomes able to receive (BLE: subscribed / CCCD
 * written) and unregister it when the peer goes away. The mesh core
 * (bitle_mesh) relays through this table without knowing what a link is.
 *
 * Handles share one namespace: BLE links use their NimBLE conn handle
 * (small integers); future transports must allocate from a disjoint range
 * (LoRa reserves 0x4000+).
 */

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BITLE_LINK_MAX  8
#define BITLE_LINK_NONE 0xFFFF

/* Handles at/above this are broadcast media (the LoRa trunk): one handle
 * fronts many remote peers. A node must NOT run point-to-point rituals —
 * proactive Noise session-init, gossip requestSync — over them; those are
 * for real 1:1 BLE peers. It still relays and answers directed traffic. */
#define BITLE_LINK_BROADCAST_BASE 0x4000
static inline bool bitle_link_is_broadcast(uint16_t handle)
{
    return handle >= BITLE_LINK_BROADCAST_BASE;
}

typedef enum {
    BITLE_LINK_BLE,
    BITLE_LINK_LORA,
} bitle_link_type_t;

typedef enum {
    BITLE_LINK_SEND_ACCEPTED = 0,
    BITLE_LINK_SEND_DEFERRED,
    BITLE_LINK_SEND_POLICY_DROPPED,
    BITLE_LINK_SEND_FAILED,
} bitle_link_send_result_t;

typedef bitle_link_send_result_t (*bitle_link_send_fn_t)(
    uint16_t handle, const uint8_t *data, uint16_t len);
typedef bitle_link_send_result_t (*bitle_link_relay_fn_t)(
    uint16_t handle, const uint8_t *data, uint16_t len);
typedef bitle_link_send_result_t (*bitle_link_reserve_fn_t)(
    uint16_t handle, uint8_t packet_type, uintptr_t *out_token);
typedef bitle_link_send_result_t (*bitle_link_commit_fn_t)(
    uint16_t handle, uintptr_t token, const uint8_t *data, uint16_t len);
typedef void (*bitle_link_cancel_fn_t)(uint16_t handle, uintptr_t token);

typedef struct {
    uint16_t handle;
    uintptr_t token;
    bitle_link_commit_fn_t commit_fn;
    bitle_link_cancel_fn_t cancel_fn;
    bool active;
} bitle_link_reservation_t;

esp_err_t bitle_link_init(void);

/* Registers a link as ready to carry packets. Idempotent per handle. */
esp_err_t bitle_link_register(uint16_t handle, bitle_link_type_t type, bitle_link_send_fn_t send_fn);
esp_err_t bitle_link_register_reservable(
    uint16_t handle, bitle_link_type_t type, bitle_link_send_fn_t send_fn,
    bitle_link_reserve_fn_t reserve_fn, bitle_link_commit_fn_t commit_fn,
    bitle_link_cancel_fn_t cancel_fn);
esp_err_t bitle_link_register_reservable_relay(
    uint16_t handle, bitle_link_type_t type, bitle_link_send_fn_t send_fn,
    bitle_link_relay_fn_t relay_fn,
    bitle_link_reserve_fn_t reserve_fn, bitle_link_commit_fn_t commit_fn,
    bitle_link_cancel_fn_t cancel_fn);
void bitle_link_unregister(uint16_t handle);
bool bitle_link_ready(uint16_t handle);

/* Link type for a registered handle, or -1 when unknown. */
int bitle_link_type_of(uint16_t handle);

/* Detailed result for callers that need to distinguish backpressure from a
 * permanent policy decision or a broken transport. ACCEPTED means the
 * transport owns the packet; it does not imply end-to-end delivery. */
bitle_link_send_result_t bitle_link_send_detailed(
    uint16_t handle, const uint8_t *data, uint16_t len);

/* Two-phase ownership for producers such as Noise that must secure transport
 * capacity before advancing a nonce. Only links registered with reservation
 * callbacks support this operation. */
bitle_link_send_result_t bitle_link_reserve_send(
    uint16_t handle, uint8_t packet_type, bitle_link_reservation_t *out);
bitle_link_send_result_t bitle_link_commit_send(
    bitle_link_reservation_t *reservation, const uint8_t *data, uint16_t len);
void bitle_link_cancel_send(bitle_link_reservation_t *reservation);

/* Compatibility wrapper for existing esp_err_t callers. */
esp_err_t bitle_link_send(uint16_t handle, const uint8_t *data, uint16_t len);

/* Sends to every registered link except exclude_handle (BITLE_LINK_NONE to
 * send to all). Returns the number of links the send succeeded on. */
int bitle_link_broadcast(uint16_t exclude_handle, const uint8_t *data, uint16_t len);

/* Relays to every other registered link and, when the ingress transport
 * provides an explicit same-medium callback, back onto that medium too. */
int bitle_link_rebroadcast(
    uint16_t source_handle, const uint8_t *data, uint16_t len);

#ifdef __cplusplus
}
#endif

#endif // BITLE_LINK_H
