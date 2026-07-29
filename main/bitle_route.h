#ifndef BITLE_ROUTE_H
#define BITLE_ROUTE_H

/* Peer-ID based routing state, mirroring the upstream BitChat mesh graph
 * (bitchat-android services/meshgraph + BluetoothConnectionTracker):
 *
 *  - Direct-peer table: which link a peer is directly connected on, learned
 *    exclusively from signature-verified ANNOUNCEs still at their origin TTL
 *    (the upstream DirectLinkAnnouncementPolicy rule). This is the only
 *    peer-ID -> link mapping; routed forwarding and the "is this peer
 *    directly connected" query both resolve through it.
 *  - Neighbor graph: every verified ANNOUNCE's DIRECT_NEIGHBORS gossip TLV
 *    (0x04), timestamp-gated so only strictly newer claims replace older
 *    ones. An edge is routable only when mutually announced (confirmed),
 *    exactly like upstream MeshGraphService.
 *  - Source-route computation: unit-weight shortest path (BFS) over
 *    confirmed edges, intermediates only, matching upstream RoutePlanner.
 */

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Upstream caps a DIRECT_NEIGHBORS TLV at 10 peer IDs. */
#define BITLE_ROUTE_MAX_NEIGHBORS 10

esp_err_t bitle_route_init(void);

/* Records peer_id as directly connected on the given link. Call only for
 * signature-verified announces that arrived at their origin TTL. Refreshes
 * the entry's liveness timestamp. */
void bitle_route_note_direct(const uint8_t peer_id[8], uint16_t link);

/* Drops every direct-peer mapping that pointed at a link which went away. */
void bitle_route_link_down(uint16_t link);

/* Link the peer is directly connected on, or BITLE_LINK_NONE. Mappings on
 * broadcast media (LoRa) lapse when not refreshed by periodic announces;
 * point-to-point mappings live until their link goes down. */
uint16_t bitle_route_link_for(const uint8_t peer_id[8]);

/* True when the peer currently has a live direct connection to us. */
bool bitle_route_is_direct(const uint8_t peer_id[8]);

/* Our verified direct peers, for the ANNOUNCE gossip TLV. Returns count. */
int bitle_route_direct_peers(uint8_t out[][8], int max);

/* Stores a verified peer's announced neighbor set; timestamp_ms is the
 * announce's own timestamp — only strictly newer claims replace older ones. */
void bitle_route_note_neighbors(const uint8_t peer_id[8], const uint8_t neighbors[][8],
                                int count, uint64_t timestamp_ms);

/* Shortest confirmed path from src to dest. Returns the number of
 * intermediate hops written to out_hops (>= 1: attach as a source route),
 * 0 when dest is a direct neighbor (no route needed), or -1 when no
 * confirmed path exists. */
int bitle_route_compute(const uint8_t src[8], const uint8_t dest[8],
                        uint8_t out_hops[][8], int max_hops);

#ifdef __cplusplus
}
#endif

#endif // BITLE_ROUTE_H
