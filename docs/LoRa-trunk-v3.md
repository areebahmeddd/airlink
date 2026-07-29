# BitLE LoRa trunk protocol v3

## Status and scope

This document defines the version 3 LoRa trunk frame used to carry encoded
BitChat packets between BitLE nodes. Version 3 replaces the collision-prone
four-byte v2 node tags and broadcast ACK behavior with explicit 64-bit
addressing and exact acknowledgement matching.

The SX1262 packet CRC protects the complete radio frame in transit. Version 3
also includes a header CRC so parser-critical fields are rejected before they
can allocate or mutate reassembly state.

## Byte order and limits

All multi-byte integers are unsigned and big-endian. A radio frame is at most
255 bytes. The fixed v3 header is 44 bytes, leaving at most 211 payload bytes.
The initial implementation transmits chunks of at most 120 bytes to retain the
existing short-frame RF behavior.

## Fixed header

| Offset | Size | Field | Definition |
|---:|---:|---|---|
| 0 | 2 | magic | `B7 1E` |
| 2 | 1 | version | `03` |
| 3 | 1 | kind | `01` data, `02` bitmap ACK, `03` COMPLETE, `04` ABORT |
| 4 | 1 | flags | Integrity-covered flags defined below |
| 5 | 1 | header length | `44` |
| 6 | 2 | capabilities | Sender capabilities |
| 8 | 1 | hop limit | Remaining forwarding budget; `0` in milestone 3 |
| 9 | 1 | hop count | Hops already crossed; `0` in milestone 3 |
| 10 | 2 | payload length | Bytes following this header |
| 12 | 8 | source | Full BitChat/Noise peer identifier |
| 20 | 8 | destination | Full peer identifier; all zero means broadcast |
| 28 | 12 | transfer ID | Reboot-safe identifier described below |
| 40 | 1 | fragment value | Data index, received bitmap, full bitmap, or abort reason |
| 41 | 1 | fragment total | `1..5` in the initial implementation |
| 42 | 2 | header CRC | CRC-16/CCITT-FALSE of bytes `0..41` |

The first implemented capability bit is `0x0001`, `TRUNK_V3`. Capability bits
describe the sender of this frame and must not be interpreted as proof that
another node supports a feature.

### Flags

- `0x01 ACK_REQUESTED`: valid only on addressed data.
- `0x02 BROADCAST`: destination must be all zero and `ACK_REQUESTED` must be
  clear.

All other flag bits are reserved and cause the frame to be rejected. An
addressed frame has a nonzero destination and a clear `BROADCAST` flag. A
broadcast has a zero destination and the `BROADCAST` flag set. The redundant
encoding makes accidental and malformed address modes detectable.

Data frames require a nonzero source, nonzero transfer ID, a fragment total of
at least one, an index below that total, and a payload length of at least one.
Control frames require a nonzero source and destination, zero flags, zero
payload, and a fragment total matching the transfer. Bitmap ACK values contain
only bits below `fragment total`. COMPLETE contains the full received bitmap.
ABORT uses the value byte for one of the defined reasons: retry exhaustion,
invalid total length, resource pressure, or radio reset.

## Node and transfer identity

The source and destination are the complete eight-byte BitChat peer IDs derived
from Noise static public keys. Version 3 never truncates them to the four-byte
v2 radio tag.

A neighbor advertisement binds a node ID to the Ed25519 key in a successfully
verified signed BitChat `ANNOUNCE`. The neighbor table stores that signing-key
identity with the radio source. If the same 64-bit node ID is observed with a
different verified signing key, every entry for that ID is quarantined and no
direct route through the conflicting identity is selected. A later firmware
may add an explicit collision-resolution exchange; milestone 3 fails closed.

Each boot generates an unpredictable 64-bit boot epoch from the hardware random
number generator. Every admitted packet appends a monotonically increasing
32-bit counter, producing a 96-bit transfer ID. The counter advances only when
the complete packet is committed to the scheduler. Reboots therefore do not
reuse the preceding boot's transfer namespace except with negligible random
collision probability. Reassembly is keyed by the complete tuple
`(source, transfer ID)`, so equal counters or transfer bytes from different
senders cannot alias.

## Neighbor and route learning

The neighbor table is static and bounded. Entries may be created or refreshed
only after all of the following are true:

1. A complete v3 packet has been reassembled without parser errors.
2. The encoded BitChat packet is an `ANNOUNCE`.
3. Its BitChat sender equals the v3 radio source.
4. The announce sender is derived from its advertised Noise static key.
5. Its signature verifies with its advertised Ed25519 key.

An entry records the v3 source, the BitChat peer advertised as reachable,
verified signing identity, capabilities, and last-seen time. Expired,
quarantined, or conflicting entries are not routes. The bounded table evicts
the oldest non-quarantined entry when full.

For an encoded BitChat packet with a recipient, the sender uses the freshest
authenticated neighbor that advertised that recipient. It emits addressed v3
data with `ACK_REQUESTED`. If there is no authenticated route, the packet is
sent as an unacknowledged v3 broadcast so discovery or higher-level relay can
still provide reachability. Packets without a recipient, including announces,
are broadcasts.

Discovery beacons use an independent randomized startup delay and interval
jitter so peers booted together do not repeatedly collide. Milestone 5 extends
this minimum discovery safeguard with broader loss-adaptation, duplicate
suppression, and cadence policy.

## Packet-level reliability

Only a node whose complete local ID equals an addressed data frame's
destination may ACK it. Broadcast frames never request or produce immediate
ACKs. Consequently four receivers of one broadcast produce zero ACK frames.

An addressed sender transmits every currently missing fragment before waiting
for feedback. A bitmap ACK reports the receiver's cumulative fragment bitmap,
so one round trip can advance multiple fragments. The next round selectively
retransmits only missing fragments. If every fragment is already acknowledged
but COMPLETE was lost, the final fragment is sent as a bounded completion
probe. A transfer uses at most eight rounds.

COMPLETE is distinct from a full bitmap. The receiver sends COMPLETE only
after all fragments are present, their combined length fits the BitChat packet
limit, non-final fragment lengths are canonical, and the encoded BitChat
header's exact recipient/payload/signature length equals the reassembled
length. An incomplete or invalid packet is never reported complete.

Every packet control reverses the data source and destination and copies the
complete transfer ID and fragment total. A sender accepts a bitmap ACK,
COMPLETE, or ABORT only when:

- control source equals the selected data destination.
- control destination equals the local data source.
- transfer ID matches all 96 bits.
- fragment total matches.

An otherwise valid control from a different node is counted and ignored.

The receiver re-ACKs duplicate fragments with its current bitmap. A bounded
completed-transfer cache retains the source, transfer ID, fragment total, and
expiry long enough to resend COMPLETE when the final control was lost.
Duplicate completed transfers do not reach the BitChat mesh twice.

Reassembly uses two static transfer slots and six static completed-cache
entries. A new transfer is rejected with a resource-pressure ABORT rather than
evicting an active transfer. Broadcast reassembly may occupy at most one slot,
leaving one admission opportunity for addressed traffic. Each active slot has
both a progress deadline,
refreshed only by a new fragment, and an absolute lifetime that cannot be
extended. Feedback wait, progress timeout, absolute lifetime, and completed
retention are derived from the active SF, bandwidth, coding rate, preamble,
maximum frame airtime, fragment count, eight-round budget, and bounded
contention allowance. No supported SF relies on a fixed ten-second timeout.
Temporary channel occupancy does not discard an addressed transfer after a
fixed number of CAD results: the sender returns to RX during randomized
backoff and retries until COMPLETE, ABORT, or its absolute deadline.

## Version 2 migration and rollback

Version 3 nodes advertise `TRUNK_V3` in every v3 frame. They originate only v3
frames. During the migration window they continue to parse v2 data and emit a
v2 ACK when the legacy frame requests one, preserving inbound compatibility
with deployed v2 senders. They do not derive v3 neighbor routes from v2 frames
and never fall back to originating v2, because v2 has only four-byte tags and
cannot authenticate an ACK source strongly enough for addressed delivery.

The mixed-firmware behavior is therefore asymmetric:

- v3 sender to v3 receiver: v3 addressed delivery after authenticated route
  learning, otherwise v3 unacknowledged broadcast.
- v2 sender to v3 receiver: legacy v2 receive and legacy ACK behavior.
- v3 sender to v2 receiver: no v3 delivery; periodic announces eventually
  expose the missing capability after that node is upgraded.

This is an intentional migration tradeoff: safety is not silently downgraded
to obtain bidirectional compatibility. Rollback consists of installing the
last v2 firmware image. Version 3 adds no persistent NVS schema and therefore
does not make rollback data-destructive.

The v2 parser accepts only the documented 16-byte header, known flag bits,
valid fragment bounds, a nonzero source, and a payload for data frames. Unknown
versions, kinds, flags, inconsistent lengths, invalid identifiers, and invalid
fragment state are rejected without allocating reassembly state.
