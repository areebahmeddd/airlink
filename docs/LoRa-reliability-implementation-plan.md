# LoRa Reliability Implementation Plan

## Milestone execution rule

Work must proceed one milestone at a time. After a milestone satisfies all of
its success criteria:

1. Update this implementation plan with the completed checklist, test evidence,
   measurements, decisions, and any changes to later milestones.
2. Record the milestone status and the resulting Git commit hash in the
   progress table below.
3. Commit the implementation, tests, documentation, and this updated plan
   together as one focused Git commit.
4. Confirm the commit succeeded and the worktree contains no unexpected
   changes.
5. Only then begin the next milestone.

If a success criterion fails, remain in the current milestone, diagnose the
failure, and update the plan as necessary. Do not mark the milestone complete
or proceed to the next one until its gate passes. Milestone commits should
remain distinct so each reliability improvement can be tested, reviewed, and
reverted independently.

## Program success criteria

The implementation is complete only when all of the following are true:

- Every supported LoRa profile can transmit the largest frame without hitting
  the SX1262 TX timeout. This includes SF7 through SF12 at BW125.
- Under a deterministic host simulation with 30% independently injected data
  and ACK loss, at least 95% of 520-byte packets are delivered within the
  documented retry deadline, with zero corrupted or falsely completed packets.
- Queue saturation never produces a partially enqueued packet. A caller gets an
  accurate accepted, deferred, or rejected result before any fragment is sent.
- A receiver never acknowledges successful packet delivery until it has a
  complete, length-valid packet. Duplicate retransmissions do not cause
  duplicate delivery to the BitChat mesh.
- An ACK from an unintended node can never satisfy an addressed transmission.
  Broadcast traffic does not trigger simultaneous ACKs from every receiver.
- At 30% injected frame loss, 95% of nodes are discovered within three
  configured beacon intervals.
- In a three-node line topology where the first and third nodes cannot hear each
  other, at least 90% of 200 test packets cross two LoRa hops under 20% injected
  per-hop loss, with no forwarding loops or duplicate application delivery.
- Regional radio profiles are explicit, validate their frequency ranges, apply
  the correct image calibration, and survive reboot. At minimum, EU868 and
  US915 profiles are covered.
- The implementation records actionable counters for TX attempts, retries, ACK
  misses, CRC failures, queue pressure, reassembly expiry, duplicate suppression,
  and completed packet delivery.
- Existing BLE-only behavior, Noise handling, packet codec behavior, courier,
  sync, OTA admission policy, and supported ESP32 targets continue to build and
  pass their existing checks.
- The README and LoRa documentation describe measured behavior and supported
  configurations. Unverified range claims are removed or clearly labeled as
  test-specific results.

## Milestone progress

| Milestone | Status | Commit | Evidence summary |
|---|---|---|---|
| 0. Baseline harness and observability | Complete | Pending checkpoint | Host baseline, both firmware targets, and two-board SF10 smoke passed |
| 1. Airtime-safe SX1262 operation | Pending | — | — |
| 2. Atomic packet scheduling and backpressure | Pending | — | — |
| 3. Addressed trunk protocol and migration | Pending | — | — |
| 4. Packet-level reliability and reassembly | Pending | — | — |
| 5. Discovery and shared-channel behavior | Pending | — | — |
| 6. LoRa multi-hop forwarding | Pending | — | — |
| 7. Link adaptation and PHY hardening | Pending | — | — |
| 8. End-to-end validation and rollout | Pending | — | — |

## Milestone 0: Baseline harness and observability

### Goal

Create repeatable tests that reproduce the current failures before changing the
wire protocol, and add enough telemetry to distinguish RF loss from protocol
loss.

### Checklist

- [x] Extract or expose the airtime calculation so it can be tested without
      hardware.
- [x] Add a deterministic host-side LoRa link simulator with configurable data
      loss, ACK loss, delay, duplication, reordering, and queue capacity.
- [x] Model SF, bandwidth, coding rate, preamble, fragment size, CAD delay,
      retry count, and radio timeout.
- [x] Add baseline tests that reproduce:
  - [x] SF11 and SF12 full-frame TX timeout.
  - [x] Reassembly expiry after weak-link retries.
  - [x] Partial packet enqueue when the frame queue fills.
  - [x] Acceptance of an ACK from the wrong source.
  - [x] Colliding ACK behavior for broadcast frames.
- [x] Add runtime counters for raw RX frames, CRC errors, TX attempts, TX
      timeouts, ACK RX/TX, ACK misses, retry exhaustion, queue full events,
      reassembly expiry, and completed packets.
- [x] Add queue depth and high-water reporting.
- [x] Log RSSI and SNR for every valid raw trunk frame rather than only after
      complete packet reassembly.
- [x] Capture the current two-node SF10 baseline for 1-, 2-, 3-, and 5-fragment
      packets.
- [x] Document how to run the host simulation and the hardware smoke test.

### Success criteria

- The automated baseline suite deterministically demonstrates each known
  failure without relying on physical RF conditions.
- Runtime logs and counters identify whether a loss occurred at TX, raw RX,
  ACK, queueing, reassembly, or BitChat delivery.
- Instrumentation does not change the v2 wire format or materially alter the
  baseline timing.
- Existing firmware targets still build.

### Milestone record

- Status: Complete
- Evidence:
  - Portable C airtime tests and seven deterministic Python baseline tests
    pass. The baseline reproduces the SF11/SF12 two-second TX timeout, fixed
    reassembly expiry, partial enqueue, wrong-source ACK acceptance, and
    four-receiver ACK implosion.
  - ESP-IDF 6.0 clean builds pass for the Heltec V3 ESP32-S3 configuration and
    the BLE-only ESP32-C3 target.
  - A two-board SF10 capture transmitted diagnostic probes spanning one through
    five fragments. One-, two-, and three-fragment probes completed. Four- and
    five-fragment probes were transmitted and their raw frames/ACKs were
    visible, but they did not complete amid concurrent traffic, reproducing the
    v2 fixed-deadline failure on hardware.
  - Runtime diagnostics now separate raw RX, CRC, TX/timeout, ACK, retry,
    queue pressure, reassembly expiry, and completed-delivery stages. Raw valid
    frames log RSSI and SNR.
- Commit: Pending checkpoint
- Suggested commit subject: `test(lora): add reliability harness and baseline telemetry`

## Milestone 1: Airtime-safe SX1262 operation

### Goal

Remove deterministic PHY failures and make every declared radio profile safe
for the configured frame size.

### Checklist

- [ ] Replace the fixed two-second SX1262 TX timeout with a timeout derived from
      calculated packet airtime plus bounded scheduling and radio margin.
- [ ] Clamp the converted SX1262 timeout to the command's valid 24-bit range.
- [ ] Add an independent software watchdog so a missing TX interrupt still
      recovers the radio.
- [ ] Verify TX timeout handling distinguishes expected watchdog recovery from
      an RF delivery failure.
- [ ] Propagate and check errors from radio configuration commands instead of
      silently continuing after failed SPI operations.
- [ ] Add BUSY-stuck recovery and a bounded radio reinitialization path.
- [ ] Make preamble length a profile parameter and set the robust default to at
      least 16 symbols.
- [ ] Apply the Heltec-compatible boosted RX gain setting and verify that it is
      retained across radio mode changes.
- [ ] Explicitly configure and verify the PA current limit needed by each
      supported board and TX power.
- [ ] Introduce explicit regional profiles, initially EU868 and US915.
- [ ] Select image calibration bytes from the active regional frequency rather
      than hardcoding the US band.
- [ ] Reject invalid persisted combinations instead of silently mixing a
      frequency with the wrong calibration or profile.
- [ ] Add airtime and timeout tests for minimum, typical, and maximum frames at
      SF7 through SF12.

### Success criteria

- Maximum-size trunk frames complete TX at SF7 through SF12 without an SX1262
  timeout.
- A deliberately suppressed TX interrupt is recovered by the software watchdog
  and returns the radio to continuous RX.
- EU868 and US915 select valid frequencies and the matching calibration.
- Radio configuration failures are visible to the caller and in diagnostics.
- A two-node hardware smoke test passes at SF10, SF11, and SF12.

### Milestone record

- Status: Pending
- Evidence:
- Commit:
- Suggested commit subject: `fix(lora): make SX1262 operation airtime safe`

## Milestone 2: Atomic packet scheduling and backpressure

### Goal

Prevent queue pressure from creating packets that can never be reassembled and
give callers an honest transport result.

### Checklist

- [ ] Replace the frame queue with a whole-packet TX descriptor queue, or reserve
      all required frame capacity atomically before enqueueing any fragment.
- [ ] Use a bounded static packet pool so queueing does not add heap
      fragmentation to the hot path.
- [ ] Define explicit send results: accepted, deferred/backpressured,
      policy-dropped, and transport-failed.
- [ ] Update `bitle_link` callers so policy drops are not reported as successful
      transport delivery.
- [ ] Ensure a Noise nonce or higher-layer state is not irreversibly advanced
      when the transport rejects a packet before transmission.
- [ ] Give control traffic, ACKs, discovery, and user data explicit priorities
      with starvation bounds.
- [ ] Preserve packet ordering where the BitChat or Noise protocol requires it.
- [ ] Add queue admission metrics by packet type and priority.
- [ ] Add saturation tests with concurrent BLE relay, Noise response, beacon,
      courier, and sync traffic.
- [ ] Add cancellation and cleanup tests for radio reset and link shutdown.

### Success criteria

- No test can produce a partial packet enqueue, including concurrent producers
  and a queue with only one free slot.
- The caller receives a failure or backpressure result before any fragment of a
  rejected packet is transmitted.
- Accepted packets preserve required ordering.
- Control traffic remains bounded, and user traffic cannot be starved
  indefinitely.
- Queue and packet-pool resources return to baseline after retry exhaustion,
  radio recovery, and link shutdown.

### Milestone record

- Status: Pending
- Evidence:
- Commit:
- Suggested commit subject: `refactor(lora): queue trunk packets atomically`

## Milestone 3: Addressed trunk protocol and migration

### Goal

Introduce a new wire version whose addressing and acknowledgement semantics are
correct on a shared multi-node channel.

### Checklist

- [ ] Write the trunk v3 wire-format specification before implementing it.
- [ ] Use a sufficiently collision-resistant node identifier on the wire, or
      define explicit collision detection and recovery for shortened tags.
- [ ] Give each packet a reboot-safe transfer identifier that cannot be confused
      with another sender's sequence.
- [ ] Include source, destination, transfer identifier, fragment information,
      capabilities, and integrity-covered flags in the v3 format.
- [ ] Build a bounded neighbor table from authenticated or otherwise
      integrity-checked discovery information.
- [ ] Track which LoRa neighbor last advertised reachability for each BitChat
      peer so directed BitChat traffic can select a trunk destination.
- [ ] Require addressed receivers to ACK only frames addressed to them.
- [ ] Require senders to validate ACK source, destination, transfer identifier,
      and fragment state.
- [ ] Define broadcast behavior with no immediate all-receiver ACK storm.
- [ ] Define behavior when the destination or route is unknown.
- [ ] Decide and document the v2-to-v3 rollout policy:
  - [ ] Version and capability advertisement.
  - [ ] Mixed-firmware behavior.
  - [ ] Whether v2 is read-only, optional fallback, or intentionally
        unsupported after migration.
  - [ ] A rollback path for deployed nodes.
- [ ] Add parser fuzz tests and malformed-frame tests for both supported wire
      versions.

### Success criteria

- An ACK from any node other than the selected destination is rejected.
- Two senders using the same sequence value cannot corrupt or complete each
  other's transfer.
- Broadcast reception by four nodes produces no simultaneous ACK burst.
- Malformed lengths, fragment counts, identifiers, flags, and versions are
  rejected without memory corruption or state leakage.
- Mixed v2/v3 behavior matches the documented rollout policy.

### Milestone record

- Status: Pending
- Evidence:
- Commit:
- Suggested commit subject: `feat(lora): introduce addressed trunk protocol v3`

## Milestone 4: Packet-level reliability and reassembly

### Goal

Replace per-fragment stop-and-wait behavior with bounded packet-level
reliability that remains correct under loss, duplicates, and reordering.

### Checklist

- [ ] Implement packet-level selective repeat with a received-fragment bitmap.
- [ ] Allow more than one useful fragment per round trip while keeping memory
      and airtime bounded.
- [ ] Send bitmap ACKs only from the addressed destination.
- [ ] Define a final COMPLETE acknowledgement that is sent only after full
      reassembly and length validation.
- [ ] Re-ACK duplicate fragments and duplicate completed transfers without
      delivering the BitChat packet twice.
- [ ] Derive retry and reassembly deadlines from SF, bandwidth, coding rate,
      fragment count, retry budget, and contention allowance.
- [ ] Refresh the progress deadline when a new fragment arrives, while enforcing
      an absolute maximum transfer lifetime.
- [ ] Retain completed-transfer state long enough to answer a sender that missed
      the final COMPLETE acknowledgement.
- [ ] Add explicit abort handling for retry exhaustion, invalid total length,
      resource pressure, and radio reset.
- [ ] Ensure a dropped transfer releases all packet-pool and reassembly
      resources.
- [ ] Test loss, ACK loss, duplication, reordering, delayed ACKs, restart, and
      sequence wrap.
- [ ] Test 1- through 5-fragment packets at every supported SF.

### Success criteria

- At 30% injected data and ACK loss, at least 95% of 520-byte packets complete
  within the documented deadline.
- No incomplete or invalid packet is reported as successfully delivered.
- Duplicate frames and final-ACK loss never cause duplicate BitChat delivery.
- Reassembly state remains bounded under a sustained stream of incomplete or
  malicious transfers.
- SF and fragment count no longer rely on a fixed ten-second timeout.

### Milestone record

- Status: Pending
- Evidence:
- Commit:
- Suggested commit subject: `feat(lora): add packet-level selective repeat ARQ`

## Milestone 5: Discovery and shared-channel behavior

### Goal

Make node discovery timely at weak signal levels and prevent synchronized
traffic from repeatedly colliding.

### Checklist

- [ ] Define a compact, single-frame trunk discovery beacon containing node ID,
      protocol version, capabilities, regional profile, and a freshness value.
- [ ] Keep BitChat identity and signed application announces separate from
      minimum viable trunk-neighbor discovery.
- [ ] Randomize first-beacon and periodic-beacon timing.
- [ ] Add controlled beacon repetition or another bounded reliability mechanism
      that does not create ACK implosion.
- [ ] Make announce throttling aware of whether a previous announce was actually
      admitted and transmitted.
- [ ] Scale contention windows to packet airtime rather than using a fixed
      30–150 ms interval.
- [ ] Recheck CAD immediately before TX after the backoff expires.
- [ ] Keep the radio in RX during software backoff whenever the SX1262 mode
      permits it.
- [ ] Add ACK priority without allowing an unlimited ACK stream to starve data.
- [ ] Add randomized scheduling for relays that hear the same broadcast.
- [ ] Test hidden-terminal, simultaneous-beacon, bidirectional-data, and
      four-receiver scenarios.

### Success criteria

- At 30% injected frame loss, 95% of nodes are discovered within three beacon
  intervals.
- Four nodes booting simultaneously converge without a persistent collision
  cycle.
- Two hidden senders eventually transmit successfully without synchronized
  retry lockstep.
- Discovery and ACK traffic remain within the configured airtime budget.
- Discovery loss does not block an already-known addressed route.

### Milestone record

- Status: Pending
- Evidence:
- Commit:
- Suggested commit subject: `feat(lora): harden discovery and channel access`

## Milestone 6: LoRa multi-hop forwarding

### Goal

Turn the current one-hop LoRa bus into an actual bounded mesh backhaul.

### Checklist

- [ ] Define hop-limit, deduplication, forwarding, and route-learning behavior
      for broadcast and addressed traffic.
- [ ] Ensure a LoRa-received packet can be forwarded back onto LoRa without
      passing through the generic link-exclusion rule that currently prevents
      it.
- [ ] Add an expiring deduplication cache keyed by source and transfer identity.
- [ ] Add SNR- and airtime-aware randomized forwarding delay so the strongest or
      earliest relay tends to win without synchronized rebroadcast.
- [ ] Suppress a scheduled rebroadcast when the same packet is overheard from a
      better-positioned relay.
- [ ] Learn reverse paths from discovery and successfully received traffic.
- [ ] Use per-hop addressed reliability for directed forwarding.
- [ ] Define fallback behavior when a learned route expires or fails.
- [ ] Enforce hop limits before queue admission.
- [ ] Keep application-level BitChat deduplication as a second safety layer.
- [ ] Add line, triangle, ring, route-failure, node-reboot, and asymmetric-link
      topology tests.

### Success criteria

- In a three-node line where endpoints cannot hear each other, at least 90% of
  200 packets cross two hops under 20% injected per-hop loss.
- Ring and triangle tests produce no persistent forwarding loops.
- A route failure triggers bounded rediscovery or fallback and releases stale
  state.
- The final BitChat packet is delivered once even when multiple LoRa paths
  exist.
- Hop-limit and deduplication bounds hold under malicious or repeated traffic.

### Milestone record

- Status: Pending
- Evidence:
- Commit:
- Suggested commit subject: `feat(lora): add bounded multi-hop forwarding`

## Milestone 7: Link adaptation and PHY hardening

### Goal

Use measured link quality to improve reliability without allowing peers to
silently diverge onto incompatible radio parameters.

### Checklist

- [ ] Maintain per-neighbor EWMA metrics for RSSI, SNR, data success, ACK
      success, retries, and recent delivery latency.
- [ ] Adapt fragment size and retry budget within documented bounds.
- [ ] Evaluate CR 4/6 and 4/7 against CR 4/5 using controlled airtime and
      delivery measurements.
- [ ] Do not change frequency, SF, bandwidth, sync word, or coding rate for one
      peer without an explicit coordinated profile-change protocol.
- [ ] If coordinated profile changes are implemented, define rendezvous,
      confirmation, timeout, and rollback behavior.
- [ ] Persist only validated profile choices and recover safely from corrupt or
      incompatible NVS values.
- [ ] Verify boosted RX gain, preamble length, PA setup, and regional frequency
      on each supported board.
- [ ] Add board-specific smoke tests for the XIAO Wio-SX1262 and Heltec V3.
- [ ] Measure power and thermal impact of boosted gain, longer preamble, retries,
      and high TX duty.

### Success criteria

- Weak links select smaller fragments or a higher retry budget without breaking
  interoperability.
- Stable links recover throughput rather than remaining permanently in a
  conservative mode.
- No automated change can strand two nodes on different PHY settings.
- Both supported boards pass the same packet-delivery and radio-recovery suite.
- Power, thermal, and airtime measurements remain within documented operating
  limits.

### Milestone record

- Status: Pending
- Evidence:
- Commit:
- Suggested commit subject: `feat(lora): adapt trunk behavior to measured link quality`

## Milestone 8: End-to-end validation and rollout

### Goal

Validate the complete system under realistic traffic and produce a safe,
documented deployment path.

### Checklist

- [ ] Run the complete host simulation matrix across SF, packet size, loss,
      duplication, reordering, queue pressure, node count, and topology.
- [ ] Run two-node and three-node hardware tests with recorded RSSI, SNR, retry,
      latency, queue, and delivery data.
- [ ] Test discovery, public messages, Noise handshake traffic, DMs, delivery
      receipts, auto-replies, courier traffic, and permitted OTA control traffic.
- [ ] Test simultaneous traffic in both directions.
- [ ] Test reboot during TX, RX, reassembly, route learning, and profile change.
- [ ] Soak test for at least 24 hours with periodic traffic and fault injection.
- [ ] Confirm BLE-only devices and LoRa-disabled configurations are unchanged.
- [ ] Build every supported ESP32 target from a clean configuration.
- [ ] Document regional setup, antenna requirements, supported PHY profiles,
      expected latency, airtime cost, retry behavior, and troubleshooting
      counters.
- [ ] Replace unsupported range claims with results tied to hardware, antenna,
      profile, environment, sample count, and measured link quality.
- [ ] Document v2-to-v3 upgrade, rollback, and mixed-firmware behavior.
- [ ] Produce a release checklist and retain raw acceptance-test results.

### Success criteria

- All program-level success criteria pass with archived evidence.
- The 24-hour soak has no deadlock, unreleased packet state, radio-stuck event
  without recovery, or duplicate application delivery.
- Clean builds succeed for all supported targets.
- Deployment and rollback are documented and have been rehearsed on hardware.
- README claims match measured results.

### Milestone record

- Status: Pending
- Evidence:
- Commit:
- Suggested commit subject: `docs(lora): finalize reliability validation and rollout`
