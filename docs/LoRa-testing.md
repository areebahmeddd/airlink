# LoRa reliability testing

The LoRa reliability work has two test layers: a deterministic host suite and
an opt-in multi-board smoke test. Run the host suite before every firmware
build.

## Host suite

```bash
tools/run_lora_host_tests.sh
```

The suite compiles the same portable airtime and regional-profile
implementations used by firmware and runs the deterministic link simulator.
It checks minimum (16-byte), typical (136-byte), and maximum (255-byte) radio
frames at SF7 through SF12, including timeout conversion and 24-bit clamping.
It also checks US915/EU868 boundaries, defaults, inference, profile mismatch
rejection, and image-calibration selection.

The same command also compiles the allocation-free v2/v3 trunk parser and v3
encoder. Its protocol cases cover malformed headers, exact ACK matching,
same-transfer isolation between senders, zero-ACK broadcast delivery to four
nodes, neighbor collision quarantine, expiry, bounded eviction, and 100,000
deterministic fuzz frames.

The packet-level reliability suite sends 520-byte transfers through 30%
independent data and feedback loss and requires at least 95% completion within
the eight-round bound. Additional cases cover cumulative bitmap selection,
lost COMPLETE controls, duplicate and reordered fragments, delayed feedback,
an incomplete receiver restart, transfer-counter wrap, exact BitChat length
validation, and profile-derived deadlines for one through five fragments at
SF7 through SF12.

The legacy-v2 simulator cases intentionally assert the original protocol
failures: fixed reassembly expiry under retries, partial frame enqueue,
acceptance of an ACK from the wrong source, and broadcast ACK implosion. The
historical SF11/SF12 case records why the former fixed two-second timeout was
unsafe; the firmware now uses the tested airtime-derived timeout instead.

The simulator controls data loss, ACK loss, delay, duplication, reordering,
queue capacity, radio profile, fragment size, retry count, CAD allowance, and
radio timeout from a fixed random seed.

The link-adaptation cases exercise the bounded per-neighbor table and its
hysteresis. They require the weak policy to improve completion under 40%
independent loss, require the stable policy to return a 480-byte transfer from
five fragments to four, and compare CR 4/5, 4/6, and 4/7 with the exact airtime
model. These are deterministic injected-erasure results, not substitutes for
RF delivery measurements.

## Firmware build

Activate ESP-IDF 6.0, then build:

```bash
source ~/.espressif/python_env/idf6.0_py3.14_env/bin/activate
source ../esp-idf/export.sh
idf.py build
```

## Radio profiles

The build-time defaults are configured under **Bitle hardware**:

- `CONFIG_BITLE_LORA_REGION_US915` or
  `CONFIG_BITLE_LORA_REGION_EU868`;
- `CONFIG_BITLE_LORA_DEFAULT_SF`, from SF7 through SF12;
- `CONFIG_BITLE_LORA_CODING_RATE`, from 5 through 8;
- `CONFIG_BITLE_LORA_PREAMBLE_SYMBOLS`, with a robust default of 16.

The `lora` NVS namespace may override these defaults with `region` (`u8`,
US915 = 0, EU868 = 1), `freq` (`u32` Hz), and `sf` (`u8`). A frequency must
fall inside its explicit profile. A mismatched pair, out-of-profile frequency,
unknown profile, malformed value, or invalid spreading factor is rejected and
counted in `config_rejections`. The final combined profile is also rejected
unless SF, bandwidth, coding rate, preamble, private sync word, TX power, and
regional frequency are all valid. Rejection falls back to the complete
build-time profile rather than mixing stored and default values. A legacy store
containing only `freq` infers the profile when the frequency is unambiguous.

Coding rate is a trunk-wide interoperability setting. Every participating
radio must use the same value. The per-neighbor adaptation described below
never changes frequency, SF, bandwidth, coding rate, sync word, preamble, or TX
power.

## Board and link-adaptation hardware smoke test

The production default keeps `CONFIG_BITLE_LORA_DIAGNOSTIC_SMOKE` disabled.
For a routine test, enable it on exactly one build. For controlled adaptation
or coding-rate measurements, also enable
`CONFIG_BITLE_LORA_DIAGNOSTIC_QUIET` on every participating node. Quiet mode
suppresses signed discovery announcements and reduces the initial beacon burst
to one transmission per node. Marked diagnostic probes may use that fresh
compatible beacon as a direct route; normal application traffic cannot. This
keeps discovery traffic from consuming the SF10 channel and biasing
link-adaptation measurements. Quiet mode otherwise admits only beacons, packet
controls, and marked test traffic to LoRa. Beacons keep the direct route fresh.
Quiet mode does not change production behavior when disabled.

Without quiet mode, the sender first transmits three closely spaced
unaddressed public probes with normal application TTL to exercise same-medium
forwarding. Quiet adaptation runs omit that forwarding preamble. They may
address marked diagnostic probes directly to a fresh compatible beacon source
if simultaneous signed announcements have not yet established an authenticated
route. That diagnostic-only fallback cannot carry application traffic and is
compiled out of production builds.

The sender then uses short successful transfers to exercise policy hysteresis,
transmits addressed packets spanning one through five fragments, and finishes
with a 480-byte recovery probe. It does not admit the next addressed probe
until the previous transfer has produced a terminal delivery sample. A stable
link must eventually select a 120-byte, six-round policy and encode the
480-byte recovery probe in four fragments. The compressed sequence is
designed to finish within a 120-second capture on an uncontended SF10 channel.
A 60-second capture is useful as a quick radio-health check but may stop before
the ninth delivery selects the stable policy.

Capture all serial streams concurrently:

```bash
python tools/lora_hardware_smoke.py PORT_A PORT_B PORT_C \
  --seconds 120 --reset --quiet \
  --json-out /tmp/bitle-lora-smoke.json
```

The capture tool accepts a third or later port for topology tests. In a
three-board same-room test, expect one receiver to transmit the forwarding
probe at `hops=1/3`; another relay may cancel its queued copy after overhearing
that transmission. A same-room triangle does not prove the physical
endpoint-isolated line gate, so retain the deterministic 20%-loss line test or
separate/attenuate the endpoints until they cannot receive each other.

The capture summarizes TX and completed RX counts by fragment count, addressed
diagnostic events, authenticated-neighbor learning, bitmap/COMPLETE/ABORT
controls, completed sender transfers, duplicate suppression, and parser
rejection counters. It also retains per-frame RSSI/SNR, adaptive policy
choices, EWMA snapshots, the active profile, watchdog/recovery events, and
periodic radio diagnostics. Raw serial output and JSON evidence may contain
local device details, so keep it outside the repository.

At boot, every node must report its expected board, region, frequency, SF,
bandwidth, coding rate, preamble, private sync word, and `phy_verified=1`.
During the run require zero radio command errors, BUSY timeouts, TX timeouts,
watchdog recoveries, and recovery failures. Repeat the same packet-delivery and
radio-recovery checks once with
`CONFIG_BITLE_LORA_BOARD_XIAO_WIO_SX1262` and once with
`CONFIG_BITLE_LORA_BOARD_HELTEC_V3`; a build-only result is not a board smoke
test.

Repeat with `CONFIG_BITLE_LORA_DEFAULT_SF` set to 10, 11, and 12 on both
boards. At each SF, verify that the receiver records 136-byte frames and both
nodes report zero `radio_timeouts`, `radio_command_errors`, and
`busy_timeouts`.

## Coding-rate comparison

Run the quiet multi-board test at CR 4/5, 4/6, and 4/7. Rebuild and flash every
participating node between runs; mixed coding rates intentionally cannot
demodulate one another. Keep board placement, antennas, region, frequency,
SF10, 125 kHz bandwidth, 16-symbol preamble, TX power, packet sequence, and
capture duration fixed.

For a 164-byte frame under that profile, the tested deterministic airtime is:

| Coding rate | Airtime |
|---|---:|
| 4/5 | 1,583 ms |
| 4/6 | 1,853 ms |
| 4/7 | 2,124 ms |

For each RF run record admitted transfers, completed transfers, fragment and
control counts, retry exhaustion, ACK misses, RSSI/SNR distribution, latency,
and every radio fault counter. Choose a non-default coding rate only when its
measured delivery improvement justifies its airtime and duty-cycle cost.
Changing the default requires a coordinated firmware rollout; there is no
automatic per-peer PHY switch.

## Power and thermal measurement

Use an inline USB power analyzer or a current-limited bench supply and a
contact probe or calibrated thermal camera. Record ambient temperature, supply
voltage, idle current, RX current, average and peak current during the smoke
sequence, maximum board/radio temperature, and temperature rise. Measure each
supported board in these configurations:

1. normal RX with boosted gain and the 16-symbol preamble;
2. sustained diagnostic transfers at CR 4/5;
3. sustained diagnostic transfers at CR 4/7;
4. the weak-link policy with its ten-round retry ceiling.

Run each loaded condition for at least 15 minutes after temperatures stabilize.
Stop immediately on a regulator fault, reset, radio recovery loop, unexpected
current-limit event, or a component temperature outside its vendor rating.
The milestone passes only when the recorded current remains inside the board
and supply ratings, temperature remains inside every component rating, and
the chosen coding rate/duty configuration complies with the active regional
airtime policy. Serial logs alone do not satisfy this measurement.

To exercise the missing-interrupt path, additionally enable
`CONFIG_BITLE_LORA_DIAGNOSTIC_SUPPRESS_TX_DONE_ONCE` on the probe sender. It
depends on diagnostic smoke mode and suppresses exactly one task-level
`TX_DONE`. The sender must then report one `tx_done_suppressed`, one
`tx_watchdog_expired`, one successful `radio_recovered`, and zero recovery
failures while later traffic continues. Never deploy either diagnostic option.

Runtime firmware emits a one-minute diagnostic summary containing:

- valid raw RX frames and CRC failures;
- TX attempts/timeouts, retries, ACK RX/TX/misses, and retry exhaustion;
- current/high-water queue depth and queue-full events;
- expired reassemblies and completed packets;
- cumulative bitmap and COMPLETE controls, duplicate fragments/transfers,
  explicit transfer aborts, invalid reassemblies, and resource-pressure
  rejects;
- rejected persisted configurations;
- low-level command/BUSY errors, radio recoveries/failures, and independent TX
  watchdog recoveries.

Milestone 1's two-board validation met those checks at SF10, SF11, and SF12
with a 16-symbol preamble. Full 136-byte frames were received at every SF; all
three runs reported zero SX1262 timeouts, command errors, and BUSY timeouts.
Each injected run produced exactly one watchdog recovery with no recovery
failure, then continued exchanging frames.

Milestone 4's SF10 packet-reliability gate admitted and sender-confirmed all
five addressed probes. The receiver emitted matching COMPLETE masks for
one through five fragments with no abort, invalid-reassembly, resource,
radio-command, BUSY-timeout, watchdog-recovery, or duplicate-delivery event.
