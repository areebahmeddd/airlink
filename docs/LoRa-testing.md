# LoRa reliability testing

The LoRa reliability work has two test layers: a deterministic host suite and
an opt-in two-board smoke test. Run the host suite before every firmware build.

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
- `CONFIG_BITLE_LORA_PREAMBLE_SYMBOLS`, with a robust default of 16.

The `lora` NVS namespace may override these defaults with `region` (`u8`,
US915 = 0, EU868 = 1), `freq` (`u32` Hz), and `sf` (`u8`). A frequency must
fall inside its explicit profile. A mismatched pair, out-of-profile frequency,
unknown profile, malformed value, or invalid spreading factor is rejected and
counted in `config_rejections`. A legacy store containing only `freq` infers
the profile when the frequency is unambiguous.

## Two-board SF10/SF11/SF12 smoke test

The production default keeps `CONFIG_BITLE_LORA_DIAGNOSTIC_SMOKE` disabled.
For a controlled test, enable it on exactly one Heltec V3 build. That node
first transmits three spaced unaddressed public probes with normal application
TTL to exercise same-medium forwarding. After a signed direct announcement
establishes an authenticated v3 neighbor, it transmits one addressed synthetic
packet at each of 1, 2, 3, 4, and 5 fragments. It retries fixture admission
every three seconds and advances only after a probe is accepted. Keep every
receiving node on the normal build.

Capture both serial streams concurrently:

```bash
python tools/lora_hardware_smoke.py PORT_A PORT_B --seconds 90 --reset --quiet \
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
rejection counters. It also retains per-frame RSSI/SNR, the active profile,
watchdog/recovery events, and periodic radio diagnostics. Raw serial output and
JSON evidence may contain local device details, so keep it outside the
repository.

Repeat with `CONFIG_BITLE_LORA_DEFAULT_SF` set to 10, 11, and 12 on both
boards. At each SF, verify that the receiver records 136-byte frames and both
nodes report zero `radio_timeouts`, `radio_command_errors`, and
`busy_timeouts`.

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
