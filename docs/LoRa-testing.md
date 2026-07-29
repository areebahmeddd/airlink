# LoRa reliability testing

The LoRa reliability work has two test layers: a deterministic host suite and
an opt-in two-board smoke test. Run the host suite before every firmware build.

## Host suite

```bash
tools/run_lora_host_tests.sh
```

The suite compiles the same portable airtime implementation used by firmware
and runs the deterministic link simulator. Its legacy-v2 cases intentionally
assert the original failures: SF11/SF12 exceeding the fixed two-second timeout,
fixed reassembly expiry under retries, partial frame enqueue, acceptance of an
ACK from the wrong source, and broadcast ACK implosion. Those cases remain as
an executable historical baseline while later milestones add fixed-protocol
acceptance cases.

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

## Two-board SF10 smoke test

The production default keeps `CONFIG_BITLE_LORA_DIAGNOSTIC_SMOKE` disabled.
For a controlled test, enable it on exactly one Heltec V3 build. That node
transmits one synthetic packet at each of 1, 2, 3, 4, and 5 fragments, spaced
12 seconds apart. Keep the receiving node on the normal build.

Capture both serial streams concurrently:

```bash
python tools/lora_hardware_smoke.py PORT_A PORT_B --seconds 90 \
  --json-out /tmp/bitle-lora-smoke.json
```

The capture summarizes TX and completed RX counts by fragment count and retains
per-frame RSSI/SNR. Raw serial output and JSON evidence may contain local device
details, so keep it outside the repository.

Runtime firmware emits a one-minute diagnostic summary containing:

- valid raw RX frames and CRC failures;
- TX attempts/timeouts, retries, ACK RX/TX/misses, and retry exhaustion;
- current/high-water queue depth and queue-full events;
- expired reassemblies and completed packets.
