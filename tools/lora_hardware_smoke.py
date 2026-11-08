#!/usr/bin/env python3
"""Capture concurrent LoRa diagnostics from serial-connected nodes."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import queue
import re
import threading
import time

import serial


PACKET_RE = re.compile(r"trunk(?: v\d+)? RX packet len=(\d+).*frags=(\d+)")
RAW_RE = re.compile(
    r"trunk(?: v\d+)? raw RX len=(\d+) rssi=(-?\d+) snr=(-?\d+)"
)
TX_RE = re.compile(r"trunk (?:TX|accepted) .*len=(\d+) frags=(\d+)")
SMOKE_RE = re.compile(
    r"diagnostic smoke enqueue len=(\d+) expected_frags=(\d+) addressed=(\d+)"
)
FORWARD_SMOKE_RE = re.compile(
    r"diagnostic forwarding smoke enqueue len=(\d+) expected_frags=(\d+)"
)
PROFILE_RE = re.compile(
    r"trunk up: board=(\S+) region=(\w+) ([0-9.]+) MHz "
    r"SF(\d+) BW(\d+) "
    r"CR4/(\d+) preamble=(\d+) sync=0x([0-9a-fA-F]+).*"
    r"phy_verified=(\d+)"
)
DIAG_RE = re.compile(
    r"tmo=(\d+).*radio_err=(\d+).*busy_tmo=(\d+).*"
    r"recover=(\d+)/(\d+).*tx_watchdog=(\d+)"
)
SCHEDULER_DIAG_RE = re.compile(
    r"q_full=(\d+) q=(\d+)/(\d+).*"
    r"admit=(\d+)/(\d+)/(\d+)/(\d+) "
    r"defer=(\d+)/(\d+)/(\d+)/(\d+) "
    r"policy=(\d+) release=(\d+) cancel=(\d+)"
)
PROTOCOL_DIAG_RE = re.compile(
    r"malformed=(\d+) unsupported=(\d+) ack_reject=(\d+) "
    r"neighbors=(\d+) collision=(\d+)"
)
RELIABILITY_DIAG_RE = re.compile(
    r"bitmap=(\d+) final=(\d+) dup=(\d+)/(\d+) "
    r"abort=(\d+)/(\d+) invalid=(\d+) resource=(\d+)"
)
CONTROL_RE = re.compile(
    r"v3 control (TX|RX) kind=(\d+) value=0x([0-9a-fA-F]{2})"
)
BEACON_TX_RE = re.compile(
    r"trunk beacon TX freshness=(\d+) repeat=(\d+)"
)
BEACON_RX_RE = re.compile(
    r"trunk beacon RX freshness=(\d+) result=(\d+)"
)
CHANNEL_DIAG_RE = re.compile(
    r"beacon=(\d+)/(\d+) stale=(\d+) budget=(\d+) "
    r"backoff=(\d+) announce_tx=(\d+)"
)
FORWARD_DIAG_RE = re.compile(
    r"forward=(\d+) suppress=(\d+) dup_net=(\d+) "
    r"hop_drop=(\d+) route_fail=(\d+)"
)
FORWARD_TX_RE = re.compile(
    r"trunk accepted .*hops=(\d+)/(\d+) forwarded=(\d+)"
)
FORWARD_RX_RE = re.compile(
    r"trunk v\d+ RX packet .*hops=(\d+)/(\d+)"
)
ADAPTIVE_TX_RE = re.compile(
    r"trunk accepted .*link=(\d+) chunk=(\d+) rounds=(\d+)"
)
LINK_METRICS_RE = re.compile(
    r"link metrics profile=(\d+) rssi_x10=(-?\d+) snr_x10=(-?\d+) "
    r"data=(\d+) ack=(\d+) retries_x100=(\d+) latency_ms=(\d+) "
    r"samples=(\d+)/(\d+)/(\d+)"
)
AUTHENTICATED_NEIGHBOR_RE = re.compile(
    r"\bauthenticated neighbor result=\d+"
)


def reader(
    label: str,
    port: str,
    output: queue.Queue[tuple[str, str]],
    stop: threading.Event,
    reset: bool,
):
    with serial.Serial(port, 115200, timeout=0) as stream:
        if reset:
            # Assert EN while keeping GPIO0 deasserted, then release EN.
            stream.dtr = False
            stream.rts = True
            time.sleep(0.1)
            stream.rts = False
            time.sleep(0.1)
        pending = bytearray()
        while not stop.is_set():
            available = stream.in_waiting
            if available == 0:
                stop.wait(0.02)
                continue
            pending.extend(stream.read(available))
            while b"\n" in pending:
                raw_line, _, remainder = pending.partition(b"\n")
                pending = bytearray(remainder)
                line = raw_line.decode(
                    "utf-8", errors="replace"
                ).rstrip("\r")
                if line:
                    output.put((label, line))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "ports", nargs="+", help="serial ports for two or more nodes"
    )
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--json-out")
    parser.add_argument(
        "--reset", action="store_true",
        help="reset all nodes at capture start",
    )
    parser.add_argument("--quiet", action="store_true", help="print only the JSON summary")
    args = parser.parse_args()
    if len(args.ports) < 2:
        parser.error("at least two serial ports are required")

    messages: queue.Queue[tuple[str, str]] = queue.Queue()
    stop = threading.Event()
    threads = [
        threading.Thread(
            target=reader,
            args=(f"node-{index + 1}", port, messages, stop, args.reset),
            daemon=True,
        )
        for index, port in enumerate(args.ports)
    ]
    for thread in threads:
        thread.start()

    summary: dict[str, dict[str, object]] = {
        f"node-{index + 1}": {
            "rx_fragments": Counter(),
            "tx_fragments": Counter(),
            "raw": [],
            "events": Counter(),
            "diagnostics": [],
            "link_metrics": [],
            "profile": None,
        }
        for index in range(len(args.ports))
    }
    deadline = time.monotonic() + args.seconds
    try:
        while time.monotonic() < deadline:
            try:
                label, line = messages.get(timeout=0.25)
            except queue.Empty:
                continue
            if not args.quiet:
                print(f"[{label}] {line}")
            if match := PACKET_RE.search(line):
                summary[label]["rx_fragments"][match.group(2)] += 1
            if match := TX_RE.search(line):
                summary[label]["tx_fragments"][match.group(2)] += 1
            if match := SMOKE_RE.search(line):
                mode = "addressed" if match.group(3) == "1" else "broadcast"
                summary[label]["events"][f"smoke_{mode}"] += 1
            if FORWARD_SMOKE_RE.search(line):
                summary[label]["events"]["smoke_forwarding_broadcast"] += 1
            if match := RAW_RE.search(line):
                summary[label]["raw"].append(
                    {
                        "length": int(match.group(1)),
                        "rssi_dbm": int(match.group(2)),
                        "snr_db": int(match.group(3)),
                    }
                )
            if match := PROFILE_RE.search(line):
                summary[label]["profile"] = {
                    "board": match.group(1),
                    "region": match.group(2),
                    "frequency_mhz": float(match.group(3)),
                    "spreading_factor": int(match.group(4)),
                    "bandwidth_hz": int(match.group(5)),
                    "coding_rate_denominator": int(match.group(6)),
                    "preamble_symbols": int(match.group(7)),
                    "sync_word": int(match.group(8), 16),
                    "phy_verified": bool(int(match.group(9))),
                }
            if match := DIAG_RE.search(line):
                summary[label]["diagnostics"].append(
                    {
                        "radio_timeouts": int(match.group(1)),
                        "radio_command_errors": int(match.group(2)),
                        "busy_timeouts": int(match.group(3)),
                        "recoveries": int(match.group(4)),
                        "recovery_failures": int(match.group(5)),
                        "tx_watchdog_recoveries": int(match.group(6)),
                    }
                )
            if match := SCHEDULER_DIAG_RE.search(line):
                scheduler_diag = {
                    "queue_full": int(match.group(1)),
                    "pool_depth": int(match.group(2)),
                    "pool_high_water": int(match.group(3)),
                    "accepted_by_priority": [
                        int(match.group(index)) for index in range(4, 8)
                    ],
                    "deferred_by_priority": [
                        int(match.group(index)) for index in range(8, 12)
                    ],
                    "policy_drops": int(match.group(12)),
                    "released": int(match.group(13)),
                    "cancelled": int(match.group(14)),
                }
                if summary[label]["diagnostics"]:
                    summary[label]["diagnostics"][-1].update(scheduler_diag)
                else:
                    summary[label]["diagnostics"].append(scheduler_diag)
            if match := PROTOCOL_DIAG_RE.search(line):
                protocol_diag = {
                    "malformed_frames": int(match.group(1)),
                    "unsupported_versions": int(match.group(2)),
                    "rejected_acks": int(match.group(3)),
                    "neighbor_count": int(match.group(4)),
                    "neighbor_collisions": int(match.group(5)),
                }
                if summary[label]["diagnostics"]:
                    summary[label]["diagnostics"][-1].update(protocol_diag)
                else:
                    summary[label]["diagnostics"].append(protocol_diag)
            if match := RELIABILITY_DIAG_RE.search(line):
                reliability_diag = {
                    "bitmap_acks": int(match.group(1)),
                    "complete_acks": int(match.group(2)),
                    "duplicate_fragments": int(match.group(3)),
                    "duplicate_transfers": int(match.group(4)),
                    "transfer_aborts_tx": int(match.group(5)),
                    "transfer_aborts_rx": int(match.group(6)),
                    "invalid_reassemblies": int(match.group(7)),
                    "resource_aborts": int(match.group(8)),
                }
                if summary[label]["diagnostics"]:
                    summary[label]["diagnostics"][-1].update(
                        reliability_diag
                    )
                else:
                    summary[label]["diagnostics"].append(
                        reliability_diag
                    )
            if match := CHANNEL_DIAG_RE.search(line):
                channel_diag = {
                    "beacon_tx": int(match.group(1)),
                    "beacon_rx": int(match.group(2)),
                    "beacon_stale": int(match.group(3)),
                    "beacon_budget_deferred": int(match.group(4)),
                    "channel_backoffs": int(match.group(5)),
                    "announce_tx": int(match.group(6)),
                }
                if summary[label]["diagnostics"]:
                    summary[label]["diagnostics"][-1].update(
                        channel_diag
                    )
                else:
                    summary[label]["diagnostics"].append(
                        channel_diag
                    )
            if match := FORWARD_DIAG_RE.search(line):
                forward_diag = {
                    "forwarded_packets": int(match.group(1)),
                    "forward_suppressed": int(match.group(2)),
                    "network_duplicates": int(match.group(3)),
                    "hop_limit_drops": int(match.group(4)),
                    "route_failures": int(match.group(5)),
                }
                if summary[label]["diagnostics"]:
                    summary[label]["diagnostics"][-1].update(
                        forward_diag
                    )
                else:
                    summary[label]["diagnostics"].append(
                        forward_diag
                    )
            if AUTHENTICATED_NEIGHBOR_RE.search(line):
                summary[label]["events"]["authenticated_neighbor"] += 1
            if match := CONTROL_RE.search(line):
                direction = match.group(1).lower()
                kind = int(match.group(2))
                value = int(match.group(3), 16)
                names = {2: "bitmap", 3: "complete", 4: "abort"}
                if kind in names:
                    summary[label]["events"][
                        f"v3_{names[kind]}_{direction}"
                    ] += 1
                    summary[label]["events"][
                        f"v3_{names[kind]}_{direction}_value_{value}"
                    ] += 1
            if match := BEACON_TX_RE.search(line):
                summary[label]["events"]["beacon_tx"] += 1
                summary[label]["events"][
                    f"beacon_tx_repeat_{match.group(2)}"
                ] += 1
            if match := BEACON_RX_RE.search(line):
                summary[label]["events"]["beacon_rx"] += 1
                if int(match.group(2)) == 4:
                    summary[label]["events"]["beacon_stale"] += 1
            if match := FORWARD_TX_RE.search(line):
                if int(match.group(3)):
                    summary[label]["events"]["forwarded_tx"] += 1
                summary[label]["events"][
                    f"tx_hops_{match.group(1)}_of_{match.group(2)}"
                ] += 1
            if match := FORWARD_RX_RE.search(line):
                summary[label]["events"][
                    f"rx_hops_{match.group(1)}_of_{match.group(2)}"
                ] += 1
            if match := ADAPTIVE_TX_RE.search(line):
                summary[label]["events"][
                    f"adaptive_profile_{match.group(1)}"
                ] += 1
                summary[label]["events"][
                    f"adaptive_chunk_{match.group(2)}"
                ] += 1
                summary[label]["events"][
                    f"adaptive_rounds_{match.group(3)}"
                ] += 1
            if match := LINK_METRICS_RE.search(line):
                summary[label]["link_metrics"].append(
                    {
                        "profile": int(match.group(1)),
                        "rssi_x10": int(match.group(2)),
                        "snr_x10": int(match.group(3)),
                        "data_success_pct": int(match.group(4)),
                        "ack_success_pct": int(match.group(5)),
                        "retries_x100": int(match.group(6)),
                        "latency_ms": int(match.group(7)),
                        "signal_samples": int(match.group(8)),
                        "data_samples": int(match.group(9)),
                        "ack_samples": int(match.group(10)),
                    }
                )
            if "duplicate network packet" in line:
                summary[label]["events"][
                    "network_duplicate_suppressed"
                ] += 1
            if "trunk transfer COMPLETE" in line:
                summary[label]["events"]["transfer_complete"] += 1
            if "TX watchdog expired" in line:
                summary[label]["events"]["tx_watchdog_expired"] += 1
            if "radio recovered on attempt" in line:
                summary[label]["events"]["radio_recovered"] += 1
            if "diagnostic: suppressed one TX_DONE" in line:
                summary[label]["events"]["tx_done_suppressed"] += 1
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=1)

    serializable = {
        label: {
            "rx_fragments": dict(values["rx_fragments"]),
            "tx_fragments": dict(values["tx_fragments"]),
            "raw": values["raw"],
            "events": dict(values["events"]),
            "diagnostics": values["diagnostics"],
            "link_metrics": values["link_metrics"],
            "profile": values["profile"],
        }
        for label, values in summary.items()
    }
    print(json.dumps(serializable, indent=2, sort_keys=True))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as output:
            json.dump(serializable, output, indent=2, sort_keys=True)
            output.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
