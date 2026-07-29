#!/usr/bin/env python3
"""Capture concurrent LoRa diagnostics from two serial-connected nodes."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import queue
import re
import threading
import time

import serial


PACKET_RE = re.compile(r"trunk RX packet len=(\d+).*frags=(\d+)")
RAW_RE = re.compile(r"trunk raw RX len=(\d+) rssi=(-?\d+) snr=(-?\d+)")
TX_RE = re.compile(r"trunk TX .*len=(\d+) frags=(\d+)")


def reader(label: str, port: str, output: queue.Queue[tuple[str, str]], stop: threading.Event):
    with serial.Serial(port, 115200, timeout=0.2) as stream:
        while not stop.is_set():
            line = stream.readline().decode("utf-8", errors="replace").rstrip()
            if line:
                output.put((label, line))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("ports", nargs=2, help="serial ports for the two nodes")
    parser.add_argument("--seconds", type=int, default=75)
    parser.add_argument("--json-out")
    args = parser.parse_args()

    messages: queue.Queue[tuple[str, str]] = queue.Queue()
    stop = threading.Event()
    threads = [
        threading.Thread(target=reader, args=(f"node-{index + 1}", port, messages, stop))
        for index, port in enumerate(args.ports)
    ]
    for thread in threads:
        thread.start()

    summary: dict[str, dict[str, object]] = {
        "node-1": {"rx_fragments": Counter(), "tx_fragments": Counter(), "raw": []},
        "node-2": {"rx_fragments": Counter(), "tx_fragments": Counter(), "raw": []},
    }
    deadline = time.monotonic() + args.seconds
    try:
        while time.monotonic() < deadline:
            try:
                label, line = messages.get(timeout=0.25)
            except queue.Empty:
                continue
            print(f"[{label}] {line}")
            if match := PACKET_RE.search(line):
                summary[label]["rx_fragments"][match.group(2)] += 1
            if match := TX_RE.search(line):
                summary[label]["tx_fragments"][match.group(2)] += 1
            if match := RAW_RE.search(line):
                summary[label]["raw"].append(
                    {
                        "length": int(match.group(1)),
                        "rssi_dbm": int(match.group(2)),
                        "snr_db": int(match.group(3)),
                    }
                )
    finally:
        stop.set()
        for thread in threads:
            thread.join()

    serializable = {
        label: {
            "rx_fragments": dict(values["rx_fragments"]),
            "tx_fragments": dict(values["tx_fragments"]),
            "raw": values["raw"],
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
