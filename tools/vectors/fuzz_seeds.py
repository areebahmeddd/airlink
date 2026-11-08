#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
"""Seed corpora for the libFuzzer harnesses, cut from the test vectors.

Each harness gets the frames and payloads it would meet first: bitchat-ios's
recorded packets, the spec generator's signed v1 and v2 packets, DEFLATE
streams, Noise transcript and filters, and the payloads inside them, framed
the way the harness reads its input.

    tools/vectors/fuzz_seeds.py test/vectors build-fuzz/corpus
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
import sys
from collections.abc import Iterator
from pathlib import Path

TRUNK_PREFIX = bytes([0x41, 0x4C, 1])


def trunk_tag(key: bytes, frame: bytes, tags_at: int, count: int) -> bytes:
    """The tag under `key` for a trunk frame: HMAC-SHA256 over it without its tags."""
    message = frame[:tags_at] + frame[tags_at + 8 * count :]
    return hmac.new(key, message, hashlib.sha256).digest()[:8]


def trunk_seeds() -> Iterator[bytes]:
    """fuzz_trunk inputs: length-prefixed frames from a node the harness meets.

    The harness's pair key with a node is the node's static key, so these are
    tagged as that node would tag them (`ah_trunk_frame.h` gives the layout): its
    beacon, a piece of a two-piece transfer asking for an answer, the piece
    that completes it, and an ACK and a COMPLETE for the harness's first
    transfer, whose number follows from its seed (0x02B9B24C, two pieces).
    """
    key = bytes(range(0x60, 0x80))
    source = hashlib.sha256(key).digest()[:8]

    def frame(kind: int, flags: int, body: bytes, tags_at: int, count: int, tail: bytes = b"") -> bytes:
        blank = TRUNK_PREFIX + bytes([kind, flags, 14]) + source + body + bytes(8 * count) + tail
        tag = trunk_tag(key, blank, tags_at, count)
        return blank[:tags_at] + tag * count + blank[tags_at + 8 * count :]

    beacon = TRUNK_PREFIX + bytes([4, 0, 14]) + source + key + bytes([0])
    first = frame(1, 1, (7).to_bytes(4, "big") + bytes([0, 2, 1]), 21, 1, bytes(range(40)))
    last = frame(1, 1, (7).to_bytes(4, "big") + bytes([1, 2, 1]), 21, 1, bytes(range(40)))
    ack = frame(2, 0, (0x02B9B24C).to_bytes(4, "big") + bytes([1, 2]), 20, 1)
    done = frame(3, 0, (0x02B9B24C).to_bytes(4, "big") + bytes([3, 2]), 20, 1)
    run = [beacon, first, last, ack, done]
    yield b"".join(bytes([len(f)]) + f for f in run)
    yield bytes([len(beacon)]) + beacon


def frames(vectors: Path) -> Iterator[bytes]:
    ios = json.loads((vectors / "bitchat-ios.json").read_text(encoding="utf-8"))
    for case in ios["cases"]:
        kind = case["kind"]
        if kind == "packet_encode":
            for form in ("padded", "unpadded"):
                if case["expected"].get(form):
                    yield bytes.fromhex(case["expected"][form])
        elif kind in ("packet_decode_accept", "packet_decode_reject"):
            yield bytes.fromhex(case["input"]["bytes"])
        elif kind == "fragment_payload":
            for fragment in case["expected"]["fragments"]:
                yield bytes.fromhex(fragment["encoded_padded"])
    spec = json.loads((vectors / "spec-vectors.json").read_text(encoding="utf-8"))
    for packet in spec["packets"]:
        yield bytes.fromhex(packet["frame"])
    # Each DEFLATE stream as a compressed v1 public message: the header, a
    # zero sender, the 2-byte declared size and the stream.
    for case in spec["inflate"]:
        stream = bytes.fromhex(case["stream"])
        header = bytes([1, 0x02, 7]) + bytes(8) + bytes([0x04]) + struct.pack(">H", 2 + len(stream))
        yield header + bytes(8) + struct.pack(">H", case["size"]) + stream


def payloads(vectors: Path) -> Iterator[tuple[int, bytes]]:
    """(parser selector, payload) as fuzz_parsers reads them."""
    ios = json.loads((vectors / "bitchat-ios.json").read_text(encoding="utf-8"))
    for case in ios["cases"]:
        kind = case["kind"]
        encoded = case["expected"].get("encoded")
        if not encoded:
            continue
        if kind == "announce_tlv":
            yield 0, bytes.fromhex(encoded)
        elif kind == "private_message_tlv":
            yield 3, bytes.fromhex(encoded)
    spec = json.loads((vectors / "spec-vectors.json").read_text(encoding="utf-8"))
    for case in spec["board"]["cases"]:
        yield 1, bytes.fromhex(case["payload"])
    courier = json.loads((vectors / "courier-test-vectors-bitchat.json").read_text(encoding="utf-8"))
    yield 2, bytes.fromhex(courier["envelopeTLV"]["encoded"])
    for case in spec["ota_manifest"]["cases"]:
        yield 6, bytes.fromhex(case["manifest"])
    # A fragment: stream ID, index, total, the inner type, then its data.
    yield 4, bytes(range(8)) + struct.pack(">HHB", 0, 2, 0x02) + b"hello"
    for g in spec["gcs"]:
        data = bytes.fromhex(g["data"])
        yield 7, struct.pack(">BI", g["p"], g["m"]) + data
        # The same filter as a sync request carries it: P, M and DATA TLVs, each
        # a type, a 2-byte length and the value.
        tlvs = struct.pack(">BHB", 0x01, 1, g["p"]) + struct.pack(">BHI", 0x02, 4, g["m"])
        yield 5, tlvs + struct.pack(">BH", 0x03, len(data)) + data
    for case in spec["live"]:
        yield 8, bytes.fromhex(case["payload"])
    # Noise: a stage byte, then the transcript's message for it; then message 1
    # carrying low-order keys (zero and one), whose DH the reply must refuse.
    noise = spec["noise_xx"]
    for stage, name in enumerate(("msg1", "msg2", "msg3", "to_responder")):
        yield 9, bytes([stage]) + bytes.fromhex(noise[name])
    yield 9, bytes([0]) + bytes(32)
    yield 9, bytes([0, 1]) + bytes(31)
    # A filter to build: a 2-byte budget selector (1 + value % 400 bytes), then
    # 8-byte hashes as the node takes them from packet IDs.
    for g in spec["gcs"]:
        hashes = b"".join(hashlib.sha256(bytes.fromhex(i)).digest()[:8] for i in g["ids"])
        yield 10, struct.pack(">H", g["max_bytes"] - 1) + hashes


def write(directory: Path, name: str, data: bytes) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(data)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    vectors, out = Path(argv[1]), Path(argv[2])
    all_frames = list(frames(vectors))
    for i, frame in enumerate(all_frames):
        write(out / "fuzz_frame", f"{i:03}", frame)
        # fuzz_node: link byte, 2-byte length, frame.
        write(out / "fuzz_node", f"{i:03}", bytes([i % 3]) + struct.pack(">H", len(frame)) + frame)
    for i, (selector, payload) in enumerate(payloads(vectors)):
        write(out / "fuzz_parsers", f"{i:03}", bytes([selector]) + payload)
    for i, seed in enumerate(trunk_seeds()):
        write(out / "fuzz_trunk", f"{i:03}", seed)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
