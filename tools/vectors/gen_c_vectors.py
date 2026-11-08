#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
"""Turn the test vectors into a C header for the host tests.

Three of the JSON files in test/vectors/ are copies of Airhop's fixtures:
bitchat-ios.json, recorded from bitchat-ios itself; courier-test-vectors-bitchat.json,
bitchat-ios's own courier vectors; and courier-test-vectors.json, Airhop's golden
file, checked against Airhop's code.
The fourth, spec-vectors.json, is written by tools/vectors/gen_spec_vectors.py.
The host build regenerates the header in its build directory:

    python3 tools/vectors/gen_c_vectors.py test/vectors build-host/generated/vectors.h
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def expand(hex_text: str | None) -> bytes:
    """Hex, or the fixture's compact 'repeat:xx*N' for a long run of one byte."""
    if hex_text is None:
        return b""
    if hex_text.startswith("repeat:"):
        byte, count = hex_text[len("repeat:") :].split("*")
        return bytes.fromhex(byte) * int(count)
    return bytes.fromhex(hex_text)


def c_bytes(data: bytes) -> str:
    if not data:
        return "NULL, 0"
    body = ",".join(f"0x{b:02x}" for b in data)
    return f"(const uint8_t[]){{{body}}}, {len(data)}"


def c_bool(value: object) -> str:
    return "true" if value else "false"


def c_str(text: str | None) -> str:
    """A C string literal of the text's UTF-8 bytes: printable ASCII as is, every
    other byte as a three-digit octal escape, which, unlike a hex escape, never
    runs on into the characters after it."""
    if text is None:
        return "NULL"
    backslash = chr(0x5C)
    out = []
    for b in text.encode("utf-8"):
        if b in (0x22, 0x5C):
            out.append(backslash + chr(b))
        elif 0x20 <= b < 0x7F:
            out.append(chr(b))
        else:
            out.append(f"{backslash}{b:03o}")
    return '"' + "".join(out) + '"'


def packet_cases(cases: list[dict[str, Any]]) -> list[str]:
    out = []
    for c in cases:
        e = c["expected"]
        if e.get("unpadded") is None:
            continue
        out.append(
            "    {"
            f".name = {c_str(c['name'])}, "
            f".unpadded = {{{c_bytes(expand(e['unpadded']))}}}, "
            f".padded = {{{c_bytes(expand(e['padded']))}}}, "
            f".preimage = {{{c_bytes(expand(e['signing_preimage']))}}}, "
            f".payload = {{{c_bytes(expand(e['decoded_payload']))}}}, "
            f".ttl = {e['decoded_ttl']}, "
            f".flags = {e['decoded_flags']}, "
            f".has_recipient = {c_bool(e['decoded_recipient_id'])}, "
            f".route_count = {len(e['decoded_route']) if e['decoded_route'] else 0}, "
            f".has_signature = {c_bool(e['decoded_signature'])}"
            "},"
        )
    return out


def decode_cases(cases: list[dict[str, Any]]) -> list[str]:
    out = []
    for c in cases:
        e = c["expected"]
        out.append(
            "    {"
            f".name = {c_str(c['name'])}, "
            f".bytes = {{{c_bytes(expand(c['input']['bytes']))}}}, "
            f".decodes = {c_bool(e['decodes'])}, "
            f".payload = {{{c_bytes(expand(e.get('payload')))}}}"
            "},"
        )
    return out


def padding_cases(cases: list[dict[str, Any]]) -> list[str]:
    return [
        "    {"
        f".data = {{{c_bytes(expand(c['input']['data']))}}}, "
        f".target = {c['input']['target']}, "
        f".padded = {{{c_bytes(expand(c['expected']['padded']))}}}"
        "},"
        for c in cases
    ]


def block_cases(cases: list[dict[str, Any]]) -> list[str]:
    return [f"    {{{c['input']['size']}, {c['expected']['block']}}}," for c in cases]


def announce_cases(cases: list[dict[str, Any]]) -> list[str]:
    out = []
    for c in cases:
        e = c["expected"]
        noise = expand(e.get("noise_public_key"))
        # The node takes only 32-byte keys; bitchat-ios also decodes a short
        # Noise key it can never bind. Those cases expect a refusal here.
        decodes = e["decodes"] and len(noise) == 32
        out.append(
            "    {"
            f".name = {c_str(c['name'])}, "
            f".bytes = {{{c_bytes(expand(c['input']['bytes']))}}}, "
            f".decodes = {c_bool(decodes)}, "
            f".nickname = {c_str(e.get('nickname'))}, "
            f".noise = {{{c_bytes(noise)}}}, "
            f".signing = {{{c_bytes(expand(e.get('signing_public_key')))}}}"
            "},"
        )
    return out


def compress_cases(cases: list[dict[str, Any]]) -> list[str]:
    out = []
    for c in cases:
        compressed = c["expected"].get("compressed")
        if compressed is None:
            continue
        out.append(
            "    {"
            f".name = {c_str(c['name'])}, "
            f".plain = {{{c_bytes(expand(c['input']['payload']))}}}, "
            f".compressed = {{{c_bytes(expand(compressed))}}}"
            "},"
        )
    return out


def fragment_cases(cases: list[dict[str, Any]]) -> list[str]:
    out = []
    for c in cases:
        e = c["expected"]
        pieces = e["fragments"]
        joined = ",\n        ".join(f"{{{c_bytes(expand(p['encoded_padded']))}}}" for p in pieces)
        out.append(f"    {{.name = {c_str(c['name'])}, .count = {len(pieces)}, .pieces = {{\n        {joined}}}}},")
    return out


def peer_id_cases(cases: list[dict[str, Any]]) -> list[str]:
    return [
        "    {"
        f".noise = {{{c_bytes(expand(c['input']['noise_public_key']))}}}, "
        f".peer_id = {{{c_bytes(expand(c['expected']['peer_id']))}}}"
        "},"
        for c in cases
    ]


def table(name: str, kind: str, rows: list[str]) -> str:
    return f"static const {kind} {name}[] = {{\n" + "\n".join(rows) + "\n};\n"


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])
    ios = json.loads((src / "bitchat-ios.json").read_text(encoding="utf-8"))
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for case in ios["cases"]:
        by_kind.setdefault(case["kind"], []).append(case)
    courier = json.loads((src / "courier-test-vectors-bitchat.json").read_text(encoding="utf-8"))
    airhop_courier = json.loads((src / "courier-test-vectors.json").read_text(encoding="utf-8"))

    max_pieces = max(len(c["expected"]["fragments"]) for c in by_kind["fragment_payload"])
    parts = [
        "// Generated by tools/vectors/gen_c_vectors.py from test/vectors/. Do not edit.\n",
        "#pragma once\n\n#include <stdbool.h>\n#include <stddef.h>\n#include <stdint.h>\n\n",
        "typedef struct {\n    const uint8_t *data;\n    size_t len;\n} vec_bytes_t;\n\n",
        "typedef struct {\n    const char *name;\n    vec_bytes_t unpadded, padded, preimage, payload;\n"
        "    unsigned ttl, flags;\n    bool has_recipient;\n    unsigned route_count;\n    bool has_signature;\n"
        "} vec_packet_t;\n\n",
        "typedef struct {\n    const char *name;\n    vec_bytes_t bytes;\n    bool decodes;\n    vec_bytes_t payload;\n"
        "} vec_decode_t;\n\n",
        "typedef struct {\n    vec_bytes_t data;\n    size_t target;\n    vec_bytes_t padded;\n} vec_pad_t;\n\n",
        "typedef struct {\n    size_t size;\n    size_t block;\n} vec_block_t;\n\n",
        "typedef struct {\n    const char *name;\n    vec_bytes_t bytes;\n    bool decodes;\n"
        "    const char *nickname;\n    vec_bytes_t noise, signing;\n} vec_announce_t;\n\n",
        "typedef struct {\n    const char *name;\n    vec_bytes_t plain, compressed;\n} vec_compress_t;\n\n",
        f"typedef struct {{\n    const char *name;\n    size_t count;\n    vec_bytes_t pieces[{max_pieces}];\n"
        "} vec_fragments_t;\n\n",
        "typedef struct {\n    vec_bytes_t noise, peer_id;\n} vec_peer_id_t;\n\n",
        table("VEC_PACKETS", "vec_packet_t", packet_cases(by_kind["packet_encode"])),
        table(
            "VEC_DECODES",
            "vec_decode_t",
            decode_cases(by_kind["packet_decode_reject"] + by_kind["packet_decode_accept"]),
        ),
        table("VEC_PADDING", "vec_pad_t", padding_cases(by_kind["padding"])),
        table("VEC_BLOCKS", "vec_block_t", block_cases(by_kind["optimal_block_size"])),
        table("VEC_ANNOUNCES", "vec_announce_t", announce_cases(by_kind["announce_decode"])),
        table("VEC_COMPRESS", "vec_compress_t", compress_cases(by_kind["compress"])),
        table("VEC_FRAGMENTS", "vec_fragments_t", fragment_cases(by_kind["fragment_payload"])),
        table("VEC_PEER_IDS", "vec_peer_id_t", peer_id_cases(by_kind["peer_id"])),
    ]

    inputs = courier["inputs"]
    signing = courier["packetSigning"]
    parts.append(
        "\n// bitchat-ios's courier test vectors, as Airhop's fixtures keep them.\n"
        f"static const vec_bytes_t VEC_COURIER_NOISE_KEY = {{{c_bytes(expand(inputs['noiseStaticKey']))}}};\n"
        f"static const uint32_t VEC_COURIER_EPOCH_DAY = {courier['recipientTagDerivation']['epochDay']}u;\n"
        "static const vec_bytes_t VEC_COURIER_TAG = "
        f"{{{c_bytes(expand(courier['recipientTagDerivation']['expected']))}}};\n"
        f"static const vec_bytes_t VEC_COURIER_ENVELOPE = {{{c_bytes(expand(courier['envelopeTLV']['encoded']))}}};\n"
        f"static const vec_bytes_t VEC_COURIER_PACKET_UNSIGNED = {{{c_bytes(expand(signing['unsignedUnpadded']))}}};\n"
        f"static const vec_bytes_t VEC_COURIER_PREIMAGE = {{{c_bytes(expand(signing['signingPreimage']))}}};\n"
        f"static const vec_bytes_t VEC_COURIER_SEED = {{{c_bytes(expand(inputs['signingSeed']))}}};\n"
        f"static const vec_bytes_t VEC_COURIER_PUBLIC = {{{c_bytes(expand(courier['signature']['publicKey']))}}};\n"
    )
    tag_rows = [
        f"    {{{case['epochDay']}u, {{{c_bytes(expand(case['tagHex']))}}}}},"
        for case in airhop_courier["recipientTag"]["cases"]
    ]
    parts.append(
        f"static const vec_bytes_t VEC_TAG_KEY = "
        f"{{{c_bytes(expand(airhop_courier['recipientTag']['recipientNoisePublicKeyHex']))}}};\n"
        "typedef struct {\n    uint32_t epoch_day;\n    vec_bytes_t tag;\n} vec_tag_t;\n"
        + table("VEC_TAGS", "vec_tag_t", tag_rows)
    )
    spec = json.loads((src / "spec-vectors.json").read_text(encoding="utf-8"))
    spec_rows = [
        "    {"
        f".name = {c_str(p['name'])}, "
        f".frame = {{{c_bytes(expand(p['frame']))}}}, "
        f".preimage = {{{c_bytes(expand(p['preimage']))}}}, "
        f".packet_id = {{{c_bytes(expand(p['packet_id']))}}}, "
        f".public_key = {{{c_bytes(expand(p['public_key']))}}}"
        "},"
        for p in spec["packets"]
    ]
    gcs_rows = [
        "    {"
        f".count = {g['count']}, .max_bytes = {g['max_bytes']}, "
        f".ids = {{{c_bytes(b''.join(expand(i) for i in g['ids']))}}}, "
        f".p = {g['p']}, .m = {g['m']}u, "
        f".data = {{{c_bytes(expand(g['data']))}}}, "
        f".included = {g['included']}"
        "},"
        for g in spec["gcs"]
    ]
    noise = spec["noise_xx"]
    parts.append(
        "\n// tools/vectors/gen_spec_vectors.py: written from PROTOCOLS.md and the Noise spec, sharing no code.\n"
        "typedef struct {\n    const char *name;\n    vec_bytes_t frame, preimage, packet_id, public_key;\n"
        "} vec_spec_packet_t;\n"
        + table("VEC_SPEC_PACKETS", "vec_spec_packet_t", spec_rows)
        + "typedef struct {\n    size_t count, max_bytes;\n    vec_bytes_t ids;\n    unsigned p;\n    uint32_t m;\n"
        "    vec_bytes_t data;\n    size_t included;\n} vec_gcs_t;\n"
        + table("VEC_GCS", "vec_gcs_t", gcs_rows)
        + "".join(
            f"static const vec_bytes_t VEC_NOISE_{k.upper()} = {{{c_bytes(expand(v))}}};\n" for k, v in noise.items()
        )
    )
    ota = spec["ota_manifest"]
    ota_rows = [
        f"    {{.name = {c_str(c['name'])}, .manifest = {{{c_bytes(expand(c['manifest']))}}}, "
        f".accept = {c_bool(c['accept'])}}},"
        for c in ota["cases"]
    ]
    parts.append(
        f"static const vec_bytes_t VEC_OTA_OWNER = {{{c_bytes(expand(ota['owner']))}}};\n"
        f"static const char *const VEC_OTA_BOARD = {c_str(ota['board'])};\n"
        f"static const uint32_t VEC_OTA_VERSION = {ota['version']}u;\n"
        f"static const uint32_t VEC_OTA_SIZE = {ota['size']}u;\n"
        f"static const vec_bytes_t VEC_OTA_SHA256 = {{{c_bytes(expand(ota['sha256']))}}};\n"
        "typedef struct {\n    const char *name;\n    vec_bytes_t manifest;\n    bool accept;\n} vec_ota_t;\n"
        + table("VEC_OTA_MANIFESTS", "vec_ota_t", ota_rows)
    )
    board = spec["board"]
    board_rows = [
        f"    {{.name = {c_str(c['name'])}, .payload = {{{c_bytes(expand(c['payload']))}}}, "
        f".check = {c_bool(c['check'])}, .live = {c_bool(c['live'])}, .urgent = {c_bool(c['urgent'])}}},"
        for c in board["cases"]
    ]
    live_rows = [
        f"    {{.name = {c_str(c['name'])}, .video = {c_bool(c['kind'] == 'video')}, "
        f".payload = {{{c_bytes(expand(c['payload']))}}}, .accept = {c_bool(c['accept'])}}},"
        for c in spec["live"]
    ]
    parts.append(
        f"static const uint64_t VEC_BOARD_NOW = {board['now']}ull;\n"
        "typedef struct {\n    const char *name;\n    vec_bytes_t payload;\n"
        "    bool check, live, urgent;\n} vec_board_t;\n"
        + table("VEC_BOARDS", "vec_board_t", board_rows)
        + "typedef struct {\n    const char *name;\n    bool video;\n    vec_bytes_t payload;\n"
        "    bool accept;\n} vec_live_t;\n" + table("VEC_LIVE", "vec_live_t", live_rows)
    )
    inflate_rows = [
        f"    {{.name = {c_str(c['name'])}, .stream = {{{c_bytes(expand(c['stream']))}}}, .size = {c['size']}u, "
        f".accept = {c_bool(c['accept'])}, .sha256 = {{{c_bytes(expand(c['sha256']))}}}}},"
        for c in spec["inflate"]
    ]
    parts.append(
        "typedef struct {\n    const char *name;\n    vec_bytes_t stream;\n    uint32_t size;\n"
        "    bool accept;\n    vec_bytes_t sha256;\n} vec_inflate_t;\n"
        + table("VEC_INFLATE", "vec_inflate_t", inflate_rows)
    )
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text("".join(parts), encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
