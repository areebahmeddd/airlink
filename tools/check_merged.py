#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
"""Check a web flasher image against the unsigned build it was signed from.

    check_merged.py <merged.bin> <unsigned-dir>
    check_merged.py --layout <unsigned-dir>

<unsigned-dir> is one board's unsigned release outputs, as CI attests them.
The images and their offsets come from the attested build alone: the
bootloader at 0, the partition table at its offset, and the OTA data and the
app where that table puts them. The build's flash_args files are not
attested, so nothing is read from them. Each image must sit in the merged
image at its offset: the partition table and OTA data byte for byte, the
bootloader and app as built with only their Secure Boot signature block after
them (signing pads to a 4 KiB boundary and appends one 4 KiB sector). The OTA
manifest may fill its own bytes at the manifest partition. Every other byte
must be erased flash, 0xFF: a board's first boot encrypts what it finds in its
data partitions, so anything planted there (NVS keys, settings) would be taken
as its own. The signatures themselves are left to the chip, and the manifest
to the nodes.

--layout prints the same images as "offset file" lines, which
tools/release_sign.sh merges, so the image it cuts is the one checked here.
"""

from __future__ import annotations

import sys
from pathlib import Path

SECTOR = 4096
# Both targets in tools/boards.py (ESP32-S3, ESP32-C6) boot from offset 0.
BOOTLOADER_OFFSET = 0x0
# CONFIG_PARTITION_TABLE_OFFSET in sdkconfig.defaults.
PARTITION_TABLE_OFFSET = 0x10000
BOOTLOADER = "bootloader/bootloader.bin"
TABLE = "partition_table/partition-table.bin"
APP = "airlink.bin"
OTA_DATA = "ota_data_initial.bin"
# Secure Boot V2 signs these; the others go as built.
SIGNED = {BOOTLOADER, APP}
# tools/ota_manifest.py MANIFEST_LEN: the fields and the Ed25519 signature.
MANIFEST_LEN = 125


def partition_offset(table: bytes, label: str) -> int:
    # 32-byte entries: magic 0x50AA (little-endian), type, subtype, offset,
    # size, a 16-byte label and flags; the first entry without the magic ends it.
    for at in range(0, len(table) - 31, 32):
        entry = table[at : at + 32]
        if entry[:2] != b"\xaa\x50":
            break
        if entry[12:28].rstrip(b"\0").decode("ascii", "replace") == label:
            return int.from_bytes(entry[4:8], "little")
    raise SystemExit(f"no {label} partition in the partition table")


def layout(directory: Path) -> list[tuple[int, str]]:
    table = (directory / TABLE).read_bytes()
    return [
        (BOOTLOADER_OFFSET, BOOTLOADER),
        (PARTITION_TABLE_OFFSET, TABLE),
        (partition_offset(table, "otadata"), OTA_DATA),
        (partition_offset(table, "ota_0"), APP),
    ]


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[1] == "--layout":
        for offset, file in layout(Path(argv[2])):
            print(f"{offset:#x} {file}")
        return 0
    if len(argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    merged = Path(argv[1]).read_bytes()
    directory = Path(argv[2])
    failed = False
    allowed = []
    for offset, file in layout(directory):
        built = (directory / file).read_bytes()
        if merged[offset : offset + len(built)] != built:
            print(f"{argv[1]}: {file} at {offset:#x} is not the attested build", file=sys.stderr)
            failed = True
        end = offset + len(built)
        if file in SIGNED:
            end = (end + SECTOR - 1) // SECTOR * SECTOR + SECTOR
        allowed.append((offset, end))
    manifest = partition_offset((directory / TABLE).read_bytes(), "manifest")
    allowed.append((manifest, manifest + MANIFEST_LEN))
    at = 0
    for start, end in [*sorted(allowed), (len(merged), len(merged))]:
        gap = merged[at:start]
        if gap.count(0xFF) != len(gap):
            first = at + next(i for i, b in enumerate(gap) if b != 0xFF)
            print(f"{argv[1]}: bytes at {first:#x} lie outside every attested image", file=sys.stderr)
            failed = True
        at = max(at, end)
    if not failed:
        print(f"{argv[1]}: matches {directory}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
