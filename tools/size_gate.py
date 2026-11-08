#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
"""Fail when a build's flash or static internal RAM grew past its baseline.

    size_gate.py <board> <size.json> [--write]

<size.json> is `idf.py size --format json2` for the board's dev build. A
growth of more than 2 % of flash (at least 8 KiB) or 1 KiB of static internal
RAM fails; --write records the current numbers as the new baseline, for a
change that grows on purpose (and says so in its commit).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from boards import boards

BASELINE = Path(__file__).resolve().parent.parent / "test" / "size-baseline.json"
FLASH_MARGIN = 0.02
FLASH_FLOOR = 8 * 1024
RAM_MARGIN = 1024


def measure(report: dict) -> dict[str, int]:
    ram = next(region for region in report["layout"] if region["name"] == "DIRAM")
    return {"image_bytes": report["total_size"], "static_ram_bytes": ram["used"]}


def main(argv: list[str]) -> int:
    if len(argv) not in (3, 4) or (len(argv) == 4 and argv[3] != "--write"):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    board, report = argv[1], json.loads(Path(argv[2]).read_text(encoding="utf-8"))
    now = measure(report)
    baseline = json.loads(BASELINE.read_text(encoding="utf-8")) if BASELINE.exists() else {}
    if len(argv) == 4:
        baseline[board] = now
        # In the board list's order; a board no longer listed drops out.
        ordered = {name: baseline[name] for name in boards() if name in baseline}
        BASELINE.write_text(json.dumps(ordered, indent=2) + "\n", encoding="utf-8")
        print(f"{board}: baseline {now}")
        return 0
    if board not in baseline:
        print(f"{board}: no baseline; record one with --write", file=sys.stderr)
        return 1
    was = baseline[board]
    flash_limit = was["image_bytes"] + max(int(was["image_bytes"] * FLASH_MARGIN), FLASH_FLOOR)
    ram_limit = was["static_ram_bytes"] + RAM_MARGIN
    failed = now["image_bytes"] > flash_limit or now["static_ram_bytes"] > ram_limit
    print(
        f"{board}: image {now['image_bytes']} (baseline {was['image_bytes']}, limit {flash_limit}), "
        f"static RAM {now['static_ram_bytes']} (baseline {was['static_ram_bytes']}, limit {ram_limit})"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
