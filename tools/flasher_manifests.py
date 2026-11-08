#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
"""Write the web flasher's ESP Web Tools manifests, one per board, and the list the page offers.

    flasher_manifests.py <site-dir> <version>

Each manifest points at firmware/<board>/airlink-<board>-merged.bin in
the site, the image tools/release_sign.sh merges from offset 0.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from boards import boards

# ESP Web Tools names a chip family the way the ROM reports it.
CHIP_FAMILY = {"esp32s3": "ESP32-S3", "esp32c6": "ESP32-C6"}


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    site, version = Path(argv[1]), argv[2].removeprefix("v")
    manifests = site / "manifests"
    manifests.mkdir(parents=True, exist_ok=True)
    offered = []
    for board in boards().values():
        manifest = {
            "name": f"Airlink for {board.title}",
            "version": version,
            "new_install_prompt_erase": True,
            "builds": [
                {
                    "chipFamily": CHIP_FAMILY[board.target],
                    "parts": [{"path": f"../firmware/{board.name}/airlink-{board.name}-merged.bin", "offset": 0}],
                }
            ],
        }
        (manifests / f"{board.name}.json").write_text(json.dumps(manifest, indent=2) + "\n")
        offered.append({"id": board.name, "title": board.title})
    (manifests / "boards.json").write_text(json.dumps(offered, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
