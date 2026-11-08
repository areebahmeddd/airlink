#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
"""The boards the firmware builds for, read from config/board.<name>.

    boards.py                    every board's name, one per line
    boards.py <board> <field>    one field: target, flash or title

A board file is the one place a board is declared: it selects the board's
Kconfig choice and sets its target and flash size, and the choice's prompt in
main/Kconfig.projbuild is its title. Scripts and tools read boards from here
rather than keeping lists of their own.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# OTA manifests carry the board's name in a 16-byte field.
NAME_MAX = 16


@dataclass(frozen=True)
class Board:
    name: str
    target: str
    flash: str
    title: str


def _setting(text: str, pattern: str, path: Path) -> str:
    match = re.search(pattern, text, re.MULTILINE)
    if not match:
        raise SystemExit(f"{path}: no line matching {pattern}")
    return match.group(1)


def boards() -> dict[str, Board]:
    kconfig = (ROOT / "main" / "Kconfig.projbuild").read_text(encoding="utf-8")
    titles = dict(re.findall(r'^\s*config (AH_BOARD_\w+)\n\s*bool "([^"]+)"', kconfig, re.MULTILINE))
    found = {}
    rank = {}
    for path in sorted((ROOT / "config").glob("board.*")):
        text = path.read_text(encoding="utf-8")
        symbol = _setting(text, r"^CONFIG_(AH_BOARD_\w+)=y$", path)
        if symbol not in titles:
            raise SystemExit(f"{path}: {symbol} is not a board in main/Kconfig.projbuild")
        name = path.name.removeprefix("board.")
        rank[name] = list(titles).index(symbol)
        if len(name) > NAME_MAX:
            raise SystemExit(f"{path}: a board name is at most {NAME_MAX} characters")
        found[name] = Board(
            name=name,
            target=_setting(text, r'^CONFIG_IDF_TARGET="(\w+)"$', path),
            flash=_setting(text, r"^CONFIG_ESPTOOLPY_FLASHSIZE_(\d+MB)=y$", path),
            title=titles[symbol],
        )
    # In the order main/Kconfig.projbuild offers them, the recommended first.
    return {name: found[name] for name in sorted(found, key=rank.__getitem__)}


def main(argv: list[str]) -> int:
    known = boards()
    if len(argv) == 1:
        print("\n".join(known))
        return 0
    if len(argv) != 3 or argv[2] not in ("target", "flash", "title"):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    board = known.get(argv[1])
    if board is None:
        print(f"unknown board {argv[1]!r}: one of {', '.join(known)}", file=sys.stderr)
        return 2
    print(getattr(board, argv[2]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
