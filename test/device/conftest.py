# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
"""On-device tests with pytest-embedded (docs/TESTING.md, "On a device").

One board, flashed from its build with its settings erased:
    pytest test/device -m "not lora" --embedded-services esp,idf --erase-all y \
        --app-path build/heltec_v4-dev --port /dev/ttyUSB0

Two LoRa boards of one region:
    AH_REGION=eu pytest test/device -m lora --embedded-services esp,idf --count 2 \
        --app-path "build/heltec_v4-dev|build/heltec_v4-dev" --port "/dev/ttyUSB0|/dev/ttyUSB1"
"""

from __future__ import annotations

import os

import pytest

BOOT_TIMEOUT = 30
PROMPT = "airlink>"


def wait_ready(dut, trunk_region: str | None = None) -> None:
    """Wait out a boot: the trunk when asked, then the mesh, then the console.

    Each line is consumed as it matches, so they are expected in the order the
    node logs them. The console starts last: a command written before its
    prompt can be lost.
    """
    if trunk_region:
        dut.expect(f"trunk on {trunk_region}", timeout=BOOT_TIMEOUT)
    dut.expect("node ready", timeout=BOOT_TIMEOUT)
    dut.expect(PROMPT, timeout=BOOT_TIMEOUT)


def provision(dut, region: str | None, trunk: bool = False) -> None:
    """Bring a node up, provisioned for `region` when given; `trunk` waits for its LoRa trunk too."""
    dut.expect(r"board (\w+)", timeout=BOOT_TIMEOUT)
    wait_ready(dut)
    if region:
        dut.write(f"region {region}")
        dut.expect("region set|refused", timeout=5)
        dut.write("reboot")
        wait_ready(dut, region if trunk else None)


@pytest.fixture
def region() -> str | None:
    return os.environ.get("AH_REGION")
