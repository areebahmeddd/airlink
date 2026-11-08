# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
"""A freshly flashed node boots, answers its console, keeps its identity, and stays off LoRa until provisioned."""

from __future__ import annotations

import pytest
from conftest import BOOT_TIMEOUT, provision, wait_ready


def test_boots_and_reports(dut, region) -> None:
    provision(dut, region)
    dut.write("status")
    dut.expect(r"airlink \d+\.\d+\.\d+ on \w+", timeout=5)
    dut.expect(r"peer [0-9a-f]{16}", timeout=5)
    dut.expect(r"heap \d+ free", timeout=5)


def test_identity_survives_a_reboot(dut, region) -> None:
    provision(dut, region)
    dut.write("status")
    first = dut.expect(r"peer ([0-9a-f]{16})", timeout=5).group(1)
    dut.write("reboot")
    wait_ready(dut)
    dut.write("status")
    assert dut.expect(r"peer ([0-9a-f]{16})", timeout=5).group(1) == first


def test_no_lora_transmission_without_a_region(dut, region) -> None:
    # Needs settings erased (--erase-all y): a provisioned node starts its trunk,
    # and with AH_REGION set the tests before this one provision it.
    if region:
        pytest.skip("run without AH_REGION")
    board = dut.expect(r"board (\w+)", timeout=BOOT_TIMEOUT).group(1).decode()
    if board in ("c6_devkit", "xiao_c6"):
        pytest.skip(f"{board} has no LoRa radio")
    dut.expect("LoRa region not provisioned", timeout=10)
