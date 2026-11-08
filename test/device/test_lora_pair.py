# SPDX-FileCopyrightText: 2026 Areeb Ahmed
# SPDX-License-Identifier: MIT
"""Two nodes of one region find each other over LoRa alone (scenario S4's first step)."""

from __future__ import annotations

import pytest
from conftest import provision

# A node's first beacon goes 2 to 12 s after its trunk starts, or once its
# first minute ends when the duty ledger was taken as spent (a board whose
# trunk never ran, so no copy is in flash), and the next 5 to 5.5 minutes
# later. The boards are provisioned one after the other, so the first one's
# first beacon can go before the second listens, which then hears the next:
# six minutes covers it.
NEIGHBOR_TIMEOUT = 6 * 60


@pytest.mark.lora
@pytest.mark.parametrize("count", [2], indirect=True)
def test_two_nodes_become_trunk_neighbors(dut, region) -> None:
    if not region:
        pytest.skip("set AH_REGION to the region both boards may transmit in")
    for node in dut:
        provision(node, region, trunk=True)
    for node in dut:
        node.expect(r"neighbor [0-9a-f]{8} up", timeout=NEIGHBOR_TIMEOUT)
    for node in dut:
        node.write("status")
        node.expect(r"lora up  neighbors 1", timeout=5)
