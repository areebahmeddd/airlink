#!/usr/bin/env python3
"""Deterministic host model for the Bitle LoRa reliability protocol.

The legacy helpers intentionally preserve v2 behavior so baseline regressions
stay reproducible after the firmware is fixed. The generic link accepts loss,
delay, duplication, reordering, and queue-capacity controls used by later
milestones.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import random
from typing import Iterable


@dataclass(frozen=True)
class RadioProfile:
    sf: int = 10
    bandwidth_hz: int = 125_000
    coding_rate: int = 5
    preamble_symbols: int = 8
    crc: bool = True
    explicit_header: bool = True


def airtime_ms(payload_len: int, profile: RadioProfile) -> int:
    if (
        not 1 <= payload_len <= 255
        or not 5 <= profile.sf <= 12
        or profile.bandwidth_hz not in (125_000, 250_000, 500_000)
        or not 5 <= profile.coding_rate <= 8
        or profile.preamble_symbols < 4
    ):
        raise ValueError("invalid LoRa airtime parameters")
    symbol_s = (1 << profile.sf) / profile.bandwidth_hz
    low_data_rate = (
        (profile.sf >= 11 and profile.bandwidth_hz == 125_000)
        or (profile.sf >= 12 and profile.bandwidth_hz == 250_000)
    )
    numerator = (
        8 * payload_len
        - 4 * profile.sf
        + 28
        + (16 if profile.crc else 0)
        - (0 if profile.explicit_header else 20)
    )
    denominator = 4 * (profile.sf - (2 if low_data_rate else 0))
    payload_symbols = 8 + max(
        math.ceil(numerator / denominator) * profile.coding_rate, 0
    )
    total_s = (
        profile.preamble_symbols + 4.25 + payload_symbols
    ) * symbol_s
    return int(total_s * 1000 + 0.5)


@dataclass(frozen=True)
class LinkConfig:
    data_loss: float = 0.0
    ack_loss: float = 0.0
    delay_ms: tuple[int, int] = (0, 0)
    duplication: float = 0.0
    reorder_window: int = 0
    queue_capacity: int = 12
    seed: int = 1


@dataclass(frozen=True)
class Delivery:
    frame_id: int
    at_ms: int
    duplicate: bool = False


class DeterministicLink:
    def __init__(self, config: LinkConfig):
        if not 0.0 <= config.data_loss <= 1.0:
            raise ValueError("data_loss must be between zero and one")
        if not 0.0 <= config.ack_loss <= 1.0:
            raise ValueError("ack_loss must be between zero and one")
        if not 0.0 <= config.duplication <= 1.0:
            raise ValueError("duplication must be between zero and one")
        if config.delay_ms[0] < 0 or config.delay_ms[1] < config.delay_ms[0]:
            raise ValueError("invalid delay range")
        if config.queue_capacity < 0:
            raise ValueError("queue capacity cannot be negative")
        self.config = config
        self.random = random.Random(config.seed)

    def deliver(self, frame_ids: Iterable[int], *, ack: bool = False) -> list[Delivery]:
        loss = self.config.ack_loss if ack else self.config.data_loss
        accepted = list(frame_ids)[: self.config.queue_capacity]
        delivered: list[Delivery] = []
        clock = 0
        for frame_id in accepted:
            if self.random.random() < loss:
                continue
            clock += self.random.randint(*self.config.delay_ms)
            delivered.append(Delivery(frame_id, clock))
            if self.random.random() < self.config.duplication:
                delivered.append(Delivery(frame_id, clock + 1, duplicate=True))
        window = self.config.reorder_window
        if window > 1:
            for start in range(0, len(delivered), window):
                block = delivered[start : start + window]
                self.random.shuffle(block)
                delivered[start : start + window] = block
        return delivered


@dataclass(frozen=True)
class LegacyV2Config:
    profile: RadioProfile = RadioProfile()
    chunk_size: int = 120
    header_size: int = 16
    tx_timeout_ms: int = 2_000
    cad_delay_ms: int = 0
    ack_margin_ms: int = 1_200
    retries: int = 3
    reassembly_timeout_ms: int = 10_000
    queue_capacity: int = 12


class LegacyV2Model:
    """Small executable specification of the failure-prone v2 semantics."""

    def __init__(self, config: LegacyV2Config = LegacyV2Config()):
        self.config = config

    def fragments(self, packet_len: int) -> list[int]:
        if packet_len <= 0:
            raise ValueError("packet length must be positive")
        return [
            min(self.config.chunk_size, packet_len - offset)
            for offset in range(0, packet_len, self.config.chunk_size)
        ]

    def tx_times_out(self, frame_len: int) -> bool:
        return airtime_ms(frame_len, self.config.profile) > self.config.tx_timeout_ms

    def enqueue_non_atomic(
        self, packet_len: int, occupied_slots: int
    ) -> tuple[bool, int]:
        free = max(self.config.queue_capacity - occupied_slots, 0)
        queued = min(len(self.fragments(packet_len)), free)
        return queued == len(self.fragments(packet_len)), queued

    @staticmethod
    def accepts_ack(
        expected_seq: int,
        expected_fragment: int,
        ack_seq: int,
        ack_fragment: int,
        ack_source: bytes,
        expected_source: bytes,
    ) -> bool:
        del ack_source, expected_source
        return expected_seq == ack_seq and expected_fragment == ack_fragment

    @staticmethod
    def broadcast_ack_count(receiver_count: int, ack_requested: bool = True) -> int:
        return receiver_count if ack_requested else 0

    def reassembly_expires(
        self, packet_len: int, missed_first_attempt_fragments: set[int]
    ) -> tuple[bool, int]:
        """Return whether v2's fixed deadline expires and elapsed RX span.

        A lost first attempt consumes a full data airtime plus ACK deadline.
        A successful attempt consumes data and ACK airtime. This is sufficient
        to reproduce the deterministic timeout conflict without RF randomness.
        """
        elapsed = 0
        first_rx_at: int | None = None
        ack_airtime = airtime_ms(self.config.header_size, self.config.profile)
        for index, chunk in enumerate(self.fragments(packet_len)):
            data_airtime = airtime_ms(
                self.config.header_size + chunk, self.config.profile
            )
            elapsed += self.config.cad_delay_ms
            if index in missed_first_attempt_fragments:
                elapsed += data_airtime + ack_airtime + self.config.ack_margin_ms
                elapsed += self.config.cad_delay_ms
            elapsed += data_airtime
            if first_rx_at is None:
                first_rx_at = elapsed
            elapsed += ack_airtime
        span = elapsed - (first_rx_at or 0)
        return span > self.config.reassembly_timeout_ms, span
