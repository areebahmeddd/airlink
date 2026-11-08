import unittest

from tools.lora_reliability_sim import (
    DeterministicLink,
    LegacyV2Config,
    LegacyV2Model,
    LinkConfig,
    RadioProfile,
    airtime_ms,
)


class AirtimeModelTests(unittest.TestCase):
    def test_sf10_full_v2_frame_airtime(self):
        self.assertEqual(airtime_ms(136, RadioProfile(sf=10)), 1313)

    def test_configuration_controls_are_deterministic(self):
        config = LinkConfig(
            data_loss=0.2,
            ack_loss=0.3,
            delay_ms=(5, 20),
            duplication=0.4,
            reorder_window=3,
            queue_capacity=6,
            seed=27,
        )
        first = DeterministicLink(config).deliver(range(10))
        second = DeterministicLink(config).deliver(range(10))
        self.assertEqual(first, second)
        self.assertTrue(all(delivery.frame_id < 6 for delivery in first))


class LegacyV2FailureBaselineTests(unittest.TestCase):
    def test_sf11_and_sf12_full_frames_exceed_fixed_tx_timeout(self):
        for sf in (11, 12):
            with self.subTest(sf=sf):
                model = LegacyV2Model(
                    LegacyV2Config(profile=RadioProfile(sf=sf))
                )
                self.assertTrue(model.tx_times_out(136))

    def test_weak_link_retries_outlive_fixed_reassembly_slot(self):
        model = LegacyV2Model()
        expired, elapsed_ms = model.reassembly_expires(520, {1, 3})
        self.assertTrue(expired)
        self.assertGreater(elapsed_ms, 10_000)

    def test_frame_queue_can_accept_only_part_of_a_packet(self):
        model = LegacyV2Model()
        accepted, queued_fragments = model.enqueue_non_atomic(520, occupied_slots=10)
        self.assertFalse(accepted)
        self.assertEqual(queued_fragments, 2)

    def test_ack_from_wrong_source_is_accepted(self):
        model = LegacyV2Model()
        self.assertTrue(
            model.accepts_ack(
                42,
                3,
                42,
                3,
                ack_source=b"evil",
                expected_source=b"peer",
            )
        )

    def test_broadcast_ack_request_causes_ack_implosion(self):
        model = LegacyV2Model()
        self.assertEqual(model.broadcast_ack_count(4), 4)


if __name__ == "__main__":
    unittest.main()
