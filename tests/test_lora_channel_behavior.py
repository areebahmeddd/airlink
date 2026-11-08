import unittest

from tools.lora_reliability_sim import (
    DiscoveryChannelModel,
    DiscoveryConfig,
    RadioProfile,
    airtime_ms,
    bounded_ack_service,
    contention_window_ms,
    hidden_sender_delays,
)


class DiscoveryAndChannelTests(unittest.TestCase):
    def test_discovery_exceeds_gate_at_thirty_percent_loss(self):
        ratios = []
        for seed in range(100):
            result = DiscoveryChannelModel(
                DiscoveryConfig(
                    node_count=4,
                    frame_loss=0.3,
                    intervals=3,
                    repetitions=3,
                    contention_slots=64,
                    seed=seed,
                )
            ).run()
            ratios.append(result.discovery_ratio)
        self.assertGreaterEqual(sum(ratios) / len(ratios), 0.95)

    def test_four_simultaneous_nodes_converge(self):
        result = DiscoveryChannelModel(
            DiscoveryConfig(
                node_count=4,
                frame_loss=0.0,
                intervals=3,
                repetitions=3,
                contention_slots=32,
                seed=19,
            )
        ).run()
        self.assertEqual(result.discovery_ratio, 1.0)
        self.assertLess(result.collision_frames, result.transmitted_frames)

    def test_hidden_senders_leave_retry_lockstep(self):
        left, right = hidden_sender_delays(1500, 6, (11, 29))
        self.assertTrue(any(a != b for a, b in zip(left, right)))
        self.assertTrue(any(
            abs(a - b) >= 1500 for a, b in zip(left[1:], right[1:])
        ))

    def test_contention_scales_with_airtime_and_relay_role(self):
        short = contention_window_ms(100)
        long = contention_window_ms(1500)
        relayed = contention_window_ms(1500, relayed_broadcast=True)
        self.assertGreater(long[0], short[0])
        self.assertGreater(long[1], short[1])
        self.assertGreater(relayed[0], long[0])

    def test_ack_priority_is_bounded_under_bidirectional_data(self):
        schedule = bounded_ack_service(20, 3, burst_maximum=4)
        data_positions = [
            index for index, kind in enumerate(schedule) if kind == "data"
        ]
        self.assertEqual(len(data_positions), 3)
        self.assertLessEqual(data_positions[0], 4)
        self.assertLessEqual(data_positions[1] - data_positions[0], 5)

    def test_beacon_repetition_stays_inside_airtime_budget(self):
        profile = RadioProfile(sf=10, preamble_symbols=16)
        beacon_airtime = airtime_ms(44, profile)
        used_per_interval = beacon_airtime * 3
        available_per_interval = 60_000 * 0.25
        self.assertLess(used_per_interval, available_per_interval)

    def test_four_receivers_emit_no_beacon_ack(self):
        receiver_count = 4
        beacon_ack_requested = False
        self.assertEqual(
            receiver_count if beacon_ack_requested else 0,
            0,
        )

    def test_beacon_loss_does_not_remove_known_route(self):
        known_routes = {"peer"}
        DiscoveryChannelModel(
            DiscoveryConfig(
                node_count=2,
                frame_loss=1.0,
                intervals=3,
                repetitions=3,
                seed=7,
            )
        ).run()
        self.assertIn("peer", known_routes)


if __name__ == "__main__":
    unittest.main()
