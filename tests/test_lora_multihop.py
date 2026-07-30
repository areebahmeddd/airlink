import unittest

from tools.lora_reliability_sim import (
    MeshHop,
    MultiHopMeshModel,
)


def bidirectional(
    left: str,
    right: str,
    *,
    loss: float = 0.0,
    snr_db: int = 0,
) -> dict[tuple[str, str], MeshHop]:
    hop = MeshHop(loss=loss, snr_db=snr_db)
    return {(left, right): hop, (right, left): hop}


class MultiHopForwardingTests(unittest.TestCase):
    def test_three_node_line_exceeds_loss_gate(self):
        model = MultiHopMeshModel(
            {"left", "relay", "right"},
            {
                **bidirectional("left", "relay", loss=0.2, snr_db=-4),
                **bidirectional("relay", "right", loss=0.2, snr_db=-7),
            },
            attempts_per_hop=4,
            seed=17,
        )
        delivered = sum(
            model.send(
                "left", index.to_bytes(4, "big"), "right"
            ).delivered
            for index in range(1, 201)
        )
        self.assertGreaterEqual(delivered, 180)

    def test_triangle_multipath_delivers_application_once(self):
        links = {
            **bidirectional("a", "b", snr_db=8),
            **bidirectional("b", "c", snr_db=2),
            **bidirectional("a", "c", snr_db=-5),
        }
        result = MultiHopMeshModel(
            {"a", "b", "c"}, links, seed=9
        ).send("a", b"triangle", "c")
        self.assertTrue(result.delivered)
        self.assertEqual(result.application_deliveries, 1)
        self.assertGreaterEqual(result.duplicate_receptions, 1)
        self.assertLessEqual(result.processed_events, 7)

    def test_ring_broadcast_terminates_without_loop(self):
        links = {}
        for left, right in (
            ("a", "b"), ("b", "c"), ("c", "d"), ("d", "a")
        ):
            links.update(bidirectional(left, right, snr_db=1))
        result = MultiHopMeshModel(
            {"a", "b", "c", "d"}, links, seed=3
        ).send("a", b"ring")
        self.assertTrue(result.delivered)
        self.assertEqual(result.application_deliveries, 3)
        self.assertGreater(result.suppressed_forwards, 0)
        self.assertLessEqual(result.processed_events, 9)

    def test_stale_route_failure_falls_back_and_is_removed(self):
        links = {
            **bidirectional("a", "b", snr_db=6),
            **bidirectional("a", "d", snr_db=0),
            **bidirectional("d", "c", snr_db=-2),
        }
        model = MultiHopMeshModel(
            {"a", "b", "c", "d"}, links, seed=12
        )
        model.learn_route("a", "c", "b")
        model.disable_link("a", "b")
        result = model.send("a", b"route-failure", "c")
        self.assertTrue(result.delivered)
        self.assertEqual(result.route_failures, 1)
        self.assertNotIn("c", model.routes["a"])
        self.assertLessEqual(result.processed_events, 6)

    def test_relay_reboot_clears_route_but_new_transfer_recovers(self):
        links = {
            **bidirectional("a", "b", snr_db=3),
            **bidirectional("b", "c", snr_db=-1),
        }
        model = MultiHopMeshModel(
            {"a", "b", "c"}, links, seed=33
        )
        first = model.send("a", b"before-reboot", "c")
        model.reboot_node("b")
        second = model.send("a", b"after-reboot", "c")
        self.assertTrue(first.delivered)
        self.assertTrue(second.delivered)
        self.assertEqual(second.application_deliveries, 1)

    def test_asymmetric_links_and_malicious_repeats_stay_bounded(self):
        model = MultiHopMeshModel(
            {"a", "b", "c"},
            {
                ("a", "b"): MeshHop(snr_db=4),
                ("b", "c"): MeshHop(snr_db=-3),
            },
            seed=41,
        )
        forward = model.send("a", b"asymmetric", "c")
        reverse = model.send("c", b"no-reverse", "a")
        self.assertTrue(forward.delivered)
        self.assertFalse(reverse.delivered)

        first = model.send("a", b"repeated")
        repeats = [
            model.send("a", b"repeated") for _ in range(100)
        ]
        self.assertGreater(first.transmissions, 0)
        self.assertTrue(all(result.transmissions == 0 for result in repeats))
        self.assertTrue(all(
            result.application_deliveries == 0 for result in repeats
        ))

    def test_hop_limit_stops_before_unbounded_forwarding(self):
        links = {
            **bidirectional("a", "b"),
            **bidirectional("b", "c"),
            **bidirectional("c", "d"),
        }
        result = MultiHopMeshModel(
            {"a", "b", "c", "d"}, links, seed=5
        ).send("a", b"short-limit", "d", hop_limit=2)
        self.assertFalse(result.delivered)
        self.assertGreater(result.hop_limit_drops, 0)
        self.assertLessEqual(result.processed_events, 6)


if __name__ == "__main__":
    unittest.main()
