import unittest

from tools.lora_reliability_sim import (
    BoundedReassemblyModel,
    SelectiveRepeatConfig,
    SelectiveRepeatModel,
)


class SelectiveRepeatReliabilityTests(unittest.TestCase):
    def test_thirty_percent_data_and_ack_loss_exceeds_gate(self):
        model = SelectiveRepeatModel(
            SelectiveRepeatConfig(
                data_loss=0.30,
                ack_loss=0.30,
                maximum_rounds=8,
                seed=4104,
            )
        )
        results = [model.transfer(520) for _ in range(2000)]
        completed = sum(result.complete for result in results)
        self.assertGreaterEqual(completed / len(results), 0.95)
        self.assertTrue(
            all(
                not result.complete or result.delivered
                for result in results
            )
        )
        self.assertTrue(
            all(result.delivery_count <= 1 for result in results)
        )

    def test_duplicate_reordered_frames_and_final_ack_loss(self):
        model = SelectiveRepeatModel(
            SelectiveRepeatConfig(
                ack_loss=0.45,
                duplication=1.0,
                reorder=True,
                maximum_rounds=8,
                seed=91,
            )
        )
        for packet_len in (100, 180, 300, 420, 520):
            result = model.transfer(packet_len)
            self.assertTrue(result.complete)
            self.assertTrue(result.delivered)
            self.assertEqual(result.delivery_count, 1)

    def test_delayed_feedback_and_incomplete_receiver_restart(self):
        model = SelectiveRepeatModel(
            SelectiveRepeatConfig(
                data_loss=0.15,
                ack_loss=0.15,
                duplication=0.4,
                reorder=True,
                feedback_delay_rounds=1,
                maximum_rounds=8,
                seed=77,
            )
        )
        result = model.transfer(520, receiver_restart_round=1)
        self.assertTrue(result.complete)
        self.assertEqual(result.delivery_count, 1)

    def test_reboot_epoch_and_counter_wrap(self):
        first = SelectiveRepeatModel.transfer_id(
            b"\x10" * 8, 0xFFFFFFFF
        )
        after_reboot = SelectiveRepeatModel.transfer_id(
            b"\x20" * 8, 1
        )
        self.assertNotEqual(first, after_reboot)
        with self.assertRaises(OverflowError):
            SelectiveRepeatModel.transfer_id(b"\x10" * 8, 0)
        with self.assertRaises(OverflowError):
            SelectiveRepeatModel.transfer_id(
                b"\x10" * 8, 0x1_0000_0000
            )

    def test_incomplete_transfer_flood_stays_bounded(self):
        receiver = BoundedReassemblyModel()
        accepted = [
            receiver.accept_fragment(index.to_bytes(12, "big"))
            for index in range(1000)
        ]
        self.assertEqual(sum(accepted), 2)
        self.assertEqual(len(receiver.active), 2)
        self.assertEqual(receiver.resource_aborts, 998)

        first = (0).to_bytes(12, "big")
        self.assertTrue(receiver.complete(first))
        self.assertFalse(receiver.complete(first))
        self.assertLessEqual(len(receiver.completed), 6)


if __name__ == "__main__":
    unittest.main()
