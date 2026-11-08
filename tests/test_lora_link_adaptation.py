import unittest

from tools.lora_reliability_sim import (
    RadioProfile,
    SelectiveRepeatConfig,
    SelectiveRepeatModel,
    airtime_ms,
)


def completion_rate(
    *, loss: float, chunk_size: int, maximum_rounds: int, seed: int
) -> float:
    model = SelectiveRepeatModel(
        SelectiveRepeatConfig(
            data_loss=loss,
            ack_loss=loss,
            chunk_size=chunk_size,
            maximum_rounds=maximum_rounds,
            seed=seed,
        )
    )
    results = [model.transfer(520) for _ in range(5000)]
    return sum(result.complete for result in results) / len(results)


class LinkAdaptationSystemTests(unittest.TestCase):
    def test_weak_policy_improves_high_loss_completion(self):
        default = completion_rate(
            loss=0.40, chunk_size=120, maximum_rounds=8, seed=701
        )
        weak = completion_rate(
            loss=0.40, chunk_size=104, maximum_rounds=10, seed=701
        )
        self.assertGreaterEqual(weak, 0.98)
        self.assertGreaterEqual(weak - default, 0.015)

    def test_stable_policy_recovers_fragment_throughput(self):
        stable = completion_rate(
            loss=0.05, chunk_size=120, maximum_rounds=6, seed=711
        )
        self.assertGreaterEqual(stable, 0.999)
        self.assertEqual((480 + 119) // 120, 4)
        self.assertEqual((480 + 103) // 104, 5)

    def test_coding_rate_airtime_tradeoff_is_explicit(self):
        airtimes = {}
        for coding_rate in (5, 6, 7):
            profile = RadioProfile(
                sf=10,
                bandwidth_hz=125_000,
                coding_rate=coding_rate,
                preamble_symbols=16,
            )
            airtimes[coding_rate] = airtime_ms(164, profile)
        self.assertEqual(
            airtimes,
            {
                5: 1583,
                6: 1853,
                7: 2124,
            },
        )
        self.assertLess(airtimes[5], airtimes[6])
        self.assertLess(airtimes[6], airtimes[7])


if __name__ == "__main__":
    unittest.main()
