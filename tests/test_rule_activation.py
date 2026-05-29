"""Tests for JSON-driven rule activation."""

from __future__ import annotations

import unittest

from ma_detector.core.baseline import BaselineManager
from ma_detector.core.rule_activation import evaluate_rule_activation, merge_default_activations, repeat_ratio_score


class RuleActivationTest(unittest.TestCase):
    def test_repeat_ratio_requires_sustained_nonzero(self) -> None:
        window_sparse = [
            {"CH1_FAULT_CRC": 1},
            {"CH1_FAULT_CRC": 0},
            {"CH1_FAULT_CRC": 0},
            {"CH1_FAULT_CRC": 0},
            {"CH1_FAULT_CRC": 0},
            {"CH1_FAULT_CRC": 0},
            {"CH1_FAULT_CRC": 0},
            {"CH1_FAULT_CRC": 0},
            {"CH1_FAULT_CRC": 0},
            {"CH1_FAULT_CRC": 0},
        ]
        window_repeat = [{"CH1_FAULT_CRC": 1 if index % 2 == 0 else 0} for index in range(10)]
        sparse_score = repeat_ratio_score(window_sparse, "CH1_FAULT_CRC", 0.1)
        repeat_score = repeat_ratio_score(window_repeat, "CH1_FAULT_CRC", 0.1)
        self.assertLess(sparse_score, repeat_score)

    def test_repeat_ratio_activation_clause(self) -> None:
        baseline = BaselineManager()
        activation = {
            "window_mode": "snapshot_series",
            "clauses": [
                {"op": "repeat_ratio", "column": "CH1_FAULT_CRC", "min_ratio": 0.1, "weight": 1.0},
            ],
        }
        window = [{"CH1_FAULT_CRC": 1 if index < 3 else 0} for index in range(10)]
        score = evaluate_rule_activation(
            activation,
            window,
            baseline,
            {"SOFT": 2, "HARD": 3, "SEVERE": 4},
            {},
        )
        self.assertGreater(score, 0.0)

    def test_step_delta_triggers_on_increase(self) -> None:
        baseline = BaselineManager()
        activation = {
            "window_mode": "snapshot_series",
            "clauses": [
                {
                    "op": "step_delta",
                    "column": "CMDREJECTEDCOUNTER",
                    "direction": "increase",
                    "weight": 1.0,
                    "min_delta_percent": 5.0,
                }
            ],
        }
        window = [
            {"UPDATED_AT": "t1", "CMDREJECTEDCOUNTER": 1},
            {"UPDATED_AT": "t2", "CMDREJECTEDCOUNTER": 3},
        ]
        score = evaluate_rule_activation(activation, window, baseline, {"SOFT": 2, "HARD": 3, "SEVERE": 4}, {})
        self.assertGreater(score, 0.0)

    def test_merge_default_activation_attaches_e02(self) -> None:
        registry = {"E-02": {"name": "test", "enabled": True}}
        merge_default_activations(registry)
        self.assertIn("activation", registry["E-02"])
        self.assertEqual(registry["E-02"]["activation"]["window_mode"], "snapshot_series")

    def test_step_delta_uses_max_pair_in_series(self) -> None:
        baseline = BaselineManager()
        activation = {
            "window_mode": "snapshot_series",
            "clauses": [
                {
                    "op": "step_delta",
                    "column": "CMDREJECTEDCOUNTER",
                    "direction": "increase",
                    "weight": 1.0,
                    "min_delta_percent": 5.0,
                }
            ],
        }
        window = [
            {"UPDATED_AT": "t1", "CMDREJECTEDCOUNTER": 1},
            {"UPDATED_AT": "t2", "CMDREJECTEDCOUNTER": 2},
            {"UPDATED_AT": "t3", "CMDREJECTEDCOUNTER": 10},
        ]
        score = evaluate_rule_activation(activation, window, baseline, {"SOFT": 2, "HARD": 3, "SEVERE": 4}, {})
        self.assertGreater(score, 0.0)


if __name__ == "__main__":
    unittest.main()
