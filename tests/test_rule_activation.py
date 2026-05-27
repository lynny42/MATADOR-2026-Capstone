"""Tests for JSON-driven rule activation."""

from __future__ import annotations

import unittest

from ma_detector.core.baseline import BaselineManager
from ma_detector.core.rule_activation import evaluate_rule_activation, merge_default_activations


class RuleActivationTest(unittest.TestCase):
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
