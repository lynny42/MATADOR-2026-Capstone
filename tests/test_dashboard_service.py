"""Tests for the dashboard service backing the FastAPI UI."""

from __future__ import annotations

import unittest

from backend.dashboard_service import DashboardService, create_detector_with_seed


class DashboardServiceTest(unittest.TestCase):
    def test_dashboard_state_contains_blueprint_and_latest_result(self) -> None:
        service = DashboardService(create_detector_with_seed())

        state = service.get_dashboard_state()

        self.assertEqual(state["core_subsystems"], ["OBC", "TCS", "EPS", "ADCS", "COM"])
        self.assertIn("OBC", state["blueprint"])
        self.assertIn("latest_communication", state)
        self.assertIn("communications", state)
        self.assertGreaterEqual(len(state["communications"]), 1)
        self.assertGreaterEqual(len(state["detections"]), 1)

    def test_detection_detail_contains_rule_details(self) -> None:
        service = DashboardService(create_detector_with_seed())
        state = service.get_dashboard_state()
        detect_id = state["detections"][0]["detect_id"]

        detail = service.get_detection_detail(detect_id)

        self.assertNotIn("error", detail)
        self.assertIn("rule_details", detail)
        self.assertGreaterEqual(len(detail["rule_details"]), 1)

    def test_replay_preview_does_not_change_saved_rules(self) -> None:
        service = DashboardService(create_detector_with_seed())
        original_rules = service.list_rules()["rules"]
        preview_rules = dict(original_rules)
        preview_rules.pop("E-02", None)
        thresholds = service.list_rules()["thresholds"]

        preview = service.run_replay_preview(preview_rules, thresholds)

        self.assertTrue(preview["temporary"])
        self.assertIn("dashboard", preview)
        self.assertIn("E-02", service.list_rules()["rules"])

    def test_apply_replay_config_persists_rules_and_rebuilds_dashboard(self) -> None:
        service = DashboardService(create_detector_with_seed())
        rules = dict(service.list_rules()["rules"])
        thresholds = service.list_rules()["thresholds"]

        result = service.apply_replay_config(rules, thresholds)

        self.assertTrue(result["ok"])
        self.assertIn("dashboard", result)


if __name__ == "__main__":
    unittest.main()
