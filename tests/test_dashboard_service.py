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
        self.assertGreaterEqual(len(state["detections"]), 1)

    def test_detection_detail_contains_rule_details(self) -> None:
        service = DashboardService(create_detector_with_seed())
        state = service.get_dashboard_state()
        detect_id = state["detections"][0]["detect_id"]

        detail = service.get_detection_detail(detect_id)

        self.assertNotIn("error", detail)
        self.assertIn("rule_details", detail)
        self.assertGreaterEqual(len(detail["rule_details"]), 1)


if __name__ == "__main__":
    unittest.main()
