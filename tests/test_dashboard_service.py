"""Tests for the dashboard service backing the FastAPI UI."""

from __future__ import annotations

import unittest

from backend.dashboard_service import DashboardService, _baseline_history, _seed_packets, create_detector_with_seed


class DashboardServiceTest(unittest.TestCase):
    def test_realistic_dataset_contains_normals_and_attack_scenarios(self) -> None:
        baseline = _baseline_history()
        packets = _seed_packets()

        self.assertGreaterEqual(len(baseline), 3)
        self.assertGreaterEqual(len(packets), 5)
        self.assertTrue(any(packet.get("false_positive_result") == "N" for packet in packets))
        self.assertTrue(any(packet.get("false_positive_result") == "Y" for packet in packets))
        self.assertTrue(
            any(packet.get("target_subsystem") == "ADCS" for packet in packets)
        )
        self.assertTrue(
            any(packet.get("target_subsystem") == "COM" for packet in packets)
        )

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
        self.assertIn("comparison", preview)
        self.assertIn("delta_count", preview["comparison"])
        self.assertIn("E-02", service.list_rules()["rules"])

    def test_replay_preview_uses_stored_history(self) -> None:
        service = DashboardService(create_detector_with_seed())
        rules = service.list_rules()["rules"]
        thresholds = service.list_rules()["thresholds"]
        extra_packet = {
            "event_id": 999,
            "detected_at": "2026-05-11T06:09:00+00:00",
            "false_positive_result": "N",
            "false_positive_weight": 0.0,
            "target_subsystem": "",
            "telemetry": {
                "UPDATED_AT": "2026-05-11T06:09:00+00:00",
                "MISSION_MODE": 2,
                "ADCS_MODE": 1,
            },
        }
        service.receive_satellite_packet(extra_packet)

        preview = service.run_replay_preview(rules, thresholds)
        communication_times = {
            item["communicated_at"]
            for item in preview["dashboard"]["communications"]
        }

        self.assertIn("2026-05-11T06:09:00+00:00", communication_times)

    def test_apply_replay_config_persists_rules_and_rebuilds_dashboard(self) -> None:
        service = DashboardService(create_detector_with_seed())
        rules = dict(service.list_rules()["rules"])
        thresholds = service.list_rules()["thresholds"]

        result = service.apply_replay_config(rules, thresholds)

        self.assertTrue(result["ok"])
        self.assertIn("dashboard", result)


if __name__ == "__main__":
    unittest.main()
