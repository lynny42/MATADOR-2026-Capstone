"""Tests for the dashboard service with mocked MySQL dependencies."""

from __future__ import annotations

import json
import unittest
from datetime import datetime
from unittest.mock import patch

from backend.dashboard_service import DashboardService
from ma_detector import MAIntegratedDetector

SAMPLE_DASHBOARD_ROW = {
    "DETECT_ID": 1,
    "DASHBOARD_ID": 1,
    "DETECT_TIME": "2026-05-12 07:20:00",
    "MODULE": "OBC",
    "ACTION": "INTEGRITY_CHECK_BYPASS",
    "SCENARIO_PHASE": 3,
    "MA_CODE": "OBC_INTEGRITY_CHECK_BYPASS_P3",
    "CONFIDENCE_SCORE": 82.0,
    "GRADE": "SUSPECTED",
    "CORROBORATION_COUNT": 2,
    "EVIDENCE_KEYS": {"E-03": "Hash mismatch"},
    "IS_NEW_PATTERN": 0,
    "ACTION_MAPPING_STATUS": "mapped",
    "TRIGGERED_RULE_IDS": ["E-03"],
    "UNREGISTERED_ACTION_IDS": [],
    "TRIGGERED_RULE_RESULTS": [{"rule_id": "E-03", "score": 0.9}],
    "MATCHES_SATELLITE_TARGET": 1,
    "TARGET_SUBSYSTEM": "OBC",
    "SATELLITE_TARGET_SUBSYSTEM": "OBC",
    "FALSE_POSITIVE_RESULT": "Y",
    "FALSE_POSITIVE_WEIGHT": 91,
    "FALSE_POSITIVE_EXCEPTION": "",
    "EVENT_ID": 7209,
    "SW_ID_LIST": [0, 1],
    "SATELLITE_DETECTED_AT": "2026-05-12 07:20:00",
}

SAMPLE_HISTORY_ROW = {
    "HISTORY_ID": 10,
    "UPDATED_AT": "2026-05-12 07:20:00",
    "MISSION_MODE": 2,
    "ADCS_MODE": 1,
    "IS_ANOMALY": 1,
    "FALSE_POSITIVE_RESULT": "Y",
    "FALSE_POSITIVE_WEIGHT": 91,
    "TARGET_SUBSYSTEM": "OBC",
    "OBC_P_HASH": "0xDEAD19C4",
    "EXPECTED_CRC": "0x8F12A9C0",
    "APPCSERRCOUNTER": 7,
    "UTILCPUAVG": 92.4,
}

SAMPLE_ANOMALY_ROW = {
    **SAMPLE_HISTORY_ROW,
    "IS_ANOMALY": True,
}


def _build_detector() -> MAIntegratedDetector:
    detector = MAIntegratedDetector()
    detector.build_baseline(
        [
            {
                "UPDATED_AT": "2026-05-12 07:00:00",
                "MISSION_MODE": 2,
                "ADCS_MODE": 1,
                "IS_ANOMALY": False,
                "FALSE_POSITIVE_WEIGHT": 0,
                "OBC_P_HASH": "0x8F12A9C0",
                "EXPECTED_CRC": "0x8F12A9C0",
            }
        ]
    )
    return detector


class DashboardServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.require_db_patcher = patch("backend.dashboard_service.require_db")
        self.require_db_patcher.start()
        self.repo_patcher = patch.multiple(
            "backend.dashboard_service.gs_repository",
            query_recent_dashboards=lambda count=100: [dict(SAMPLE_DASHBOARD_ROW)],
            load_recent_tlm_history=lambda limit=600: [dict(SAMPLE_HISTORY_ROW)],
            query_dashboard=lambda detect_id: dict(SAMPLE_DASHBOARD_ROW) if detect_id == 1 else None,
            query_detail_rows=lambda dashboard_id: [
                {
                    "DETAIL_ID": 1,
                    "DASHBOARD_ID": dashboard_id,
                    "DETECT_ID": 1,
                    "IMU_WBN_X": 0.1,
                    "QERR_0": 0.02,
                    "MOMENTUM_NMS_0": 0.2,
                }
            ],
            query_history_window=lambda detect_time, window_size_sec, limit=60: [dict(SAMPLE_HISTORY_ROW)],
            query_detection_history_rows=lambda detect_time: [dict(SAMPLE_HISTORY_ROW)],
            query_evaluation_snapshot=lambda detect_id: dict(SAMPLE_HISTORY_ROW),
            query_anomaly_row_near=lambda detect_time, tolerance_sec=5: dict(SAMPLE_HISTORY_ROW),
            load_baseline_history=lambda limit=500: [
                {
                    "UPDATED_AT": "2026-05-12 07:00:00",
                    "MISSION_MODE": 2,
                    "ADCS_MODE": 1,
                    "IS_ANOMALY": 0,
                    "FALSE_POSITIVE_WEIGHT": 0,
                }
            ],
            load_anomaly_history=lambda limit=5000: [dict(SAMPLE_ANOMALY_ROW)],
            clear_ma_results=lambda: True,
        )
        self.repo_patcher.start()
        self.detector_query_patcher = patch.multiple(
            "ma_detector.ma_integrated_detector.gs_repository",
            query_dashboard=lambda detect_id: dict(SAMPLE_DASHBOARD_ROW) if detect_id == 1 else None,
            query_detail_rows=lambda dashboard_id: [
                {
                    "DETAIL_ID": 1,
                    "DASHBOARD_ID": dashboard_id,
                    "DETECT_ID": 1,
                    "IMU_WBN_X": 0.1,
                    "QERR_0": 0.02,
                    "MOMENTUM_NMS_0": 0.2,
                }
            ],
            query_history_window=lambda detect_time, window_size_sec, limit=60: [dict(SAMPLE_HISTORY_ROW)],
            query_detection_history_rows=lambda detect_time: [dict(SAMPLE_HISTORY_ROW)],
            query_evaluation_snapshot=lambda detect_id: dict(SAMPLE_HISTORY_ROW),
            query_anomaly_row_near=lambda detect_time, tolerance_sec=5: dict(SAMPLE_HISTORY_ROW),
            load_recent_tlm_history=lambda limit=600: [dict(SAMPLE_HISTORY_ROW)],
        )
        self.detector_query_patcher.start()
        self.service = DashboardService(_build_detector())

    def tearDown(self) -> None:
        self.detector_query_patcher.stop()
        self.repo_patcher.stop()
        self.require_db_patcher.stop()

    def test_dashboard_state_contains_blueprint_and_latest_result(self) -> None:
        state = self.service.get_dashboard_state()

        self.assertEqual(state["core_subsystems"], ["OBC", "TCS", "EPS", "ADCS", "COM"])
        self.assertIn("OBC", state["blueprint"])
        self.assertIn("latest_communication", state)
        self.assertIn("communications", state)
        self.assertGreaterEqual(len(state["communications"]), 1)
        self.assertGreaterEqual(len(state["detections"]), 1)

    def test_build_communications_clusters_same_uplink_window(self) -> None:
        history_rows = [
            {
                "HISTORY_ID": 1,
                "UPDATED_AT": "2026-05-30 10:00:00",
                "CREATED_AT": "2026-05-30 12:00:01",
            },
            {
                "HISTORY_ID": 2,
                "UPDATED_AT": "2026-05-30 10:00:01",
                "CREATED_AT": "2026-05-30 12:00:02",
            },
            {
                "HISTORY_ID": 3,
                "UPDATED_AT": "2026-05-30 10:00:02",
                "CREATED_AT": "2026-05-30 12:00:03",
            },
            {
                "HISTORY_ID": 4,
                "UPDATED_AT": "2026-05-30 10:05:00",
                "CREATED_AT": "2026-05-30 12:05:00",
            },
        ]
        communications = self.service._build_communications(history_rows, [])
        self.assertEqual(len(communications), 2)
        self.assertEqual(communications[-1]["communicated_at"], "2026-05-30 12:05:00")
        self.assertEqual(communications[-2]["sample_count"], 3)
        self.assertEqual(communications[-2]["anomaly_count"], 0)

    def test_normal_communication_does_not_inherit_old_detections(self) -> None:
        history_rows = [
            {
                "HISTORY_ID": 1,
                "UPDATED_AT": "2026-05-30 17:19:30",
                "CREATED_AT": "2026-05-30 17:29:55",
                "IS_ANOMALY": 0,
            },
            {
                "HISTORY_ID": 2,
                "UPDATED_AT": "2026-05-30 17:29:52",
                "CREATED_AT": "2026-05-30 17:29:57",
                "IS_ANOMALY": 0,
            },
        ]
        detections = [
            {
                "detect_id": 99,
                "detect_time": "2026-05-30 17:20:00",
                "ma_code": "OBC_INTEGRITY_CHECK_BYPASS_P3",
            }
        ]
        communications = self.service._build_communications(history_rows, detections)
        self.assertEqual(len(communications), 1)
        self.assertEqual(communications[0]["anomaly_count"], 0)
        self.assertEqual(communications[0]["status"], "NORMAL")

    def test_detection_detail_contains_rule_details(self) -> None:
        state = self.service.get_dashboard_state()
        detect_id = state["detections"][0]["detect_id"]

        detail = self.service.get_detection_detail(detect_id)

        self.assertNotIn("error", detail)
        self.assertIn("rule_details", detail)
        self.assertIn("snapshot_frame", detail)
        self.assertEqual(detail["snapshot_frame"]["mode"], "detection_snapshot")
        self.assertEqual(detail["snapshot_frame"]["total"], 1)

    def test_detection_detail_populates_rule_column_observations(self) -> None:
        prior_row = {
            "HISTORY_ID": 1,
            "UPDATED_AT": "2026-05-12 07:19:59",
            "MISSION_MODE": 2,
            "OBC_P_HASH": "0x8F12A9C0",
            "EXPECTED_CRC": "0x8F12A9C0",
        }
        partial_row = {
            "HISTORY_ID": 2,
            "UPDATED_AT": "2026-05-12 07:20:00",
            "MISSION_MODE": 2,
            "ADCS_MODE": 1,
        }
        anomaly_row = dict(SAMPLE_HISTORY_ROW)
        with patch(
            "backend.dashboard_service.gs_repository.query_detection_history_rows",
            lambda detect_time: [prior_row, partial_row, anomaly_row],
        ):
            detail = self.service.get_detection_detail(1)

        rule_details = detail.get("rule_details", [])
        self.assertTrue(rule_details)
        hash_columns = rule_details[0].get("columns", {}).get("OBC_P_HASH")
        self.assertIsNotNone(hash_columns)
        self.assertEqual(hash_columns["observed"], "0xDEAD19C4")
        self.assertEqual(hash_columns["previous_observed"], "0x8F12A9C0")

    def test_detection_detail_uses_db_only_previous_frame(self) -> None:
        adcs_dashboard = {
            **SAMPLE_DASHBOARD_ROW,
            "DETECT_TIME": "2026-05-12 07:20:02",
            "MODULE": "ADCS",
            "TRIGGERED_RULE_IDS": ["S2-X01"],
            "EVIDENCE_KEYS": {"S2-X01": "Attitude mismatch"},
            "TRIGGERED_RULE_RESULTS": [{"rule_id": "S2-X01", "score": 0.9}],
        }
        rows = [
            {
                "HISTORY_ID": 1,
                "UPDATED_AT": "2026-05-12 07:19:59",
                "MISSION_MODE": 2,
            },
            {
                "HISTORY_ID": 2,
                "UPDATED_AT": "2026-05-12 07:20:00",
                "QERR_0": 0.99,
            },
            {
                "HISTORY_ID": 3,
                "UPDATED_AT": "2026-05-12 07:20:01",
                "MISSION_MODE": 2,
            },
            {
                **SAMPLE_HISTORY_ROW,
                "HISTORY_ID": 4,
                "UPDATED_AT": "2026-05-12 07:20:02",
                "QERR_0": 0.7,
            },
        ]
        with patch(
            "backend.dashboard_service.gs_repository.query_detection_history_rows",
            lambda detect_time: rows,
        ), patch(
            "ma_detector.ma_integrated_detector.gs_repository.query_dashboard",
            lambda detect_id: dict(adcs_dashboard) if detect_id == 1 else None,
        ), patch(
            "backend.dashboard_service.gs_repository.query_dashboard",
            lambda detect_id: dict(adcs_dashboard) if detect_id == 1 else None,
        ):
            detail = self.service.get_detection_detail(1)

        qerr_columns = detail.get("rule_details", [{}])[0].get("columns", {}).get("QERR_0")
        self.assertIsNotNone(qerr_columns)
        self.assertEqual(qerr_columns["observed"], 0.7)
        self.assertIsNone(qerr_columns["previous_observed"])
        self.assertEqual(detail["snapshot_frame"]["total"], 1)

    def test_replay_preview_does_not_change_saved_rules(self) -> None:
        original_rules = self.service.list_rules()["rules"]
        preview_rules = dict(original_rules)
        preview_rules.pop("E-02", None)
        thresholds = self.service.list_rules()["thresholds"]

        preview = self.service.run_replay_preview(preview_rules, thresholds)

        self.assertTrue(preview["temporary"])
        self.assertIn("dashboard", preview)
        self.assertIn("comparison", preview)
        self.assertIn("E-02", self.service.list_rules()["rules"])

    def test_replay_preview_handles_datetime_history_rows(self) -> None:
        preview = self.service.run_replay_preview(
            self.service.list_rules()["rules"],
            self.service.list_rules()["thresholds"],
        )
        self.assertTrue(preview["ok"])

    def test_replay_preview_reflects_disabled_rules(self) -> None:
        current_count = len(self.service.get_dashboard_state()["detections"])
        self.assertGreater(current_count, 0)

        disabled_rules = {
            rule_id: {**definition, "enabled": False}
            for rule_id, definition in self.service.list_rules()["rules"].items()
        }
        preview = self.service.run_replay_preview(
            disabled_rules,
            self.service.list_rules()["thresholds"],
        )
        comparison = preview["comparison"]
        self.assertLessEqual(comparison["preview_count"], comparison["current_count"])

    def test_apply_replay_config_persists_rules_and_rebuilds_dashboard(self) -> None:
        rules = dict(self.service.list_rules()["rules"])
        thresholds = self.service.list_rules()["thresholds"]

        result = self.service.apply_replay_config(rules, thresholds)

        self.assertTrue(result["ok"])
        self.assertIn("dashboard", result)

    def test_abnormal_percent_for_matching_hash_fields_is_zero(self) -> None:
        snapshot = {"OBC_P_HASH": "OK", "EXPECTED_CRC": "OK"}
        self.assertEqual(DashboardService._abnormal_percent("OBC_P_HASH", snapshot), 0.0)
        self.assertEqual(DashboardService._abnormal_percent("EXPECTED_CRC", snapshot), 0.0)

    def test_abnormal_percent_for_hash_mismatch_uses_flag(self) -> None:
        snapshot = {"OBC_P_HASH": "TAMPERED", "EXPECTED_CRC": "0x8F12A9C0"}
        self.assertIsNone(DashboardService._abnormal_percent("OBC_P_HASH", snapshot))


if __name__ == "__main__":
    unittest.main()
