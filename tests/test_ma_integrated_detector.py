"""Smoke tests for the MA integrated detector pipeline."""

from __future__ import annotations

import json
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from ma_detector import MAIntegratedDetector
from ma_detector.core.ma_onboard_view import derive_ma_fields_from_event
from ma_detector.ma_integrated_detector import DEFAULT_ANALYSIS_WINDOW_SEC


def _normal_record() -> dict:
    return {
        "UPDATED_AT": "2026-05-10T07:00:00+00:00",
        "MISSION_MODE": 2,
        "ADCS_MODE": 1,
        "IS_ANOMALY": False,
        "OBC_P_HASH": "OK",
        "EXPECTED_CRC": "OK",
        "APPCSERRCOUNTER": 0,
        "OSCSERRCOUNTER": 0,
        "LASTVALCRC": 100,
        "PROCESSOR_RESET_COUNT": 0,
        "OBC_S_TICK": 1000,
        "CH1_FAULT_CRC": 0,
        "CH2_FAULT_CRC": 0,
        "CH1_FAULT_FILE_SIZE_MISMATCH": 0,
        "CHILDQUEUECOUNT": 1,
        "FILEWRITEERRCOUNTER": 0,
        "CMDREJECTEDCOUNTER": 0,
        "PIPEOVERFLOWRRCNT": 0,
        "COMBINEDPACKETSSENT": 100,
        "HEAP_FREE": 1000,
        "MEMINUSE": 200,
        "EXECOUNTS": 10,
        "UTILCPUAVG": 20.0,
        "SKIPPEDSLOTSCOUNT": 0,
        "ERLOGENTRIES": 0,
        "DWELL_MASK": 0,
        "DWELL_ADDR_COUNT": 0,
        "DWELL_BYTE_COUNT": 0,
        "ENABLEDROUTES": 1,
        "FORWARD_ERR_COUNT": 0,
        "QERR_0": 0.0,
        "QERR_1": 0.0,
        "QERR_2": 0.0,
        "QERR_3": 0.0,
        "TCMD_X": 0.0,
        "TCMD_Y": 0.0,
        "TCMD_Z": 0.0,
        "MOMENTUM_NMS_0": 0.0,
        "MOMENTUM_NMS_1": 0.0,
        "MOMENTUM_NMS_2": 0.0,
        "DEVICE_ERR_RW0": 0,
        "DEVICE_ERR_RW1": 0,
        "DEVICE_ERR_RW2": 0,
        "BATT_VOLTAGE": 7.4,
        "BUS_3P3V": 3.3,
        "BUS_5P0V": 5.0,
        "BUS_12V": 12.0,
        "SW_0_CURRENT": 0.2,
        "SW_1_CURRENT": 0.2,
        "SW_2_CURRENT": 0.2,
        "IMU_WBN_VARIANCE": 0.01,
        "RAW_MAG_VARIANCE": 0.01,
        "ST_VALID": 1,
        "IS_SENT": 1,
    }


@contextmanager
def _ui_db_from_detector(detector: MAIntegratedDetector):
    """Route get_ui_data() DB queries to the detector pipeline cache in unit tests."""

    def _query_dashboard(detect_id: int):
        for row in detector.get_dashboard_records():
            if int(row.get("DETECT_ID", -1)) == int(detect_id):
                return dict(row)
        return None

    def _query_detail_rows(dashboard_id: int):
        return [
            dict(row)
            for row in detector._detail_rows
            if int(row.get("DASHBOARD_ID", -1)) == int(dashboard_id)
        ]

    def _query_history_window(detect_time: str, window_size_sec: int, limit: int = 60):
        if detector._telemetry_window:
            return [dict(detector._telemetry_window[-1])]
        return [dict(row) for row in detector.get_history_records()[-limit:]]

    def _query_detection_history_rows(detect_time: str):
        if detector._telemetry_window:
            return [dict(detector._telemetry_window[-1])]
        return [dict(row) for row in detector.get_history_records()]

    with patch(
        "ma_detector.ma_integrated_detector.gs_repository.query_dashboard",
        side_effect=_query_dashboard,
    ), patch(
        "ma_detector.ma_integrated_detector.gs_repository.query_detail_rows",
        side_effect=_query_detail_rows,
    ), patch(
        "ma_detector.ma_integrated_detector.gs_repository.query_history_window",
        side_effect=_query_history_window,
    ), patch(
        "ma_detector.ma_integrated_detector.gs_repository.query_detection_history_rows",
        side_effect=_query_detection_history_rows,
    ), patch(
        "ma_detector.ma_integrated_detector.gs_repository.load_recent_tlm_history",
        side_effect=lambda limit=600: [dict(row) for row in detector.get_history_records()[-limit:]],
    ):
        yield


def _official_satellite_packet(result: str = "Y") -> dict:
    telemetry = _normal_record()
    telemetry.update(
        {
            "UPDATED_AT": "2026-05-10T07:03:00+00:00",
            "OBC_P_HASH": "TAMPERED",
            "APPCSERRCOUNTER": 5,
            "LASTVALCRC": 101,
            "CH1_FAULT_CRC": 1,
            "HEAP_FREE": 300,
            "UTILCPUAVG": 95.0,
        }
    )
    return {
        "event_id": 42,
        "detected_at": "2026-05-10T07:03:00+00:00",
        "false_positive_result": result,
        "false_positive_weight": 88.5,
        "false_positive_exception": "",
        "target_subsystem": "ADCS",
        "sw_id_list": [0, 1],
        "telemetry": telemetry,
    }


class MAIntegratedDetectorTest(unittest.TestCase):
    def test_default_analysis_window_uses_original_size(self) -> None:
        detector = MAIntegratedDetector()

        self.assertEqual(DEFAULT_ANALYSIS_WINDOW_SEC, 600)
        self.assertEqual(detector._window_size_sec, DEFAULT_ANALYSIS_WINDOW_SEC)

    def test_rule_evaluation_and_ma_generation(self) -> None:
        detector = MAIntegratedDetector()
        detector.build_baseline([_normal_record() for _ in range(4)])

        anomaly = _normal_record()
        anomaly.update(
            {
                "UPDATED_AT": "2026-05-10T07:01:00+00:00",
                "IS_ANOMALY": True,
                "TARGET_SUBSYSTEM": "OBC",
                "FALSE_POSITIVE_RESULT": "Y",
                "OBC_P_HASH": "TAMPERED",
                "APPCSERRCOUNTER": 5,
                "LASTVALCRC": 101,
                "CH1_FAULT_CRC": 1,
                "HEAP_FREE": 300,
                "UTILCPUAVG": 95.0,
            }
        )

        rule_json = detector.evaluate_parallel_rules(json.dumps([anomaly]))
        rule_data = json.loads(rule_json)
        triggered_rule_ids = {result["rule_id"] for result in rule_data["rule_results"]}

        self.assertIn("E-03", triggered_rule_ids)
        self.assertIn("E-X3", triggered_rule_ids)

        final_input = json.loads(rule_json)
        final_input["sequence_adjustment"] = detector.verify_attack_sequence(rule_json)
        reports = json.loads(detector.generate_ma_code(json.dumps(final_input)))

        self.assertTrue(reports)
        self.assertIn(reports[0]["grade"], {"CONFIRMED", "SUSPECTED", "UNKNOWN"})

    def test_rule_score_threshold_filters_low_scores(self) -> None:
        detector = MAIntegratedDetector()
        detector._action_registry = {
            "A001": {
                "name": "MALICIOUS_PAYLOAD_INJECT",
                "module": "CF",
                "phase": 1,
                "weight": 1.0,
            }
        }
        detector._rule_registry = {
            "E-01": {
                "name": "파일 전송 무결성 이상",
                "columns": ["CH1_FAULT_CRC"],
                "contributes_to": {"A001": 0.4},
                "enabled": True,
                "score_threshold": 0.9,
            }
        }
        anomaly = _normal_record()
        anomaly["CH1_FAULT_CRC"] = 1

        rule_data = json.loads(detector.evaluate_parallel_rules(json.dumps([anomaly])))

        self.assertEqual(rule_data["rule_results"], [])

    def test_receive_telemetry_stores_ui_data(self) -> None:
        detector = MAIntegratedDetector()
        detector.build_baseline([_normal_record() for _ in range(4)])

        anomaly = _normal_record()
        anomaly.update(
            {
                "UPDATED_AT": "2026-05-10T07:02:00+00:00",
                "IS_ANOMALY": True,
                "TARGET_SUBSYSTEM": "OBC",
                "FALSE_POSITIVE_RESULT": "Y",
                "OBC_P_HASH": "TAMPERED",
                "APPCSERRCOUNTER": 5,
                "CH1_FAULT_CRC": 1,
                "HEAP_FREE": 300,
                "UTILCPUAVG": 95.0,
            }
        )

        detector.receive_telemetry(json.dumps(anomaly))
        with _ui_db_from_detector(detector):
            ui_payload = json.loads(detector.get_ui_data(1))

        self.assertNotIn("error", ui_payload)
        self.assertIn("ma_code", ui_payload)
        self.assertIn("detail", ui_payload)

    def test_receive_official_satellite_json_maps_filter_fields(self) -> None:
        detector = MAIntegratedDetector()
        normal_packet = _official_satellite_packet("N")
        normal_packet["telemetry"].update(_normal_record())
        detector.build_baseline([normal_packet for _ in range(4)])

        detector.receive_telemetry(json.dumps(_official_satellite_packet("Y")))
        with _ui_db_from_detector(detector):
            ui_payload = json.loads(detector.get_ui_data(1))

        self.assertNotIn("error", ui_payload)
        self.assertEqual(ui_payload["satellite_filter"]["result"], "Y")
        self.assertEqual(ui_payload["satellite_filter"]["weight"], 88.5)
        self.assertEqual(ui_payload["satellite_filter"]["target_subsystem"], "ADCS")
        self.assertEqual(ui_payload["satellite_filter"]["event_id"], 42)
        self.assertEqual(ui_payload["satellite_filter"]["sw_id_list"], [0, 1])
        self.assertEqual(ui_payload["detail"]["history"][0]["FALSE_POSITIVE_RESULT"], "Y")

    def test_attack_without_target_subsystem_returns_error(self) -> None:
        detector = MAIntegratedDetector()
        detector.build_baseline([_normal_record() for _ in range(4)])

        packet = _official_satellite_packet("Y")
        packet["target_subsystem"] = ""
        packet["sw_id_list"] = []

        error = detector.receive_telemetry(json.dumps(packet))

        self.assertIsNotNone(error)
        self.assertEqual(detector.get_dashboard_records(), [])

    def test_false_positive_n_does_not_generate_ma_dashboard_row(self) -> None:
        detector = MAIntegratedDetector()
        detector.build_baseline([_normal_record() for _ in range(4)])

        packet = _official_satellite_packet("N")
        detector.receive_telemetry(json.dumps(packet))
        ui_payload = json.loads(detector.get_ui_data(1))

        self.assertIn("error", ui_payload)

    def test_seu_packet_does_not_append_baseline(self) -> None:
        detector = MAIntegratedDetector()
        detector.build_baseline([_normal_record() for _ in range(4)])
        key = (2, 1)
        initial_buffer_len = len(detector._baseline_manager._normal_buffers[key])

        seu_packet = _normal_record()
        seu_packet.update(
            {
                "IS_ANOMALY": False,
                "FALSE_POSITIVE_RESULT": "N",
                "FALSE_POSITIVE_WEIGHT": 28,
                "SW_0_VOLTAGE": 99.0,
            }
        )
        detector.receive_telemetry(json.dumps(seu_packet))

        self.assertEqual(len(detector._baseline_manager._normal_buffers[key]), initial_buffer_len)

    def test_zero_weight_normal_packet_appends_baseline(self) -> None:
        detector = MAIntegratedDetector()
        detector.build_baseline([_normal_record() for _ in range(4)])
        key = (2, 1)
        initial_buffer_len = len(detector._baseline_manager._normal_buffers[key])

        normal_packet = _normal_record()
        normal_packet.update(
            {
                "IS_ANOMALY": False,
                "FALSE_POSITIVE_WEIGHT": 0,
                "SW_0_VOLTAGE": 3.3,
            }
        )
        detector.receive_telemetry(json.dumps(normal_packet))

        self.assertEqual(len(detector._baseline_manager._normal_buffers[key]), initial_buffer_len + 1)

    def test_persist_bulk_telemetry_packet_inserts_one_row_per_sample(self) -> None:
        detector = MAIntegratedDetector()
        calls: list[dict] = []

        def fake_insert(prepared: dict) -> int:
            calls.append(dict(prepared))
            return len(calls)

        bulk = {
            "packet_type": "SAT_BULK_TELEMETRY",
            "_comm_session": "comm-bulk-1",
            "SAT_TLM_HISTORY": {
                "records": [
                    {
                        "HISTORY_ID": 899,
                        "UPDATED_AT": "2026-05-31T05:20:33+09:00",
                        "MISSION_MODE": 2,
                        "ERLOGENTRIES": 5,
                    },
                    {
                        "HISTORY_ID": 900,
                        "UPDATED_AT": "2026-05-31T05:20:40+09:00",
                        "MISSION_MODE": 2,
                        "ERLOGENTRIES": 6,
                    },
                ]
            },
            "SAT_ADCS_FILTER": {
                "records": [
                    {"TIMESTAMP": "2026-05-31T05:20:33+09:00", "IMU_WBN_X": 0.01, "ERLOGENTRIES": 0},
                    {"TIMESTAMP": "2026-05-31T05:20:40+09:00", "IMU_WBN_X": 0.02, "ERLOGENTRIES": 0},
                ]
            },
            "SAT_PWR_HISTORY": {
                "records": [
                    {
                        "HISTORY_ID": 11495,
                        "UPDATED_AT": "2026-05-31T05:20:33+09:00",
                        "channels": [{"SW_ID": 0, "VOLTAGE": 3.2, "CURRENT_A": 0.1}],
                    },
                    {
                        "HISTORY_ID": 11496,
                        "UPDATED_AT": "2026-05-31T05:20:40+09:00",
                        "channels": [{"SW_ID": 0, "VOLTAGE": 3.3, "CURRENT_A": 0.2}],
                    },
                ]
            },
        }

        with patch("ma_detector.ma_integrated_detector.is_db_available", return_value=True):
            pwr_calls: list[tuple] = []

            def fake_pwr(packet: dict, history_id: int | None = None) -> bool:
                pwr_calls.append((dict(packet), history_id))
                return True

            with patch(
                "ma_detector.ma_integrated_detector.gs_repository.insert_tlm_history",
                side_effect=fake_insert,
            ):
                with patch(
                    "ma_detector.ma_integrated_detector.gs_repository.insert_pwr_meta_rows",
                    side_effect=fake_pwr,
                ):
                    inserted, skipped = detector.persist_bulk_telemetry_packet(bulk)
                    self.assertEqual((inserted, skipped), (2, 0))
                    self.assertEqual(len(calls), 2)
                    self.assertEqual(len(pwr_calls), 2)
                    self.assertEqual(pwr_calls[0][1], 1)
                    self.assertEqual(pwr_calls[1][1], 2)
                    self.assertEqual(calls[0]["MISSION_MODE"], 2)
                    self.assertEqual(calls[0]["IMU_WBN_X"], 0.01)
                    self.assertEqual(calls[0]["SW_0_VOLTAGE"], 3.2)
                    self.assertEqual(calls[0]["TLM_ERLOGENTRIES"], 5)
                    self.assertEqual(calls[0]["ADCS_ERLOGENTRIES"], 0)
                    self.assertEqual(calls[0]["ERLOGENTRIES"], 5)

                    inserted, skipped = detector.persist_bulk_telemetry_packet(bulk)
                    self.assertEqual((inserted, skipped), (0, 2))
                    self.assertEqual(len(calls), 2)

    def test_persist_bulk_inserts_each_event_separately(self) -> None:
        detector = MAIntegratedDetector()
        event_calls: list[dict] = []

        def fake_event_insert(row: dict) -> int:
            event_calls.append(dict(row))
            return len(event_calls)

        bulk = {
            "packet_type": "SAT_BULK_TELEMETRY",
            "_comm_session": "comm-events",
            "SAT_EVENT_QUEUE": {
                "events": [
                    {
                        "EVENT_ID": 10,
                        "SNAPSHOT_ID": 30,
                        "DETECTED_AT": "2026-05-31T12:00:00+09:00",
                        "EVENT_TYPE": "SEU_DETECTED",
                        "WEIGHT": 28,
                    },
                    {
                        "EVENT_ID": 11,
                        "SNAPSHOT_ID": 31,
                        "DETECTED_AT": "2026-05-31T12:00:01+09:00",
                        "EVENT_TYPE": "ATTACK_CONFIRMED",
                        "WEIGHT": 100,
                    },
                ]
            },
            "SAT_TLM_HISTORY": {
                "records": [
                    {"SNAPSHOT_ID": 30, "UPDATED_AT": "2026-05-31T12:00:00+09:00", "MISSION_MODE": 2},
                    {"SNAPSHOT_ID": 31, "UPDATED_AT": "2026-05-31T12:00:01+09:00", "MISSION_MODE": 2},
                ]
            },
        }

        with patch("ma_detector.ma_integrated_detector.is_db_available", return_value=True):
            with patch(
                "ma_detector.ma_integrated_detector.gs_repository.insert_tlm_history",
                side_effect=lambda prepared: prepared.get("SNAPSHOT_ID", 0),
            ):
                with patch(
                    "ma_detector.ma_integrated_detector.gs_repository.insert_pwr_meta_rows",
                    return_value=True,
                ):
                    with patch(
                        "ma_detector.ma_integrated_detector.gs_repository.insert_event_queue_row",
                        side_effect=fake_event_insert,
                    ):
                        inserted, skipped = detector.persist_bulk_telemetry_packet(bulk)
                        self.assertEqual((inserted, skipped), (2, 0))
                        self.assertEqual(len(event_calls), 2)
                        self.assertEqual(event_calls[0]["EVENT_ID"], 10)
                        self.assertEqual(event_calls[0]["EVENT_TYPE"], "SEU_DETECTED")
                        self.assertNotIn("IS_ANOMALY", event_calls[0])
                        self.assertEqual(event_calls[1]["EVENT_ID"], 11)
                        self.assertEqual(event_calls[1]["EVENT_TYPE"], "ATTACK_CONFIRMED")
                        self.assertNotIn("TARGET_SUBSYSTEM", event_calls[1])
                        self.assertEqual(len(detector.get_event_queue_records()), 2)
                        attack_record = derive_ma_fields_from_event(detector.get_event_queue_records()[1])
                        self.assertTrue(attack_record["IS_ANOMALY"])


if __name__ == "__main__":
    unittest.main()
