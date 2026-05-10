"""Smoke tests for the MA integrated detector pipeline."""

from __future__ import annotations

import json
import unittest

from ma_detector import MAIntegratedDetector


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


class MAIntegratedDetectorTest(unittest.TestCase):
    def test_rule_evaluation_and_ma_generation(self) -> None:
        detector = MAIntegratedDetector()
        detector.build_baseline([_normal_record() for _ in range(4)])

        anomaly = _normal_record()
        anomaly.update(
            {
                "UPDATED_AT": "2026-05-10T07:01:00+00:00",
                "IS_ANOMALY": True,
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

    def test_receive_telemetry_stores_ui_data(self) -> None:
        detector = MAIntegratedDetector()
        detector.build_baseline([_normal_record() for _ in range(4)])

        anomaly = _normal_record()
        anomaly.update(
            {
                "UPDATED_AT": "2026-05-10T07:02:00+00:00",
                "IS_ANOMALY": True,
                "OBC_P_HASH": "TAMPERED",
                "APPCSERRCOUNTER": 5,
                "CH1_FAULT_CRC": 1,
                "HEAP_FREE": 300,
                "UTILCPUAVG": 95.0,
            }
        )

        detector.receive_telemetry(json.dumps(anomaly))
        ui_payload = json.loads(detector.get_ui_data(1))

        self.assertNotIn("error", ui_payload)
        self.assertIn("ma_code", ui_payload)
        self.assertIn("detail", ui_payload)


if __name__ == "__main__":
    unittest.main()
