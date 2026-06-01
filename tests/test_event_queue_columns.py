"""Tests for onboard SAT_EVENT_QUEUE wire field mapping."""

from __future__ import annotations

import unittest

from ma_detector.core.event_queue_columns import (
    ONBOARD_EVENT_WIRE_FIELDS,
    apply_onboard_event_to_queue_row,
    parse_module_scores,
    strip_event_fields_from_tlm_packet,
)
from ma_detector.core.ma_onboard_view import derive_ma_fields_from_event
from ma_detector.core.bulk_history_merge import build_event_queue_row

SAMPLE_WIRE_EVENT = {
    "SW_ID": 0,
    "WEIGHT": 69,
    "IS_SENT": 0,
    "EVENT_ID": 88,
    "PRIORITY": 1,
    "TIMESTAMP": "2026-06-01T23:07:53.260273+09:00",
    "EVENT_TYPE": "ATTACK_CONFIRMED",
    "DETECTED_AT": "2026-06-01T23:07:53.260273+09:00",
    "MODULE_SCORES": '{"physical":1.0,"statistical":0.64,"system":0.0}',
    "EXCEPTION_CODE": 0,
    "CHILDQUEUECOUNT": 1051,
    "CH1_CH2_FAULT_CRC": 0,
    "PIPEOVERFLOWRRCNT": 3,
    "CMDREJECTEDCOUNTER": 0,
    "FILEWRITEERRCOUNTER": 0,
    "PROCESSOR_RESET_COUNT": 2,
    "CH1_FAULT_FILE_SIZE_MISMATCH": 3,
}


class EventQueueColumnsTest(unittest.TestCase):
    def test_wire_fields_list_matches_sample(self) -> None:
        for key in SAMPLE_WIRE_EVENT:
            self.assertIn(key, ONBOARD_EVENT_WIRE_FIELDS)

    def test_module_scores_string_parsed(self) -> None:
        scores = parse_module_scores(SAMPLE_WIRE_EVENT["MODULE_SCORES"])
        self.assertIsNotNone(scores)
        assert scores is not None
        self.assertAlmostEqual(scores["physical"], 1.0)
        self.assertAlmostEqual(scores["statistical"], 0.64)

    def test_build_event_queue_row_from_wire_sample(self) -> None:
        row = build_event_queue_row(SAMPLE_WIRE_EVENT, bulk_sent_at="2026-06-01T23:07:53+09:00")
        self.assertEqual(row["EVENT_ID"], 88)
        self.assertEqual(row["EVENT_TYPE"], "ATTACK_CONFIRMED")
        self.assertEqual(row["WEIGHT"], 69)
        self.assertEqual(row["PIPEOVERFLOWRRCNT"], 3)
        self.assertNotIn("IS_ANOMALY", row)
        self.assertNotIn("TARGET_SUBSYSTEM", row)
        self.assertNotIn("CH1_FAULT_CRC", row)
        self.assertNotIn("CH2_FAULT_CRC", row)
        self.assertIsInstance(row["MODULE_SCORES"], dict)
        derived = derive_ma_fields_from_event(row)
        self.assertTrue(derived["IS_ANOMALY"])
        self.assertEqual(derived["FALSE_POSITIVE_RESULT"], "Y")
        self.assertEqual(derived["FALSE_POSITIVE_WEIGHT"], 69)
        self.assertIn("TIMESTAMP", row)
        self.assertIn("DETECTED_AT", row)
        self.assertEqual(row["PAYLOAD"]["EVENT_ID"], 88)

    def test_strip_event_fields_from_tlm(self) -> None:
        tlm = {
            "MISSION_MODE": 2,
            "UPDATED_AT": "2026-06-01T23:07:53+09:00",
            "EVENT_ID": 88,
            "IS_ANOMALY": True,
            "WEIGHT": 69,
        }
        cleaned = strip_event_fields_from_tlm_packet(tlm)
        self.assertEqual(cleaned["MISSION_MODE"], 2)
        self.assertNotIn("EVENT_ID", cleaned)
        self.assertNotIn("IS_ANOMALY", cleaned)
        self.assertNotIn("WEIGHT", cleaned)

    def test_apply_onboard_event_to_queue_row(self) -> None:
        row: dict = {}
        apply_onboard_event_to_queue_row(row, SAMPLE_WIRE_EVENT)
        self.assertEqual(row["CHILDQUEUECOUNT"], 1051)
        self.assertEqual(row["SW_ID"], 0)
        self.assertNotIn("TARGET_SUBSYSTEM", row)
        self.assertEqual(derive_ma_fields_from_event(row)["TARGET_SUBSYSTEM"], "ADCS")


if __name__ == "__main__":
    unittest.main()
