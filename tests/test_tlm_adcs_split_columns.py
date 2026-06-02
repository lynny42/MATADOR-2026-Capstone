"""Tests for TLM/ADCS split DB column mapping."""

from __future__ import annotations

import unittest

from ma_detector.core.bulk_history_merge import merge_bulk_telemetry_sections
from ma_detector.core.tlm_adcs_columns import (
    TLM_ADCS_OVERLAP_FIELDS,
    adcs_column,
    all_split_column_ddls,
    tlm_column,
)
from ma_detector.core.baseline import BaselineManager
from ma_detector.core.evidence_rules import EvidenceRules
from ma_detector.db.gs_repository import (
    build_tlm_history_insert_row,
    enrich_packet_from_db,
    prepare_packet_for_db,
    sanitize_rule_engine_fields,
)


class TlmAdcsSplitColumnsTest(unittest.TestCase):
    def test_all_split_columns_defined(self) -> None:
        names = {name for name, _ddl in all_split_column_ddls()}
        for field in TLM_ADCS_OVERLAP_FIELDS:
            self.assertIn(tlm_column(field), names)
            self.assertIn(adcs_column(field), names)
        self.assertIn("TLM_HISTORY_ID", names)
        self.assertIn("ADCS_ERLOGENTRIES", names)

    def test_prepare_packet_for_db_keeps_split_columns(self) -> None:
        rows = merge_bulk_telemetry_sections(
            [{"TIMESTAMP": "2026-05-31T05:20:33+09:00", "ERLOGENTRIES": 0, "IMU_WBN_X": 0.1}],
            [
                {
                    "HISTORY_ID": 901,
                    "UPDATED_AT": "2026-05-31T05:20:33+09:00",
                    "ERLOGENTRIES": 5,
                    "MISSION_MODE": 2,
                }
            ],
            None,
        )
        prepared = prepare_packet_for_db(rows[0])
        self.assertEqual(prepared["TLM_ERLOGENTRIES"], 5)
        self.assertEqual(prepared["ADCS_ERLOGENTRIES"], 0)
        self.assertEqual(prepared["ERLOGENTRIES"], 5)
        self.assertEqual(prepared["TLM_HISTORY_ID"], 901)
        self.assertEqual(prepared["IMU_WBN_X"], 0.1)

    def test_build_tlm_history_insert_row_strips_bulk_wire_payload(self) -> None:
        prepared = {
            "MISSION_MODE": 2,
            "UPDATED_AT": "2026-05-31T05:20:33+09:00",
            "WIRE_PAYLOAD": {"packet_type": "SAT_BULK_TELEMETRY", "sent_at": "x"},
            "SOURCE_RECORDS": {"tlm": []},
        }
        row = build_tlm_history_insert_row(prepared)
        self.assertNotIn("WIRE_PAYLOAD", row)
        self.assertNotIn("RAW_PAYLOAD", row)
        self.assertNotIn("WIRE_PAYLOAD", row["PAYLOAD"])
        self.assertEqual(row["PAYLOAD"]["MISSION_MODE"], 2)

    def test_enrich_packet_from_db_does_not_copy_expected_hash_to_obc_p_hash(self) -> None:
        enriched = enrich_packet_from_db(
            {
                "EXPECTED_HASH": "0xAAA",
                "IS_VIOLATED": 0,
            },
        )
        self.assertEqual(enriched.get("EXPECTED_CRC"), "0xAAA")
        self.assertIsNone(enriched.get("OBC_P_HASH"))

    def test_sanitize_negative_combined_packets_sent(self) -> None:
        packet = sanitize_rule_engine_fields({"COMBINEDPACKETSSENT": -2})
        self.assertIsNone(packet.get("COMBINEDPACKETSSENT"))

    def test_sanitize_device_err_rw_from_enabled_flags(self) -> None:
        packet = sanitize_rule_engine_fields(
            {
                "DEVICE_ENABLED_RW0": 1,
                "DEVICE_ENABLED_RW1": 0,
                "DEVICE_ENABLED_RW2": 0,
            },
        )
        self.assertEqual(packet.get("DEVICE_ERR_RW0"), 0)
        self.assertEqual(packet.get("DEVICE_ERR_RW1"), 1)
        self.assertEqual(packet.get("DEVICE_ERR_RW2"), 1)

    def test_e11_low_imu_variance_indicates_ghost_telemetry(self) -> None:
        rules = EvidenceRules(
            BaselineManager(),
            {"z_score": {"SOFT": 2.0, "HARD": 3.0, "SEVERE": 4.0}, "absolute": {}},
        )
        frozen_score = rules._e11(
            [{"IMU_WBN_VARIANCE": 0.0, "RAW_MAG_VARIANCE": 0.0, "ST_VALID": 0}],
        )
        normal_score = rules._e11(
            [{"IMU_WBN_VARIANCE": 0.01, "RAW_MAG_VARIANCE": 0.01, "ST_VALID": 1}],
        )
        self.assertGreaterEqual(frozen_score, 0.6)
        self.assertEqual(normal_score, 0.0)


if __name__ == "__main__":
    unittest.main()
