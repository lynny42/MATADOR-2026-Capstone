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
from ma_detector.db.gs_repository import (
    build_tlm_history_insert_row,
    enrich_packet_from_db,
    prepare_packet_for_db,
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


if __name__ == "__main__":
    unittest.main()
