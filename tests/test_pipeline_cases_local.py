"""Local pipeline expectations for cases 1-4 without HTTP/MySQL."""

from __future__ import annotations

import asyncio
import json
import unittest
from pathlib import Path

from api.packet_buffer import PacketBufferManager
from ma_detector.core.packet_protocol import combine_uplink_packets_to_bulk
from ma_detector.ma_integrated_detector import MAIntegratedDetector

ROOT = Path(__file__).resolve().parents[1]
CASES_PATH = ROOT / "backend" / "test_data" / "pipeline_cases.json"

ALLOWED_CASE3_CODES = {
    "CS_INTEGRITY_CHECK_BYPASS_P3",
    "OBC+CF_SEU_DISGUISED_INTRUSION_P1",
}
CASE4_CODE = "ADCS_ATTITUDE_CONTROL_TAMPERING_P3"
UNMAPPED_CODE = "UNMAPPED_SATELLITE_ATTACK_P0"


def _load_case(case_id: str) -> list[dict]:
    payload = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    return payload["cases"][case_id]["packets"]


class PipelineCaseLocalTest(unittest.TestCase):
    def _run_case(self, case_id: str) -> tuple[list[dict], list[dict]]:
        detector = MAIntegratedDetector()
        normal_history = _load_case("1")
        detector.build_baseline(normal_history[:1])

        def on_bulk_persist(bulk: dict) -> None:
            detector.persist_bulk_telemetry_packet(bulk)

        async def ingest() -> None:
            buffer = PacketBufferManager(on_bulk_telemetry_persist=on_bulk_persist)
            packets = combine_uplink_packets_to_bulk(_load_case(case_id))
            for packet in packets:
                await buffer.receive(packet)

        asyncio.run(ingest())
        dashboard_rows = detector.get_dashboard_records()
        return dashboard_rows, detector.get_history_records()

    def test_case1_normal_no_ma(self) -> None:
        dashboard_rows, history_rows = self._run_case("1")
        self.assertGreaterEqual(len(history_rows), 0)
        self.assertEqual(len(dashboard_rows), 0)

    def test_case2_seu_no_ma(self) -> None:
        dashboard_rows, _history = self._run_case("2")
        self.assertEqual(len(dashboard_rows), 0)

    def test_case3_integrity_mapped_ma(self) -> None:
        dashboard_rows, _history = self._run_case("3")
        self.assertGreater(len(dashboard_rows), 0)
        codes = {row.get("MA_CODE") for row in dashboard_rows}
        self.assertNotIn(UNMAPPED_CODE, codes)
        self.assertTrue(codes & ALLOWED_CASE3_CODES, f"unexpected codes: {codes}")
        latest = dashboard_rows[-1]
        self.assertIn(latest.get("GRADE"), ("CONFIRMED", "SUSPECTED"))
        targets = {row.get("TARGET_SUBSYSTEM") for row in dashboard_rows}
        self.assertTrue(targets & {"COM", "EPS", "OBC", "ADCS"}, f"unexpected targets: {targets}")

    def test_case4_adcs_attack_ma(self) -> None:
        dashboard_rows, _history = self._run_case("4")
        self.assertGreater(len(dashboard_rows), 0)
        codes = {row.get("MA_CODE") for row in dashboard_rows}
        self.assertNotIn(UNMAPPED_CODE, codes)
        self.assertIn(CASE4_CODE, codes)
        matching = [row for row in dashboard_rows if row.get("MA_CODE") == CASE4_CODE][0]
        self.assertIn(matching.get("GRADE"), ("CONFIRMED", "SUSPECTED"))


if __name__ == "__main__":
    unittest.main()
