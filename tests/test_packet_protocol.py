"""Tests for satellite packet protocol helpers."""

from __future__ import annotations

import unittest

from ma_detector import MAIntegratedDetector
from ma_detector.core.packet_protocol import (
    BULK_HISTORY_TYPES,
    BULK_TELEMETRY_PACKET_TYPE,
    build_bulk_telemetry_packet,
    detection_snapshots_from_history,
    event_is_attack_anomaly,
    expand_bulk_telemetry_packet,
    flatten_integrity_record,
    infer_subsystem_from_file_path,
    is_accumulated_bulk_packet,
    is_bulk_telemetry_packet,
    latest_record_time_key,
    merge_history_snapshots,
    normalize_packet_type,
    packet_buffer_keys,
    select_integrity_record,
    select_nearest_record_for_key,
    should_append_baseline,
    slice_packet_for_key,
    summarize_uplink_packet,
    timestamp_to_epoch,
)


class PacketProtocolTest(unittest.TestCase):
    def test_packet_type_aliases(self) -> None:
        self.assertEqual(normalize_packet_type("SAT_TLM_CURRENT"), "SAT_TLM_HISTORY")
        self.assertEqual(normalize_packet_type("SAT_PWR_META"), "SAT_PWR_HISTORY")

    def test_accumulated_bulk_does_not_fan_out_buffer_keys(self) -> None:
        packet = {
            "packet_type": "SAT_TLM_HISTORY",
            "records": [
                {"UPDATED_AT": "2026-05-30T12:00:00+00:00"},
                {"UPDATED_AT": "2026-05-30T12:01:00+00:00"},
            ],
        }
        self.assertTrue(is_accumulated_bulk_packet(packet))
        self.assertEqual(packet_buffer_keys(packet), [])

    def test_latest_record_time_key(self) -> None:
        packet = {
            "packet_type": "SAT_TLM_HISTORY",
            "records": [
                {"UPDATED_AT": "2026-05-30T12:00:00+00:00"},
                {"UPDATED_AT": "2026-05-30T12:01:00+00:00"},
            ],
        }
        self.assertEqual(latest_record_time_key(packet), "2026-05-30T12:01:00")

    def test_nearest_record_within_tolerance(self) -> None:
        packet = {
            "packet_type": "SAT_TLM_HISTORY",
            "records": [
                {"UPDATED_AT": "2026-05-30T12:00:58+00:00", "MISSION_MODE": 1},
                {"UPDATED_AT": "2026-05-30T12:01:08+00:00", "MISSION_MODE": 2},
            ],
        }
        nearest = select_nearest_record_for_key(packet, "2026-05-30T12:01:00", tolerance_sec=5)
        self.assertIsNotNone(nearest)
        assert nearest is not None
        self.assertEqual(nearest["MISSION_MODE"], 1)

    def test_nearest_record_prefers_exact_match(self) -> None:
        packet = {
            "packet_type": "SAT_TLM_HISTORY",
            "records": [
                {"UPDATED_AT": "2026-05-30T11:59:59+00:00", "MISSION_MODE": 1},
                {"UPDATED_AT": "2026-05-30T12:00:00+00:00", "MISSION_MODE": 2},
            ],
        }
        nearest = select_nearest_record_for_key(packet, "2026-05-30T12:00:00", tolerance_sec=5)
        self.assertIsNotNone(nearest)
        assert nearest is not None
        self.assertEqual(nearest["MISSION_MODE"], 2)

    def test_integrity_record_prefers_violated_within_bucket(self) -> None:
        packet = {
            "packet_type": "SAT_INTEGRITY_HASH",
            "records": [
                {
                    "IS_VIOLATED": 1,
                    "EXPECTED_HASH": "bbb",
                    "FILE_PATH": "/cf/apps/adcs.so",
                    "UPDATED_AT": "2026-05-30T12:01:00+00:00",
                },
                {
                    "IS_VIOLATED": 1,
                    "EXPECTED_HASH": "ccc",
                    "FILE_PATH": "/cf/apps/obc.so",
                    "UPDATED_AT": "2026-05-30T12:09:00+00:00",
                },
            ],
        }
        chosen = select_integrity_record(
            packet,
            buffer_key="2026-05-30T12:01:00",
            tolerance_sec=5,
        )
        self.assertIsNotNone(chosen)
        assert chosen is not None
        self.assertEqual(chosen["EXPECTED_HASH"], "bbb")

    def test_integrity_record_ignores_rows_outside_bucket_window(self) -> None:
        packet = {
            "packet_type": "SAT_INTEGRITY_HASH",
            "records": [
                {
                    "IS_VIOLATED": 1,
                    "EXPECTED_HASH": "bbb",
                    "UPDATED_AT": "2026-05-30T12:09:00+00:00",
                },
            ],
        }
        chosen = select_integrity_record(
            packet,
            buffer_key="2026-05-30T12:01:00",
            tolerance_sec=5,
        )
        self.assertIsNone(chosen)

    def test_infer_subsystem_from_file_path(self) -> None:
        self.assertEqual(infer_subsystem_from_file_path("/cf/apps/adcs.so"), "ADCS")
        self.assertEqual(infer_subsystem_from_file_path("/cf/apps/obc.so"), "OBC")

    def test_slice_packet_for_key_ignores_other_records(self) -> None:
        packet = {
            "packet_type": "SAT_ADCS_FILTER",
            "records": [
                {"TIMESTAMP": "2026-05-30T12:00:00+00:00", "CHENNEL1": 9, "QBN_0": 0.1},
                {"TIMESTAMP": "2026-05-30T12:01:00+00:00", "CHENNEL1": 8, "QBN_0": 0.9},
            ],
        }
        sliced = slice_packet_for_key(packet, "2026-05-30T12:01:00")
        self.assertEqual(sliced["_active_record"]["QBN_0"], 0.9)
        self.assertNotIn("CHENNEL1", sliced["_active_record"])

    def test_merge_sat_tlm_history_record(self) -> None:
        detector = MAIntegratedDetector()
        merged = detector._merge_packet_sections(
            {
                "packet_type": "SAT_TLM_HISTORY",
                "records": [
                    {
                        "UPDATED_AT": "2026-05-30T12:00:00+00:00",
                        "MISSION_MODE": 2,
                        "ADCS_MODE": 1,
                    }
                ],
                "_active_record": {
                    "UPDATED_AT": "2026-05-30T12:00:00+00:00",
                    "MISSION_MODE": 2,
                    "ADCS_MODE": 1,
                },
            }
        )
        self.assertEqual(merged["packet_type"], "SAT_TLM_HISTORY")
        self.assertEqual(merged["MISSION_MODE"], 2)

    def test_seu_event_does_not_create_buffer_key(self) -> None:
        packet = {
            "packet_type": "SAT_EVENT_QUEUE",
            "event": {
                "DETECTED_AT": "2026-05-30T12:00:05+00:00",
                "EVENT_TYPE": "SEU_DETECTED",
                "WEIGHT": 28,
            },
        }
        self.assertFalse(event_is_attack_anomaly(packet["event"]))
        self.assertEqual(packet_buffer_keys(packet), [])

    def test_attack_event_creates_buffer_key(self) -> None:
        packet = {
            "packet_type": "SAT_EVENT_QUEUE",
            "event": {
                "DETECTED_AT": "2026-05-30T12:01:00+00:00",
                "EVENT_TYPE": "ATTACK_CONFIRMED",
                "WEIGHT": 100,
            },
        }
        self.assertTrue(event_is_attack_anomaly(packet["event"]))
        self.assertEqual(packet_buffer_keys(packet), ["2026-05-30T12:01:00"])

    def test_should_append_baseline_requires_zero_weight(self) -> None:
        self.assertTrue(should_append_baseline({"IS_ANOMALY": False, "FALSE_POSITIVE_WEIGHT": 0}))
        self.assertFalse(should_append_baseline({"IS_ANOMALY": False, "FALSE_POSITIVE_WEIGHT": 28}))
        self.assertFalse(should_append_baseline({"IS_ANOMALY": True, "FALSE_POSITIVE_WEIGHT": 0}))

    def test_merge_integrity_sets_target_from_file_path(self) -> None:
        detector = MAIntegratedDetector()
        merged = detector._merge_packet_sections(
            {
                "packet_type": "SAT_INTEGRITY_HASH",
                "_buffer_key": "2026-05-30T12:01:00",
                "records": [
                    {
                        "IS_VIOLATED": 1,
                        "EXPECTED_HASH": "deadbeef",
                        "FILE_PATH": "/cf/apps/adcs.so",
                        "UPDATED_AT": "2026-05-30T12:01:00+00:00",
                    }
                ],
                "_active_record": {
                    "IS_VIOLATED": 1,
                    "EXPECTED_HASH": "deadbeef",
                    "FILE_PATH": "/cf/apps/adcs.so",
                    "UPDATED_AT": "2026-05-30T12:01:00+00:00",
                },
            }
        )
        self.assertEqual(merged["TARGET_SUBSYSTEM"], "ADCS")
        self.assertEqual(merged["IS_VIOLATED"], 1)
        self.assertEqual(merged["EXPECTED_CRC"], "deadbeef")
        self.assertNotEqual(merged["OBC_P_HASH"], merged["EXPECTED_CRC"])

    def test_select_integrity_record_prefers_violated_without_timestamps(self) -> None:
        packet = {
            "packet_type": "SAT_INTEGRITY_HASH",
            "records": [
                {
                    "FILE_ID": 1,
                    "FILE_PATH": "/cf/apps/to_lab.so",
                    "EXPECTED_HASH": "a3f2c891d4e5b6078190ab12cd34ef56",
                    "IS_VIOLATED": 0,
                },
                {
                    "FILE_ID": 2,
                    "FILE_PATH": "/cf/apps/adcs.so",
                    "EXPECTED_HASH": "7b1e9043c2d8a5f60123456789abcdef0",
                    "IS_VIOLATED": 1,
                },
            ],
        }
        chosen = select_integrity_record(packet, buffer_key="2026-05-30T12:05:00")
        self.assertIsNotNone(chosen)
        assert chosen is not None
        self.assertEqual(chosen["FILE_PATH"], "/cf/apps/adcs.so")
        flattened = flatten_integrity_record(chosen)
        self.assertEqual(flattened["IS_VIOLATED"], 1)
        self.assertEqual(flattened["EXPECTED_CRC"], "7b1e9043c2d8a5f60123456789abcdef0")
        self.assertNotEqual(flattened["OBC_P_HASH"], flattened["EXPECTED_CRC"])
        self.assertEqual(flattened["TARGET_SUBSYSTEM"], "ADCS")

    def test_timestamp_to_epoch_handles_mysql_datetime(self) -> None:
        from datetime import datetime, timezone

        naive = datetime(2026, 5, 30, 21, 5, 0)
        expected = datetime(2026, 5, 30, 21, 5, 0, tzinfo=timezone.utc).timestamp()
        self.assertEqual(timestamp_to_epoch(naive), expected)
        self.assertEqual(timestamp_to_epoch("2026-05-30 21:05:00"), expected)

    def test_merge_history_snapshots_prefers_anomaly_row(self) -> None:
        partial = {
            "HISTORY_ID": 1,
            "UPDATED_AT": "2026-05-30 21:05:00",
            "MISSION_MODE": 2,
            "IS_ANOMALY": 0,
        }
        anomaly = {
            "HISTORY_ID": 2,
            "UPDATED_AT": "2026-05-30 21:05:00",
            "IS_ANOMALY": 1,
            "CH1_FAULT_CRC": 1,
            "APPCSERRCOUNTER": 5,
        }
        merged = merge_history_snapshots([partial, anomaly])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["MISSION_MODE"], 2)
        self.assertEqual(merged[0]["CH1_FAULT_CRC"], 1)
        self.assertEqual(merged[0]["APPCSERRCOUNTER"], 5)

    def test_detection_snapshots_from_history(self) -> None:
        rows = [
            {"UPDATED_AT": "2026-05-12 07:19:59", "OBC_P_HASH": "0xAAA"},
            {"UPDATED_AT": "2026-05-12 07:20:00", "OBC_P_HASH": "0xBBB", "IS_ANOMALY": 1},
        ]
        previous, current = detection_snapshots_from_history(rows, "2026-05-12 07:20:00")
        self.assertEqual(previous.get("OBC_P_HASH"), "0xAAA")
        self.assertEqual(current.get("OBC_P_HASH"), "0xBBB")

    def test_expand_bulk_telemetry_packet(self) -> None:
        bulk = {
            "packet_type": "SAT_BULK_TELEMETRY",
            "sent_at": "2026-05-31T04:37:20+09:00",
            "SAT_ADCS_FILTER": {
                "records": [{"TIMESTAMP": "2026-05-31T04:37:18+09:00", "IMU_WBN_X": 0.016}]
            },
            "SAT_TLM_HISTORY": {
                "records": [{"UPDATED_AT": "2026-05-31T04:37:18+09:00", "MISSION_MODE": 2}]
            },
            "SAT_PWR_HISTORY": {
                "records": [
                    {
                        "UPDATED_AT": "2026-05-31T04:37:19+09:00",
                        "channels": [{"SW_ID": 0, "VOLTAGE": 3.24}],
                    }
                ]
            },
        }
        self.assertTrue(is_bulk_telemetry_packet(bulk))
        children = expand_bulk_telemetry_packet(bulk)
        self.assertEqual([child["packet_type"] for child in children], [
            "SAT_ADCS_FILTER",
            "SAT_TLM_HISTORY",
            "SAT_PWR_HISTORY",
        ])
        self.assertEqual(children[0]["records"][0]["IMU_WBN_X"], 0.016)

    def test_expand_bulk_telemetry_with_event_queue_events(self) -> None:
        bulk = {
            "packet_type": "SAT_BULK_TELEMETRY",
            "SAT_EVENT_QUEUE": {
                "event_total": 1,
                "event_ids": [42],
                "events": [{"EVENT_ID": 42, "EVENT_TYPE": "ATTACK_CONFIRMED", "WEIGHT": 78}],
            },
            "SAT_SNAPSHOT": {"records": [{"SNAPSHOT_ID": 30}]},
            "SAT_TLM_HISTORY": {"records": [{"SNAPSHOT_ID": 30, "MISSION_MODE": 2}]},
        }
        children = expand_bulk_telemetry_packet(bulk)
        types = [child["packet_type"] for child in children]
        self.assertIn("SAT_EVENT_QUEUE", types)
        event_child = next(child for child in children if child["packet_type"] == "SAT_EVENT_QUEUE")
        self.assertEqual(len(event_child["events"]), 1)
        self.assertEqual(event_child["events"][0]["EVENT_ID"], 42)

    def test_build_and_summarize_bulk_telemetry(self) -> None:
        sections = {
            "SAT_TLM_HISTORY": {"records": [{"UPDATED_AT": "2026-05-31T04:37:18+09:00"}]},
            "SAT_PWR_HISTORY": {"records": [{"UPDATED_AT": "2026-05-31T04:37:19+09:00", "channels": []}]},
        }
        bulk = build_bulk_telemetry_packet(sections, sent_at="2026-05-31T04:37:20+09:00")
        self.assertEqual(bulk["packet_type"], BULK_TELEMETRY_PACKET_TYPE)
        summary = summarize_uplink_packet(bulk)
        self.assertIn("BULK", summary)
        self.assertIn("SAT_TLM_HISTORY=1", summary)


if __name__ == "__main__":
    unittest.main()
