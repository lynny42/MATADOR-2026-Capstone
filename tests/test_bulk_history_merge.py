"""Tests for SAT_BULK_TELEMETRY history merge by HISTORY_ID index."""

from __future__ import annotations

import unittest

from ma_detector.core.ma_onboard_view import derive_ma_fields_from_event
from ma_detector.core.bulk_history_merge import (
    build_event_queue_row,
    build_ma_reference_packet,
    extract_bulk_event_records,
    find_nearest_history_for_event,
    merge_bulk_telemetry_packet,
    merge_bulk_telemetry_sections,
    resolve_event_history_link,
)


class BulkHistoryMergeTest(unittest.TestCase):
    def test_overlap_fields_are_prefixed_not_overwritten(self) -> None:
        tlm = [
            {
                "HISTORY_ID": 901,
                "UPDATED_AT": "2026-05-31T05:20:33+09:00",
                "MISSION_MODE": 2,
                "ERLOGENTRIES": 5,
                "SUN_VALID": 1,
            }
        ]
        adcs = [
            {
                "HISTORY_ID": 901,
                "TIMESTAMP": "2026-05-31T05:20:33+09:00",
                "IMU_WBN_X": 0.016,
                "ERLOGENTRIES": 0,
                "SUN_VALID": 0,
            }
        ]
        pwr = [
            {
                "HISTORY_ID": 11501,
                "UPDATED_AT": "2026-05-31T05:20:33+09:00",
                "channels": [{"SW_ID": 0, "VOLTAGE": 3.24, "CURRENT_A": 0.12}],
            }
        ]

        rows = merge_bulk_telemetry_sections(adcs, tlm, pwr)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["MISSION_MODE"], 2)
        self.assertEqual(row["IMU_WBN_X"], 0.016)
        self.assertEqual(row["SW_0_VOLTAGE"], 3.24)
        self.assertEqual(row["TLM_ERLOGENTRIES"], 5)
        self.assertEqual(row["ADCS_ERLOGENTRIES"], 0)
        self.assertEqual(row["ERLOGENTRIES"], 5)
        self.assertEqual(row["TLM_SUN_VALID"], 1)
        self.assertEqual(row["ADCS_SUN_VALID"], 0)
        self.assertEqual(row["TLM_HISTORY_ID"], 901)
        self.assertEqual(row["PWR_HISTORY_ID"], 11501)

    def test_records_sorted_by_history_id_before_index_merge(self) -> None:
        tlm = [
            {"HISTORY_ID": 902, "UPDATED_AT": "2026-05-31T05:20:40+09:00", "MISSION_MODE": 2},
            {"HISTORY_ID": 901, "UPDATED_AT": "2026-05-31T05:20:33+09:00", "MISSION_MODE": 1},
        ]
        adcs = [
            {"TIMESTAMP": "2026-05-31T05:20:40+09:00", "IMU_WBN_X": 0.02},
            {"TIMESTAMP": "2026-05-31T05:20:33+09:00", "IMU_WBN_X": 0.01},
        ]
        pwr = [
            {"HISTORY_ID": 11502, "UPDATED_AT": "2026-05-31T05:20:40+09:00", "channels": []},
            {"HISTORY_ID": 11501, "UPDATED_AT": "2026-05-31T05:20:33+09:00", "channels": []},
        ]

        rows = merge_bulk_telemetry_sections(adcs, tlm, pwr)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["MISSION_MODE"], 1)
        self.assertEqual(rows[0]["IMU_WBN_X"], 0.01)
        self.assertEqual(rows[1]["MISSION_MODE"], 2)
        self.assertEqual(rows[1]["IMU_WBN_X"], 0.02)

    def test_merge_bulk_telemetry_packet(self) -> None:
        bulk = {
            "packet_type": "SAT_BULK_TELEMETRY",
            "sent_at": "2026-05-31T05:20:47+09:00",
            "SAT_TLM_HISTORY": {
                "records": [
                    {"HISTORY_ID": 899, "UPDATED_AT": "2026-05-31T05:20:33+09:00", "MISSION_MODE": 2}
                ]
            },
            "SAT_ADCS_FILTER": {
                "records": [
                    {"TIMESTAMP": "2026-05-31T05:20:33+09:00", "IMU_WBN_X": 0.016}
                ]
            },
            "SAT_PWR_HISTORY": {
                "records": [
                    {
                        "HISTORY_ID": 11495,
                        "UPDATED_AT": "2026-05-31T05:20:33+09:00",
                        "channels": [{"SW_ID": 0, "VOLTAGE": 3.24}],
                    }
                ]
            },
        }
        rows = merge_bulk_telemetry_packet(bulk)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["PACKET_TYPE"], "SAT_BULK_TELEMETRY")
        self.assertIn("tlm", rows[0]["SOURCE_RECORDS"])
        self.assertIn("adcs", rows[0]["SOURCE_RECORDS"])
        self.assertIn("pwr", rows[0]["SOURCE_RECORDS"])


    def test_merge_by_snapshot_id_payload_shape(self) -> None:
        bulk = {
            "packet_type": "SAT_BULK_TELEMETRY",
            "sent_at": "2026-05-31T06:24:04+09:00",
            "SAT_SNAPSHOT": {
                "records": [
                    {"SNAPSHOT_ID": 30, "SNAPSHOT_AT": "2026-05-31T06:23:46.902219+09:00"},
                    {"SNAPSHOT_ID": 31, "SNAPSHOT_AT": "2026-05-31T06:23:51.206692+09:00"},
                ]
            },
            "SAT_TLM_HISTORY": {
                "records": [
                    {
                        "HISTORY_ID": 933,
                        "SNAPSHOT_ID": 30,
                        "UPDATED_AT": "2026-05-31T06:23:46.891980+09:00",
                        "MISSION_MODE": 2,
                        "ERLOGENTRIES": 5,
                    },
                    {
                        "HISTORY_ID": 934,
                        "SNAPSHOT_ID": 31,
                        "UPDATED_AT": "2026-05-31T06:23:51.201235+09:00",
                        "MISSION_MODE": 2,
                        "ERLOGENTRIES": 5,
                    },
                ]
            },
            "SAT_PWR_HISTORY": {
                "records": [
                    {
                        "HISTORY_ID": 11556,
                        "SNAPSHOT_ID": 30,
                        "UPDATED_AT": "2026-05-31T06:23:46.902219+09:00",
                        "channels": [{"SW_ID": 0, "VOLTAGE": 3.252, "CURRENT_A": 0.0001}],
                    },
                    {
                        "HISTORY_ID": 11557,
                        "SNAPSHOT_ID": 31,
                        "UPDATED_AT": "2026-05-31T06:23:51.206692+09:00",
                        "channels": [{"SW_ID": 0, "VOLTAGE": 3.255, "CURRENT_A": 0.0001}],
                    },
                ]
            },
            "SAT_ADCS_FILTER": {
                "records": [
                    {
                        "SNAPSHOT_ID": 30,
                        "TIMESTAMP": "2026-05-31T06:23:46.902219+09:00",
                        "IMU_WBN_X": 0.012788,
                        "ERLOGENTRIES": 5,
                        "MAG_BVB_X": 40043.0,
                    },
                    {
                        "SNAPSHOT_ID": 31,
                        "TIMESTAMP": "2026-05-31T06:23:51.206692+09:00",
                        "IMU_WBN_X": -0.010553,
                        "ERLOGENTRIES": 5,
                        "MAG_BVB_X": 40149.0,
                    },
                ]
            },
        }
        rows = merge_bulk_telemetry_packet(bulk)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["SNAPSHOT_ID"], 30)
        self.assertEqual(rows[1]["SNAPSHOT_ID"], 31)
        self.assertEqual(rows[0]["TLM_HISTORY_ID"], 933)
        self.assertEqual(rows[1]["TLM_HISTORY_ID"], 934)
        self.assertEqual(rows[0]["PWR_HISTORY_ID"], 11556)
        self.assertEqual(rows[0]["SW_0_VOLTAGE"], 3.252)
        self.assertEqual(rows[1]["SW_0_VOLTAGE"], 3.255)
        self.assertAlmostEqual(rows[0]["IMU_WBN_X"], 0.012788)
        self.assertAlmostEqual(rows[1]["IMU_WBN_X"], -0.010553)
        self.assertEqual(rows[0]["TLM_ERLOGENTRIES"], 5)
        self.assertEqual(rows[0]["ADCS_ERLOGENTRIES"], 5)
        self.assertEqual(rows[0]["MAG_BVB_X"], 40043.0)

    def test_pwr_without_snapshot_id_aligns_by_updated_at(self) -> None:
        bulk = {
            "packet_type": "SAT_BULK_TELEMETRY",
            "sent_at": "2026-06-02T02:27:13",
            "SAT_SNAPSHOT": {
                "records": [
                    {"SNAPSHOT_ID": 282, "SNAPSHOT_AT": "2026-06-02 02:22:55"},
                    {"SNAPSHOT_ID": 283, "SNAPSHOT_AT": "2026-06-02 02:23:04"},
                ]
            },
            "SAT_TLM_HISTORY": {
                "records": [
                    {
                        "SNAPSHOT_ID": 282,
                        "UPDATED_AT": "2026-06-02 02:22:55",
                        "MISSION_MODE": 2,
                    },
                    {
                        "SNAPSHOT_ID": 283,
                        "UPDATED_AT": "2026-06-02 02:23:04",
                        "MISSION_MODE": 2,
                    },
                ]
            },
            "SAT_PWR_HISTORY": {
                "records": [
                    {
                        "HISTORY_ID": 11808,
                        "UPDATED_AT": "2026-06-02 02:22:55",
                        "channels": [{"SW_ID": 0, "VOLTAGE": 4.413, "CURRENT_A": 0.0004}],
                    },
                    {
                        "HISTORY_ID": 11809,
                        "UPDATED_AT": "2026-06-02 02:23:04",
                        "channels": [{"SW_ID": 2, "VOLTAGE": 3.755, "CURRENT_A": 0.0451}],
                    },
                ]
            },
            "SAT_ADCS_FILTER": {"records": []},
        }
        rows = merge_bulk_telemetry_packet(bulk)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["SW_0_VOLTAGE"], 4.413)
        self.assertEqual(rows[1]["SW_2_VOLTAGE"], 3.755)

    def test_attack_bulk_with_events_array_merges_and_flags_anomaly(self) -> None:
        bulk = {
            "packet_type": "SAT_BULK_TELEMETRY",
            "sent_at": "2026-05-31T12:05:00+09:00",
            "SAT_EVENT_QUEUE": {
                "event_total": 1,
                "event_ids": [42],
                "events": [
                    {
                        "EVENT_ID": 42,
                        "DETECTED_AT": "2026-05-31T12:04:18+09:00",
                        "EVENT_TYPE": "ATTACK_CONFIRMED",
                        "PRIORITY": 1,
                        "SW_ID": 0,
                        "WEIGHT": 78,
                        "EXCEPTION_CODE": 2,
                        "MODULE_SCORES": "{\"physical\":0.82,\"statistical\":0.71,\"system\":0.65}",
                        "PIPEOVERFLOWRRCNT": 1,
                        "PROCESSOR_RESET_COUNT": 2,
                    }
                ],
            },
            "SAT_SNAPSHOT": {
                "records": [
                    {"SNAPSHOT_ID": 30, "SNAPSHOT_AT": "2026-05-31T12:04:15+09:00"},
                ]
            },
            "SAT_TLM_HISTORY": {
                "records": [
                    {
                        "HISTORY_ID": 933,
                        "SNAPSHOT_ID": 30,
                        "UPDATED_AT": "2026-05-31T12:04:15+09:00",
                        "MISSION_MODE": 2,
                        "ADCS_MODE": 2,
                    }
                ]
            },
            "SAT_PWR_HISTORY": {
                "records": [
                    {
                        "HISTORY_ID": 11556,
                        "SNAPSHOT_ID": 30,
                        "UPDATED_AT": "2026-05-31T12:04:15+09:00",
                        "SW_ID": 0,
                        "VOLTAGE": 2.85,
                        "CURRENT_A": 0.12,
                        "ANOMALY_FLAG": 1,
                    }
                ]
            },
            "SAT_ADCS_FILTER": {
                "records": [
                    {
                        "SNAPSHOT_ID": 30,
                        "TIMESTAMP": "2026-05-31T12:04:15+09:00",
                        "QBN_0": 0.99,
                        "TCMD_X": -0.002,
                        "IMU_WBN_X": 0.01,
                    }
                ]
            },
        }
        rows = merge_bulk_telemetry_packet(bulk)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["SNAPSHOT_ID"], 30)
        self.assertNotIn("EVENT_ID", row)
        self.assertNotIn("IS_ANOMALY", row)
        self.assertEqual(row["SW_0_VOLTAGE"], 2.85)
        self.assertEqual(row["SW_0_ANOMALY_FLAG"], 1)
        self.assertEqual(row["IMU_WBN_X"], 0.01)
        self.assertNotIn("event", row.get("SOURCE_RECORDS", {}))

        events = extract_bulk_event_records(bulk)
        self.assertEqual(len(events), 1)
        event_row = build_event_queue_row(events[0])
        self.assertEqual(event_row["EVENT_ID"], 42)
        self.assertEqual(event_row["EVENT_TYPE"], "ATTACK_CONFIRMED")
        self.assertTrue(derive_ma_fields_from_event(event_row)["IS_ANOMALY"])
        self.assertEqual(event_row["WEIGHT"], 78)
        self.assertEqual(event_row["MODULE_SCORES"]["physical"], 0.82)

    def test_multiple_bulk_events_extracted(self) -> None:
        bulk = {
            "packet_type": "SAT_BULK_TELEMETRY",
            "SAT_EVENT_QUEUE": {
                "events": [
                    {
                        "EVENT_ID": 1,
                        "SNAPSHOT_ID": 10,
                        "DETECTED_AT": "2026-05-31T12:00:00+09:00",
                        "EVENT_TYPE": "SEU_DETECTED",
                        "WEIGHT": 28,
                    },
                    {
                        "EVENT_ID": 2,
                        "SNAPSHOT_ID": 11,
                        "DETECTED_AT": "2026-05-31T12:00:01+09:00",
                        "EVENT_TYPE": "ATTACK_CONFIRMED",
                        "WEIGHT": 100,
                    },
                ]
            },
            "SAT_TLM_HISTORY": {
                "records": [
                    {"SNAPSHOT_ID": 10, "UPDATED_AT": "2026-05-31T12:00:00+09:00", "MISSION_MODE": 2},
                    {"SNAPSHOT_ID": 11, "UPDATED_AT": "2026-05-31T12:00:01+09:00", "MISSION_MODE": 2},
                ]
            },
        }
        events = extract_bulk_event_records(bulk)
        self.assertEqual(len(events), 2)
        rows = merge_bulk_telemetry_packet(bulk)
        self.assertEqual(len(rows), 2)
        self.assertNotIn("EVENT_ID", rows[0])
        seu_row = build_event_queue_row(events[0])
        attack_row = build_event_queue_row(events[1])
        self.assertFalse(derive_ma_fields_from_event(seu_row)["IS_ANOMALY"])
        self.assertTrue(derive_ma_fields_from_event(attack_row)["IS_ANOMALY"])

    def test_bulk_json_mirror_fields_and_wire_payload(self) -> None:
        bulk = {
            "packet_type": "SAT_BULK_TELEMETRY",
            "sent_at": "2026-05-31T06:24:04+09:00",
            "note": "comm-window",
            "SAT_SNAPSHOT": {
                "records": [{"SNAPSHOT_ID": 30, "SNAPSHOT_AT": "2026-05-31T06:23:46+09:00"}]
            },
            "SAT_TLM_HISTORY": {
                "records": [
                    {
                        "SNAPSHOT_ID": 30,
                        "HISTORY_ID": 901,
                        "TLM_ID": 1,
                        "UPDATED_AT": "2026-05-31T06:23:46+09:00",
                        "DT": 0.25,
                        "TORQUER_PERIOD": 8,
                        "MISSION_MODE": 2,
                    }
                ]
            },
            "SAT_ADCS_FILTER": {
                "records": [
                    {
                        "SNAPSHOT_ID": 30,
                        "CHENNEL1": 3,
                        "TIMESTAMP": "2026-05-31T06:23:46+09:00",
                        "QBN_0": 0.98,
                        "THERR_X": 0.5,
                        "CMDCOUNTER": 42,
                    }
                ]
            },
            "SAT_PWR_HISTORY": {
                "records": [
                    {
                        "SNAPSHOT_ID": 30,
                        "HISTORY_ID": 11501,
                        "UPDATED_AT": "2026-05-31T06:23:46+09:00",
                        "channels": [
                            {
                                "SW_ID": 0,
                                "VOLTAGE": 3.24,
                                "PREV_VOLTAGE": 3.28,
                                "PREV_DELTA_V": 0.01,
                                "EXCEED_COUNT": 3,
                                "V_THRESHOLD_LO": 3.0,
                            }
                        ],
                    }
                ]
            },
            "SAT_INTEGRITY_HASH": {
                "records": [
                    {
                        "FILE_ID": 1,
                        "FILE_PATH": "/cf/apps/adcs.so",
                        "EXPECTED_HASH": "abc123",
                        "LAST_VERIFIED_AT": "2026-05-31T06:23:46+09:00",
                        "IS_VIOLATED": 1,
                    }
                ]
            },
        }
        rows = merge_bulk_telemetry_packet(bulk)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["TLM_ID"], 1)
        self.assertEqual(row["DT"], 0.25)
        self.assertEqual(row["CHENNEL1"], 3)
        self.assertEqual(row["QBN_0"], 0.98)
        self.assertEqual(row["SW_0_PREV_VOLTAGE"], 3.28)
        self.assertEqual(row["SW_0_EXCEED_COUNT"], 3)
        self.assertEqual(row["INTEGRITY_FILE_PATH"], "/cf/apps/adcs.so")
        self.assertEqual(row["IS_VIOLATED"], 1)
        self.assertIn("SAT_TLM_HISTORY", row["WIRE_PAYLOAD"])
        self.assertEqual(row["BULK_NOTE"], "comm-window")

    def test_find_nearest_history_by_time_not_snapshot_id(self) -> None:
        event = {
            "EVENT_ID": 99,
            "SNAPSHOT_ID": 999,
            "DETECTED_AT": "2026-05-31T12:00:01+09:00",
            "EVENT_TYPE": "ATTACK_CONFIRMED",
            "WEIGHT": 90,
        }
        history_rows = [
            {
                "HISTORY_ID": 1,
                "SNAPSHOT_ID": 10,
                "UPDATED_AT": "2026-05-31T12:00:00+09:00",
                "IMU_WBN_X": 0.01,
            },
            {
                "HISTORY_ID": 2,
                "SNAPSHOT_ID": 11,
                "UPDATED_AT": "2026-05-31T12:00:01+09:00",
                "IMU_WBN_X": 0.02,
            },
        ]
        row, delta = find_nearest_history_for_event(event, history_rows, tolerance_sec=5.0)
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(row["HISTORY_ID"], 2)
        self.assertIsNotNone(delta)
        assert delta is not None
        self.assertLessEqual(delta, 1.0)

        linked_row, history_id = resolve_event_history_link(
            event,
            history_rows,
            tolerance_sec=5.0,
        )
        self.assertEqual(history_id, 2)
        self.assertEqual(linked_row["SNAPSHOT_ID"], 11)

    def test_build_ma_reference_keeps_history_telemetry(self) -> None:
        history = {
            "HISTORY_ID": 2,
            "SNAPSHOT_ID": 11,
            "UPDATED_AT": "2026-05-31T12:00:01+09:00",
            "IMU_WBN_X": 0.02,
            "MISSION_MODE": 2,
        }
        event_row = build_event_queue_row(
            {
                "EVENT_ID": 11,
                "SNAPSHOT_ID": 31,
                "DETECTED_AT": "2026-05-31T12:00:01+09:00",
                "EVENT_TYPE": "ATTACK_CONFIRMED",
                "WEIGHT": 100,
                "PIPEOVERFLOWRRCNT": 7,
            },
        )
        event_row = derive_ma_fields_from_event(event_row)
        packet = build_ma_reference_packet(history, event_row, time_delta_sec=0.0)
        self.assertEqual(packet["IMU_WBN_X"], 0.02)
        self.assertEqual(packet["MISSION_MODE"], 2)
        self.assertTrue(packet["IS_ANOMALY"])
        self.assertEqual(packet["ONBOARD_EVENT"]["EVENT_ID"], 11)
        self.assertEqual(packet["PIPEOVERFLOWRRCNT"], 7)
        self.assertNotIn("event", packet.get("SOURCE_RECORDS", {}))

    def test_find_nearest_history_accepts_mysql_datetime(self) -> None:
        from datetime import datetime

        event = {"DETECTED_AT": datetime(2026, 6, 2, 2, 22, 52), "SNAPSHOT_ID": 282}
        history_rows = [
            {
                "SNAPSHOT_ID": 282,
                "UPDATED_AT": datetime(2026, 6, 2, 2, 22, 52),
                "HISTORY_ID": 1,
            },
            {
                "SNAPSHOT_ID": 283,
                "UPDATED_AT": datetime(2026, 6, 2, 2, 23, 0),
                "HISTORY_ID": 2,
            },
        ]
        linked_row, delta = find_nearest_history_for_event(event, history_rows, tolerance_sec=30.0)
        self.assertIsNotNone(linked_row)
        self.assertEqual(linked_row["SNAPSHOT_ID"], 282)
        self.assertIsNotNone(delta)


if __name__ == "__main__":
    unittest.main()
