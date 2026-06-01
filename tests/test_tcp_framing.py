"""Tests for TCP length-prefix framing and packet buffer deduplication."""

from __future__ import annotations

import asyncio
import json
import struct
import unittest

from api.packet_buffer import PacketBufferManager


class TCPFramingTest(unittest.TestCase):
    def test_length_prefix_roundtrip(self) -> None:
        payload = {"ack": True, "cmd": "ACK"}
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        frame = struct.pack(">I", len(body)) + body
        length = struct.unpack(">I", frame[:4])[0]
        decoded = json.loads(frame[4 : 4 + length].decode("utf-8"))
        self.assertEqual(decoded, payload)


class PacketBufferDedupTest(unittest.TestCase):
    def test_duplicate_packet_is_ignored(self) -> None:
        async def scenario() -> None:
            buffer = PacketBufferManager(timeout_sec=5.0, on_flush=lambda *_args: None)
            packet = {
                "packet_type": "SAT_EVENT_QUEUE",
                "event": {
                    "DETECTED_AT": "2026-05-30T12:01:00+00:00",
                    "EVENT_TYPE": "ATTACK_CONFIRMED",
                    "WEIGHT": 100,
                },
            }
            first = await buffer.receive(packet)
            second = await buffer.receive(packet)
            self.assertNotEqual(first.get("status"), "duplicate_ignored")
            self.assertEqual(second.get("status"), "duplicate_ignored")

        asyncio.run(scenario())

    def test_bulk_completion_triggers_single_flush(self) -> None:
        async def scenario() -> None:
            flush_keys: list[str] = []

            def on_flush(key, packets, bulk_packets, event_meta=None, comm_session=None):
                flush_keys.append(key)

            buffer = PacketBufferManager(timeout_sec=5.0, on_flush=on_flush)
            packets = [
                {
                    "packet_type": "SAT_EVENT_QUEUE",
                    "event": {
                        "EVENT_ID": 401,
                        "DETECTED_AT": "2026-05-30T12:05:00+00:00",
                        "EVENT_TYPE": "ATTACK_CONFIRMED",
                        "WEIGHT": 100,
                        "FALSE_POSITIVE_RESULT": "Y",
                    },
                },
                {
                    "packet_type": "SAT_INTEGRITY_HASH",
                    "records": [
                        {
                            "FILE_PATH": "/cf/apps/adcs.so",
                            "UPDATED_AT": "2026-05-30T12:05:00+00:00",
                            "IS_VIOLATED": 1,
                        }
                    ],
                },
                {
                    "packet_type": "SAT_ADCS_FILTER",
                    "records": [
                        {
                            "TIMESTAMP": "2026-05-30T12:05:00+00:00",
                            "QERR_0": 0.99,
                        }
                    ],
                },
                {
                    "packet_type": "SAT_TLM_HISTORY",
                    "records": [
                        {
                            "UPDATED_AT": "2026-05-30T12:05:00+00:00",
                            "MISSION_MODE": 2,
                        }
                    ],
                },
                {
                    "packet_type": "SAT_PWR_HISTORY",
                    "records": [
                        {
                            "UPDATED_AT": "2026-05-30T12:05:00+00:00",
                            "channels": [],
                        }
                    ],
                },
            ]
            for packet in packets:
                await buffer.receive(packet)

            self.assertEqual(flush_keys, ["2026-05-30T12:05:00"])

        asyncio.run(scenario())

    def test_bulk_telemetry_triggers_single_flush(self) -> None:
        async def scenario() -> None:
            flush_keys: list[str] = []

            def on_flush(key, packets, bulk_packets, event_meta=None, comm_session=None):
                flush_keys.append(key)

            buffer = PacketBufferManager(timeout_sec=5.0, on_flush=on_flush)
            bulk = {
                "packet_type": "SAT_BULK_TELEMETRY",
                "sent_at": "2026-05-30T12:05:00+00:00",
                "SAT_EVENT_QUEUE": {
                    "event": {
                        "EVENT_ID": 401,
                        "DETECTED_AT": "2026-05-30T12:05:00+00:00",
                        "EVENT_TYPE": "ATTACK_CONFIRMED",
                        "WEIGHT": 100,
                        "FALSE_POSITIVE_RESULT": "Y",
                    }
                },
                "SAT_INTEGRITY_HASH": {
                    "records": [
                        {
                            "FILE_PATH": "/cf/apps/adcs.so",
                            "UPDATED_AT": "2026-05-30T12:05:00+00:00",
                            "IS_VIOLATED": 1,
                        }
                    ],
                },
                "SAT_ADCS_FILTER": {
                    "records": [
                        {
                            "TIMESTAMP": "2026-05-30T12:05:00+00:00",
                            "QERR_0": 0.99,
                        }
                    ],
                },
                "SAT_TLM_HISTORY": {
                    "records": [
                        {
                            "UPDATED_AT": "2026-05-30T12:05:00+00:00",
                            "MISSION_MODE": 2,
                        }
                    ],
                },
                "SAT_PWR_HISTORY": {
                    "records": [
                        {
                            "UPDATED_AT": "2026-05-30T12:05:00+00:00",
                            "channels": [],
                        }
                    ],
                },
            }
            status = await buffer.receive(bulk)
            self.assertEqual(status.get("status"), "pipeline_triggered")
            self.assertTrue(status.get("bulk_telemetry"))
            self.assertEqual(flush_keys, ["2026-05-30T12:05:00"])

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
