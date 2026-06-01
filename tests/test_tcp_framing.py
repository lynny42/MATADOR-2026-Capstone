"""Tests for TCP length-prefix framing and bulk telemetry deduplication."""

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
    def test_duplicate_bulk_packet_is_ignored(self) -> None:
        async def scenario() -> None:
            persisted: list[dict] = []

            def on_persist(bulk: dict) -> None:
                persisted.append(bulk)

            buffer = PacketBufferManager(on_bulk_telemetry_persist=on_persist)
            bulk = {
                "packet_type": "SAT_BULK_TELEMETRY",
                "sent_at": "2026-05-30T12:05:00+00:00",
                "SAT_TLM_HISTORY": {
                    "records": [{"UPDATED_AT": "2026-05-30T12:05:00+00:00", "MISSION_MODE": 2}]
                },
            }
            first = await buffer.receive(bulk)
            second = await buffer.receive(bulk)
            self.assertEqual(first.get("status"), "bulk_telemetry_stored")
            self.assertEqual(second.get("status"), "duplicate_ignored")
            self.assertEqual(len(persisted), 1)

        asyncio.run(scenario())

    def test_non_bulk_packet_is_ignored(self) -> None:
        async def scenario() -> None:
            persisted: list[dict] = []

            buffer = PacketBufferManager(on_bulk_telemetry_persist=lambda bulk: persisted.append(bulk))
            status = await buffer.receive(
                {
                    "packet_type": "SAT_TLM_HISTORY",
                    "records": [{"UPDATED_AT": "2026-05-30T12:05:00+00:00"}],
                }
            )
            self.assertEqual(status.get("status"), "ignored")
            self.assertEqual(status.get("reason"), "bulk_telemetry_required")
            self.assertEqual(len(persisted), 0)

        asyncio.run(scenario())

    def test_bulk_telemetry_triggers_persist(self) -> None:
        async def scenario() -> None:
            persisted: list[dict] = []

            buffer = PacketBufferManager(on_bulk_telemetry_persist=lambda bulk: persisted.append(bulk))
            bulk = {
                "packet_type": "SAT_BULK_TELEMETRY",
                "sent_at": "2026-05-30T12:05:00+00:00",
                "SAT_EVENT_QUEUE": {
                    "event": {
                        "EVENT_ID": 401,
                        "DETECTED_AT": "2026-05-30T12:05:00+00:00",
                        "EVENT_TYPE": "ATTACK_CONFIRMED",
                        "WEIGHT": 100,
                    }
                },
                "SAT_TLM_HISTORY": {
                    "records": [{"UPDATED_AT": "2026-05-30T12:05:00+00:00", "MISSION_MODE": 2}]
                },
            }
            status = await buffer.receive(bulk)
            self.assertEqual(status.get("status"), "bulk_telemetry_stored")
            self.assertEqual(len(persisted), 1)
            self.assertEqual(persisted[0].get("packet_type"), "SAT_BULK_TELEMETRY")

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()
