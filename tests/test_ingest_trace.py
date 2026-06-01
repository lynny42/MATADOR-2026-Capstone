"""Tests for ingest trace raw packet storage."""

from __future__ import annotations

import unittest

from api import ingest_trace


class IngestTraceRawPacketTest(unittest.TestCase):
    def setUp(self) -> None:
        ingest_trace._raw_packets.clear()
        ingest_trace._raw_packet_index.clear()
        ingest_trace._next_raw_packet_id = 1

    def test_large_raw_text_not_truncated(self) -> None:
        payload = {"packet_type": "SAT_BULK_TELEMETRY", "note": "x" * 5000}
        raw_text = '{"packet_type":"SAT_BULK_TELEMETRY","note":"' + ("x" * 5000) + '"}'
        entry_id = ingest_trace.record_raw_packet(payload, raw_text=raw_text, byte_length=len(raw_text))
        self.assertIsNotNone(entry_id)

        item = ingest_trace.get_raw_packet(int(entry_id))
        self.assertIsNotNone(item)
        assert item is not None
        self.assertEqual(len(item.get("raw_text", "")), len(raw_text))
        self.assertNotIn("truncated", item.get("raw_text", ""))

    def test_list_default_is_compact(self) -> None:
        ingest_trace.record_raw_packet({"packet_type": "SAT_BULK_TELEMETRY"}, raw_text='{"a":1}')
        items = ingest_trace.recent_raw_packets(5, include_body=False)
        self.assertEqual(len(items), 1)
        self.assertNotIn("packet", items[0])
        self.assertNotIn("raw_text", items[0])
        self.assertIn("id", items[0])


if __name__ == "__main__":
    unittest.main()
