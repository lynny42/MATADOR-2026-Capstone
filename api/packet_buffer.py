"""Five-packet telemetry buffering and timeout merge."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ma_detector.core.packet_protocol import (
    BULK_HISTORY_TYPES,
    BULK_TELEMETRY_PACKET_TYPE,
    buffer_has_core_types,
    communication_snapshot_key,
    event_is_attack_anomaly,
    expand_bulk_telemetry_packet,
    is_accumulated_bulk_packet,
    is_bulk_telemetry_packet,
    is_event_queue_meta_packet,
    missing_buffer_types,
    normalize_packet_type,
    packet_buffer_keys,
    parse_event_queue_meta,
    record_time_key,
    scrub_record,
    slice_packet_for_key,
    time_key_to_epoch,
)

logger = logging.getLogger(__name__)


@dataclass
class _BufferEntry:
    packets: dict[str, dict[str, Any]] = field(default_factory=dict)
    timer_task: asyncio.Task[None] | None = None
    flushed: bool = False


class PacketBufferManager:
    """Buffer satellite packets by event time or latest accumulated communication snapshot."""

    def __init__(
        self,
        timeout_sec: float,
        on_flush: Callable[[str, dict[str, dict[str, Any]], dict[str, dict[str, Any]]], Any],
        match_tolerance_sec: float = 5.0,
        on_bulk_stored: Callable[[dict[str, Any]], Any] | None = None,
        on_bulk_telemetry_persist: Callable[[dict[str, Any]], Any] | None = None,
        on_comm_session_end: Callable[[str], Any] | None = None,
    ) -> None:
        self._timeout_sec = timeout_sec
        self._match_tolerance_sec = float(match_tolerance_sec)
        self._on_flush = on_flush
        self._on_bulk_stored = on_bulk_stored
        self._on_bulk_telemetry_persist = on_bulk_telemetry_persist
        self._on_comm_session_end = on_comm_session_end
        self._buffers: dict[str, _BufferEntry] = {}
        self._bulk_packets: dict[str, dict[str, Any]] = {}
        self._recent_fingerprints: dict[str, float] = {}
        self._dedup_ttl_sec = 300.0
        self._flushed_keys: set[str] = set()
        self._seu_event_meta: list[dict[str, Any]] = []
        self._pending_event_queue_meta: dict[str, Any] | None = None
        self._received_event_ids: set[int] = set()
        self._comm_session_seq = 0
        self._comm_session_id: str | None = None
        self._last_comm_wall_time = 0.0
        self._comm_idle_flush_task: asyncio.Task[None] | None = None

    def update_timeout(self, timeout_sec: float) -> None:
        try:
            self._timeout_sec = float(timeout_sec)
        except Exception as error:
            logger.error("packet buffer timeout update failed: %s", error)

    def update_match_tolerance(self, match_tolerance_sec: float) -> None:
        try:
            self._match_tolerance_sec = float(match_tolerance_sec)
        except Exception as error:
            logger.error("packet buffer tolerance update failed: %s", error)

    def _touch_comm_session(self) -> str:
        """Assign packets arriving in one uplink burst to the same comm session."""
        try:
            now = time.time()
            gap_sec = max(self._timeout_sec * 2.0, 10.0)
            if self._comm_session_id is None or now - self._last_comm_wall_time > gap_sec:
                previous = self._comm_session_id
                if previous and self._on_comm_session_end is not None:
                    try:
                        self._on_comm_session_end(previous)
                    except Exception as error:
                        logger.error("comm session end callback failed: %s", error)
                self._comm_session_seq += 1
                self._comm_session_id = f"comm-{self._comm_session_seq}"
                self._bulk_packets.clear()
                self._buffers.clear()
                self._flushed_keys.clear()
            self._last_comm_wall_time = now
            self._schedule_comm_idle_flush()
            return self._comm_session_id
        except Exception as error:
            logger.error("comm session touch failed: %s", error)
            return "comm-0"

    def _schedule_comm_idle_flush(self) -> None:
        """Flush staged DB rows when an uplink burst goes quiet (~10s) without a new comm session."""
        try:
            if self._comm_idle_flush_task and not self._comm_idle_flush_task.done():
                self._comm_idle_flush_task.cancel()
            gap_sec = max(self._timeout_sec * 2.0, 10.0)

            async def _idle_flush() -> None:
                try:
                    await asyncio.sleep(gap_sec)
                    session = self._comm_session_id
                    if session and self._on_comm_session_end is not None:
                        self._on_comm_session_end(session)
                except asyncio.CancelledError:
                    return
                except Exception as error:
                    logger.error("comm idle flush failed: %s", error)

            self._comm_idle_flush_task = asyncio.create_task(_idle_flush())
        except Exception as error:
            logger.error("comm idle flush schedule failed: %s", error)

    def _attach_comm_session(self, status: dict[str, Any], comm_session: str) -> dict[str, Any]:
        try:
            enriched = dict(status)
            enriched["comm_session"] = comm_session
            return enriched
        except Exception as error:
            logger.error("comm session attach failed: %s", error)
            return status

    @staticmethod
    def buffer_key(packet: dict[str, Any]) -> str:
        try:
            keys = packet_buffer_keys(packet)
            return keys[0] if keys else ""
        except Exception as error:
            logger.error("packet buffer key build failed: %s", error)
            return ""

    def update_callbacks(
        self,
        on_flush: Callable[[str, dict[str, dict[str, Any]], dict[str, dict[str, Any]]], Any],
        *,
        on_bulk_stored: Callable[[dict[str, Any]], Any] | None = None,
        on_bulk_telemetry_persist: Callable[[dict[str, Any]], Any] | None = None,
        on_comm_session_end: Callable[[str], Any] | None = None,
    ) -> None:
        try:
            self._on_flush = on_flush
            if on_bulk_stored is not None:
                self._on_bulk_stored = on_bulk_stored
            if on_bulk_telemetry_persist is not None:
                self._on_bulk_telemetry_persist = on_bulk_telemetry_persist
            if on_comm_session_end is not None:
                self._on_comm_session_end = on_comm_session_end
        except Exception as error:
            logger.error("packet buffer callback update failed: %s", error)

    def _store_bulk_packet(
        self,
        packet_type: str,
        packet: dict[str, Any],
        *,
        notify_persist: bool = True,
    ) -> None:
        try:
            stored = dict(packet)
            stored["packet_type"] = packet_type
            if self._comm_session_id:
                stored["_comm_session"] = self._comm_session_id
            self._bulk_packets[packet_type] = stored
            if notify_persist and self._on_bulk_stored is not None:
                self._on_bulk_stored(stored)
            elif notify_persist:
                logger.error("bulk packet stored but on_bulk_stored callback is missing")
        except Exception as error:
            logger.error("bulk packet store failed: %s", error)

    def _slice_for_bucket(self, packet: dict[str, Any], key: str) -> dict[str, Any]:
        try:
            sliced = slice_packet_for_key(packet, key, self._match_tolerance_sec)
            sliced["_buffer_key"] = key
            sliced["_match_tolerance_sec"] = self._match_tolerance_sec
            return sliced
        except Exception as error:
            logger.error("bulk packet slice failed: %s", error)
            return dict(packet)

    def _apply_bulk_to_bucket(self, key: str, entry: _BufferEntry) -> None:
        try:
            for packet_type, bulk_packet in self._bulk_packets.items():
                if packet_type in entry.packets:
                    continue
                sliced = self._slice_for_bucket(bulk_packet, key)
                if sliced.get("_active_record") or sliced.get("event"):
                    entry.packets[packet_type] = sliced
        except Exception as error:
            logger.error("bulk packet attach failed: %s", error)

    def _get_or_create_snapshot_bucket(self) -> tuple[str, _BufferEntry] | None:
        """Create a normal-communication bucket from accumulated bulk packets when no event exists."""
        try:
            if not self._bulk_packets:
                return None
            if not buffer_has_core_types(self._bulk_packets):
                return None

            key = communication_snapshot_key(self._bulk_packets)
            if not key:
                return None

            entry = self._buffers.setdefault(key, _BufferEntry())
            self._apply_bulk_to_bucket(key, entry)
            for packet_type, bulk_packet in self._bulk_packets.items():
                if packet_type not in entry.packets:
                    sliced = self._slice_for_bucket(bulk_packet, key)
                    if sliced.get("_active_record"):
                        entry.packets[packet_type] = sliced
            return key, entry
        except Exception as error:
            logger.error("snapshot bucket ensure failed: %s", error)
            return None

    async def _maybe_flush_bucket(self, key: str, entry: _BufferEntry) -> dict[str, Any]:
        try:
            received = sorted(entry.packets.keys())
            if buffer_has_core_types(entry.packets):
                await self._flush(key, entry, partial=False)
                return {
                    "status": "pipeline_triggered",
                    "buffer_key": key,
                    "received": received,
                }

            if entry.timer_task is None or entry.timer_task.done():
                entry.timer_task = asyncio.create_task(self._timeout_flush(key))
            return {"status": "buffered", "buffer_key": key, "received": received}
        except Exception as error:
            logger.error("bucket flush decision failed: %s", error)
            return {"status": "error", "message": str(error)}

    def _collect_event_meta_for_key(self, key: str) -> list[dict[str, Any]]:
        try:
            bucket_epoch = time_key_to_epoch(key)
            if bucket_epoch is None:
                return [dict(item) for item in self._seu_event_meta]

            matched: list[dict[str, Any]] = []
            for meta in self._seu_event_meta:
                meta_epoch = time_key_to_epoch(record_time_key(meta))
                if meta_epoch is None:
                    continue
                if abs(meta_epoch - bucket_epoch) <= self._match_tolerance_sec:
                    matched.append(dict(meta))
            return matched
        except Exception as error:
            logger.error("event meta collection failed: %s", error)
            return []

    def _consume_event_meta_for_key(self, key: str) -> list[dict[str, Any]]:
        try:
            matched = self._collect_event_meta_for_key(key)
            if not matched:
                return []

            matched_ids = {
                (
                    record_time_key(item),
                    item.get("EVENT_ID"),
                    item.get("EVENT_TYPE"),
                    item.get("WEIGHT"),
                )
                for item in matched
            }
            remaining: list[dict[str, Any]] = []
            for meta in self._seu_event_meta:
                fingerprint = (
                    record_time_key(meta),
                    meta.get("EVENT_ID"),
                    meta.get("EVENT_TYPE"),
                    meta.get("WEIGHT"),
                )
                if fingerprint in matched_ids:
                    continue
                remaining.append(meta)
            self._seu_event_meta = remaining
            return matched
        except Exception as error:
            logger.error("event meta consume failed: %s", error)
            return []

    def _remember_seu_event(self, packet: dict[str, Any]) -> None:
        try:
            event = packet.get("event", packet)
            if not isinstance(event, dict):
                return
            if event_is_attack_anomaly(event):
                return
            cleaned = scrub_record(event)
            if cleaned:
                self._seu_event_meta.append(cleaned)
        except Exception as error:
            logger.error("seu event meta store failed: %s", error)

    async def _attempt_bulk_pipeline_flush(self) -> tuple[dict[str, Any], bool]:
        """Try to flush buffered buckets after one or more bulk sections were stored."""
        last_status: dict[str, Any] = {"status": "buffered"}
        pipeline_triggered = False
        try:
            for key, entry in list(self._buffers.items()):
                if key in self._flushed_keys or entry.flushed:
                    continue
                self._apply_bulk_to_bucket(key, entry)
                status = await self._maybe_flush_bucket(key, entry)
                if status.get("status") == "pipeline_triggered":
                    pipeline_triggered = True
                    last_status = status

            if not self._buffers and not pipeline_triggered:
                snapshot = self._get_or_create_snapshot_bucket()
                if snapshot is not None:
                    key, entry = snapshot
                    if key not in self._flushed_keys and not entry.flushed:
                        status = await self._maybe_flush_bucket(key, entry)
                        if status.get("status") == "pipeline_triggered":
                            pipeline_triggered = True
                        last_status = status
            return last_status, pipeline_triggered
        except Exception as error:
            logger.error("bulk pipeline flush attempt failed: %s", error)
            return last_status, pipeline_triggered

    async def _handle_bulk_packet(self, packet_type: str, incoming: dict[str, Any]) -> dict[str, Any]:
        try:
            self._store_bulk_packet(packet_type, incoming)
            last_status: dict[str, Any] = {
                "status": "bulk_stored",
                "packet_type": packet_type,
                "record_count": len(incoming.get("records", [])),
            }
            flush_status, pipeline_triggered = await self._attempt_bulk_pipeline_flush()
            if pipeline_triggered:
                return flush_status
            return last_status
        except Exception as error:
            logger.error("bulk packet receive failed: %s", error)
            return {"status": "error", "message": str(error)}

    async def _handle_bulk_telemetry_packet(self, incoming: dict[str, Any]) -> dict[str, Any]:
        """Expand SAT_BULK_TELEMETRY and store every nested section before one pipeline flush."""
        try:
            children = expand_bulk_telemetry_packet(incoming)
            if not children:
                return {"status": "ignored", "reason": "empty SAT_BULK_TELEMETRY"}

            received: list[str] = []
            record_counts: dict[str, int] = {}

            for child in children:
                child_type = normalize_packet_type(str(child.get("packet_type", "")).strip())
                if not child_type:
                    continue

                if is_event_queue_meta_packet(child):
                    meta_status = self._store_event_queue_meta(child)
                    if meta_status.get("status") == "meta_stored":
                        received.append(child_type)
                    continue

                if child_type == "SAT_EVENT_QUEUE":
                    events = child.get("events")
                    if isinstance(events, list):
                        for event in events:
                            if not isinstance(event, dict):
                                continue
                            self._track_event_queue_item(event)
                            if not event_is_attack_anomaly(event):
                                self._remember_seu_event({"packet_type": child_type, "event": event})
                            event_packet = {"packet_type": child_type, "event": event}
                            bucket_keys = packet_buffer_keys(event_packet)
                            for key in bucket_keys:
                                sliced = self._slice_for_bucket(event_packet, key)
                                entry = self._buffers.setdefault(key, _BufferEntry())
                                entry.packets[child_type] = sliced
                                self._apply_bulk_to_bucket(key, entry)
                    else:
                        event = child.get("event", child)
                        if isinstance(event, dict):
                            self._track_event_queue_item(event)
                            self._remember_seu_event(child)
                        bucket_keys = packet_buffer_keys(child)
                        for key in bucket_keys:
                            sliced = self._slice_for_bucket(child, key)
                            entry = self._buffers.setdefault(key, _BufferEntry())
                            entry.packets[child_type] = sliced
                            self._apply_bulk_to_bucket(key, entry)
                    received.append(child_type)
                    continue

                if child_type in BULK_HISTORY_TYPES and isinstance(child.get("records"), list):
                    self._store_bulk_packet(child_type, child, notify_persist=False)
                    received.append(child_type)
                    record_counts[child_type] = len(child.get("records", []))
                    continue

                bucket_keys = packet_buffer_keys(child)
                for key in bucket_keys:
                    sliced = self._slice_for_bucket(child, key)
                    entry = self._buffers.setdefault(key, _BufferEntry())
                    entry.packets[child_type] = sliced
                    self._apply_bulk_to_bucket(key, entry)
                if bucket_keys:
                    received.append(child_type)

            if self._on_bulk_telemetry_persist is not None:
                bulk_stored = dict(incoming)
                bulk_stored["packet_type"] = BULK_TELEMETRY_PACKET_TYPE
                if self._comm_session_id:
                    bulk_stored["_comm_session"] = self._comm_session_id
                self._on_bulk_telemetry_persist(bulk_stored)

            flush_status, pipeline_triggered = await self._attempt_bulk_pipeline_flush()
            if pipeline_triggered:
                flush_status.setdefault("bulk_telemetry", True)
                flush_status["received"] = received
                return flush_status

            return {
                "status": "bulk_telemetry_stored",
                "packet_type": BULK_TELEMETRY_PACKET_TYPE,
                "sent_at": incoming.get("sent_at"),
                "received": received,
                "record_counts": record_counts,
            }
        except Exception as error:
            logger.error("bulk telemetry receive failed: %s", error)
            return {"status": "error", "message": str(error)}

    @staticmethod
    def _packet_fingerprint(packet: dict[str, Any]) -> str:
        try:
            canonical = {
                key: value
                for key, value in packet.items()
                if not str(key).startswith("_")
            }
            payload = json.dumps(canonical, sort_keys=True, ensure_ascii=False, default=str)
            return hashlib.sha256(payload.encode("utf-8")).hexdigest()
        except Exception as error:
            logger.error("packet fingerprint build failed: %s", error)
            return ""

    def _prune_fingerprints(self, now: float | None = None) -> None:
        try:
            current = now if now is not None else time.time()
            expired = [
                fingerprint
                for fingerprint, seen_at in self._recent_fingerprints.items()
                if current - seen_at > self._dedup_ttl_sec
            ]
            for fingerprint in expired:
                self._recent_fingerprints.pop(fingerprint, None)
        except Exception as error:
            logger.error("packet fingerprint prune failed: %s", error)

    def _is_duplicate(self, fingerprint: str) -> bool:
        try:
            if not fingerprint:
                return False
            self._prune_fingerprints()
            return fingerprint in self._recent_fingerprints
        except Exception as error:
            logger.error("packet duplicate check failed: %s", error)
            return False

    def _remember_fingerprint(self, fingerprint: str) -> None:
        try:
            if fingerprint:
                self._recent_fingerprints[fingerprint] = time.time()
        except Exception as error:
            logger.error("packet fingerprint remember failed: %s", error)

    async def add_packet(self, packet: dict[str, Any]) -> dict[str, Any]:
        """Alias for receive(); used by TCP and HTTP ingest paths."""
        return await self.receive(packet)

    async def receive(self, packet: dict[str, Any]) -> dict[str, Any]:
        try:
            comm_session = self._touch_comm_session()
            fingerprint = self._packet_fingerprint(packet)
            if self._is_duplicate(fingerprint):
                return self._attach_comm_session(
                    {
                        "status": "duplicate_ignored",
                        "packet_type": packet.get("packet_type"),
                    },
                    comm_session,
                )

            status = await self._receive_packet(packet)
            if status.get("status") != "error":
                self._remember_fingerprint(fingerprint)
            return self._attach_comm_session(status, comm_session)
        except Exception as error:
            logger.error("packet buffer receive failed: %s", error)
            return {"status": "error", "message": str(error)}

    def _store_event_queue_meta(self, packet: dict[str, Any]) -> dict[str, Any]:
        try:
            parsed = parse_event_queue_meta(packet)
            if parsed is None:
                return {"status": "error", "reason": "invalid SAT_EVENT_QUEUE_META"}
            self._pending_event_queue_meta = parsed
            self._received_event_ids = set()
            return {
                "status": "meta_stored",
                "packet_type": "SAT_EVENT_QUEUE_META",
                "event_total": parsed["event_total"],
                "event_ids": parsed["event_ids"],
            }
        except Exception as error:
            logger.error("event queue meta store failed: %s", error)
            return {"status": "error", "message": str(error)}

    def _track_event_queue_item(self, event: dict[str, Any]) -> None:
        try:
            if self._pending_event_queue_meta is None:
                return
            self._received_event_ids.add(int(event.get("EVENT_ID", len(self._received_event_ids) + 1)))
            expected = int(self._pending_event_queue_meta.get("event_total", 0) or 0)
            if expected > 0 and len(self._received_event_ids) >= expected:
                self._pending_event_queue_meta = None
                self._received_event_ids = set()
        except (TypeError, ValueError) as error:
            logger.error("event queue item tracking failed: %s", error)
        except Exception as error:
            logger.error("unexpected event queue item tracking failure: %s", error)

    async def _receive_packet(self, packet: dict[str, Any]) -> dict[str, Any]:
        try:
            packet_type = normalize_packet_type(str(packet.get("packet_type", "")).strip())
            if not packet_type:
                return {"status": "ignored", "reason": "missing packet_type"}

            incoming = dict(packet)
            incoming["packet_type"] = packet_type

            if is_event_queue_meta_packet(incoming):
                return self._store_event_queue_meta(incoming)

            if is_bulk_telemetry_packet(incoming):
                return await self._handle_bulk_telemetry_packet(incoming)

            if is_accumulated_bulk_packet(incoming) or (
                packet_type in BULK_HISTORY_TYPES and isinstance(incoming.get("records"), list)
            ):
                return await self._handle_bulk_packet(packet_type, incoming)

            if packet_type == "SAT_EVENT_QUEUE":
                event = incoming.get("event", incoming)
                if isinstance(event, dict):
                    self._track_event_queue_item(event)
                self._remember_seu_event(incoming)

            bucket_keys = packet_buffer_keys(incoming)
            last_status: dict[str, Any] = {"status": "ignored", "reason": "no buffer key"}

            for key in bucket_keys:
                sliced = self._slice_for_bucket(incoming, key)
                entry = self._buffers.setdefault(key, _BufferEntry())
                entry.packets[packet_type] = sliced
                self._apply_bulk_to_bucket(key, entry)
                last_status = await self._maybe_flush_bucket(key, entry)

            return last_status
        except Exception as error:
            logger.error("packet buffer ingest failed: %s", error)
            return {"status": "error", "message": str(error)}

    async def _timeout_flush(self, key: str) -> None:
        try:
            await asyncio.sleep(self._timeout_sec)
            if key in self._flushed_keys:
                return
            entry = self._buffers.get(key)
            if entry is None or entry.flushed:
                return
            await self._flush(key, entry, partial=True)
        except asyncio.CancelledError:
            return
        except Exception as error:
            logger.error("packet buffer timeout flush failed: %s", error)

    async def _flush(self, key: str, entry: _BufferEntry, partial: bool) -> None:
        try:
            if entry.flushed or key in self._flushed_keys:
                return

            if entry.timer_task and not entry.timer_task.done():
                entry.timer_task.cancel()

            entry.flushed = True
            self._flushed_keys.add(key)

            missing = missing_buffer_types(entry.packets)
            if missing:
                logger.warning(
                    "partial packet merge for %s; missing types: %s",
                    key,
                    ", ".join(missing),
                )

            event_meta = self._consume_event_meta_for_key(key)
            await asyncio.to_thread(
                self._on_flush,
                key,
                dict(entry.packets),
                dict(self._bulk_packets),
                event_meta,
                self._comm_session_id,
            )
            self._buffers.pop(key, None)
            self._bulk_packets.clear()
            if partial and missing:
                return
        except Exception as error:
            logger.error("packet buffer flush failed: %s", error)
