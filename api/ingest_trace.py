"""In-memory ring buffer of recent satellite uplink events for live inspection."""

from __future__ import annotations

import json
import logging
from collections import deque
from datetime import datetime, timezone
from threading import Lock
from typing import Any

logger = logging.getLogger(__name__)

_MAX_EVENTS = 100
_MAX_RAW_PACKETS = 30
_RAW_PREVIEW_CHARS = 4000
_events: deque[dict[str, Any]] = deque(maxlen=_MAX_EVENTS)
_raw_packets: deque[dict[str, Any]] = deque(maxlen=_MAX_RAW_PACKETS)
_lock = Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def record_raw_packet(
    packet: dict[str, Any] | None = None,
    *,
    peer: str | None = None,
    comm_session: str | None = None,
    byte_length: int = 0,
    status: dict[str, Any] | None = None,
    parse_error: str | None = None,
    raw_text: str | None = None,
) -> None:
    """Store one uplink payload as parsed JSON (or parse failure preview)."""
    try:
        entry: dict[str, Any] = {
            "at": _utc_now(),
            "byte_length": int(byte_length or 0),
            "parse_ok": parse_error is None and isinstance(packet, dict),
        }
        if peer:
            entry["peer"] = peer
        if comm_session:
            entry["comm_session"] = comm_session
        if status:
            entry["status"] = status
        if parse_error:
            entry["parse_error"] = parse_error
        if isinstance(packet, dict):
            entry["packet_type"] = str(packet.get("packet_type", "") or "")
            entry["packet"] = packet
        if raw_text:
            preview = raw_text if len(raw_text) <= _RAW_PREVIEW_CHARS else raw_text[:_RAW_PREVIEW_CHARS] + "...(truncated)"
            entry["raw_text"] = preview
        with _lock:
            _raw_packets.appendleft(entry)
    except Exception as error:
        logger.error("raw packet trace record failed: %s", error)


def recent_raw_packets(limit: int = 20) -> list[dict[str, Any]]:
    try:
        capped = max(1, min(int(limit), _MAX_RAW_PACKETS))
        with _lock:
            return [dict(item) for item in list(_raw_packets)[:capped]]
    except Exception as error:
        logger.error("raw packet trace read failed: %s", error)
        return []


def format_packet_json(packet: dict[str, Any]) -> str:
    try:
        return json.dumps(packet, ensure_ascii=False, indent=2, default=str)
    except Exception as error:
        logger.error("packet json format failed: %s", error)
        return str(packet)


def record_ingest_event(
    stage: str,
    *,
    packet_type: str | None = None,
    summary: str = "",
    status: dict[str, Any] | None = None,
    peer: str | None = None,
    buffer_key: str | None = None,
    comm_session: str | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    try:
        entry: dict[str, Any] = {
            "at": _utc_now(),
            "stage": stage,
        }
        if packet_type:
            entry["packet_type"] = packet_type
        if summary:
            entry["summary"] = summary
        if status:
            entry["status"] = status
        if peer:
            entry["peer"] = peer
        if buffer_key:
            entry["buffer_key"] = buffer_key
        if comm_session:
            entry["comm_session"] = comm_session
        if extra:
            entry["extra"] = extra
        with _lock:
            _events.appendleft(entry)
    except Exception as error:
        logger.error("ingest trace record failed: %s", error)


def recent_ingest_events(limit: int = 30) -> list[dict[str, Any]]:
    try:
        capped = max(1, min(int(limit), _MAX_EVENTS))
        with _lock:
            return [dict(item) for item in list(_events)[:capped]]
    except Exception as error:
        logger.error("ingest trace read failed: %s", error)
        return []
