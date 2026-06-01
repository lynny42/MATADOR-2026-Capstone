"""In-memory ring buffer of recent satellite uplink events for live inspection."""

from __future__ import annotations

import json
import logging
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

logger = logging.getLogger(__name__)

_MAX_EVENTS = 100
_MAX_RAW_PACKETS = 20
_RAW_SPOOL_THRESHOLD = 100_000
_RAW_SPOOL_DIR = Path(__file__).resolve().parents[1] / "data" / "raw_uplink"

_events: deque[dict[str, Any]] = deque(maxlen=_MAX_EVENTS)
_raw_packets: deque[dict[str, Any]] = deque(maxlen=_MAX_RAW_PACKETS)
_raw_packet_index: dict[int, dict[str, Any]] = {}
_next_raw_packet_id = 1
_lock = Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _write_raw_spool(entry_id: int, raw_text: str) -> Path | None:
    try:
        _RAW_SPOOL_DIR.mkdir(parents=True, exist_ok=True)
        path = _RAW_SPOOL_DIR / f"uplink_{entry_id}.json"
        path.write_text(raw_text, encoding="utf-8")
        return path
    except OSError as error:
        logger.error("raw spool write failed id=%s: %s", entry_id, error)
        return None
    except Exception as error:
        logger.error("unexpected raw spool write failure id=%s: %s", entry_id, error)
        return None


def _read_raw_spool(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        logger.error("raw spool read failed path=%s: %s", path, error)
        return None
    except Exception as error:
        logger.error("unexpected raw spool read failure path=%s: %s", path, error)
        return None


def _attach_raw_text(entry: dict[str, Any]) -> None:
    try:
        spool_path = entry.get("raw_spool_path")
        if isinstance(spool_path, str) and spool_path:
            loaded = _read_raw_spool(Path(spool_path))
            if loaded is not None:
                entry["raw_text"] = loaded
    except Exception as error:
        logger.error("raw text attach failed: %s", error)


def _compact_raw_entry(entry: dict[str, Any]) -> dict[str, Any]:
    try:
        compact = dict(entry)
        compact.pop("packet", None)
        compact.pop("raw_text", None)
        return compact
    except Exception as error:
        logger.error("raw entry compact failed: %s", error)
        return dict(entry)


def record_raw_packet(
    packet: dict[str, Any] | None = None,
    *,
    peer: str | None = None,
    comm_session: str | None = None,
    byte_length: int = 0,
    status: dict[str, Any] | None = None,
    parse_error: str | None = None,
    raw_text: str | None = None,
) -> int | None:
    """Store one uplink payload; return entry id for full fetch via get_raw_packet."""
    global _next_raw_packet_id
    try:
        with _lock:
            entry_id = _next_raw_packet_id
            _next_raw_packet_id += 1

        entry: dict[str, Any] = {
            "id": entry_id,
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
            entry["raw_byte_length"] = len(raw_text.encode("utf-8"))
            if len(raw_text) > _RAW_SPOOL_THRESHOLD:
                spool_path = _write_raw_spool(entry_id, raw_text)
                if spool_path is not None:
                    entry["raw_spool_path"] = str(spool_path)
                    entry["raw_spooled"] = True
                else:
                    entry["raw_text"] = raw_text
            else:
                entry["raw_text"] = raw_text

        with _lock:
            _raw_packets.appendleft(entry)
            _raw_packet_index[entry_id] = entry
            if len(_raw_packet_index) > _MAX_RAW_PACKETS * 2:
                stale_ids = sorted(_raw_packet_index)[: len(_raw_packet_index) - _MAX_RAW_PACKETS]
                for stale_id in stale_ids:
                    _raw_packet_index.pop(stale_id, None)
        return entry_id
    except Exception as error:
        logger.error("raw packet trace record failed: %s", error)
        return None


def recent_raw_packets(limit: int = 20, *, include_body: bool = False) -> list[dict[str, Any]]:
    """Return recent uplink metadata; set include_body=True to embed full packet/raw_text."""
    try:
        capped = max(1, min(int(limit), _MAX_RAW_PACKETS))
        with _lock:
            items = [dict(item) for item in list(_raw_packets)[:capped]]
        if include_body:
            for item in items:
                _attach_raw_text(item)
            return items
        return [_compact_raw_entry(item) for item in items]
    except Exception as error:
        logger.error("raw packet trace read failed: %s", error)
        return []


def get_raw_packet(entry_id: int) -> dict[str, Any] | None:
    """Return one stored uplink with full packet and wire-format raw_text."""
    try:
        with _lock:
            entry = _raw_packet_index.get(int(entry_id))
            if entry is None:
                for item in _raw_packets:
                    if item.get("id") == int(entry_id):
                        entry = item
                        break
        if entry is None:
            return None
        result = dict(entry)
        _attach_raw_text(result)
        return result
    except Exception as error:
        logger.error("raw packet fetch failed id=%s: %s", entry_id, error)
        return None


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
