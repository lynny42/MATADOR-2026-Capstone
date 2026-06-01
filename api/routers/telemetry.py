"""Telemetry ingest routes for SAT_BULK_TELEMETRY uplinks."""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse, PlainTextResponse

from api.ingest_trace import (
    format_packet_json,
    get_raw_packet,
    recent_ingest_events,
    recent_raw_packets,
    record_ingest_event,
    record_raw_packet,
)
from api.packet_buffer import PacketBufferManager
from api.state import get_detector
from ma_detector.core.bulk_history_merge import merge_bulk_telemetry_packet
from ma_detector.core.packet_protocol import summarize_uplink_packet
from ma_detector.db.database import is_db_available

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/telemetry", tags=["telemetry"])

_buffer_manager: PacketBufferManager | None = None


def _packet_buffer_settings() -> tuple[float, float]:
    try:
        from ma_detector.registry.registry_manager import RegistryManager

        _, _, thresholds = RegistryManager().load_all()
        section = thresholds.get("packet_buffer", {})
        timeout_sec = float(section.get("packet_buffer_timeout_sec", 5))
        tolerance_sec = float(section.get("RECORD_MATCH_TOLERANCE_SEC", 5))
        return timeout_sec, tolerance_sec
    except Exception as error:
        logger.error("packet buffer settings lookup failed: %s", error)
        return 5.0, 5.0


def configure_buffer(timeout_sec: float | None = None, match_tolerance_sec: float | None = None) -> None:
    """Initialize or update the bulk telemetry ingest manager."""
    global _buffer_manager

    default_timeout, default_tolerance = _packet_buffer_settings()
    timeout = float(timeout_sec if timeout_sec is not None else default_timeout)
    tolerance = float(match_tolerance_sec if match_tolerance_sec is not None else default_tolerance)

    def _on_bulk_telemetry_persist(bulk: dict[str, Any]) -> None:
        try:
            detector = get_detector()
            inserted, skipped = detector.persist_bulk_telemetry_packet(bulk)
            sample_count = len(merge_bulk_telemetry_packet(bulk))
            record_ingest_event(
                "db_persist",
                packet_type="SAT_BULK_TELEMETRY",
                comm_session=bulk.get("_comm_session"),
                summary=(
                    f"bulk inserted={inserted} skipped={skipped} "
                    f"samples={sample_count} "
                    f"db={'ok' if is_db_available() else 'unavailable'}"
                ),
                extra={
                    "inserted": inserted,
                    "skipped": skipped,
                    "db_available": is_db_available(),
                    "record_count": sample_count,
                    "bulk_telemetry": True,
                },
            )
        except Exception as error:
            logger.error("bulk telemetry history persist failed: %s", error)
            record_ingest_event(
                "db_persist_error",
                packet_type="SAT_BULK_TELEMETRY",
                comm_session=bulk.get("_comm_session"),
                summary=str(error),
            )

    if _buffer_manager is None:
        _buffer_manager = PacketBufferManager(
            timeout_sec=timeout,
            match_tolerance_sec=tolerance,
            on_bulk_telemetry_persist=_on_bulk_telemetry_persist,
        )
    else:
        _buffer_manager.update_timeout(timeout)
        _buffer_manager.update_match_tolerance(tolerance)
        _buffer_manager.update_callbacks(on_bulk_telemetry_persist=_on_bulk_telemetry_persist)


def get_buffer_manager() -> PacketBufferManager:
    """Return the shared packet buffer singleton."""
    if _buffer_manager is None:
        configure_buffer()
    assert _buffer_manager is not None
    return _buffer_manager


@router.get("/recent")
def get_recent_ingest(limit: int = Query(default=30, ge=1, le=100)) -> dict[str, Any]:
    """Return recent TCP ingest / buffer / pipeline events (newest first)."""
    try:
        items = recent_ingest_events(limit)
        return {"count": len(items), "items": items}
    except Exception as error:
        logger.error("recent ingest query failed: %s", error)
        return {"count": 0, "items": [], "error": str(error)}


@router.get("/raw")
def get_recent_raw_packets(
    limit: int = Query(default=10, ge=1, le=30),
    include_body: bool = Query(default=False, description="Include full packet/raw_text in list (large JSON)"),
) -> dict[str, Any]:
    """Return recent uplink index rows (metadata only by default)."""
    try:
        items = recent_raw_packets(limit, include_body=include_body)
        return {"count": len(items), "items": items}
    except Exception as error:
        logger.error("recent raw packet query failed: %s", error)
        return {"count": 0, "items": [], "error": str(error)}


@router.get("/raw/{entry_id}")
def get_raw_packet_detail(
    entry_id: int,
    wire: bool = Query(default=False, description="Return original TCP wire JSON as plain text"),
) -> Any:
    """Return one full uplink payload by id from the ingest ring buffer."""
    try:
        item = get_raw_packet(entry_id)
        if item is None:
            return JSONResponse(status_code=404, content={"error": "raw packet not found", "id": entry_id})
        if wire:
            raw_text = item.get("raw_text")
            if isinstance(raw_text, str) and raw_text:
                return PlainTextResponse(content=raw_text, media_type="application/json; charset=utf-8")
            packet = item.get("packet")
            if isinstance(packet, dict):
                return PlainTextResponse(
                    content=format_packet_json(packet),
                    media_type="application/json; charset=utf-8",
                )
            return PlainTextResponse(content="", media_type="text/plain")
        return item
    except Exception as error:
        logger.error("raw packet detail query failed: %s", error)
        return JSONResponse(status_code=500, content={"error": str(error)})


@router.post("/receive")
async def receive_telemetry(packet: dict[str, Any]) -> dict[str, Any]:
    """Receive one SAT_BULK_TELEMETRY packet and persist merged history rows."""
    try:
        summary = summarize_uplink_packet(packet)
        status = await get_buffer_manager().receive(packet)
        wire_text = json.dumps(packet, ensure_ascii=False, default=str)
        record_raw_packet(
            packet,
            byte_length=len(wire_text.encode("utf-8")),
            status=status,
            raw_text=wire_text,
            comm_session=status.get("comm_session"),
        )
        record_ingest_event(
            "http_received",
            packet_type=str(packet.get("packet_type", "")),
            summary=summary,
            status=status,
            buffer_key=status.get("buffer_key"),
            comm_session=status.get("comm_session"),
        )
        return status
    except Exception as error:
        logger.error("telemetry receive failed: %s", error)
        return {"status": "error", "message": str(error)}
