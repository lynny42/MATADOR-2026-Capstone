"""Telemetry ingest routes with five-packet buffering."""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Query

from api.ingest_trace import recent_ingest_events, recent_raw_packets, record_ingest_event
from api.packet_buffer import PacketBufferManager
from api.state import get_detector
from api.websocket_manager import ws_manager
from ma_detector.core.packet_protocol import summarize_uplink_packet
from ma_detector.core.bulk_history_merge import merge_bulk_telemetry_packet
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
    """Initialize or update the packet buffer manager."""
    global _buffer_manager

    default_timeout, default_tolerance = _packet_buffer_settings()
    timeout = float(timeout_sec if timeout_sec is not None else default_timeout)
    tolerance = float(match_tolerance_sec if match_tolerance_sec is not None else default_tolerance)

    def _on_bulk_stored(packet: dict[str, Any]) -> None:
        try:
            detector = get_detector()
            inserted, skipped = detector.persist_accumulated_packet(packet)
            record_ingest_event(
                "db_persist",
                packet_type=str(packet.get("packet_type", "")),
                comm_session=packet.get("_comm_session"),
                summary=(
                    f"inserted={inserted} skipped={skipped} "
                    f"type={packet.get('packet_type', '')} "
                    f"db={'ok' if is_db_available() else 'unavailable'}"
                ),
                extra={
                    "inserted": inserted,
                    "skipped": skipped,
                    "db_available": is_db_available(),
                    "record_count": len(packet.get("records", [])),
                },
            )
        except Exception as error:
            logger.error("accumulated history persist failed: %s", error)
            record_ingest_event(
                "db_persist_error",
                packet_type=str(packet.get("packet_type", "")),
                comm_session=packet.get("_comm_session"),
                summary=str(error),
            )

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

    def _on_comm_session_end(comm_session: str) -> None:
        try:
            detector = get_detector()
            inserted, skipped = detector.flush_comm_session_history(comm_session)
            if inserted or skipped:
                record_ingest_event(
                    "db_persist",
                    comm_session=comm_session,
                    summary=f"comm_end inserted={inserted} skipped={skipped}",
                    extra={"inserted": inserted, "skipped": skipped, "comm_end": True},
                )
        except Exception as error:
            logger.error("comm session history flush failed: %s", error)

    def _on_flush(
        key: str,
        packets: dict[str, dict[str, Any]],
        bulk_packets: dict[str, dict[str, Any]],
        event_meta: list[dict[str, Any]] | None = None,
        comm_session: str | None = None,
    ) -> None:
        try:
            detector = get_detector()
            if comm_session:
                inserted, skipped = detector.flush_comm_session_history(comm_session)
                record_ingest_event(
                    "db_persist",
                    buffer_key=key,
                    comm_session=comm_session,
                    summary=(
                        f"pipeline_flush inserted={inserted} skipped={skipped} "
                        f"db={'ok' if is_db_available() else 'unavailable'}"
                    ),
                    extra={
                        "inserted": inserted,
                        "skipped": skipped,
                        "pipeline_flush": True,
                        "db_available": is_db_available(),
                    },
                )
            merged = detector.merge_buffered_packets(
                packets,
                buffer_key=key,
                match_tolerance_sec=tolerance,
                bulk_packets=bulk_packets,
                event_meta=event_meta,
            )
            if not merged:
                logger.warning("merged packet is empty; pipeline skipped")
                record_ingest_event(
                    "pipeline_skipped",
                    buffer_key=key,
                    summary="merged packet empty",
                )
                return
            merged["_buffer_key"] = key
            merged["_match_tolerance_sec"] = tolerance
            if comm_session:
                merged["_comm_session"] = comm_session
            is_anomaly = bool(merged.get("IS_ANOMALY"))
            weight = int(merged.get("WEIGHT", merged.get("FALSE_POSITIVE_WEIGHT", 0)) or 0)
            stage = "pipeline_flush" if is_anomaly else "buffer_merge"
            flush_summary = (
                f"buffer_key={key} IS_ANOMALY={is_anomaly} WEIGHT={weight} "
                f"EVENT_TYPE={merged.get('EVENT_TYPE', '')}"
            )
            logger.info("%s: %s", stage, flush_summary)
            record_ingest_event(
                stage,
                buffer_key=key,
                comm_session=comm_session,
                summary=flush_summary,
                extra={
                    "is_anomaly": is_anomaly,
                    "weight": weight,
                    "event_type": merged.get("EVENT_TYPE"),
                    "target_subsystem": merged.get("TARGET_SUBSYSTEM"),
                },
            )
            detector.receive_telemetry(
                json.dumps(merged, ensure_ascii=False, default=str),
                skip_history_insert=True,
            )
            if is_anomaly:
                ws_manager.broadcast_sync(
                    {
                        "type": "PIPELINE_FLUSH",
                        "buffer_key": key,
                        "summary": flush_summary,
                        "is_anomaly": is_anomaly,
                    }
                )
        except Exception as error:
            logger.error("buffer flush pipeline failed: %s", error)

    if _buffer_manager is None:
        _buffer_manager = PacketBufferManager(
            timeout,
            _on_flush,
            match_tolerance_sec=tolerance,
            on_bulk_stored=_on_bulk_stored,
            on_bulk_telemetry_persist=_on_bulk_telemetry_persist,
            on_comm_session_end=_on_comm_session_end,
        )
    else:
        _buffer_manager.update_timeout(timeout)
        _buffer_manager.update_match_tolerance(tolerance)
        _buffer_manager.update_callbacks(
            _on_flush,
            on_bulk_stored=_on_bulk_stored,
            on_bulk_telemetry_persist=_on_bulk_telemetry_persist,
            on_comm_session_end=_on_comm_session_end,
        )


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
def get_recent_raw_packets(limit: int = Query(default=10, ge=1, le=30)) -> dict[str, Any]:
    """Return recent uplink payloads as parsed JSON objects (newest first)."""
    try:
        items = recent_raw_packets(limit)
        return {"count": len(items), "items": items}
    except Exception as error:
        logger.error("recent raw packet query failed: %s", error)
        return {"count": 0, "items": [], "error": str(error)}


@router.post("/receive")
async def receive_telemetry(packet: dict[str, Any]) -> dict[str, Any]:
    """Receive one satellite packet and buffer until merge."""
    try:
        summary = summarize_uplink_packet(packet)
        status = await get_buffer_manager().receive(packet)
        record_ingest_event(
            "http_received",
            packet_type=str(packet.get("packet_type", "")),
            summary=summary,
            status=status,
            buffer_key=status.get("buffer_key"),
        )
        return status
    except Exception as error:
        logger.error("telemetry receive failed: %s", error)
        return {"status": "error", "message": str(error)}
