"""Bulk telemetry ingest buffer (used by TCP uplink on port 6000)."""

from __future__ import annotations

import logging
from typing import Any, Callable

from api.packet_buffer import PacketBufferManager

logger = logging.getLogger(__name__)

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
            from api.state import get_detector
            from api.ingest_trace import record_ingest_event
            from ma_detector.core.bulk_history_merge import merge_bulk_telemetry_packet
            from ma_detector.db.database import is_db_available

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
            from api.ingest_trace import record_ingest_event

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
