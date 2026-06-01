"""SAT_BULK_TELEMETRY ingest with deduplication."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from typing import Any, Callable

from ma_detector.core.packet_protocol import (
    BULK_TELEMETRY_PACKET_TYPE,
    is_bulk_telemetry_packet,
    normalize_packet_type,
)

logger = logging.getLogger(__name__)


class PacketBufferManager:
    """Accept SAT_BULK_TELEMETRY uplinks and forward them for DB persist."""

    def __init__(
        self,
        timeout_sec: float = 5.0,
        *,
        on_bulk_telemetry_persist: Callable[[dict[str, Any]], Any] | None = None,
        match_tolerance_sec: float = 5.0,
    ) -> None:
        self._timeout_sec = float(timeout_sec)
        self._match_tolerance_sec = float(match_tolerance_sec)
        self._on_bulk_telemetry_persist = on_bulk_telemetry_persist
        self._recent_fingerprints: dict[str, float] = {}
        self._dedup_ttl_sec = 300.0
        self._comm_session_seq = 0
        self._comm_session_id: str | None = None
        self._last_comm_wall_time = 0.0

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

    def update_callbacks(
        self,
        *,
        on_bulk_telemetry_persist: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        try:
            if on_bulk_telemetry_persist is not None:
                self._on_bulk_telemetry_persist = on_bulk_telemetry_persist
        except Exception as error:
            logger.error("packet buffer callback update failed: %s", error)

    def _touch_comm_session(self) -> str:
        """Assign packets arriving in one uplink burst to the same comm session."""
        try:
            now = time.time()
            gap_sec = max(self._timeout_sec * 2.0, 10.0)
            if self._comm_session_id is None or now - self._last_comm_wall_time > gap_sec:
                self._comm_session_seq += 1
                self._comm_session_id = f"comm-{self._comm_session_seq}"
            self._last_comm_wall_time = now
            return self._comm_session_id
        except Exception as error:
            logger.error("comm session touch failed: %s", error)
            return "comm-0"

    @staticmethod
    def _attach_comm_session(status: dict[str, Any], comm_session: str) -> dict[str, Any]:
        try:
            enriched = dict(status)
            enriched["comm_session"] = comm_session
            return enriched
        except Exception as error:
            logger.error("comm session attach failed: %s", error)
            return status

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

            packet_type = normalize_packet_type(str(packet.get("packet_type", "")).strip())
            if not is_bulk_telemetry_packet(packet):
                logger.warning("ignored non-bulk uplink packet_type=%s", packet_type)
                status = {
                    "status": "ignored",
                    "reason": "bulk_telemetry_required",
                    "packet_type": packet_type,
                }
            else:
                status = await self._handle_bulk_telemetry_packet(dict(packet))

            if status.get("status") != "error":
                self._remember_fingerprint(fingerprint)
            return self._attach_comm_session(status, comm_session)
        except Exception as error:
            logger.error("packet buffer receive failed: %s", error)
            return {"status": "error", "message": str(error)}

    async def _handle_bulk_telemetry_packet(self, incoming: dict[str, Any]) -> dict[str, Any]:
        try:
            if self._on_bulk_telemetry_persist is None:
                logger.error("bulk telemetry received but persist callback is missing")
                return {"status": "error", "reason": "missing_persist_callback"}

            bulk_stored = dict(incoming)
            bulk_stored["packet_type"] = BULK_TELEMETRY_PACKET_TYPE
            if self._comm_session_id:
                bulk_stored["_comm_session"] = self._comm_session_id

            await asyncio.to_thread(self._on_bulk_telemetry_persist, bulk_stored)
            return {
                "status": "bulk_telemetry_stored",
                "packet_type": BULK_TELEMETRY_PACKET_TYPE,
                "sent_at": incoming.get("sent_at"),
            }
        except Exception as error:
            logger.error("bulk telemetry receive failed: %s", error)
            return {"status": "error", "message": str(error)}
