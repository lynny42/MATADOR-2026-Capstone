"""Replay analysis routes backed by stored MySQL telemetry."""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.state import get_detector
from ma_detector.db import gs_repository
from ma_detector.db.database import require_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/replay", tags=["replay"])


class ReplayStartRequest(BaseModel):
    from_time: str
    to_time: str


@router.post("/start")
def start_replay(request: ReplayStartRequest) -> dict[str, Any]:
    try:
        require_db()
        detector = get_detector()
        payloads = gs_repository.load_replay_payloads(request.from_time, request.to_time)
        gs_repository.clear_ma_results()
        confirmed_count = 0
        suspected_count = 0
        new_pattern_count = 0
        skipped_normal = 0
        reprocessed = 0

        for payload in payloads:
            try:
                packet = json.loads(payload)
                if not isinstance(packet, dict):
                    continue
                if not packet.get("IS_ANOMALY", False):
                    skipped_normal += 1
                    continue
                error = detector.receive_telemetry(
                    json.dumps(packet, ensure_ascii=False, default=str),
                    reprocess=True,
                )
                if error is not None:
                    continue
                reprocessed += 1
            except json.JSONDecodeError as error:
                logger.error("replay payload parse failed: %s", error)

        rows = gs_repository.query_recent_dashboards(500)
        for row in rows:
            grade = str(row.get("GRADE", ""))
            if grade == "CONFIRMED":
                confirmed_count += 1
            elif grade == "SUSPECTED":
                suspected_count += 1
            if int(row.get("IS_NEW_PATTERN", 0) or 0) == 1:
                new_pattern_count += 1

        from backend.dashboard_service import _hydrate_detector_from_db

        _hydrate_detector_from_db(detector)

        return {
            "confirmed_count": confirmed_count,
            "suspected_count": suspected_count,
            "new_pattern_count": new_pattern_count,
            "processed": len(payloads),
            "reprocessed": reprocessed,
            "skipped_normal": skipped_normal,
        }
    except Exception as error:
        logger.error("replay start failed: %s", error)
        raise HTTPException(status_code=500, detail=str(error)) from error


@router.get("/result")
def replay_result() -> dict[str, Any]:
    try:
        require_db()
        rows = gs_repository.query_recent_dashboards(500)
        confirmed: list[Any] = []
        suspected: list[Any] = []
        discarded: list[Any] = []
        for row in rows:
            grade = str(row.get("GRADE", ""))
            item = {
                "ma_code": row.get("MA_CODE"),
                "grade": grade,
                "confidence_score": row.get("CONFIDENCE_SCORE"),
                "module": row.get("MODULE"),
                "action": row.get("ACTION"),
            }
            if grade == "CONFIRMED":
                confirmed.append(item)
            elif grade == "SUSPECTED":
                suspected.append(item)
            else:
                discarded.append(item)
        return {"confirmed": confirmed, "suspected": suspected, "discarded": discarded}
    except Exception as error:
        logger.error("replay result failed: %s", error)
        raise HTTPException(status_code=500, detail=str(error)) from error


@router.delete("/clear")
def clear_replay() -> dict[str, str]:
    try:
        require_db()
        gs_repository.clear_ma_results()
        detector = get_detector()
        detector.set_replay_mode(False)
        from backend.dashboard_service import _hydrate_detector_from_db

        _hydrate_detector_from_db(detector)
        return {"status": "cleared"}
    except Exception as error:
        logger.error("replay clear failed: %s", error)
        raise HTTPException(status_code=500, detail=str(error)) from error
