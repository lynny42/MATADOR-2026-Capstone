"""Dashboard query routes."""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, HTTPException, Query

from api.state import get_detector
from ma_detector.db import gs_repository
from ma_detector.db.database import require_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/recent")
def get_recent_dashboards(count: int = Query(default=5, ge=1, le=100)) -> dict:
    try:
        require_db()
        rows = gs_repository.query_recent_dashboards(count)
        return {"count": len(rows), "items": rows}
    except Exception as error:
        logger.error("recent dashboard query failed: %s", error)
        raise HTTPException(status_code=500, detail=str(error)) from error


@router.get("/ma_codes")
def get_ma_codes() -> dict:
    try:
        require_db()
        rows = gs_repository.query_ma_codes()
        return {"items": rows}
    except Exception as error:
        logger.error("ma code query failed: %s", error)
        raise HTTPException(status_code=500, detail=str(error)) from error


@router.get("/{detect_id}")
def get_dashboard_detail(detect_id: int) -> dict:
    try:
        require_db()
        payload = json.loads(get_detector().get_ui_data(detect_id))
        if "error" in payload:
            raise HTTPException(status_code=404, detail=payload["error"])
        return payload
    except HTTPException:
        raise
    except Exception as error:
        logger.error("dashboard detail query failed: %s", error)
        raise HTTPException(status_code=500, detail=str(error)) from error
