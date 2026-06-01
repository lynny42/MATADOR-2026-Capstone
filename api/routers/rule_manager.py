"""Rule and threshold management routes (extensions beyond legacy backend/app.py)."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.state import get_detector

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["rules"])


class ContributionUpdateRequest(BaseModel):
    action_id: str
    score: float


class ThresholdUpdateRequest(BaseModel):
    category: str
    key: str
    value: float


class ToggleRuleRequest(BaseModel):
    enabled: bool = True


@router.patch("/rules/{rule_id}/toggle")
def toggle_rule(rule_id: str, request: ToggleRuleRequest) -> dict:
    try:
        detector = get_detector()
        if not detector._registry_manager.toggle_rule(rule_id, request.enabled):
            raise HTTPException(status_code=400, detail="rule toggle failed")
        detector.reload_config()
        return {"ok": True, "rule_id": rule_id, "enabled": request.enabled}
    except HTTPException:
        raise
    except Exception as error:
        logger.error("toggle rule failed: %s", error)
        raise HTTPException(status_code=500, detail=str(error)) from error


@router.patch("/rules/{rule_id}/contribution")
def update_contribution(rule_id: str, request: ContributionUpdateRequest) -> dict:
    try:
        detector = get_detector()
        if not detector._registry_manager.update_contribution(rule_id, request.action_id, request.score):
            raise HTTPException(status_code=400, detail="contribution update failed")
        detector.reload_config()
        return {"ok": True, "rule_id": rule_id, "action_id": request.action_id, "score": request.score}
    except HTTPException:
        raise
    except Exception as error:
        logger.error("update contribution failed: %s", error)
        raise HTTPException(status_code=500, detail=str(error)) from error


@router.get("/actions")
def get_actions() -> dict:
    try:
        detector = get_detector()
        return {"actions": detector.get_action_registry()}
    except Exception as error:
        logger.error("get actions failed: %s", error)
        raise HTTPException(status_code=500, detail=str(error)) from error


@router.patch("/threshold")
def update_threshold_singular(request: ThresholdUpdateRequest) -> dict:
    try:
        detector = get_detector()
        if not detector._registry_manager.update_threshold(request.category, request.key, request.value):
            raise HTTPException(status_code=400, detail="threshold update failed")
        detector.reload_config()
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as error:
        logger.error("update threshold failed: %s", error)
        raise HTTPException(status_code=500, detail=str(error)) from error
