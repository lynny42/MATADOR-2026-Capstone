"""FastAPI application for the MA integrated detector dashboard."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Query
from pydantic import BaseModel, Field

from api.main import app
from api.state import get_service
from backend.dashboard_service import DashboardService

service: DashboardService | None = None


def _service() -> DashboardService:
    global service
    if service is None:
        service = get_service()
    return service


class RuleUpsertRequest(BaseModel):
    """Request body for creating or replacing a rule."""

    rule_id: str = Field(..., min_length=1)
    definition: dict[str, Any]


class ActionUpsertRequest(BaseModel):
    """Request body for creating or replacing an action."""

    action_id: str = Field(..., min_length=1)
    definition: dict[str, Any]


class ActionUpdateRequest(BaseModel):
    """Request body for patching an existing action."""

    updates: dict[str, Any]


class RuleUpdateRequest(BaseModel):
    """Request body for patching an existing rule."""

    updates: dict[str, Any]


class ThresholdUpdateRequest(BaseModel):
    """Request body for updating one threshold value."""

    category: str
    key: str
    value: float


class ReplayRequest(BaseModel):
    """Request body for running replay analysis."""

    packets: list[dict[str, Any]] | None = None


class ReplayConfigRequest(BaseModel):
    """Request body for temporary replay configuration."""

    rules: dict[str, Any]
    thresholds: dict[str, Any]
    actions: dict[str, Any] | None = None
    packets: list[dict[str, Any]] | None = None


class RulesPersistRequest(BaseModel):
    """Request body for replacing the full rule registry on disk."""

    rules: dict[str, Any]


class ThresholdsPersistRequest(BaseModel):
    """Request body for replacing threshold configuration on disk."""

    thresholds: dict[str, Any]


class ActionsPersistRequest(BaseModel):
    """Request body for replacing the full action registry on disk."""

    actions: dict[str, Any]


@app.get("/api/health")
def health() -> dict[str, str]:
    """Health check endpoint."""
    from ma_detector.db.database import is_db_available

    if not is_db_available():
        raise HTTPException(status_code=503, detail="MySQL unavailable")
    return {"status": "ok", "database": "connected"}


@app.get("/api/dashboard")
def get_dashboard() -> dict[str, Any]:
    """Return the auto-refresh dashboard state."""
    return _service().get_dashboard_state()


@app.post("/api/telemetry")
def receive_telemetry_legacy(packet: dict[str, Any]) -> dict[str, Any]:
    """Receive satellite JSON and refresh dashboard state."""
    return _service().receive_satellite_packet(packet)


@app.get("/api/detections/{detect_id}")
def get_detection(
    detect_id: int,
    snapshot_index: int | None = Query(default=None, ge=0),
) -> dict[str, Any]:
    """Return detail for a selected MA code at an optional 1-second snapshot index."""
    payload = _service().get_detection_detail(detect_id, snapshot_index)
    if "error" in payload:
        raise HTTPException(status_code=404, detail=payload["error"])
    return payload


@app.get("/api/rules")
def get_rules() -> dict[str, Any]:
    """Return editable rules, actions, and thresholds."""
    return _service().list_rules()


@app.post("/api/rules")
def upsert_rule(request: RuleUpsertRequest) -> dict[str, Any]:
    """Create or replace a rule definition."""
    return _service().upsert_rule(request.rule_id, request.definition)


@app.patch("/api/rules/{rule_id}")
def update_rule(rule_id: str, request: RuleUpdateRequest) -> dict[str, Any]:
    """Patch an existing rule definition."""
    return _service().update_rule(rule_id, request.updates)


@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: str) -> dict[str, Any]:
    """Delete a rule definition."""
    return _service().delete_rule(rule_id)


@app.post("/api/actions")
def upsert_action(request: ActionUpsertRequest) -> dict[str, Any]:
    """Create or replace an action definition."""
    return _service().upsert_action(request.action_id, request.definition)


@app.patch("/api/actions/{action_id}")
def update_action(action_id: str, request: ActionUpdateRequest) -> dict[str, Any]:
    """Patch an existing action definition."""
    return _service().update_action(action_id, request.updates)


@app.delete("/api/actions/{action_id}")
def delete_action(action_id: str) -> dict[str, Any]:
    """Delete an action definition."""
    return _service().delete_action(action_id)


@app.patch("/api/thresholds")
def update_threshold(request: ThresholdUpdateRequest) -> dict[str, Any]:
    """Update a threshold setting."""
    return _service().update_threshold(request.category, request.key, request.value)


@app.post("/api/replay")
def replay(request: ReplayRequest) -> dict[str, Any]:
    """Run replay analysis after rule or threshold edits."""
    return _service().run_replay(request.packets)


@app.post("/api/replay/preview")
def replay_preview(request: ReplayConfigRequest) -> dict[str, Any]:
    """Run a replay with temporary rules and thresholds."""
    try:
        return _service().run_replay_preview(
            request.rules, request.thresholds, request.packets, request.actions
        )
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error)) from error


@app.post("/api/replay/apply")
def replay_apply(request: ReplayConfigRequest) -> dict[str, Any]:
    """Persist Rule/Action/Threshold JSON and re-run MAIntegratedDetector on all stored telemetry."""
    return _service().apply_replay_config(
        request.rules, request.thresholds, request.actions
    )


@app.post("/api/config/rules")
def persist_rules(request: RulesPersistRequest) -> dict[str, Any]:
    """Persist the full rule registry JSON used by the live detector."""
    return _service().persist_rules(request.rules)


@app.post("/api/config/thresholds")
def persist_thresholds(request: ThresholdsPersistRequest) -> dict[str, Any]:
    """Persist threshold configuration JSON used by the live detector."""
    return _service().persist_thresholds(request.thresholds)


@app.post("/api/config/actions")
def persist_actions(request: ActionsPersistRequest) -> dict[str, Any]:
    """Persist the full action registry JSON used by the live detector."""
    return _service().persist_actions(request.actions)
