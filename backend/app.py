"""FastAPI application for the MA integrated detector dashboard."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.dashboard_service import DashboardService, create_detector_with_seed

app = FastAPI(title="MATADOR MA Integrated Detector API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

service = DashboardService(create_detector_with_seed())


class RuleUpsertRequest(BaseModel):
    """Request body for creating or replacing a rule."""

    rule_id: str = Field(..., min_length=1)
    definition: dict[str, Any]


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
    packets: list[dict[str, Any]] | None = None


@app.get("/api/health")
def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok"}


@app.get("/api/dashboard")
def get_dashboard() -> dict[str, Any]:
    """Return the auto-refresh dashboard state."""
    return service.get_dashboard_state()


@app.post("/api/telemetry")
def receive_telemetry(packet: dict[str, Any]) -> dict[str, Any]:
    """Receive satellite JSON and refresh dashboard state."""
    return service.receive_satellite_packet(packet)


@app.get("/api/detections/{detect_id}")
def get_detection(
    detect_id: int,
    snapshot_index: int | None = Query(default=None, ge=0),
) -> dict[str, Any]:
    """Return detail for a selected MA code at an optional 1-second snapshot index."""
    payload = service.get_detection_detail(detect_id, snapshot_index)
    if "error" in payload:
        raise HTTPException(status_code=404, detail=payload["error"])
    return payload


@app.get("/api/rules")
def get_rules() -> dict[str, Any]:
    """Return editable rules, actions, and thresholds."""
    return service.list_rules()


@app.post("/api/rules")
def upsert_rule(request: RuleUpsertRequest) -> dict[str, Any]:
    """Create or replace a rule definition."""
    return service.upsert_rule(request.rule_id, request.definition)


@app.patch("/api/rules/{rule_id}")
def update_rule(rule_id: str, request: RuleUpdateRequest) -> dict[str, Any]:
    """Patch an existing rule definition."""
    return service.update_rule(rule_id, request.updates)


@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: str) -> dict[str, Any]:
    """Delete a rule definition."""
    return service.delete_rule(rule_id)


@app.patch("/api/thresholds")
def update_threshold(request: ThresholdUpdateRequest) -> dict[str, Any]:
    """Update a threshold setting."""
    return service.update_threshold(request.category, request.key, request.value)


@app.post("/api/replay")
def replay(request: ReplayRequest) -> dict[str, Any]:
    """Run replay analysis after rule or threshold edits."""
    return service.run_replay(request.packets)


@app.post("/api/replay/preview")
def replay_preview(request: ReplayConfigRequest) -> dict[str, Any]:
    """Run a replay with temporary rules and thresholds."""
    return service.run_replay_preview(request.rules, request.thresholds, request.packets)


@app.post("/api/replay/apply")
def replay_apply(request: ReplayConfigRequest) -> dict[str, Any]:
    """Persist replay rules and thresholds, then rebuild detector state."""
    return service.apply_replay_config(request.rules, request.thresholds)
