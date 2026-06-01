"""Shared FastAPI application state."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from backend.dashboard_service import DashboardService
    from ma_detector import MAIntegratedDetector

detector: MAIntegratedDetector | None = None
service: DashboardService | None = None


def get_detector() -> MAIntegratedDetector:
    """Return the initialized detector singleton."""
    if detector is None:
        raise RuntimeError("detector is not initialized")
    return detector


def get_service() -> DashboardService:
    """Return the initialized dashboard service singleton."""
    if service is None:
        raise RuntimeError("dashboard service is not initialized")
    return service
