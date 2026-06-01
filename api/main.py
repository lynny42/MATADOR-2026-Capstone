"""FastAPI application entry point for the MATADOR ground station."""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from api.routers import command, dashboard, replay, rule_manager, telemetry
import api.state as app_state
from api.tcp_command_sender import TCPCommandSender
from api.tcp_receiver import TCPTelemetryReceiver
from api.websocket_manager import ws_manager
from backend.dashboard_service import create_detector
from ma_detector.db import config as db_config
from ma_detector.db.database import init_db, is_db_available, require_db
from ma_detector.db.gs_repository import refresh_column_cache
from ma_detector.db.startup_bootstrap import ensure_schema

logger = logging.getLogger(__name__)


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


def _tcp_settings() -> dict[str, Any]:
    try:
        from ma_detector.registry.registry_manager import RegistryManager

        _, _, thresholds = RegistryManager().load_all()
        section = thresholds.get("tcp", {})
        return dict(section) if isinstance(section, dict) else {}
    except Exception as error:
        logger.error("tcp settings lookup failed: %s", error)
        return {}


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    tcp_receiver: TCPTelemetryReceiver | None = None
    tcp_task: asyncio.Task[None] | None = None

    try:
        init_db(
            host=db_config.DB_HOST,
            port=db_config.DB_PORT,
            user=db_config.DB_USER,
            password=db_config.DB_PASSWORD,
            database=db_config.DB_NAME,
            pool_size=db_config.DB_POOL_SIZE,
        )
        if is_db_available():
            ensure_schema()
            refresh_column_cache()
            require_db()
        else:
            raise RuntimeError("MySQL is required for ground-station operation")
    except RuntimeError:
        raise
    except Exception as error:
        logger.error("database initialization failed: %s", error)
        raise RuntimeError("MySQL is required for ground-station operation") from error

    detector_instance = create_detector()
    from backend.dashboard_service import DashboardService

    service_instance = DashboardService(detector_instance)
    app_state.detector = detector_instance
    app_state.service = service_instance
    timeout_sec, tolerance_sec = _packet_buffer_settings()
    telemetry.configure_buffer(timeout_sec, tolerance_sec)

    tcp_config = _tcp_settings()
    tcp_receiver = TCPTelemetryReceiver(
        detector=detector_instance,
        buffer=telemetry.get_buffer_manager(),
        ws_manager=ws_manager,
        host=str(tcp_config.get("host", "0.0.0.0")),
        port=int(tcp_config.get("port", 6000)),
        max_packet_size=int(tcp_config.get("max_packet_size", 2097152)),
    )
    tcp_task = asyncio.create_task(tcp_receiver.start())

    app.state.command_sender = TCPCommandSender(
        sat_host=os.getenv("SAT_HOST", str(tcp_config.get("sat_host", "192.168.0.7"))),
        sat_port=int(tcp_config.get("sat_port", 6001)),
        max_packet_size=int(tcp_config.get("recv_buffer_size", 65535)),
    )
    app.state.tcp_receiver = tcp_receiver

    yield

    if tcp_task is not None:
        tcp_task.cancel()
        try:
            await tcp_task
        except asyncio.CancelledError:
            pass
    if tcp_receiver is not None:
        await tcp_receiver.stop()


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    app = FastAPI(
        title="MATADOR MA Integrated Detector API",
        version="0.2.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(telemetry.router)
    app.include_router(command.router)
    app.include_router(dashboard.router)
    app.include_router(rule_manager.router)
    app.include_router(replay.router)

    @app.websocket("/ws/status")
    async def websocket_status(websocket: WebSocket) -> None:
        try:
            await ws_manager.connect(websocket)
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)
        except Exception as error:
            logger.error("websocket status endpoint failed: %s", error)
            ws_manager.disconnect(websocket)

    return app


app = create_app()
