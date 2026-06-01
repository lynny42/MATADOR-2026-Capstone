"""WebSocket connection manager for live dashboard status."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    """Manage dashboard WebSocket clients and broadcast JSON events."""

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    async def connect(self, websocket: WebSocket) -> None:
        try:
            await websocket.accept()
            self._connections.add(websocket)
            self._loop = asyncio.get_running_loop()
        except Exception as error:
            logger.error("websocket connect failed: %s", error)

    def disconnect(self, websocket: WebSocket) -> None:
        try:
            self._connections.discard(websocket)
        except Exception as error:
            logger.error("websocket disconnect failed: %s", error)

    async def broadcast(self, message: dict[str, Any]) -> None:
        try:
            payload = json.dumps(message, ensure_ascii=False, default=str)
            stale: list[WebSocket] = []
            for connection in list(self._connections):
                try:
                    await connection.send_text(payload)
                except Exception as error:
                    logger.error("websocket send failed: %s", error)
                    stale.append(connection)
            for connection in stale:
                self.disconnect(connection)
        except Exception as error:
            logger.error("websocket broadcast failed: %s", error)

    def broadcast_sync(self, message: dict[str, Any]) -> None:
        try:
            if self._loop is None or not self._loop.is_running():
                return
            asyncio.run_coroutine_threadsafe(self.broadcast(message), self._loop)
        except Exception as error:
            logger.error("websocket sync broadcast failed: %s", error)


ws_manager = WebSocketManager()
