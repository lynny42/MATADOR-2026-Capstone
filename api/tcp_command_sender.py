"""TCP command sender for satellite downlink on port 6001."""

from __future__ import annotations

import asyncio
import json
import logging
import struct
from typing import Any

logger = logging.getLogger(__name__)


class TCPCommandSender:
    """Send length-prefixed JSON commands to the satellite listener."""

    def __init__(
        self,
        sat_host: str,
        sat_port: int = 6001,
        connect_timeout_sec: float = 5.0,
        max_packet_size: int = 65535,
    ) -> None:
        self._sat_host = sat_host
        self._sat_port = int(sat_port)
        self._connect_timeout_sec = float(connect_timeout_sec)
        self._max_packet_size = int(max_packet_size)

    async def send_command(self, cmd: dict[str, Any]) -> bool:
        """Connect to the satellite, send one command, and close the connection."""
        writer: asyncio.StreamWriter | None = None
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(self._sat_host, self._sat_port),
                timeout=self._connect_timeout_sec,
            )
            await self._send_length_prefix(writer, cmd)
            await writer.drain()
            logger.info("command sent to %s:%s: %s", self._sat_host, self._sat_port, cmd.get("cmd"))
            return True
        except asyncio.TimeoutError as error:
            logger.error("command send timeout: %s", error)
            return False
        except OSError as error:
            logger.error("command send connection failed: %s", error)
            return False
        except Exception as error:
            logger.error("command send failed: %s", error)
            return False
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception as error:
                    logger.error("command connection close failed: %s", error)

    async def send_attack_sim(self) -> bool:
        try:
            return await self.send_command({"cmd": "ATTACK_SIM"})
        except Exception as error:
            logger.error("send attack sim failed: %s", error)
            return False

    async def send_attack_hash(self) -> bool:
        try:
            return await self.send_command({"cmd": "ATTACK_HASH"})
        except Exception as error:
            logger.error("send attack hash failed: %s", error)
            return False

    async def send_recovery(self) -> bool:
        try:
            return await self.send_command({"cmd": "RECOVERY"})
        except Exception as error:
            logger.error("send recovery failed: %s", error)
            return False

    async def send_update_threshold(self, sw_id: int, lo: float, hi: float) -> bool:
        try:
            return await self.send_command(
                {
                    "cmd": "UPDATE_THRESHOLD",
                    "sw_id": int(sw_id),
                    "lo": float(lo),
                    "hi": float(hi),
                }
            )
        except Exception as error:
            logger.error("send update threshold failed: %s", error)
            return False

    async def send_update_hash(self, file_id: int, file_path: str, expected_hash: str) -> bool:
        try:
            return await self.send_command(
                {
                    "cmd": "UPDATE_HASH",
                    "file_id": int(file_id),
                    "file_path": str(file_path),
                    "expected_hash": str(expected_hash),
                }
            )
        except Exception as error:
            logger.error("send update hash failed: %s", error)
            return False

    @staticmethod
    async def _send_length_prefix(writer: asyncio.StreamWriter, payload: dict[str, Any]) -> None:
        try:
            body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
            if len(body) > 65535:
                raise ValueError("command payload too large")
            header = struct.pack(">I", len(body))
            writer.write(header + body)
        except (TypeError, ValueError) as error:
            logger.error("command length-prefix send failed: %s", error)
            raise
        except Exception as error:
            logger.error("unexpected command length-prefix send failure: %s", error)
            raise
