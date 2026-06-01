"""TCP telemetry receiver for satellite uplink on port 6000."""

from __future__ import annotations

import asyncio
import json
import logging
import struct
from typing import Any

from api.ingest_trace import record_ingest_event, record_raw_packet
from api.packet_buffer import PacketBufferManager
from api.websocket_manager import WebSocketManager
from ma_detector.core.packet_protocol import summarize_uplink_packet
from ma_detector.ma_integrated_detector import MAIntegratedDetector

logger = logging.getLogger(__name__)


class TCPTelemetryReceiver:
    """Listen on port 6000 for length-prefixed JSON telemetry packets."""

    def __init__(
        self,
        detector: MAIntegratedDetector,
        buffer: PacketBufferManager,
        ws_manager: WebSocketManager,
        host: str = "0.0.0.0",
        port: int = 6000,
        max_packet_size: int = 2097152,
    ) -> None:
        self._host = host
        self._port = int(port)
        self._detector = detector
        self._buffer = buffer
        self._ws_manager = ws_manager
        self._max_packet_size = int(max_packet_size)
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        """Start the TCP listener and run until stopped."""
        try:
            self._server = await asyncio.start_server(
                self._handle_client,
                self._host,
                self._port,
            )
            sockets = ", ".join(str(sock.getsockname()) for sock in self._server.sockets or [])
            logger.info("TCP telemetry server listening on %s", sockets)
            async with self._server:
                await self._server.serve_forever()
        except asyncio.CancelledError:
            logger.info("TCP telemetry server cancelled")
            raise
        except Exception as error:
            logger.error("TCP telemetry server failed: %s", error)
            raise

    async def stop(self) -> None:
        """Shut down the TCP listener."""
        try:
            if self._server is not None:
                self._server.close()
                await self._server.wait_closed()
                self._server = None
        except Exception as error:
            logger.error("TCP telemetry server stop failed: %s", error)

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        try:
            logger.info("위성 연결: %s", peer)
            _length, body = await self._recv_length_prefix(reader, self._max_packet_size)
            raw_text = body.decode("utf-8")
            try:
                packet = json.loads(raw_text)
            except json.JSONDecodeError as error:
                record_raw_packet(
                    None,
                    peer=str(peer),
                    byte_length=len(body),
                    parse_error=str(error),
                    raw_text=raw_text,
                )
                record_ingest_event(
                    "tcp_parse_error",
                    summary=str(error),
                    peer=str(peer),
                    extra={"byte_length": len(body)},
                )
                raise
            if not isinstance(packet, dict):
                record_raw_packet(
                    None,
                    peer=str(peer),
                    byte_length=len(body),
                    parse_error="packet must be a JSON object",
                    raw_text=raw_text,
                )
                raise ValueError("packet must be a JSON object")

            packet_type = str(packet.get("packet_type", "UNKNOWN"))
            summary = summarize_uplink_packet(packet)
            logger.info("패킷 수신: %s | %s | from %s", packet_type, summary, peer)

            status = await self._ingest_packet(
                packet,
                peer=str(peer),
                summary=summary,
                byte_length=len(body),
            )
            await self._send_length_prefix(writer, {"ack": True, "cmd": "ACK"})
            logger.info("ACK 전송 완료: %s -> %s", packet_type, status.get("status"))
            await writer.drain()

            await self._ws_manager.broadcast(
                {
                    "type": "TCP_PACKET_ACKED",
                    "packet_type": packet_type,
                    "status": status,
                    "peer": str(peer),
                }
            )
        except asyncio.IncompleteReadError as error:
            logger.error("수신 오류: incomplete read from %s: %s", peer, error)
        except json.JSONDecodeError as error:
            logger.error("수신 오류: JSON parse failed from %s: %s", peer, error)
        except ValueError as error:
            logger.error("수신 오류: invalid packet from %s: %s", peer, error)
        except Exception as error:
            logger.error("수신 오류: %s", error)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as error:
                logger.error("TCP client close failed: %s", error)

    async def _ingest_packet(
        self,
        packet: dict[str, Any],
        *,
        peer: str = "",
        summary: str = "",
        byte_length: int = 0,
    ) -> dict[str, Any]:
        try:
            status = await self._buffer.add_packet(packet)
            comm_session = status.get("comm_session")
            record_raw_packet(
                packet,
                peer=peer or None,
                comm_session=str(comm_session) if comm_session else None,
                byte_length=byte_length,
                status=status,
            )
            record_ingest_event(
                "tcp_received",
                packet_type=str(packet.get("packet_type", "")),
                summary=summary,
                status=status,
                peer=peer or None,
                buffer_key=status.get("buffer_key"),
                comm_session=comm_session,
            )
            await self._ws_manager.broadcast(
                {
                    "type": "TELEMETRY_RECEIVED",
                    "packet_type": packet.get("packet_type"),
                    "summary": summary,
                    "status": status,
                    "peer": peer,
                    "packet": packet,
                }
            )
            return status
        except Exception as error:
            logger.error("TCP packet ingest failed: %s", error)
            return {"status": "error", "message": str(error)}

    @staticmethod
    async def _recv_length_prefix(
        reader: asyncio.StreamReader,
        max_packet_size: int,
    ) -> tuple[int, bytes]:
        try:
            header = await reader.readexactly(4)
            length = struct.unpack(">I", header)[0]
            if length <= 0:
                raise ValueError("packet length must be positive")
            if length > max_packet_size:
                raise ValueError(f"packet length {length} exceeds max {max_packet_size}")
            body = await reader.readexactly(length)
            return length, body
        except asyncio.IncompleteReadError as error:
            logger.error("length-prefix receive failed: %s", error)
            raise
        except struct.error as error:
            logger.error("length-prefix header parse failed: %s", error)
            raise ValueError("invalid length header") from error
        except Exception as error:
            logger.error("unexpected length-prefix receive failure: %s", error)
            raise

    @staticmethod
    async def _send_length_prefix(writer: asyncio.StreamWriter, payload: dict[str, Any]) -> None:
        try:
            body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
            header = struct.pack(">I", len(body))
            writer.write(header + body)
        except (TypeError, ValueError) as error:
            logger.error("length-prefix send failed: %s", error)
            raise
        except Exception as error:
            logger.error("unexpected length-prefix send failure: %s", error)
            raise
