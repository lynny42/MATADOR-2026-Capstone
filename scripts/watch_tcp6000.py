#!/usr/bin/env python3
"""Watch TCP port 6000 for satellite uplink connections (Windows-friendly)."""

from __future__ import annotations

import argparse
import json
import logging
import socket
import struct
import sys
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _recv_exact(conn: socket.socket, nbytes: int) -> bytes | None:
    try:
        chunks: list[bytes] = []
        remaining = nbytes
        while remaining > 0:
            part = conn.recv(remaining)
            if not part:
                return None
            chunks.append(part)
            remaining -= len(part)
        return b"".join(chunks)
    except OSError as error:
        logger.error("recv failed: %s", error)
        return None


def _handle_once(conn: socket.socket, addr: tuple[str, int]) -> None:
    try:
        header = _recv_exact(conn, 4)
        if header is None or len(header) < 4:
            print(f"[{_utc_now()}] {addr[0]}:{addr[1]} — header incomplete")
            return
        (length,) = struct.unpack(">I", header)
        if length <= 0 or length > 2_000_000:
            print(f"[{_utc_now()}] {addr[0]}:{addr[1]} — bad length {length}")
            return
        body = _recv_exact(conn, length)
        if body is None:
            print(f"[{_utc_now()}] {addr[0]}:{addr[1]} — body incomplete ({length} bytes expected)")
            return
        packet = json.loads(body.decode("utf-8"))
        ptype = packet.get("packet_type", "?")
        extra = ""
        if ptype == "SAT_EVENT_QUEUE":
            ev = packet.get("event", {})
            extra = f" EVENT_ID={ev.get('EVENT_ID')} TYPE={ev.get('EVENT_TYPE')}"
        elif ptype == "SAT_EVENT_QUEUE_META":
            extra = f" total={packet.get('event_total')} ids={packet.get('event_ids')}"
        elif isinstance(packet.get("records"), list):
            extra = f" records={len(packet['records'])}"
        print(f"[{_utc_now()}] OK from {addr[0]}:{addr[1]}  type={ptype}{extra}  bytes={length}")
        ack = json.dumps({"ack": True, "cmd": "ACK"}, separators=(",", ":")).encode("utf-8")
        conn.sendall(struct.pack(">I", len(ack)) + ack)
        print(f"[{_utc_now()}]     -> ACK sent")
    except json.JSONDecodeError as error:
        print(f"[{_utc_now()}] {addr[0]}:{addr[1]} — JSON error: {error}")
    except Exception as error:
        print(f"[{_utc_now()}] {addr[0]}:{addr[1]} — error: {error}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Watch satellite TCP uplink on port 6000")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=6000)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((args.host, args.port))
        sock.listen(32)
    except OSError as error:
        print(f"bind failed {args.host}:{args.port} — {error}", file=sys.stderr)
        print("Port 6000 already in use (API server running). Use watch_tcp6000.ps1 instead.", file=sys.stderr)
        return 1

    print(f"=== TCP watch {args.host}:{args.port} ===")
    print(f"Started {_utc_now()} — waiting for satellite...")
    print("Press Ctrl+C to stop\n")

    try:
        while True:
            conn, addr = sock.accept()
            print(f"[{_utc_now()}] CONNECT {addr[0]}:{addr[1]}")
            _handle_once(conn, addr)
            try:
                conn.close()
            except OSError:
                pass
            print()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
