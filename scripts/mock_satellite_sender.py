"""Send pipeline case packets to ground-station TCP port 6000 (length-prefix JSON)."""

from __future__ import annotations

import argparse
import json
import logging
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ma_detector.core.packet_protocol import (
    BULK_HISTORY_TYPES,
    build_bulk_telemetry_packet,
    normalize_packet_type,
)

CASES_PATH = ROOT / "backend" / "test_data" / "pipeline_cases.json"

logger = logging.getLogger(__name__)


def _load_case(case_id: str) -> list[dict]:
    payload = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    case = payload.get("cases", {}).get(str(case_id))
    if not case:
        raise RuntimeError(f"case {case_id} not found in {CASES_PATH}")
    packets = case.get("packets", [])
    if not packets:
        raise RuntimeError(f"case {case_id} has no packets")
    return packets


def _combine_history_packets(packets: list[dict], sent_at: str | None = None) -> list[dict]:
    """Merge separate bulk history packets into one SAT_BULK_TELEMETRY uplink."""
    sections: dict[str, dict] = {}
    remaining: list[dict] = []
    for packet in packets:
        packet_type = normalize_packet_type(str(packet.get("packet_type", "")).strip())
        if packet_type in BULK_HISTORY_TYPES and isinstance(packet.get("records"), list):
            sections[packet_type] = {"records": packet["records"]}
            continue
        remaining.append(packet)

    if not sections:
        return packets

    combined = build_bulk_telemetry_packet(sections, sent_at=sent_at)
    return remaining + [combined]


def _send_packet(host: str, port: int, packet: dict, timeout_sec: float) -> dict:
    import socket

    body = json.dumps(packet, ensure_ascii=False, default=str).encode("utf-8")
    frame = struct.pack(">I", len(body)) + body
    with socket.create_connection((host, port), timeout=timeout_sec) as sock:
        sock.settimeout(timeout_sec)
        sock.sendall(frame)
        header = sock.recv(4)
        if len(header) != 4:
            raise RuntimeError("ACK header incomplete")
        ack_len = struct.unpack(">I", header)[0]
        ack_body = sock.recv(ack_len)
        if len(ack_body) != ack_len:
            raise RuntimeError("ACK body incomplete")
        return json.loads(ack_body.decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Mock satellite TCP sender for pipeline cases")
    parser.add_argument("--case", default="1", help="pipeline case id (1-4)")
    parser.add_argument("--host", default="127.0.0.1", help="ground-station TCP host")
    parser.add_argument("--port", type=int, default=6000, help="ground-station TCP port")
    parser.add_argument("--delay-sec", type=float, default=0.3, help="delay between packets")
    parser.add_argument("--timeout-sec", type=float, default=10.0, help="socket timeout")
    parser.add_argument(
        "--combined",
        action="store_true",
        help="send ADCS/TLM/PWR history as one SAT_BULK_TELEMETRY packet",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    packets = _load_case(args.case)
    if args.combined:
        packets = _combine_history_packets(packets)
    logger.info("Sending case %s (%d packets) to %s:%s", args.case, len(packets), args.host, args.port)

    for index, packet in enumerate(packets, start=1):
        packet_type = packet.get("packet_type", "UNKNOWN")
        ack = _send_packet(args.host, args.port, packet, args.timeout_sec)
        logger.info("[%d/%d] %s -> ACK %s", index, len(packets), packet_type, ack)
        if index < len(packets) and args.delay_sec > 0:
            time.sleep(args.delay_sec)

    logger.info("Case %s complete", args.case)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
