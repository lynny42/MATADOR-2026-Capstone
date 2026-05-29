#!/usr/bin/env python3
"""
지상국(GS) TCP 테스트 서버 — 위성 텔레메트리 수신·ACK + 위성 커맨드 송신.

역할:
  - :6000 listen — 위성 demon 이 텔레메트리를내면 출력 후 ACK
  - 위성 :6001 로 커맨드 — ATTACK_SIM / ATTACK_HASH / RECOVERY

네트워크:
  - GS (이 PC): 192.168.0.12 — :6000 수신, 위성 :6001 로 커맨드
  - 위성 demon: config GS_HOST=192.168.0.12, GS_PORT=6000
  - 추후 위성 IP: 192.168.0.7 → --sat-host 192.168.0.7

실행:
    python3 -m demon.tools.gs_test_server
    python3 -m demon.tools.gs_test_server --sat-host 192.168.0.7
    python3 -m demon.tools.gs_test_server --send ATTACK_SIM
    python3 -m demon.tools.gs_test_server --send RECOVERY

대화형 (서버 실행 중 stdin):
    attack / a       → ATTACK_SIM (모터·전력·ADCS 논리)
    attack_hash / ah → ATTACK_HASH (전력 이상 + cf 파일 → hash 검사)
    recovery 또는  r  → RECOVERY
"""
from __future__ import annotations

import argparse
import json
import logging
import socket
import struct
import sys
import threading
from datetime import datetime, timezone
from typing import Any

from .. import config as demon_config

logger = logging.getLogger(__name__)

_MAX_PACKET_BYTES = 2_000_000
_ACK_PAYLOAD = {"ack": True, "cmd": "ACK"}

_PACKET_EVENT = "SAT_EVENT_QUEUE"
_PACKET_TLM_HISTORY = "SAT_TLM_HISTORY"
_PACKET_PWR_HISTORY = "SAT_PWR_HISTORY"
_PACKET_ADCS_FILTER = "SAT_ADCS_FILTER"
_PACKET_INTEGRITY = "SAT_INTEGRITY_HASH"

_CMD_ATTACK = demon_config.GS_CMD_ATTACK_SIM
_CMD_ATTACK_HASH = demon_config.GS_CMD_ATTACK_HASH
_CMD_RECOVERY = demon_config.GS_CMD_RECOVERY


def recv_packet(conn: socket.socket) -> dict[str, Any] | None:
    try:
        header = _recv_exact(conn, 4)
        if header is None or len(header) < 4:
            return None
        (length,) = struct.unpack(">I", header)
        if length <= 0 or length > _MAX_PACKET_BYTES:
            logger.error("비정상 패킷 길이: %s", length)
            return None
        body = _recv_exact(conn, length)
        if body is None:
            return None
        parsed = json.loads(body.decode("utf-8"))
        if not isinstance(parsed, dict):
            logger.error("JSON 루트가 dict 가 아님")
            return None
        return parsed
    except json.JSONDecodeError as e:
        logger.error("JSON 파싱 실패: %s", e)
        return None
    except UnicodeError as e:
        logger.error("UTF-8 디코딩 실패: %s", e)
        return None
    except Exception as e:
        logger.error("recv_packet 실패: %s", e)
        return None


def send_packet(conn: socket.socket, payload: dict[str, Any]) -> bool:
    try:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        conn.sendall(struct.pack(">I", len(body)) + body)
        return True
    except OSError as e:
        logger.error("send_packet 실패(OSError): %s", e)
        return False
    except Exception as e:
        logger.error("send_packet 실패: %s", e)
        return False


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
    except OSError as e:
        logger.error("_recv_exact 실패: %s", e)
        return None
    except Exception as e:
        logger.error("_recv_exact 실패: %s", e)
        return None


def send_satellite_command(
    cmd_name: str,
    sat_host: str,
    sat_port: int,
    extra: dict[str, Any] | None = None,
) -> bool:
    """지상국 → 위성 GScomms 커맨드 포트로 [4B][JSON] 전송."""
    try:
        payload: dict[str, Any] = {"cmd": cmd_name}
        if extra:
            payload.update(extra)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((sat_host, sat_port))
        ok = send_packet(sock, payload)
        sock.close()
        if ok:
            print(f"[GS→위성] {cmd_name} 전송 완료 → {sat_host}:{sat_port}")
            if cmd_name == _CMD_ATTACK:
                print("  → 모터·전력·ADCS 논리 (ATTACK_SIM)")
            elif cmd_name == _CMD_ATTACK_HASH:
                print("  → [1]모터·바이어스 [2]cf파일 [3]전력이상→hash검사 (10~15초 후 dark→light)")
            logger.info("위성 커맨드 전송 cmd=%s target=%s:%s", cmd_name, sat_host, sat_port)
        else:
            print(f"[GS→위성] {cmd_name} 전송 실패")
        return ok
    except OSError as e:
        logger.error("위성 연결 실패 %s:%s — %s", sat_host, sat_port, e)
        print(f"[GS→위성] 연결 실패 {sat_host}:{sat_port} — {e}")
        return False
    except Exception as e:
        logger.error("send_satellite_command 실패: %s", e)
        return False


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _safe_records(pkt: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        raw = pkt.get("records")
        if not isinstance(raw, list):
            return []
        out: list[dict[str, Any]] = []
        for item in raw:
            if isinstance(item, dict):
                out.append(item)
        return out
    except Exception as e:
        logger.error("_safe_records 실패: %s", e)
        return []


def _print_event(ev: dict[str, Any]) -> None:
    print("  [이벤트]")
    print(f"    EVENT_ID      = {ev.get('EVENT_ID')}")
    print(f"    EVENT_TYPE    = {ev.get('EVENT_TYPE')}")
    print(f"    PRIORITY      = {ev.get('PRIORITY')}")
    print(f"    DETECTED_AT   = {ev.get('DETECTED_AT')}")
    print(f"    SW_ID         = {ev.get('SW_ID')}")
    print(f"    WEIGHT        = {ev.get('WEIGHT')}")
    print(f"    CHENNEL1      = {ev.get('CHENNEL1')}")
    print(f"    EXCEPTION_CODE= {ev.get('EXCEPTION_CODE')}")
    scores = ev.get("MODULE_SCORES")
    if scores:
        print(f"    MODULE_SCORES = {scores}")


def _print_tlm_record(rec: dict[str, Any], idx: int) -> None:
    print(
        f"    [{idx}] HISTORY_ID={rec.get('HISTORY_ID')} "
        f"MODE={rec.get('MISSION_MODE')} ADCS_MODE={rec.get('ADCS_MODE')} "
        f"SUN_VALID={rec.get('SUN_VALID')} @ {rec.get('UPDATED_AT')}"
    )


def _print_pwr_snapshot(snap: dict[str, Any], idx: int) -> None:
    """SAT_PWR_HISTORY 1스냅샷 = HISTORY_ID + channels[4] (db_manager.get_pwr_history 형식)."""
    try:
        hid = snap.get("HISTORY_ID")
        updated = snap.get("UPDATED_AT")
        channels = snap.get("channels")
        if isinstance(channels, list) and channels:
            print(f"    [{idx}] HISTORY_ID={hid} @ {updated}")
            for ch in channels:
                if not isinstance(ch, dict):
                    continue
                print(
                    f"        SW_{ch.get('SW_ID')} "
                    f"V={ch.get('VOLTAGE')} A={ch.get('CURRENT_A')} "
                    f"ANOMALY={ch.get('ANOMALY_FLAG')} "
                    f"EXCEED={ch.get('EXCEED_COUNT')}"
                )
            return
        # 구형 flat 행 (채널 테이블 직렬화) 호환
        print(
            f"    [{idx}] HISTORY_ID={hid} SW_ID={snap.get('SW_ID')} "
            f"V={snap.get('VOLTAGE')} A={snap.get('CURRENT_A')} "
            f"ANOMALY={snap.get('ANOMALY_FLAG')} @ {updated}"
        )
    except Exception as e:
        logger.error("_print_pwr_snapshot 실패: %s", e)


def _print_adcs_record(rec: dict[str, Any], idx: int) -> None:
    print(
        f"    [{idx}] CHENNEL1={rec.get('CHENNEL1')} "
        f"QBN_0={rec.get('QBN_0')} ST_VALID={rec.get('ST_VALID')} "
        f"@ {rec.get('TIMESTAMP')}"
    )


def _print_integrity_record(rec: dict[str, Any], idx: int) -> None:
    print(
        f"    [{idx}] FILE_ID={rec.get('FILE_ID')} PATH={rec.get('FILE_PATH')} "
        f"VIOLATED={rec.get('IS_VIOLATED')}"
    )


def print_packet_summary(pkt: dict[str, Any], addr: tuple, verbose: bool) -> None:
    try:
        ptype = str(pkt.get("packet_type", "?"))
        sep = "-" * 60
        print(sep)
        print(f"[{_utc_now()}] from {addr[0]}:{addr[1]}  packet_type={ptype}")

        if ptype == _PACKET_EVENT:
            ev = pkt.get("event")
            if isinstance(ev, dict):
                _print_event(ev)
            else:
                print("  (event 필드 없음)")

        elif ptype == _PACKET_TLM_HISTORY:
            records = _safe_records(pkt)
            print(f"  [TLM history] {len(records)}건")
            for i, rec in enumerate(records[:10]):
                _print_tlm_record(rec, i)
            if len(records) > 10:
                print(f"    ... 외 {len(records) - 10}건")

        elif ptype == _PACKET_PWR_HISTORY:
            records = _safe_records(pkt)
            print(f"  [PWR history] 스냅샷 {len(records)}건 (1건=4채널)")
            show_max = 5
            for i, rec in enumerate(records[:show_max]):
                _print_pwr_snapshot(rec, i)
            if len(records) > show_max:
                print(f"    ... 외 {len(records) - show_max} 스냅샷")

        elif ptype == _PACKET_ADCS_FILTER:
            records = _safe_records(pkt)
            print(f"  [ADCS filter 누적] {len(records)}행")
            for i, rec in enumerate(records[:8]):
                _print_adcs_record(rec, i)
            if len(records) > 8:
                print(f"    ... 외 {len(records) - 8}행")

        elif ptype == _PACKET_INTEGRITY:
            records = _safe_records(pkt)
            if not records and isinstance(pkt.get("records"), dict):
                records = [pkt["records"]]
            print(f"  [무결성 해시] {len(records)}건")
            for i, rec in enumerate(records[:5]):
                _print_integrity_record(rec, i)

        else:
            print(f"  keys={list(pkt.keys())}")

        if verbose:
            print("  --- raw JSON ---")
            print(json.dumps(pkt, indent=2, ensure_ascii=False, default=str))
        print(sep)
    except Exception as e:
        logger.error("print_packet_summary 실패: %s", e)


def handle_client(conn: socket.socket, addr: tuple, verbose: bool, stats: dict[str, int]) -> None:
    try:
        header = _recv_exact(conn, 4)
        if header is None or len(header) < 4:
            logger.warning("헤더 수신 실패 from %s:%s", addr[0], addr[1])
            return
        (length,) = struct.unpack(">I", header)
        if length <= 0 or length > _MAX_PACKET_BYTES:
            logger.error("비정상 패킷 길이 %s from %s:%s", length, addr[0], addr[1])
            return
        body = _recv_exact(conn, length)
        if body is None:
            logger.error("본문 수신 실패 len=%s from %s:%s", length, addr[0], addr[1])
            return
        logger.info("패킷 수신 %s bytes from %s:%s", length, addr[0], addr[1])
        try:
            pkt = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as e:
            logger.error("JSON 파싱 실패 len=%s: %s", length, e)
            return
        if not isinstance(pkt, dict):
            logger.error("JSON 루트가 dict 가 아님")
            return

        ptype = str(pkt.get("packet_type", "UNKNOWN"))
        stats["total"] = stats.get("total", 0) + 1
        stats[ptype] = stats.get(ptype, 0) + 1

        print_packet_summary(pkt, addr, verbose)

        if not send_packet(conn, _ACK_PAYLOAD):
            logger.error("ACK 전송 실패 → %s:%s", addr[0], addr[1])
            return
        print("  → ACK 전송 완료 (ack=true, cmd=ACK)\n")
    except Exception as e:
        logger.error("handle_client 실패: %s", e)
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            conn.close()
        except OSError as e:
            logger.error("conn close 실패: %s", e)


def _stdin_command_loop(
    sat_host: str,
    sat_port: int,
    stop_event: threading.Event,
) -> None:
    """대화형: attack / recovery 입력 시 위성에 커맨드 전송."""
    aliases = {
        "a": _CMD_ATTACK,
        "attack": _CMD_ATTACK,
        "ah": _CMD_ATTACK_HASH,
        "attack_hash": _CMD_ATTACK_HASH,
        "hash": _CMD_ATTACK_HASH,
        "r": _CMD_RECOVERY,
        "recovery": _CMD_RECOVERY,
    }
    print("\n[커맨드] attack(a) | attack_hash(ah/hash) | recovery(r) | quit(q)")
    while not stop_event.is_set():
        try:
            line = sys.stdin.readline()
            if not line:
                break
            token = line.strip().lower()
            if not token:
                continue
            if token in ("q", "quit", "exit"):
                stop_event.set()
                break
            cmd = aliases.get(token)
            if cmd is None:
                print(
                    f"  알 수 없는 입력: {line.strip()} "
                    "(attack / attack_hash / recovery)",
                )
                continue
            send_satellite_command(cmd, sat_host, sat_port)
        except Exception as e:
            logger.error("_stdin_command_loop 실패: %s", e)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="MATADOR 지상국 테스트 서버 (텔레메트리 수신 + 위성 커맨드 송신)",
    )
    parser.add_argument("--host", default="0.0.0.0", help="텔레메트리 listen 주소")
    parser.add_argument("--port", type=int, default=demon_config.GS_PORT, help="텔레메트리 listen 포트")
    parser.add_argument(
        "--sat-host",
        default=demon_config.GS_CMD_SAT_HOST,
        help="위성 demon 커맨드 목적 IP (추후 192.168.0.7)",
    )
    parser.add_argument(
        "--sat-port",
        type=int,
        default=demon_config.GS_CMD_SAT_PORT,
        help="위성 demon 커맨드 포트 (기본 6001)",
    )
    parser.add_argument(
        "--send",
        choices=[_CMD_ATTACK, _CMD_ATTACK_HASH, _CMD_RECOVERY],
        help="시작 시 위성에 커맨드 1회 전송 후 서버 대기",
    )
    parser.add_argument(
        "--no-interactive",
        action="store_true",
        help="stdin 커맨드 입력 비활성화",
    )
    parser.add_argument("--verbose", action="store_true", help="패킷 전체 JSON 출력")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if args.send:
        send_satellite_command(args.send, args.sat_host, args.sat_port)

    stats: dict[str, int] = {"total": 0}
    stop_event = threading.Event()

    if not args.no_interactive and sys.stdin.isatty():
        threading.Thread(
            target=_stdin_command_loop,
            args=(args.sat_host, args.sat_port, stop_event),
            name="GS-stdin-cmd",
            daemon=True,
        ).start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((args.host, args.port))
        sock.listen(16)
    except OSError as e:
        logger.error("bind 실패 %s:%s — %s", args.host, args.port, e)
        return 1

    print("=" * 60)
    print("MATADOR 지상국 테스트 서버")
    print(f"  텔레메트리 수신 : {args.host}:{args.port}")
    print(f"  위성 커맨드 송신 : {args.sat_host}:{args.sat_port}")
    print(f"  일반 공격       : {_CMD_ATTACK} (attack / a)")
    print(f"  hash 공격       : {_CMD_ATTACK_HASH} (ah — 전력+파일, attack와 별도)")
    print("  텔레메트리 수신 : 위성 조도 dark→light 후 bulk 송신")
    print("  Ctrl+C 종료")
    print("=" * 60)

    sock.settimeout(1.0)
    try:
        while not stop_event.is_set():
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError as e:
                if stop_event.is_set():
                    break
                logger.error("accept 실패: %s", e)
                continue
            logger.info("연결 수락 %s:%s", addr[0], addr[1])
            handle_client(conn, addr, args.verbose, stats)
    except KeyboardInterrupt:
        stop_event.set()
        print("\n종료 — 수신 통계:")
        for key, count in sorted(stats.items()):
            print(f"  {key}: {count}")
    finally:
        stop_event.set()
        try:
            sock.close()
        except OSError as e:
            logger.error("sock close 실패: %s", e)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
