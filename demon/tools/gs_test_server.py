#!/usr/bin/env python3
"""
지상국(GS) TCP 테스트 서버 — 위성 텔레메트리 수신·ACK + 위성 커맨드 송신.

역할:
  - :6000 listen — 위성 demon 이 텔레메트리를내면 출력 후 ACK
  - 위성 :6001 로 커맨드 — ATTACK_SIM / ATTACK_HASH / SEU_SIM / RECOVERY

네트워크:
  - GS (이 PC): 192.168.0.12 — :6000 수신, 위성 :6001 로 커맨드
  - 위성 demon: config GS_HOST=192.168.0.12, GS_PORT=6000
  - 추후 위성 IP: 192.168.0.7 → --sat-host 192.168.0.7

실행:
    python3 -m demon.tools.gs_test_server
    python3 -m demon.tools.gs_test_server --sat-host 192.168.0.7
    python3 -m demon.tools.gs_test_server --send ATTACK_SIM
    python3 -m demon.tools.gs_test_server --send SEU_SIM
    python3 -m demon.tools.gs_test_server --send RECOVERY
    python3 -m demon.tools.gs_test_server --scenario false_positive

대화형 (서버 실행 중 stdin):
    attack / a        → ATTACK_SIM (gyro/servo 실부하 + ADCS 논리 → FPF Y)
    attack_hash / ah  → ATTACK_HASH (실부하 + cf 파일 → hash 검사)
    seu / s / fpf     → SEU_SIM (gyro/servo 실부하만 → FPF N / SEU_DETECTED)
    recovery / r      → RECOVERY (AttackSimulator + FpfSimulator 해제)

오탐 시연 권장 순서: attack → (bulk 확인) → recovery → seu → (bulk 확인)
"""
from __future__ import annotations

import argparse
import json
import logging
import socket
import struct
import sys
import threading
import time
from typing import Any

from .. import config as demon_config
from ..workers.gs_comms import format_fpf_gs_event

logger = logging.getLogger(__name__)

_MAX_PACKET_BYTES = 2_000_000
_ACK_PAYLOAD = {"ack": True, "cmd": "ACK"}

_PACKET_EVENT = demon_config.GS_PACKET_TYPE_EVENT
_PACKET_EVENT_META = demon_config.GS_PACKET_TYPE_EVENT_META
_PACKET_TLM_HISTORY = demon_config.GS_PACKET_TYPE_TLM_HISTORY
_PACKET_PWR_HISTORY = demon_config.GS_PACKET_TYPE_PWR_HISTORY
_PACKET_SNAPSHOT = demon_config.GS_PACKET_TYPE_SNAPSHOT
_PACKET_ADCS_FILTER = demon_config.GS_PACKET_TYPE_ADCS_FILTER
_PACKET_INTEGRITY = demon_config.GS_PACKET_TYPE_INTEGRITY
_PACKET_BULK = demon_config.GS_PACKET_TYPE_BULK

_CMD_ATTACK = demon_config.GS_CMD_ATTACK_SIM
_CMD_ATTACK_HASH = demon_config.GS_CMD_ATTACK_HASH
_CMD_SEU_SIM = demon_config.GS_CMD_SEU_SIM
_CMD_RECOVERY = demon_config.GS_CMD_RECOVERY
_GS_CMD_CHOICES = (_CMD_ATTACK, _CMD_ATTACK_HASH, _CMD_SEU_SIM, _CMD_RECOVERY)

_FPF_EVENT_TYPES = frozenset(
    {
        demon_config.GS_EVENT_ATTACK_CONFIRMED,
        demon_config.GS_EVENT_SEU_DETECTED,
    },
)



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
                print("  → ATTACK_SIM: gyro/servo 실부하 + ADCS/TLM 논리 (FPF Y 기대)")
            elif cmd_name == _CMD_ATTACK_HASH:
                print("  → ATTACK_HASH: 실부하 + cf 파일 → 전력 이상 시 hash 검사")
            elif cmd_name == _CMD_SEU_SIM:
                print("  → SEU_SIM: gyro/servo 실부하만 (FPF N / SEU_DETECTED 기대)")
            elif cmd_name == _CMD_RECOVERY:
                print("  → RECOVERY: 물리·hash·FPF SEU 모드 해제")
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
    from ..core.time_utils import now

    return now().strftime("%Y-%m-%d %H:%M:%S KST")


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
    try:
        event_type = str(ev.get("EVENT_TYPE", ""))
        if event_type in _FPF_EVENT_TYPES:
            print(format_fpf_gs_event(ev).strip())
            return
        print("  [이벤트]")
        print(f"    EVENT_ID      = {ev.get('EVENT_ID')}")
        print(f"    EVENT_TYPE    = {event_type}")
        print(f"    PRIORITY      = {ev.get('PRIORITY')}")
        print(f"    DETECTED_AT   = {ev.get('DETECTED_AT')}")
        print(f"    SW_ID_LIST    = {ev.get('SW_ID_LIST', ev.get('SW_ID'))}")
        print(f"    WEIGHT        = {ev.get('WEIGHT')}")
        print(f"    CHENNEL1      = {ev.get('CHENNEL1')}")
        print(f"    EXCEPTION_CODE= {ev.get('EXCEPTION_CODE')}")
        scores = ev.get("MODULE_SCORES")
        if scores:
            print(f"    MODULE_SCORES = {scores}")
    except Exception as e:
        logger.error("_print_event 실패: %s", e)


def _print_tlm_record(rec: dict[str, Any], idx: int) -> None:
    print(
        f"    [{idx}] SNAPSHOT_ID={rec.get('SNAPSHOT_ID')} "
        f"HISTORY_ID={rec.get('HISTORY_ID')} "
        f"MODE={rec.get('MISSION_MODE')} ADCS_MODE={rec.get('ADCS_MODE')} "
        f"SUN_VALID={rec.get('SUN_VALID')} @ {rec.get('UPDATED_AT')}"
    )


def _print_pwr_snapshot(snap: dict[str, Any], idx: int) -> None:
    """SAT_PWR_HISTORY 1스냅샷 = HISTORY_ID + channels[4] (db_manager.get_pwr_history 형식)."""
    try:
        hid = snap.get("HISTORY_ID")
        sid = snap.get("SNAPSHOT_ID")
        updated = snap.get("UPDATED_AT")
        channels = snap.get("channels")
        if isinstance(channels, list) and channels:
            print(f"    [{idx}] SNAPSHOT_ID={sid} HISTORY_ID={hid} @ {updated}")
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
        f"    [{idx}] SNAPSHOT_ID={rec.get('SNAPSHOT_ID')} "
        f"CHENNEL1={rec.get('CHENNEL1')} "
        f"QBN_0={rec.get('QBN_0')} ST_VALID={rec.get('ST_VALID')} "
        f"@ {rec.get('TIMESTAMP')}"
    )


def _print_integrity_record(rec: dict[str, Any], idx: int) -> None:
    print(
        f"    [{idx}] FILE_ID={rec.get('FILE_ID')} PATH={rec.get('FILE_PATH')} "
        f"VIOLATED={rec.get('IS_VIOLATED')}"
    )


def _print_bulk_section(key: str, section: Any, verbose: bool) -> None:
    """SAT_BULK_TELEMETRY 내부 섹션 출력."""
    try:
        if key == _PACKET_EVENT and isinstance(section, dict):
            print(
                f"  [EVENT] total={section.get('event_total')} "
                f"ids={section.get('event_ids')}"
            )
            events = section.get("events")
            if isinstance(events, list):
                for ev in events[:5]:
                    if isinstance(ev, dict):
                        _print_event(ev)
                if len(events) > 5:
                    print(f"    ... 외 {len(events) - 5}건")
            return

        if key == _PACKET_INTEGRITY and isinstance(section, dict):
            records = _safe_records(section)
            print(f"  [무결성 해시] {len(records)}건")
            for i, rec in enumerate(records[:5]):
                _print_integrity_record(rec, i)
            return

        if key == _PACKET_SNAPSHOT and isinstance(section, dict):
            records = _safe_records(section)
            print(f"  [통합 SNAPSHOT] {len(records)}건")
            for i, rec in enumerate(records[:10]):
                print(
                    f"    [{i}] SNAPSHOT_ID={rec.get('SNAPSHOT_ID')} "
                    f"@ {rec.get('SNAPSHOT_AT')}"
                )
            return

        if key == _PACKET_ADCS_FILTER and isinstance(section, dict):
            records = _safe_records(section)

            print(f"  [ADCS filter 누적] {len(records)}행")
            for i, rec in enumerate(records[:8]):
                _print_adcs_record(rec, i)
            if len(records) > 8:
                print(f"    ... 외 {len(records) - 8}행")
            return

        if key == _PACKET_TLM_HISTORY and isinstance(section, dict):
            records = _safe_records(section)
            print(f"  [TLM history] {len(records)}건")
            for i, rec in enumerate(records[:10]):
                _print_tlm_record(rec, i)
            if len(records) > 10:
                print(f"    ... 외 {len(records) - 10}건")
            return

        if key == _PACKET_PWR_HISTORY and isinstance(section, dict):
            records = _safe_records(section)
            print(f"  [PWR history] 스냅샷 {len(records)}건 (1건=4채널)")
            for i, rec in enumerate(records[:5]):
                _print_pwr_snapshot(rec, i)
            if len(records) > 5:
                print(f"    ... 외 {len(records) - 5} 스냅샷")
            return

        if verbose:
            print(f"  [{key}] {section}")
    except Exception as e:
        logger.error("_print_bulk_section 실패 key=%s: %s", key, e)


def print_packet_summary(pkt: dict[str, Any], addr: tuple, verbose: bool) -> None:
    try:
        ptype = str(pkt.get("packet_type", "?"))
        sep = "-" * 60
        print(sep)
        print(f"[{_utc_now()}] from {addr[0]}:{addr[1]}  packet_type={ptype}")

        if ptype == _PACKET_BULK:
            print(f"  sent_at={pkt.get('sent_at')}")
            for sec_key in (
                _PACKET_EVENT,
                _PACKET_INTEGRITY,
                _PACKET_SNAPSHOT,
                _PACKET_ADCS_FILTER,
                _PACKET_TLM_HISTORY,
                _PACKET_PWR_HISTORY,
            ):
                if sec_key in pkt:
                    _print_bulk_section(sec_key, pkt.get(sec_key), verbose)

        elif ptype == _PACKET_EVENT:
            ev = pkt.get("event")
            if isinstance(ev, dict):
                _print_event(ev)
            else:
                print("  (event 필드 없음)")

        elif ptype == _PACKET_EVENT_META:
            print(
                f"  [EVENT META] total={pkt.get('event_total')} "
                f"ids={pkt.get('event_ids')}"
            )

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
        "s": _CMD_SEU_SIM,
        "seu": _CMD_SEU_SIM,
        "seu_sim": _CMD_SEU_SIM,
        "fpf": _CMD_SEU_SIM,
        "fpf_seu": _CMD_SEU_SIM,
        "r": _CMD_RECOVERY,
        "recovery": _CMD_RECOVERY,
    }
    print(
        "\n[커맨드] attack(a) | attack_hash(ah/hash) | seu(s/fpf) | recovery(r) | quit(q)",
    )
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
                    "(attack / attack_hash / seu / recovery)",
                )
                continue
            send_satellite_command(cmd, sat_host, sat_port)
        except Exception as e:
            logger.error("_stdin_command_loop 실패: %s", e)


def _run_false_positive_scenario(sat_host: str, sat_port: int, step_delay_sec: float) -> bool:
    """오탐 시연: ATTACK_SIM → RECOVERY → SEU_SIM (각 단계 사이 대기)."""
    try:
        steps = [
            (_CMD_ATTACK, "ATTACK_SIM (FPF Y 기대)"),
            (_CMD_RECOVERY, "RECOVERY"),
            (_CMD_SEU_SIM, "SEU_SIM (FPF N 기대)"),
        ]
        delay = max(0.0, float(step_delay_sec))
        print("\n[시나리오] false_positive — 3단계 커맨드 전송")
        for idx, (cmd, label) in enumerate(steps, start=1):
            print(f"\n  [{idx}/{len(steps)}] {label}")
            if not send_satellite_command(cmd, sat_host, sat_port):
                return False
            if idx < len(steps) and delay > 0:
                print(f"  … {delay:.0f}s 대기")
                time.sleep(delay)
        print("\n  → 각 단계 후 조도 dark→light 로 bulk 수신 대기")
        return True
    except Exception as e:
        logger.error("_run_false_positive_scenario 실패: %s", e)
        return False


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
        choices=list(_GS_CMD_CHOICES),
        help="시작 시 위성에 커맨드 1회 전송 후 서버 대기",
    )
    parser.add_argument(
        "--scenario",
        choices=("false_positive",),
        help="연속 시나리오 커맨드 전송 (false_positive: attack→recovery→seu)",
    )
    parser.add_argument(
        "--scenario-delay",
        type=float,
        default=5.0,
        help="--scenario 단계 간 대기(초), 기본 5",
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

    if args.scenario == "false_positive":
        if not _run_false_positive_scenario(
            args.sat_host,
            args.sat_port,
            args.scenario_delay,
        ):
            return 1
    elif args.send:
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
    print(f"  1) 공격 시뮬     : {_CMD_ATTACK} (attack / a)")
    print(f"  2) hash 공격     : {_CMD_ATTACK_HASH} (attack_hash / ah / hash)")
    print(f"  3) 오탐(SEU) 시뮬: {_CMD_SEU_SIM} (seu / s / fpf)")
    print(f"  4) 복구          : {_CMD_RECOVERY} (recovery / r)")
    print("  bulk 수신       : 위성 조도 dark→light 엣지 후 SAT_BULK_TELEMETRY")
    print("  FPF 이벤트      : ATTACK_CONFIRMED(Y) / SEU_DETECTED(N) 요약 출력")
    if args.scenario != "false_positive":
        print("  시나리오        : --scenario false_positive (attack→recovery→seu)")
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
