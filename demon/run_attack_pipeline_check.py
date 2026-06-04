#!/usr/bin/env python3
"""
공격 시뮬 → 전력 이상 → 다음 단계(오탐필터/이벤트) 확인.

    (4종 시나리오 통합) python3 -m demon.run_pipeline_scenario attack

    python3 -m demon.run_attack_pipeline_check
    python3 -m demon.run_attack_pipeline_check --no-hardware   # DB만 모의
    python3 -m demon.run_attack_pipeline_check -v              # tick·로그 상세
    python3 -m demon.run_attack_pipeline_check --no-color
"""
from __future__ import annotations

import argparse
import logging
import sqlite3
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from demon import config as demon_config
from demon.core.context import DaemonConfig, RuntimeContext
from demon.db.db_manager import DBManager
from demon.workers.anomaly_detector import AnomalyDetector
from demon.workers.attack_simulator import AttackSimulator
from demon.workers.false_positive_filter import (
    FalsePositiveFilter,
    PhysicalConsistencyModule,
    StatisticalConsistencyModule,
    SystemResponseModule,
)
from demon.workers.gs_comms import GScomms
from demon.workers.serial_reader import SerialReader

logger = logging.getLogger(__name__)

_EXC_LABEL = {
    0: "정상",
    1: "사원수",
    2: "토크",
    3: "휠",
    4: "다채널",
    5: "누락",
    6: "모드",
    7: "경로",
}


class _Term:
    """터미널 ANSI (미지원 시 plain)."""

    def __init__(self, use_color: bool):
        self._on = use_color
        self.RESET = "\033[0m" if use_color else ""
        self.BOLD = "\033[1m" if use_color else ""
        self.DIM = "\033[2m" if use_color else ""
        self.GREEN = "\033[92m" if use_color else ""
        self.RED = "\033[91m" if use_color else ""
        self.CYAN = "\033[96m" if use_color else ""
        self.YELLOW = "\033[93m" if use_color else ""

    def wrap(self, text: str, *codes: str) -> str:
        if not self._on:
            return text
        return "".join(codes) + text + self.RESET


def _enable_ansi() -> bool:
    if sys.platform != "win32":
        return True
    try:
        import ctypes

        h = ctypes.windll.kernel32.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        if not ctypes.windll.kernel32.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        return bool(ctypes.windll.kernel32.SetConsoleMode(h, mode.value | 7))
    except Exception:
        return False


def _fix_stdout_encoding() -> None:
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _pwr_rows(db: DBManager) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        for row in db.get_pwr_meta_all():
            if int(row["SW_ID"]) > 2:
                continue
            rows.append(row)
    except Exception:
        return []
    return rows


def _anomaly_sw_list(anomaly: dict | None) -> list[int] | None:
    if not anomaly:
        return None
    raw = anomaly.get("sw_id_list")
    if not isinstance(raw, list):
        return None
    return [int(x) for x in raw]


def _print_pwr_table(c: _Term, rows: list[dict[str, Any]], *, indent: int = 2) -> None:
    pad = " " * indent
    if not rows:
        print(f"{pad}(전력 데이터 없음)")
        return
    consec_thresh = int(demon_config.CONSECUTIVE_THRESHOLD)
    print(f"{pad}{'SW':>2}  {'V':>7}  {'CON':>4}  {'ANOM':>4}")
    for row in rows:
        sw = int(row["SW_ID"])
        v = float(row["VOLTAGE"])
        consec = int(row.get("CONSECUTIVE_EXCEED", 0))
        con_str = f"{consec}/{consec_thresh}"
        anom = int(row["ANOMALY_FLAG"])
        line = f"{pad}{sw:>2}  {v:7.3f}  {con_str:>4}  {anom:>4}"
        if anom:
            line = c.wrap(line, c.YELLOW)
        print(line)


def _print_section(c: _Term, num: int, title: str) -> None:
    print(c.wrap(f"[{num}] {title}", c.BOLD, c.CYAN))


def _pass_fail(c: _Term, ok: bool, pass_text: str = "PASS", fail_text: str = "FAIL") -> str:
    text = pass_text if ok else fail_text
    return c.wrap(text, c.BOLD, c.GREEN) if ok else c.wrap(text, c.BOLD, c.RED)


def _print_fpf_summary(c: _Term, payload: dict[str, Any] | None) -> None:
    if not payload:
        return
    yn = str(payload.get("is_attack", "?"))
    score = float(payload.get("weighted_score", 0.0))
    exc = int(payload.get("exception_code", 0))
    exc_txt = _EXC_LABEL.get(exc, "?")
    ms = payload.get("module_scores") or {}
    p = float(ms.get("physical", 0.0))
    s = float(ms.get("statistical", 0.0))
    sys_s = float(ms.get("system", 0.0))
    yn_col = c.wrap(yn, c.BOLD, c.RED) if yn == "Y" else c.wrap(yn, c.CYAN)
    print(
        f"  FPF → {yn_col}  score={score:.3f}  exc={exc}({exc_txt})  "
        f"P={p:.3f} S={s:.3f} Sys={sys_s:.3f}",
    )


def _wrap_gs_capture(gs: GScomms) -> dict[str, Any]:
    """insert_event 호출 시 마지막 FPF 페이로드를 저장."""
    state: dict[str, Any] = {"last_fpf": None}
    original = gs.insert_event

    def _insert_event(payload: dict[str, Any]) -> int:
        if isinstance(payload, dict) and "is_attack" in payload:
            state["last_fpf"] = dict(payload)
        return original(payload)

    gs.insert_event = _insert_event  # type: ignore[method-assign]
    return state


def _pending_events(db: DBManager) -> list[dict]:
    try:
        return db.get_pending_events()
    except Exception:
        return []


def _print_check_summary(
    c: _Term,
    *,
    saw_anomaly: bool,
    adcs_n: int,
    events: list[dict],
    fpf_ran: bool,
    fpf_wired: bool,
    hist: int,
    fpf_last: dict[str, Any] | None,
) -> None:
    fpf_ok = fpf_ran
    fpf_label = (
        "AnomalyDetector → FPF → GScomms"
        if fpf_ok
        else ("연결됨 (이벤트 미발생)" if fpf_wired else "미연결")
    )

    col_w = 22
    print()
    print(c.wrap("  항목".ljust(col_w) + "결과", c.BOLD))
    print(c.wrap("  " + "─" * 40, c.DIM))
    print(f"  {'전력 이상 감지'.ljust(col_w)}{_pass_fail(c, saw_anomaly)}")
    print(f"  {'SAT_ADCS_FILTER'.ljust(col_w)}{adcs_n}행")
    print(f"  {'SAT_EVENT_QUEUE'.ljust(col_w)}{len(events)}건 pending")
    print(f"  {'오탐필터(FPF)'.ljust(col_w)}{_pass_fail(c, fpf_ok, 'PASS', '—')}  {fpf_label}")

    if fpf_last:
        _print_fpf_summary(c, fpf_last)

    if events:
        print(c.wrap("  이벤트", c.DIM))
        for ev in events[:3]:
            print(
                f"    #{ev.get('EVENT_ID')} {ev.get('EVENT_TYPE')}  "
                f"priority={ev.get('PRIORITY')}  sw_id_list={ev.get('SW_ID_LIST')}",
            )

    print(c.wrap(f"  SAT_PWR_HISTORY snapshots={hist}", c.DIM))
    print()
    if saw_anomaly:
        print(c.wrap("종합: 파이프라인 OK", c.BOLD, c.GREEN))
    else:
        print(c.wrap("종합: 전력 이상 미탐지 (펌웨어/임계치 확인)", c.BOLD, c.RED))


def main() -> int:
    _fix_stdout_encoding()

    parser = argparse.ArgumentParser(description="공격 파이프라인 점검 (전력 이상 → FPF → 이벤트)")
    parser.add_argument("--warmup-sec", type=int, default=5, help="공격 전 베이스라인(초)")
    parser.add_argument("--attack-sec", type=int, default=12, help="공격 후 관측(초)")
    parser.add_argument("--no-hardware", action="store_true", help="시리얼 없이 DB 모의")
    parser.add_argument("--port", type=str, default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="tick·로그 상세")
    parser.add_argument("--no-color", action="store_true", help="색상 끄기")
    args = parser.parse_args()

    use_color = not args.no_color and _enable_ansi()
    c = _Term(use_color)

    log_level = logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(levelname)s %(message)s")
    logging.getLogger("false_positive_filter").setLevel(log_level)

    db_path = Path(tempfile.mkdtemp()) / "attack_pipe.db"
    cfg = DaemonConfig(db_path=db_path)
    if args.port:
        cfg.serial_port = args.port

    db = DBManager(db_path)
    if not db.init_db():
        print("DB init 실패", file=sys.stderr)
        return 1

    for sw_id in range(demon_config.PWR_SW_ID_COUNT):
        lo = float(demon_config.V_THRESHOLD_LO[sw_id])
        hi = float(demon_config.V_THRESHOLD_HI[sw_id])
        db.update_threshold(sw_id, lo, hi)

    shutdown = threading.Event()
    ctx = RuntimeContext(config=cfg, shutdown_event=shutdown, db=db)
    serial = SerialReader(ctx)
    detector = AnomalyDetector(ctx)
    gs_comms = GScomms(ctx)
    gs_comms.set_serial_reader(serial)
    gs_comms.set_anomaly_detector(detector)
    false_positive_filter = FalsePositiveFilter(
        PhysicalConsistencyModule(db),
        StatisticalConsistencyModule(db),
        SystemResponseModule(db),
        gs_comms,
    )
    detector.set_false_positive_filter(false_positive_filter)
    detector.set_gs_comms(gs_comms)
    gs_state = _wrap_gs_capture(gs_comms)
    attack_sim = AttackSimulator(ctx)
    attack_sim.set_serial_reader(serial)
    attack_sim.set_anomaly_detector(detector)

    use_serial = not args.no_hardware
    t_serial = None
    if use_serial:
        t_serial = threading.Thread(target=serial.run, daemon=True)
        t_serial.start()
        time.sleep(2.0)
        if not t_serial.is_alive():
            print("시리얼 미연결 — --no-hardware 로 재시도하거나 포트 확인", file=sys.stderr)
            return 1

    mode_label = "하드웨어+시리얼" if use_serial else "모의(수동 upsert)"
    print(c.wrap("공격 파이프라인 점검", c.BOLD, c.CYAN))
    print(f"  DB   {db_path}")
    print(f"  모드 {mode_label}")
    print()

    _print_section(c, 1, f"베이스라인 {args.warmup_sec}s")
    for _ in range(args.warmup_sec):
        detector._tick()
        time.sleep(1.0)
    _print_pwr_table(c, _pwr_rows(db))
    anomaly0 = detector.detect_power_anomaly()
    sw0 = _anomaly_sw_list(anomaly0)
    if sw0:
        print(f"  이상 sw_id_list={sw0}")
    else:
        print(c.wrap("  이상 없음", c.DIM))
    print()

    _print_section(c, 2, "AttackSimulator.start()")
    if use_serial:
        if not attack_sim.start():
            print("AttackSimulator.start 실패", file=sys.stderr)
            return 1
        print(c.wrap("  ATTACK_SIM 시작 (시리얼)", c.DIM))
    else:
        detector.set_attack_mode(True)
        for v in (3.27, 4.20, 4.50, 4.55):
            db.upsert_pwr_meta({"sw_id": 0, "voltage": v, "current_a": 0.001})
            detector._tick()
            time.sleep(0.3)
        print(c.wrap("  SW_0 전압 스텝 + attack_mode=True", c.DIM))
    print()

    _print_section(c, 3, f"공격 후 {args.attack_sec}s")
    saw_anomaly = False
    prev_sw_list: list[int] | None = None
    last_rows: list[dict[str, Any]] = []
    for i in range(1, args.attack_sec + 1):
        detector._tick()
        anomaly = detector.detect_power_anomaly()
        sw_list = _anomaly_sw_list(anomaly)
        if anomaly:
            saw_anomaly = True
        rows = _pwr_rows(db)
        last_rows = rows
        changed = sw_list != prev_sw_list
        show_tick = args.verbose or i == 1 or i == args.attack_sec or changed
        if show_tick:
            tag = c.wrap(f"tick {i:>2}", c.DIM)
            print(f"  {tag}")
            _print_pwr_table(c, rows, indent=4)
            if sw_list:
                print(f"      → sw_id_list={sw_list}")
        prev_sw_list = sw_list
        time.sleep(1.0)

    if not args.verbose and last_rows:
        print(c.wrap(f"  (마지막 tick {args.attack_sec} 요약 — 상세는 -v)", c.DIM))

    events = _pending_events(db)
    adcs_n = len(db.get_adcs_filter_all())

    _print_section(c, 4, "점검 결과")
    fpf_wired = detector._false_positive_filter is not None
    fpf_event_types = {ev.get("EVENT_TYPE") for ev in events}
    fpf_ran = bool(
        fpf_wired
        and (
            "ATTACK_CONFIRMED" in fpf_event_types
            or "SEU_DETECTED" in fpf_event_types
        ),
    )

    conn = sqlite3.connect(db_path)
    hist = conn.execute("SELECT COUNT(*) FROM SAT_PWR_HISTORY").fetchone()[0]
    conn.close()

    _print_check_summary(
        c,
        saw_anomaly=saw_anomaly,
        adcs_n=adcs_n,
        events=events,
        fpf_ran=fpf_ran,
        fpf_wired=fpf_wired,
        hist=hist,
        fpf_last=gs_state.get("last_fpf"),
    )

    _print_section(c, 5, "종료")
    attack_sim.stop()
    if not use_serial:
        detector.set_attack_mode(False)
    print(c.wrap("  AttackSimulator.stop() 완료", c.DIM))

    shutdown.set()
    if t_serial is not None:
        t_serial.join(timeout=3.0)

    return 0 if saw_anomaly else 1


if __name__ == "__main__":
    raise SystemExit(main())
