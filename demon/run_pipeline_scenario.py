#!/usr/bin/env python3
"""
파이프라인 통합 시나리오 4종 — 발표·실환경 점검.

기본(발표): 운영 DB + Serial + UDP + AnomalyDetector + GScomms (main.py 와 동일 wiring)
            시나리오 실행 전 python3 -m demon.main 은 중지할 것 (DB·포트 점유).

    python3 -m demon.run_pipeline_scenario normal
    python3 -m demon.run_pipeline_scenario false_positive
    python3 -m demon.run_pipeline_scenario integrity
    python3 -m demon.run_pipeline_scenario attack

발표 전 준비 (최초 1회)
    python3 -m demon.tools.seed_cf_integrity

옵션
    --db PATH          SQLite 경로 (기본: config.DB_PATH 또는 demon/database.sqlite)
    -v                 로그·tick 상세
    --observe-sec N    관측 시간
    --port /dev/ttyUSB0

integrity
    --seed             cf baseline 재등록 (기본: DB에 등록된 baseline 사용)

격리 테스트 (--lab, 개발용 — temp DB·수동 tick)
    python3 -m demon.run_pipeline_scenario normal --lab --no-hardware
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
from typing import Any, Callable

from demon import config as demon_config
from demon.core.context import DaemonConfig, RuntimeContext
from demon.db.db_manager import DBManager
from demon.db.paths import default_db_path
from demon.tools.seed_cf_integrity import seed_directory_baseline
from demon.workers.anomaly_detector import AnomalyDetector
from demon.workers.attack_simulator import AttackSimulator
from demon.workers.false_positive_filter import (
    FalsePositiveFilter,
    PhysicalConsistencyModule,
    StatisticalConsistencyModule,
    SystemResponseModule,
)
from demon.workers.false_positive_filter.fpf_scenario_injector import (
    FpfScenarioInjector,
    SCENARIO_FPF_NATURAL,
    inject_natural_adcs_tlm,
)
from demon.workers.gs_comms import GScomms
from demon.workers.serial_reader import SerialReader
from demon.workers.udp_receiver import UDPReceiver

logger = logging.getLogger(__name__)

SCENARIO_NORMAL = "normal"
SCENARIO_FALSE_POSITIVE = "false_positive"
SCENARIO_INTEGRITY = "integrity"
SCENARIO_ATTACK = "attack"
SCENARIOS = (
    SCENARIO_NORMAL,
    SCENARIO_FALSE_POSITIVE,
    SCENARIO_INTEGRITY,
    SCENARIO_ATTACK,
)

_SCENARIO_TITLES = {
    SCENARIO_NORMAL: "1. 정상 — FPF 미진입 · 주기 송신",
    SCENARIO_FALSE_POSITIVE: "2. 오탐 — FPF 판정 N (SEU)",
    SCENARIO_INTEGRITY: "3. 해시 무결성 — FPF 스킵 · INTEGRITY",
    SCENARIO_ATTACK: "4. 공격 — FPF 판정 Y (ATTACK)",
}

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


class _MockSerial:
    def set_pwr_bias(self, enabled: bool) -> bool:
        return True

    def set_gyro_enabled(self, enabled: bool) -> bool:
        return True

    def run_servo_motion(self, repeat_count: int, angle_deg: int) -> bool:
        return True

    def get_light_state(self) -> str | None:
        return None


class _Harness:
    """main.py 와 동일 wiring. lab_mode=False 이면 4워커 스레드 기동."""

    def __init__(
        self,
        *,
        cfg: DaemonConfig,
        lab_mode: bool,
        use_serial: bool,
    ) -> None:
        self.cfg = cfg
        self.db_path = Path(cfg.db_path)
        self.lab_mode = lab_mode
        self.use_serial = use_serial

        self.db = DBManager(self.db_path)
        if not self.db.init_db():
            raise RuntimeError("DB init 실패")

        if lab_mode:
            for sw_id in range(demon_config.PWR_SW_ID_COUNT):
                lo = float(demon_config.V_THRESHOLD_LO[sw_id])
                hi = float(demon_config.V_THRESHOLD_HI[sw_id])
                self.db.update_threshold(sw_id, lo, hi)

        self.shutdown = threading.Event()
        self.ctx = RuntimeContext(config=cfg, shutdown_event=self.shutdown, db=self.db)
        self.serial = SerialReader(self.ctx)
        self.udp = UDPReceiver(self.ctx)
        self.detector = AnomalyDetector(self.ctx)
        self.gs_comms = GScomms(self.ctx)
        self.gs_comms.set_serial_reader(self.serial)
        self.gs_comms.set_anomaly_detector(self.detector)

        self.fpf = FalsePositiveFilter(
            PhysicalConsistencyModule(self.db),
            StatisticalConsistencyModule(self.db),
            SystemResponseModule(self.db),
            self.gs_comms,
        )
        self.detector.set_false_positive_filter(self.fpf)
        self.detector.set_gs_comms(self.gs_comms)

        self.gs_state = self._wrap_gs_capture()
        self.attack_sim = AttackSimulator(self.ctx)
        self.attack_sim.set_anomaly_detector(self.detector)
        self.gs_comms.set_attack_simulator(self.attack_sim)
        self.injector = FpfScenarioInjector(self.db)

        if use_serial:
            self.attack_sim.set_serial_reader(self.serial)
        else:
            self.attack_sim.set_serial_reader(_MockSerial())

        self._threads: list[threading.Thread] = []
        self.baseline_max_event_id = _max_event_id(self.db_path)
        self._scenario_fpf_seen = False

    def _wrap_gs_capture(self) -> dict[str, Any]:
        state: dict[str, Any] = {"last_fpf": None, "bulk_attempts": 0}
        original_insert = self.gs_comms.insert_event
        original_send = self.gs_comms.send_with_retry

        def _insert_event(payload: dict[str, Any]) -> int:
            if isinstance(payload, dict) and "is_attack" in payload:
                state["last_fpf"] = dict(payload)
                self._scenario_fpf_seen = True
            return original_insert(payload)

        def _send_with_retry(payload: dict[str, Any], on_ack: Callable[..., Any]) -> bool:
            if isinstance(payload, dict):
                if payload.get("packet_type") == demon_config.GS_PACKET_TYPE_BULK:
                    state["bulk_attempts"] = int(state["bulk_attempts"]) + 1
            return original_send(payload, on_ack)

        self.gs_comms.insert_event = _insert_event  # type: ignore[method-assign]
        self.gs_comms.send_with_retry = _send_with_retry  # type: ignore[method-assign]
        return state

    def start(self) -> bool:
        if self.lab_mode:
            if not self.use_serial:
                return True
            t = threading.Thread(target=self.serial.run, name="SerialReader", daemon=True)
            t.start()
            self._threads.append(t)
            time.sleep(2.0)
            return t.is_alive()

        specs: list[tuple[str, Any]] = [
            ("SerialReader", self.serial),
            ("UDPReceiver", self.udp),
            ("AnomalyDetector", self.detector),
            ("GScomms", self.gs_comms),
        ]
        for name, worker in specs:
            t = threading.Thread(target=worker.run, name=name, daemon=True)
            t.start()
            self._threads.append(t)
        time.sleep(3.0)
        alive = [t.name for t in self._threads if t.is_alive()]
        if self.use_serial and "SerialReader" not in alive:
            return False
        return bool(alive)

    def stop(self) -> None:
        try:
            self.attack_sim.stop()
        except Exception as e:
            logger.error("attack_sim.stop 실패: %s", e)
        self.shutdown.set()
        for t in self._threads:
            t.join(timeout=5.0)
        try:
            self.injector.release_scenario()
        except Exception as e:
            logger.error("injector.release 실패: %s", e)
        try:
            self.db.close()
        except Exception as e:
            logger.error("db.close 실패: %s", e)


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


def _max_event_id(db_path: Path) -> int:
    try:
        conn = sqlite3.connect(db_path)
        row = conn.execute("SELECT COALESCE(MAX(EVENT_ID), 0) FROM SAT_EVENT_QUEUE").fetchone()
        conn.close()
        return int(row[0])
    except Exception:
        return 0


def _events_since(db_path: Path, since_id: int) -> list[dict[str, Any]]:
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM SAT_EVENT_QUEUE WHERE EVENT_ID > ? ORDER BY EVENT_ID",
            (since_id,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


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


def _pwr_history_count(db_path: Path) -> int:
    try:
        conn = sqlite3.connect(db_path)
        n = conn.execute("SELECT COUNT(*) FROM SAT_PWR_HISTORY").fetchone()[0]
        conn.close()
        return int(n)
    except Exception:
        return 0


def _pwr_history_count_since(db_path: Path, since_count: int) -> int:
    return max(0, _pwr_history_count(db_path) - since_count)


def _print_section(c: _Term, num: int, title: str) -> None:
    print(c.wrap(f"[{num}] {title}", c.BOLD, c.CYAN))


def _pass_fail(c: _Term, ok: bool, pass_text: str = "PASS", fail_text: str = "FAIL") -> str:
    text = pass_text if ok else fail_text
    return c.wrap(text, c.BOLD, c.GREEN) if ok else c.wrap(text, c.BOLD, c.RED)


def _print_pwr_table(c: _Term, rows: list[dict[str, Any]], *, indent: int = 2) -> None:
    pad = " " * indent
    if not rows:
        print(f"{pad}(전력 데이터 없음)")
        return
    print(f"{pad}{'SW':>2}  {'V':>7}  {'EX':>4}  {'ANOM':>4}")
    for row in rows:
        sw = int(row["SW_ID"])
        v = float(row["VOLTAGE"])
        ex = int(row["EXCEED_COUNT"])
        anom = int(row["ANOMALY_FLAG"])
        line = f"{pad}{sw:>2}  {v:7.3f}  {ex:>4}  {anom:>4}"
        if anom:
            line = c.wrap(line, c.YELLOW)
        print(line)


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


def _print_result_block(
    c: _Term,
    *,
    checks: list[tuple[str, bool, str]],
    overall_ok: bool,
    events: list[dict],
    fpf_last: dict[str, Any] | None,
    extra_lines: list[str] | None = None,
) -> None:
    col_w = 28
    print()
    print(c.wrap("  검증 항목".ljust(col_w) + "결과", c.BOLD))
    print(c.wrap("  " + "─" * 44, c.DIM))
    for label, ok, detail in checks:
        suffix = f"  {detail}" if detail else ""
        print(f"  {label.ljust(col_w)}{_pass_fail(c, ok)}{suffix}")

    if fpf_last:
        _print_fpf_summary(c, fpf_last)

    if events:
        print(c.wrap("  이번 시나리오 이벤트", c.DIM))
        for ev in events[:8]:
            print(
                f"    #{ev.get('EVENT_ID')} {ev.get('EVENT_TYPE')}  "
                f"priority={ev.get('PRIORITY')}  sw={ev.get('SW_ID')}",
            )

    if extra_lines:
        for line in extra_lines:
            print(c.wrap(f"  {line}", c.DIM))

    print()
    if overall_ok:
        print(c.wrap("종합: 시나리오 OK", c.BOLD, c.GREEN))
    else:
        print(c.wrap("종합: 시나리오 FAIL — 위 FAIL 항목 확인", c.BOLD, c.RED))


def _observe(
    h: _Harness,
    c: _Term,
    *,
    seconds: int,
    verbose: bool,
    poll: Callable[[int], None] | None = None,
) -> None:
    for i in range(1, seconds + 1):
        if poll is not None:
            poll(i)
        if verbose:
            print(c.wrap(f"  tick {i:>2}", c.DIM))
            _print_pwr_table(c, _pwr_rows(h.db), indent=4)
            anomaly = h.detector.detect_power_anomaly()
            sw_list = _anomaly_sw_list(anomaly)
            if sw_list:
                print(f"      → sw_id_list={sw_list}")
        time.sleep(1.0)


def _run_ticks_lab(
    h: _Harness,
    c: _Term,
    *,
    count: int,
    verbose: bool,
) -> dict[str, Any]:
    h.detector._warmup_ticks_remaining = 0
    last_anomaly: dict[str, Any] = {}
    last_sw: list[int] | None = None
    for i in range(1, count + 1):
        h.detector._tick()
        anomaly = h.detector.detect_power_anomaly()
        sw_list = _anomaly_sw_list(anomaly)
        if anomaly:
            last_anomaly = anomaly
        if verbose:
            print(c.wrap(f"  tick {i:>2}", c.DIM))
            _print_pwr_table(c, _pwr_rows(h.db), indent=4)
            if sw_list:
                print(f"      → sw_id_list={sw_list}")
        last_sw = sw_list
        time.sleep(1.0)
    return {"anomaly": last_anomaly, "sw_list": last_sw}


def _mock_power_anomaly_steps(h: _Harness) -> bool:
    try:
        h.detector.set_attack_mode(True)
        h.detector._warmup_ticks_remaining = 0
        steps = (3.27, 4.20, 4.50, 4.55, 4.60, 4.65, 4.70)
        for v in steps:
            h.db.upsert_pwr_meta({"sw_id": 0, "voltage": v, "current_a": 0.001})
            h.detector._tick()
            if h.detector.detect_power_anomaly():
                return True
            time.sleep(0.2)
        return bool(h.detector.detect_power_anomaly())
    except Exception as e:
        logger.error("_mock_power_anomaly_steps 실패: %s", e)
        return False


def _seed_lab_normal_state(db: DBManager) -> None:
    try:
        for sw_id in range(demon_config.PWR_SW_ID_COUNT):
            lo = float(demon_config.V_THRESHOLD_LO[sw_id])
            hi = float(demon_config.V_THRESHOLD_HI[sw_id])
            mid = (lo + hi) / 2.0
            db.upsert_pwr_meta({"sw_id": sw_id, "voltage": mid, "current_a": 0.05})
            db.update_pwr_exceed_meta(
                {
                    "sw_id": sw_id,
                    "exceed_count": 0,
                    "consecutive_exceed": 0,
                    "anomaly_flag": 0,
                },
            )
    except Exception as e:
        logger.error("_seed_lab_normal_state 실패: %s", e)


def _scenario_events(h: _Harness) -> list[dict[str, Any]]:
    return _events_since(h.db_path, h.baseline_max_event_id)


def run_normal(h: _Harness, c: _Term, args: argparse.Namespace) -> int:
    observe = int(args.observe_sec or 10)
    hist0 = _pwr_history_count(h.db_path)

    _print_section(c, 1, f"정상 운용 {observe}s — 실측 Serial·UDP·Detector")
    if h.lab_mode:
        _seed_lab_normal_state(h.db)
        _run_ticks_lab(h, c, count=observe, verbose=args.verbose)
    else:
        print(c.wrap("  워커 스레드 관측 중 (FPF·이상 이벤트 없음 기대)", c.DIM))
        _observe(h, c, seconds=observe, verbose=args.verbose)

    new_events = _scenario_events(h)
    fpf_new = [
        ev
        for ev in new_events
        if ev.get("EVENT_TYPE")
        in (demon_config.GS_EVENT_ATTACK_CONFIRMED, demon_config.GS_EVENT_SEU_DETECTED)
    ]
    hist_delta = _pwr_history_count_since(h.db_path, hist0)
    bulk_before = int(h.gs_state.get("bulk_attempts", 0))

    _print_section(c, 2, "bulk 송신 (GScomms — 조도 엣지 또는 수동)")
    if h.lab_mode:
        h.gs_comms.transmit_all()
    else:
        print(c.wrap("  실운영: 아두이노 L,dark→L,light 시 GScomms 가 자동 transmit_all", c.DIM))
        print(c.wrap("  검증용으로 1회 transmit_all 호출", c.DIM))
        h.gs_comms.transmit_all()

    bulk_after = int(h.gs_state.get("bulk_attempts", 0))
    anomaly = h.detector.detect_power_anomaly()

    ok = (
        not fpf_new
        and h.gs_state.get("last_fpf") is None
        and hist_delta > 0
        and (bulk_after > bulk_before or not h.lab_mode)
    )

    _print_result_block(
        c,
        checks=[
            ("신규 FPF 이벤트 없음", not fpf_new, f"{len(fpf_new)}건"),
            ("FPF 미호출", h.gs_state.get("last_fpf") is None, ""),
            ("PWR history 증가", hist_delta > 0, f"+{hist_delta}"),
            ("bulk 송신 경로", bulk_after > bulk_before or not h.lab_mode, ""),
            ("현재 ANOM 플래그", not bool(anomaly), str(_anomaly_sw_list(anomaly) or "없음")),
        ],
        overall_ok=ok,
        events=new_events,
        fpf_last=h.gs_state.get("last_fpf"),
        extra_lines=[
            f"GS {h.cfg.gs_host}:{h.cfg.gs_port}",
            f"UDP :{h.cfg.udp_tlm_bind[1]}",
        ],
    )
    return 0 if ok else 1


def run_false_positive(h: _Harness, c: _Term, args: argparse.Namespace) -> int:
    observe = int(args.observe_sec or 15)

    if h.lab_mode:
        _print_section(c, 1, "lab: fpf_natural DB 주입")
        if not h.injector.prepare_scenario(SCENARIO_FPF_NATURAL):
            print("시나리오 주입 실패", file=sys.stderr)
            return 1
        _print_section(c, 2, "AnomalyDetector → FPF (N 기대)")
        _run_ticks_lab(h, c, count=3, verbose=args.verbose)
    else:
        _print_section(c, 1, "물리 전력 이상 + DB 정상 ADCS/TLM")
        print(c.wrap("  Serial(pwr_bias) → 전력 이상 | DB inject_natural_adcs_tlm → FPF N 기대", c.DIM))
        if not inject_natural_adcs_tlm(h.db):
            print("정상 ADCS/TLM DB 주입 실패", file=sys.stderr)
            return 1
        if not h.attack_sim.start(inject_logical=False):
            print("물리 공격 시작 실패 (SerialReader 확인)", file=sys.stderr)
            return 1

        def _poll_fp(_i: int) -> None:
            if not h._scenario_fpf_seen:
                inject_natural_adcs_tlm(h.db)

        _print_section(c, 2, f"관측 {observe}s")
        _observe(h, c, seconds=observe, verbose=args.verbose, poll=_poll_fp)

    new_events = _scenario_events(h)
    seu = [ev for ev in new_events if ev.get("EVENT_TYPE") == demon_config.GS_EVENT_SEU_DETECTED]
    attack = [ev for ev in new_events if ev.get("EVENT_TYPE") == demon_config.GS_EVENT_ATTACK_CONFIRMED]
    fpf_last = h.gs_state.get("last_fpf")
    is_n = isinstance(fpf_last, dict) and str(fpf_last.get("is_attack")) == "N"
    had_anomaly = bool(h.detector.detect_power_anomaly()) or h._scenario_fpf_seen

    ok = had_anomaly and bool(seu) and not attack and is_n

    _print_result_block(
        c,
        checks=[
            ("앞단 이상·FPF 진입", had_anomaly, ""),
            ("FPF 판정 N", is_n, ""),
            ("SEU_DETECTED", bool(seu), f"{len(seu)}건"),
            ("ATTACK_CONFIRMED 없음", not attack, ""),
        ],
        overall_ok=ok,
        events=new_events,
        fpf_last=fpf_last,
    )
    return 0 if ok else 1


def run_integrity(h: _Harness, c: _Term, args: argparse.Namespace) -> int:
    integrity_dir = Path(h.ctx.config.integrity_target_dir).expanduser()
    observe = int(args.observe_sec or 20)

    _print_section(c, 1, f"cf baseline ({integrity_dir})")
    if args.seed:
        if not seed_directory_baseline(integrity_dir, h.db):
            print("baseline seed 실패", file=sys.stderr)
            return 1
        print(c.wrap("  baseline 재등록 완료", c.DIM))
    else:
        rec = h.db.get_integrity_hash(int(demon_config.INTEGRITY_DIR_FILE_ID))
        if rec is None:
            print(
                "DB baseline 없음 — python3 -m demon.tools.seed_cf_integrity 또는 --seed",
                file=sys.stderr,
            )
            return 1
        print(c.wrap(f"  DB baseline 사용 manifest={str(rec.get('EXPECTED_HASH', ''))[:16]}…", c.DIM))

    _print_section(c, 2, "ATTACK_HASH — cf 파일 주입")
    if not h.attack_sim.start_hash():
        print("ATTACK_HASH 시작 실패", file=sys.stderr)
        return 1

    _print_section(c, 3, f"전력 이상·hash 검사 대기 {observe}s")
    state = {"saw_anomaly": False}

    def _poll(_i: int) -> None:
        if h.detector.detect_power_anomaly():
            state["saw_anomaly"] = True

    if h.lab_mode and not h.use_serial:
        state["saw_anomaly"] = _mock_power_anomaly_steps(h)
        _run_ticks_lab(h, c, count=max(2, observe // 2), verbose=args.verbose)
    else:
        _observe(h, c, seconds=observe, verbose=args.verbose, poll=_poll)

    new_events = _scenario_events(h)
    integrity_ev = [ev for ev in new_events if str(ev.get("EVENT_TYPE", "")).startswith("INTEGRITY_")]
    fpf_attack = [ev for ev in new_events if ev.get("EVENT_TYPE") == demon_config.GS_EVENT_ATTACK_CONFIRMED]
    fpf_last = h.gs_state.get("last_fpf")
    ok = state["saw_anomaly"] and bool(integrity_ev) and fpf_last is None and not fpf_attack

    _print_result_block(
        c,
        checks=[
            ("전력 이상 감지", state["saw_anomaly"], ""),
            ("INTEGRITY 이벤트", bool(integrity_ev), integrity_ev[0].get("EVENT_TYPE") if integrity_ev else ""),
            ("FPF 미진입", fpf_last is None, ""),
            ("ATTACK_CONFIRMED(FPF) 없음", not fpf_attack, ""),
        ],
        overall_ok=ok,
        events=new_events,
        fpf_last=fpf_last,
        extra_lines=[f"integrity_dir={integrity_dir}"],
    )
    return 0 if ok else 1


def run_attack(h: _Harness, c: _Term, args: argparse.Namespace) -> int:
    warmup = int(args.warmup_sec or 5)
    observe = int(args.observe_sec or 15)

    _print_section(c, 1, f"베이스라인 {warmup}s")
    if h.lab_mode:
        _run_ticks_lab(h, c, count=warmup, verbose=args.verbose)
    else:
        _observe(h, c, seconds=warmup, verbose=args.verbose)
    _print_pwr_table(c, _pwr_rows(h.db))

    _print_section(c, 2, "ATTACK_SIM — 물리(Serial) + DB 변조 ADCS/TLM")
    if h.lab_mode and not h.use_serial:
        h.attack_sim.start()
        _mock_power_anomaly_steps(h)
    else:
        if not h.attack_sim.start(inject_logical=True):
            print("ATTACK_SIM 시작 실패", file=sys.stderr)
            return 1

    _print_section(c, 3, f"공격 후 {observe}s")
    state = {"saw_anomaly": False}

    def _poll_attack(_i: int) -> None:
        if not h._scenario_fpf_seen:
            h.attack_sim.reinject_logical_attack()
        if h.detector.detect_power_anomaly():
            state["saw_anomaly"] = True

    if h.lab_mode and not h.use_serial:
        h.detector._warmup_ticks_remaining = 0
        last_anomaly: dict[str, Any] = {}
        for i in range(1, observe + 1):
            if not h._scenario_fpf_seen:
                h.attack_sim.reinject_logical_attack()
            h.detector._tick()
            anomaly = h.detector.detect_power_anomaly()
            if anomaly:
                last_anomaly = anomaly
                state["saw_anomaly"] = True
            if args.verbose:
                print(c.wrap(f"  tick {i:>2}", c.DIM))
                _print_pwr_table(c, _pwr_rows(h.db), indent=4)
            time.sleep(1.0)
        tick_info = {"anomaly": last_anomaly}
    else:
        _observe(h, c, seconds=observe, verbose=args.verbose, poll=_poll_attack)

    new_events = _scenario_events(h)
    attack_ev = [ev for ev in new_events if ev.get("EVENT_TYPE") == demon_config.GS_EVENT_ATTACK_CONFIRMED]
    fpf_last = h.gs_state.get("last_fpf")
    is_y = isinstance(fpf_last, dict) and str(fpf_last.get("is_attack")) == "Y"
    ok = state["saw_anomaly"] and bool(attack_ev) and is_y

    _print_result_block(
        c,
        checks=[
            ("전력 이상 감지", state["saw_anomaly"], str(_anomaly_sw_list(h.detector.detect_power_anomaly()))),
            ("FPF 판정 Y", is_y, ""),
            ("ATTACK_CONFIRMED", bool(attack_ev), f"{len(attack_ev)}건"),
        ],
        overall_ok=ok,
        events=new_events,
        fpf_last=fpf_last,
        extra_lines=[f"SAT_ADCS_FILTER {len(h.db.get_adcs_filter_all())}행"],
    )
    return 0 if ok else 1


def main() -> int:
    _fix_stdout_encoding()

    parser = argparse.ArgumentParser(description="파이프라인 시나리오 4종 (발표=운영 DB·실워커)")
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("--observe-sec", type=int, default=None)
    parser.add_argument("--warmup-sec", type=int, default=None)
    parser.add_argument("--db", type=str, default=None, help="운영 SQLite (기본 config/database.sqlite)")
    parser.add_argument(
        "--lab",
        action="store_true",
        help="격리 테스트: temp DB + 수동 tick (--no-hardware 가능)",
    )
    parser.add_argument(
        "--no-hardware",
        action="store_true",
        help="--lab 전용: Mock Serial",
    )
    parser.add_argument("--port", type=str, default=None)
    parser.add_argument("--integrity-dir", type=str, default=None)
    parser.add_argument("--seed", action="store_true", help="integrity cf baseline 재등록")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    if args.no_hardware and not args.lab:
        print("--no-hardware 는 --lab 과 함께만 사용 가능 (발표는 실 Serial 필수)", file=sys.stderr)
        return 2

    use_color = not args.no_color and _enable_ansi()
    c = _Term(use_color)

    log_level = logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(levelname)s %(message)s")
    logging.getLogger("false_positive_filter").setLevel(log_level)

    if args.lab:
        db_path = Path(tempfile.mkdtemp()) / f"lab_{args.scenario}.db"
    elif args.db:
        db_path = Path(args.db).expanduser().resolve()
    else:
        db_path = default_db_path()

    cfg = DaemonConfig(db_path=db_path)
    if args.port:
        cfg.serial_port = args.port
    if args.integrity_dir:
        cfg.integrity_target_dir = str(Path(args.integrity_dir).expanduser())

    use_serial = not args.no_hardware

    try:
        h = _Harness(cfg=cfg, lab_mode=args.lab, use_serial=use_serial)
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        return 1

    title = _SCENARIO_TITLES.get(args.scenario, args.scenario)
    mode = "격리(lab)" if args.lab else "발표(운영 DB·실워커)"
    print(c.wrap(title, c.BOLD, c.CYAN))
    print(f"  DB   {db_path}")
    print(f"  모드 {mode}")
    print(f"  GS   {cfg.gs_host}:{cfg.gs_port}  UDP :{cfg.udp_tlm_bind[1]}  Serial {cfg.serial_port}")
    print()

    if not h.start():
        print("워커 기동 실패 — main.py 중지·Serial·UDP 포트 확인", file=sys.stderr)
        return 1

    runners = {
        SCENARIO_NORMAL: run_normal,
        SCENARIO_FALSE_POSITIVE: run_false_positive,
        SCENARIO_INTEGRITY: run_integrity,
        SCENARIO_ATTACK: run_attack,
    }
    try:
        rc = runners[args.scenario](h, c, args)
    finally:
        print()
        _print_section(c, 99, "종료 — RECOVERY·워커 stop")
        h.stop()
        print(c.wrap("  cleanup 완료 (이벤트는 운영 DB에 유지)", c.DIM))

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
