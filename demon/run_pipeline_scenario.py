#!/usr/bin/env python3
"""
파이프라인 통합 시나리오 4종 — 발표·실환경 점검.

기본(발표): 운영 DB + Serial + UDP + AnomalyDetector + GScomms (main.py 와 동일 wiring)
            시나리오 실행 전 python3 -m demon.main 은 중지할 것 (DB·포트 점유).

    python3 -m demon.run_pipeline_scenario normal
    python3 -m demon.run_pipeline_scenario false_positive
        (ATTACK_SIM·이상탐지 선행 — FPF/큐 미등록 → RECOVERY → SEU·FPF N 1회 → 지상 bulk)

실험/운영: main.py 동일 wiring. SEU FPF = 실측 전력(Serial) + DB·adcs_series(ADCS/TLM).
공격 논리 잔존 시에만 정상 ADCS/TLM 복원(실험 조건). _snapshots 고정 미사용.
    python3 -m demon.run_pipeline_scenario integrity
        (ATTACK_HASH·cf 주입 → INTEGRITY 이벤트 · FPF 미진입 → 지상 bulk)
    python3 -m demon.run_pipeline_scenario attack
        (ATTACK_SIM·FPF Y → 지상 bulk)

발표 전 준비 (최초 1회)
    python3 -m demon.tools.seed_cf_integrity

옵션
    --db PATH          SQLite 경로 (기본: config.DB_PATH 또는 demon/database.sqlite)
    -v                 로그·tick 상세
    --observe-sec N    관측 시간 (기본 15s)
    --pre-transmit-sec N  transmit_all 직전 추가 수집 (기본 10s)
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
from demon.core.time_utils import parse_utc_timestamp, utc_now
from demon.db.db_manager import DBManager
from demon.db.paths import default_db_path
from demon.integrity_dir_hash import compute_directory_manifest_hash
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
    SCENARIO_FPF_ATTACK,
    SCENARIO_FPF_NATURAL,
    inject_natural_adcs_tlm_bypass,
    is_attack_adcs_row,
)
from demon.workers.false_positive_filter import config as fpf_config
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
    SCENARIO_FALSE_POSITIVE: "2. 오탐 — 공격·이상탐지 후 FPF N · 지상 bulk",
    SCENARIO_INTEGRITY: "3. 해시 무결성 — FPF 스킵 · INTEGRITY · 지상 bulk",
    SCENARIO_ATTACK: "4. 공격 — FPF 판정 Y (ATTACK) · 지상 bulk",
}

# 발표 모드 — 아두이노 전력·조도 preflight 대기(초)
_SCENARIO_SERIAL_READY_SEC = 15
_SCENARIO_PWR_FRESH_SEC = 8

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
        self._fpf_on_anomaly_original: Callable[[dict[str, Any]], None] | None = None
        self.false_positive_mode = False
        self.suppress_fpf_for_attack_phase = False
        self._false_positive_seu_fpf_done = False

    def install_fpf_natural_patch(self) -> None:
        """false_positive SEU: FPF 직전 DB·시계열 실측 반영 ( _snapshots 미사용 )."""
        if self._fpf_on_anomaly_original is not None:
            return
        original = self.fpf.on_anomaly_detected
        self._fpf_on_anomaly_original = original

        def _patched(key_set: dict[str, Any]) -> None:
            try:
                merged = prepare_seu_fpf_key_set(self, key_set)
                original(merged)
            except Exception as e:
                logger.error("FPF natural patch 실패: %s", e)

        self.fpf.on_anomaly_detected = _patched  # type: ignore[method-assign]

    def restore_fpf_patch(self) -> None:
        if self._fpf_on_anomaly_original is not None:
            self.fpf.on_anomaly_detected = self._fpf_on_anomaly_original  # type: ignore[method-assign]
            self._fpf_on_anomaly_original = None

    def _wrap_gs_capture(self) -> dict[str, Any]:
        state: dict[str, Any] = {
            "last_fpf": None,
            "last_fpf_event_id": -1,
            "bulk_attempts": 0,
        }
        original_insert = self.gs_comms.insert_event
        original_send = self.gs_comms.send_with_retry

        def _insert_event(payload: dict[str, Any]) -> int:
            if isinstance(payload, dict) and "is_attack" in payload:
                if getattr(self, "false_positive_mode", False):
                    if self.suppress_fpf_for_attack_phase:
                        logger.info(
                            "false_positive 공격 선행: FPF→SAT_EVENT_QUEUE 생략 (전력 이상만 확인)",
                        )
                        return -1
                    if str(payload.get("is_attack")).upper() == "Y":
                        logger.info(
                            "false_positive SEU 단계: ATTACK FPF 이벤트 생략 (공격 ADCS 잔존·전환 레이스)",
                        )
                        return -1
                    if self._false_positive_seu_fpf_done:
                        logger.info("false_positive SEU: FPF 중복 이벤트 생략")
                        return -1
            event_id = original_insert(payload)
            if event_id >= 0 and isinstance(payload, dict) and "is_attack" in payload:
                state["last_fpf"] = dict(payload)
                state["last_fpf_event_id"] = int(event_id)
                self._scenario_fpf_seen = True
                if getattr(self, "false_positive_mode", False) and not self.suppress_fpf_for_attack_phase:
                    self._false_positive_seu_fpf_done = True
            return event_id

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
            self.gs_comms.handle_recovery()
        except Exception as e:
            logger.error("handle_recovery(cleanup) 실패: %s", e)
        self.restore_fpf_patch()
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


def _reset_detector_series_from_db(h: _Harness) -> None:
    """AnomalyDetector deque 를 현재 DB live 행으로 재구성."""
    try:
        h.detector._adcs_series.clear()
        h.detector._tlm_series.clear()
        h.detector._refresh_series_buffers()
    except Exception as e:
        logger.error("_reset_detector_series_from_db 실패: %s", e)


def restore_seu_logical_if_needed(h: _Harness) -> bool:
    """
    SEU 실험 조건 — 공격 논리 ADCS/TLM 이 DB에 남아 있으면 정상 스냅샷으로 복원.

    UDP 가 이미 정상 텔레메트리면 DB 를 덮어쓰지 않는다(실측 유지).
    """
    try:
        adcs = h.db.get_adcs_filter()
        if is_attack_adcs_row(adcs):
            if not inject_natural_adcs_tlm_bypass(h.db):
                logger.warning("SEU: 공격 ADCS 복원(inject_natural) 실패")
                return False
            logger.info("SEU 실험: 공격 논리 ADCS/TLM → 정상 상태 복원")
        _reset_detector_series_from_db(h)
        return True
    except Exception as e:
        logger.error("restore_seu_logical_if_needed 실패: %s", e)
        return False


def _restore_fpf_demo_mode(h: _Harness, saved: dict[str, Any]) -> None:
    try:
        h.fpf.weights = dict(saved.get("weights", fpf_config.MODULE_WEIGHTS))
        h.fpf.seu_experiment_mode = bool(saved.get("seu_experiment_mode", False))
    except Exception as e:
        logger.error("_restore_fpf_demo_mode 실패: %s", e)


def _apply_false_positive_fpf_weights(h: _Harness) -> dict[str, Any]:
    """false_positive 시나리오 전용 FPF 가중치(system ↑) 및 SEU 실험 모드."""
    try:
        saved: dict[str, Any] = {
            "weights": dict(h.fpf.weights),
            "seu_experiment_mode": bool(getattr(h.fpf, "seu_experiment_mode", False)),
        }
        h.fpf.weights = dict(fpf_config.FALSE_POSITIVE_SCENARIO_MODULE_WEIGHTS)
        h.fpf.seu_experiment_mode = True
        return saved
    except Exception as e:
        logger.error("_apply_false_positive_fpf_weights 실패: %s", e)
        return {
            "weights": dict(fpf_config.MODULE_WEIGHTS),
            "seu_experiment_mode": False,
        }


def _restore_false_positive_fpf_weights(h: _Harness, saved: dict[str, Any]) -> None:
    _restore_fpf_demo_mode(h, saved)


def _apply_attack_fpf_demo_mode(h: _Harness) -> dict[str, Any]:
    """attack 시나리오: exc 1~5·score=1.0 바이패스 없이 가중합으로 ATTACK(Y) 유도."""
    try:
        saved: dict[str, Any] = {
            "weights": dict(h.fpf.weights),
            "seu_experiment_mode": bool(getattr(h.fpf, "seu_experiment_mode", False)),
        }
        h.fpf.seu_experiment_mode = True
        return saved
    except Exception as e:
        logger.error("_apply_attack_fpf_demo_mode 실패: %s", e)
        return {
            "weights": dict(fpf_config.MODULE_WEIGHTS),
            "seu_experiment_mode": False,
        }


def _restore_attack_fpf_demo_mode(h: _Harness, saved: dict[str, Any]) -> None:
    _restore_fpf_demo_mode(h, saved)


def prepare_seu_fpf_key_set(h: _Harness, key_set: dict[str, Any]) -> dict[str, Any]:
    """
    FPF 호출 직전 key_set — 실측 전력·DB·adcs_series 반영 (_snapshots 없음).

    전력(sw_id_list 등)은 AnomalyDetector 가 넘긴 key_set 유지.
    """
    try:
        restore_seu_logical_if_needed(h)
        h.fpf.physical._prev_state.clear()
        h.fpf.system._prev_state.clear()

        merged = dict(key_set) if isinstance(key_set, dict) else {}
        merged.pop(fpf_config.KEY_SNAPSHOTS, None)

        # SEU FPF: 공격 단계 deque 혼입 → exc=2(토크) 방지, DB live 1프레임만 사용
        adcs_row = h.db.get_adcs_filter()
        tlm_row = h.db.get_tlm_current()
        if adcs_row is not None:
            merged["adcs_series"] = [dict(adcs_row)]
        else:
            merged["adcs_series"] = []
        if tlm_row is not None:
            merged["tlm_series"] = [dict(tlm_row)]
        else:
            merged["tlm_series"] = []

        if adcs_row is not None:
            ch1 = int(
                adcs_row.get(
                    "CHENNEL1",
                    adcs_row.get("channel1", demon_config.SAT_ADCS_FILTER_CHANNEL_ID),
                ),
            )
            merged["channel1"] = ch1
            merged["CHENNEL1"] = ch1
        return merged
    except Exception as e:
        logger.error("prepare_seu_fpf_key_set 실패: %s", e)
        return dict(key_set) if isinstance(key_set, dict) else {}


def _pwr_meta_fresh(db: DBManager, sw_id: int, *, max_age_sec: float) -> bool:
    """아두이노 전력 CSV가 최근 DB에 반영됐는지."""
    try:
        meta = db.get_pwr_meta(sw_id)
        if meta is None:
            return False
        parsed = parse_utc_timestamp(meta.get("UPDATED_AT"))
        if parsed is None:
            return False
        return (utc_now() - parsed).total_seconds() <= float(max_age_sec)
    except Exception as e:
        logger.error("_pwr_meta_fresh 실패 sw_id=%s: %s", sw_id, e)
        return False


def _wait_for_serial_ready(h: _Harness, *, timeout_sec: int) -> tuple[bool, str | None]:
    """
    아두이노 전력(SW0) + 조도(L,light|dark) 수신 대기.

    Returns:
        (ready, light_state)
    """
    try:
        if not h.use_serial:
            return True, None
        deadline = time.time() + max(1, int(timeout_sec))
        light: str | None = None
        while time.time() < deadline:
            if not h.lab_mode:
                alive = any(
                    t.name == "SerialReader" and t.is_alive() for t in h._threads
                )
                if not alive:
                    return False, None
            light = h.serial.get_light_state()
            if light is not None and _pwr_meta_fresh(
                h.db,
                0,
                max_age_sec=_SCENARIO_PWR_FRESH_SEC,
            ):
                return True, light
            time.sleep(0.5)
        return False, h.serial.get_light_state()
    except Exception as e:
        logger.error("_wait_for_serial_ready 실패: %s", e)
        return False, None


def _preflight_hardware(h: _Harness, c: _Term, scenario: str) -> bool:
    """발표 모드 — Serial·조도·워커 preflight (lab+Mock Serial 은 스킵)."""
    try:
        if h.lab_mode and not h.use_serial:
            return True

        if not h.lab_mode:
            alive = [t.name for t in h._threads if t.is_alive()]
            required = ["AnomalyDetector", "GScomms"]
            if h.use_serial:
                required.insert(0, "SerialReader")
            missing = [n for n in required if n not in alive]
            if missing:
                print(
                    c.wrap(f"  preflight FAIL: 워커 미기동 {missing}", c.RED),
                    file=sys.stderr,
                )
                return False

        if h.use_serial:
            ready, light = _wait_for_serial_ready(h, timeout_sec=_SCENARIO_SERIAL_READY_SEC)
            if not ready:
                print(
                    c.wrap(
                        "  preflight FAIL: 아두이노 미수신 — "
                        f"전력 CSV(SW0~2) + 조도 L,light|dark · 포트 {h.cfg.serial_port}",
                        c.RED,
                    ),
                    file=sys.stderr,
                )
                return False
            print(
                c.wrap(
                    f"  preflight OK — 조도={light} · Serial 전력 갱신 확인",
                    c.DIM,
                ),
            )

        if scenario in (SCENARIO_FALSE_POSITIVE, SCENARIO_ATTACK, SCENARIO_INTEGRITY) and h.use_serial:
            print(
                c.wrap(
                    "  bulk 송신: 조도 dark→light 자동 + 시나리오 종료 시 transmit_all 1회",
                    c.DIM,
                ),
            )
        return True
    except Exception as e:
        logger.error("_preflight_hardware 실패: %s", e)
        return False


def _sync_gs_light_state(h: _Harness) -> None:
    """수동 transmit_all 전후 조도 엣지 중복 송신 방지 — GScomms 와 동일 상태 유지."""
    try:
        if not h.use_serial:
            return
        curr = h.serial.get_light_state()
        dark = demon_config.SERIAL_LIGHT_STATE_DARK
        light = demon_config.SERIAL_LIGHT_STATE_LIGHT
        if curr in (dark, light):
            h.gs_comms._prev_light_state = curr
    except Exception as e:
        logger.error("_sync_gs_light_state 실패: %s", e)


def _scenario_attack_sim(h: _Harness, *, servo_repeats: int | None = None) -> bool:
    """main.py 와 동일 — GScomms.handle_attack_sim 경로."""
    try:
        cmd: dict[str, Any] | None = None
        if servo_repeats is not None:
            cmd = {"servo_repeats": int(servo_repeats)}
        h.gs_comms.handle_attack_sim(cmd)
        return h.attack_sim.is_active or h.detector._attack_mode
    except Exception as e:
        logger.error("_scenario_attack_sim 실패: %s", e)
        return False


def _scenario_recovery(h: _Harness) -> bool:
    """main.py 와 동일 — GScomms.handle_recovery (RECOVERY 커맨드)."""
    try:
        h.gs_comms.handle_recovery()
        return True
    except Exception as e:
        logger.error("_scenario_recovery 실패: %s", e)
        return False


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


def _advance_scenario_event_baseline(h: _Harness) -> None:
    """공격 단계 이벤트를 SEU(오탐) 단계 검증에서 제외."""
    try:
        h.baseline_max_event_id = _max_event_id(h.db_path)
        h.gs_state["last_fpf"] = None
        h.gs_state["last_fpf_event_id"] = -1
        h._scenario_fpf_seen = False
    except Exception as e:
        logger.error("_advance_scenario_event_baseline 실패: %s", e)


def _seu_detected_verified(h: _Harness, events: list[dict[str, Any]], is_n: bool) -> tuple[bool, str]:
    """SEU_DETECTED — DB 잔존 또는 bulk ACK 후 삭제된 insert 이력."""
    try:
        seu = [ev for ev in events if ev.get("EVENT_TYPE") == demon_config.GS_EVENT_SEU_DETECTED]
        if seu:
            return True, f"{len(seu)}건"
        last_eid = int(h.gs_state.get("last_fpf_event_id", -1))
        if is_n and last_eid > h.baseline_max_event_id:
            return True, f"송신·ACK(eid={last_eid})"
        return False, f"{len(seu)}건"
    except Exception as e:
        logger.error("_seu_detected_verified 실패: %s", e)
        return False, "0건"


def _purge_false_positive_attack_events(h: _Harness) -> int:
    """false_positive bulk 송신 전 미전송 ATTACK_CONFIRMED 제거(전환·잔존 큐 정리)."""
    try:
        pending = h.db.get_pending_events()
        removed = 0
        for ev in pending:
            if ev.get("EVENT_TYPE") != demon_config.GS_EVENT_ATTACK_CONFIRMED:
                continue
            event_id = int(ev.get("EVENT_ID", -1))
            if event_id >= 0 and h.db.delete_event(event_id):
                removed += 1
        if removed:
            logger.info("false_positive: 미전송 ATTACK_CONFIRMED %d건 삭제", removed)
        return removed
    except Exception as e:
        logger.error("_purge_false_positive_attack_events 실패: %s", e)
        return 0


def _prepare_false_positive_seu_phase(h: _Harness) -> bool:
    """RECOVERY 후 오탐(SEU) 단계만 재개 — FPF·전력 메타·이벤트 기준선 초기화."""
    try:
        _scenario_recovery(h)
        restore_seu_logical_if_needed(h)
        h.suppress_fpf_for_attack_phase = False
        h.detector._fpf_dispatched = False
        h.fpf.physical._prev_state.clear()
        h.fpf.system._prev_state.clear()
        if not h.db.reset_pwr_anomaly_state():
            logger.warning("reset_pwr_anomaly_state 실패 — SEU 단계 이전 이상 플래그가 남을 수 있음")
        _advance_scenario_event_baseline(h)
        return True
    except Exception as e:
        logger.error("_prepare_false_positive_seu_phase 실패: %s", e)
        return False


def _resolve_pre_transmit_collect_sec(args: argparse.Namespace) -> int:
    """transmit_all 직전 추가 수집 시간(초)."""
    try:
        if args.pre_transmit_sec is not None:
            return max(0, int(args.pre_transmit_sec))
        return int(demon_config.SCENARIO_PRE_TRANSMIT_COLLECT_SEC)
    except (TypeError, ValueError) as e:
        logger.error("_resolve_pre_transmit_collect_sec 입력 오류: %s", e)
        return int(demon_config.SCENARIO_PRE_TRANSMIT_COLLECT_SEC)
    except Exception as e:
        logger.error("_resolve_pre_transmit_collect_sec 실패: %s", e)
        return int(demon_config.SCENARIO_PRE_TRANSMIT_COLLECT_SEC)


def _scenario_transmit_all(
    h: _Harness,
    c: _Term,
    args: argparse.Namespace,
    *,
    section_base: int,
) -> None:
    """지상 bulk 송신 전 추가 수집(UDP flush·history) 후 transmit_all 1회."""
    try:
        collect_sec = _resolve_pre_transmit_collect_sec(args)
        step = int(section_base)
        if collect_sec > 0:
            _print_section(
                c,
                step,
                f"지상 송신 전 데이터 누적 {collect_sec}s — Serial·UDP",
            )
            step += 1
            if h.lab_mode:
                _run_ticks_lab(h, c, count=collect_sec, verbose=args.verbose)
            else:
                print(c.wrap("  워커 계속 기동 — SAT_*_HISTORY 누적", c.DIM))
                _observe(h, c, seconds=collect_sec, verbose=args.verbose)

        _print_section(c, step, "bulk 송신 (GScomms)")
        if not h.lab_mode:
            print(
                c.wrap(
                    "  운영: 조도 dark→light 자동 송신 · 시나리오는 transmit_all 1회 추가",
                    c.DIM,
                ),
            )
        _sync_gs_light_state(h)
        h.gs_comms.transmit_all()
        _sync_gs_light_state(h)
    except Exception as e:
        logger.error("_scenario_transmit_all 실패: %s", e)


def _prepare_clean_baseline(h: _Harness) -> None:
    """직전 시나리오 잔여(물리 bias·공격 ADCS·전력 ANOM) 정리 — normal 등 FPF 미진입 기대 시."""
    try:
        _scenario_recovery(h)
        restore_seu_logical_if_needed(h)
        if not h.db.reset_pwr_anomaly_state():
            logger.warning("reset_pwr_anomaly_state 실패 — normal 시작 전 ANOM 잔존 가능")
        h.detector._fpf_dispatched = False
        h.gs_state["last_fpf"] = None
        h.gs_state["last_fpf_event_id"] = -1
        h._scenario_fpf_seen = False
        h.baseline_max_event_id = _max_event_id(h.db_path)
    except Exception as e:
        logger.error("_prepare_clean_baseline 실패: %s", e)


def run_normal(h: _Harness, c: _Term, args: argparse.Namespace) -> int:
    observe = int(
        args.observe_sec or demon_config.SCENARIO_NORMAL_OBSERVE_SEC_DEFAULT,
    )
    hist0 = _pwr_history_count(h.db_path)

    _print_section(c, 1, f"정상 운용 {observe}s — 실측 Serial·UDP·Detector")
    if not h.lab_mode:
        _prepare_clean_baseline(h)
        print(
            c.wrap(
                "  시작 전 RECOVERY·ADCS/전력 ANOM 정리 (직전 attack/false_positive 잔여 제거)",
                c.DIM,
            ),
        )
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

    _scenario_transmit_all(h, c, args, section_base=2)

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
    observe = int(
        args.observe_sec or demon_config.SCENARIO_NORMAL_OBSERVE_SEC_DEFAULT,
    )
    warmup = int(args.warmup_sec or 5)
    attack_phase_saw_anomaly = False
    bulk_before = 0
    bulk_after = 0
    saved_fpf_weights = _apply_false_positive_fpf_weights(h)
    h.false_positive_mode = True
    h.suppress_fpf_for_attack_phase = True
    h._false_positive_seu_fpf_done = False
    w = fpf_config.FALSE_POSITIVE_SCENARIO_MODULE_WEIGHTS
    print(
        c.wrap(
            f"  FPF 가중치(오탐 실험): P={w['physical']:.2f} S={w['statistical']:.2f} "
            f"Sys={w['system']:.2f} · 단독바이패스(exc1~4) 비활성",
            c.DIM,
        ),
    )
    print(
        c.wrap(
            "  공격 선행: 전력 이상·ATTACK_SIM만 — FPF/이벤트 큐 미등록 (SEU 단계 1회만)",
            c.DIM,
        ),
    )

    exit_code = 1
    try:
        if h.lab_mode:
            _print_section(c, 1, "lab: fpf_attack — 공격·이상탐지 선행")
            if not h.injector.prepare_scenario(SCENARIO_FPF_ATTACK):
                print("fpf_attack 시나리오 주입 실패", file=sys.stderr)
                exit_code = 1
            else:
                _run_ticks_lab(h, c, count=max(3, observe // 3), verbose=args.verbose)
                attack_phase_saw_anomaly = (
                    bool(h.detector.detect_power_anomaly()) or h._scenario_fpf_seen
                )

                _print_section(c, 2, "lab: RECOVERY — 오탐(SEU) 단계")
                h.injector.release_scenario()
                if not _prepare_false_positive_seu_phase(h):
                    print("SEU 단계 준비 실패", file=sys.stderr)
                    exit_code = 1
                elif not h.use_serial and not h.injector.prepare_scenario(SCENARIO_FPF_NATURAL):
                    print("fpf_natural 시나리오 주입 실패", file=sys.stderr)
                    exit_code = 1
                elif h.use_serial and not h.attack_sim.start_seu_physical():
                    print("SEU physical 시작 실패 (SerialReader·pwr_bias 확인)", file=sys.stderr)
                    exit_code = 1
                else:
                    h.install_fpf_natural_patch()
                    restore_seu_logical_if_needed(h)
                    _print_section(c, 3, "lab: AnomalyDetector → FPF (N 기대, 실측 key_set)")
                    _run_ticks_lab(h, c, count=max(3, observe // 3), verbose=args.verbose)
                    bulk_before = int(h.gs_state.get("bulk_attempts", 0))
                    _purge_false_positive_attack_events(h)
                    _scenario_transmit_all(h, c, args, section_base=4)
                    bulk_after = int(h.gs_state.get("bulk_attempts", 0))
                    exit_code = _finalize_false_positive_result(
                        h,
                        c,
                        attack_phase_saw_anomaly=attack_phase_saw_anomaly,
                        bulk_before=bulk_before,
                        bulk_after=bulk_after,
                    )
        else:
            _print_section(c, 1, f"베이스라인 {warmup}s")
            _observe(h, c, seconds=warmup, verbose=args.verbose)
            _print_pwr_table(c, _pwr_rows(h.db))

            _print_section(c, 2, "ATTACK_SIM — 전력 이상탐지 선행 (물리+논리)")
            fp_servo = int(getattr(demon_config, "FALSE_POSITIVE_ATTACK_SERVO_REPEATS", 1))
            print(
                c.wrap(
                    f"  서보 반복(오탐 공격): {fp_servo}회 "
                    f"(일반 공격={getattr(demon_config, 'ATTACK_SIM_SERVO_REPEATS', 5)}회)",
                    c.DIM,
                ),
            )
            if not _scenario_attack_sim(h, servo_repeats=fp_servo):
                print("ATTACK_SIM 시작 실패 (SerialReader·아두이노 확인)", file=sys.stderr)
                exit_code = 1
            else:

                def _poll_attack(_i: int) -> None:
                    nonlocal attack_phase_saw_anomaly
                    if not h._scenario_fpf_seen:
                        h.attack_sim.reinject_logical_attack()
                    if h.detector.detect_power_anomaly():
                        attack_phase_saw_anomaly = True

                _print_section(c, 3, f"공격·이상탐지 관측 {observe}s")
                _observe(h, c, seconds=observe, verbose=args.verbose, poll=_poll_attack)
                attack_phase_saw_anomaly = (
                    attack_phase_saw_anomaly
                    or bool(h.detector.detect_power_anomaly())
                    or h._scenario_fpf_seen
                )

                if not attack_phase_saw_anomaly:
                    print("공격 단계에서 전력 이상 미감지 — 오탐 시나리오 중단", file=sys.stderr)
                    exit_code = 1
                elif not _prepare_false_positive_seu_phase(h):
                    print("SEU 단계 준비 실패", file=sys.stderr)
                    exit_code = 1
                else:
                    _print_section(c, 4, "RECOVERY — 오탐(SEU) 단계만 진행")
                    _print_section(c, 5, "SEU physical — 실측 pwr_bias + 논리(ADCS/TLM) 정상")
                    print(
                        c.wrap(
                            "  attack_mode OFF · gyro/servo OFF · FPF=실측 전력+DB/adcs_series "
                            "(공격 논리 잔존 시에만 ADCS 복원)",
                            c.DIM,
                        ),
                    )
                    h.install_fpf_natural_patch()
                    restore_seu_logical_if_needed(h)
                    if not h.attack_sim.start_seu_physical():
                        print("SEU physical 시작 실패 (SerialReader·pwr_bias 확인)", file=sys.stderr)
                        exit_code = 1
                    else:

                        def _poll_fp(_i: int) -> None:
                            if not h._scenario_fpf_seen:
                                restore_seu_logical_if_needed(h)

                        _print_section(c, 6, f"SEU 관측 {observe}s")
                        _observe(h, c, seconds=observe, verbose=args.verbose, poll=_poll_fp)

                        bulk_before = int(h.gs_state.get("bulk_attempts", 0))
                        _purge_false_positive_attack_events(h)
                        _scenario_transmit_all(h, c, args, section_base=7)
                        bulk_after = int(h.gs_state.get("bulk_attempts", 0))
                        exit_code = _finalize_false_positive_result(
                            h,
                            c,
                            attack_phase_saw_anomaly=attack_phase_saw_anomaly,
                            bulk_before=bulk_before,
                            bulk_after=bulk_after,
                        )
    finally:
        _restore_false_positive_fpf_weights(h, saved_fpf_weights)
        h.false_positive_mode = False
        h.suppress_fpf_for_attack_phase = False
        h._false_positive_seu_fpf_done = False

    return exit_code


def _finalize_false_positive_result(
    h: _Harness,
    c: _Term,
    *,
    attack_phase_saw_anomaly: bool,
    bulk_before: int,
    bulk_after: int,
) -> int:
    new_events = _scenario_events(h)
    attack = [ev for ev in new_events if ev.get("EVENT_TYPE") == demon_config.GS_EVENT_ATTACK_CONFIRMED]
    fpf_last = h.gs_state.get("last_fpf")
    is_n = isinstance(fpf_last, dict) and str(fpf_last.get("is_attack")) == "N"
    had_anomaly = bool(h.detector.detect_power_anomaly()) or h._scenario_fpf_seen
    seu_ok, seu_detail = _seu_detected_verified(h, new_events, is_n)

    bulk_ok = bulk_after > bulk_before or not h.lab_mode
    ok = (
        attack_phase_saw_anomaly
        and had_anomaly
        and seu_ok
        and not attack
        and is_n
        and bulk_ok
    )

    _print_result_block(
        c,
        checks=[
            ("공격·이상탐지(선행)", attack_phase_saw_anomaly, ""),
            ("SEU 단계 이상·FPF 진입", had_anomaly, ""),
            ("FPF 판정 N", is_n, ""),
            ("SEU_DETECTED", seu_ok, seu_detail),
            ("SEU 단계 ATTACK_CONFIRMED 없음", not attack, ""),
            ("bulk 송신 (GScomms)", bulk_ok, f"{bulk_before}→{bulk_after}"),
        ],
        overall_ok=ok,
        events=new_events,
        fpf_last=fpf_last,
        extra_lines=[
            f"GS {h.cfg.gs_host}:{h.cfg.gs_port}",
        ],
    )
    return 0 if ok else 1


def _prepare_integrity_scenario(h: _Harness) -> None:
    """integrity 시작 — 공격 ADCS 잔여·FPF 이력 정리 (ATTACK_HASH 전)."""
    try:
        restore_seu_logical_if_needed(h)
        h.detector._fpf_dispatched = False
        h.gs_state["last_fpf"] = None
        h.gs_state["last_fpf_event_id"] = -1
        h._scenario_fpf_seen = False
        h.baseline_max_event_id = _max_event_id(h.db_path)
    except Exception as e:
        logger.error("_prepare_integrity_scenario 실패: %s", e)


def _warn_integrity_baseline_matches_inject(h: _Harness, integrity_dir: Path) -> None:
    """cf 주입 직후 baseline과 해시가 같으면 경고 (무결성 시나리오 실패 원인)."""
    try:
        rec = h.db.get_integrity_hash(int(demon_config.INTEGRITY_DIR_FILE_ID))
        if rec is None:
            return
        expected = str(rec.get("EXPECTED_HASH", "")).strip().lower()
        if not expected:
            return
        actual = compute_directory_manifest_hash(integrity_dir)
        if actual is not None and actual.lower() == expected:
            logger.warning(
                "cf 주입 후에도 baseline 해시와 동일 — "
                "주입 파일 포함 상태로 --seed 했을 수 있음. "
                "matador_gs_inject.txt 삭제 후 seed_cf_integrity 재실행 권장",
            )
    except Exception as e:
        logger.error("_warn_integrity_baseline_matches_inject 실패: %s", e)


def run_integrity(h: _Harness, c: _Term, args: argparse.Namespace) -> int:
    integrity_dir = Path(h.ctx.config.integrity_target_dir).expanduser()
    observe = int(args.observe_sec or demon_config.SCENARIO_NORMAL_OBSERVE_SEC_DEFAULT)

    if not h.lab_mode:
        _prepare_integrity_scenario(h)
        print(
            c.wrap(
                "  종료 시 pre-transmit 수집 + transmit_all 1회 → GS bulk "
                "(INTEGRITY 이벤트·SAT_INTEGRITY_HASH 포함)",
                c.DIM,
            ),
        )

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
    if h.lab_mode and not h.use_serial:
        if not h.attack_sim.start_hash():
            print("ATTACK_HASH 시작 실패", file=sys.stderr)
            return 1
    else:
        h.gs_comms.handle_attack_hash()
        if not h.attack_sim.is_active:
            print("ATTACK_HASH 시작 실패 (SerialReader·cf 확인)", file=sys.stderr)
            return 1

    _warn_integrity_baseline_matches_inject(h, integrity_dir)

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
    fpf_last = h.gs_state.get("last_fpf")

    bulk_before = int(h.gs_state.get("bulk_attempts", 0))
    _scenario_transmit_all(h, c, args, section_base=4)
    bulk_after = int(h.gs_state.get("bulk_attempts", 0))
    bulk_ok = bulk_after > bulk_before or not h.lab_mode

    ok = state["saw_anomaly"] and bool(integrity_ev) and fpf_last is None and bulk_ok

    _print_result_block(
        c,
        checks=[
            ("전력 이상 감지", state["saw_anomaly"], ""),
            ("INTEGRITY 이벤트", bool(integrity_ev), integrity_ev[0].get("EVENT_TYPE") if integrity_ev else ""),
            ("FPF 미진입", fpf_last is None, ""),
            ("bulk 송신 (GScomms)", bulk_ok, f"{bulk_before}→{bulk_after}"),
        ],
        overall_ok=ok,
        events=new_events,
        fpf_last=fpf_last,
        extra_lines=[
            f"GS {h.cfg.gs_host}:{h.cfg.gs_port}",
            f"integrity_dir={integrity_dir}",
        ],
    )
    return 0 if ok else 1


def run_attack(h: _Harness, c: _Term, args: argparse.Namespace) -> int:
    warmup = int(args.warmup_sec or 5)
    observe = int(args.observe_sec or demon_config.SCENARIO_NORMAL_OBSERVE_SEC_DEFAULT)
    saved_fpf = _apply_attack_fpf_demo_mode(h)
    print(
        c.wrap(
            "  FPF(attack): exc 1~5 미표시 · score=1.0 단독바이패스 없음 · 가중합으로 Y",
            c.DIM,
        ),
    )
    if not h.lab_mode:
        print(
            c.wrap(
                "  종료 시 pre-transmit 수집 + transmit_all 1회 → GS bulk (normal·오탐과 동일)",
                c.DIM,
            ),
        )

    exit_code = 1
    try:
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
            if not _scenario_attack_sim(h):
                print("ATTACK_SIM 시작 실패 (SerialReader·아두이노 확인)", file=sys.stderr)
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

        bulk_before = int(h.gs_state.get("bulk_attempts", 0))
        _scenario_transmit_all(h, c, args, section_base=4)
        bulk_after = int(h.gs_state.get("bulk_attempts", 0))

        new_events = _scenario_events(h)
        fpf_last = h.gs_state.get("last_fpf")
        is_y = isinstance(fpf_last, dict) and str(fpf_last.get("is_attack")) == "Y"
        exc_ok = not isinstance(fpf_last, dict) or int(fpf_last.get("exception_code", 0)) == 0
        bulk_ok = bulk_after > bulk_before or not h.lab_mode
        ok = state["saw_anomaly"] and is_y and exc_ok and bulk_ok
        exit_code = 0 if ok else 1

        _print_result_block(
            c,
            checks=[
                ("전력 이상 감지", state["saw_anomaly"], str(_anomaly_sw_list(h.detector.detect_power_anomaly()))),
                ("FPF 판정 Y", is_y, ""),
                ("exc=0 (1~5 없음)", exc_ok, str(fpf_last.get("exception_code")) if fpf_last else ""),
                ("bulk 송신 (GScomms)", bulk_ok, f"{bulk_before}→{bulk_after}"),
            ],
            overall_ok=ok,
            events=new_events,
            fpf_last=fpf_last,
            extra_lines=[
                f"GS {h.cfg.gs_host}:{h.cfg.gs_port}",
                f"UDP :{h.cfg.udp_tlm_bind[1]}",
                f"SAT_ADCS_FILTER {len(h.db.get_adcs_filter_all())}행",
            ],
        )
    finally:
        _restore_attack_fpf_demo_mode(h, saved_fpf)

    return exit_code


def main() -> int:
    _fix_stdout_encoding()

    parser = argparse.ArgumentParser(description="파이프라인 시나리오 4종 (발표=운영 DB·실워커)")
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("--observe-sec", type=int, default=None)
    parser.add_argument(
        "--pre-transmit-sec",
        type=int,
        default=None,
        help=(
            "transmit_all 직전 추가 수집(초). "
            f"기본 {demon_config.SCENARIO_PRE_TRANSMIT_COLLECT_SEC} "
            f"(시나리오 관측 기본 {demon_config.SCENARIO_NORMAL_OBSERVE_SEC_DEFAULT}s)"
        ),
    )
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

    if not _preflight_hardware(h, c, args.scenario):
        h.stop()
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
