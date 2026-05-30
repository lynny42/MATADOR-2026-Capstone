#!/usr/bin/env python3
"""run_fpf_experiment — 오탐 필터 Mock/실DB 실험.

사용
    cd <repo_root>
    python3 -m demon.workers.false_positive_filter.run_fpf_experiment
    python3 -m demon.workers.false_positive_filter.run_fpf_experiment --mock
    python3 -m demon.workers.false_positive_filter.run_fpf_experiment --full
    python3 -m demon.workers.false_positive_filter.run_fpf_experiment --db-path /tmp/fpf_test.db

통합 시나리오 (기본, 실DB)
    fpf_natural  — 전력 이상(앞단) + ADCS/TLM 정상 → FPF 기대 N (자연현상)
    fpf_attack   — 전력 이상 + AttackSimulator 논리 변조 → FPF 기대 Y (공격)
    시나리오 주입 시 DB 누적(freeze) 중지, 최종 DB 는 주입값만 반영.

GitHub 반영 전 로컬 검증용. 운영 데몬 경로(main.py)와 별개.
"""

from __future__ import annotations

import argparse
import logging
import sys
import tempfile
from pathlib import Path
from typing import Any

from . import config
from .experiment_db import ExperimentMockDB, try_real_db
from .false_positive_filter import FalsePositiveFilter
from .fpf_scenario_injector import (
    FpfScenarioInjector,
    INTEGRATION_SCENARIOS,
    SCENARIO_EXPECTED_ATTACK,
    SCENARIO_FPF_ATTACK,
    SCENARIO_FPF_NATURAL,
)
from .physical_consistency_module import PhysicalConsistencyModule
from .statistical_consistency_module import StatisticalConsistencyModule
from .system_response_module import SystemResponseModule

# 표 컬럼 (이름, 너비)
_COLS = (
    ("시나리오", 22),
    ("기대", 4),
    ("Y/N", 4),
    ("score", 7),
    ("weight", 7),
    ("exc", 5),
    ("P", 7),
    ("S", 7),
    ("Sys", 7),
)

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


class _C:
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


def _enable_ansi_windows() -> bool:
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


class _PrintGScomms:
    def __init__(self):
        self.last_payload: dict | None = None

    def insert_event(self, payload: dict) -> None:
        self.last_payload = payload


def _base_key_set(db=None) -> dict:
    key = {
        "tlm_id": 1,
        "sw_id": config.PWR_SW_ID_ADCS,
        "channel1": config.CHANNEL1_DEFAULT,
        "event_id": 1,
        "detected_at": "2026-05-12T12:00:00Z",
    }
    series = getattr(db, "_adcs_series", None) if db is not None else None
    if isinstance(series, list) and series:
        key[config.KEY_ADCS_SERIES] = series
    return key


def build_fpf(db) -> FalsePositiveFilter:
    return FalsePositiveFilter(
        physical=PhysicalConsistencyModule(db),
        statistical=StatisticalConsistencyModule(db),
        system=SystemResponseModule(db),
        gs_comms=_PrintGScomms(),
    )


def _row_line(c: _C, cells: list[str], yn: str | None = None, expect: str | None = None) -> str:
    parts = []
    for (name, width), val in zip(_COLS, cells):
        text = val[:width].ljust(width)
        if name == "Y/N" and yn is not None:
            if yn == "Y":
                text = c.wrap(text, c.BOLD, c.RED)
            else:
                text = c.wrap(text, c.CYAN)
        if name == "기대" and expect is not None and yn is not None and expect == yn:
            text = c.wrap(text, c.GREEN)
        parts.append(text)
    return "  ".join(parts)


def _print_table(c: _C, rows: list[dict]) -> None:
    header = _row_line(c, [name for name, _ in _COLS])
    sep = "-" * len(header)
    print(c.wrap(header, c.BOLD))
    print(c.wrap(sep, c.DIM))
    for r in rows:
        exc = r["exception_code"]
        exc_txt = f"{exc}({_EXC_LABEL.get(exc, '?')})"
        print(
            _row_line(
                c,
                [
                    r["label"],
                    r.get("expected") or "-",
                    r["is_attack"],
                    f"{r['weighted_score']:.3f}",
                    str(r["weight"]),
                    exc_txt,
                    f"{r['P']:.3f}",
                    f"{r['S']:.3f}",
                    f"{r['Sys']:.3f}",
                ],
                yn=r["is_attack"],
                expect=r.get("expected"),
            )
        )


def _print_conclusion(c: _C, rows: list[dict], *, integration: bool) -> None:
    y_cnt = sum(1 for r in rows if r["is_attack"] == "Y")
    n_cnt = len(rows) - y_cnt

    print()
    print(c.wrap("─" * 72, c.DIM))
    print(c.wrap("[ 최종 결론 ]", c.BOLD, c.YELLOW))
    print(f"  시나리오 {len(rows)}건  |  공격(Y) {y_cnt}건  |  비공격(N) {n_cnt}건")

    if integration:
        ok_rows = [r for r in rows if r.get("expected") == r["is_attack"]]
        if len(ok_rows) == len(rows):
            msg = "  통합 시나리오 판정 일치 (전력 이상 → FPF N/Y 변별 OK)"
            print(c.wrap(msg, c.BOLD, c.GREEN))
        else:
            msg = "  통합 시나리오 기대와 불일치 — fpf_scenario_injector·임계치 확인"
            print(c.wrap(msg, c.BOLD, c.RED))
            for r in rows:
                if r.get("expected") != r["is_attack"]:
                    print(
                        c.wrap(
                            f"    · {r['label']}: 기대={r.get('expected')} 실제={r['is_attack']}",
                            c.YELLOW,
                        )
                    )
    else:
        varied = len({r["is_attack"] for r in rows}) > 1 or len({r["weighted_score"] for r in rows}) > 1
        normal_row = next((r for r in rows if r["label"] == "normal"), None)
        attack_rows = [r for r in rows if r["label"] != "normal"]
        normal_ok = normal_row is not None and normal_row["is_attack"] == "N"
        attacks_ok = bool(attack_rows) and all(r["is_attack"] == "Y" for r in attack_rows)
        if normal_ok and attacks_ok and varied:
            msg = "  정상=N · 공격=Y 구분 성공 → Mock 시나리오별 변별 동작 정상"
            print(c.wrap(msg, c.BOLD, c.GREEN))
        elif varied:
            msg = "  판정이 시나리오별로 달라짐 (정상/공격 구분은 일부 확인 필요)"
            print(c.wrap(msg, c.BOLD, c.YELLOW))
        else:
            msg = "  모든 시나리오 결과가 동일 → Mock/데이터 설정을 확인하세요"
            print(c.wrap(msg, c.BOLD, c.RED))

    print(c.wrap("  (exc: 0정상 1사원수 2토크 3휠 4다채널 5누락 6모드 7경로)", c.DIM))


def run_once(
    fpf: FalsePositiveFilter,
    key_set: dict,
    label: str,
    *,
    expected: str | None = None,
) -> dict:
    result = fpf.run_false_positive_filter(key_set)
    ms = result.get("module_scores", {})
    return {
        "label": label,
        "expected": expected,
        "is_attack": result["is_attack"],
        "weighted_score": result["weighted_score"],
        "weight": config.weighted_score_to_gs_int(result["weighted_score"]),
        "exception_code": int(result["exception_code"]),
        "P": float(ms.get("physical", 0.0)),
        "S": float(ms.get("statistical", 0.0)),
        "Sys": float(ms.get("system", 0.0)),
    }


def _skip_label(label: str) -> bool:
    return label.endswith("_prime") or label == "prime_system"


def _fix_stdout_encoding() -> None:
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _open_real_db(db_path: Path | None) -> tuple[Any | None, str]:
    if db_path is None:
        db_path = Path(tempfile.mkdtemp(prefix="fpf_exp_")) / "fpf_experiment.db"
    db = try_real_db(db_path)
    if db is None:
        return None, "real-db 실패"
    return db, f"SQLite ({db_path})"


def run_integration_experiment(fpf: FalsePositiveFilter, db, c: _C) -> list[dict]:
    injector = FpfScenarioInjector(db)
    table_rows: list[dict] = []

    for scenario in INTEGRATION_SCENARIOS:
        fpf.physical._prev_state.clear()
        fpf.system._prev_state.clear()

        if scenario == SCENARIO_FPF_ATTACK:
            run_once(fpf, injector.build_key_set(SCENARIO_FPF_NATURAL), f"{scenario}_prime")

        if not injector.prepare_scenario(scenario):
            print(c.wrap(f"  시나리오 주입 실패: {scenario}", c.RED))
            continue

        key = injector.build_key_set(scenario)
        expected = SCENARIO_EXPECTED_ATTACK.get(scenario)
        row = run_once(fpf, key, scenario, expected=expected)
        row["db_frozen"] = db.is_accumulation_frozen()
        table_rows.append(row)

        if scenario == SCENARIO_FPF_NATURAL:
            blocked = db.upsert_pwr_meta(
                {"sw_id": 0, "voltage": 9.99, "current_a": 9.99},
            )
            meta = db.get_pwr_meta(0)
            row["accum_blocked"] = blocked and float(meta.get("VOLTAGE", 0)) < 5.0

    injector.release_scenario()
    return table_rows


def run_mock_experiment(fpf: FalsePositiveFilter, db, *, full: bool) -> list[dict]:
    table_rows: list[dict] = []

    scenarios = [
        ("normal", "normal"),
        ("attack_torque", "attack_torque"),
        ("attack_multi", "attack_multi_channel"),
        ("attack_quat", "attack_quaternion"),
        ("attack_sys_pkt", "attack_system_packet"),
        ("attack_qerr", "attack_qerr_diverge"),
    ]
    if not full:
        scenarios = [("normal", "normal"), ("attack_torque", "attack_torque")]

    key = _base_key_set(db)
    for label, scen in scenarios:
        if hasattr(db, "set_scenario"):
            db.set_scenario(scen)
        key = _base_key_set(db)
        if scen == "attack_torque":
            fpf.physical._prev_state.clear()
            run_once(fpf, key, f"{label}_prime")
        if scen == "attack_system_packet":
            fpf.system._prev_state.clear()
            if hasattr(db, "set_scenario"):
                db.set_scenario("attack_system_packet_prime")
            run_once(fpf, _base_key_set(db), f"{label}_prime")
            if hasattr(db, "set_scenario"):
                db.set_scenario(scen)
            key = _base_key_set(db)
        row = run_once(fpf, key, label)
        if not _skip_label(label):
            table_rows.append(row)

    if full and hasattr(db, "set_scenario"):
        db.set_scenario("normal")
        fpf.system._prev_state.clear()
        run_once(fpf, key, "prime_system")
        db.set_scenario("attack_mode_change")
        if getattr(db, "_adcs", None):
            db._adcs["CMDCOUNTER"] = db._adcs.get("CMDCOUNTER", 10)
        table_rows.append(run_once(fpf, key, "attack_mode_change"))

    return table_rows


def main() -> int:
    _fix_stdout_encoding()
    p = argparse.ArgumentParser(description="오탐 필터 Mock/실DB 실험")
    p.add_argument(
        "--mock",
        action="store_true",
        help="ExperimentMockDB 사용 (Windows 단독 개발용)",
    )
    p.add_argument(
        "--full",
        action="store_true",
        help="Mock 전체 시나리오 표 (--mock 와 함께)",
    )
    p.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="실DB SQLite 경로 (미지정 시 임시 파일)",
    )
    p.add_argument("--no-color", action="store_true", help="색상 끄기")
    p.add_argument("-v", "--verbose", action="store_true", help="모듈 경고 로그 표시")
    args = p.parse_args()

    use_color = not args.no_color and _enable_ansi_windows()
    c = _C(use_color)

    log_level = logging.INFO if args.verbose else logging.ERROR
    logging.basicConfig(level=log_level, format="%(levelname)s %(message)s")
    logging.getLogger(config.LOGGER_NAME).setLevel(log_level)

    integration_mode = not args.mock

    if integration_mode:
        db, db_src = _open_real_db(args.db_path)
        if db is None:
            print(c.wrap("실DB 초기화 실패 — --mock 으로 Mock 실험 가능", c.RED))
            return 1
    else:
        db_src = "MockDB"
        db = ExperimentMockDB("normal")

    mode_label = "통합(실DB)" if integration_mode else "Mock"
    print(c.wrap(f"오탐 필터 실험 [{mode_label}]  |  데이터: {db_src}", c.BOLD, c.CYAN))
    if integration_mode:
        print(
            c.wrap(
                "  시나리오: fpf_natural(N) / fpf_attack(Y) — 주입 후 DB 누적 중지",
                c.DIM,
            )
        )
    print()

    fpf = build_fpf(db)

    if integration_mode:
        table_rows = run_integration_experiment(fpf, db, c)
    else:
        table_rows = run_mock_experiment(fpf, db, full=args.full)

    _print_table(c, table_rows)
    _print_conclusion(c, table_rows, integration=integration_mode)

    if integration_mode:
        natural = next((r for r in table_rows if r["label"] == SCENARIO_FPF_NATURAL), None)
        if natural and natural.get("accum_blocked"):
            print(c.wrap("  DB freeze 확인: 시나리오 후 upsert_pwr_meta 차단됨", c.DIM))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
