#!/usr/bin/env python3
"""
공격 시뮬 → 전력 이상 → 다음 단계(오탐필터/이벤트) 확인.

    python3 -m demon.run_attack_pipeline_check
    python3 -m demon.run_attack_pipeline_check --no-hardware   # DB만 모의
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

from demon import config as demon_config
from demon.core.context import DaemonConfig, RuntimeContext
from demon.db.db_manager import DBManager
from demon.workers.anomaly_detector import AnomalyDetector
from demon.workers.attack_simulator import AttackSimulator
from demon.workers.serial_reader import SerialReader

logger = logging.getLogger(__name__)


def _pwr_snapshot(db: DBManager) -> str:
    lines = []
    for row in db.get_pwr_meta_all():
        if int(row["SW_ID"]) > 2:
            continue
        lines.append(
            f"SW_{row['SW_ID']}: V={row['VOLTAGE']:.3f} "
            f"exceed={row['EXCEED_COUNT']} ANOMALY={row['ANOMALY_FLAG']}",
        )
    return " | ".join(lines) if lines else "(no data)"


def _pending_events(db: DBManager) -> list[dict]:
    try:
        return db.get_pending_events()
    except Exception:
        return []


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser()
    parser.add_argument("--warmup-sec", type=int, default=5, help="공격 전 베이스라인(초)")
    parser.add_argument("--attack-sec", type=int, default=12, help="공격 후 관측(초)")
    parser.add_argument("--no-hardware", action="store_true", help="시리얼 없이 DB 모의")
    parser.add_argument("--port", type=str, default=None)
    args = parser.parse_args()

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

    print(f"DB: {db_path}")
    print(f"모드: {'하드웨어+시리얼' if use_serial else '모의(수동 upsert)'}")
    print()

    # 베이스라인
    print(f"=== [1] 베이스라인 {args.warmup_sec}s ===")
    for _ in range(args.warmup_sec):
        detector._tick()
        time.sleep(1.0)
    print(_pwr_snapshot(db))
    anomaly0 = detector.detect_power_anomaly()
    print(f"이상: {anomaly0 or '없음'}\n")

    # 공격
    print("=== [2] AttackSimulator.start() ===")
    if use_serial:
        if not attack_sim.start():
            print("AttackSimulator.start 실패", file=sys.stderr)
            return 1
    else:
        detector.set_attack_mode(True)
        # SW_0: 정상 → ATTACK 수준 전압 (임계 HI 3.45 초과) + delta > 0.1
        for v in (3.27, 4.20, 4.50, 4.55):
            db.upsert_pwr_meta({"sw_id": 0, "voltage": v, "current_a": 0.001})
            detector._tick()
            time.sleep(0.3)
        print("(모의) SW_0 전압 스텝 + attack_mode=True")

    # 관측
    print(f"\n=== [3] 공격 후 {args.attack_sec}s (tick + 파이프라인) ===")
    saw_anomaly = False
    saw_fpf_log = False
    for i in range(1, args.attack_sec + 1):
        detector._tick()
        anomaly = detector.detect_power_anomaly()
        if anomaly:
            saw_anomaly = True
        print(f"  tick {i}: {_pwr_snapshot(db)}")
        if anomaly:
            print(f"         >>> 이상 sw_id_list={anomaly.get('sw_id_list')}")
        time.sleep(1.0)

    events = _pending_events(db)
    adcs_n = len(db.get_adcs_filter_all())

    print("\n=== [4] 다음 단계 점검 ===")
    print(f"  전력 이상 감지:     {'PASS' if saw_anomaly else 'FAIL (ANOMALY_FLAG 미발생)'}")
    print(f"  SAT_ADCS_FILTER:    {adcs_n}행 (이상 구간 누적)")
    print(f"  SAT_EVENT_QUEUE:    {len(events)}건 pending")
    if events:
        for ev in events[:3]:
            print(
                f"    - id={ev.get('EVENT_ID')} type={ev.get('EVENT_TYPE')} "
                f"priority={ev.get('PRIORITY')} sw={ev.get('SW_ID')}",
            )

    try:
        from demon.filter.false_positive_filter import FalsePositiveFilter  # noqa: F401
        fpf_status = "구현됨 (로그에 '오탐필터 전달' 확인)"
    except ImportError:
        fpf_status = "미구현 — anomaly_detector가 FPF 스킵 후 _fpf_dispatched=True (정상)"

    print(f"  오탐필터(FPF):      {fpf_status}")
    print(
        "  기대: 이상 시 verify_hash → FPF.on_anomaly_detected "
        "→ (FPF 있으면) GScomms.insert_event",
    )

    print("\n=== [5] AttackSimulator.stop() ===")
    if use_serial:
        attack_sim.stop()
    else:
        attack_sim.stop()
        detector.set_attack_mode(False)

    shutdown.set()
    if t_serial is not None:
        t_serial.join(timeout=3.0)

    conn = sqlite3.connect(db_path)
    hist = conn.execute("SELECT COUNT(*) FROM SAT_PWR_HISTORY").fetchone()[0]
    conn.close()
    print(f"\nSAT_PWR_HISTORY snapshots={hist}")
    print(f"종합: {'파이프라인 OK' if saw_anomaly else '전력 이상 미탐지 — 펌웨어/임계치 확인'}")

    return 0 if saw_anomaly else 1


if __name__ == "__main__":
    raise SystemExit(main())
