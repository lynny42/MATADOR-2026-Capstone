#!/usr/bin/env python3
"""
아두이노 시리얼 → SAT_PWR_META → 전력 이상 탐지 라이브 검증.

저장소 루트에서 실행:

    python3 -m demon.run_pwr_anomaly_live
    python3 -m demon.run_pwr_anomaly_live --seconds 30 --attack

옵션:
    --seconds N   수집·탐지 시간(초, 기본 20)
    --attack      중간에 AttackSimulator.start() (JSON pwr_bias/gyro/servo)
    --port PATH   시리얼 포트 (기본 config.SERIAL_PORT)
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


def _print_pwr_meta(db: DBManager) -> None:
    rows = db.get_pwr_meta_all()
    print("--- SAT_PWR_META ---")
    for row in rows:
        print(
            f"  SW_{row['SW_ID']}: V={row['VOLTAGE']:.3f} A={row['CURRENT_A']:.4f} "
            f"ΔV={row['CURR_DELTA_V']:.4f} exceed={row['EXCEED_COUNT']} "
            f"consec={row['CONSECUTIVE_EXCEED']} ANOMALY={row['ANOMALY_FLAG']}"
        )


def _print_anomaly_result(detector: AnomalyDetector) -> None:
    result = detector.detect_power_anomaly()
    if result:
        print(f"  >>> 이상 감지: sw_id_list={result.get('sw_id_list')}")
    else:
        print("  >>> 이상 없음 (ANOMALY_FLAG=0 전 채널)")


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    parser = argparse.ArgumentParser(description="전력 이상 탐지 라이브 검증")
    parser.add_argument("--seconds", type=int, default=20, help="실행 시간(초)")
    parser.add_argument("--attack", action="store_true", help="AttackSimulator 시작/종료")
    parser.add_argument("--port", type=str, default=None, help="시리얼 포트")
    args = parser.parse_args()

    db_path = Path(tempfile.mkdtemp()) / "pwr_live.db"
    cfg = DaemonConfig(db_path=db_path)
    if args.port:
        cfg.serial_port = args.port

    db = DBManager(db_path)
    if not db.init_db():
        print("DB init 실패", file=sys.stderr)
        return 1

    shutdown = threading.Event()
    ctx = RuntimeContext(config=cfg, shutdown_event=shutdown, db=db)
    serial = SerialReader(ctx)
    detector = AnomalyDetector(ctx)
    attack_sim = AttackSimulator(ctx)
    attack_sim.set_serial_reader(serial)
    attack_sim.set_anomaly_detector(detector)

    print(f"DB: {db_path}")
    print(f"Serial: {cfg.serial_port} @ {cfg.serial_baud}")
    print(f"임계치 LO/HI (0~2): {cfg.v_threshold_lo[:3]} / {cfg.v_threshold_hi[:3]}")
    print(f"EXCEED_COUNT_THRESHOLD={cfg.exceed_count_threshold}, delta>|0.1|")
    print()

    t_serial = threading.Thread(target=serial.run, name="SerialReader", daemon=True)
    t_serial.start()
    time.sleep(2.0)

    if not t_serial.is_alive():
        print("SerialReader 스레드가 종료됨 — 포트 확인 필요", file=sys.stderr)
        return 1

    ticks = max(1, args.seconds)
    attack_sent = False
    for i in range(1, ticks + 1):
        if args.attack and i == max(3, ticks // 2) and not attack_sent:
            print("\n>>> AttackSimulator.start()")
            attack_sim.start()
            attack_sent = True

        detector._tick()
        print(f"\n[tick {i}/{ticks}]")
        _print_pwr_meta(db)
        _print_anomaly_result(detector)
        time.sleep(1.0)

    if args.attack and attack_sent:
        print("\n>>> AttackSimulator.stop()")
        attack_sim.stop()
        for _ in range(3):
            detector._tick()
            time.sleep(1.0)
        _print_pwr_meta(db)
        _print_anomaly_result(detector)

    shutdown.set()
    t_serial.join(timeout=5.0)

    conn = sqlite3.connect(db_path)
    hist = conn.execute("SELECT COUNT(*) FROM SAT_PWR_HISTORY").fetchone()[0]
    ch = conn.execute("SELECT COUNT(*) FROM SAT_PWR_HISTORY_CHANNEL").fetchone()[0]
    conn.close()
    print(f"\nSAT_PWR_HISTORY snapshots={hist}, channel_rows={ch}")
    print(f"DB 파일: {db_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
