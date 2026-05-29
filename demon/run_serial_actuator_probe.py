#!/usr/bin/env python3
"""
아두이노 자이로/서보 JSON 명령 + 전력 실측 + config 임계치 대조.

    python3 -m demon.run_serial_actuator_probe
    python3 -m demon.run_serial_actuator_probe --servo-repeats 5 --servo-angle 90
"""
from __future__ import annotations

import argparse
import logging
import statistics
import sys
import tempfile
import threading
import time
from collections import defaultdict
from pathlib import Path

from demon import config as demon_config
from demon.core.context import DaemonConfig, RuntimeContext
from demon.db.db_manager import DBManager
from demon.workers.anomaly_detector import AnomalyDetector
from demon.workers.serial_reader import SerialReader

logger = logging.getLogger(__name__)

_SW_LABELS = {
    0: "MPU(자이로) rail",
    1: "RPi rail",
    2: "Servo rail",
    3: "(미사용/조도)",
}


def _phase_stats(db: DBManager) -> dict[int, dict[str, float]]:
    out: dict[int, dict[str, float]] = {}
    for row in db.get_pwr_meta_all():
        sw = int(row["SW_ID"])
        out[sw] = {
            "voltage": float(row["VOLTAGE"]),
            "current_a": float(row["CURRENT_A"]),
            "delta_v": float(row["CURR_DELTA_V"]),
            "anomaly_flag": int(row["ANOMALY_FLAG"]),
        }
    return out


def _in_threshold(sw_id: int, voltage: float, lo: list[float], hi: list[float]) -> bool:
    return lo[sw_id] <= voltage <= hi[sw_id]


def _print_threshold_report(
    samples: dict[int, list[tuple[float, float]]],
    lo: list[float],
    hi: list[float],
) -> None:
    print("\n=== 임계치 대조 (실측 vs config) ===")
    print(f"config V_THRESHOLD_LO = {lo}")
    print(f"config V_THRESHOLD_HI = {hi}")
    print()
    for sw_id in range(demon_config.PWR_SW_ID_COUNT):
        pts = samples.get(sw_id, [])
        label = _SW_LABELS.get(sw_id, f"SW_{sw_id}")
        if not pts:
            print(f"  SW_{sw_id} ({label}): 샘플 없음")
            continue
        volts = [v for v, _ in pts]
        amps = [a for _, a in pts]
        vmin, vmax = min(volts), max(volts)
        vmean = statistics.mean(volts)
        amean = statistics.mean(amps)
        amax = max(amps)
        in_range = sum(1 for v in volts if _in_threshold(sw_id, v, lo, hi))
        pct = 100.0 * in_range / len(volts) if volts else 0.0
        status = "OK" if pct >= 95 else "임계치 불일치"
        print(
            f"  SW_{sw_id} ({label}): V {vmin:.3f}~{vmax:.3f} (avg {vmean:.3f}) "
            f"| A avg {amean:.4f} max {amax:.4f} "
            f"| config 범위 내 {in_range}/{len(volts)} ({pct:.0f}%) → {status}",
        )
        margin = 0.15
        suggest_lo = round(max(0.0, vmin - margin), 2)
        suggest_hi = round(min(demon_config.VOLTAGE_MAX, vmax + margin), 2)
        print(f"       제안 임계: LO={suggest_lo}, HI={suggest_hi}  (±{margin}V 여유)")


def _collect_phase(
    db: DBManager,
    detector: AnomalyDetector,
    seconds: int,
    samples: dict[int, list[tuple[float, float]]],
) -> None:
    for _ in range(seconds):
        detector._tick()
        for row in db.get_pwr_meta_all():
            sw = int(row["SW_ID"])
            v = float(row["VOLTAGE"])
            a = float(row["CURRENT_A"])
            if v > 0.01 or a > 0.0001:
                samples[sw].append((v, a))
        time.sleep(1.0)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="자이로/서보 + 전력·임계치 프로브")
    parser.add_argument("--baseline-sec", type=int, default=8, help="베이스라인 수집(초)")
    parser.add_argument("--gyro-sec", type=int, default=8, help="자이로 ON 후 수집(초)")
    parser.add_argument("--servo-repeats", type=int, default=3, help="서보 반복 횟수")
    parser.add_argument("--servo-angle", type=int, default=90, help="서보 각도 0~180")
    parser.add_argument("--after-servo-sec", type=int, default=10, help="서보 동작 후 수집(초)")
    args = parser.parse_args()

    db_path = Path(tempfile.mkdtemp()) / "actuator_probe.db"
    cfg = DaemonConfig(db_path=db_path)
    db = DBManager(db_path)
    if not db.init_db():
        print("DB init 실패", file=sys.stderr)
        return 1

    shutdown = threading.Event()
    ctx = RuntimeContext(config=cfg, shutdown_event=shutdown, db=db)
    serial = SerialReader(ctx)
    detector = AnomalyDetector(ctx)
    samples: dict[int, list[tuple[float, float]]] = defaultdict(list)

    print(f"Serial: {cfg.serial_port} @ {cfg.serial_baud}")
    print(f"DB: {db_path}\n")

    t_serial = threading.Thread(target=serial.run, daemon=True)
    t_serial.start()
    time.sleep(3.0)

    if not t_serial.is_alive():
        print("SerialReader 종료 — /dev/ttyUSB0 확인", file=sys.stderr)
        return 1

    print(f"=== [1] 베이스라인 {args.baseline_sec}s (자이로 OFF, 서보 정지) ===")
    _collect_phase(db, detector, args.baseline_sec, samples)
    base = _phase_stats(db)
    for sw, st in sorted(base.items()):
        if st["voltage"] > 0.01:
            print(f"  SW_{sw}: V={st['voltage']:.3f} A={st['current_a']:.4f}")

    print("\n=== [2] 자이로 ON ===")
    if not serial.set_gyro_enabled(True):
        print("  gyro ON 명령 실패", file=sys.stderr)
    else:
        print("  → {\"gyro\":\"on\"} 전송 완료")
    time.sleep(2.0)
    _collect_phase(db, detector, args.gyro_sec, samples)
    gyro = _phase_stats(db)
    for sw, st in sorted(gyro.items()):
        if st["voltage"] > 0.01:
            print(f"  SW_{sw}: V={st['voltage']:.3f} A={st['current_a']:.4f}")

    print(f"\n=== [3] 서보 동작 num={args.servo_repeats} angle={args.servo_angle} ===")
    if not serial.run_servo_motion(args.servo_repeats, args.servo_angle):
        print("  servo 명령 실패", file=sys.stderr)
    else:
        print(f"  → {{\"num\":{args.servo_repeats},\"angle\":{args.servo_angle}}} 전송 완료")
        print("  (아두이노에서 서보 구동 중 — 약 1초×2×반복 소요)")
    block_sec = max(4, args.servo_repeats * 2 + 2)
    time.sleep(block_sec)
    print(f"\n=== [4] 서보 후 {args.after_servo_sec}s 수집 ===")
    _collect_phase(db, detector, args.after_servo_sec, samples)
    after = _phase_stats(db)
    for sw, st in sorted(after.items()):
        if st["voltage"] > 0.01:
            print(f"  SW_{sw}: V={st['voltage']:.3f} A={st['current_a']:.4f}")

    print("\n=== [5] 자이로 OFF ===")
    serial.set_gyro_enabled(False)

    anomaly = detector.detect_power_anomaly()
    print("\n=== 이상 탐지 (최종 tick) ===")
    if anomaly:
        print(f"  ANOMALY sw_id_list={anomaly.get('sw_id_list')}")
    else:
        print("  ANOMALY_FLAG=0 (현재 시점 이상 없음)")

    _print_threshold_report(
        samples,
        list(cfg.v_threshold_lo),
        list(cfg.v_threshold_hi),
    )

    shutdown.set()
    t_serial.join(timeout=3.0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
