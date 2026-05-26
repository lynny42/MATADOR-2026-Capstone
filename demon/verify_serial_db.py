#!/usr/bin/env python3
"""시리얼 파싱 → SAT_PWR_META DB 저장 검증 (하드웨어 없이)."""
from __future__ import annotations

import logging
import sqlite3
import sys
import tempfile
import threading
from pathlib import Path

from demon.core.context import DaemonConfig, RuntimeContext
from demon.db.db_manager import DBManager
from demon.db.paths import default_db_path
from demon.workers.serial_reader import SerialReader

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("verify_serial_db")


def _print_pwr_table(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        """
        SELECT SW_ID, VOLTAGE, CURRENT_A, CURR_DELTA_V, UPDATED_AT
        FROM SAT_PWR_META
        ORDER BY SW_ID
        """,
    ).fetchall()
    print("\n--- SAT_PWR_META ---")
    for row in rows:
        print(
            f"  SW_ID={row[0]} V={row[1]:.4f} A={row[2]:.4f} "
            f"dV={row[3]:.4f} updated={row[4]}",
        )


def test_simulated_arduino_burst(tmp_db: Path) -> None:
    db = DBManager(tmp_db)
    if not db.init_db():
        raise SystemExit("init_db failed")

    ctx = RuntimeContext(
        config=DaemonConfig(db_path=tmp_db),
        shutdown_event=threading.Event(),
        db=db,
    )
    reader = SerialReader(ctx)

    lines = [
        "# sat_power_monitor ready",
        "0,3.280,0.0410,100001",
        "1,3.310,0.0520,100002",
        "2,3.150,0.1200,100003",
        "L,light,100004",
        "0,3.350,0.0430,101001",
        "1,3.320,0.0510,101002",
        "2,3.160,0.1180,101003",
        "L,dark,101004",
    ]
    for line in lines:
        reader._dispatch_line(line)

    conn = sqlite3.connect(tmp_db)
    conn.row_factory = sqlite3.Row
    _print_pwr_table(conn)

    m0 = db.get_pwr_meta(0)
    m1 = db.get_pwr_meta(1)
    m2 = db.get_pwr_meta(2)
    m3 = db.get_pwr_meta(3)

    if m0 is None or abs(float(m0["VOLTAGE"]) - 3.35) > 1e-4:
        raise SystemExit(f"SW_ID 0 expected V=3.35 got {m0}")
    if m1 is None or abs(float(m1["VOLTAGE"]) - 3.32) > 1e-4:
        raise SystemExit(f"SW_ID 1 expected V=3.32 got {m1}")
    if m2 is None or abs(float(m2["VOLTAGE"]) - 3.16) > 1e-4:
        raise SystemExit(f"SW_ID 2 expected V=3.16 got {m2}")
    if abs(float(m0["CURR_DELTA_V"]) - 0.07) > 1e-4:
        raise SystemExit(f"SW_ID 0 delta expected ~0.07 got {m0['CURR_DELTA_V']}")
    if m3 is None or float(m3["VOLTAGE"]) != 0.0:
        raise SystemExit(f"SW_ID 3 should stay seed 0.0 got {m3}")
    if reader.get_light_state() != "dark":
        raise SystemExit(f"light state expected dark got {reader.get_light_state()}")

    conn.close()
    db.close()
    logger.info("PASS: simulated serial burst → DB OK (ch0~2 updated, ch3 untouched, light=dark)")


def inspect_live_db() -> None:
    live = default_db_path()
    if not live.is_file():
        print(f"\n(live DB 없음: {live} — demon.main 을 한 번도 안 돌렸거나 DB_PATH 다름)")
        return

    conn = sqlite3.connect(live)
    conn.row_factory = sqlite3.Row
    print(f"\n=== live DB: {live} ===")
    _print_pwr_table(conn)
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM SAT_PWR_META WHERE UPDATED_AT IS NOT NULL",
    ).fetchone()
    print(f"  rows with UPDATED_AT: {row['n']}")
    conn.close()


def main() -> int:
    try:
        tmp = Path(tempfile.mkdtemp()) / "serial_db_test.sqlite"
        test_simulated_arduino_burst(tmp)
        inspect_live_db()
        logger.info("=== serial DB verification done ===")
        return 0
    except SystemExit as exc:
        logger.error("FAIL: %s", exc)
        return int(exc.code) if exc.code is not None else 1
    except Exception as e:
        logger.error("FAIL: %s", e)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
