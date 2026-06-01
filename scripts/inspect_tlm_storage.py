"""Print how gs_tlm_history rows are stored (for debugging)."""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ma_detector.db import config as db_config
from ma_detector.db.database import get_connection, init_db


def main() -> int:
    init_db(
        db_config.DB_HOST,
        db_config.DB_PORT,
        db_config.DB_USER,
        db_config.DB_PASSWORD,
        db_config.DB_NAME,
        db_config.DB_POOL_SIZE,
    )
    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT COUNT(*) AS c FROM gs_tlm_history")
        total = cur.fetchone()["c"]
        cur.execute(
            """
            SELECT COUNT(DISTINCT DATE_FORMAT(UPDATED_AT, '%Y-%m-%d %H:%i:%s')) AS c
            FROM gs_tlm_history
            """
        )
        seconds = cur.fetchone()["c"]
        cur.execute("SELECT MIN(UPDATED_AT) AS mn, MAX(UPDATED_AT) AS mx FROM gs_tlm_history")
        span = cur.fetchone()
        cur.execute("SELECT IS_ANOMALY, COUNT(*) AS c FROM gs_tlm_history GROUP BY IS_ANOMALY")
        by_anom = cur.fetchall()
        cur.execute(
            """
            SELECT DATE_FORMAT(UPDATED_AT, '%Y-%m-%d %H:%i:%s') AS sec,
                   COUNT(*) AS row_count,
                   SUM(IS_ANOMALY) AS anomaly_rows
            FROM gs_tlm_history
            GROUP BY sec
            ORDER BY row_count DESC
            LIMIT 8
            """
        )
        dup = cur.fetchall()
        cur.execute(
            """
            SELECT HISTORY_ID, UPDATED_AT, IS_ANOMALY, PACKET_TYPE
            FROM gs_tlm_history
            ORDER BY HISTORY_ID DESC
            LIMIT 15
            """
        )
        recent = cur.fetchall()
        cur.close()

    print(f"total_rows={total} distinct_seconds={seconds}")
    print(f"time_span={span['mn']} .. {span['mx']}")
    print(f"by_anomaly={by_anom}")
    print("rows_per_second_top8:")
    for row in dup:
        print(f"  {row['sec']}: {row['row_count']} rows ({row['anomaly_rows']} anomaly)")
    print("recent_rows:")
    for row in recent:
        print(
            f"  id={row['HISTORY_ID']} at={row['UPDATED_AT']} anom={row['IS_ANOMALY']} "
            f"type={row['PACKET_TYPE']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
