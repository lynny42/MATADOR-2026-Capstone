"""Dump DB samples for attack replay packet generation."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ma_detector.db import config as db_config
from ma_detector.db import gs_repository
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
    print("tlm_count:", gs_repository.count_tlm_history())
    dashboards = gs_repository.query_recent_dashboards(20)
    print("dashboard_rows:", len(dashboards))
    for row in dashboards:
        print(
            json.dumps(
                {
                    "MA_CODE": row.get("MA_CODE"),
                    "GRADE": row.get("GRADE"),
                    "MODULE": row.get("MODULE"),
                    "TARGET": row.get("TARGET_SUBSYSTEM"),
                    "FP_WEIGHT": row.get("FALSE_POSITIVE_WEIGHT"),
                    "DETECT_TIME": str(row.get("DETECT_TIME")),
                },
                ensure_ascii=False,
            )
        )

    with get_connection() as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT HISTORY_ID, UPDATED_AT, PACKET_TYPE, TARGET_SUBSYSTEM,
                   FALSE_POSITIVE_RESULT, FALSE_POSITIVE_WEIGHT, IS_ANOMALY,
                   EXPECTED_HASH, APPCSERRCOUNTER, CH1_FAULT_CRC,
                   TCMD_X, QERR_0, IMU_WBN_X, EVENT_TYPE, WEIGHT
            FROM gs_tlm_history
            ORDER BY UPDATED_AT DESC
            LIMIT 8
            """
        )
        recent = cursor.fetchall()
        cursor.execute(
            """
            SELECT HISTORY_ID, UPDATED_AT, TARGET_SUBSYSTEM, FALSE_POSITIVE_WEIGHT,
                   RAW_PAYLOAD, PAYLOAD
            FROM gs_tlm_history
            WHERE IS_ANOMALY = 1
            ORDER BY UPDATED_AT DESC
            LIMIT 3
            """
        )
        anomalies = cursor.fetchall()
        cursor.close()

    print("\nrecent_tlm:")
    for row in recent:
        print(json.dumps({k: str(v) if v is not None else None for k, v in row.items()}, ensure_ascii=False))

    print("\nanomaly_payload_keys:")
    for row in anomalies:
        payload = row.get("RAW_PAYLOAD") or row.get("PAYLOAD")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                pass
        keys = list(payload.keys())[:20] if isinstance(payload, dict) else type(payload).__name__
        print(
            row.get("HISTORY_ID"),
            str(row.get("UPDATED_AT")),
            row.get("TARGET_SUBSYSTEM"),
            row.get("FALSE_POSITIVE_WEIGHT"),
            "keys:",
            keys,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
