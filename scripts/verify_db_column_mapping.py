#!/usr/bin/env python3
"""Compare recent TCP-ingested DB rows against expected JSON field mapping."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ma_detector.db import config as db_config
from ma_detector.db.database import get_connection, init_db
from ma_detector.db.gs_repository import enrich_packet_from_db

TLM_EXPECT = {
    "MISSION_MODE": 2,
    "ADCS_MODE": 2,
    "SUN_VALID": 1,
    "WBN_X": -0.015369057655334473,
    "SVB_X": 0.9971692047726839,
}

PWR_EXPECT = {
    "SW_0_VOLTAGE": 3.256,
    "SW_0_ANOMALY_FLAG": 0,
    "SW_1_VOLTAGE": 4.709,
    "SW_2_VOLTAGE": 4.748,
}

ADCS_EXPECT = {
    "IMU_WBN_X": -0.015369057655334473,
    "TCMD_X": -0.0020425477623939514,
    "MOMENTUM_NMS_0": -0.000557,
    "ST_VALID": 0,
    "SUN_VALID": 1,
}


def _compare(label: str, row: dict, expected: dict) -> list[str]:
    issues: list[str] = []
    for key, want in expected.items():
        got = row.get(key)
        if got is None:
            issues.append(f"{label}: {key} missing in DB (expected {want})")
            continue
        if isinstance(want, float):
            if abs(float(got) - float(want)) > 1e-6:
                issues.append(f"{label}: {key} mismatch DB={got} expected={want}")
        elif got != want:
            issues.append(f"{label}: {key} mismatch DB={got} expected={want}")
    return issues


def _fetch_one(cur, sql: str, params: tuple) -> dict | None:
    cur.execute(sql, params)
    row = cur.fetchone()
    return enrich_packet_from_db(dict(row)) if row else None


def main() -> int:
    init_db(
        db_config.DB_HOST,
        db_config.DB_PORT,
        db_config.DB_USER,
        db_config.DB_PASSWORD,
        db_config.DB_NAME,
        db_config.DB_POOL_SIZE,
    )

    print("=== DB column mapping check (TCP ingest) ===\n")

    with get_connection() as conn:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            SELECT COUNT(*) AS total,
                   SUM(SVB_X IS NOT NULL) AS tlm_like,
                   SUM(SW_0_VOLTAGE IS NOT NULL) AS pwr_like,
                   SUM(IMU_WBN_X IS NOT NULL) AS adcs_like,
                   SUM(PACKET_TYPE IS NOT NULL) AS typed
            FROM gs_tlm_history
            WHERE CREATED_AT >= '2026-05-31'
            """
        )
        print("aggregate since 2026-05-31:")
        print(json.dumps(cur.fetchone(), indent=2, default=str))

        tlm_row = _fetch_one(
            cur,
            "SELECT * FROM gs_tlm_history WHERE WBN_X = %s ORDER BY HISTORY_ID DESC LIMIT 1",
            (TLM_EXPECT["WBN_X"],),
        )
        pwr_row = _fetch_one(
            cur,
            """
            SELECT * FROM gs_tlm_history
            WHERE SW_0_VOLTAGE = %s AND SW_1_VOLTAGE = %s AND SW_2_VOLTAGE = %s
            ORDER BY HISTORY_ID DESC LIMIT 1
            """,
            (PWR_EXPECT["SW_0_VOLTAGE"], PWR_EXPECT["SW_1_VOLTAGE"], PWR_EXPECT["SW_2_VOLTAGE"]),
        )
        adcs_row = _fetch_one(
            cur,
            """
            SELECT * FROM gs_tlm_history
            WHERE IMU_WBN_X = %s AND TCMD_X = %s
            ORDER BY HISTORY_ID DESC LIMIT 1
            """,
            (ADCS_EXPECT["IMU_WBN_X"], ADCS_EXPECT["TCMD_X"]),
        )
        cur.close()

    all_issues: list[str] = []

    if tlm_row:
        print(f"\nTLM HISTORY_ID={tlm_row.get('HISTORY_ID')} UPDATED_AT={tlm_row.get('UPDATED_AT')}")
        all_issues.extend(_compare("TLM", tlm_row, TLM_EXPECT))
    else:
        all_issues.append("TLM: sample row not found by WBN_X")

    if pwr_row:
        print(f"PWR HISTORY_ID={pwr_row.get('HISTORY_ID')} UPDATED_AT={pwr_row.get('UPDATED_AT')}")
        all_issues.extend(_compare("PWR", pwr_row, PWR_EXPECT))
    else:
        all_issues.append("PWR: sample row not found by SW voltages")

    if adcs_row:
        print(f"ADCS HISTORY_ID={adcs_row.get('HISTORY_ID')} UPDATED_AT={adcs_row.get('UPDATED_AT')}")
        all_issues.extend(_compare("ADCS", adcs_row, ADCS_EXPECT))
    else:
        all_issues.append("ADCS: sample row not found by IMU/TCMD")

    print("\n=== result ===")
    if all_issues:
        for issue in all_issues:
            print("FAIL:", issue)
        return 1
    print("OK: comm-1 sample values are present in gs_tlm_history columns")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
