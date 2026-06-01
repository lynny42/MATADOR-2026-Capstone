#!/usr/bin/env python3
"""Report which gs_tlm_history columns are populated vs empty."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ma_detector.db import config as db_config
from ma_detector.db.database import get_connection, init_db

GROUPS = {
    "attack_meta (SAT_EVENT_QUEUE / FP filter)": [
        "IS_ANOMALY",
        "TARGET_SUBSYSTEM",
        "EVENT_ID",
        "EVENT_TYPE",
        "FALSE_POSITIVE_RESULT",
        "FALSE_POSITIVE_WEIGHT",
        "FALSE_POSITIVE_EXCEPTION",
        "SW_ID_LIST",
        "WEIGHT",
        "EXCEPTION_CODE",
        "IS_VIOLATED",
        "EXPECTED_HASH",
    ],
    "TLM (SAT_TLM_HISTORY)": [
        "MISSION_MODE",
        "ADCS_MODE",
        "OBC_S_TICK",
        "HEAP_FREE",
        "DWELL_MASK",
        "APPENABLESTATE",
        "SVB_X",
        "WBN_X",
        "SUN_VALID",
    ],
    "PWR (SAT_PWR_HISTORY)": [
        "SW_0_VOLTAGE",
        "SW_1_VOLTAGE",
        "SW_3_VOLTAGE",
        "SW_0_ANOMALY_FLAG",
        "SW_0_CURR_DELTA_V",
    ],
    "ADCS (SAT_ADCS_FILTER)": [
        "IMU_WBN_X",
        "QERR_0",
        "TCMD_X",
        "MOMENTUM_NMS_0",
        "ST_VALID",
        "IMU_WBN_VARIANCE",
    ],
    "integrity / event counters": [
        "PIPEOVERFLOWRRCNT",
        "CHILDQUEUECOUNT",
        "FILEWRITEERRCOUNTER",
        "CMDREJECTEDCOUNTER",
        "CH1_FAULT_CRC",
        "CH2_FAULT_CRC",
        "CH1_FAULT_FILE_SIZE_MISMATCH",
        "PROCESSOR_RESET_COUNT",
    ],
    "system log counters (often in TLM or EVENT)": [
        "COMBINEDPACKETSSENT",
        "ERLOGENTRIES",
        "SKIPPEDSLOTSCOUNT",
        "LASTVALCRC",
        "ENABLEDROUTES",
        "FORWARD_ERR_COUNT",
        "APPCSERRCOUNTER",
        "OSCSERRCOUNTER",
        "SYSLOGENTRIES",
        "RESETSPERFORMED",
        "EXECOUNTS",
    ],
}


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
        total = int(cur.fetchone()["c"])
        cur.execute("SELECT COUNT(*) AS c FROM gs_tlm_history WHERE IS_ANOMALY = 1")
        anomaly = int(cur.fetchone()["c"])
        cur.execute("SELECT COUNT(*) AS c FROM gs_anomaly_ma_dashboard")
        ma_rows = int(cur.fetchone()["c"])
        cur.execute("SELECT COUNT(*) AS c FROM gs_pwr_meta")
        pwr_meta = int(cur.fetchone()["c"])

        print(f"total_rows={total} anomaly_rows={anomaly} ma_dashboard={ma_rows} gs_pwr_meta={pwr_meta}\n")

        for group_name, cols in GROUPS.items():
            parts = [
                f"SUM(CASE WHEN `{col}` IS NOT NULL THEN 1 ELSE 0 END) AS `{col}`"
                for col in cols
            ]
            sql = f"SELECT {', '.join(parts)} FROM gs_tlm_history"
            cur.execute(sql)
            row = cur.fetchone()
            print(f"[{group_name}]")
            for col in cols:
                count = int(row[col])
                pct = 100.0 * count / total if total else 0.0
                if count == 0:
                    tag = "empty"
                elif pct >= 95:
                    tag = "filled"
                else:
                    tag = "partial"
                print(f"  {col}: {count}/{total} ({pct:.1f}%) {tag}")
            print()
        cur.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
