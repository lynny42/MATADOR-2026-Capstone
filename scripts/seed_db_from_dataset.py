"""Optional one-off loader for backend/test_data into MySQL (not used at runtime).

Usage (from repo root):
    python scripts/seed_db_from_dataset.py --clear
    python scripts/seed_db_from_dataset.py
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DATASET_PATH = ROOT / "backend" / "test_data" / "realistic_satellite_dataset.json"

from ma_detector import MAIntegratedDetector
from ma_detector.db import config as db_config
from ma_detector.db import gs_repository
from ma_detector.db.database import get_connection, init_db, is_db_available, require_db
from ma_detector.db.gs_repository import refresh_column_cache

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

_CLEAR_ORDER = (
    db_config.TABLE_ANOMALY_DETAIL,
    db_config.TABLE_ANOMALY_DASHBOARD,
    db_config.TABLE_ANOMALY_DISCARD_LOG,
    db_config.TABLE_PWR_META,
    db_config.TABLE_TLM_HISTORY,
)


def _load_dataset() -> dict[str, Any]:
    try:
        with DATASET_PATH.open("r", encoding="utf-8-sig") as file:
            payload = json.load(file)
        return payload if isinstance(payload, dict) else {}
    except (OSError, json.JSONDecodeError) as error:
        logger.error("dataset load failed: %s", error)
        return {}


def _baseline_history() -> list[dict[str, Any]]:
    dataset = _load_dataset()
    baseline = dataset.get("baseline_history", [])
    if isinstance(baseline, list) and baseline:
        return [deepcopy(row) for row in baseline if isinstance(row, dict)]
    return []


def _seed_packets() -> list[dict[str, Any]]:
    dataset = _load_dataset()
    packets = dataset.get("packets", [])
    if isinstance(packets, list) and packets:
        return [deepcopy(packet) for packet in packets if isinstance(packet, dict)]
    return []


def _clear_gs_tables() -> None:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
            for table in _CLEAR_ORDER:
                cursor.execute(f"DELETE FROM `{table}`")
                logger.info("cleared %s", table)
            cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
            conn.commit()
            cursor.close()
    except Exception as error:
        logger.error("table clear failed: %s", error)
        raise


def _seed_baseline_rows(rows: list[dict[str, Any]]) -> int:
    inserted = 0
    for row in rows:
        try:
            if not isinstance(row, dict):
                continue
            packet = dict(row)
            packet["IS_ANOMALY"] = 0
            history_id = gs_repository.insert_tlm_history(packet)
            if history_id is not None:
                inserted += 1
        except Exception as error:
            logger.error("baseline insert failed: %s", error)
    return inserted


def _run_ma_on_packets(packets: list[dict[str, Any]]) -> dict[str, int]:
    require_db()
    detector = MAIntegratedDetector()
    baseline = gs_repository.load_baseline_history()
    if not baseline:
        logger.error("baseline rows missing in DB after seed step")
        return {"tlm_history": 0, "dashboard": 0, "discard_log": 0}
    detector.build_baseline(baseline)

    for packet in packets:
        try:
            if not isinstance(packet, dict):
                continue
            ingest_error = detector.receive_telemetry(json.dumps(packet, ensure_ascii=False))
            if ingest_error:
                logger.warning("packet ingest skipped: %s", ingest_error)
        except Exception as error:
            logger.error("packet ingest failed: %s", error)

    return {
        "tlm_history": gs_repository.count_tlm_history(),
        "dashboard": len(gs_repository.query_recent_dashboards(500)),
        "discard_log": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Load backend/test_data JSON into MySQL")
    parser.add_argument(
        "--clear",
        action="store_true",
        help="delete existing gs_* rows before seeding",
    )
    args = parser.parse_args()

    init_db(
        host=db_config.DB_HOST,
        port=db_config.DB_PORT,
        user=db_config.DB_USER,
        password=db_config.DB_PASSWORD,
        database=db_config.DB_NAME,
        pool_size=db_config.DB_POOL_SIZE,
    )
    if not is_db_available():
        logger.error(
            "MySQL unavailable. Check connection (%s@%s/%s)",
            db_config.DB_USER,
            db_config.DB_HOST,
            db_config.DB_NAME,
        )
        return 1

    refresh_column_cache()

    dataset = _load_dataset()
    baseline_rows = dataset.get("baseline_history")
    if not isinstance(baseline_rows, list) or not baseline_rows:
        baseline_rows = _baseline_history()

    packet_rows = dataset.get("packets")
    if not isinstance(packet_rows, list) or not packet_rows:
        packet_rows = _seed_packets()

    if not baseline_rows or not packet_rows:
        logger.error("dataset file missing baseline_history or packets: %s", DATASET_PATH)
        return 1

    if args.clear:
        _clear_gs_tables()

    baseline_count = _seed_baseline_rows(baseline_rows)
    logger.info("inserted baseline rows: %s", baseline_count)

    counts = _run_ma_on_packets(packet_rows)
    logger.info(
        "MA finished: tlm_history=%s dashboard=%s discard_log=%s",
        counts["tlm_history"],
        counts["dashboard"],
        counts["discard_log"],
    )
    logger.info("Restart uvicorn or call GET /api/dashboard to view results.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
