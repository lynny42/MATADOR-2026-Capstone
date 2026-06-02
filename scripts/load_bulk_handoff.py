"""Clear gs_* tables and ingest one bulk handoff JSON (SAT_BULK_TELEMETRY + SAT_EVENT_QUEUE).

Usage (repo root):
    python scripts/load_bulk_handoff.py --clear backend/test_data/comm-3_bulk_handoff.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ma_detector import MAIntegratedDetector
from ma_detector.core.bulk_history_merge import (
    extract_bulk_event_records,
    merge_bulk_telemetry_packet,
    select_pre_attack_baseline_rows,
)
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
    db_config.TABLE_EVENT_QUEUE,
    db_config.TABLE_PWR_META,
    db_config.TABLE_TLM_HISTORY,
)


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


def _load_handoff(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8-sig") as file:
            payload = json.load(file)
        if not isinstance(payload, dict):
            raise ValueError("handoff root must be a JSON object")
        return payload
    except (OSError, json.JSONDecodeError, ValueError) as error:
        logger.error("handoff load failed: %s", error)
        raise


def _prepare_bulk(handoff: dict[str, Any]) -> dict[str, Any]:
    try:
        bulk_section = handoff.get("SAT_BULK_TELEMETRY")
        if not isinstance(bulk_section, dict):
            raise ValueError("handoff missing SAT_BULK_TELEMETRY object")
        bulk = dict(bulk_section)
        event_section = handoff.get("SAT_EVENT_QUEUE")
        if isinstance(event_section, dict):
            bulk["SAT_EVENT_QUEUE"] = event_section
        comm_session = handoff.get("comm_session") or bulk.get("_comm_session")
        if comm_session:
            bulk["_comm_session"] = str(comm_session).strip()
        if bulk.get("packet_type") is None:
            bulk["packet_type"] = "SAT_BULK_TELEMETRY"
        return bulk
    except Exception as error:
        logger.error("bulk prepare failed: %s", error)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Load one SAT_BULK_TELEMETRY handoff into MySQL")
    parser.add_argument(
        "handoff_path",
        nargs="?",
        type=Path,
        help="JSON handoff file path (omit with --stdin)",
    )
    parser.add_argument("--clear", action="store_true", help="delete gs_* rows before ingest")
    parser.add_argument("--stdin", action="store_true", help="read handoff JSON from stdin")
    args = parser.parse_args()

    if args.stdin:
        try:
            handoff = json.load(sys.stdin)
            if not isinstance(handoff, dict):
                raise ValueError("stdin JSON root must be an object")
        except (json.JSONDecodeError, ValueError) as error:
            logger.error("stdin handoff parse failed: %s", error)
            return 1
    else:
        handoff_path = args.handoff_path
        if handoff_path is None or not handoff_path.is_file():
            logger.error("handoff file not found: %s", handoff_path)
            return 1
        handoff = _load_handoff(handoff_path)

    init_db(
        host=db_config.DB_HOST,
        port=db_config.DB_PORT,
        user=db_config.DB_USER,
        password=db_config.DB_PASSWORD,
        database=db_config.DB_NAME,
        pool_size=db_config.DB_POOL_SIZE,
    )
    if not is_db_available():
        logger.error("MySQL unavailable (%s@%s/%s)", db_config.DB_USER, db_config.DB_HOST, db_config.DB_NAME)
        return 1

    require_db()
    refresh_column_cache()

    if args.clear:
        _clear_gs_tables()

    bulk = _prepare_bulk(handoff)
    merged_preview = merge_bulk_telemetry_packet(bulk)
    bulk_events = extract_bulk_event_records(bulk)
    baseline_rows = select_pre_attack_baseline_rows(merged_preview, bulk_events)

    detector = MAIntegratedDetector()
    if baseline_rows:
        detector.build_baseline(baseline_rows)
        logger.info("MA baseline from handoff: %s row(s)", len(baseline_rows))
    else:
        fallback = gs_repository.load_baseline_history()
        detector.build_baseline(fallback)
        logger.info("MA baseline from DB fallback: %s row(s)", len(fallback))

    inserted, skipped = detector.persist_bulk_telemetry_packet(bulk)

    logger.info(
        "bulk ingest done: inserted=%s skipped=%s tlm_history=%s event_queue=%s dashboard=%s",
        inserted,
        skipped,
        gs_repository.count_tlm_history(),
        _count_table(db_config.TABLE_EVENT_QUEUE),
        len(gs_repository.query_recent_dashboards(100)),
    )
    return 0


def _count_table(table: str) -> int:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"SELECT COUNT(*) FROM `{table}`")
            row = cursor.fetchone()
            cursor.close()
            return int(row[0]) if row else 0
    except Exception as error:
        logger.error("count failed for %s: %s", table, error)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
