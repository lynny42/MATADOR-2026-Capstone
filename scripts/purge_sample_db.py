#!/usr/bin/env python3
"""Remove seeded/sample DB rows and keep TCP-ingested telemetry only.

Default cutoff keeps rows whose gs_tlm_history.CREATED_AT is on/after 2026-05-31
(local MySQL server time), which matches live satellite uplink in this project.

Usage:
    python scripts/purge_sample_db.py
    python scripts/purge_sample_db.py --since 2026-05-31
    python scripts/purge_sample_db.py --dry-run
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ma_detector.db import config as db_config
from ma_detector.db.database import get_connection, init_db, is_db_available

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

_DEFAULT_SINCE = "2026-05-31"


def _count(cursor, sql: str, params: tuple = ()) -> int:
    cursor.execute(sql, params)
    row = cursor.fetchone()
    if row is None:
        return 0
    if isinstance(row, dict):
        return int(next(iter(row.values())))
    return int(row[0])


def purge_sample_rows(since: str, dry_run: bool = False) -> dict[str, int]:
    """Delete seeded rows before `since`; clear MA tables derived from samples."""
    stats = {
        "tlm_deleted": 0,
        "pwr_deleted": 0,
        "dashboard_deleted": 0,
        "detail_deleted": 0,
        "discard_deleted": 0,
        "tlm_kept": 0,
        "pwr_kept": 0,
    }
    try:
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)

            stats["tlm_kept"] = _count(
                cursor,
                f"SELECT COUNT(*) AS c FROM `{db_config.TABLE_TLM_HISTORY}` WHERE CREATED_AT >= %s",
                (since,),
            )
            stats["tlm_deleted"] = _count(
                cursor,
                f"SELECT COUNT(*) AS c FROM `{db_config.TABLE_TLM_HISTORY}` WHERE CREATED_AT < %s",
                (since,),
            )
            stats["pwr_deleted"] = _count(
                cursor,
                f"""
                SELECT COUNT(*) AS c FROM `{db_config.TABLE_PWR_META}` p
                LEFT JOIN `{db_config.TABLE_TLM_HISTORY}` h ON h.HISTORY_ID = p.HISTORY_ID
                WHERE h.HISTORY_ID IS NULL OR h.CREATED_AT < %s
                """,
                (since,),
            )
            stats["pwr_kept"] = _count(
                cursor,
                f"""
                SELECT COUNT(*) AS c FROM `{db_config.TABLE_PWR_META}` p
                INNER JOIN `{db_config.TABLE_TLM_HISTORY}` h ON h.HISTORY_ID = p.HISTORY_ID
                WHERE h.CREATED_AT >= %s
                """,
                (since,),
            )
            stats["dashboard_deleted"] = _count(
                cursor,
                f"SELECT COUNT(*) AS c FROM `{db_config.TABLE_ANOMALY_DASHBOARD}`",
            )
            stats["detail_deleted"] = _count(
                cursor,
                f"SELECT COUNT(*) AS c FROM `{db_config.TABLE_ANOMALY_DETAIL}`",
            )
            stats["discard_deleted"] = _count(
                cursor,
                f"SELECT COUNT(*) AS c FROM `{db_config.TABLE_ANOMALY_DISCARD_LOG}`",
            )

            logger.info(
                "plan since=%s dry_run=%s tlm_delete=%s tlm_keep=%s pwr_delete=%s pwr_keep=%s "
                "dashboard_delete=%s detail_delete=%s discard_delete=%s",
                since,
                dry_run,
                stats["tlm_deleted"],
                stats["tlm_kept"],
                stats["pwr_deleted"],
                stats["pwr_kept"],
                stats["dashboard_deleted"],
                stats["detail_deleted"],
                stats["discard_deleted"],
            )

            if dry_run:
                cursor.close()
                return stats

            cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
            cursor.execute(f"DELETE FROM `{db_config.TABLE_ANOMALY_DETAIL}`")
            cursor.execute(f"DELETE FROM `{db_config.TABLE_ANOMALY_DASHBOARD}`")
            cursor.execute(f"DELETE FROM `{db_config.TABLE_ANOMALY_DISCARD_LOG}`")
            cursor.execute(
                f"""
                DELETE p FROM `{db_config.TABLE_PWR_META}` p
                LEFT JOIN `{db_config.TABLE_TLM_HISTORY}` h ON h.HISTORY_ID = p.HISTORY_ID
                WHERE h.HISTORY_ID IS NULL OR h.CREATED_AT < %s
                """,
                (since,),
            )
            cursor.execute(
                f"DELETE FROM `{db_config.TABLE_TLM_HISTORY}` WHERE CREATED_AT < %s",
                (since,),
            )
            cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
            conn.commit()
            cursor.close()
        return stats
    except Exception as error:
        logger.error("sample purge failed: %s", error)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Purge seeded DB rows; keep TCP ingest only")
    parser.add_argument(
        "--since",
        default=_DEFAULT_SINCE,
        help="Keep gs_tlm_history rows with CREATED_AT >= this date (YYYY-MM-DD)",
    )
    parser.add_argument("--dry-run", action="store_true", help="show counts only")
    args = parser.parse_args()

    try:
        datetime.strptime(args.since, "%Y-%m-%d")
    except ValueError:
        logger.error("invalid --since date: %s", args.since)
        return 1

    init_db(
        host=db_config.DB_HOST,
        port=db_config.DB_PORT,
        user=db_config.DB_USER,
        password=db_config.DB_PASSWORD,
        database=db_config.DB_NAME,
        pool_size=db_config.DB_POOL_SIZE,
    )
    if not is_db_available():
        logger.error("MySQL unavailable")
        return 1

    stats = purge_sample_rows(args.since, dry_run=args.dry_run)
    if args.dry_run:
        logger.info("dry-run complete; no rows deleted")
    else:
        logger.info(
            "purge complete: deleted tlm=%s pwr=%s dashboard=%s detail=%s discard=%s; kept tlm=%s pwr=%s",
            stats["tlm_deleted"],
            stats["pwr_deleted"],
            stats["dashboard_deleted"],
            stats["detail_deleted"],
            stats["discard_deleted"],
            stats["tlm_kept"],
            stats["pwr_kept"],
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
