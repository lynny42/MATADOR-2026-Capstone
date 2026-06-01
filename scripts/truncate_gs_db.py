"""Truncate all matador_gs ground-station tables (data only, schema kept)."""

from __future__ import annotations

import logging
import sys

from ma_detector.db.config import (
    TABLE_ANOMALY_DASHBOARD,
    TABLE_ANOMALY_DETAIL,
    TABLE_ANOMALY_DISCARD_LOG,
    TABLE_PWR_META,
    TABLE_TLM_HISTORY,
)
from ma_detector.db.database import get_connection, is_db_available

logger = logging.getLogger(__name__)

TABLES_IN_ORDER = (
    TABLE_ANOMALY_DETAIL,
    TABLE_ANOMALY_DASHBOARD,
    TABLE_ANOMALY_DISCARD_LOG,
    TABLE_PWR_META,
    TABLE_TLM_HISTORY,
)


def truncate_gs_tables() -> bool:
    """Delete all rows from ground-station tables."""
    try:
        if not is_db_available():
            logger.error("MySQL unavailable; cannot truncate")
            return False
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
            for table in TABLES_IN_ORDER:
                cursor.execute(f"TRUNCATE TABLE `{table}`")
                logger.info("truncated %s", table)
            cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
            for table in TABLES_IN_ORDER:
                cursor.execute(f"SELECT COUNT(*) FROM `{table}`")
                row = cursor.fetchone()
                count = int(row[0]) if row else -1
                print(f"{table}: {count} rows")
            cursor.close()
        return True
    except Exception as error:
        logger.error("truncate failed: %s", error)
        return False


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    ok = truncate_gs_tables()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
