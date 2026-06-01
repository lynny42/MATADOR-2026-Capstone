"""Delete all rows from ground-station MySQL tables (schema kept)."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ma_detector.db import config as db_config
from ma_detector.db.database import get_connection, init_db, is_db_available
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


def reset_gs_db() -> bool:
    """Delete every row from gs_* tables and return True on success."""
    try:
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
            return False

        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
            for table in _CLEAR_ORDER:
                cursor.execute(f"SELECT COUNT(*) FROM `{table}`")
                before = int(cursor.fetchone()[0])
                cursor.execute(f"DELETE FROM `{table}`")
                cursor.execute(f"SELECT COUNT(*) FROM `{table}`")
                after = int(cursor.fetchone()[0])
                logger.info("cleared %s (%s -> %s)", table, before, after)
            cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
            conn.commit()
            cursor.close()

        refresh_column_cache()
        logger.info("ground-station DB reset complete")
        return True
    except Exception as error:
        logger.error("ground-station DB reset failed: %s", error)
        return False


if __name__ == "__main__":
    raise SystemExit(0 if reset_gs_db() else 1)
