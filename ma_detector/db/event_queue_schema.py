"""gs_event_queue table DDL and startup migration."""

from __future__ import annotations

import logging

from ma_detector.core.event_queue_columns import (
    DROPPED_EVENT_QUEUE_COLUMNS,
    ONBOARD_EVENT_WIRE_COLUMN_DDLS,
)
from ma_detector.db.config import TABLE_EVENT_QUEUE
from ma_detector.db.database import get_connection, is_db_available
from ma_detector.db import gs_repository

logger = logging.getLogger(__name__)

EVENT_QUEUE_DDL = f"""
CREATE TABLE IF NOT EXISTS `{TABLE_EVENT_QUEUE}` (
  `EVENT_QUEUE_ID` bigint NOT NULL AUTO_INCREMENT,
  `HISTORY_ID` bigint DEFAULT NULL,
  `SNAPSHOT_ID` int DEFAULT NULL,
  `EVENT_ID` int DEFAULT NULL,
  `EVENT_TYPE` varchar(64) DEFAULT NULL,
  `PRIORITY` int DEFAULT NULL,
  `IS_SENT` tinyint DEFAULT NULL,
  `SW_ID` int DEFAULT NULL,
  `WEIGHT` int DEFAULT NULL,
  `EXCEPTION_CODE` int DEFAULT NULL,
  `FALSE_POSITIVE_RESULT` char(1) DEFAULT NULL,
  `FALSE_POSITIVE_WEIGHT` int DEFAULT NULL,
  `FALSE_POSITIVE_EXCEPTION` varchar(32) DEFAULT NULL,
  `IS_ANOMALY` tinyint DEFAULT 0,
  `TARGET_SUBSYSTEM` varchar(32) DEFAULT NULL,
  `PIPEOVERFLOWRRCNT` int DEFAULT NULL,
  `CHILDQUEUECOUNT` int DEFAULT NULL,
  `FILEWRITEERRCOUNTER` int DEFAULT NULL,
  `CMDREJECTEDCOUNTER` int DEFAULT NULL,
  `CH1_CH2_FAULT_CRC` int DEFAULT NULL,
  `CH1_FAULT_FILE_SIZE_MISMATCH` int DEFAULT NULL,
  `PROCESSOR_RESET_COUNT` int DEFAULT NULL,
  `DETECTED_AT` datetime(3) DEFAULT NULL,
  `TIMESTAMP` datetime(3) DEFAULT NULL,
  `MODULE_SCORES` json DEFAULT NULL,
  `BULK_SENT_AT` datetime(3) DEFAULT NULL,
  `COMM_SESSION` varchar(64) DEFAULT NULL,
  `PAYLOAD` json DEFAULT NULL,
  `CREATED_AT` datetime(3) DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`EVENT_QUEUE_ID`),
  KEY `idx_event_history` (`HISTORY_ID`),
  KEY `idx_event_snapshot` (`SNAPSHOT_ID`),
  KEY `idx_event_detected` (`DETECTED_AT`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
"""


def _drop_obsolete_event_queue_columns() -> None:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            for column in DROPPED_EVENT_QUEUE_COLUMNS:
                try:
                    cursor.execute(
                        f"ALTER TABLE `{TABLE_EVENT_QUEUE}` DROP COLUMN `{column}`",
                    )
                except Exception as error:
                    errno = getattr(error, "errno", None)
                    if errno == 1091:
                        continue
                    raise
            cursor.close()
    except Exception as error:
        logger.error("obsolete event queue column drop failed: %s", error)


def ensure_event_queue_columns() -> bool:
    """Add missing wire-mirror columns and drop obsolete derived columns."""
    try:
        if not is_db_available():
            return False
        with get_connection() as conn:
            cursor = conn.cursor()
            for _col_name, ddl in ONBOARD_EVENT_WIRE_COLUMN_DDLS:
                try:
                    cursor.execute(f"ALTER TABLE `{TABLE_EVENT_QUEUE}` ADD COLUMN {ddl}")
                except Exception as error:
                    errno = getattr(error, "errno", None)
                    if errno == 1060:
                        continue
                    raise
            cursor.close()
        _drop_obsolete_event_queue_columns()
        gs_repository.refresh_column_cache()
        logger.info("%s wire columns ensured", TABLE_EVENT_QUEUE)
        return True
    except Exception as error:
        logger.error("event queue column migration failed: %s", error)
        return False


def ensure_event_queue_table() -> bool:
    """Create gs_event_queue when missing and align columns to onboard wire JSON."""
    try:
        if not is_db_available():
            return False
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(EVENT_QUEUE_DDL)
            cursor.close()
        gs_repository.refresh_column_cache()
        ensure_event_queue_columns()
        logger.info("%s table ensured", TABLE_EVENT_QUEUE)
        return True
    except Exception as error:
        logger.error("event queue table migration failed: %s", error)
        return False
