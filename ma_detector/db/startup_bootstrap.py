"""Startup schema creation and baseline seed injection."""

from __future__ import annotations

import logging
import random
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from ma_detector.db.database import get_connection, is_db_available, require_db
from ma_detector.db import gs_repository
from ma_detector.core.tlm_adcs_columns import all_split_column_ddls
from ma_detector.core.bulk_json_columns import all_bulk_json_column_ddls
from ma_detector.db.config import TABLE_TLM_HISTORY

logger = logging.getLogger(__name__)

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "backend" / "sql" / "schema.sql"
MIN_BASELINE_ROWS = 30

TLM_SEED = {
    "MISSION_MODE": 2,
    "ADCS_MODE": 1,
    "HEAP_FREE": 518400,
    "DWELL_MASK": 0,
    "OBC_S_TICK": 184300,
    "WBN_X": 0.0012,
    "WBN_Y": -0.0018,
    "WBN_Z": 0.0003,
    "SVB_X": 0.11,
    "SVB_Y": -0.84,
    "SVB_Z": 0.52,
    "SUN_VALID": 1,
    "APPENABLESTATE": 1,
    "OBC_P_HASH": "0x8F12A9C0",
    "EXPECTED_CRC": "0x8F12A9C0",
    "APPCSERRCOUNTER": 0,
    "OSCSERRCOUNTER": 0,
    "LASTVALCRC": "c4e1a2b3",
    "PROCESSOR_RESET_COUNT": 0,
    "RESETSPERFORMED": 0,
}

ADCS_SEED = {
    "MISSION_MODE": 2,
    "ADCS_MODE": 1,
    "TCMD_X": 0.02,
    "TCMD_Y": -0.01,
    "TCMD_Z": 0.01,
    "MOMENTUM_NMS_0": 0.12,
    "MOMENTUM_NMS_1": -0.08,
    "MOMENTUM_NMS_2": 0.05,
    "APPCSERRCOUNTER": 0,
    "OSCSERRCOUNTER": 0,
    "FORWARD_ERR_COUNT": 0,
    "ERLOGENTRIES": 10,
    "SKIPPEDSLOTSCOUNT": 0,
    "ENABLEDROUTES": 7,
    "EXECOUNTS": 1.0,
    "SYSLOGENTRIES": 85,
    "RESETSPERFORMED": 0,
    "COMBINEDPACKETSSENT": 450000,
    "LASTVALCRC": "c4e1a2b3",
}

PWR_SEED = {
    0: {"CURRENT_A": 0.41, "VOLTAGE": 3.27, "ANOMALY_FLAG": 0},
    1: {"CURRENT_A": 0.37, "VOLTAGE": 3.30, "ANOMALY_FLAG": 0},
    2: {"CURRENT_A": 0.54, "VOLTAGE": 5.01, "ANOMALY_FLAG": 0},
    3: {"CURRENT_A": 0.39, "VOLTAGE": 3.28, "ANOMALY_FLAG": 0},
}


def _apply_noise(record: dict[str, Any]) -> dict[str, Any]:
    try:
        noisy = dict(record)
        for key, value in list(noisy.items()):
            if isinstance(value, float) and value != 0.0:
                noisy[key] = value * (1 + random.uniform(-0.01, 0.01))
        return noisy
    except Exception as error:
        logger.error("seed noise apply failed: %s", error)
        return dict(record)


def build_seed_records(count: int = MIN_BASELINE_ROWS) -> list[dict[str, Any]]:
    """Build merged normal baseline rows with small random noise."""
    try:
        base_time = datetime(2026, 5, 30, 11, 59, 30, tzinfo=timezone.utc)
        records: list[dict[str, Any]] = []
        for index in range(count):
            merged = {
                **TLM_SEED,
                **ADCS_SEED,
                "UPDATED_AT": (base_time + timedelta(seconds=index)).isoformat(),
            }
            merged["OBC_S_TICK"] = int(TLM_SEED["OBC_S_TICK"]) + index * 20
            merged["HEAP_FREE"] = float(TLM_SEED["HEAP_FREE"]) - index * 120
            merged["COMBINEDPACKETSSENT"] = int(ADCS_SEED["COMBINEDPACKETSSENT"]) + index * 10
            for sw_id, channel in PWR_SEED.items():
                merged[f"SW_{sw_id}_CURRENT_A"] = channel["CURRENT_A"]
                merged[f"SW_{sw_id}_VOLTAGE"] = channel["VOLTAGE"]
                merged[f"SW_{sw_id}_ANOMALY_FLAG"] = channel["ANOMALY_FLAG"]
            records.append(_apply_noise(merged))
        return records
    except Exception as error:
        logger.error("seed record build failed: %s", error)
        return []


def ensure_bulk_json_columns() -> bool:
    """Add JSON-mirror columns so bulk telemetry fields map 1:1 to gs_tlm_history."""
    try:
        if not is_db_available():
            return False
        with get_connection() as conn:
            cursor = conn.cursor()
            for _col_name, ddl in all_bulk_json_column_ddls():
                try:
                    cursor.execute(f"ALTER TABLE `{TABLE_TLM_HISTORY}` ADD COLUMN {ddl}")
                except Exception as error:
                    errno = getattr(error, "errno", None)
                    if errno == 1060:
                        continue
                    raise
            cursor.close()
        gs_repository.refresh_column_cache()
        logger.info("gs_tlm_history bulk JSON mirror columns ensured")
        return True
    except Exception as error:
        logger.error("bulk json column migration failed: %s", error)
        return False


def ensure_tlm_adcs_split_columns() -> bool:
    """Add TLM_* / ADCS_* split columns to an existing gs_tlm_history table."""
    try:
        if not is_db_available():
            return False
        with get_connection() as conn:
            cursor = conn.cursor()
            for _col_name, ddl in all_split_column_ddls():
                try:
                    cursor.execute(f"ALTER TABLE `{TABLE_TLM_HISTORY}` ADD COLUMN {ddl}")
                except Exception as error:
                    errno = getattr(error, "errno", None)
                    if errno == 1060:
                        continue
                    raise
            cursor.close()
        gs_repository.refresh_column_cache()
        logger.info("gs_tlm_history TLM/ADCS split columns ensured")
        return True
    except Exception as error:
        logger.error("tlm/adcs split column migration failed: %s", error)
        return False


def ensure_schema() -> bool:
    """Create ground-station tables when MySQL is available."""
    try:
        if not is_db_available():
            logger.info("schema bootstrap skipped; database unavailable")
            return False
        if not SCHEMA_PATH.exists():
            logger.warning("schema file missing: %s", SCHEMA_PATH)
            return False

        ddl_text = SCHEMA_PATH.read_text(encoding="utf-8")
        statements = [
            statement.strip()
            for statement in re.split(r";\s*\n", ddl_text)
            if statement.strip() and not statement.strip().upper().startswith("USE ")
        ]
        with get_connection() as conn:
            cursor = conn.cursor()
            for statement in statements:
                try:
                    cursor.execute(statement)
                except Exception as error:
                    errno = getattr(error, "errno", None)
                    if errno == 1142:
                        logger.warning(
                            "schema DDL skipped (REFERENCES privilege missing): %s",
                            statement[:80],
                        )
                        continue
                    if errno == 1050:
                        logger.info("schema table already exists; skipped")
                        continue
                    raise
            cursor.close()
        gs_repository.refresh_column_cache()
        ensure_tlm_adcs_split_columns()
        ensure_bulk_json_columns()
        from ma_detector.db.event_queue_schema import ensure_event_queue_table

        ensure_event_queue_table()
        logger.info("ground-station schema ensured from %s", SCHEMA_PATH.name)
        return True
    except Exception as error:
        logger.error("schema bootstrap failed: %s", error)
        return False


def ensure_baseline_seed() -> int:
    """Return current normal telemetry row count; no synthetic seed is injected."""
    try:
        require_db()
        row_count = gs_repository.count_tlm_history()
        logger.info("baseline seed disabled; GS_TLM_HISTORY count=%s", row_count)
        return row_count
    except Exception as error:
        logger.error("baseline count lookup failed: %s", error)
        return 0
