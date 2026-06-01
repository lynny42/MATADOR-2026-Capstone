"""MySQL read/write helpers for ground-station tables."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from ma_detector.core.tlm_adcs_columns import sync_legacy_tlm_columns
from ma_detector.db.config import (
    TABLE_ANOMALY_DASHBOARD,
    TABLE_ANOMALY_DETAIL,
    TABLE_ANOMALY_DISCARD_LOG,
    TABLE_PWR_META,
    TABLE_TLM_HISTORY,
)
from ma_detector.db.database import get_connection, is_db_available, require_db

logger = logging.getLogger(__name__)

_JSON_COLUMNS = frozenset(
    {
        "RAW_PAYLOAD",
        "PAYLOAD",
        "EVIDENCE_KEYS",
        "TRIGGERED_RULE_IDS",
        "UNREGISTERED_ACTION_IDS",
        "TRIGGERED_RULE_RESULTS",
        "SW_ID_LIST",
        "SNAPSHOT",
        "REPORT",
        "TRIGGERED_RULES",
        "MODULE_SCORES",
        "WIRE_PAYLOAD",
        "SOURCE_RECORDS",
    }
)

_AUTO_COLUMNS = frozenset({"HISTORY_ID", "PWR_META_ID", "DETAIL_ID", "LOG_ID", "CREATED_AT"})

_column_cache: dict[str, list[str]] = {}


def refresh_column_cache() -> None:
    """Load table column names from MySQL."""
    global _column_cache
    try:
        if not is_db_available():
            _column_cache = {}
            return
        tables = [
            TABLE_TLM_HISTORY,
            TABLE_PWR_META,
            TABLE_ANOMALY_DASHBOARD,
            TABLE_ANOMALY_DETAIL,
            TABLE_ANOMALY_DISCARD_LOG,
        ]
        cache: dict[str, list[str]] = {}
        with get_connection() as conn:
            cursor = conn.cursor()
            for table in tables:
                cursor.execute(f"SHOW COLUMNS FROM `{table}`")
                cache[table] = [row[0] for row in cursor.fetchall()]
            cursor.close()
        _column_cache = cache
    except Exception as error:
        logger.warning("column cache refresh failed: %s", error)
        _column_cache = {}


def _table_columns(table: str) -> list[str]:
    try:
        if table not in _column_cache:
            refresh_column_cache()
        return list(_column_cache.get(table, []))
    except Exception as error:
        logger.error("table column lookup failed: %s", error)
        return []


def _serialize_value(column: str, value: Any) -> Any:
    try:
        if column in _JSON_COLUMNS and value is not None and not isinstance(value, (str, bytes)):
            return json.dumps(value, ensure_ascii=False, default=str)
        if isinstance(value, bool):
            return int(value)
        return value
    except Exception as error:
        logger.error("value serialization failed: %s", error)
        return value


def _parse_json_value(value: Any) -> Any:
    try:
        if value is None:
            return None
        if isinstance(value, (dict, list)):
            return value
        if isinstance(value, (bytes, bytearray)):
            value = value.decode("utf-8")
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                return json.loads(stripped)
        return value
    except (json.JSONDecodeError, TypeError, ValueError) as error:
        logger.error("json parse failed: %s", error)
        return value
    except Exception as error:
        logger.error("unexpected json parse failure: %s", error)
        return value


def prepare_packet_for_db(packet: dict[str, Any]) -> dict[str, Any]:
    """Map flattened packet keys to DB column names."""
    try:
        prepared = dict(packet)
        for sw_id in range(4):
            current_key = f"SW_{sw_id}_CURRENT_A"
            alias_key = f"SW_{sw_id}_CURRENT"
            if prepared.get(current_key) is None and alias_key in prepared:
                prepared[current_key] = prepared[alias_key]
            if prepared.get(alias_key) is None and current_key in prepared:
                prepared[alias_key] = prepared[current_key]

        if prepared.get("RESETSPERFORMED") is None and "PROCESSOR_RESET_COUNT" in prepared:
            prepared["RESETSPERFORMED"] = prepared["PROCESSOR_RESET_COUNT"]
        if prepared.get("PROCESSOR_RESET_COUNT") is None and prepared.get("RESETSPERFORMED") is not None:
            prepared["PROCESSOR_RESET_COUNT"] = prepared["RESETSPERFORMED"]

        if prepared.get("LASTVALCRC") is not None and not isinstance(prepared["LASTVALCRC"], str):
            prepared["LASTVALCRC"] = str(prepared["LASTVALCRC"])

        for crc_key in ("TLM_LASTVALCRC", "ADCS_LASTVALCRC"):
            if prepared.get(crc_key) is not None and not isinstance(prepared[crc_key], str):
                prepared[crc_key] = str(prepared[crc_key])

        sync_legacy_tlm_columns(prepared)

        if prepared.get("EXPECTED_HASH") is None:
            prepared["EXPECTED_HASH"] = (
                prepared.get("EXPECTED_CRC")
                or prepared.get("OBC_P_HASH")
            )

        combined_crc = prepared.get("CH1_CH2_FAULT_CRC")
        if combined_crc is not None:
            if prepared.get("CH1_FAULT_CRC") is None:
                prepared["CH1_FAULT_CRC"] = combined_crc
            if prepared.get("CH2_FAULT_CRC") is None:
                prepared["CH2_FAULT_CRC"] = combined_crc

        return prepared
    except Exception as error:
        logger.error("packet db preparation failed: %s", error)
        return dict(packet)


def _merge_stored_payloads(row: dict[str, Any]) -> dict[str, Any]:
    """Merge PAYLOAD / RAW_PAYLOAD JSON columns into the row dict."""
    try:
        item = dict(row)
        for key in ("PAYLOAD", "RAW_PAYLOAD"):
            payload = _parse_json_value(item.get(key))
            if isinstance(payload, dict):
                for payload_key, payload_value in payload.items():
                    item.setdefault(payload_key, payload_value)
        return item
    except Exception as error:
        logger.error("stored payload merge failed: %s", error)
        return dict(row)


def enrich_packet_from_db(row: dict[str, Any]) -> dict[str, Any]:
    """Add rule-engine aliases when loading rows from DB."""
    try:
        packet = _merge_stored_payloads(row)

        for sw_id in range(4):
            current_key = f"SW_{sw_id}_CURRENT_A"
            alias_key = f"SW_{sw_id}_CURRENT"
            if packet.get(alias_key) is None and packet.get(current_key) is not None:
                packet[alias_key] = packet[current_key]

        if packet.get("PROCESSOR_RESET_COUNT") is None and packet.get("RESETSPERFORMED") is not None:
            packet["PROCESSOR_RESET_COUNT"] = packet["RESETSPERFORMED"]

        expected_hash = packet.get("EXPECTED_HASH")
        if expected_hash is not None:
            packet.setdefault("EXPECTED_CRC", expected_hash)
            if packet.get("OBC_P_HASH") is None and int(packet.get("IS_VIOLATED", 0) or 0) != 1:
                packet.setdefault("OBC_P_HASH", expected_hash)

        for wheel_index in range(3):
            err_key = f"DEVICE_ERR_RW{wheel_index}"
            enabled_key = f"DEVICE_ENABLED_RW{wheel_index}"
            if packet.get(err_key) is None and packet.get(enabled_key) is not None:
                packet[err_key] = packet[enabled_key]

        sync_legacy_tlm_columns(packet)

        return packet
    except Exception as error:
        logger.error("packet db enrichment failed: %s", error)
        return dict(row)


def _build_insert(table: str, values: dict[str, Any]) -> tuple[str, list[Any]]:
    columns: list[str] = []
    params: list[Any] = []
    for col in _table_columns(table):
        if col in _AUTO_COLUMNS:
            continue
        if col == "SNAPSHOT" and "_snapshot_json" in values:
            columns.append(col)
            params.append(_serialize_value(col, values["_snapshot_json"]))
            continue
        if col not in values:
            continue
        if values[col] is None:
            continue
        columns.append(col)
        params.append(_serialize_value(col, values[col]))
    if not columns:
        return "", []
    placeholders = ", ".join(["%s"] * len(columns))
    col_sql = ", ".join(f"`{col}`" for col in columns)
    sql = f"INSERT INTO `{table}` ({col_sql}) VALUES ({placeholders})"
    return sql, params


def count_tlm_history() -> int:
    """Return total GS_TLM_HISTORY row count."""
    try:
        if not is_db_available():
            return 0
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"SELECT COUNT(*) FROM `{TABLE_TLM_HISTORY}`")
            row = cursor.fetchone()
            cursor.close()
        return int(row[0]) if row else 0
    except Exception as error:
        logger.error("tlm history count failed: %s", error)
        return 0


def insert_tlm_history(packet: dict[str, Any]) -> int | None:
    """Insert one flattened telemetry row and return HISTORY_ID."""
    try:
        if not is_db_available():
            return None
        prepared = prepare_packet_for_db(packet)
        row = dict(prepared)
        row["PAYLOAD"] = prepared
        row["RAW_PAYLOAD"] = prepared
        if row.get("IS_ANOMALY") is not None:
            row["IS_ANOMALY"] = int(bool(row["IS_ANOMALY"]))
        sql, params = _build_insert(TABLE_TLM_HISTORY, row)
        if not params:
            return None
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            history_id = int(cursor.lastrowid)
            cursor.close()
        return history_id
    except Exception as error:
        logger.error("%s insert failed: %s", TABLE_TLM_HISTORY, error)
        return None


def _build_pwr_channel_payload(prepared: dict[str, Any], sw_id: int) -> dict[str, Any]:
    keys = [
        "VOLTAGE",
        "PREV_VOLTAGE",
        "CURRENT_A",
        "PREV_DELTA_V",
        "CURR_DELTA_V",
        "EXCEED_COUNT",
        "CONSECUTIVE_EXCEED",
        "ANOMALY_FLAG",
        "V_THRESHOLD_LO",
        "V_THRESHOLD_HI",
    ]
    payload: dict[str, Any] = {"SW_ID": sw_id}
    for key in keys:
        flat_key = f"SW_{sw_id}_{key}"
        if flat_key in prepared:
            payload[key] = prepared.get(flat_key)
    if prepared.get(f"SW_{sw_id}_CURRENT") is not None:
        payload["CURRENT"] = prepared.get(f"SW_{sw_id}_CURRENT")
    return payload


def insert_pwr_meta_rows(packet: dict[str, Any], history_id: int | None = None) -> bool:
    """Insert one gs_pwr_meta row per SW channel present in the packet."""
    try:
        if not is_db_available():
            return False
        prepared = prepare_packet_for_db(packet)
        updated_at = prepared.get("UPDATED_AT")
        inserted = False
        with get_connection() as conn:
            cursor = conn.cursor()
            for sw_id in range(4):
                prefix = f"SW_{sw_id}_"
                if not any(key.startswith(prefix) for key in prepared):
                    continue
                channel_payload = _build_pwr_channel_payload(prepared, sw_id)
                row = {
                    "HISTORY_ID": history_id,
                    "UPDATED_AT": updated_at,
                    "SW_ID": sw_id,
                    "VOLTAGE": prepared.get(f"SW_{sw_id}_VOLTAGE"),
                    "PREV_VOLTAGE": prepared.get(f"SW_{sw_id}_PREV_VOLTAGE"),
                    "CURRENT_A": prepared.get(
                        f"SW_{sw_id}_CURRENT_A",
                        prepared.get(f"SW_{sw_id}_CURRENT"),
                    ),
                    "PREV_DELTA_V": prepared.get(f"SW_{sw_id}_PREV_DELTA_V"),
                    "CURR_DELTA_V": prepared.get(f"SW_{sw_id}_CURR_DELTA_V"),
                    "EXCEED_COUNT": prepared.get(f"SW_{sw_id}_EXCEED_COUNT"),
                    "CONSECUTIVE_EXCEED": prepared.get(f"SW_{sw_id}_CONSECUTIVE_EXCEED"),
                    "ANOMALY_FLAG": prepared.get(f"SW_{sw_id}_ANOMALY_FLAG"),
                    "PAYLOAD": channel_payload,
                }
                sql, params = _build_insert(TABLE_PWR_META, row)
                if params:
                    cursor.execute(sql, params)
                    inserted = True
            cursor.close()
        return inserted
    except Exception as error:
        logger.error("%s insert failed: %s", TABLE_PWR_META, error)
        return False


def insert_dashboard_row(row: dict[str, Any]) -> int | None:
    """Insert dashboard row and return DETECT_ID."""
    try:
        if not is_db_available():
            return None
        payload = dict(row)
        payload.pop("DETECT_ID", None)
        if payload.get("IS_NEW_PATTERN") is not None:
            payload["IS_NEW_PATTERN"] = int(bool(payload["IS_NEW_PATTERN"]))
        if payload.get("MATCHES_SATELLITE_TARGET") is not None:
            payload["MATCHES_SATELLITE_TARGET"] = int(bool(payload["MATCHES_SATELLITE_TARGET"]))
        payload["ACTION_MAPPING_STATUS"] = _truncate_text(payload.get("ACTION_MAPPING_STATUS"), 16)
        detect_id = fetch_next_detect_id()
        payload["DETECT_ID"] = detect_id
        payload["DASHBOARD_ID"] = detect_id
        sql, params = _build_insert(TABLE_ANOMALY_DASHBOARD, payload)
        if not params:
            return None
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            detect_id = int(cursor.lastrowid or detect_id)
            cursor.close()
        return detect_id
    except Exception as error:
        logger.error("%s insert failed: %s", TABLE_ANOMALY_DASHBOARD, error)
        return None


def update_new_pattern_flag(detect_id: int, ma_code: str) -> bool:
    """Set IS_NEW_PATTERN on an existing dashboard row."""
    try:
        if not is_db_available():
            return False
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"UPDATE {TABLE_ANOMALY_DASHBOARD} SET IS_NEW_PATTERN = %s WHERE DETECT_ID = %s",
                (1, int(detect_id)),
            )
            cursor.close()
        logger.info("new pattern flag updated: detect_id=%s ma_code=%s", detect_id, ma_code)
        return True
    except Exception as error:
        logger.error("new pattern flag update failed: %s", error)
        return False


def _truncate_text(value: Any, max_len: int) -> Any:
    try:
        if value is None or not isinstance(value, str):
            return value
        return value[:max_len]
    except Exception as error:
        logger.error("text truncate failed: %s", error)
        return value


def insert_detail_row(row: dict[str, Any], snapshot: dict[str, Any]) -> bool:
    """Insert detail snapshot row."""
    try:
        if not is_db_available():
            return False
        payload = dict(row)
        payload["ACTION_MAPPING_STATUS"] = _truncate_text(
            payload.get("ACTION_MAPPING_STATUS"),
            16,
        )
        payload["_snapshot_json"] = snapshot if isinstance(snapshot, dict) else {}
        sql, params = _build_insert(TABLE_ANOMALY_DETAIL, payload)
        if not params:
            logger.error("%s insert skipped: no matching columns", TABLE_ANOMALY_DETAIL)
            return False
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            cursor.close()
        return True
    except Exception as error:
        logger.error("%s insert failed: %s", TABLE_ANOMALY_DETAIL, error)
        return False


def insert_discard_log(report: dict[str, Any]) -> bool:
    """Insert discarded report log row."""
    try:
        if not is_db_available():
            return False
        row = {
            "MA_CODE": report.get("ma_code"),
            "GRADE": report.get("grade"),
            "CONFIDENCE_SCORE": report.get("confidence_score"),
            "TRIGGERED_RULES": report.get("triggered_rules", []),
            "REPORT": report,
        }
        sql, params = _build_insert(TABLE_ANOMALY_DISCARD_LOG, row)
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            cursor.close()
        return True
    except Exception as error:
        logger.error("GS_ANOMALY_DISCARD_LOG insert failed: %s", error)
        return False


def query_dashboard(detect_id: int) -> dict[str, Any]:
    """Fetch one dashboard row by DETECT_ID."""
    try:
        if not is_db_available():
            return {}
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                f"SELECT * FROM `{TABLE_ANOMALY_DASHBOARD}` WHERE DETECT_ID = %s LIMIT 1",
                (detect_id,),
            )
            row = cursor.fetchone()
            cursor.close()
        if not row:
            return {}
        result = dict(row)
        for col in _JSON_COLUMNS:
            if col in result:
                result[col] = _parse_json_value(result[col])
        return result
    except Exception as error:
        logger.error("dashboard query failed: %s", error)
        return {}


def query_detail_rows(dashboard_id: int) -> list[dict[str, Any]]:
    """Fetch detail rows for one dashboard id."""
    try:
        if not is_db_available():
            return []
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                f"SELECT * FROM `{TABLE_ANOMALY_DETAIL}` WHERE DASHBOARD_ID = %s",
                (dashboard_id,),
            )
            rows = cursor.fetchall()
            cursor.close()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            snapshot = _parse_json_value(item.get("SNAPSHOT"))
            if isinstance(snapshot, dict):
                item.update(snapshot)
            for col in _JSON_COLUMNS:
                if col in item:
                    item[col] = _parse_json_value(item[col])
            results.append(enrich_packet_from_db(item))
        return results
    except Exception as error:
        logger.error("detail query failed: %s", error)
        return []


def query_evaluation_snapshot(detect_id: int) -> dict[str, Any]:
    """Return merged SNAPSHOT payload stored at MA detection time."""
    try:
        rows = query_detail_rows(int(detect_id))
        if not rows:
            return {}
        return enrich_packet_from_db(dict(rows[0]))
    except Exception as error:
        logger.error("evaluation snapshot query failed: %s", error)
        return {}


def query_anomaly_row_near(detect_time: str, tolerance_sec: int = 5) -> dict[str, Any]:
    """Return nearest IS_ANOMALY=1 telemetry row around detect_time."""
    try:
        if not is_db_available() or not detect_time:
            return {}
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                f"""
                SELECT * FROM `{TABLE_TLM_HISTORY}`
                WHERE IS_ANOMALY = 1
                  AND UPDATED_AT BETWEEN DATE_SUB(%s, INTERVAL %s SECOND)
                                     AND DATE_ADD(%s, INTERVAL %s SECOND)
                ORDER BY ABS(TIMESTAMPDIFF(SECOND, UPDATED_AT, %s)) ASC
                LIMIT 1
                """,
                (detect_time, tolerance_sec, detect_time, tolerance_sec, detect_time),
            )
            row = cursor.fetchone()
            cursor.close()
        if not row:
            return {}
        return enrich_packet_from_db(dict(row))
    except Exception as error:
        logger.error("anomaly row near detect_time query failed: %s", error)
        return {}


def query_history_window(detect_time: str, window_size_sec: int, limit: int = 60) -> list[dict[str, Any]]:
    """Fetch telemetry history rows around detect_time."""
    try:
        if not is_db_available():
            return []
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                f"""
                SELECT * FROM `{TABLE_TLM_HISTORY}`
                WHERE UPDATED_AT BETWEEN DATE_SUB(%s, INTERVAL %s SECOND)
                                      AND DATE_ADD(%s, INTERVAL %s SECOND)
                ORDER BY UPDATED_AT DESC
                LIMIT %s
                """,
                (detect_time, window_size_sec, detect_time, window_size_sec, limit),
            )
            rows = cursor.fetchall()
            cursor.close()
        results: list[dict[str, Any]] = []
        for row in rows:
            results.append(enrich_packet_from_db(dict(row)))
        return results
    except Exception as error:
        logger.error("history query failed: %s", error)
        return []


def query_detection_history_rows(detect_time: str) -> list[dict[str, Any]]:
    """Fetch gs_tlm_history rows for detect second and the immediately previous second."""
    try:
        if not is_db_available() or not detect_time:
            return []
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                f"""
                SELECT * FROM `{TABLE_TLM_HISTORY}`
                WHERE UPDATED_AT >= DATE_SUB(%s, INTERVAL 1 SECOND)
                  AND UPDATED_AT < DATE_ADD(%s, INTERVAL 1 SECOND)
                ORDER BY UPDATED_AT ASC
                """,
                (detect_time, detect_time),
            )
            rows = cursor.fetchall()
            cursor.close()
        return [enrich_packet_from_db(dict(row)) for row in rows]
    except Exception as error:
        logger.error("detection history query failed: %s", error)
        return []


def load_baseline_history(limit: int = 500) -> list[dict[str, Any]]:
    """Load normal telemetry rows for baseline building."""
    try:
        if not is_db_available():
            return []
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                f"""
                SELECT * FROM `{TABLE_TLM_HISTORY}`
                WHERE IS_ANOMALY = 0
                ORDER BY UPDATED_AT DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            cursor.close()
        results = [enrich_packet_from_db(dict(row)) for row in rows]
        results.reverse()
        return results
    except Exception as error:
        logger.error("baseline history load failed: %s", error)
        return []


def load_replay_payloads(from_time: str, to_time: str) -> list[str]:
    """Load RAW_PAYLOAD (or PAYLOAD fallback) JSON strings for replay."""
    try:
        if not is_db_available():
            return []
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"""
                SELECT COALESCE(RAW_PAYLOAD, PAYLOAD) AS REPLAY_PAYLOAD
                FROM `{TABLE_TLM_HISTORY}`
                WHERE UPDATED_AT BETWEEN %s AND %s
                  AND IS_ANOMALY = 1
                ORDER BY UPDATED_AT ASC
                """,
                (from_time, to_time),
            )
            rows = cursor.fetchall()
            cursor.close()
        payloads: list[str] = []
        for (raw_payload,) in rows:
            if raw_payload is None:
                continue
            if isinstance(raw_payload, (dict, list)):
                payloads.append(json.dumps(raw_payload, ensure_ascii=False, default=str))
            else:
                payloads.append(str(raw_payload))
        return payloads
    except Exception as error:
        logger.error("replay payload load failed: %s", error)
        return []


def query_recent_dashboards(count: int = 5) -> list[dict[str, Any]]:
    """Fetch recent dashboard rows."""
    try:
        if not is_db_available():
            return []
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                f"""
                SELECT * FROM `{TABLE_ANOMALY_DASHBOARD}`
                ORDER BY DETECT_TIME DESC
                LIMIT %s
                """,
                (count,),
            )
            rows = cursor.fetchall()
            cursor.close()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            for col in _JSON_COLUMNS:
                if col in item:
                    item[col] = _parse_json_value(item[col])
            results.append(item)
        return results
    except Exception as error:
        logger.error("recent dashboard query failed: %s", error)
        return []


def query_ma_codes() -> list[dict[str, Any]]:
    """Fetch MA code dropdown rows."""
    try:
        if not is_db_available():
            return []
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                f"""
                SELECT DETECT_ID, MA_CODE, MODULE, GRADE, CONFIDENCE_SCORE, DETECT_TIME
                FROM `{TABLE_ANOMALY_DASHBOARD}`
                ORDER BY DETECT_TIME DESC
                """
            )
            rows = cursor.fetchall()
            cursor.close()
        return [dict(row) for row in rows]
    except Exception as error:
        logger.error("ma code query failed: %s", error)
        return []


def load_recent_tlm_history(limit: int = 600) -> list[dict[str, Any]]:
    """Load recent telemetry rows for dashboard timeline hydration."""
    try:
        if not is_db_available():
            return []
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                f"""
                SELECT * FROM (
                    SELECT * FROM `{TABLE_TLM_HISTORY}`
                    ORDER BY UPDATED_AT DESC
                    LIMIT %s
                ) AS recent
                ORDER BY UPDATED_AT ASC
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            cursor.close()
        return [enrich_packet_from_db(dict(row)) for row in rows]
    except Exception as error:
        logger.error("recent tlm history load failed: %s", error)
        return []


def fetch_next_detect_id() -> int:
    """Return next detect id based on current table max."""
    try:
        if not is_db_available():
            return 1
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"SELECT COALESCE(MAX(DETECT_ID), 0) + 1 FROM `{TABLE_ANOMALY_DASHBOARD}`")
            row = cursor.fetchone()
            cursor.close()
        return int(row[0]) if row else 1
    except Exception as error:
        logger.error("next detect id lookup failed: %s", error)
        return 1


def clear_ma_results() -> bool:
    """Remove all MA dashboard, detail, and discard-log rows."""
    try:
        require_db()
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"DELETE FROM `{TABLE_ANOMALY_DISCARD_LOG}`")
            cursor.execute(f"DELETE FROM `{TABLE_ANOMALY_DASHBOARD}`")
            cursor.close()
        logger.info("cleared MA dashboard and discard-log tables")
        return True
    except Exception as error:
        logger.error("MA result clear failed: %s", error)
        return False


def load_anomaly_history(limit: int = 5000) -> list[dict[str, Any]]:
    """Load IS_ANOMALY=1 telemetry rows for MA reprocessing."""
    try:
        require_db()
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                f"""
                SELECT * FROM `{TABLE_TLM_HISTORY}`
                WHERE IS_ANOMALY = 1
                ORDER BY UPDATED_AT ASC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            cursor.close()
        return [enrich_packet_from_db(dict(row)) for row in rows]
    except Exception as error:
        logger.error("anomaly history load failed: %s", error)
        return []
