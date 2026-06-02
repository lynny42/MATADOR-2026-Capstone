"""MySQL read/write helpers for ground-station tables."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from ma_detector.core.event_queue_columns import strip_event_fields_from_tlm_packet
from ma_detector.core.tlm_adcs_columns import sync_legacy_tlm_columns
from ma_detector.db.config import (
    TABLE_ANOMALY_DASHBOARD,
    TABLE_ANOMALY_DETAIL,
    TABLE_ANOMALY_DISCARD_LOG,
    TABLE_EVENT_QUEUE,
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
        "DETECT_TIMES",
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

_GRADE_RANK = {"CONFIRMED": 3, "SUSPECTED": 2, "PENDING": 1, "DISCARDED": 0}
DETECT_TIMES_EVIDENCE_KEY = "__detect_times__"
_DETECT_TIMES_EVIDENCE_KEY = DETECT_TIMES_EVIDENCE_KEY

# HISTORY_ID is not global-auto: gs_tlm_history uses AUTO_INCREMENT (omitted from INSERT row),
# but gs_pwr_meta must store the parent HISTORY_ID FK explicitly.
_AUTO_COLUMNS = frozenset({"PWR_META_ID", "DETAIL_ID", "LOG_ID", "CREATED_AT"})

# Bulk-wide archive keys: keep on merge rows for MA ingest, omit from gs_tlm_history INSERT.
_TLM_BULK_ONLY_COLUMNS = frozenset({"WIRE_PAYLOAD", "SOURCE_RECORDS"})

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
            TABLE_EVENT_QUEUE,
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


def build_tlm_history_insert_row(prepared: dict[str, Any]) -> dict[str, Any]:
    """Build one gs_tlm_history INSERT dict without bulk-wide JSON duplication."""
    try:
        row = dict(prepared)
        for key in _TLM_BULK_ONLY_COLUMNS:
            row.pop(key, None)
        payload = {
            key: value
            for key, value in prepared.items()
            if key not in _TLM_BULK_ONLY_COLUMNS and value is not None
        }
        row["PAYLOAD"] = payload
        row.pop("RAW_PAYLOAD", None)
        return row
    except Exception as error:
        logger.error("tlm history insert row build failed: %s", error)
        return dict(prepared)


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


def sanitize_rule_engine_fields(packet: dict[str, Any]) -> dict[str, Any]:
    """Normalize wire quirks before evidence rules (negative counters, RW err alias)."""
    try:
        combined = packet.get("COMBINEDPACKETSSENT")
        if isinstance(combined, (int, float)) and float(combined) < 0:
            packet["COMBINEDPACKETSSENT"] = None

        for wheel_index in range(3):
            enabled_key = f"DEVICE_ENABLED_RW{wheel_index}"
            err_key = f"DEVICE_ERR_RW{wheel_index}"
            enabled = packet.get(enabled_key)
            if enabled is not None:
                try:
                    packet[err_key] = 1 if int(enabled) == 0 else 0
                except (TypeError, ValueError) as error:
                    logger.error("DEVICE_ERR_RW alias failed for %s: %s", enabled_key, error)

        return packet
    except Exception as error:
        logger.error("rule engine field sanitize failed: %s", error)
        return packet


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

        sync_legacy_tlm_columns(packet)
        sanitize_rule_engine_fields(packet)

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
        tlm_only = strip_event_fields_from_tlm_packet(packet)
        prepared = prepare_packet_for_db(tlm_only)
        row = build_tlm_history_insert_row(prepared)
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


def insert_event_queue_row(row: dict[str, Any]) -> int | None:
    """Insert one onboard event row and return EVENT_QUEUE_ID."""
    try:
        if not is_db_available():
            return None
        from ma_detector.core.event_queue_columns import GS_EVENT_LEGACY_DERIVED_COLUMNS

        payload = dict(row)
        for column_name, _ddl in GS_EVENT_LEGACY_DERIVED_COLUMNS:
            payload.pop(column_name, None)
        payload.pop("HISTORY_ID", None)
        payload.pop("SNAPSHOT_ID", None)
        payload.pop("COMM_SESSION", None)
        if isinstance(payload.get("PAYLOAD"), dict):
            payload["PAYLOAD"] = dict(payload["PAYLOAD"])
        sql, params = _build_insert(TABLE_EVENT_QUEUE, payload)
        if not params:
            return None
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            event_queue_id = int(cursor.lastrowid)
            cursor.close()
        return event_queue_id
    except Exception as error:
        logger.error("%s insert failed: %s", TABLE_EVENT_QUEUE, error)
        return None


def enrich_event_queue_row(row: dict[str, Any]) -> dict[str, Any]:
    """Parse JSON columns on one raw gs_event_queue row."""
    try:
        item = dict(row)
        for key in ("PAYLOAD", "MODULE_SCORES"):
            if key in item:
                item[key] = _parse_json_value(item[key])
        return item
    except Exception as error:
        logger.error("event queue row enrich failed: %s", error)
        return dict(row)


def query_event_queue_row(event_queue_id: int) -> dict[str, Any]:
    """Fetch one gs_event_queue row by primary key."""
    try:
        if not is_db_available():
            return {}
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                f"SELECT * FROM `{TABLE_EVENT_QUEUE}` WHERE EVENT_QUEUE_ID = %s LIMIT 1",
                (int(event_queue_id),),
            )
            row = cursor.fetchone()
            cursor.close()
        if not row:
            return {}
        return enrich_event_queue_row(dict(row))
    except Exception as error:
        logger.error("event queue row query failed: %s", error)
        return {}


def query_history_row(history_id: int) -> dict[str, Any]:
    """Fetch one gs_tlm_history row by HISTORY_ID."""
    try:
        if not is_db_available():
            return {}
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                f"SELECT * FROM `{TABLE_TLM_HISTORY}` WHERE HISTORY_ID = %s LIMIT 1",
                (int(history_id),),
            )
            row = cursor.fetchone()
            cursor.close()
        if not row:
            return {}
        return enrich_packet_from_db(dict(row))
    except Exception as error:
        logger.error("history row query failed: %s", error)
        return {}


def query_attack_events(limit: int = 5000) -> list[dict[str, Any]]:
    """Load attack-class onboard events from gs_event_queue."""
    try:
        from ma_detector.core.ma_onboard_view import is_attack_event_row

        if not is_db_available():
            return []
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                f"""
                SELECT * FROM `{TABLE_EVENT_QUEUE}`
                WHERE EVENT_TYPE = 'ATTACK_CONFIRMED'
                   OR COALESCE(WEIGHT, 0) >= 50
                ORDER BY COALESCE(DETECTED_AT, TIMESTAMP, CREATED_AT) ASC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            cursor.close()
        return [
            enriched
            for row in rows
            if is_attack_event_row(enriched := enrich_event_queue_row(dict(row)))
        ]
    except Exception as error:
        logger.error("attack event query failed: %s", error)
        return []


def load_attack_replay_packets(limit: int = 5000) -> list[dict[str, Any]]:
    """Build MA replay packets from gs_event_queue joined to gs_tlm_history."""
    try:
        from ma_detector.core.bulk_history_merge import (
            build_ma_reference_packet,
            find_nearest_history_for_event,
        )

        packets: list[dict[str, Any]] = []
        for event_row in query_attack_events(limit):
            payload = event_row.get("PAYLOAD")
            event_ref = payload if isinstance(payload, dict) else event_row
            history_row: dict[str, Any] | None = None
            history_id = event_row.get("HISTORY_ID")
            if history_id is not None:
                history_row = query_history_row(int(history_id)) or None
            if history_row is None:
                detect_time = event_row.get("DETECTED_AT") or event_row.get("TIMESTAMP")
                if detect_time:
                    window = query_history_window(str(detect_time), window_size_sec=30, limit=20)
                    history_row, _delta = find_nearest_history_for_event(event_ref, window)
            if history_row is None:
                logger.warning(
                    "attack replay skipped: no tlm match event_id=%s detected_at=%s",
                    event_row.get("EVENT_ID"),
                    event_row.get("DETECTED_AT"),
                )
                continue
            packets.append(build_ma_reference_packet(history_row, event_row))
        if not packets:
            logger.warning("attack replay packets empty (events=%s)", len(query_attack_events(limit)))
        return packets
    except Exception as error:
        logger.error("attack replay packet load failed: %s", error)
        return []


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
        effective_history_id = history_id if history_id is not None else packet.get("HISTORY_ID")
        if effective_history_id is None:
            logger.error("%s insert skipped: missing HISTORY_ID", TABLE_PWR_META)
            return False
        prepared = prepare_packet_for_db(strip_event_fields_from_tlm_packet(packet))
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
                    "HISTORY_ID": int(effective_history_id),
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


def _normalize_detect_time(value: Any) -> str:
    """Normalize one detect instant for DETECT_TIMES storage."""
    try:
        from ma_detector.core.packet_protocol import time_key_from_value

        key = time_key_from_value(value)
        if key:
            return key.replace("T", " ")
        text = str(value or "").strip()
        return text
    except Exception as error:
        logger.error("detect time normalize failed: %s", error)
        return str(value or "")


def _parse_detect_times(row: dict[str, Any]) -> list[str]:
    """Read all stored detect instants from DETECT_TIMES or legacy DETECT_TIME."""
    try:
        parsed = _parse_json_value(row.get("DETECT_TIMES"))
        if isinstance(parsed, list):
            return [_normalize_detect_time(item) for item in parsed if item]
        evidence = _parse_json_value(row.get("EVIDENCE_KEYS"))
        if isinstance(evidence, dict):
            embedded = evidence.get(_DETECT_TIMES_EVIDENCE_KEY)
            if isinstance(embedded, list):
                return [_normalize_detect_time(item) for item in embedded if item]
        if row.get("DETECT_TIME"):
            return [_normalize_detect_time(row.get("DETECT_TIME"))]
        return []
    except Exception as error:
        logger.error("detect times parse failed: %s", error)
        return []


def _write_detect_times(payload: dict[str, Any], times: list[str]) -> None:
    """Persist detect instants on a dashboard row (column or evidence fallback)."""
    try:
        cleaned = [_normalize_detect_time(item) for item in times if item]
        if "DETECT_TIMES" in _table_columns(TABLE_ANOMALY_DASHBOARD):
            payload["DETECT_TIMES"] = cleaned
            return
        evidence = _parse_json_value(payload.get("EVIDENCE_KEYS"))
        if not isinstance(evidence, dict):
            evidence = {}
        evidence = dict(evidence)
        evidence[_DETECT_TIMES_EVIDENCE_KEY] = cleaned
        payload["EVIDENCE_KEYS"] = evidence
    except Exception as error:
        logger.error("detect times write failed: %s", error)


def _pick_higher_grade(current: Any, candidate: Any) -> str:
    try:
        current_grade = str(current or "")
        candidate_grade = str(candidate or "")
        if _GRADE_RANK.get(candidate_grade, 0) >= _GRADE_RANK.get(current_grade, 0):
            return candidate_grade
        return current_grade
    except Exception as error:
        logger.error("grade merge failed: %s", error)
        return str(current or candidate or "")


def _merge_triggered_rule_ids(existing: Any, incoming: Any) -> list[str]:
    try:
        merged: list[str] = []
        for source in (existing, incoming):
            if isinstance(source, list):
                for rule_id in source:
                    text = str(rule_id)
                    if text and text not in merged:
                        merged.append(text)
            elif isinstance(source, dict):
                for rule_id in source:
                    text = str(rule_id)
                    if text and text not in merged:
                        merged.append(text)
        return merged
    except Exception as error:
        logger.error("triggered rule merge failed: %s", error)
        return []


def ensure_dashboard_detect_times_column() -> bool:
    """Add DETECT_TIMES JSON column when missing (idempotent)."""
    try:
        if not is_db_available():
            return False
        refresh_column_cache()
        if "DETECT_TIMES" in _table_columns(TABLE_ANOMALY_DASHBOARD):
            return True
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"""
                ALTER TABLE `{TABLE_ANOMALY_DASHBOARD}`
                ADD COLUMN `DETECT_TIMES` JSON NULL
                COMMENT 'All detect instants for this MA_CODE'
                AFTER `DETECT_TIME`
                """
            )
            cursor.close()
        refresh_column_cache()
        logger.info("added %s.DETECT_TIMES column", TABLE_ANOMALY_DASHBOARD)
        return True
    except Exception as error:
        logger.warning("DETECT_TIMES column ensure failed: %s", error)
        return False


def query_dashboard_by_ma_code(ma_code: str) -> dict[str, Any] | None:
    """Return the latest dashboard row for one MA_CODE."""
    try:
        if not is_db_available() or not ma_code:
            return None
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                f"""
                SELECT * FROM `{TABLE_ANOMALY_DASHBOARD}`
                WHERE MA_CODE = %s
                ORDER BY DETECT_ID DESC
                LIMIT 1
                """,
                (str(ma_code),),
            )
            row = cursor.fetchone()
            cursor.close()
        if not row:
            return None
        item = dict(row)
        for col in _JSON_COLUMNS:
            if col in item:
                item[col] = _parse_json_value(item[col])
        return item
    except Exception as error:
        logger.error("dashboard lookup by ma_code failed: %s", error)
        return None


def _update_dashboard_row(detect_id: int, updates: dict[str, Any]) -> bool:
    try:
        if not is_db_available():
            return False
        assignments: list[str] = []
        params: list[Any] = []
        allowed = set(_table_columns(TABLE_ANOMALY_DASHBOARD))
        for column, value in updates.items():
            if column not in allowed or column in _AUTO_COLUMNS:
                continue
            if value is None:
                continue
            assignments.append(f"`{column}` = %s")
            params.append(_serialize_value(column, value))
        if not assignments:
            return False
        params.append(int(detect_id))
        sql = f"UPDATE `{TABLE_ANOMALY_DASHBOARD}` SET {', '.join(assignments)} WHERE DETECT_ID = %s"
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            cursor.close()
        return True
    except Exception as error:
        logger.error("dashboard update failed: %s", error)
        return False


parse_dashboard_detect_times = _parse_detect_times
write_dashboard_detect_times = _write_detect_times
pick_higher_ma_grade = _pick_higher_grade
merge_dashboard_triggered_rule_ids = _merge_triggered_rule_ids
normalize_dashboard_detect_time = _normalize_detect_time


def append_dashboard_occurrence(row: dict[str, Any]) -> int | None:
    """Insert one MA_CODE row, or append DETECT_TIME when the same MA_CODE already exists."""
    try:
        if not is_db_available():
            return None
        ensure_dashboard_detect_times_column()
        ma_code = str(row.get("MA_CODE") or "").strip()
        if not ma_code:
            return insert_dashboard_row(row)

        detect_time = _normalize_detect_time(row.get("DETECT_TIME"))
        existing = query_dashboard_by_ma_code(ma_code)
        if existing is None:
            payload = dict(row)
            times = [detect_time] if detect_time else []
            if times:
                payload["DETECT_TIME"] = times[-1]
                _write_detect_times(payload, times)
            return insert_dashboard_row(payload)

        detect_id = int(existing["DETECT_ID"])
        times = _parse_detect_times(existing)
        if detect_time and detect_time not in times:
            times.append(detect_time)
        times.sort()

        merged_rules = _merge_triggered_rule_ids(
            existing.get("TRIGGERED_RULE_IDS"),
            row.get("TRIGGERED_RULE_IDS"),
        )
        updates: dict[str, Any] = {
            "DETECT_TIME": times[-1] if times else row.get("DETECT_TIME"),
            "CONFIDENCE_SCORE": max(
                float(existing.get("CONFIDENCE_SCORE") or 0.0),
                float(row.get("CONFIDENCE_SCORE") or 0.0),
            ),
            "GRADE": _pick_higher_grade(existing.get("GRADE"), row.get("GRADE")),
            "CORROBORATION_COUNT": max(
                int(existing.get("CORROBORATION_COUNT") or 0),
                int(row.get("CORROBORATION_COUNT") or 0),
            ),
            "TRIGGERED_RULE_IDS": merged_rules,
            "EVIDENCE_KEYS": row.get("EVIDENCE_KEYS") or existing.get("EVIDENCE_KEYS"),
            "TRIGGERED_RULE_RESULTS": row.get("TRIGGERED_RULE_RESULTS")
            or existing.get("TRIGGERED_RULE_RESULTS"),
            "MATCHES_SATELLITE_TARGET": int(
                bool(existing.get("MATCHES_SATELLITE_TARGET"))
                or bool(row.get("MATCHES_SATELLITE_TARGET"))
            ),
        }
        _write_detect_times(updates, times)
        if not _update_dashboard_row(detect_id, updates):
            return detect_id
        logger.info(
            "dashboard occurrence appended: ma_code=%s detect_id=%s times=%s",
            ma_code,
            detect_id,
            len(times),
        )
        return detect_id
    except Exception as error:
        logger.error("dashboard occurrence append failed: %s", error)
        return None


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
        if payload.get("DETECT_TIME") and not payload.get("DETECT_TIMES"):
            _write_detect_times(payload, [_normalize_detect_time(payload.get("DETECT_TIME"))])
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
                f"""
                SELECT * FROM `{TABLE_ANOMALY_DETAIL}`
                WHERE DASHBOARD_ID = %s
                ORDER BY DETAIL_ID ASC
                """,
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
    """Return nearest attack event + linked telemetry around detect_time."""
    try:
        if not is_db_available() or not detect_time:
            return {}
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                f"""
                SELECT * FROM `{TABLE_EVENT_QUEUE}`
                WHERE (EVENT_TYPE = 'ATTACK_CONFIRMED' OR COALESCE(WEIGHT, 0) >= 50)
                  AND COALESCE(DETECTED_AT, TIMESTAMP) BETWEEN DATE_SUB(%s, INTERVAL %s SECOND)
                                                             AND DATE_ADD(%s, INTERVAL %s SECOND)
                ORDER BY ABS(
                    TIMESTAMPDIFF(
                        SECOND,
                        COALESCE(DETECTED_AT, TIMESTAMP),
                        %s
                    )
                ) ASC
                LIMIT 1
                """,
                (detect_time, tolerance_sec, detect_time, tolerance_sec, detect_time),
            )
            row = cursor.fetchone()
            cursor.close()
        if not row:
            return {}
        event_row = enrich_event_queue_row(dict(row))
        history_id = event_row.get("HISTORY_ID")
        if history_id is not None:
            history = query_history_row(int(history_id))
            if history:
                from ma_detector.core.bulk_history_merge import build_ma_reference_packet

                return build_ma_reference_packet(history, event_row)
        payload = event_row.get("PAYLOAD")
        event_ref = payload if isinstance(payload, dict) else event_row
        detect_at = event_row.get("DETECTED_AT") or event_row.get("TIMESTAMP")
        if detect_at:
            from ma_detector.core.bulk_history_merge import (
                build_ma_reference_packet,
                find_nearest_history_for_event,
            )

            window = query_history_window(str(detect_at), window_size_sec=tolerance_sec, limit=10)
            history_row, _delta = find_nearest_history_for_event(event_ref, window)
            if history_row is not None:
                return build_ma_reference_packet(history_row, event_row)
        return event_row
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
                SELECT h.*
                FROM `{TABLE_TLM_HISTORY}` h
                WHERE NOT EXISTS (
                    SELECT 1 FROM `{TABLE_EVENT_QUEUE}` e
                    WHERE (e.EVENT_TYPE = 'ATTACK_CONFIRMED' OR COALESCE(e.WEIGHT, 0) >= 50)
                      AND ABS(
                          TIMESTAMPDIFF(
                              SECOND,
                              COALESCE(e.DETECTED_AT, e.TIMESTAMP),
                              h.UPDATED_AT
                          )
                      ) <= 5
                )
                ORDER BY h.UPDATED_AT DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            cursor.close()
        results = [enrich_packet_from_db(dict(row)) for row in rows]
        results.reverse()
        if results:
            return results
        return _load_pre_attack_baseline_fallback(limit)
    except Exception as error:
        logger.error("baseline history load failed: %s", error)
        return []


def _load_pre_attack_baseline_fallback(limit: int) -> list[dict[str, Any]]:
    """When every TLM row is near an attack event, use earliest snapshots as baseline (comm-3 demo)."""
    try:
        from ma_detector.core.bulk_history_merge import select_pre_attack_baseline_rows
        from ma_detector.core.ma_onboard_view import _event_source_dict

        tlm_rows = load_recent_tlm_history(limit)
        if not tlm_rows:
            return []
        event_payloads = [
            _event_source_dict(enrich_event_queue_row(dict(row)))
            for row in query_attack_events(limit)
        ]
        baseline = select_pre_attack_baseline_rows(tlm_rows, event_payloads)
        if baseline:
            logger.info("baseline fallback: %s pre-attack tlm row(s)", len(baseline))
        return baseline
    except Exception as error:
        logger.error("pre-attack baseline fallback failed: %s", error)
        return []


def load_replay_payloads(from_time: str, to_time: str) -> list[str]:
    """Load attack replay JSON strings for gs_event_queue rows in a time range."""
    try:
        if not is_db_available():
            return []
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                f"""
                SELECT * FROM `{TABLE_EVENT_QUEUE}`
                WHERE (EVENT_TYPE = 'ATTACK_CONFIRMED' OR COALESCE(WEIGHT, 0) >= 50)
                  AND COALESCE(DETECTED_AT, TIMESTAMP, CREATED_AT)
                      BETWEEN %s AND %s
                ORDER BY COALESCE(DETECTED_AT, TIMESTAMP, CREATED_AT) ASC
                """,
                (from_time, to_time),
            )
            rows = cursor.fetchall()
            cursor.close()
        from ma_detector.core.bulk_history_merge import (
            build_ma_reference_packet,
            find_nearest_history_for_event,
        )

        payloads: list[str] = []
        for row in rows:
            event_row = enrich_event_queue_row(dict(row))
            payload = event_row.get("PAYLOAD")
            event_ref = payload if isinstance(payload, dict) else event_row
            history_row: dict[str, Any] | None = None
            history_id = event_row.get("HISTORY_ID")
            if history_id is not None:
                history_row = query_history_row(int(history_id)) or None
            if history_row is None:
                detect_time = event_row.get("DETECTED_AT") or event_row.get("TIMESTAMP")
                if detect_time:
                    window = query_history_window(str(detect_time), window_size_sec=30, limit=20)
                    history_row, _delta = find_nearest_history_for_event(event_ref, window)
            if history_row is None:
                continue
            packet = build_ma_reference_packet(history_row, event_row)
            payloads.append(json.dumps(packet, ensure_ascii=False, default=str))
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


def load_recent_event_queue(limit: int = 500) -> list[dict[str, Any]]:
    """Load recent onboard events for dashboard communication clustering."""
    try:
        if not is_db_available():
            return []
        with get_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                f"""
                SELECT * FROM (
                    SELECT * FROM `{TABLE_EVENT_QUEUE}`
                    ORDER BY COALESCE(DETECTED_AT, TIMESTAMP, CREATED_AT) DESC
                    LIMIT %s
                ) AS recent
                ORDER BY COALESCE(DETECTED_AT, TIMESTAMP, CREATED_AT) ASC
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            cursor.close()
        return [enrich_event_queue_row(dict(row)) for row in rows]
    except Exception as error:
        logger.error("recent event queue load failed: %s", error)
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
    """Load attack replay packets built from gs_event_queue + gs_tlm_history."""
    try:
        return load_attack_replay_packets(limit)
    except Exception as error:
        logger.error("anomaly history load failed: %s", error)
        return []
