"""Merge SAT_BULK_TELEMETRY sections by SNAPSHOT_ID or HISTORY_ID without fuzzy time buckets."""

from __future__ import annotations

import json
import logging
from typing import Any

from ma_detector.core.packet_protocol import (
    DEFAULT_RECORD_MATCH_TOLERANCE_SEC,
    event_is_attack_anomaly,
    extract_event_queue_section_events,
    infer_subsystem_from_file_path,
    normalize_packet_type,
    record_time_key,
    scrub_record,
    time_key_from_value,
    time_key_to_epoch,
)
from ma_detector.core.event_queue_columns import (
    ONBOARD_EVENT_WIRE_FIELDS,
    apply_onboard_event_to_queue_row,
    parse_module_scores,
)
from ma_detector.core.target_context import infer_target_from_sw_ids
from ma_detector.core.tlm_adcs_columns import (
    TLM_ADCS_OVERLAP_FIELD_SET,
    adcs_column,
    tlm_column,
)

logger = logging.getLogger(__name__)

METADATA_SKIP_FIELDS = frozenset({"SNAPSHOT_ID", "SNAPSHOT_AT"})
TLM_SKIP_FLAT_FIELDS = frozenset({"channels", "HISTORY_ID", "UPDATED_AT"}) | METADATA_SKIP_FIELDS
ADCS_SKIP_FLAT_FIELDS = frozenset({"HISTORY_ID", "TIMESTAMP"}) | METADATA_SKIP_FIELDS
PWR_SKIP_FLAT_FIELDS = frozenset({"HISTORY_ID", "UPDATED_AT", "channels"}) | METADATA_SKIP_FIELDS

EVENT_REFERENCE_FIELDS = ONBOARD_EVENT_WIRE_FIELDS

EVENT_QUEUE_META_FIELDS = frozenset(
    {
        "EVENT_QUEUE_ID",
        "HISTORY_ID",
        "SNAPSHOT_ID",
        "COMM_SESSION",
        "BULK_SENT_AT",
        "PAYLOAD",
        "CREATED_AT",
    }
)

MA_GATE_FIELDS = (
    "EVENT_ID",
    "EVENT_TYPE",
    "WEIGHT",
    "TARGET_SUBSYSTEM",
    "SW_ID",
    "DETECTED_AT",
    "FALSE_POSITIVE_RESULT",
    "FALSE_POSITIVE_WEIGHT",
    "FALSE_POSITIVE_EXCEPTION",
    "EXCEPTION_CODE",
)


def apply_event_fields_to_row(row: dict[str, Any], event: dict[str, Any]) -> None:
    """Legacy helper: copy onboard event fields onto a dict (tests / old merge paths)."""
    try:
        apply_onboard_event_to_queue_row(row, event)
        cleaned = scrub_record(event)
        sw_id = cleaned.get("SW_ID")
        if sw_id is not None:
            sw_list = row.setdefault("SW_ID_LIST", [])
            if isinstance(sw_list, list) and int(sw_id) not in sw_list:
                sw_list.append(int(sw_id))
    except Exception as error:
        logger.error("event field apply failed: %s", error)


def _pick_best_event(events: list[dict[str, Any]]) -> dict[str, Any] | None:
    try:
        if not events:
            return None
        attacks = [event for event in events if event_is_attack_anomaly(event)]
        pool = attacks or events
        return sorted(
            pool,
            key=lambda item: (
                int(item.get("PRIORITY", 0) or 0),
                int(item.get("WEIGHT", 0) or 0),
            ),
            reverse=True,
        )[0]
    except Exception as error:
        logger.error("event pick failed: %s", error)
        return events[0] if events else None


def _nearest_event_for_row(
    events: list[dict[str, Any]],
    row: dict[str, Any],
) -> dict[str, Any] | None:
    try:
        if not events:
            return None
        if len(events) == 1:
            return events[0]

        anchor = time_key_to_epoch(row.get("SNAPSHOT_AT") or row.get("UPDATED_AT"))
        if anchor is None:
            return _pick_best_event(events)

        best_event: dict[str, Any] | None = None
        best_delta = float("inf")
        for event in events:
            event_epoch = time_key_to_epoch(
                event.get("DETECTED_AT") or event.get("TIMESTAMP"),
            )
            if event_epoch is None:
                continue
            delta = abs(event_epoch - anchor)
            if delta < best_delta:
                best_delta = delta
                best_event = event
        return best_event or _pick_best_event(events)
    except Exception as error:
        logger.error("nearest event lookup failed: %s", error)
        return _pick_best_event(events)


def apply_bulk_events_to_rows(
    rows: list[dict[str, Any]],
    events: list[dict[str, Any]] | None,
) -> None:
    """Map SAT_EVENT_QUEUE events onto merged rows using SNAPSHOT_ID or time proximity."""
    try:
        if not rows or not events:
            return

        by_snapshot: dict[int, list[dict[str, Any]]] = {}
        orphan_events: list[dict[str, Any]] = []
        for event in events:
            snapshot_id = record_snapshot_id(event)
            if snapshot_id is not None:
                by_snapshot.setdefault(snapshot_id, []).append(event)
            else:
                orphan_events.append(event)

        if len(rows) == 1 and events:
            best = _pick_best_event(events)
            if best is not None:
                apply_event_fields_to_row(rows[0], best)
            return

        for row in rows:
            snapshot_id = row.get("SNAPSHOT_ID")
            candidates: list[dict[str, Any]] = []
            if snapshot_id is not None:
                candidates = list(by_snapshot.get(int(snapshot_id), []))
            if not candidates:
                candidates = list(orphan_events)
            best = _nearest_event_for_row(candidates, row) if candidates else None
            if best is not None:
                apply_event_fields_to_row(row, best)
    except Exception as error:
        logger.error("bulk event apply failed: %s", error)


def record_snapshot_id(record: dict[str, Any] | None) -> int | None:
    """Return onboard SNAPSHOT_ID when present."""
    try:
        if not isinstance(record, dict):
            return None
        snapshot_id = record.get("SNAPSHOT_ID")
        if snapshot_id is None:
            return None
        return int(snapshot_id)
    except (TypeError, ValueError) as error:
        logger.error("snapshot id parse failed: %s", error)
        return None
    except Exception as error:
        logger.error("snapshot id read failed: %s", error)
        return None


def _record_sort_key(record: dict[str, Any]) -> tuple[int, int, int, str]:
    """Sort samples by SNAPSHOT_ID, then HISTORY_ID, then time key."""
    try:
        snapshot_id = record_snapshot_id(record)
        if snapshot_id is not None:
            return (0, snapshot_id, 0, record_time_key(record))
        history_id = record.get("HISTORY_ID")
        if history_id is not None:
            try:
                return (1, 0, int(history_id), record_time_key(record))
            except (TypeError, ValueError):
                pass
        return (2, 0, 0, record_time_key(record))
    except Exception as error:
        logger.error("record sort key build failed: %s", error)
        return (3, 0, 0, "")


def _sorted_records(records: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    try:
        if not isinstance(records, list):
            return []
        cleaned = [scrub_record(record) for record in records if isinstance(record, dict)]
        return sorted(cleaned, key=_record_sort_key)
    except Exception as error:
        logger.error("record sort failed: %s", error)
        return []


def _index_records_by_snapshot_id(
    records: list[dict[str, Any]] | None,
) -> dict[int, dict[str, Any]]:
    try:
        indexed: dict[int, dict[str, Any]] = {}
        for record in records or []:
            snapshot_id = record_snapshot_id(record)
            if snapshot_id is None:
                continue
            indexed[snapshot_id] = record
        return indexed
    except Exception as error:
        logger.error("snapshot index build failed: %s", error)
        return {}


def _ordered_snapshot_ids(
    snapshot_records: list[dict[str, Any]] | None,
    tlm_records: list[dict[str, Any]] | None,
    adcs_records: list[dict[str, Any]] | None,
    pwr_records: list[dict[str, Any]] | None,
) -> list[int]:
    """Prefer SAT_SNAPSHOT order, else sorted union of section SNAPSHOT_ID values."""
    try:
        if snapshot_records:
            ordered: list[int] = []
            for record in _sorted_records(snapshot_records):
                snapshot_id = record_snapshot_id(record)
                if snapshot_id is not None and snapshot_id not in ordered:
                    ordered.append(snapshot_id)
            if ordered:
                return ordered

        union: set[int] = set()
        for records in (tlm_records, adcs_records, pwr_records):
            for record in records or []:
                snapshot_id = record_snapshot_id(record)
                if snapshot_id is not None:
                    union.add(snapshot_id)
        return sorted(union)
    except Exception as error:
        logger.error("snapshot id ordering failed: %s", error)
        return []


def _snapshot_at_lookup(snapshot_records: list[dict[str, Any]] | None) -> dict[int, Any]:
    try:
        lookup: dict[int, Any] = {}
        for record in snapshot_records or []:
            snapshot_id = record_snapshot_id(record)
            if snapshot_id is None:
                continue
            snapshot_at = record.get("SNAPSHOT_AT")
            if snapshot_at is not None:
                lookup[snapshot_id] = snapshot_at
        return lookup
    except Exception as error:
        logger.error("snapshot at lookup failed: %s", error)
        return {}


def _uses_snapshot_alignment(
    tlm_records: list[dict[str, Any]] | None,
    adcs_records: list[dict[str, Any]] | None,
    pwr_records: list[dict[str, Any]] | None,
    snapshot_records: list[dict[str, Any]] | None,
) -> bool:
    try:
        if snapshot_records:
            return True
        sections_with_ids = 0
        for records in (tlm_records, adcs_records, pwr_records):
            if any(record_snapshot_id(record) is not None for record in records or []):
                sections_with_ids += 1
        return sections_with_ids >= 2
    except Exception as error:
        logger.error("snapshot alignment check failed: %s", error)
        return False


def _apply_tlm_fields(row: dict[str, Any], record: dict[str, Any]) -> None:
    try:
        snapshot_id = record_snapshot_id(record)
        if snapshot_id is not None:
            row["SNAPSHOT_ID"] = snapshot_id
        if record.get("HISTORY_ID") is not None:
            row["TLM_HISTORY_ID"] = record.get("HISTORY_ID")
        updated_at = record.get("UPDATED_AT")
        if updated_at:
            row["UPDATED_AT"] = updated_at
        for key, value in record.items():
            if key in TLM_SKIP_FLAT_FIELDS:
                continue
            if value is None:
                continue
            if key in TLM_ADCS_OVERLAP_FIELD_SET:
                row[tlm_column(key)] = value
                row[key] = value
            else:
                row[key] = value
    except Exception as error:
        logger.error("tlm field apply failed: %s", error)


def _apply_adcs_fields(row: dict[str, Any], record: dict[str, Any]) -> None:
    try:
        snapshot_id = record_snapshot_id(record)
        if snapshot_id is not None and row.get("SNAPSHOT_ID") is None:
            row["SNAPSHOT_ID"] = snapshot_id
        if record.get("HISTORY_ID") is not None:
            row["ADCS_HISTORY_ID"] = record.get("HISTORY_ID")
        timestamp = record.get("TIMESTAMP")
        if timestamp:
            row["ADCS_TIMESTAMP"] = timestamp
            if not row.get("UPDATED_AT"):
                row["UPDATED_AT"] = timestamp
        for key, value in record.items():
            if key in ADCS_SKIP_FLAT_FIELDS:
                continue
            if value is None:
                continue
            if key in TLM_ADCS_OVERLAP_FIELD_SET:
                row[adcs_column(key)] = value
            else:
                row[key] = value
    except Exception as error:
        logger.error("adcs field apply failed: %s", error)


def _apply_pwr_fields(row: dict[str, Any], record: dict[str, Any]) -> None:
    try:
        snapshot_id = record_snapshot_id(record)
        if snapshot_id is not None and row.get("SNAPSHOT_ID") is None:
            row["SNAPSHOT_ID"] = snapshot_id
        if record.get("HISTORY_ID") is not None:
            row["PWR_HISTORY_ID"] = record.get("HISTORY_ID")
        updated_at = record.get("UPDATED_AT")
        if updated_at and not row.get("UPDATED_AT"):
            row["UPDATED_AT"] = updated_at
        channels = record.get("channels")
        if isinstance(channels, list) and channels:
            for channel in channels:
                if not isinstance(channel, dict):
                    continue
                sw_id = channel.get("SW_ID", 0)
                row[f"SW_{sw_id}_VOLTAGE"] = channel.get("VOLTAGE")
                row[f"SW_{sw_id}_CURRENT_A"] = channel.get("CURRENT_A")
                row[f"SW_{sw_id}_CURRENT"] = channel.get("CURRENT_A")
                row[f"SW_{sw_id}_PREV_VOLTAGE"] = channel.get("PREV_VOLTAGE")
                row[f"SW_{sw_id}_PREV_DELTA_V"] = channel.get("PREV_DELTA_V")
                row[f"SW_{sw_id}_CURR_DELTA_V"] = channel.get("CURR_DELTA_V")
                row[f"SW_{sw_id}_EXCEED_COUNT"] = channel.get("EXCEED_COUNT")
                row[f"SW_{sw_id}_CONSECUTIVE_EXCEED"] = channel.get("CONSECUTIVE_EXCEED")
                row[f"SW_{sw_id}_ANOMALY_FLAG"] = channel.get("ANOMALY_FLAG")
                row[f"SW_{sw_id}_V_THRESHOLD_LO"] = channel.get("V_THRESHOLD_LO")
                row[f"SW_{sw_id}_V_THRESHOLD_HI"] = channel.get("V_THRESHOLD_HI")
                if channel.get("ANOMALY_FLAG", 0) == 1:
                    sw_list = row.setdefault("SW_ID_LIST", [])
                    if isinstance(sw_list, list) and int(sw_id) not in sw_list:
                        sw_list.append(int(sw_id))
        elif record.get("SW_ID") is not None:
            sw_id = record.get("SW_ID", 0)
            row[f"SW_{sw_id}_VOLTAGE"] = record.get("VOLTAGE")
            row[f"SW_{sw_id}_CURRENT_A"] = record.get("CURRENT_A")
            row[f"SW_{sw_id}_CURRENT"] = record.get("CURRENT_A")
            row[f"SW_{sw_id}_PREV_VOLTAGE"] = record.get("PREV_VOLTAGE")
            row[f"SW_{sw_id}_PREV_DELTA_V"] = record.get("PREV_DELTA_V")
            row[f"SW_{sw_id}_CURR_DELTA_V"] = record.get("CURR_DELTA_V")
            row[f"SW_{sw_id}_EXCEED_COUNT"] = record.get("EXCEED_COUNT")
            row[f"SW_{sw_id}_CONSECUTIVE_EXCEED"] = record.get("CONSECUTIVE_EXCEED")
            row[f"SW_{sw_id}_ANOMALY_FLAG"] = record.get("ANOMALY_FLAG")
            row[f"SW_{sw_id}_V_THRESHOLD_LO"] = record.get("V_THRESHOLD_LO")
            row[f"SW_{sw_id}_V_THRESHOLD_HI"] = record.get("V_THRESHOLD_HI")
            if record.get("ANOMALY_FLAG", 0) == 1:
                sw_list = row.setdefault("SW_ID_LIST", [])
                if isinstance(sw_list, list) and int(sw_id) not in sw_list:
                    sw_list.append(int(sw_id))
    except Exception as error:
        logger.error("pwr field apply failed: %s", error)


def merge_sample_records(
    tlm_record: dict[str, Any] | None,
    adcs_record: dict[str, Any] | None,
    pwr_record: dict[str, Any] | None,
    *,
    sample_index: int,
    snapshot_id: int | None = None,
    snapshot_at: Any = None,
) -> dict[str, Any] | None:
    """Merge one aligned TLM/ADCS/PWR sample into one gs_tlm_history row dict."""
    try:
        if not any(isinstance(record, dict) for record in (tlm_record, adcs_record, pwr_record)):
            return None

        row: dict[str, Any] = {
            "SAMPLE_INDEX": sample_index,
            "PACKET_TYPE": "SAT_BULK_TELEMETRY",
            "HISTORY_ONLY": True,
        }
        if snapshot_id is not None:
            row["SNAPSHOT_ID"] = snapshot_id
        if snapshot_at is not None:
            row["SNAPSHOT_AT"] = snapshot_at

        source: dict[str, Any] = {}
        if isinstance(tlm_record, dict):
            source["tlm"] = dict(tlm_record)
            _apply_tlm_fields(row, tlm_record)
        if isinstance(adcs_record, dict):
            source["adcs"] = dict(adcs_record)
            _apply_adcs_fields(row, adcs_record)
        if isinstance(pwr_record, dict):
            source["pwr"] = dict(pwr_record)
            _apply_pwr_fields(row, pwr_record)

        row["SOURCE_RECORDS"] = source

        time_key = time_key_from_value(row.get("UPDATED_AT"))
        if time_key:
            row["UPDATED_AT"] = time_key.replace("T", " ")

        adcs_ts = row.get("ADCS_TIMESTAMP")
        if adcs_ts:
            adcs_key = time_key_from_value(adcs_ts)
            if adcs_key:
                row["ADCS_TIMESTAMP"] = adcs_key.replace("T", " ")

        snapshot_at_value = row.get("SNAPSHOT_AT")
        if snapshot_at_value:
            snapshot_key = time_key_from_value(snapshot_at_value)
            if snapshot_key:
                row["SNAPSHOT_AT"] = snapshot_key.replace("T", " ")

        sample_id = (
            row.get("SNAPSHOT_ID")
            or row.get("TLM_HISTORY_ID")
            or row.get("PWR_HISTORY_ID")
            or row.get("ADCS_HISTORY_ID")
            or sample_index
        )
        row["SAMPLE_HISTORY_ID"] = sample_id
        return row
    except Exception as error:
        logger.error("sample record merge failed: %s", error)
        return None


def _merge_by_snapshot_id(
    adcs_records: list[dict[str, Any]] | None,
    tlm_records: list[dict[str, Any]] | None,
    pwr_records: list[dict[str, Any]] | None,
    snapshot_records: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    try:
        ordered_ids = _ordered_snapshot_ids(snapshot_records, tlm_records, adcs_records, pwr_records)
        if not ordered_ids:
            return []

        tlm_by_id = _index_records_by_snapshot_id(tlm_records)
        adcs_by_id = _index_records_by_snapshot_id(adcs_records)
        pwr_by_id = _index_records_by_snapshot_id(pwr_records)
        snapshot_at_by_id = _snapshot_at_lookup(snapshot_records)

        merged_rows: list[dict[str, Any]] = []
        for index, snapshot_id in enumerate(ordered_ids):
            row = merge_sample_records(
                tlm_by_id.get(snapshot_id),
                adcs_by_id.get(snapshot_id),
                pwr_by_id.get(snapshot_id),
                sample_index=index,
                snapshot_id=snapshot_id,
                snapshot_at=snapshot_at_by_id.get(snapshot_id),
            )
            if row is not None:
                merged_rows.append(row)
        return merged_rows
    except Exception as error:
        logger.error("snapshot merge failed: %s", error)
        return []


def _merge_by_sorted_index(
    adcs_records: list[dict[str, Any]] | None,
    tlm_records: list[dict[str, Any]] | None,
    pwr_records: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    try:
        adcs_sorted = _sorted_records(adcs_records)
        tlm_sorted = _sorted_records(tlm_records)
        pwr_sorted = _sorted_records(pwr_records)

        sample_count = max(len(adcs_sorted), len(tlm_sorted), len(pwr_sorted))
        if sample_count == 0:
            return []

        if len({len(adcs_sorted), len(tlm_sorted), len(pwr_sorted)}) > 1:
            logger.warning(
                "bulk section length mismatch adcs=%s tlm=%s pwr=%s; merging by index",
                len(adcs_sorted),
                len(tlm_sorted),
                len(pwr_sorted),
            )

        merged_rows: list[dict[str, Any]] = []
        for index in range(sample_count):
            row = merge_sample_records(
                tlm_sorted[index] if index < len(tlm_sorted) else None,
                adcs_sorted[index] if index < len(adcs_sorted) else None,
                pwr_sorted[index] if index < len(pwr_sorted) else None,
                sample_index=index,
            )
            if row is not None:
                merged_rows.append(row)
        return merged_rows
    except Exception as error:
        logger.error("index merge failed: %s", error)
        return []


def merge_bulk_telemetry_sections(
    adcs_records: list[dict[str, Any]] | None,
    tlm_records: list[dict[str, Any]] | None,
    pwr_records: list[dict[str, Any]] | None,
    snapshot_records: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Align sections by SNAPSHOT_ID when available, else sorted HISTORY_ID / time index."""
    try:
        if _uses_snapshot_alignment(tlm_records, adcs_records, pwr_records, snapshot_records):
            return _merge_by_snapshot_id(adcs_records, tlm_records, pwr_records, snapshot_records)
        return _merge_by_sorted_index(adcs_records, tlm_records, pwr_records)
    except Exception as error:
        logger.error("bulk telemetry section merge failed: %s", error)
        return []


def _pick_integrity_record(records: list[dict[str, Any]]) -> dict[str, Any] | None:
    try:
        if not records:
            return None
        violated = [record for record in records if int(record.get("IS_VIOLATED", 0) or 0) == 1]
        if violated:
            return violated[0]
        return records[0]
    except Exception as error:
        logger.error("integrity record pick failed: %s", error)
        return None


def _apply_integrity_fields(row: dict[str, Any], record: dict[str, Any]) -> None:
    try:
        row["INTEGRITY_FILE_ID"] = record.get("FILE_ID")
        row["INTEGRITY_FILE_PATH"] = record.get("FILE_PATH")
        row["EXPECTED_HASH"] = record.get("EXPECTED_HASH")
        row["IS_VIOLATED"] = record.get("IS_VIOLATED")
        last_verified = record.get("LAST_VERIFIED_AT")
        if last_verified:
            verified_key = time_key_from_value(last_verified)
            if verified_key:
                row["INTEGRITY_LAST_VERIFIED_AT"] = verified_key.replace("T", " ")
        source = row.setdefault("SOURCE_RECORDS", {})
        if isinstance(source, dict):
            source["integrity"] = dict(record)
    except Exception as error:
        logger.error("integrity field apply failed: %s", error)


def apply_bulk_integrity_to_rows(rows: list[dict[str, Any]], records: list[dict[str, Any]]) -> None:
    """Attach SAT_INTEGRITY_HASH fields to each merged row (same snapshot batch)."""
    try:
        chosen = _pick_integrity_record(records)
        if not chosen:
            return
        for row in rows:
            _apply_integrity_fields(row, chosen)
    except Exception as error:
        logger.error("bulk integrity apply failed: %s", error)


def bulk_wire_archive(bulk: dict[str, Any]) -> dict[str, Any]:
    """Return uplink bulk JSON without internal comm-session keys."""
    try:
        return {
            key: value
            for key, value in bulk.items()
            if not str(key).startswith("_")
        }
    except Exception as error:
        logger.error("bulk wire archive build failed: %s", error)
        return dict(bulk)


def attach_bulk_envelope_fields(rows: list[dict[str, Any]], bulk: dict[str, Any]) -> None:
    """Set WIRE_PAYLOAD and bulk envelope columns on merged rows."""
    try:
        wire = bulk_wire_archive(bulk)
        sent_at = bulk.get("sent_at")
        note = bulk.get("note")
        sent_key = time_key_from_value(sent_at) if sent_at else None
        comm_session = str(bulk.get("_comm_session", "") or "").strip()
        for row in rows:
            row["WIRE_PAYLOAD"] = wire
            if sent_key:
                row["BULK_SENT_AT"] = sent_key.replace("T", " ")
            if comm_session:
                row["COMM_SESSION"] = comm_session
            if note:
                row["BULK_NOTE"] = str(note)
    except Exception as error:
        logger.error("bulk envelope attach failed: %s", error)


def extract_bulk_section_records(bulk: dict[str, Any], section_key: str) -> list[dict[str, Any]]:
    """Return records list from one SAT_BULK_TELEMETRY nested section."""
    try:
        section = bulk.get(section_key)
        if not isinstance(section, dict):
            return []
        records = section.get("records")
        if isinstance(records, list):
            return [record for record in records if isinstance(record, dict)]
        return []
    except Exception as error:
        logger.error("bulk section extract failed: %s", error)
        return []


def merge_bulk_telemetry_packet(bulk: dict[str, Any]) -> list[dict[str, Any]]:
    """Build merged gs_tlm_history rows from one SAT_BULK_TELEMETRY packet."""
    try:
        packet_type = normalize_packet_type(str(bulk.get("packet_type", "")).strip())
        if packet_type != "SAT_BULK_TELEMETRY":
            return []

        snapshot_records = extract_bulk_section_records(bulk, "SAT_SNAPSHOT")
        adcs_records = extract_bulk_section_records(bulk, "SAT_ADCS_FILTER")
        tlm_records = extract_bulk_section_records(bulk, "SAT_TLM_HISTORY")
        pwr_records = extract_bulk_section_records(bulk, "SAT_PWR_HISTORY")
        rows = merge_bulk_telemetry_sections(
            adcs_records,
            tlm_records,
            pwr_records,
            snapshot_records=snapshot_records,
        )

        integrity_records = extract_bulk_section_records(bulk, "SAT_INTEGRITY_HASH")
        if integrity_records:
            apply_bulk_integrity_to_rows(rows, integrity_records)

        attach_bulk_envelope_fields(rows, bulk)
        return rows
    except Exception as error:
        logger.error("bulk telemetry packet merge failed: %s", error)
        return []


def extract_bulk_event_records(bulk: dict[str, Any]) -> list[dict[str, Any]]:
    """Return every SAT_EVENT_QUEUE event dict from one bulk uplink."""
    try:
        packet_type = normalize_packet_type(str(bulk.get("packet_type", "")).strip())
        if packet_type != "SAT_BULK_TELEMETRY":
            return []
        event_section = bulk.get("SAT_EVENT_QUEUE")
        if not isinstance(event_section, dict):
            return []
        events = extract_event_queue_section_events(event_section)
        return [scrub_record(event) for event in events if isinstance(event, dict)]
    except Exception as error:
        logger.error("bulk event extract failed: %s", error)
        return []


def build_event_queue_row(
    event: dict[str, Any],
    *,
    bulk_sent_at: str | None = None,
) -> dict[str, Any]:
    """Build one gs_event_queue insert row — onboard wire fields only."""
    try:
        row: dict[str, Any] = {}
        apply_onboard_event_to_queue_row(row, event)
        if bulk_sent_at:
            sent_key = time_key_from_value(bulk_sent_at)
            row["BULK_SENT_AT"] = sent_key.replace("T", " ") if sent_key else bulk_sent_at
        row["PAYLOAD"] = scrub_record(event)
        return row
    except Exception as error:
        logger.error("event queue row build failed: %s", error)
        return {}


def _history_row_epoch(row: dict[str, Any]) -> float | None:
    try:
        return time_key_to_epoch(
            row.get("SNAPSHOT_AT") or row.get("UPDATED_AT") or row.get("DETECTED_AT"),
        )
    except Exception as error:
        logger.error("history row epoch failed: %s", error)
        return None


def _event_epoch(event: dict[str, Any]) -> float | None:
    try:
        return time_key_to_epoch(event.get("DETECTED_AT") or event.get("TIMESTAMP"))
    except Exception as error:
        logger.error("event epoch failed: %s", error)
        return None


def _coerce_history_rows(
    history_rows: list[dict[str, Any]] | dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    try:
        if isinstance(history_rows, dict):
            return [dict(row) for row in history_rows.values() if isinstance(row, dict)]
        return [dict(row) for row in history_rows if isinstance(row, dict)]
    except Exception as error:
        logger.error("history row list coerce failed: %s", error)
        return []


def find_nearest_history_for_event(
    event: dict[str, Any],
    history_rows: list[dict[str, Any]] | dict[int, dict[str, Any]],
    *,
    tolerance_sec: float = DEFAULT_RECORD_MATCH_TOLERANCE_SEC,
) -> tuple[dict[str, Any] | None, float | None]:
    """Pick gs_tlm_history row nearest to event DETECTED_AT within tolerance."""
    try:
        rows = _coerce_history_rows(history_rows)
        if not rows:
            return None, None

        event_time = _event_epoch(event)
        if event_time is None:
            if len(rows) == 1:
                return rows[0], None
            snapshot_id = record_snapshot_id(event)
            if snapshot_id is not None:
                for row in rows:
                    if row.get("SNAPSHOT_ID") == snapshot_id:
                        return row, None
            return None, None

        within_tolerance: list[tuple[float, dict[str, Any]]] = []
        nearest_any: tuple[float, dict[str, Any]] | None = None
        snapshot_id = record_snapshot_id(event)

        for row in rows:
            row_time = _history_row_epoch(row)
            if row_time is None:
                continue
            delta = abs(row_time - event_time)
            if nearest_any is None or delta < nearest_any[0]:
                nearest_any = (delta, row)
            if delta <= tolerance_sec:
                within_tolerance.append((delta, row))

        pool = within_tolerance or ([nearest_any] if nearest_any is not None else [])
        if not pool:
            return None, None

        if snapshot_id is not None:
            snapshot_matches = [
                item for item in pool if item[1].get("SNAPSHOT_ID") == snapshot_id
            ]
            if snapshot_matches:
                pool = snapshot_matches

        best_delta, best_row = sorted(pool, key=lambda item: item[0])[0]
        return best_row, best_delta
    except Exception as error:
        logger.error("nearest history for event failed: %s", error)
        return None, None


def resolve_event_history_link(
    event: dict[str, Any],
    history_rows: list[dict[str, Any]] | dict[int, dict[str, Any]],
    *,
    fallback_history: dict[str, Any] | None = None,
    tolerance_sec: float = DEFAULT_RECORD_MATCH_TOLERANCE_SEC,
) -> tuple[dict[str, Any] | None, int | None]:
    """Link one event to gs_tlm_history by time proximity (SNAPSHOT_ID tie-break only)."""
    try:
        row, _delta = find_nearest_history_for_event(
            event,
            history_rows,
            tolerance_sec=tolerance_sec,
        )
        if row is None and fallback_history is not None:
            row = fallback_history
        if row is None:
            return None, None
        history_id = row.get("HISTORY_ID")
        return row, history_id if isinstance(history_id, int) else None
    except Exception as error:
        logger.error("event history link resolve failed: %s", error)
        return None, None


def _event_payload_from_row(event_row: dict[str, Any]) -> dict[str, Any]:
    try:
        payload = event_row.get("PAYLOAD")
        if isinstance(payload, dict):
            return scrub_record(payload)
        extracted: dict[str, Any] = {}
        for key, value in event_row.items():
            if key in EVENT_QUEUE_META_FIELDS:
                continue
            if value is not None:
                extracted[key] = value
        return scrub_record(extracted)
    except Exception as error:
        logger.error("event payload extract failed: %s", error)
        return {}


def build_ma_reference_packet(
    history_row: dict[str, Any],
    event_row: dict[str, Any],
    *,
    time_delta_sec: float | None = None,
) -> dict[str, Any]:
    """Build MA input: telemetry snapshot + onboard event reference (no history flatten)."""
    try:
        from ma_detector.core.ma_onboard_view import apply_ma_onboard_fields

        packet = dict(history_row)
        onboard_event = _event_payload_from_row(event_row)
        packet["ONBOARD_EVENT"] = onboard_event
        packet["EVENT_QUEUE_ID"] = event_row.get("EVENT_QUEUE_ID")
        if time_delta_sec is not None:
            packet["_EVENT_HISTORY_DELTA_SEC"] = round(float(time_delta_sec), 3)

        apply_ma_onboard_fields(packet, event_row)

        for key in MA_GATE_FIELDS:
            if event_row.get(key) is not None:
                packet[key] = event_row[key]
            elif onboard_event.get(key) is not None:
                packet[key] = onboard_event[key]

        promote_event_reference_fields(packet)
        return packet
    except Exception as error:
        logger.error("ma reference packet build failed: %s", error)
        return dict(history_row)


def promote_event_reference_fields(packet: dict[str, Any]) -> None:
    """Fill missing rule-evidence columns from ONBOARD_EVENT without overwriting telemetry."""
    try:
        onboard = packet.get("ONBOARD_EVENT")
        if not isinstance(onboard, dict):
            return

        for key in EVENT_REFERENCE_FIELDS:
            if packet.get(key) is not None:
                continue
            value = onboard.get(key)
            if value is not None:
                packet[key] = value

        combined_crc = onboard.get("CH1_CH2_FAULT_CRC")
        if combined_crc is not None:
            if packet.get("CH1_FAULT_CRC") is None:
                packet["CH1_FAULT_CRC"] = combined_crc
            if packet.get("CH2_FAULT_CRC") is None:
                packet["CH2_FAULT_CRC"] = combined_crc

        module_scores = parse_module_scores(onboard.get("MODULE_SCORES"))
        if module_scores is not None and packet.get("MODULE_SCORES") is None:
            packet["MODULE_SCORES"] = module_scores
    except Exception as error:
        logger.error("event reference field promote failed: %s", error)


def merge_history_with_event(
    history_row: dict[str, Any],
    event_row: dict[str, Any],
) -> dict[str, Any]:
    """Backward-compatible alias for build_ma_reference_packet."""
    return build_ma_reference_packet(history_row, event_row)
