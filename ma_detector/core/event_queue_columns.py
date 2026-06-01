"""Onboard SAT_EVENT_QUEUE wire fields and gs_event_queue column definitions."""

from __future__ import annotations

import json
import logging
from typing import Any

from ma_detector.core.packet_protocol import (
    scrub_record,
    time_key_from_value,
)

logger = logging.getLogger(__name__)

# Exact keys from satellite SAT_EVENT_QUEUE event JSON (no ground-only fields).
ONBOARD_EVENT_WIRE_FIELDS: tuple[str, ...] = (
    "SW_ID",
    "WEIGHT",
    "IS_SENT",
    "EVENT_ID",
    "PRIORITY",
    "TIMESTAMP",
    "EVENT_TYPE",
    "DETECTED_AT",
    "MODULE_SCORES",
    "EXCEPTION_CODE",
    "CHILDQUEUECOUNT",
    "CH1_CH2_FAULT_CRC",
    "PIPEOVERFLOWRRCNT",
    "CMDREJECTEDCOUNTER",
    "FILEWRITEERRCOUNTER",
    "PROCESSOR_RESET_COUNT",
    "CH1_FAULT_FILE_SIZE_MISMATCH",
)

# Legacy DB columns on gs_event_queue — not written on ingest; use ma_onboard_view at MA/UI time.
GS_EVENT_LEGACY_DERIVED_COLUMNS: tuple[tuple[str, str], ...] = (
    ("IS_ANOMALY", "`IS_ANOMALY` tinyint DEFAULT 0"),
    ("FALSE_POSITIVE_RESULT", "`FALSE_POSITIVE_RESULT` char(1) DEFAULT NULL"),
    ("FALSE_POSITIVE_WEIGHT", "`FALSE_POSITIVE_WEIGHT` int DEFAULT NULL"),
    ("FALSE_POSITIVE_EXCEPTION", "`FALSE_POSITIVE_EXCEPTION` varchar(32) DEFAULT NULL"),
    ("TARGET_SUBSYSTEM", "`TARGET_SUBSYSTEM` varchar(32) DEFAULT NULL"),
)

# Optional wire envelope mirror (bulk.sent_at) + lossless event archive.
GS_EVENT_ARCHIVE_COLUMNS: tuple[tuple[str, str], ...] = (
    ("BULK_SENT_AT", "`BULK_SENT_AT` datetime(3) DEFAULT NULL"),
    ("PAYLOAD", "`PAYLOAD` json DEFAULT NULL"),
)

ONBOARD_EVENT_WIRE_COLUMN_DDLS: tuple[tuple[str, str], ...] = (
    ("EVENT_ID", "`EVENT_ID` int DEFAULT NULL"),
    ("EVENT_TYPE", "`EVENT_TYPE` varchar(64) DEFAULT NULL"),
    ("PRIORITY", "`PRIORITY` int DEFAULT NULL"),
    ("IS_SENT", "`IS_SENT` tinyint DEFAULT NULL"),
    ("SW_ID", "`SW_ID` int DEFAULT NULL"),
    ("WEIGHT", "`WEIGHT` int DEFAULT NULL"),
    ("EXCEPTION_CODE", "`EXCEPTION_CODE` int DEFAULT NULL"),
    ("PIPEOVERFLOWRRCNT", "`PIPEOVERFLOWRRCNT` int DEFAULT NULL"),
    ("CHILDQUEUECOUNT", "`CHILDQUEUECOUNT` int DEFAULT NULL"),
    ("FILEWRITEERRCOUNTER", "`FILEWRITEERRCOUNTER` int DEFAULT NULL"),
    ("CMDREJECTEDCOUNTER", "`CMDREJECTEDCOUNTER` int DEFAULT NULL"),
    ("CH1_CH2_FAULT_CRC", "`CH1_CH2_FAULT_CRC` int DEFAULT NULL"),
    ("CH1_FAULT_FILE_SIZE_MISMATCH", "`CH1_FAULT_FILE_SIZE_MISMATCH` int DEFAULT NULL"),
    ("PROCESSOR_RESET_COUNT", "`PROCESSOR_RESET_COUNT` int DEFAULT NULL"),
    ("DETECTED_AT", "`DETECTED_AT` datetime(3) DEFAULT NULL"),
    ("TIMESTAMP", "`TIMESTAMP` datetime(3) DEFAULT NULL"),
    ("MODULE_SCORES", "`MODULE_SCORES` json DEFAULT NULL"),
)

# Removed from gs_event_queue (derived duplicates; wire uses CH1_CH2_FAULT_CRC only).
DROPPED_EVENT_QUEUE_COLUMNS: tuple[str, ...] = (
    "CH1_FAULT_CRC",
    "CH2_FAULT_CRC",
)

# Must never be written to gs_tlm_history (live in gs_event_queue).
TLM_EVENT_FIELD_BLOCKLIST: frozenset[str] = frozenset(
    {
        *ONBOARD_EVENT_WIRE_FIELDS,
        "IS_ANOMALY",
        "FALSE_POSITIVE_RESULT",
        "FALSE_POSITIVE_WEIGHT",
        "FALSE_POSITIVE_EXCEPTION",
        "TARGET_SUBSYSTEM",
        "CH1_FAULT_CRC",
        "CH2_FAULT_CRC",
        "SW_ID_LIST",
    }
)


def parse_module_scores(value: Any) -> dict[str, Any] | None:
    try:
        if isinstance(value, dict):
            return dict(value)
        if isinstance(value, str) and value.strip():
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        return None
    except Exception as error:
        logger.error("module scores parse failed: %s", error)
        return None


def _normalize_event_datetime(value: Any) -> str | None:
    try:
        if value is None:
            return None
        key = time_key_from_value(value)
        if key:
            return key.replace("T", " ")
        text = str(value).strip()
        return text or None
    except Exception as error:
        logger.error("event datetime normalize failed: %s", error)
        return None


def apply_onboard_event_to_queue_row(row: dict[str, Any], event: dict[str, Any]) -> None:
    """Map onboard SAT_EVENT_QUEUE wire JSON into one gs_event_queue insert row."""
    try:
        cleaned = scrub_record(event)
        for key in ONBOARD_EVENT_WIRE_FIELDS:
            if key not in cleaned or cleaned[key] is None:
                continue
            if key in ("DETECTED_AT", "TIMESTAMP"):
                normalized = _normalize_event_datetime(cleaned[key])
                if normalized is not None:
                    row[key] = normalized
                continue
            if key == "MODULE_SCORES":
                scores = parse_module_scores(cleaned[key])
                if scores is not None:
                    row[key] = scores
                continue
            row[key] = cleaned[key]
    except Exception as error:
        logger.error("onboard event queue row apply failed: %s", error)


def _event_source_dict(row: dict[str, Any]) -> dict[str, Any]:
    try:
        payload = row.get("PAYLOAD")
        if isinstance(payload, dict):
            return scrub_record(payload)
        return scrub_record(row)
    except Exception as error:
        logger.error("event source dict resolve failed: %s", error)
        return scrub_record(row)


def strip_event_fields_from_tlm_packet(packet: dict[str, Any]) -> dict[str, Any]:
    """Remove event-queue keys before gs_tlm_history insert."""
    try:
        cleaned = dict(packet)
        for key in TLM_EVENT_FIELD_BLOCKLIST:
            cleaned.pop(key, None)
        source = cleaned.get("SOURCE_RECORDS")
        if isinstance(source, dict) and "event" in source:
            source = dict(source)
            source.pop("event", None)
            if source:
                cleaned["SOURCE_RECORDS"] = source
            else:
                cleaned.pop("SOURCE_RECORDS", None)
        cleaned.pop("ONBOARD_EVENT", None)
        cleaned.pop("EVENT_QUEUE_ID", None)
        return cleaned
    except Exception as error:
        logger.error("tlm event field strip failed: %s", error)
        return dict(packet)
