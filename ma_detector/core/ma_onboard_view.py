"""Derive MA / UI fields from raw onboard rows. Do not use on gs_tlm / gs_pwr / gs_event_queue writes."""

from __future__ import annotations

import logging
from typing import Any

from ma_detector.core.event_queue_columns import _event_source_dict
from ma_detector.core.packet_protocol import (
    event_is_attack_anomaly,
    infer_subsystem_from_file_path,
    scrub_record,
)
from ma_detector.core.target_context import infer_target_from_sw_ids, normalize_target_subsystem

logger = logging.getLogger(__name__)


def is_attack_event_row(row: dict[str, Any]) -> bool:
    """Return True when a raw gs_event_queue row is an attack-class onboard event."""
    try:
        return event_is_attack_anomaly(_event_source_dict(row))
    except Exception as error:
        logger.error("attack event row check failed: %s", error)
        return False


def derive_ma_fields_from_event(row: dict[str, Any]) -> dict[str, Any]:
    """Add MA gate fields derived from wire event columns (in-memory only)."""
    try:
        item = dict(row)
        cleaned = _event_source_dict(item)
        is_anomaly = event_is_attack_anomaly(cleaned)
        item["IS_ANOMALY"] = bool(is_anomaly)
        item["FALSE_POSITIVE_RESULT"] = "Y" if is_anomaly else "N"
        item["FALSE_POSITIVE_WEIGHT"] = int(cleaned.get("WEIGHT", 0) or 0)
        exception_code = cleaned.get("EXCEPTION_CODE")
        if exception_code is not None:
            item["FALSE_POSITIVE_EXCEPTION"] = str(exception_code)
        file_target = infer_subsystem_from_file_path(cleaned.get("FILE_PATH"))
        if file_target:
            item["TARGET_SUBSYSTEM"] = file_target
        elif cleaned.get("SW_ID") is not None:
            item["TARGET_SUBSYSTEM"] = infer_target_from_sw_ids([cleaned.get("SW_ID")])
        sw_id = cleaned.get("SW_ID")
        if sw_id is not None:
            sw_list = item.setdefault("SW_ID_LIST", [])
            if isinstance(sw_list, list) and int(sw_id) not in sw_list:
                sw_list.append(int(sw_id))
        return item
    except Exception as error:
        logger.error("ma fields derive from event failed: %s", error)
        return dict(row)


def apply_ma_onboard_fields(packet: dict[str, Any], event_row: dict[str, Any]) -> None:
    """Promote derived onboard filter fields onto an MA reference packet."""
    try:
        derived = derive_ma_fields_from_event(event_row)
        onboard_event = derived.get("PAYLOAD") if isinstance(derived.get("PAYLOAD"), dict) else {}
        if not onboard_event:
            onboard_event = scrub_record(_event_source_dict(event_row))

        if derived.get("IS_ANOMALY") is not None:
            packet["IS_ANOMALY"] = derived["IS_ANOMALY"]
        for key in (
            "FALSE_POSITIVE_RESULT",
            "FALSE_POSITIVE_WEIGHT",
            "FALSE_POSITIVE_EXCEPTION",
            "TARGET_SUBSYSTEM",
            "EVENT_ID",
            "DETECTED_AT",
            "WEIGHT",
            "EXCEPTION_CODE",
            "SW_ID",
        ):
            if derived.get(key) is not None:
                packet[key] = derived[key]
            elif onboard_event.get(key) is not None:
                packet[key] = onboard_event[key]

        sw_id_list = derived.get("SW_ID_LIST")
        if isinstance(sw_id_list, list) and sw_id_list:
            packet["SW_ID_LIST"] = list(sw_id_list)
    except Exception as error:
        logger.error("ma onboard field apply failed: %s", error)


def satellite_filter_from_ma_packet(packet: dict[str, Any]) -> dict[str, Any]:
    """Build gs_anomaly_ma_dashboard satellite-filter columns from an MA window packet."""
    try:
        target = normalize_target_subsystem(packet.get("TARGET_SUBSYSTEM"))
        sw_id_list = packet.get("SW_ID_LIST", [])
        if not isinstance(sw_id_list, list):
            sw_id_list = [sw_id_list] if sw_id_list is not None else []
        return {
            "FALSE_POSITIVE_RESULT": packet.get("FALSE_POSITIVE_RESULT"),
            "FALSE_POSITIVE_WEIGHT": packet.get("FALSE_POSITIVE_WEIGHT", packet.get("WEIGHT")),
            "FALSE_POSITIVE_EXCEPTION": packet.get("FALSE_POSITIVE_EXCEPTION", packet.get("EXCEPTION_CODE")),
            "TARGET_SUBSYSTEM": target or None,
            "SATELLITE_TARGET_SUBSYSTEM": target or None,
            "EVENT_ID": packet.get("EVENT_ID"),
            "SW_ID_LIST": sw_id_list,
            "SATELLITE_DETECTED_AT": packet.get("DETECTED_AT") or packet.get("TIMESTAMP"),
        }
    except Exception as error:
        logger.error("satellite filter snapshot build failed: %s", error)
        return {}
