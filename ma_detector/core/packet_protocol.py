"""Satellite TCP packet type aliases, time keys, and record slicing helpers."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

PACKET_TYPE_ALIASES: dict[str, str] = {
    "SAT_TLM_CURRENT": "SAT_TLM_HISTORY",
    "SAT_PWR_META": "SAT_PWR_HISTORY",
    "SAT_HASH": "SAT_INTEGRITY_HASH",
}

# GScomms uplink order (after optional SAT_EVENT_QUEUE_META prefix per comm window).
SATELLITE_TRANSMIT_ORDER: tuple[str, ...] = (
    "SAT_EVENT_QUEUE",
    "SAT_INTEGRITY_HASH",
    "SAT_ADCS_FILTER",
    "SAT_TLM_HISTORY",
    "SAT_PWR_HISTORY",
)

META_PACKET_TYPES = frozenset({"SAT_EVENT_QUEUE_META"})

BULK_HISTORY_TYPES = frozenset(
    {
        "SAT_TLM_HISTORY",
        "SAT_PWR_HISTORY",
        "SAT_ADCS_FILTER",
        "SAT_INTEGRITY_HASH",
    }
)

BULK_TELEMETRY_PACKET_TYPE = "SAT_BULK_TELEMETRY"

BULK_TELEMETRY_CONTAINER_FIELDS = frozenset(
    {
        "packet_type",
        "sent_at",
    }
)

BULK_TELEMETRY_NESTED_ORDER: tuple[str, ...] = (
    "SAT_EVENT_QUEUE_META",
    "SAT_SNAPSHOT",
    *SATELLITE_TRANSMIT_ORDER,
)

BULK_METADATA_TYPES = frozenset({"SAT_SNAPSHOT"})

IGNORED_RECORD_FIELDS = frozenset({"CHENNEL1"})

DEFAULT_RECORD_MATCH_TOLERANCE_SEC = 5

FILE_PATH_SUBSYSTEM_MARKERS: tuple[tuple[str, str], ...] = (
    ("adcs.so", "ADCS"),
    ("/adcs/", "ADCS"),
    ("adcs", "ADCS"),
    ("obc.so", "OBC"),
    ("/obc/", "OBC"),
    ("obc", "OBC"),
    ("eps.so", "EPS"),
    ("/eps/", "EPS"),
    ("eps", "EPS"),
    ("to_lab", "COM"),
    ("/to/", "COM"),
    ("/ci/", "COM"),
    ("com.so", "COM"),
    ("/com/", "COM"),
    ("tcs.so", "TCS"),
    ("/tcs/", "TCS"),
    ("tcs", "TCS"),
    ("/cf/apps/", "OBC"),
)


def normalize_packet_type(packet_type: str) -> str:
    """Map legacy packet_type names to the satellite wire format."""
    try:
        cleaned = str(packet_type or "").strip()
        return PACKET_TYPE_ALIASES.get(cleaned, cleaned)
    except Exception as error:
        logger.error("packet type normalization failed: %s", error)
        return str(packet_type or "")


def scrub_record(record: dict[str, Any]) -> dict[str, Any]:
    """Drop onboard-only fields that must not affect ground-station logic."""
    try:
        return {
            key: value
            for key, value in record.items()
            if key not in IGNORED_RECORD_FIELDS
        }
    except Exception as error:
        logger.error("record scrub failed: %s", error)
        return dict(record)


def infer_subsystem_from_file_path(file_path: Any) -> str:
    """Map onboard FILE_PATH values to a subsystem label (e.g. /cf/apps/adcs.so -> ADCS)."""
    try:
        path = str(file_path or "").strip().lower()
        if not path:
            return ""
        for marker, subsystem in FILE_PATH_SUBSYSTEM_MARKERS:
            if marker in path:
                return subsystem
        return ""
    except Exception as error:
        logger.error("file path subsystem inference failed: %s", error)
        return ""


def is_event_queue_meta_packet(packet: dict[str, Any]) -> bool:
    """Return True when the packet is SAT_EVENT_QUEUE_META (event count prelude)."""
    try:
        packet_type = normalize_packet_type(str(packet.get("packet_type", "")).strip())
        return packet_type == "SAT_EVENT_QUEUE_META"
    except Exception as error:
        logger.error("event queue meta packet check failed: %s", error)
        return False


def parse_event_queue_meta(packet: dict[str, Any]) -> dict[str, Any] | None:
    """Parse SAT_EVENT_QUEUE_META; field values are runtime data from the satellite."""
    try:
        if not is_event_queue_meta_packet(packet):
            return None
        event_total = int(packet.get("event_total", 0) or 0)
        raw_ids = packet.get("event_ids", [])
        if not isinstance(raw_ids, list):
            logger.error("event_ids must be a list in SAT_EVENT_QUEUE_META")
            return None
        if event_total <= 0:
            event_total = len(raw_ids)
        if event_total <= 0:
            logger.error("invalid SAT_EVENT_QUEUE_META: event_total=%s", event_total)
            return None
        event_ids = [int(item) for item in raw_ids] if raw_ids else []
        return {"event_total": event_total, "event_ids": event_ids}
    except (TypeError, ValueError) as error:
        logger.error("event queue meta parse failed: %s", error)
        return None
    except Exception as error:
        logger.error("unexpected event queue meta parse failure: %s", error)
        return None


def extract_event_queue_section_events(section: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Parse SAT_EVENT_QUEUE nested section (events[] or legacy event)."""
    try:
        if not isinstance(section, dict):
            return []

        events = section.get("events")
        if isinstance(events, list):
            cleaned = [scrub_record(event) for event in events if isinstance(event, dict)]
            if cleaned:
                return cleaned

        event = section.get("event")
        if isinstance(event, dict):
            return [scrub_record(event)]

        if section.get("EVENT_ID") is not None:
            return [scrub_record(section)]
        return []
    except Exception as error:
        logger.error("event queue section extract failed: %s", error)
        return []


def is_bulk_telemetry_packet(packet: dict[str, Any]) -> bool:
    """Return True when the uplink uses one SAT_BULK_TELEMETRY container."""
    try:
        packet_type = normalize_packet_type(str(packet.get("packet_type", "")).strip())
        return packet_type == BULK_TELEMETRY_PACKET_TYPE
    except Exception as error:
        logger.error("bulk telemetry packet check failed: %s", error)
        return False


def _bulk_section_to_child_packet(section_key: str, section: Any) -> dict[str, Any] | None:
    """Convert one nested bulk section into a standalone satellite packet."""
    try:
        packet_type = normalize_packet_type(str(section_key or "").strip())
        if not packet_type:
            return None

        if packet_type == "SAT_EVENT_QUEUE_META":
            if isinstance(section, dict):
                return {"packet_type": packet_type, **section}
            return None

        if packet_type == "SAT_EVENT_QUEUE":
            if not isinstance(section, dict):
                return None
            events = extract_event_queue_section_events(section)
            if not events:
                return None
            child: dict[str, Any] = {
                "packet_type": packet_type,
                "events": events,
                "event_total": int(section.get("event_total", len(events)) or len(events)),
                "event_ids": section.get("event_ids", [event.get("EVENT_ID") for event in events]),
            }
            if len(events) == 1:
                child["event"] = events[0]
            return child

        if not isinstance(section, dict):
            return None
        records = section.get("records")
        if not isinstance(records, list) or not records:
            return None
        cleaned = [scrub_record(record) for record in records if isinstance(record, dict)]
        if not cleaned:
            return None
        return {"packet_type": packet_type, "records": cleaned}
    except Exception as error:
        logger.error("bulk section child packet build failed: %s", error)
        return None


def expand_bulk_telemetry_packet(packet: dict[str, Any]) -> list[dict[str, Any]]:
    """Expand SAT_BULK_TELEMETRY into ordered standalone packet payloads."""
    try:
        if not is_bulk_telemetry_packet(packet):
            return []

        children: list[dict[str, Any]] = []
        seen: set[str] = set()

        for section_key in BULK_TELEMETRY_NESTED_ORDER:
            child = _bulk_section_to_child_packet(section_key, packet.get(section_key))
            if child is None:
                continue
            children.append(child)
            seen.add(section_key)

        for section_key, section in packet.items():
            if section_key in seen:
                continue
            if section_key in BULK_TELEMETRY_CONTAINER_FIELDS or str(section_key).startswith("_"):
                continue
            canonical = normalize_packet_type(str(section_key))
            if canonical not in BULK_HISTORY_TYPES and canonical not in {
                "SAT_EVENT_QUEUE",
                "SAT_EVENT_QUEUE_META",
                "SAT_SNAPSHOT",
            }:
                continue
            child = _bulk_section_to_child_packet(canonical, section)
            if child is None:
                continue
            children.append(child)
            seen.add(canonical)

        return children
    except Exception as error:
        logger.error("bulk telemetry expand failed: %s", error)
        return []


def build_bulk_telemetry_packet(
    sections: dict[str, dict[str, Any]],
    *,
    sent_at: str | None = None,
) -> dict[str, Any]:
    """Build one SAT_BULK_TELEMETRY wire payload from nested section dicts."""
    try:
        payload: dict[str, Any] = {"packet_type": BULK_TELEMETRY_PACKET_TYPE}
        if sent_at:
            payload["sent_at"] = sent_at
        for section_key in BULK_TELEMETRY_NESTED_ORDER:
            section = sections.get(section_key)
            if isinstance(section, dict):
                payload[section_key] = section
        for section_key, section in sections.items():
            if section_key in payload or not isinstance(section, dict):
                continue
            canonical = normalize_packet_type(str(section_key))
            if canonical in BULK_HISTORY_TYPES or canonical in {
                "SAT_EVENT_QUEUE",
                "SAT_EVENT_QUEUE_META",
                "SAT_SNAPSHOT",
            }:
                payload[canonical] = section
        return payload
    except Exception as error:
        logger.error("bulk telemetry packet build failed: %s", error)
        return {"packet_type": BULK_TELEMETRY_PACKET_TYPE}


def combine_uplink_packets_to_bulk(
    packets: list[dict[str, Any]],
    *,
    sent_at: str | None = None,
) -> list[dict[str, Any]]:
    """Fold legacy separate uplink packets into one SAT_BULK_TELEMETRY."""
    try:
        if not packets:
            return []

        if len(packets) == 1 and is_bulk_telemetry_packet(packets[0]):
            return [dict(packets[0])]

        sections: dict[str, dict[str, Any]] = {}
        events: list[dict[str, Any]] = []
        meta: dict[str, Any] | None = None
        passthrough: list[dict[str, Any]] = []

        for packet in packets:
            if is_bulk_telemetry_packet(packet):
                return [dict(packet)]

            ptype = normalize_packet_type(str(packet.get("packet_type", "")).strip())
            if ptype == "SAT_EVENT_QUEUE_META":
                meta = {key: value for key, value in packet.items() if key != "packet_type"}
                continue

            if ptype == "SAT_EVENT_QUEUE":
                event = packet.get("event", packet)
                if isinstance(event, dict):
                    cleaned = scrub_record(event)
                    if cleaned:
                        events.append(cleaned)
                continue

            if ptype in BULK_HISTORY_TYPES or ptype in BULK_METADATA_TYPES:
                bucket = sections.setdefault(ptype, {"records": []})
                records = packet.get("records")
                if isinstance(records, list):
                    for record in records:
                        if isinstance(record, dict):
                            cleaned = scrub_record(record)
                            if cleaned:
                                bucket["records"].append(cleaned)
                continue

            passthrough.append(dict(packet))

        if not sections and not events:
            return passthrough or list(packets)

        if events:
            event_section: dict[str, Any] = {}
            if meta:
                event_section.update(meta)
            if len(events) == 1 and "events" not in event_section:
                event_section["event"] = events[0]
            else:
                event_section["events"] = events
            sections["SAT_EVENT_QUEUE"] = event_section

        bulk = build_bulk_telemetry_packet(sections, sent_at=sent_at)
        return passthrough + [bulk]
    except Exception as error:
        logger.error("combine uplink packets failed: %s", error)
        return list(packets)


def summarize_uplink_packet(packet: dict[str, Any]) -> str:
    """One-line human-readable summary for logs and ingest trace."""
    try:
        ptype = normalize_packet_type(str(packet.get("packet_type", "")).strip())
        if not ptype:
            return "unknown packet (missing packet_type)"

        if ptype == BULK_TELEMETRY_PACKET_TYPE:
            sections: list[str] = []
            for section_key in BULK_TELEMETRY_NESTED_ORDER:
                section = packet.get(section_key)
                if not isinstance(section, dict):
                    continue
                if section_key == "SAT_EVENT_QUEUE":
                    event_count = len(extract_event_queue_section_events(section))
                    if event_count:
                        sections.append(f"EVENT={event_count}")
                    continue
                records = section.get("records")
                count = len(records) if isinstance(records, list) else 0
                if count:
                    if section_key == "SAT_SNAPSHOT":
                        sections.append(f"SNAPSHOT={count}")
                    else:
                        sections.append(f"{section_key}={count}")
            sent_at = str(packet.get("sent_at", ""))[:19]
            body = " ".join(sections) if sections else "empty"
            return f"BULK sent_at={sent_at} {body}"

        if ptype == "SAT_EVENT_QUEUE_META":
            return (
                f"META event_total={packet.get('event_total')} "
                f"event_ids={packet.get('event_ids')}"
            )

        if ptype == "SAT_EVENT_QUEUE":
            event = packet.get("event", packet)
            if not isinstance(event, dict):
                return "EVENT (invalid event object)"
            return (
                f"EVENT_ID={event.get('EVENT_ID')} "
                f"TYPE={event.get('EVENT_TYPE')} "
                f"WEIGHT={event.get('WEIGHT')} "
                f"SW_ID={event.get('SW_ID')} "
                f"PRIORITY={event.get('PRIORITY')}"
            )

        records = packet.get("records")
        if isinstance(records, list):
            if ptype == "SAT_PWR_HISTORY":
                channel_counts = []
                for rec in records[:5]:
                    if isinstance(rec, dict):
                        ch = rec.get("channels")
                        channel_counts.append(len(ch) if isinstance(ch, list) else 0)
                suffix = f" channels={channel_counts}" if channel_counts else ""
                return f"snapshots={len(records)}{suffix}"
            if ptype == "SAT_ADCS_FILTER":
                first_ts = ""
                last_ts = ""
                if records and isinstance(records[0], dict):
                    first_ts = str(records[0].get("TIMESTAMP", ""))[:19]
                if records and isinstance(records[-1], dict):
                    last_ts = str(records[-1].get("TIMESTAMP", ""))[:19]
                span = f" {first_ts}..{last_ts}" if first_ts and last_ts else ""
                return f"rows={len(records)}{span}"
            if ptype == "SAT_INTEGRITY_HASH":
                violated = sum(
                    1
                    for rec in records
                    if isinstance(rec, dict) and int(rec.get("IS_VIOLATED", 0) or 0) == 1
                )
                return f"files={len(records)} violated={violated}"
            return f"records={len(records)}"

        return f"keys={list(packet.keys())[:6]}"
    except Exception as error:
        logger.error("uplink packet summary failed: %s", error)
        return "summary unavailable"


def event_is_attack_anomaly(event: dict[str, Any]) -> bool:
    """Return True when an onboard event should open an anomaly buffer bucket."""
    try:
        event_type = str(event.get("EVENT_TYPE", ""))
        weight = int(event.get("WEIGHT", 0) or 0)
        return event_type == "ATTACK_CONFIRMED" or weight >= 50
    except (TypeError, ValueError) as error:
        logger.error("event anomaly check failed: %s", error)
        return False
    except Exception as error:
        logger.error("unexpected event anomaly check failure: %s", error)
        return False


def should_append_baseline(packet: dict[str, Any]) -> bool:
    """Return True only for verified-normal snapshots with no onboard filter weight."""
    try:
        if packet.get("IS_ANOMALY", False):
            return False
        weight = int(packet.get("FALSE_POSITIVE_WEIGHT", packet.get("WEIGHT", 0)) or 0)
        return weight == 0
    except (TypeError, ValueError) as error:
        logger.error("baseline eligibility check failed: %s", error)
        return False
    except Exception as error:
        logger.error("unexpected baseline eligibility check failure: %s", error)
        return False


def time_key_from_value(value: Any) -> str:
    """Normalize DETECTED_AT / TIMESTAMP / UPDATED_AT to second-level key."""
    try:
        if value is None:
            return ""
        text = str(value).strip()
        if not text:
            return ""
        normalized = text.replace("Z", "+00:00")
        if "T" not in normalized and " " in normalized:
            normalized = normalized.replace(" ", "T", 1)
        if "+" in normalized:
            normalized = normalized.split("+", 1)[0]
        if "." in normalized:
            normalized = normalized.split(".", 1)[0]
        return normalized[:19]
    except Exception as error:
        logger.error("time key normalization failed: %s", error)
        return ""


def time_key_to_epoch(key: str) -> float | None:
    """Convert a normalized time key to Unix epoch seconds."""
    try:
        if not key:
            return None
        normalized = key.replace("Z", "+00:00")
        if "T" not in normalized and " " in normalized:
            normalized = normalized.replace(" ", "T", 1)
        if "+" not in normalized and len(normalized) == 19:
            normalized = f"{normalized}+00:00"
        return datetime.fromisoformat(normalized).timestamp()
    except (TypeError, ValueError) as error:
        logger.error("time key epoch conversion failed: %s", error)
        return None
    except Exception as error:
        logger.error("unexpected time key epoch conversion failure: %s", error)
        return None


def timestamp_to_epoch(value: Any) -> float | None:
    """Convert DB datetimes, ISO strings, or numeric epochs to UTC epoch seconds."""
    try:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, datetime):
            dt = value
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        if isinstance(value, str):
            return time_key_to_epoch(time_key_from_value(value))
        return None
    except (TypeError, ValueError) as error:
        logger.error("timestamp epoch conversion failed: %s", error)
        return None
    except Exception as error:
        logger.error("unexpected timestamp epoch conversion failure: %s", error)
        return None


def merge_history_snapshots(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge partial gs_tlm_history rows that share the same second into one snapshot."""
    try:
        buckets: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            key = time_key_from_value(row.get("UPDATED_AT"))
            if not key:
                continue
            buckets.setdefault(key, []).append(dict(row))

        merged_rows: list[dict[str, Any]] = []
        for key in sorted(buckets.keys()):
            group = buckets[key]
            group.sort(
                key=lambda item: (
                    int(item.get("IS_ANOMALY") or 0),
                    int(item.get("HISTORY_ID") or 0),
                )
            )
            merged: dict[str, Any] = {}
            for item in group:
                for field, value in item.items():
                    if value is not None:
                        merged[field] = value
            merged["UPDATED_AT"] = key.replace("T", " ")
            merged_rows.append(merged)
        return merged_rows
    except Exception as error:
        logger.error("history snapshot merge failed: %s", error)
        return [dict(row) for row in rows if isinstance(row, dict)]


def detection_snapshots_from_history(
    rows: list[dict[str, Any]],
    detect_time: str,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Return (previous_second, detect_second) snapshots from gs_tlm_history rows."""
    try:
        merged = merge_history_snapshots(rows)
        detect_key = time_key_from_value(detect_time)
        anchor_epoch = time_key_to_epoch(detect_key)
        if anchor_epoch is None:
            return None, None
        previous_epoch = anchor_epoch - 1.0
        previous: dict[str, Any] | None = None
        current: dict[str, Any] | None = None
        for row in merged:
            row_epoch = timestamp_to_epoch(row.get("UPDATED_AT"))
            if row_epoch is None:
                continue
            if row_epoch == anchor_epoch:
                current = dict(row)
            elif row_epoch == previous_epoch:
                previous = dict(row)
        return previous, current
    except Exception as error:
        logger.error("detection snapshot lookup failed: %s", error)
        return None, None


def record_time_key(record: dict[str, Any]) -> str:
    """Pick the first usable timestamp field from one record."""
    try:
        for field in ("DETECTED_AT", "TIMESTAMP", "LAST_VERIFIED_AT", "UPDATED_AT"):
            key = time_key_from_value(record.get(field))
            if key:
                return key
        return ""
    except Exception as error:
        logger.error("record time key lookup failed: %s", error)
        return ""


def record_epoch(record: dict[str, Any]) -> float | None:
    """Return epoch seconds for one record row."""
    try:
        for field in ("DETECTED_AT", "TIMESTAMP", "LAST_VERIFIED_AT", "UPDATED_AT"):
            epoch = timestamp_to_epoch(record.get(field))
            if epoch is not None:
                return epoch
        return time_key_to_epoch(record_time_key(record))
    except Exception as error:
        logger.error("record epoch lookup failed: %s", error)
        return None


def latest_record_time_key(packet: dict[str, Any]) -> str:
    """Return the latest onboard sample timestamp inside one accumulated packet."""
    try:
        records = packet.get("records")
        if not isinstance(records, list):
            return record_time_key(packet)

        latest_key = ""
        latest_epoch = float("-inf")
        for record in records:
            if not isinstance(record, dict):
                continue
            key = record_time_key(record)
            epoch = time_key_to_epoch(key)
            if epoch is None:
                continue
            if epoch >= latest_epoch:
                latest_epoch = epoch
                latest_key = key
        if latest_key:
            return latest_key
        return record_time_key(packet)
    except Exception as error:
        logger.error("latest record time key lookup failed: %s", error)
        return ""


def _records_within_tolerance(
    records: list[dict[str, Any]],
    key: str,
    tolerance_sec: float,
) -> list[tuple[float, dict[str, Any]]]:
    try:
        bucket_epoch = time_key_to_epoch(key)
        if bucket_epoch is None:
            return []

        candidates: list[tuple[float, dict[str, Any]]] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            record_key = record_time_key(record)
            record_epoch_value = time_key_to_epoch(record_key)
            if record_epoch_value is None:
                continue
            delta = abs(record_epoch_value - bucket_epoch)
            if delta <= tolerance_sec:
                candidates.append((delta, scrub_record(record)))
        candidates.sort(key=lambda item: (item[0], record_time_key(item[1])))
        return candidates
    except Exception as error:
        logger.error("records within tolerance lookup failed: %s", error)
        return []


def select_nearest_record_for_key(
    packet: dict[str, Any],
    key: str,
    tolerance_sec: float = DEFAULT_RECORD_MATCH_TOLERANCE_SEC,
) -> dict[str, Any] | None:
    """Pick the onboard row whose timestamp is nearest to the buffer bucket key."""
    try:
        records = packet.get("records")
        if isinstance(records, list):
            exact = [
                scrub_record(record)
                for record in records
                if isinstance(record, dict) and record_time_key(record) == key
            ]
            if exact:
                return exact[0]

            candidates = _records_within_tolerance(
                [record for record in records if isinstance(record, dict)],
                key,
                tolerance_sec,
            )
            if candidates:
                return candidates[0][1]

        packet_type = normalize_packet_type(str(packet.get("packet_type", "")).strip())
        if packet_type == "SAT_EVENT_QUEUE":
            event = packet.get("event", packet)
            if isinstance(event, dict) and record_time_key(event) == key:
                return scrub_record(event)

        if record_time_key(packet) == key:
            return scrub_record(packet)

        single_epoch = record_epoch(packet)
        bucket_epoch = time_key_to_epoch(key)
        if single_epoch is not None and bucket_epoch is not None:
            if abs(single_epoch - bucket_epoch) <= tolerance_sec:
                return scrub_record(packet)
        return None
    except Exception as error:
        logger.error("nearest record selection failed: %s", error)
        return None


def select_records_for_key(
    packet: dict[str, Any],
    key: str,
    tolerance_sec: float = DEFAULT_RECORD_MATCH_TOLERANCE_SEC,
) -> list[dict[str, Any]]:
    """Return the merge-active row for one buffer bucket (exact match first, then nearest)."""
    try:
        nearest = select_nearest_record_for_key(packet, key, tolerance_sec)
        if nearest is not None:
            return [nearest]
        return []
    except Exception as error:
        logger.error("record selection for key failed: %s", error)
        return []


def select_active_record(packet: dict[str, Any]) -> dict[str, Any]:
    """Return the record row used when flattening one packet."""
    try:
        active = packet.get("_active_record")
        if isinstance(active, dict):
            return scrub_record(active)

        buffer_key = packet.get("_buffer_key")
        tolerance = float(packet.get("_match_tolerance_sec", DEFAULT_RECORD_MATCH_TOLERANCE_SEC))
        if isinstance(buffer_key, str) and buffer_key:
            nearest = select_nearest_record_for_key(packet, buffer_key, tolerance)
            if nearest is not None:
                return nearest

        records = packet.get("records")
        if isinstance(records, list):
            for record in records:
                if isinstance(record, dict):
                    return scrub_record(record)

        if packet_type := normalize_packet_type(str(packet.get("packet_type", "")).strip()):
            if packet_type == "SAT_EVENT_QUEUE":
                event = packet.get("event", packet)
                if isinstance(event, dict):
                    return scrub_record(event)

        return scrub_record(packet)
    except Exception as error:
        logger.error("active record selection failed: %s", error)
        return {}


def flatten_integrity_record(record: dict[str, Any]) -> dict[str, Any]:
    """Map one SAT_INTEGRITY_HASH row to flattened hash fields for rule evaluation."""
    try:
        cleaned = scrub_record(record)
        expected_hash = cleaned.get("EXPECTED_HASH")
        is_violated = int(cleaned.get("IS_VIOLATED", 0) or 0) == 1
        actual_hash = cleaned.get("ACTUAL_HASH") or cleaned.get("OBC_P_HASH")

        if is_violated:
            if actual_hash and actual_hash != expected_hash:
                obc_p_hash = actual_hash
            elif expected_hash:
                obc_p_hash = f"{expected_hash}_TAMPERED"
            else:
                obc_p_hash = "TAMPERED"
        elif actual_hash:
            obc_p_hash = actual_hash
        else:
            obc_p_hash = expected_hash

        flattened = {
            "IS_VIOLATED": int(cleaned.get("IS_VIOLATED", 0) or 0),
            "EXPECTED_HASH": expected_hash,
            "EXPECTED_CRC": expected_hash,
            "OBC_P_HASH": obc_p_hash,
            "FILE_PATH": cleaned.get("FILE_PATH"),
            "FILE_ID": cleaned.get("FILE_ID"),
            "LAST_VERIFIED_AT": cleaned.get("LAST_VERIFIED_AT"),
            "UPDATED_AT": cleaned.get("UPDATED_AT", ""),
        }
        file_target = infer_subsystem_from_file_path(flattened.get("FILE_PATH"))
        if file_target:
            flattened["TARGET_SUBSYSTEM"] = file_target
        return flattened
    except Exception as error:
        logger.error("integrity record flatten failed: %s", error)
        return scrub_record(record)


def select_integrity_record(
    packet: dict[str, Any],
    buffer_key: str | None = None,
    tolerance_sec: float = DEFAULT_RECORD_MATCH_TOLERANCE_SEC,
) -> dict[str, Any] | None:
    """Prefer IS_VIOLATED rows within the bucket key window, nearest first."""
    try:
        records = packet.get("records", [packet])
        if not isinstance(records, list):
            records = [packet]

        valid = [scrub_record(record) for record in records if isinstance(record, dict)]
        if not valid:
            return None

        if buffer_key:
            timed_records = [record for record in valid if record_time_key(record)]
            if timed_records:
                candidates = _records_within_tolerance(valid, buffer_key, tolerance_sec)
                if not candidates:
                    return None
                valid = [record for _, record in candidates]

        violated = [record for record in valid if int(record.get("IS_VIOLATED", 0) or 0) == 1]
        if violated:
            return violated[0]

        non_violated = [record for record in valid if int(record.get("IS_VIOLATED", 0) or 0) == 0]
        if non_violated:
            return non_violated[0]

        return valid[0]
    except Exception as error:
        logger.error("integrity record selection failed: %s", error)
        return None