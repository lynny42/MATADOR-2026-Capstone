"""Service layer that builds dashboard API responses from MySQL."""

from __future__ import annotations

import json
import logging
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from ma_detector import MAIntegratedDetector
from ma_detector.core.evidence_rules import EvidenceRules
from ma_detector.core.packet_protocol import detection_snapshots_from_history
from ma_detector.core.rule_activation import compute_step_change_percent, merge_default_activations
from ma_detector.core.target_context import (
    CORE_SUBSYSTEMS,
    normalize_target_subsystem,
    report_matches_target,
)
from ma_detector.db import gs_repository
from ma_detector.db.database import require_db
from ma_detector.registry.registry_manager import RegistryManager

logger = logging.getLogger(__name__)

# Rows inserted within this wall-clock gap belong to one satellite uplink window.
COMM_SESSION_GAP_SEC = 30
DETECTION_MATCH_TOLERANCE_SEC = 5
MAX_COMMUNICATIONS = 200
TLM_HISTORY_CLUSTER_LIMIT = 5000

_SKIP_SNAPSHOT_KEYS = frozenset(
    {
        "HISTORY_ID",
        "DETAIL_ID",
        "DASHBOARD_ID",
        "DETECT_ID",
        "CREATED_AT",
        "SNAPSHOT",
        "PAYLOAD",
        "RAW_PAYLOAD",
    }
)

RULE_COLUMN_ALIASES: dict[str, tuple[str, ...]] = {
    "DEVICE_ERR_RW0": ("DEVICE_ENABLED_RW0",),
    "DEVICE_ERR_RW1": ("DEVICE_ENABLED_RW1",),
    "DEVICE_ERR_RW2": ("DEVICE_ENABLED_RW2",),
    "EXPECTED_CRC": ("EXPECTED_HASH",),
    "OBC_P_HASH": ("ACTUAL_HASH", "OBC_P_HASH"),
}

MODULE_ALIASES = {
    "CF": ["OBC"],
    "CS": ["OBC"],
    "DS": ["OBC"],
    "ES": ["OBC"],
    "HK": ["COM"],
    "MD": ["OBC"],
    "SB": ["OBC"],
    "SCH": ["OBC"],
    "TBL": ["OBC"],
    "TO": ["COM"],
}
_REPLAY_ROW_SKIP_KEYS = frozenset({"HISTORY_ID", "PAYLOAD", "RAW_PAYLOAD"})


def _json_safe_value(value: Any) -> Any:
    """Convert DB-loaded values into JSON-serializable forms for replay."""
    try:
        if isinstance(value, datetime):
            return value.isoformat(sep=" ", timespec="seconds")
        if isinstance(value, date):
            return value.isoformat()
        if isinstance(value, Decimal):
            return float(value)
        if isinstance(value, dict):
            return {str(key): _json_safe_value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [_json_safe_value(item) for item in value]
        if isinstance(value, (bytes, bytearray)):
            return value.decode("utf-8", errors="replace")
        return value
    except Exception as error:
        logger.error("json safe conversion failed: %s", error)
        return value


def _normalize_replay_packet(packet: dict[str, Any]) -> dict[str, Any]:
    """Strip DB-only columns and normalize values before replay ingestion."""
    try:
        cleaned = {
            key: value
            for key, value in packet.items()
            if key not in _REPLAY_ROW_SKIP_KEYS
        }
        safe = _json_safe_value(cleaned)
        return safe if isinstance(safe, dict) else cleaned
    except Exception as error:
        logger.error("replay packet normalization failed: %s", error)
        return packet


def _dump_replay_packet(packet: dict[str, Any]) -> str:
    """Serialize one replay packet for receive_telemetry()."""
    try:
        return json.dumps(_normalize_replay_packet(packet), ensure_ascii=False)
    except Exception as error:
        logger.error("replay packet serialization failed: %s", error)
        return json.dumps(_json_safe_value(packet), ensure_ascii=False, default=str)


def create_detector() -> MAIntegratedDetector:
    """Create a detector with baseline and pipeline state loaded from MySQL."""
    require_db()
    detector = MAIntegratedDetector()
    history = gs_repository.load_baseline_history()
    if not history:
        logger.warning("GS_TLM_HISTORY has no normal rows; baseline empty until telemetry arrives")
    detector.build_baseline(history)
    _hydrate_detector_from_db(detector)
    return detector


def _hydrate_detector_from_db(detector: MAIntegratedDetector) -> None:
    """Load recent telemetry and dashboard rows from MySQL into the detector pipeline cache."""
    try:
        tlm_rows = gs_repository.load_recent_tlm_history(600)
        dashboard_rows = gs_repository.query_recent_dashboards(100)
        if tlm_rows or dashboard_rows:
            detector.hydrate_memory_state(tlm_rows, dashboard_rows)
            logger.info(
                "hydrated detector pipeline cache from DB: tlm=%s dashboard=%s",
                len(tlm_rows),
                len(dashboard_rows),
            )
    except Exception as error:
        logger.error("detector DB hydration failed: %s", error)


class DashboardService:
    """Builds dashboard, rule, and replay responses from detector state."""

    def __init__(self, detector: MAIntegratedDetector) -> None:
        self.detector = detector
        self.registry_manager = RegistryManager()

    def receive_satellite_packet(self, packet: dict[str, Any]) -> dict[str, Any]:
        """Insert a satellite packet and return the current dashboard state."""
        ingest_error = self.detector.receive_telemetry(json.dumps(packet, ensure_ascii=False))
        state = self.get_dashboard_state()
        state["ingest_ok"] = ingest_error is None
        if ingest_error:
            state["ingest_error"] = ingest_error
        return state

    def get_dashboard_state(self) -> dict[str, Any]:
        """Return the full dashboard model consumed by the Next.js UI."""
        return self._get_dashboard_state_for_detector(self.detector)

    def _get_dashboard_state_for_detector(
        self,
        detector: MAIntegratedDetector,
        *,
        preview_detector: MAIntegratedDetector | None = None,
    ) -> dict[str, Any]:
        """Return the dashboard model; production reads MySQL, preview uses in-memory replay output."""
        if preview_detector is not None:
            dashboard_rows = preview_detector.get_dashboard_records()
            history_rows = preview_detector.get_history_records()
        else:
            require_db()
            dashboard_rows = gs_repository.query_recent_dashboards(100)
            history_rows = gs_repository.load_recent_tlm_history(TLM_HISTORY_CLUSTER_LIMIT)
        detections = [self._to_detection(row) for row in dashboard_rows]
        detections = self._sort_detections_for_display(detections)
        communications = self._build_communications(history_rows, detections)
        latest_comm = communications[-1] if communications else None
        latest_detections = list(latest_comm.get("detections", [])) if latest_comm else []
        latest_time = latest_comm.get("communicated_at") if latest_comm else None
        latest_target = ""
        if latest_detections:
            latest_target = str(latest_detections[0].get("satellite_filter", {}).get("target_subsystem") or "")
        latest_target = normalize_target_subsystem(latest_target)
        selected = detections[0] if detections else None

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "core_subsystems": list(CORE_SUBSYSTEMS),
            "communications": communications,
            "latest_communication": {
                "communicated_at": latest_time,
                "status": latest_comm.get("status", "NORMAL") if latest_comm else "NORMAL",
                "anomaly_count": len(latest_detections),
                "detections": latest_detections,
                "satellite_target_subsystem": latest_target or None,
            },
            "ingest_error": detector.get_last_ingest_error(),
            "recent_threats": self._recent_threats(detections),
            "blueprint": self._build_blueprint(detections, latest_target),
            "detections": detections,
            "selected_detection": selected,
        }

    def get_detection_detail(self, detect_id: int, snapshot_index: int | None = None) -> dict[str, Any]:
        """Return UI-ready detail for one dashboard detection at its detect_time snapshot."""
        _ = snapshot_index
        payload = json.loads(self.detector.get_ui_data(detect_id))
        if "error" in payload:
            return payload

        detail_history = payload.get("detail", {}).get("history", [])
        detection = self._dashboard_detection_by_id(detect_id)
        detect_time = str(detection.get("detect_time") or "")
        history_rows = gs_repository.query_detection_history_rows(detect_time)
        if not history_rows:
            history_rows = list(detail_history)
        previous_snapshot, current_snapshot = detection_snapshots_from_history(history_rows, detect_time)
        if current_snapshot is None and detail_history:
            previous_snapshot, current_snapshot = detection_snapshots_from_history(
                detail_history,
                detect_time,
            )
        snapshot = dict(current_snapshot or {})
        previous_snapshot = dict(previous_snapshot) if previous_snapshot else None
        payload["snapshot_frame"] = {
            "mode": "detection_snapshot",
            "index": 0,
            "total": 1 if current_snapshot else 0,
            "previous_at": (previous_snapshot or {}).get("UPDATED_AT"),
            "current_at": snapshot.get("UPDATED_AT"),
        }
        payload["rule_details"] = self._build_rule_details(
            payload.get("evidence_keys", {}),
            snapshot,
            detection,
            previous_snapshot,
        )
        payload["matches_satellite_target"] = bool(detection.get("matches_satellite_target"))
        payload["is_new_pattern"] = bool(detection.get("is_new_pattern"))
        payload["action_mapping_status"] = detection.get("action_mapping_status", "mapped")
        payload["unregistered_action_ids"] = detection.get("unregistered_action_ids", [])
        payload["triggered_rule_results"] = detection.get("triggered_rule_results", [])
        payload["novel_attack_advisory"] = self._novel_advisory_for_detection(detection)
        return payload

    def _novel_advisory_for_detection(self, detection: dict[str, Any]) -> dict[str, Any] | None:
        """Return B-3 advisory when attack(Y) has no mapped Action or is_new_pattern."""
        try:
            if detection.get("action_mapping_status") != "undefined" and not detection.get("is_new_pattern"):
                return None
            advisory = self.detector.get_latest_novel_advisory()
            if not advisory:
                return None
            ma_code = str(detection.get("ma_code", ""))
            return {
                **advisory,
                "related_ma_codes": [ma_code] if ma_code else [],
            }
        except Exception:
            return None

    def list_rules(self) -> dict[str, Any]:
        """Return active rule and threshold configuration."""
        return {
            "rules": self.detector.get_rule_registry(),
            "thresholds": self.detector.get_threshold_config(),
            "actions": self.detector.get_action_registry(),
        }

    def upsert_rule(self, rule_id: str, definition: dict[str, Any]) -> dict[str, Any]:
        """Create or replace a rule definition and reload the detector config."""
        if not rule_id:
            return {"ok": False, "error": "rule_id is required"}
        ok = self.registry_manager.add_rule(rule_id, definition)
        self.detector.reload_config()
        return {"ok": ok, "rule_id": rule_id}

    def update_rule(self, rule_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update a rule definition and reload detector config."""
        ok = self.registry_manager.update_rule(rule_id, updates)
        self.detector.reload_config()
        return {"ok": ok, "rule_id": rule_id}

    def delete_rule(self, rule_id: str) -> dict[str, Any]:
        """Delete a rule definition and reload detector config."""
        ok = self.registry_manager.delete_rule(rule_id)
        self.detector.reload_config()
        return {"ok": ok, "rule_id": rule_id}

    def upsert_action(self, action_id: str, definition: dict[str, Any]) -> dict[str, Any]:
        """Create or replace an action definition and reload the detector config."""
        if not action_id:
            return {"ok": False, "error": "action_id is required"}
        ok = self.registry_manager.add_action(action_id, definition)
        self.detector.reload_config()
        return {"ok": ok, "action_id": action_id}

    def update_action(self, action_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update an action definition and reload detector config."""
        ok = self.registry_manager.update_action(action_id, updates)
        self.detector.reload_config()
        return {"ok": ok, "action_id": action_id}

    def delete_action(self, action_id: str) -> dict[str, Any]:
        """Delete an action definition and reload detector config."""
        ok = self.registry_manager.delete_action(action_id)
        self.detector.reload_config()
        return {"ok": ok, "action_id": action_id}

    def update_threshold(self, category: str, key: str, value: float) -> dict[str, Any]:
        """Update a threshold value and reload detector config."""
        ok = self.registry_manager.update_threshold(category, key, value)
        self.detector.reload_config()
        return {"ok": ok, "category": category, "key": key, "value": value}

    def run_replay(self, packets: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Re-run MA detection on stored anomaly telemetry and persist results to MySQL."""
        require_db()
        if packets is not None:
            return {"ok": False, "error": "custom replay packets are disabled; use stored DB telemetry"}
        gs_repository.clear_ma_results()
        reprocessed = 0
        for row in gs_repository.load_anomaly_history():
            error = self.detector.receive_telemetry(
                _dump_replay_packet(row),
                reprocess=True,
            )
            if error is None:
                reprocessed += 1
        _hydrate_detector_from_db(self.detector)
        return {
            "ok": True,
            "reprocessed": reprocessed,
            "dashboard": self.get_dashboard_state(),
        }

    def run_replay_preview(
        self,
        rules: dict[str, Any],
        thresholds: dict[str, Any],
        packets: list[dict[str, Any]] | None = None,
        actions: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Run a replay with temporary rules and thresholds without changing saved config or MySQL."""
        if packets is not None:
            return {"ok": False, "error": "custom replay packets are disabled; use stored DB telemetry"}
        preview_detector = self._reprocess_detector_from_db(
            rules,
            thresholds,
            actions,
            preview=True,
        )
        current_dashboard = self.get_dashboard_state()
        preview_dashboard = self._get_dashboard_state_for_detector(
            self.detector,
            preview_detector=preview_detector,
        )
        return {
            "ok": True,
            "temporary": True,
            "dashboard": preview_dashboard,
            "comparison": self._build_replay_comparison(current_dashboard, preview_dashboard),
            "rules": rules,
            "thresholds": thresholds,
        }

    def apply_replay_config(
        self,
        rules: dict[str, Any],
        thresholds: dict[str, Any],
        actions: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Persist replay settings, clear MA tables, and reprocess stored anomaly telemetry."""
        rules_ok = self.registry_manager.replace_rules(rules)
        thresholds_ok = self.registry_manager.replace_thresholds(thresholds)
        actions_ok = True
        if actions is not None:
            actions_ok = self.registry_manager.replace_actions(actions)
        if not (rules_ok and thresholds_ok and actions_ok):
            return {"ok": False, "error": "config persistence failed"}

        self.detector = self._reprocess_detector_from_db(
            rules,
            thresholds,
            actions,
            preview=False,
        )
        return {"ok": True, "dashboard": self.get_dashboard_state()}

    def persist_rules(self, rules: dict[str, Any]) -> dict[str, Any]:
        """Write the full rule registry to disk and reload the live detector."""
        ok = self.registry_manager.replace_rules(rules)
        if ok:
            self.detector.reload_config()
        return {"ok": ok, "target": "rule_registry.json"}

    def persist_thresholds(self, thresholds: dict[str, Any]) -> dict[str, Any]:
        """Write threshold config to disk and reload the live detector."""
        ok = self.registry_manager.replace_thresholds(thresholds)
        if ok:
            self.detector.reload_config()
        return {"ok": ok, "target": "threshold_config.json"}

    def persist_actions(self, actions: dict[str, Any]) -> dict[str, Any]:
        """Write the full action registry to disk and reload the live detector."""
        ok = self.registry_manager.replace_actions(actions)
        if ok:
            self.detector.reload_config()
        return {"ok": ok, "target": "action_registry.json"}

    def _dashboard_detection_by_id(self, detect_id: int) -> dict[str, Any]:
        try:
            require_db()
            row = gs_repository.query_dashboard(int(detect_id))
            if row:
                return self._to_detection(row)
            return {}
        except (TypeError, ValueError):
            return {}

    def _reprocess_detector_from_db(
        self,
        rules: dict[str, Any],
        thresholds: dict[str, Any],
        actions: dict[str, Any] | None,
        *,
        preview: bool,
    ) -> MAIntegratedDetector:
        """Rebuild detector config and re-run MA on stored IS_ANOMALY=1 rows."""
        require_db()
        detector = MAIntegratedDetector()
        detector._action_registry = (
            actions if actions is not None else self.detector.get_action_registry()
        )
        detector._rule_registry = rules
        merge_default_activations(detector._rule_registry)
        detector._threshold_config = thresholds
        detector._evidence_rules = EvidenceRules(detector._baseline_manager, thresholds)
        baseline = gs_repository.load_baseline_history()
        detector.build_baseline(baseline)

        if not preview:
            gs_repository.clear_ma_results()

        detector.set_replay_mode(preview)
        try:
            for row in gs_repository.load_anomaly_history():
                detector.receive_telemetry(
                    _dump_replay_packet(row),
                    reprocess=True,
                )
        finally:
            detector.set_replay_mode(False)

        if not preview:
            _hydrate_detector_from_db(detector)
        return detector

    @staticmethod
    def _build_replay_comparison(
        current_dashboard: dict[str, Any],
        preview_dashboard: dict[str, Any],
    ) -> dict[str, Any]:
        """Compare current detections with temporary replay detections."""
        current_by_code = {
            detection["ma_code"]: detection
            for detection in current_dashboard.get("detections", [])
        }
        preview_by_code = {
            detection["ma_code"]: detection
            for detection in preview_dashboard.get("detections", [])
        }
        current_codes = set(current_by_code)
        preview_codes = set(preview_by_code)

        changed = []
        for code in sorted(current_codes & preview_codes):
            current = current_by_code[code]
            preview = preview_by_code[code]
            confidence_delta = round(
                float(preview.get("confidence", 0.0)) - float(current.get("confidence", 0.0)),
                2,
            )
            phase_delta = int(preview.get("phase", 0) or 0) - int(current.get("phase", 0) or 0)
            if confidence_delta != 0 or phase_delta != 0 or current.get("grade") != preview.get("grade"):
                changed.append(
                    {
                        "ma_code": code,
                        "current": current,
                        "preview": preview,
                        "confidence_delta": confidence_delta,
                        "phase_delta": phase_delta,
                    }
                )

        return {
            "current_count": len(current_codes),
            "preview_count": len(preview_codes),
            "delta_count": len(preview_codes) - len(current_codes),
            "added": [preview_by_code[code] for code in sorted(preview_codes - current_codes)],
            "removed": [current_by_code[code] for code in sorted(current_codes - preview_codes)],
            "changed": changed,
            "unchanged": [
                preview_by_code[code]
                for code in sorted((current_codes & preview_codes) - {item["ma_code"] for item in changed})
            ],
        }

    def _to_detection(self, row: dict[str, Any]) -> dict[str, Any]:
        module = str(row.get("MODULE", "UNKNOWN"))
        confidence = float(row.get("CONFIDENCE_SCORE", 0.0) or 0.0)
        phase = int(row.get("SCENARIO_PHASE", 0) or 0)
        target = normalize_target_subsystem(row.get("SATELLITE_TARGET_SUBSYSTEM") or row.get("TARGET_SUBSYSTEM"))
        report_stub = {
            "module": module,
            "ma_code": row.get("MA_CODE"),
            "triggered_rules": list((row.get("EVIDENCE_KEYS") or {}).keys()),
        }
        matches_target = bool(row.get("MATCHES_SATELLITE_TARGET"))
        if target and not matches_target:
            matches_target = report_matches_target(
                report_stub,
                target,
                self.detector.get_rule_registry(),
            )
        return {
            "detect_id": row.get("DETECT_ID"),
            "dashboard_id": row.get("DASHBOARD_ID"),
            "detect_time": row.get("DETECT_TIME"),
            "module": module,
            "subsystems": self._module_to_subsystems(module),
            "action": row.get("ACTION"),
            "phase": phase,
            "ma_code": row.get("MA_CODE"),
            "confidence": confidence,
            "grade": row.get("GRADE"),
            "corroboration_count": row.get("CORROBORATION_COUNT"),
            "evidence_keys": row.get("EVIDENCE_KEYS", {}),
            "matches_satellite_target": matches_target,
            "is_new_pattern": bool(row.get("IS_NEW_PATTERN")),
            "action_mapping_status": str(row.get("ACTION_MAPPING_STATUS", "mapped")),
            "triggered_rule_ids": list(row.get("TRIGGERED_RULE_IDS", [])),
            "unregistered_action_ids": list(row.get("UNREGISTERED_ACTION_IDS", [])),
            "triggered_rule_results": list(row.get("TRIGGERED_RULE_RESULTS", [])),
            "satellite_filter": {
                "result": row.get("FALSE_POSITIVE_RESULT"),
                "weight": row.get("FALSE_POSITIVE_WEIGHT"),
                "exception": row.get("FALSE_POSITIVE_EXCEPTION"),
                "target_subsystem": target or row.get("TARGET_SUBSYSTEM"),
                "event_id": row.get("EVENT_ID"),
                "sw_id_list": row.get("SW_ID_LIST", []),
                "detected_at": row.get("SATELLITE_DETECTED_AT"),
            },
            "severity": self._severity(phase, confidence),
        }

    def _sort_detections_for_display(self, detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
        try:
            return sorted(
                detections,
                key=lambda item: (
                    0 if item.get("matches_satellite_target") else 1,
                    -float(item.get("confidence", 0.0) or 0.0),
                    str(item.get("detect_time", "")),
                ),
            )
        except Exception:
            return detections

    @staticmethod
    def _format_communicated_at(value: Any) -> str:
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
            return normalized.replace("T", " ")
        except Exception:
            return str(value)

    @staticmethod
    def _parse_datetime_value(value: Any) -> datetime | None:
        try:
            if value is None:
                return None
            if isinstance(value, datetime):
                return value.replace(tzinfo=None) if value.tzinfo else value
            if isinstance(value, date):
                return datetime.combine(value, datetime.min.time())
            text = str(value).strip()
            if not text:
                return None
            normalized = text.replace("Z", "+00:00")
            if "T" not in normalized and " " in normalized:
                normalized = normalized.replace(" ", "T", 1)
            parsed = datetime.fromisoformat(normalized)
            return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed
        except Exception:
            return None

    @staticmethod
    def _communication_time_key(value: str) -> str:
        try:
            return value.replace("T", " ").strip()
        except Exception:
            return str(value)

    def _cluster_history_sessions(
        self,
        history_rows: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Group onboard history rows that arrived in the same uplink burst."""
        try:
            dated_rows: list[tuple[datetime, dict[str, Any]]] = []
            for row in history_rows:
                created_at = self._parse_datetime_value(row.get("CREATED_AT"))
                if created_at is None:
                    fallback = self._parse_datetime_value(row.get("UPDATED_AT") or row.get("DETECTED_AT"))
                    if fallback is None:
                        continue
                    created_at = fallback
                dated_rows.append((created_at, row))

            if not dated_rows:
                return []

            dated_rows.sort(key=lambda item: item[0])
            sessions: list[dict[str, Any]] = []
            current_created = dated_rows[0][0]
            current_rows = [dated_rows[0][1]]
            last_created = current_created

            for created_at, row in dated_rows[1:]:
                if (created_at - last_created).total_seconds() > COMM_SESSION_GAP_SEC:
                    sessions.append(
                        {
                            "created_start": current_created,
                            "created_end": last_created,
                            "rows": current_rows,
                        }
                    )
                    current_created = created_at
                    current_rows = [row]
                else:
                    current_rows.append(row)
                last_created = created_at

            sessions.append(
                {
                    "created_start": current_created,
                    "created_end": last_created,
                    "rows": current_rows,
                }
            )

            for session in sessions:
                onboard_times = [
                    self._parse_datetime_value(item.get("UPDATED_AT") or item.get("DETECTED_AT"))
                    for item in session["rows"]
                ]
                valid_onboard = [value for value in onboard_times if value is not None]
                session["received_at"] = self._format_communicated_at(session["created_end"])
                session["communicated_at"] = session["received_at"]
                session["onboard_snapshot_at"] = (
                    self._format_communicated_at(max(valid_onboard)) if valid_onboard else session["received_at"]
                )
                session["onboard_start"] = min(valid_onboard) if valid_onboard else session["created_start"]
                session["onboard_end"] = max(valid_onboard) if valid_onboard else session["created_end"]
                session["sample_count"] = len(session["rows"])
                session["has_anomaly_rows"] = any(int(item.get("IS_ANOMALY", 0) or 0) == 1 for item in session["rows"])
            return sessions
        except Exception as error:
            logger.error("history session clustering failed: %s", error)
            return []

    def _session_anomaly_event_times(self, session: dict[str, Any]) -> list[datetime]:
        try:
            event_times: list[datetime] = []
            for row in session.get("rows", []):
                if int(row.get("IS_ANOMALY", 0) or 0) != 1:
                    continue
                parsed = self._parse_datetime_value(row.get("UPDATED_AT") or row.get("DETECTED_AT"))
                if parsed is not None:
                    event_times.append(parsed)
            return event_times
        except Exception as error:
            logger.error("session anomaly event lookup failed: %s", error)
            return []

    def _assign_detection_to_session(
        self,
        detection: dict[str, Any],
        sessions: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        try:
            detect_time = self._parse_datetime_value(detection.get("detect_time"))
            if detect_time is None or not sessions:
                return None

            tolerance = DETECTION_MATCH_TOLERANCE_SEC
            best_session: dict[str, Any] | None = None
            best_delta = float("inf")
            for session in sessions:
                if not session.get("has_anomaly_rows"):
                    continue
                for event_time in self._session_anomaly_event_times(session):
                    delta = abs((detect_time - event_time).total_seconds())
                    if delta <= tolerance and delta < best_delta:
                        best_delta = delta
                        best_session = session
            return best_session
        except Exception as error:
            logger.error("detection session assignment failed: %s", error)
            return None

    def _build_communications(
        self,
        history_rows: list[dict[str, Any]],
        detections: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        sessions = self._cluster_history_sessions(history_rows)
        if not sessions:
            communication_map: dict[str, dict[str, Any]] = {}
            for row in history_rows:
                communicated_at = self._format_communicated_at(
                    row.get("UPDATED_AT") or row.get("DETECTED_AT")
                )
                if not communicated_at:
                    continue
                key = self._communication_time_key(communicated_at)
                communication_map[key] = {
                    "communicated_at": communicated_at,
                    "status": "NORMAL",
                    "detections": [],
                    "sample_count": 1,
                }
        else:
            communication_map = {
                self._communication_time_key(str(session["communicated_at"])): {
                    "communicated_at": session["communicated_at"],
                    "received_at": session.get("received_at", session["communicated_at"]),
                    "onboard_snapshot_at": session.get("onboard_snapshot_at"),
                    "status": "NORMAL",
                    "detections": [],
                    "sample_count": int(session.get("sample_count", 0) or 0),
                }
                for session in sessions
            }

        for detection in detections:
            detect_time = self._format_communicated_at(detection.get("detect_time"))
            if not detect_time:
                continue
            session = self._assign_detection_to_session(detection, sessions) if sessions else None
            if session is None:
                continue
            key = self._communication_time_key(str(session["communicated_at"]))
            entry = communication_map.setdefault(
                key,
                {
                    "communicated_at": session["communicated_at"],
                    "received_at": session.get("received_at", session["communicated_at"]),
                    "onboard_snapshot_at": session.get("onboard_snapshot_at"),
                    "status": "NORMAL",
                    "detections": [],
                    "sample_count": int(session.get("sample_count", 0) or 0),
                },
            )
            entry["status"] = "ANOMALY"
            entry["detections"].append(detection)

        communications = sorted(communication_map.values(), key=lambda item: item["communicated_at"])
        if len(communications) > MAX_COMMUNICATIONS:
            communications = communications[-MAX_COMMUNICATIONS:]
        for communication in communications:
            communication["detections"] = sorted(
                communication["detections"],
                key=lambda item: (str(item.get("detect_time", "")), int(item.get("detect_id", 0) or 0)),
            )
            communication["anomaly_count"] = len(communication["detections"])
        return communications

    def _recent_threats(self, detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(detections, key=lambda item: str(item.get("detect_time", "")))[-5:]

    def _build_blueprint(
        self,
        detections: list[dict[str, Any]],
        satellite_target: str = "",
    ) -> dict[str, Any]:
        recent = self._recent_threats(detections)
        normalized_target = normalize_target_subsystem(satellite_target)
        blueprint: dict[str, Any] = {
            subsystem: {
                "name": subsystem,
                "detections": [],
                "severity": "normal",
                "satellite_target_emphasis": subsystem == normalized_target,
            }
            for subsystem in CORE_SUBSYSTEMS
        }
        for detection in recent:
            for subsystem in detection["subsystems"]:
                if subsystem not in blueprint:
                    continue
                entry = dict(detection)
                entry["emphasized"] = bool(
                    detection.get("matches_satellite_target")
                    or subsystem == normalized_target
                )
                blueprint[subsystem]["detections"].append(entry)
                blueprint[subsystem]["severity"] = self._max_severity(
                    blueprint[subsystem]["severity"],
                    detection["severity"],
                )
        return blueprint

    def _build_rule_details(
        self,
        evidence_keys: dict[str, str],
        snapshot: dict[str, Any],
        detection: dict[str, Any],
        previous_snapshot: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        rules = self.detector.get_rule_registry()
        actions = self.detector.get_action_registry()
        triggered_results = {
            str(item.get("rule_id", "")): item
            for item in (detection.get("triggered_rule_results") or [])
            if item.get("rule_id")
        }
        rule_ids = detection.get("triggered_rule_ids") or list(evidence_keys.keys())
        details = []
        for rule_id in rule_ids:
            rule_name = evidence_keys.get(rule_id) or rules.get(rule_id, {}).get("name", rule_id)
            rule = rules.get(rule_id, {})
            columns = rule.get("columns", [])
            column_values = {
                column: self._build_column_detail(column, snapshot, previous_snapshot)
                for column in columns
            }
            contributes = rule.get("contributes_to", {})
            mapped_actions = []
            unmapped_actions = []
            for action_id, weight in contributes.items():
                action_def = actions.get(action_id)
                entry = {
                    "action_id": action_id,
                    "weight": weight,
                    "registered": action_def is not None,
                    "name": (action_def or {}).get("name", "(미등록)"),
                    "module": (action_def or {}).get("module", "-"),
                    "phase": (action_def or {}).get("phase", "-"),
                }
                if action_def is None:
                    unmapped_actions.append(entry)
                else:
                    mapped_actions.append(entry)
            result = triggered_results.get(rule_id, {})
            details.append(
                {
                    "rule_id": rule_id,
                    "name": rule_name,
                    "rule_score": result.get("score"),
                    "triggered": result.get("triggered", rule_id in evidence_keys),
                    "first_triggered_at": detection.get("detect_time"),
                    "subsystems": rule.get("subsystems", []),
                    "columns": column_values,
                    "contributes_to": contributes,
                    "mapped_actions": mapped_actions,
                    "unmapped_actions": unmapped_actions,
                    "single_sufficient": rule.get("single_sufficient", False),
                    "activation": rule.get("activation", {}),
                    "evidence": result.get("evidence", {}),
                }
            )
        return details

    def _build_column_detail(
        self,
        column: str,
        snapshot: dict[str, Any],
        previous_snapshot: dict[str, Any] | None,
    ) -> dict[str, Any]:
        observed = self._snapshot_column_value(snapshot, column)
        previous_observed = (
            self._snapshot_column_value(previous_snapshot, column) if previous_snapshot else None
        )
        return {
            "observed": observed,
            "normal": self._normal_reference(column, snapshot, previous_snapshot),
            "abnormal_percent": self._metric_percent(column, snapshot, previous_snapshot),
            "previous_observed": previous_observed,
        }

    @staticmethod
    def _module_to_subsystems(module: str) -> list[str]:
        raw_modules = [part.strip() for part in module.replace(",", "+").split("+")]
        subsystems: list[str] = []
        for raw_module in raw_modules:
            if raw_module in CORE_SUBSYSTEMS and raw_module not in subsystems:
                subsystems.append(raw_module)
            for mapped in MODULE_ALIASES.get(raw_module, []):
                if mapped not in subsystems:
                    subsystems.append(mapped)
        return subsystems or ["OBC"]

    @staticmethod
    def _severity(phase: int, confidence: float) -> str:
        if phase >= 3 or confidence >= 70.0:
            return "critical"
        if phase >= 2 or confidence >= 55.0:
            return "warning"
        if confidence > 0.0:
            return "watch"
        return "normal"

    @staticmethod
    def _max_severity(current: str, incoming: str) -> str:
        order = {"normal": 0, "watch": 1, "warning": 2, "critical": 3}
        return incoming if order.get(incoming, 0) > order.get(current, 0) else current

    @staticmethod
    def _merge_snapshot_layers(*layers: dict[str, Any] | None) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        try:
            for layer in layers:
                if not isinstance(layer, dict):
                    continue
                for key, value in layer.items():
                    if key in _SKIP_SNAPSHOT_KEYS or str(key).startswith("_"):
                        continue
                    if value is not None:
                        merged[key] = value
            return merged
        except Exception as error:
            logger.error("snapshot layer merge failed: %s", error)
            return merged

    @staticmethod
    def _snapshot_column_value(snapshot: dict[str, Any], column: str) -> Any:
        try:
            if not isinstance(snapshot, dict):
                return None
            value = snapshot.get(column)
            if value is not None:
                return value
            for alias in RULE_COLUMN_ALIASES.get(column, ()):
                alias_value = snapshot.get(alias)
                if alias_value is not None:
                    return alias_value
            return None
        except Exception as error:
            logger.error("snapshot column lookup failed: %s", error)
            return None

    @staticmethod
    def _normal_reference(
        column: str,
        snapshot: dict[str, Any],
        previous_snapshot: dict[str, Any] | None = None,
    ) -> Any:
        if previous_snapshot is not None:
            previous_value = DashboardService._snapshot_column_value(previous_snapshot, column)
            if previous_value is not None:
                return previous_value
        if column in {"OBC_P_HASH", "EXPECTED_CRC"}:
            return DashboardService._snapshot_column_value(snapshot, "EXPECTED_CRC")
        return None

    @staticmethod
    def _metric_percent(
        column: str,
        snapshot: dict[str, Any],
        previous_snapshot: dict[str, Any] | None = None,
    ) -> float | None:
        if previous_snapshot is None:
            return DashboardService._hash_mismatch_flag(column, snapshot)
        resolved_snapshot = DashboardService._resolve_snapshot_column(snapshot, column)
        resolved_previous = DashboardService._resolve_snapshot_column(previous_snapshot, column)
        current_value = DashboardService._snapshot_column_value(resolved_snapshot, column)
        previous_value = DashboardService._snapshot_column_value(resolved_previous, column)
        if current_value is None or previous_value is None:
            return DashboardService._hash_mismatch_flag(column, snapshot)
        if not isinstance(current_value, (int, float)) or not isinstance(previous_value, (int, float)):
            return DashboardService._hash_mismatch_flag(column, snapshot)
        return compute_step_change_percent(column, resolved_snapshot, resolved_previous)

    @staticmethod
    def _hash_mismatch_flag(column: str, snapshot: dict[str, Any]) -> float | None:
        if column not in {"OBC_P_HASH", "EXPECTED_CRC"}:
            return None
        observed = DashboardService._snapshot_column_value(snapshot, column)
        expected = DashboardService._snapshot_column_value(snapshot, "EXPECTED_CRC")
        if observed is None or expected is None:
            return None
        if str(observed).strip() == str(expected).strip():
            return 0.0
        return None

    @staticmethod
    def _resolve_snapshot_column(snapshot: dict[str, Any], column: str) -> dict[str, Any]:
        resolved = dict(snapshot)
        value = DashboardService._snapshot_column_value(snapshot, column)
        if value is not None:
            resolved[column] = value
        return resolved

    @staticmethod
    def _abnormal_percent(column: str, snapshot: dict[str, Any]) -> float | None:
        """Legacy helper kept for tests; UI uses DB-backed _metric_percent only."""
        return DashboardService._hash_mismatch_flag(column, snapshot)
