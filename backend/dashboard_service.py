"""Service layer that adapts MA detector memory tables for the dashboard API."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ma_detector import MAIntegratedDetector
from ma_detector.core.evidence_rules import EvidenceRules
from ma_detector.core.rule_activation import compute_step_change_percent, merge_default_activations
from ma_detector.core.target_context import (
    CORE_SUBSYSTEMS,
    normalize_target_subsystem,
    report_matches_target,
)
from ma_detector.registry.registry_manager import RegistryManager

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
# Primary seed/replay dataset for dashboard boot and tests (see tests/ and create_detector_with_seed).
DATASET_PATH = Path(__file__).resolve().parent / "test_data" / "realistic_satellite_dataset.json"


def create_detector_with_seed() -> MAIntegratedDetector:
    """Create a detector instance with representative ground-station data."""
    detector = MAIntegratedDetector()
    detector.build_baseline(_baseline_history())

    for packet in _seed_packets():
        detector.receive_telemetry(json.dumps(packet, ensure_ascii=False))
    return detector


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

    def _get_dashboard_state_for_detector(self, detector: MAIntegratedDetector) -> dict[str, Any]:
        """Return the dashboard model for a specific detector instance."""
        dashboard_rows = detector.get_dashboard_records()
        history_rows = detector.get_history_records()
        detections = [self._to_detection(row) for row in dashboard_rows]
        detections = self._sort_detections_for_display(detections)
        communications = self._build_communications(history_rows, detections)
        latest_time = communications[-1]["communicated_at"] if communications else None
        latest_detections = [
            detection
            for detection in detections
            if latest_time is not None and detection["detect_time"] == latest_time
        ]
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
                "status": "ANOMALY" if latest_detections else "NORMAL",
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
        """Return UI-ready detail for one dashboard detection at a snapshot frame."""
        payload = json.loads(self.detector.get_ui_data(detect_id))
        if "error" in payload:
            return payload

        detail_history = payload.get("detail", {}).get("history", [])
        detection = self._dashboard_detection_by_id(detect_id)
        detect_time = str(detection.get("detect_time") or "")
        previous_snapshot, current_snapshot, series = self.detector.get_snapshot_frame(
            detect_time,
            snapshot_index,
        )
        snapshot = current_snapshot or (detail_history[0] if detail_history else {})
        frame_index = snapshot_index
        if frame_index is None:
            frame_index = len(series) - 1 if series else 0
        evaluation = self.detector.get_threshold_config().get("evaluation", {})
        payload["snapshot_frame"] = {
            "mode": "snapshot_series",
            "index": frame_index,
            "total": len(series),
            "window_seconds": int(evaluation.get("series_seconds", self.detector._window_size_sec)),
            "interval_seconds": int(evaluation.get("series_interval_sec", 1)),
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
        payload["novel_attack_advisory"] = self._novel_advisory_for_detection(detection)
        return payload

    def _novel_advisory_for_detection(self, detection: dict[str, Any]) -> dict[str, Any] | None:
        """Return B-3 advisory only when the selected MA row is flagged is_new_pattern."""
        try:
            if not detection.get("is_new_pattern"):
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

    def update_threshold(self, category: str, key: str, value: float) -> dict[str, Any]:
        """Update a threshold value and reload detector config."""
        ok = self.registry_manager.update_threshold(category, key, value)
        self.detector.reload_config()
        return {"ok": ok, "category": category, "key": key, "value": value}

    def run_replay(self, packets: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Run replay mode for supplied packets or stored raw telemetry history."""
        replay_packets = packets if packets else self._replay_source_packets()
        self.detector.set_replay_mode(True)
        for packet in replay_packets:
            self.detector.receive_telemetry(json.dumps(packet, ensure_ascii=False))
        buffer = self.detector.get_replay_buffer()
        self.detector.set_replay_mode(False)
        return {"ok": True, "result_count": len(buffer), "results": buffer}

    def run_replay_preview(
        self,
        rules: dict[str, Any],
        thresholds: dict[str, Any],
        packets: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Run a replay with temporary rules and thresholds without changing saved config."""
        detector = self._create_detector_with_config(rules, thresholds, packets)
        current_dashboard = self.get_dashboard_state()
        preview_dashboard = self._get_dashboard_state_for_detector(detector)
        return {
            "ok": True,
            "temporary": True,
            "dashboard": preview_dashboard,
            "comparison": self._build_replay_comparison(current_dashboard, preview_dashboard),
            "rules": rules,
            "thresholds": thresholds,
        }

    def apply_replay_config(self, rules: dict[str, Any], thresholds: dict[str, Any]) -> dict[str, Any]:
        """Persist replay settings and rebuild detector state from scratch."""
        rules_ok = self.registry_manager.replace_rules(rules)
        thresholds_ok = self.registry_manager.replace_thresholds(thresholds)
        if not (rules_ok and thresholds_ok):
            return {"ok": False, "error": "config persistence failed"}

        self.detector = self._create_detector_with_config(rules, thresholds, None)
        return {"ok": True, "dashboard": self.get_dashboard_state()}

    def _dashboard_detection_by_id(self, detect_id: int) -> dict[str, Any]:
        try:
            for row in self.detector.get_dashboard_records():
                if int(row.get("DETECT_ID", -1)) == detect_id:
                    return self._to_detection(row)
            return {}
        except (TypeError, ValueError):
            return {}

    def _create_detector_with_config(
        self,
        rules: dict[str, Any],
        thresholds: dict[str, Any],
        packets: list[dict[str, Any]] | None,
    ) -> MAIntegratedDetector:
        detector = MAIntegratedDetector()
        detector._action_registry = self.detector.get_action_registry()
        detector._rule_registry = rules
        merge_default_activations(detector._rule_registry)
        detector._threshold_config = thresholds
        detector._evidence_rules = EvidenceRules(detector._baseline_manager, thresholds)
        detector.build_baseline(_baseline_history())
        for packet in packets if packets is not None else self._replay_source_packets():
            detector.receive_telemetry(json.dumps(packet, ensure_ascii=False))
        return detector

    def _replay_source_packets(self) -> list[dict[str, Any]]:
        """Use all stored received telemetry rows as replay source."""
        history = self.detector.get_history_records()
        return [deepcopy(row) for row in history] if history else _seed_packets()

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

    def _build_communications(
        self,
        history_rows: list[dict[str, Any]],
        detections: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        communication_map: dict[str, dict[str, Any]] = {}
        for row in history_rows:
            communicated_at = str(row.get("UPDATED_AT") or row.get("DETECTED_AT") or "")
            if not communicated_at:
                continue
            communication_map[communicated_at] = {
                "communicated_at": communicated_at,
                "status": "NORMAL",
                "detections": [],
            }

        for detection in detections:
            detect_time = str(detection.get("detect_time") or "")
            if not detect_time:
                continue
            entry = communication_map.setdefault(
                detect_time,
                {"communicated_at": detect_time, "status": "NORMAL", "detections": []},
            )
            entry["status"] = "ANOMALY"
            entry["detections"].append(detection)

        communications = sorted(communication_map.values(), key=lambda item: item["communicated_at"])[-5:]
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
        details = []
        for rule_id, rule_name in evidence_keys.items():
            rule = rules.get(rule_id, {})
            columns = rule.get("columns", [])
            column_values = {
                column: {
                    "observed": snapshot.get(column),
                    "normal": self._normal_reference(column, snapshot, previous_snapshot),
                    "abnormal_percent": self._metric_percent(column, snapshot, previous_snapshot),
                    "previous_observed": (previous_snapshot or {}).get(column),
                }
                for column in columns
                if column in snapshot
            }
            details.append(
                {
                    "rule_id": rule_id,
                    "name": rule_name,
                    "first_triggered_at": detection.get("detect_time"),
                    "subsystems": rule.get("subsystems", []),
                    "columns": column_values,
                    "contributes_to": rule.get("contributes_to", {}),
                    "single_sufficient": rule.get("single_sufficient", False),
                    "activation": rule.get("activation", {}),
                }
            )
        return details

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
    def _normal_reference(
        column: str,
        snapshot: dict[str, Any],
        previous_snapshot: dict[str, Any] | None = None,
    ) -> Any:
        if previous_snapshot is not None and column in previous_snapshot:
            return previous_snapshot.get(column)
        if column in {"OBC_P_HASH", "EXPECTED_CRC"}:
            return snapshot.get("EXPECTED_CRC", "expected hash")
        if column.startswith("CH") and "CRC" in column:
            return 0
        if "ERR" in column or "FAULT" in column or "REJECTED" in column:
            return 0
        if "UTILCPUAVG" == column:
            return "<= 80.0"
        return "baseline mean"

    @staticmethod
    def _metric_percent(
        column: str,
        snapshot: dict[str, Any],
        previous_snapshot: dict[str, Any] | None = None,
    ) -> float | None:
        if previous_snapshot is not None:
            step_value = compute_step_change_percent(column, snapshot, previous_snapshot)
            if step_value is not None:
                return step_value
        return DashboardService._abnormal_percent(column, snapshot)

    @staticmethod
    def _abnormal_percent(column: str, snapshot: dict[str, Any]) -> float | None:
        value = snapshot.get(column)
        if not isinstance(value, (int, float)):
            if value is None:
                return None
            observed = str(value).strip()
            expected = str(DashboardService._normal_reference(column, snapshot)).strip()
            if observed == expected:
                return 0.0
            if column == "OBC_P_HASH":
                crc = snapshot.get("EXPECTED_CRC")
                if crc is not None and observed == str(crc).strip():
                    return 0.0
            return None
        if column == "UTILCPUAVG":
            return round(max(0.0, value - 80.0), 2)
        if value == 0:
            return 0.0
        return round(min(abs(float(value)) * 10.0, 100.0), 2)


def _load_realistic_dataset() -> dict[str, Any]:
    """Load the realistic satellite communication test dataset."""
    try:
        with DATASET_PATH.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return {}


def _baseline_history() -> list[dict[str, Any]]:
    """Return baseline history rows from dataset, with fallback records."""
    dataset = _load_realistic_dataset()
    baseline = dataset.get("baseline_history", [])
    if isinstance(baseline, list) and baseline:
        return [deepcopy(row) for row in baseline if isinstance(row, dict)]
    normal = _normal_record()
    return [deepcopy(normal) for _ in range(6)]


def _normal_record() -> dict[str, Any]:
    """Return one representative normal telemetry row."""
    dataset = _load_realistic_dataset()
    baseline = dataset.get("baseline_history", [])
    if isinstance(baseline, list) and baseline and isinstance(baseline[0], dict):
        return deepcopy(baseline[0])
    return {
        "UPDATED_AT": "2026-05-11T06:00:00+00:00",
        "MISSION_MODE": 2,
        "ADCS_MODE": 1,
        "IS_ANOMALY": False,
        "OBC_P_HASH": "OK",
        "EXPECTED_CRC": "OK",
        "APPCSERRCOUNTER": 0,
        "OSCSERRCOUNTER": 0,
        "LASTVALCRC": 100,
        "PROCESSOR_RESET_COUNT": 0,
        "OBC_S_TICK": 1000,
        "CH1_FAULT_CRC": 0,
        "CH2_FAULT_CRC": 0,
        "CH1_FAULT_FILE_SIZE_MISMATCH": 0,
        "CHILDQUEUECOUNT": 1,
        "FILEWRITEERRCOUNTER": 0,
        "CMDREJECTEDCOUNTER": 0,
        "PIPEOVERFLOWRRCNT": 0,
        "COMBINEDPACKETSSENT": 100,
        "HEAP_FREE": 1000,
        "MEMINUSE": 200,
        "EXECOUNTS": 10,
        "UTILCPUAVG": 20.0,
        "SKIPPEDSLOTSCOUNT": 0,
        "ERLOGENTRIES": 0,
        "DWELL_MASK": 0,
        "DWELL_ADDR_COUNT": 0,
        "DWELL_BYTE_COUNT": 0,
        "ENABLEDROUTES": 1,
        "FORWARD_ERR_COUNT": 0,
        "QERR_0": 0.0,
        "QERR_1": 0.0,
        "QERR_2": 0.0,
        "QERR_3": 0.0,
        "TCMD_X": 0.0,
        "TCMD_Y": 0.0,
        "TCMD_Z": 0.0,
        "MOMENTUM_NMS_0": 0.0,
        "MOMENTUM_NMS_1": 0.0,
        "MOMENTUM_NMS_2": 0.0,
        "DEVICE_ERR_RW0": 0,
        "DEVICE_ERR_RW1": 0,
        "DEVICE_ERR_RW2": 0,
        "BATT_VOLTAGE": 7.4,
        "BUS_3P3V": 3.3,
        "BUS_5P0V": 5.0,
        "BUS_12V": 12.0,
        "SW_0_CURRENT": 0.2,
        "SW_1_CURRENT": 0.2,
        "SW_2_CURRENT": 0.2,
        "IMU_WBN_VARIANCE": 0.01,
        "RAW_MAG_VARIANCE": 0.01,
        "ST_VALID": 1,
        "IS_SENT": 1,
    }


def _seed_packets() -> list[dict[str, Any]]:
    """Return representative satellite packets from dataset, with fallback packets."""
    dataset = _load_realistic_dataset()
    packets_from_dataset = dataset.get("packets", [])
    if isinstance(packets_from_dataset, list) and packets_from_dataset:
        return [deepcopy(packet) for packet in packets_from_dataset if isinstance(packet, dict)]

    normal = _normal_record()
    packets = []
    for idx in range(2):
        packet = deepcopy(normal)
        packet["UPDATED_AT"] = f"2026-05-11T06:0{idx + 1}:00+00:00"
        packets.append(
            {
                "event_id": idx + 1,
                "detected_at": packet["UPDATED_AT"],
                "false_positive_result": "N",
                "false_positive_weight": 12.0,
                "false_positive_exception": "",
                "target_subsystem": "",
                "sw_id_list": [],
                "telemetry": packet,
            }
        )

    anomaly_one = deepcopy(normal)
    anomaly_one.update(
        {
            "UPDATED_AT": "2026-05-11T06:03:00+00:00",
            "OBC_P_HASH": "TAMPERED",
            "APPCSERRCOUNTER": 5,
            "LASTVALCRC": 101,
            "CH1_FAULT_CRC": 1,
            "HEAP_FREE": 300,
            "UTILCPUAVG": 95.0,
        }
    )
    packets.append(
        {
            "event_id": 42,
            "detected_at": anomaly_one["UPDATED_AT"],
            "false_positive_result": "Y",
            "false_positive_weight": 88.5,
            "false_positive_exception": "",
            "target_subsystem": "OBC",
            "sw_id_list": [0, 1],
            "telemetry": anomaly_one,
        }
    )

    anomaly_two = deepcopy(normal)
    anomaly_two.update(
        {
            "UPDATED_AT": "2026-05-11T06:04:00+00:00",
            "IMU_WBN_VARIANCE": 0.0001,
            "RAW_MAG_VARIANCE": 0.0001,
            "BUS_3P3V": 4.1,
            "BUS_5P0V": 5.9,
            "FORWARD_ERR_COUNT": 8,
            "CH1_FAULT_CRC": 0,
            "CH2_FAULT_CRC": 0,
        }
    )
    packets.append(
        {
            "event_id": 43,
            "detected_at": anomaly_two["UPDATED_AT"],
            "false_positive_result": "Y",
            "false_positive_weight": 76.0,
            "false_positive_exception": "GHOST_TELEMETRY_PATTERN",
            "target_subsystem": "ADCS",
            "sw_id_list": [0, 2],
            "telemetry": anomaly_two,
        }
    )
    return packets
