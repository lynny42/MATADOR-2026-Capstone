"""Service layer that adapts MA detector memory tables for the dashboard API."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from ma_detector import MAIntegratedDetector
from ma_detector.core.evidence_rules import EvidenceRules
from ma_detector.registry.registry_manager import RegistryManager

CORE_SUBSYSTEMS = ["OBC", "TCS", "EPS", "ADCS", "COM"]
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


def create_detector_with_seed() -> MAIntegratedDetector:
    """Create a detector instance with representative ground-station data."""
    detector = MAIntegratedDetector()
    normal = _normal_record()
    detector.build_baseline([deepcopy(normal) for _ in range(6)])

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
        self.detector.receive_telemetry(json.dumps(packet, ensure_ascii=False))
        return self.get_dashboard_state()

    def get_dashboard_state(self) -> dict[str, Any]:
        """Return the full dashboard model consumed by the Next.js UI."""
        return self._get_dashboard_state_for_detector(self.detector)

    def _get_dashboard_state_for_detector(self, detector: MAIntegratedDetector) -> dict[str, Any]:
        """Return the dashboard model for a specific detector instance."""
        dashboard_rows = detector.get_dashboard_records()
        history_rows = detector.get_history_records()
        detections = [self._to_detection(row) for row in dashboard_rows]
        communications = self._build_communications(history_rows, detections)
        latest_time = communications[-1]["communicated_at"] if communications else None
        latest_detections = [
            detection
            for detection in detections
            if latest_time is not None and detection["detect_time"] == latest_time
        ]
        selected = detections[-1] if detections else None

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "core_subsystems": CORE_SUBSYSTEMS,
            "communications": communications,
            "latest_communication": {
                "communicated_at": latest_time,
                "status": "ANOMALY" if latest_detections else "NORMAL",
                "anomaly_count": len(latest_detections),
                "detections": latest_detections,
            },
            "recent_threats": self._recent_threats(detections),
            "blueprint": self._build_blueprint(detections),
            "detections": detections,
            "selected_detection": selected,
        }

    def get_detection_detail(self, detect_id: int) -> dict[str, Any]:
        """Return UI-ready detail for one dashboard detection."""
        payload = json.loads(self.detector.get_ui_data(detect_id))
        if "error" in payload:
            return payload

        detail_history = payload.get("detail", {}).get("history", [])
        detection = self._dashboard_detection_by_id(detect_id)
        payload["rule_details"] = self._build_rule_details(
            payload.get("evidence_keys", {}),
            detail_history[0] if detail_history else {},
            detection,
        )
        return payload

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
        """Run replay mode for supplied packets or representative seeded anomalies."""
        replay_packets = packets if packets else _seed_packets()
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
        return {
            "ok": True,
            "temporary": True,
            "dashboard": self._get_dashboard_state_for_detector(detector),
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
        detector._threshold_config = thresholds
        detector._evidence_rules = EvidenceRules(detector._baseline_manager, thresholds)
        normal = _normal_record()
        detector.build_baseline([deepcopy(normal) for _ in range(6)])
        for packet in packets if packets is not None else _seed_packets():
            detector.receive_telemetry(json.dumps(packet, ensure_ascii=False))
        return detector

    def _to_detection(self, row: dict[str, Any]) -> dict[str, Any]:
        module = str(row.get("MODULE", "UNKNOWN"))
        confidence = float(row.get("CONFIDENCE_SCORE", 0.0) or 0.0)
        phase = int(row.get("SCENARIO_PHASE", 0) or 0)
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
            "satellite_filter": {
                "result": row.get("FALSE_POSITIVE_RESULT"),
                "weight": row.get("FALSE_POSITIVE_WEIGHT"),
                "exception": row.get("FALSE_POSITIVE_EXCEPTION"),
                "target_subsystem": row.get("TARGET_SUBSYSTEM"),
                "event_id": row.get("EVENT_ID"),
                "sw_id_list": row.get("SW_ID_LIST", []),
                "detected_at": row.get("SATELLITE_DETECTED_AT"),
            },
            "severity": self._severity(phase, confidence),
        }

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

    def _build_blueprint(self, detections: list[dict[str, Any]]) -> dict[str, Any]:
        recent = self._recent_threats(detections)
        blueprint: dict[str, Any] = {
            subsystem: {"name": subsystem, "detections": [], "severity": "normal"}
            for subsystem in CORE_SUBSYSTEMS
        }
        for detection in recent:
            for subsystem in detection["subsystems"]:
                if subsystem not in blueprint:
                    continue
                blueprint[subsystem]["detections"].append(detection)
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
    ) -> list[dict[str, Any]]:
        rules = self.detector.get_rule_registry()
        details = []
        for rule_id, rule_name in evidence_keys.items():
            rule = rules.get(rule_id, {})
            columns = rule.get("columns", [])
            column_values = {
                column: {
                    "observed": snapshot.get(column),
                    "normal": self._normal_reference(column, snapshot),
                    "abnormal_percent": self._abnormal_percent(column, snapshot),
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
    def _normal_reference(column: str, snapshot: dict[str, Any]) -> Any:
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
    def _abnormal_percent(column: str, snapshot: dict[str, Any]) -> float | None:
        value = snapshot.get(column)
        if not isinstance(value, (int, float)):
            return None
        if column == "UTILCPUAVG":
            return round(max(0.0, value - 80.0), 2)
        if value == 0:
            return 0.0
        return round(min(abs(float(value)) * 10.0, 100.0), 2)


def _normal_record() -> dict[str, Any]:
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
