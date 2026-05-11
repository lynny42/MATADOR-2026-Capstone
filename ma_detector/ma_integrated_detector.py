"""Ground-station MA integrated detection code generator."""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ma_detector.core.baseline import BaselineManager
from ma_detector.core.evidence_rules import EvidenceRules
from ma_detector.registry.registry_manager import RegistryManager

logger = logging.getLogger(__name__)


@dataclass
class _ActionAccumulator:
    action_id: str
    accumulated_score: float = 0.0
    max_possible_score: float = 0.0
    triggered_rules: list[str] = field(default_factory=list)
    detected_phases: list[int] = field(default_factory=list)
    timestamps: list[float] = field(default_factory=list)


@dataclass
class _PendingCandidate:
    action_id: str
    module: str
    confidence: float
    triggered_rules: list[str]
    timestamp: float = field(default_factory=time.time)


class MAIntegratedDetector:
    """M-A integrated detection pipeline for ground-station telemetry."""

    def __init__(self, config_dir: str | None = None) -> None:
        try:
            self._registry_manager = RegistryManager(config_dir)
            (
                self._action_registry,
                self._rule_registry,
                self._threshold_config,
            ) = self._registry_manager.load_all()

            self._baseline_manager = BaselineManager()
            self._evidence_rules = EvidenceRules(self._baseline_manager, self._threshold_config)

            self._is_replay_mode = False
            self._pending_pool: list[_PendingCandidate] = []
            self._known_patterns: set[str] = set()
            self._replay_buffer: list[dict[str, Any]] = []
            self._telemetry_window: list[dict[str, Any]] = []
            self._window_size_sec = 600

            self._gs_tlm_history: list[dict[str, Any]] = []
            self._gs_pwr_meta: list[dict[str, Any]] = []
            self._dashboard_rows: list[dict[str, Any]] = []
            self._detail_rows: list[dict[str, Any]] = []
            self._discard_log: list[dict[str, Any]] = []
            self._next_detect_id = 1
        except Exception as error:
            logger.error("MA integrated detector initialization failed: %s", error)
            self._action_registry = {}
            self._rule_registry = {}
            self._threshold_config = {}
            self._baseline_manager = BaselineManager()
            self._evidence_rules = EvidenceRules(self._baseline_manager, {})
            self._is_replay_mode = False
            self._pending_pool = []
            self._known_patterns = set()
            self._replay_buffer = []
            self._telemetry_window = []
            self._window_size_sec = 600
            self._gs_tlm_history = []
            self._gs_pwr_meta = []
            self._dashboard_rows = []
            self._detail_rows = []
            self._discard_log = []
            self._next_detect_id = 1

    def build_baseline(self, history: list[dict[str, Any]]) -> None:
        """Build normal-operation baseline statistics from history records."""
        try:
            normalized_history = [
                self._normalize_packet(record)
                for record in history
                if isinstance(record, dict)
            ]
            self._baseline_manager.build_from_history(normalized_history)
        except TypeError as error:
            logger.error("build baseline failed: %s", error)
        except Exception as error:
            logger.error("unexpected build baseline failure: %s", error)

    def set_replay_mode(self, enabled: bool) -> None:
        """Enable or disable replay mode for rule/threshold experiments."""
        try:
            self._is_replay_mode = bool(enabled)
            if not self._is_replay_mode:
                self._replay_buffer.clear()
        except Exception as error:
            logger.error("set replay mode failed: %s", error)

    def reload_config(self) -> None:
        """Reload JSON registries and rebuild evidence-rule functions."""
        try:
            (
                self._action_registry,
                self._rule_registry,
                self._threshold_config,
            ) = self._registry_manager.load_all()
            self._evidence_rules = EvidenceRules(self._baseline_manager, self._threshold_config)
        except Exception as error:
            logger.error("reload config failed: %s", error)

    def get_replay_buffer(self) -> list[dict[str, Any]]:
        """Return replay results accumulated while replay mode is enabled."""
        try:
            return list(self._replay_buffer)
        except Exception as error:
            logger.error("get replay buffer failed: %s", error)
            return []

    def get_dashboard_records(self) -> list[dict[str, Any]]:
        """Return persisted MA dashboard rows."""
        try:
            return [dict(row) for row in self._dashboard_rows]
        except Exception as error:
            logger.error("get dashboard records failed: %s", error)
            return []

    def get_history_records(self) -> list[dict[str, Any]]:
        """Return ground-station telemetry history rows."""
        try:
            return [dict(row) for row in self._gs_tlm_history]
        except Exception as error:
            logger.error("get history records failed: %s", error)
            return []

    def get_discard_records(self) -> list[dict[str, Any]]:
        """Return discarded detection reports."""
        try:
            return [dict(row) for row in self._discard_log]
        except Exception as error:
            logger.error("get discard records failed: %s", error)
            return []

    def get_rule_registry(self) -> dict[str, Any]:
        """Return the active rule registry."""
        try:
            return dict(self._rule_registry)
        except Exception as error:
            logger.error("get rule registry failed: %s", error)
            return {}

    def get_action_registry(self) -> dict[str, Any]:
        """Return the active action registry."""
        try:
            return dict(self._action_registry)
        except Exception as error:
            logger.error("get action registry failed: %s", error)
            return {}

    def get_threshold_config(self) -> dict[str, Any]:
        """Return the active threshold configuration."""
        try:
            return dict(self._threshold_config)
        except Exception as error:
            logger.error("get threshold config failed: %s", error)
            return {}

    def receive_telemetry(self, json_token: str) -> None:
        """Parse satellite JSON and execute the MA detection pipeline for attack-like events."""
        try:
            packet = json.loads(json_token)
            if not isinstance(packet, dict):
                logger.error("received telemetry must be a JSON object")
                return
        except json.JSONDecodeError as error:
            logger.error("receive telemetry JSON parse failed: %s", error)
            return
        except TypeError as error:
            logger.error("receive telemetry input type failed: %s", error)
            return
        except Exception as error:
            logger.error("unexpected receive telemetry failure: %s", error)
            return

        try:
            packet = self._normalize_packet(packet)
            if self._is_replay_mode:
                self._telemetry_window.append(packet)
                self._trim_window()
                self._run_pipeline()
                return

            self._insert_gs_tables(packet)
            if not packet.get("IS_ANOMALY", False):
                self._notify_ui_normal(packet)
                return

            self._telemetry_window.append(packet)
            self._trim_window()
            self._run_pipeline()
        except Exception as error:
            logger.error("receive telemetry pipeline failed: %s", error)

    def evaluate_parallel_rules(self, snapshot: str) -> str:
        """Evaluate all enabled rules independently and return rule/action scores as JSON."""
        try:
            window = json.loads(snapshot)
            if isinstance(window, dict):
                window = [window]
            if not isinstance(window, list):
                logger.error("rule snapshot must decode to a list or object")
                return json.dumps({"rule_results": [], "accumulators": {}, "corroboration": {}, "phase_hits": []})
        except json.JSONDecodeError as error:
            logger.error("evaluate rules JSON parse failed: %s", error)
            return json.dumps({"rule_results": [], "accumulators": {}, "corroboration": {}, "phase_hits": []})
        except TypeError as error:
            logger.error("evaluate rules input type failed: %s", error)
            return json.dumps({"rule_results": [], "accumulators": {}, "corroboration": {}, "phase_hits": []})
        except Exception as error:
            logger.error("unexpected evaluate rules failure: %s", error)
            return json.dumps({"rule_results": [], "accumulators": {}, "corroboration": {}, "phase_hits": []})

        try:
            typed_window = [record for record in window if isinstance(record, dict)]
            accumulators = {
                action_id: _ActionAccumulator(action_id=action_id)
                for action_id in self._action_registry
            }
            rule_results: list[dict[str, Any]] = []
            phase_hits: list[dict[str, Any]] = []

            for rule_id, rule_def in self._rule_registry.items():
                if not rule_def.get("enabled", True):
                    continue

                rule_score = self._evidence_rules.evaluate(rule_id, typed_window)
                if rule_score <= 0.0:
                    continue

                latest = typed_window[-1] if typed_window else {}
                timestamp = self._timestamp_to_epoch(latest.get("UPDATED_AT", time.time()))

                for action_id, base_score in rule_def.get("contributes_to", {}).items():
                    action_def = self._action_registry.get(action_id)
                    if action_def is None:
                        continue

                    phase = int(action_def.get("phase", 0))
                    action_weight = float(action_def.get("weight", 1.0))
                    weighted_base = float(base_score) + 0.3 * phase
                    contribution = weighted_base * rule_score * action_weight
                    max_possible = (1.0 + 0.3 * phase) * action_weight

                    accumulator = accumulators[action_id]
                    accumulator.accumulated_score += contribution
                    accumulator.max_possible_score += max_possible
                    if rule_id not in accumulator.triggered_rules:
                        accumulator.triggered_rules.append(rule_id)
                    if phase not in accumulator.detected_phases:
                        accumulator.detected_phases.append(phase)
                    accumulator.timestamps.append(timestamp)
                    phase_hits.append(
                        {
                            "phase": phase,
                            "timestamp": timestamp,
                            "action_id": action_id,
                            "rule_id": rule_id,
                        }
                    )

                rule_results.append(
                    {
                        "rule_id": rule_id,
                        "score": round(rule_score, 4),
                        "name": rule_def.get("name", ""),
                        "subsystems": rule_def.get("subsystems", []),
                        "contributes_to": rule_def.get("contributes_to", {}),
                        "triggered": True,
                        "single_sufficient": bool(rule_def.get("single_sufficient", False)),
                        "evidence": {
                            column: latest.get(column)
                            for column in rule_def.get("columns", [])
                            if column in latest
                        },
                    }
                )

            corroboration: dict[tuple[str, str], int] = defaultdict(int)
            for result in rule_results:
                for action_id in result.get("contributes_to", {}):
                    action_def = self._action_registry.get(action_id)
                    if action_def is None:
                        continue
                    corroboration[(str(action_def.get("module", "UNKNOWN")), action_id)] += 1

            output = {
                "rule_results": rule_results,
                "accumulators": {
                    action_id: {
                        "accumulated_score": round(accumulator.accumulated_score, 6),
                        "max_possible_score": round(accumulator.max_possible_score, 6),
                        "triggered_rules": accumulator.triggered_rules,
                        "detected_phases": accumulator.detected_phases,
                        "timestamps": accumulator.timestamps,
                    }
                    for action_id, accumulator in accumulators.items()
                },
                "corroboration": {
                    f"{module}::{action_id}": count
                    for (module, action_id), count in corroboration.items()
                },
                "phase_hits": phase_hits,
            }
            return json.dumps(output, ensure_ascii=False, default=str)
        except (TypeError, ValueError) as error:
            logger.error("rule scoring failed: %s", error)
            return json.dumps({"rule_results": [], "accumulators": {}, "corroboration": {}, "phase_hits": []})
        except Exception as error:
            logger.error("unexpected rule scoring failure: %s", error)
            return json.dumps({"rule_results": [], "accumulators": {}, "corroboration": {}, "phase_hits": []})

    def verify_attack_sequence(self, results_json: str) -> float:
        """Verify phase sequence evidence and return a confidence adjustment in percentage points."""
        try:
            data = json.loads(results_json)
        except json.JSONDecodeError as error:
            logger.error("verify sequence JSON parse failed: %s", error)
            return 0.0
        except TypeError as error:
            logger.error("verify sequence input type failed: %s", error)
            return 0.0
        except Exception as error:
            logger.error("unexpected verify sequence failure: %s", error)
            return 0.0

        try:
            sequence_config = self._threshold_config.get("sequence", {})
            phase_hits = data.get("phase_hits", [])
            if not phase_hits:
                return 0.0

            ordered_phases = [
                int(hit.get("phase", 0))
                for hit in sorted(phase_hits, key=lambda item: float(item.get("timestamp", 0.0)))
                if int(hit.get("phase", 0)) > 0
            ]
            unique_ordered = list(dict.fromkeys(ordered_phases))
            adjustment = 0.0

            full_sequence = (
                all(phase in unique_ordered for phase in [1, 2, 3])
                and unique_ordered.index(1) < unique_ordered.index(2) < unique_ordered.index(3)
            )
            if full_sequence:
                adjustment += float(sequence_config.get("FULL_MATCH_BONUS", 15.0))
            elif 1 in unique_ordered and 3 in unique_ordered and unique_ordered.index(1) < unique_ordered.index(3):
                adjustment += float(sequence_config.get("PARTIAL_MATCH_BONUS", 5.0))

            latest = self._telemetry_window[-1] if self._telemetry_window else {}
            no_reset_hash = (
                latest.get("OBC_P_HASH") != latest.get("EXPECTED_CRC")
                and latest.get("PROCESSOR_RESET_COUNT")
                == self._baseline_manager.get_stats(latest, "PROCESSOR_RESET_COUNT").mean
            )
            if no_reset_hash:
                adjustment += float(sequence_config.get("NO_RESET_HASH_BONUS", 10.0))

            if len(set(ordered_phases)) == 1 and len(ordered_phases) == 1:
                adjustment += float(sequence_config.get("RANDOM_PENALTY", -10.0))

            return adjustment
        except (TypeError, ValueError, KeyError) as error:
            logger.error("sequence verification failed: %s", error)
            return 0.0
        except Exception as error:
            logger.error("unexpected sequence verification failure: %s", error)
            return 0.0

    def generate_ma_code(self, final_scores: str) -> str:
        """Generate MA codes by confidence, corroboration, and phase-sequence evidence."""
        try:
            data = json.loads(final_scores)
        except json.JSONDecodeError as error:
            logger.error("generate MA code JSON parse failed: %s", error)
            return json.dumps([], ensure_ascii=False)
        except TypeError as error:
            logger.error("generate MA code input type failed: %s", error)
            return json.dumps([], ensure_ascii=False)
        except Exception as error:
            logger.error("unexpected generate MA code failure: %s", error)
            return json.dumps([], ensure_ascii=False)

        try:
            confidence_config = self._threshold_config.get("confidence", {})
            corroboration_config = self._threshold_config.get("corroboration", {})
            confirmed_threshold = float(confidence_config.get("CONFIRMED_THRESHOLD", 70.0))
            suspected_threshold = float(confidence_config.get("SUSPECTED_THRESHOLD", 40.0))
            confirmed_min = int(corroboration_config.get("CONFIRMED_MIN", 2))
            sequence_adjustment = float(data.get("sequence_adjustment", 0.0))

            results: list[dict[str, Any]] = []
            pending_entries: list[dict[str, Any]] = []
            discarded_entries: list[dict[str, Any]] = []
            any_anomaly = False

            for action_id, accumulator in data.get("accumulators", {}).items():
                accumulated_score = float(accumulator.get("accumulated_score", 0.0))
                max_possible_score = float(accumulator.get("max_possible_score", 0.0))
                if accumulated_score <= 0.0 or max_possible_score <= 0.0:
                    continue

                any_anomaly = True
                action_def = self._action_registry.get(action_id, {})
                module = str(action_def.get("module", "UNKNOWN"))
                phase = int(action_def.get("phase", 0))
                action_name = str(action_def.get("name", "UNKNOWN"))
                triggered_rules = list(accumulator.get("triggered_rules", []))

                raw_confidence = accumulated_score / max_possible_score * 100.0
                confidence = round(max(0.0, min(raw_confidence + sequence_adjustment, 100.0)), 2)
                corroboration_count = int(data.get("corroboration", {}).get(f"{module}::{action_id}", 0))
                single_sufficient = any(
                    self._rule_registry.get(rule_id, {}).get("single_sufficient", False)
                    for rule_id in triggered_rules
                )
                grade = self._classify_grade(
                    confidence,
                    corroboration_count,
                    single_sufficient,
                    confirmed_threshold,
                    suspected_threshold,
                    confirmed_min,
                )
                ma_code = f"{module}_{action_name}_P{phase}"
                entry = {
                    "ma_code": ma_code,
                    "action_id": action_id,
                    "action_name": action_name,
                    "module": module,
                    "scenario_phase": phase,
                    "confidence_score": confidence,
                    "grade": grade,
                    "corroboration_count": corroboration_count,
                    "evidence_keys": {
                        rule_id: self._rule_registry.get(rule_id, {}).get("name", "")
                        for rule_id in triggered_rules
                    },
                    "is_new_pattern": ma_code not in self._known_patterns,
                    "triggered_rules": triggered_rules,
                }

                if grade in ("CONFIRMED", "SUSPECTED"):
                    results.append(entry)
                    self._known_patterns.add(ma_code)
                elif grade == "PENDING":
                    pending_entries.append(entry)
                    self._pending_pool.append(
                        _PendingCandidate(
                            action_id=action_id,
                            module=module,
                            confidence=confidence,
                            triggered_rules=triggered_rules,
                        )
                    )
                else:
                    discarded_entries.append(entry)

            results.extend(self._flush_pending_pool())
            if not results:
                results.extend(discarded_entries)
            if any_anomaly and not results:
                results.append(self._unknown_pattern_entry())

            if any_anomaly and not any(result["grade"] in ("CONFIRMED", "SUSPECTED") for result in results):
                results.append(self._unknown_pattern_entry())

            results.sort(key=lambda item: item["confidence_score"], reverse=True)
            return json.dumps(results, ensure_ascii=False, default=str)
        except (TypeError, ValueError, KeyError) as error:
            logger.error("MA code generation failed: %s", error)
            return json.dumps([], ensure_ascii=False)
        except Exception as error:
            logger.error("unexpected MA code generation failure: %s", error)
            return json.dumps([], ensure_ascii=False)

    def insert_dashboard_db(self, report_json: str) -> None:
        """Store generated reports in dashboard/detail memory tables or replay buffer."""
        try:
            reports = json.loads(report_json)
            if not isinstance(reports, list):
                logger.error("dashboard report must be a JSON list")
                return
        except json.JSONDecodeError as error:
            logger.error("insert dashboard JSON parse failed: %s", error)
            return
        except TypeError as error:
            logger.error("insert dashboard input type failed: %s", error)
            return
        except Exception as error:
            logger.error("unexpected insert dashboard failure: %s", error)
            return

        try:
            for report in reports:
                if not isinstance(report, dict):
                    continue
                grade = report.get("grade", "DISCARDED")
                if self._is_replay_mode:
                    self._replay_buffer.append(
                        {
                            "target": "DASHBOARD" if grade in ("CONFIRMED", "SUSPECTED") else "DISCARD_LOG",
                            "data": report,
                        }
                    )
                    if report.get("is_new_pattern"):
                        self._replay_buffer.append({"target": "DB_UPDATE_FLAG", "data": {"ma_code": report["ma_code"]}})
                    continue

                if grade in ("CONFIRMED", "SUSPECTED"):
                    self._db_insert_dashboard(report)
                    if report.get("is_new_pattern"):
                        self._db_set_new_pattern_flag(report)
                else:
                    self._db_insert_discard_log(report)
        except Exception as error:
            logger.error("dashboard insert failed: %s", error)

    def get_ui_data(self, detect_id: int) -> str:
        """Return dashboard rendering data for one detection ID."""
        try:
            dashboard_row = self._db_query_dashboard(int(detect_id))
            if not dashboard_row:
                return json.dumps({"error": f"detect_id {detect_id} not found"}, ensure_ascii=False)

            dashboard_id = int(dashboard_row.get("DASHBOARD_ID", detect_id))
            detail_rows = self._db_query_detail(dashboard_id)
            history_rows = self._db_query_history(str(dashboard_row.get("DETECT_TIME", "")))
            result = {
                "detect_time": dashboard_row.get("DETECT_TIME"),
                "module": dashboard_row.get("MODULE"),
                "action": dashboard_row.get("ACTION"),
                "scenario_phase": dashboard_row.get("SCENARIO_PHASE"),
                "ma_code": dashboard_row.get("MA_CODE"),
                "confidence_score": dashboard_row.get("CONFIDENCE_SCORE"),
                "grade": dashboard_row.get("GRADE"),
                "corroboration_count": dashboard_row.get("CORROBORATION_COUNT"),
                "evidence_keys": dashboard_row.get("EVIDENCE_KEYS", {}),
                "is_new_pattern": dashboard_row.get("IS_NEW_PATTERN"),
                "satellite_filter": {
                    "result": dashboard_row.get("FALSE_POSITIVE_RESULT"),
                    "weight": dashboard_row.get("FALSE_POSITIVE_WEIGHT"),
                    "exception": dashboard_row.get("FALSE_POSITIVE_EXCEPTION"),
                    "target_subsystem": dashboard_row.get("TARGET_SUBSYSTEM"),
                    "event_id": dashboard_row.get("EVENT_ID"),
                    "sw_id_list": dashboard_row.get("SW_ID_LIST", []),
                    "detected_at": dashboard_row.get("SATELLITE_DETECTED_AT"),
                },
                "detail": {
                    "imu": [row.get("IMU_WBN_X") for row in detail_rows],
                    "mag": [row.get("RAW_MAG_X") for row in detail_rows],
                    "qerr": [row.get("QERR_0") for row in detail_rows],
                    "momentum": [row.get("MOMENTUM_NMS_0") for row in detail_rows],
                    "history": history_rows,
                },
            }
            return json.dumps(result, ensure_ascii=False, default=str)
        except (TypeError, ValueError) as error:
            logger.error("get UI data failed: %s", error)
            return json.dumps({"error": str(error)}, ensure_ascii=False)
        except Exception as error:
            logger.error("unexpected get UI data failure: %s", error)
            return json.dumps({"error": str(error)}, ensure_ascii=False)

    def _run_pipeline(self) -> None:
        try:
            snapshot_json = json.dumps(self._telemetry_window, ensure_ascii=False, default=str)
            rule_result_json = self.evaluate_parallel_rules(snapshot_json)
            confidence = self.verify_attack_sequence(rule_result_json)
            final_input = self._build_final_input(rule_result_json, confidence)
            report_json = self.generate_ma_code(final_input)
            self.insert_dashboard_db(report_json)
        except Exception as error:
            logger.error("pipeline execution failed: %s", error)

    def _normalize_packet(self, packet: dict[str, Any]) -> dict[str, Any]:
        try:
            normalized = self._merge_packet_sections(packet)
            normalized.setdefault("UPDATED_AT", datetime.now(timezone.utc).isoformat())
            normalized.setdefault("DETECTED_AT", normalized["UPDATED_AT"])
            self._normalize_filter_fields(normalized)
            return normalized
        except Exception as error:
            logger.error("packet normalization failed: %s", error)
            return packet

    def _merge_packet_sections(self, packet: dict[str, Any]) -> dict[str, Any]:
        try:
            normalized = dict(packet)
            section_keys = [
                "telemetry",
                "tlm",
                "power",
                "pwr_meta",
                "adcs",
                "system",
                "integrity",
                "event",
                "counters",
                "evidence",
                "ma_payload",
                "SAT_TLM_CURRENT",
                "SAT_PWR_META",
                "SAT_ADCS_FILTER",
                "SAT_EVENT_QUEUE",
                "SAT_INTEGRITY_HASH",
                "GS_TLM_HISTORY",
                "GS_PWR_META",
            ]
            for section_key in section_keys:
                section = packet.get(section_key)
                if isinstance(section, dict):
                    normalized.update(section)
            return normalized
        except TypeError as error:
            logger.error("packet section merge failed: %s", error)
            return dict(packet)
        except Exception as error:
            logger.error("unexpected packet section merge failure: %s", error)
            return dict(packet)

    def _normalize_filter_fields(self, normalized: dict[str, Any]) -> None:
        try:
            result = self._first_present(
                normalized,
                [
                    "false_positive_result",
                    "FALSE_POSITIVE_RESULT",
                    "filter_result",
                    "FILTER_RESULT",
                    "filter_decision",
                    "FILTER_DECISION",
                    "decision",
                    "DECISION",
                ],
            )
            weight = self._first_present(
                normalized,
                [
                    "false_positive_weight",
                    "FALSE_POSITIVE_WEIGHT",
                    "filter_weight",
                    "FILTER_WEIGHT",
                    "weight",
                    "WEIGHT",
                ],
            )
            exception = self._first_present(
                normalized,
                [
                    "false_positive_exception",
                    "FALSE_POSITIVE_EXCEPTION",
                    "filter_exception",
                    "FILTER_EXCEPTION",
                    "exception",
                    "EXCEPTION",
                ],
            )
            target_subsystem = self._first_present(
                normalized,
                [
                    "target_subsystem",
                    "TARGET_SUBSYSTEM",
                    "subsystem",
                    "SUBSYSTEM",
                    "attack_subsystem",
                    "ATTACK_SUBSYSTEM",
                ],
            )
            event_id = self._first_present(normalized, ["event_id", "EVENT_ID"])
            sw_id_list = self._first_present(normalized, ["sw_id_list", "SW_ID_LIST"])
            detected_at = self._first_present(normalized, ["detected_at", "DETECTED_AT"])

            if result is not None:
                normalized["FALSE_POSITIVE_RESULT"] = result
                normalized["FILTER_DECISION"] = result
                normalized["IS_ANOMALY"] = self._is_attack_decision(result)
            else:
                normalized.setdefault("FALSE_POSITIVE_RESULT", "Y" if normalized.get("IS_ANOMALY") else "N")
                normalized.setdefault("FILTER_DECISION", normalized["FALSE_POSITIVE_RESULT"])

            if weight is not None:
                normalized["FALSE_POSITIVE_WEIGHT"] = weight
                normalized["FILTER_WEIGHT"] = weight
            if exception is not None:
                normalized["FALSE_POSITIVE_EXCEPTION"] = exception
                normalized["FILTER_EXCEPTION"] = exception
            else:
                normalized.setdefault("FALSE_POSITIVE_EXCEPTION", "")
                normalized.setdefault("FILTER_EXCEPTION", normalized["FALSE_POSITIVE_EXCEPTION"])
            if target_subsystem is not None:
                normalized["TARGET_SUBSYSTEM"] = target_subsystem
            if event_id is not None:
                normalized["EVENT_ID"] = event_id
            if sw_id_list is not None:
                normalized["SW_ID_LIST"] = sw_id_list if isinstance(sw_id_list, list) else [sw_id_list]
            if detected_at is not None:
                normalized["DETECTED_AT"] = detected_at
                normalized.setdefault("UPDATED_AT", detected_at)
        except Exception as error:
            logger.error("filter field normalization failed: %s", error)

    @staticmethod
    def _first_present(packet: dict[str, Any], keys: list[str]) -> Any:
        try:
            for key in keys:
                if key in packet:
                    return packet[key]
            return None
        except Exception as error:
            logger.error("first present lookup failed: %s", error)
            return None

    @staticmethod
    def _is_attack_decision(value: Any) -> bool:
        try:
            if isinstance(value, bool):
                return value
            if isinstance(value, (int, float)):
                return value > 0
            normalized = str(value).strip().upper()
            return normalized in {"Y", "YES", "TRUE", "ATTACK", "ATTACK_CONFIRMED", "1"}
        except Exception as error:
            logger.error("attack decision normalization failed: %s", error)
            return False

    def _trim_window(self) -> None:
        try:
            if len(self._telemetry_window) <= 1:
                return
            latest_epoch = self._timestamp_to_epoch(self._telemetry_window[-1].get("UPDATED_AT", time.time()))
            cutoff = latest_epoch - self._window_size_sec
            self._telemetry_window = [
                snapshot
                for snapshot in self._telemetry_window
                if self._timestamp_to_epoch(snapshot.get("UPDATED_AT", latest_epoch)) >= cutoff
            ]
        except Exception as error:
            logger.error("telemetry window trim failed: %s", error)

    def _build_final_input(self, rule_result_json: str, sequence_adjustment: float) -> str:
        try:
            data = json.loads(rule_result_json)
            data["sequence_adjustment"] = sequence_adjustment
            return json.dumps(data, ensure_ascii=False, default=str)
        except json.JSONDecodeError as error:
            logger.error("final input JSON parse failed: %s", error)
            return json.dumps({"sequence_adjustment": sequence_adjustment}, ensure_ascii=False)
        except Exception as error:
            logger.error("final input build failed: %s", error)
            return json.dumps({"sequence_adjustment": sequence_adjustment}, ensure_ascii=False)

    @staticmethod
    def _classify_grade(
        confidence: float,
        corroboration_count: int,
        single_sufficient: bool,
        confirmed_threshold: float,
        suspected_threshold: float,
        confirmed_min_corr: int,
    ) -> str:
        try:
            if confidence >= confirmed_threshold:
                if corroboration_count >= confirmed_min_corr:
                    return "CONFIRMED"
                return "CONFIRMED" if single_sufficient else "SUSPECTED"
            if confidence >= suspected_threshold:
                return "SUSPECTED" if corroboration_count >= 2 else "PENDING"
            return "DISCARDED"
        except Exception as error:
            logger.error("grade classification failed: %s", error)
            return "DISCARDED"

    def _flush_pending_pool(self) -> list[dict[str, Any]]:
        try:
            config = self._threshold_config.get("pending_pool", {})
            cutoff = time.time() - float(config.get("TIME_WINDOW_SEC", 300))
            recent = [candidate for candidate in self._pending_pool if candidate.timestamp >= cutoff]
            self._pending_pool = recent

            unique_modules = {candidate.module for candidate in recent}
            if len(unique_modules) < int(config.get("UNIQUE_MODULE_MIN", 3)):
                return []

            all_rules = sorted({rule for candidate in recent for rule in candidate.triggered_rules})
            ma_code = "MULTI_UNKNOWN_MULTI_COMPLEX_ATTACK_SUSPECTED_P0"
            self._pending_pool.clear()
            return [
                {
                    "ma_code": ma_code,
                    "action_id": "A000",
                    "action_name": "MULTI_COMPLEX_ATTACK_SUSPECTED",
                    "module": "+".join(sorted(unique_modules)),
                    "scenario_phase": 0,
                    "confidence_score": 35.0,
                    "grade": "SUSPECTED",
                    "corroboration_count": len(all_rules),
                    "evidence_keys": {rule: self._rule_registry.get(rule, {}).get("name", "") for rule in all_rules},
                    "is_new_pattern": ma_code not in self._known_patterns,
                    "triggered_rules": all_rules,
                }
            ]
        except (TypeError, ValueError) as error:
            logger.error("pending pool flush failed: %s", error)
            return []
        except Exception as error:
            logger.error("unexpected pending pool flush failure: %s", error)
            return []

    @staticmethod
    def _unknown_pattern_entry() -> dict[str, Any]:
        return {
            "ma_code": "UNKNOWN_UNKNOWN_P0",
            "action_id": "A000",
            "action_name": "UNKNOWN_PATTERN",
            "module": "UNKNOWN",
            "scenario_phase": 0,
            "confidence_score": 0.0,
            "grade": "UNKNOWN",
            "corroboration_count": 0,
            "evidence_keys": {},
            "is_new_pattern": True,
            "triggered_rules": [],
        }

    @staticmethod
    def _timestamp_to_epoch(value: Any) -> float:
        try:
            if isinstance(value, (int, float)):
                return float(value)
            if isinstance(value, str):
                normalized = value.replace("Z", "+00:00")
                return datetime.fromisoformat(normalized).timestamp()
            return time.time()
        except (TypeError, ValueError) as error:
            logger.error("timestamp conversion failed: %s", error)
            return time.time()
        except Exception as error:
            logger.error("unexpected timestamp conversion failure: %s", error)
            return time.time()

    def _insert_gs_tables(self, packet: dict[str, Any]) -> None:
        try:
            self._gs_tlm_history.append(dict(packet))
            power_columns = {
                key: value
                for key, value in packet.items()
                if key.startswith("SW_") or key.startswith("BUS_") or key == "BATT_VOLTAGE"
            }
            if power_columns:
                power_columns["UPDATED_AT"] = packet.get("UPDATED_AT")
                self._gs_pwr_meta.append(power_columns)
        except Exception as error:
            logger.error("GS table insert failed: %s", error)

    def _notify_ui_normal(self, packet: dict[str, Any]) -> None:
        try:
            logger.info("normal telemetry received at %s", packet.get("UPDATED_AT"))
        except Exception as error:
            logger.error("normal UI notification failed: %s", error)

    def _db_insert_dashboard(self, report: dict[str, Any]) -> None:
        try:
            detect_id = self._next_detect_id
            self._next_detect_id += 1
            latest = self._telemetry_window[-1] if self._telemetry_window else {}
            row = {
                "DETECT_ID": detect_id,
                "DASHBOARD_ID": detect_id,
                "DETECT_TIME": latest.get("UPDATED_AT", datetime.now(timezone.utc).isoformat()),
                "MODULE": report.get("module"),
                "ACTION": report.get("action_name"),
                "SCENARIO_PHASE": report.get("scenario_phase"),
                "MA_CODE": report.get("ma_code"),
                "CONFIDENCE_SCORE": report.get("confidence_score"),
                "GRADE": report.get("grade"),
                "CORROBORATION_COUNT": report.get("corroboration_count"),
                "EVIDENCE_KEYS": report.get("evidence_keys", {}),
                "IS_NEW_PATTERN": report.get("is_new_pattern", False),
                "FALSE_POSITIVE_RESULT": latest.get("FALSE_POSITIVE_RESULT"),
                "FALSE_POSITIVE_WEIGHT": latest.get("FALSE_POSITIVE_WEIGHT"),
                "FALSE_POSITIVE_EXCEPTION": latest.get("FALSE_POSITIVE_EXCEPTION"),
                "TARGET_SUBSYSTEM": latest.get("TARGET_SUBSYSTEM"),
                "EVENT_ID": latest.get("EVENT_ID"),
                "SW_ID_LIST": latest.get("SW_ID_LIST", []),
                "SATELLITE_DETECTED_AT": latest.get("DETECTED_AT"),
            }
            self._dashboard_rows.append(row)
            detail = dict(latest)
            detail["DASHBOARD_ID"] = detect_id
            detail["DETECT_ID"] = detect_id
            detail["MA_CODE"] = report.get("ma_code")
            self._detail_rows.append(detail)
        except Exception as error:
            logger.error("dashboard row insert failed: %s", error)

    def _db_insert_discard_log(self, report: dict[str, Any]) -> None:
        try:
            self._discard_log.append({"logged_at": datetime.now(timezone.utc).isoformat(), "report": dict(report)})
        except Exception as error:
            logger.error("discard log insert failed: %s", error)

    def _db_set_new_pattern_flag(self, report: dict[str, Any]) -> None:
        try:
            self._known_patterns.add(str(report.get("ma_code", "")))
        except Exception as error:
            logger.error("new pattern flag update failed: %s", error)

    def _db_query_dashboard(self, detect_id: int) -> dict[str, Any]:
        try:
            for row in self._dashboard_rows:
                if int(row.get("DETECT_ID", -1)) == detect_id:
                    return dict(row)
            return {}
        except (TypeError, ValueError) as error:
            logger.error("dashboard query failed: %s", error)
            return {}
        except Exception as error:
            logger.error("unexpected dashboard query failure: %s", error)
            return {}

    def _db_query_detail(self, dashboard_id: int) -> list[dict[str, Any]]:
        try:
            return [dict(row) for row in self._detail_rows if int(row.get("DASHBOARD_ID", -1)) == dashboard_id]
        except (TypeError, ValueError) as error:
            logger.error("detail query failed: %s", error)
            return []
        except Exception as error:
            logger.error("unexpected detail query failure: %s", error)
            return []

    def _db_query_history(self, detect_time: str) -> list[dict[str, Any]]:
        try:
            if not detect_time:
                return list(self._gs_tlm_history[-10:])
            target = self._timestamp_to_epoch(detect_time)
            return [
                dict(row)
                for row in self._gs_tlm_history
                if abs(self._timestamp_to_epoch(row.get("UPDATED_AT", target)) - target) <= self._window_size_sec
            ]
        except Exception as error:
            logger.error("history query failed: %s", error)
            return []
