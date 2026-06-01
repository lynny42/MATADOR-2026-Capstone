"""Ground-station MA integrated detection code generator."""

from __future__ import annotations

import json
import logging
import statistics
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ma_detector.core.baseline import BaselineManager
from ma_detector.core.bulk_history_merge import (
    build_event_queue_row,
    build_ma_reference_packet,
    extract_bulk_event_records,
    find_nearest_history_for_event,
    merge_bulk_telemetry_packet,
    promote_event_reference_fields,
    resolve_event_history_link,
)
from ma_detector.core.evidence_rules import EvidenceRules
from ma_detector.core.packet_protocol import (
    event_is_attack_anomaly,
    infer_subsystem_from_file_path,
    normalize_packet_type,
    record_time_key,
    scrub_record,
    select_active_record,
    select_integrity_record,
    flatten_integrity_record,
    merge_history_snapshots,
    should_append_baseline,
    time_key_from_value,
    timestamp_to_epoch,
)
from ma_detector.core.rule_activation import merge_default_activations
from ma_detector.core.target_context import (
    build_novel_attack_advisory,
    expand_module_tokens,
    infer_adcs_attack_target,
    infer_target_from_sw_ids,
    normalize_target_subsystem,
    report_matches_target,
    sort_reports_by_target,
)
from ma_detector.db import gs_repository
from ma_detector.db.database import is_db_available
from ma_detector.registry.registry_manager import RegistryManager

logger = logging.getLogger(__name__)

_RULE_SCORE_LOG_IDS = frozenset({"E-03", "E-X3", "E-05"})
DEFAULT_ANALYSIS_WINDOW_SEC = 600


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
            merge_default_activations(self._rule_registry)

            self._baseline_manager = BaselineManager()
            self._evidence_rules = EvidenceRules(self._baseline_manager, self._threshold_config)

            self._is_replay_mode = False
            self._pending_pool: list[_PendingCandidate] = []
            self._known_patterns: set[str] = set()
            self._replay_buffer: list[dict[str, Any]] = []
            self._telemetry_window: list[dict[str, Any]] = []
            self._window_size_sec = DEFAULT_ANALYSIS_WINDOW_SEC

            self._gs_tlm_history: list[dict[str, Any]] = []
            self._gs_event_queue: list[dict[str, Any]] = []
            self._gs_pwr_meta: list[dict[str, Any]] = []
            self._dashboard_rows: list[dict[str, Any]] = []
            self._detail_rows: list[dict[str, Any]] = []
            self._discard_log: list[dict[str, Any]] = []
            self._next_detect_id = gs_repository.fetch_next_detect_id()
            self._last_ingest_error: str | None = None
            self._latest_novel_advisory: dict[str, Any] | None = None
            self._next_event_queue_id = 1
            self._persisted_record_fingerprints: set[str] = set()
            self._persist_comm_session: str = ""
            self._history_persist_lock = threading.RLock()
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
            self._gs_event_queue = []
            self._gs_pwr_meta = []
            self._dashboard_rows = []
            self._detail_rows = []
            self._discard_log = []
            self._next_detect_id = 1
            self._last_ingest_error = None
            self._latest_novel_advisory = None
            self._next_event_queue_id = 1
            self._persisted_record_fingerprints = set()
            self._persist_comm_session = ""
            self._history_persist_lock = threading.RLock()

    def _begin_persist_comm_session(self, comm_session: str) -> None:
        """Reset dedup fingerprints when a new uplink comm session starts."""
        try:
            session = str(comm_session or "").strip()
            if not session:
                return
            if self._persist_comm_session and self._persist_comm_session != session:
                self._persisted_record_fingerprints.clear()
            self._persist_comm_session = session
        except Exception as error:
            logger.error("persist comm session reset failed: %s", error)

    def get_last_ingest_error(self) -> str | None:
        """Return the most recent telemetry ingest validation error, if any."""
        try:
            return self._last_ingest_error
        except Exception as error:
            logger.error("get last ingest error failed: %s", error)
            return None

    def get_latest_novel_advisory(self) -> dict[str, Any] | None:
        """Return advisory metadata for novel / unknown attack patterns."""
        try:
            if self._latest_novel_advisory is None:
                return None
            return dict(self._latest_novel_advisory)
        except Exception as error:
            logger.error("get novel advisory failed: %s", error)
            return None

    def persist_bulk_telemetry_packet(self, bulk: dict[str, Any]) -> tuple[int, int]:
        """Merge telemetry by SNAPSHOT_ID, store events separately, run MA per attack event."""
        inserted = 0
        skipped = 0
        try:
            if self._is_replay_mode:
                return inserted, skipped

            with self._history_persist_lock:
                comm_session = str(bulk.get("_comm_session", "") or "").strip()
                session = comm_session or "_default"
                if comm_session:
                    self._begin_persist_comm_session(comm_session)

                merged_rows = merge_bulk_telemetry_packet(bulk)
                stored_history_rows: list[dict[str, Any]] = []
                fallback_history: dict[str, Any] | None = None
                tolerance_sec = float(
                    self._threshold_config.get("packet_buffer", {}).get(
                        "RECORD_MATCH_TOLERANCE_SEC",
                        5,
                    )
                )

                for row in merged_rows:
                    snapshot_id = row.get("SNAPSHOT_ID")
                    sample_id = snapshot_id or row.get("SAMPLE_HISTORY_ID", row.get("SAMPLE_INDEX", ""))
                    if snapshot_id is not None:
                        fingerprint = f"{session}:snapshot:{snapshot_id}"
                    else:
                        fingerprint = f"{session}:bulk:{sample_id}"
                    if fingerprint in self._persisted_record_fingerprints:
                        skipped += 1
                        continue
                    if comm_session:
                        row["_comm_session"] = comm_session
                    history_id = self._insert_gs_tables(row)
                    if history_id is None:
                        logger.error(
                            "bulk history row insert failed comm=%s sample=%s",
                            comm_session or "no-session",
                            sample_id,
                        )
                        continue
                    stored_row = dict(row)
                    stored_row["HISTORY_ID"] = history_id
                    self._persisted_record_fingerprints.add(fingerprint)
                    inserted += 1
                    stored_history_rows.append(stored_row)
                    if fallback_history is None:
                        fallback_history = stored_row

                events_inserted = 0
                events_skipped = 0
                attack_runs = 0
                bulk_sent_at = bulk.get("sent_at")
                if isinstance(bulk_sent_at, str):
                    bulk_sent_at = bulk_sent_at
                else:
                    bulk_sent_at = None

                for event in extract_bulk_event_records(bulk):
                    event_key = self._event_persist_fingerprint(session, event)
                    if event_key in self._persisted_record_fingerprints:
                        events_skipped += 1
                        continue

                    history_row, link_history_id = resolve_event_history_link(
                        event,
                        stored_history_rows,
                        fallback_history=fallback_history,
                        tolerance_sec=tolerance_sec,
                    )
                    event_row = build_event_queue_row(
                        event,
                        bulk_sent_at=bulk_sent_at,
                    )
                    if not event_row:
                        continue

                    event_queue_id = self._insert_event_queue_row(event_row)
                    if event_queue_id is None:
                        logger.error(
                            "event queue insert failed comm=%s event_id=%s",
                            comm_session or "no-session",
                            event.get("EVENT_ID"),
                        )
                        continue

                    self._persisted_record_fingerprints.add(event_key)
                    events_inserted += 1
                    stored_event = dict(event_row)
                    stored_event["EVENT_QUEUE_ID"] = event_queue_id

                    if event_is_attack_anomaly(event) and history_row is not None:
                        _, time_delta = find_nearest_history_for_event(
                            event,
                            stored_history_rows,
                            tolerance_sec=tolerance_sec,
                        )
                        pipeline_row = build_ma_reference_packet(
                            history_row,
                            stored_event,
                            time_delta_sec=time_delta,
                        )
                        pipeline_row["_bulk_persisted"] = True
                        pipeline_row.setdefault("packet_type", "SAT_BULK_TELEMETRY")
                        self.receive_telemetry(
                            json.dumps(pipeline_row, ensure_ascii=False, default=str),
                            skip_history_insert=True,
                        )
                        attack_runs += 1

                logger.info(
                    "bulk history persist comm=%s samples=%s inserted=%s skipped=%s "
                    "events=%s events_skipped=%s attacks=%s",
                    comm_session or "no-session",
                    len(merged_rows),
                    inserted,
                    skipped,
                    events_inserted,
                    events_skipped,
                    attack_runs,
                )
            return inserted, skipped
        except Exception as error:
            logger.error("bulk telemetry persist failed: %s", error)
            return inserted, skipped

    @staticmethod
    def _event_persist_fingerprint(session: str, event: dict[str, Any]) -> str:
        try:
            detected = time_key_from_value(event.get("DETECTED_AT") or event.get("TIMESTAMP") or "")
            event_id = event.get("EVENT_ID", "")
            return f"{session}:event:{event_id}:{detected or 'unknown'}"
        except Exception as error:
            logger.error("event persist fingerprint build failed: %s", error)
            return f"{session}:event:unknown"

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
            merge_default_activations(self._rule_registry)
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

    def hydrate_memory_state(
        self,
        tlm_history: list[dict[str, Any]] | None = None,
        dashboard_rows: list[dict[str, Any]] | None = None,
    ) -> None:
        """Load DB rows into in-memory tables used by the dashboard API."""
        try:
            if tlm_history:
                self._gs_tlm_history.extend(dict(row) for row in tlm_history if isinstance(row, dict))
            if dashboard_rows:
                self._dashboard_rows.extend(dict(row) for row in dashboard_rows if isinstance(row, dict))
            if self._dashboard_rows:
                max_detect_id = max(
                    int(row.get("DETECT_ID", 0) or 0) for row in self._dashboard_rows
                )
                self._next_detect_id = max(self._next_detect_id, max_detect_id + 1)
        except Exception as error:
            logger.error("memory state hydration failed: %s", error)

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

    def receive_telemetry(
        self,
        json_token: str,
        skip_history_insert: bool = False,
        *,
        reprocess: bool = False,
    ) -> str | None:
        """Parse satellite JSON and execute the MA detection pipeline for attack-like events."""
        try:
            self._last_ingest_error = None
            packet = json.loads(json_token)
            if not isinstance(packet, dict):
                message = "received telemetry must be a JSON object"
                logger.error(message)
                self._last_ingest_error = message
                return message
        except json.JSONDecodeError as error:
            message = f"receive telemetry JSON parse failed: {error}"
            logger.error(message)
            self._last_ingest_error = message
            return message
        except TypeError as error:
            message = f"receive telemetry input type failed: {error}"
            logger.error(message)
            self._last_ingest_error = message
            return message
        except Exception as error:
            message = f"unexpected receive telemetry failure: {error}"
            logger.error(message)
            self._last_ingest_error = message
            return message

        try:
            packet = self._normalize_packet(packet)
            if self._is_replay_mode:
                try:
                    self._gs_tlm_history.append(dict(packet))
                except Exception as error:
                    logger.error("replay history append failed: %s", error)
                if not packet.get("IS_ANOMALY", False):
                    if should_append_baseline(packet):
                        self._baseline_manager.append_normal_record(packet)
                    return None
                validation_error = self._validate_attack_packet(packet)
                if validation_error:
                    self._last_ingest_error = validation_error
                    return validation_error
                self._telemetry_window.append(packet)
                self._trim_window()
                self._run_pipeline()
                return None

            should_persist_history = (
                not reprocess
                and not packet.get("_bulk_persisted", False)
                and ((not skip_history_insert) or bool(packet.get("IS_ANOMALY", False)))
            )
            if should_persist_history:
                self._insert_gs_tables(packet)
            if not packet.get("IS_ANOMALY", False):
                if should_append_baseline(packet):
                    self._baseline_manager.append_normal_record(packet)
                self._notify_ui_normal(packet)
                return None

            validation_error = self._validate_attack_packet(packet)
            if validation_error:
                self._last_ingest_error = validation_error
                logger.error(validation_error)
                return validation_error

            logger.info("IS_ANOMALY: True")
            self._telemetry_window.append(packet)
            self._trim_window()
            self._run_pipeline()
            return None
        except Exception as error:
            message = f"receive telemetry pipeline failed: {error}"
            logger.error(message)
            self._last_ingest_error = message
            return message

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

                rule_score = self._evidence_rules.evaluate(rule_id, typed_window, rule_def)
                latest = typed_window[-1] if typed_window else {}
                integrity_floor = float(
                    self._threshold_config.get("integrity_rules", {}).get("IS_VIOLATED_SCORE_FLOOR", 0.65)
                )
                if int(latest.get("IS_VIOLATED", 0) or 0) == 1 and rule_id in ("E-03", "E-X3", "E-05"):
                    rule_score = max(float(rule_score), integrity_floor)
                if rule_id in _RULE_SCORE_LOG_IDS:
                    logger.info("Rule %s score: %.2f", rule_id, rule_score)
                score_threshold = float(rule_def.get("score_threshold", 0.0) or 0.0)
                if rule_score <= 0.0 or rule_score < score_threshold:
                    continue

                timestamp = self._timestamp_to_epoch(latest.get("UPDATED_AT", time.time()))

                for action_id, base_score in rule_def.get("contributes_to", {}).items():
                    action_def = self._action_registry.get(action_id)
                    if action_def is None:
                        continue

                    phase = int(action_def.get("phase", 0))
                    action_weight = float(action_def.get("weight", 1.0))
                    weighted_base = float(base_score) + 0.3 * phase
                    contribution = weighted_base * rule_score * action_weight
                    max_possible = weighted_base * action_weight

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
                    "is_new_pattern": False,
                    "action_mapping_status": "mapped",
                    "triggered_rules": triggered_rules,
                    "unregistered_action_ids": [],
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

            for entry in discarded_entries:
                self._db_insert_discard_log(entry)

            results.extend(self._flush_pending_pool())

            latest = self._telemetry_window[-1] if self._telemetry_window else {}
            results = self._finalize_reports_for_action_mapping(results, data, latest)
            target = normalize_target_subsystem(latest.get("TARGET_SUBSYSTEM"))
            results = sort_reports_by_target(results, target, self._rule_registry)
            results = self._prefer_integrity_action_reports(results, latest)
            for entry in results:
                if not isinstance(entry, dict):
                    continue
                if entry.get("grade") in ("CONFIRMED", "SUSPECTED"):
                    logger.info(
                        "MA 코드 생성: %s (grade=%s, confidence=%.2f)",
                        entry.get("ma_code"),
                        entry.get("grade"),
                        float(entry.get("confidence_score", 0.0) or 0.0),
                    )
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
                    if grade in ("CONFIRMED", "SUSPECTED"):
                        self._memory_insert_dashboard(report)
                    continue

                if grade in ("CONFIRMED", "SUSPECTED"):
                    self._db_insert_dashboard(report)
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
                "action_mapping_status": dashboard_row.get("ACTION_MAPPING_STATUS", "mapped"),
                "triggered_rules": dashboard_row.get("TRIGGERED_RULE_IDS", []),
                "unregistered_action_ids": dashboard_row.get("UNREGISTERED_ACTION_IDS", []),
                "triggered_rule_results": dashboard_row.get("TRIGGERED_RULE_RESULTS", []),
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

    def get_snapshot_series(self, reference_time: str | None = None) -> list[dict[str, Any]]:
        """Return up to 600 snapshots (1 Hz series) ending at reference_time within the analysis window."""
        try:
            evaluation = self._threshold_config.get("evaluation", {})
            window_seconds = int(evaluation.get("series_seconds", self._window_size_sec))
            max_points = int(evaluation.get("series_max_points", window_seconds))
            if is_db_available():
                if reference_time:
                    history = gs_repository.query_history_window(
                        reference_time,
                        window_seconds,
                        limit=max_points,
                    )
                else:
                    history = gs_repository.load_recent_tlm_history(max_points)
            else:
                history = []
            history = merge_history_snapshots(history)
            history = sorted(
                history,
                key=lambda row: self._timestamp_to_epoch(row.get("UPDATED_AT", 0)),
            )
            if not history:
                return []
            anchor_epoch = self._timestamp_to_epoch(reference_time) if reference_time else None
            if anchor_epoch is None:
                anchor_epoch = self._timestamp_to_epoch(history[-1].get("UPDATED_AT", time.time()))
            cutoff = anchor_epoch - window_seconds
            series = [
                dict(row)
                for row in history
                if cutoff <= self._timestamp_to_epoch(row.get("UPDATED_AT", 0)) <= anchor_epoch
            ]
            if len(series) > max_points:
                series = series[-max_points:]
            return series
        except Exception as error:
            logger.error("snapshot series lookup failed: %s", error)
            return []

    def get_snapshot_frame(
        self,
        reference_time: str | None,
        snapshot_index: int | None = None,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None, list[dict[str, Any]]]:
        """Return (previous, current, full_series) for one frame inside the 1-second snapshot series."""
        try:
            series = self.get_snapshot_series(reference_time)
            if not series:
                return None, None, []
            if snapshot_index is not None:
                index = max(0, min(int(snapshot_index), len(series) - 1))
            else:
                detect_key = time_key_from_value(reference_time)
                index = len(series) - 1
                if detect_key:
                    for frame_index, row in enumerate(series):
                        if time_key_from_value(row.get("UPDATED_AT")) == detect_key:
                            index = frame_index
                            break
            current = series[index]
            previous = series[index - 1] if index > 0 else None
            return previous, current, series
        except Exception as error:
            logger.error("snapshot frame lookup failed: %s", error)
            return None, None, []

    def get_step_snapshots_for_time(self, detect_time: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Backward-compatible wrapper that returns the last frame in the snapshot series."""
        try:
            previous, current, _series = self.get_snapshot_frame(detect_time, None)
            return previous, current
        except Exception as error:
            logger.error("step snapshot lookup failed: %s", error)
            return None, None

    def _build_evaluation_window(self) -> list[dict[str, Any]]:
        """Build rule evaluation window as a 10-minute 1 Hz snapshot series (up to 600 points)."""
        try:
            if not self._telemetry_window:
                return []
            mode = str(
                self._threshold_config.get("evaluation", {}).get("default_window_mode", "snapshot_series")
            ).strip()
            current = dict(self._telemetry_window[-1])
            anchor_time = str(current.get("UPDATED_AT") or current.get("DETECTED_AT") or "")
            if mode == "snapshot_series":
                series = self.get_snapshot_series(anchor_time)
                series = self._compute_imu_variance(series)
                return series if series else [current]
            series = self._compute_imu_variance([dict(row) for row in self._telemetry_window])
            return series
        except Exception as error:
            logger.error("evaluation window build failed: %s", error)
            return [dict(row) for row in self._telemetry_window]

    def _compute_imu_variance(self, window: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Compute IMU_WBN_VARIANCE from IMU_WBN_X/Y/Z series when not provided in telemetry."""
        try:
            if len(window) < 2:
                for snap in window:
                    snap.setdefault("IMU_WBN_VARIANCE", 0.0)
                return window

            axis_values: dict[str, list[float]] = {"X": [], "Y": [], "Z": []}
            for snap in window:
                for axis in ["X", "Y", "Z"]:
                    val = snap.get(f"IMU_WBN_{axis}")
                    if isinstance(val, (int, float)):
                        axis_values[axis].append(float(val))

            variances: list[float] = []
            for axis in ["X", "Y", "Z"]:
                vals = axis_values[axis]
                if len(vals) >= 2:
                    try:
                        variances.append(statistics.variance(vals))
                    except statistics.StatisticsError:
                        variances.append(0.0)
                else:
                    variances.append(0.0)

            imu_variance = sum(variances) / len(variances) if variances else 0.0
            for snap in window:
                snap["IMU_WBN_VARIANCE"] = imu_variance
            return window
        except Exception as error:
            logger.error("IMU variance computation failed: %s", error)
            return window

    def _run_pipeline(self) -> None:
        try:
            evaluation_window = self._build_evaluation_window()
            snapshot_json = json.dumps(evaluation_window, ensure_ascii=False, default=str)
            rule_result_json = self.evaluate_parallel_rules(snapshot_json)
            confidence = self.verify_attack_sequence(rule_result_json)
            final_input = self._build_final_input(rule_result_json, confidence)
            report_json = self.generate_ma_code(final_input)
            reports = json.loads(report_json)
            latest = evaluation_window[-1] if evaluation_window else {}
            if isinstance(reports, list):
                self._latest_novel_advisory = build_novel_attack_advisory(latest, reports)
            else:
                self._latest_novel_advisory = None
            self.insert_dashboard_db(report_json)
            self._broadcast_ma_reports(reports if isinstance(reports, list) else [])
        except Exception as error:
            logger.error("pipeline execution failed: %s", error)

    def _broadcast_ma_reports(self, reports: list[dict[str, Any]]) -> None:
        try:
            from api.websocket_manager import ws_manager

            for report in reports:
                if not isinstance(report, dict):
                    continue
                if report.get("grade") not in ("CONFIRMED", "SUSPECTED"):
                    continue
                ws_manager.broadcast_sync(
                    {
                        "type": "MA_CODE_GENERATED",
                        "ma_code": report.get("ma_code"),
                        "grade": report.get("grade"),
                        "confidence": report.get("confidence_score"),
                    }
                )
        except Exception as error:
            logger.error("ma report websocket broadcast failed: %s", error)

    def _normalize_packet(self, packet: dict[str, Any]) -> dict[str, Any]:
        try:
            normalized = self._merge_packet_sections(packet)
            normalized.setdefault("UPDATED_AT", datetime.now(timezone.utc).isoformat())
            normalized.setdefault("DETECTED_AT", normalized["UPDATED_AT"])
            promote_event_reference_fields(normalized)
            self._normalize_filter_fields(normalized)
            return normalized
        except Exception as error:
            logger.error("packet normalization failed: %s", error)
            return packet

    def _merge_packet_sections(self, packet: dict[str, Any]) -> dict[str, Any]:
        try:
            normalized: dict[str, Any] = {}
            packet_type = normalize_packet_type(str(packet.get("packet_type", "")).strip())

            if packet_type in ("SAT_TLM_HISTORY", "SAT_TLM_CURRENT"):
                normalized["packet_type"] = "SAT_TLM_HISTORY"
                if packet_type == "SAT_TLM_CURRENT":
                    data = packet.get("data", packet)
                    if isinstance(data, dict):
                        normalized.update(scrub_record(data))
                else:
                    record = select_active_record(packet)
                    if record:
                        normalized.update(record)

            elif packet_type in ("SAT_PWR_HISTORY", "SAT_PWR_META"):
                normalized["packet_type"] = "SAT_PWR_HISTORY"
                record = select_active_record(packet)
                normalized["UPDATED_AT"] = record.get("UPDATED_AT", packet.get("UPDATED_AT", ""))
                channels = record.get("channels", packet.get("channels", []))
                has_anomaly = False
                anomaly_sw_ids: list[int] = []
                if isinstance(channels, list):
                    for ch in channels:
                        if not isinstance(ch, dict):
                            continue
                        sw_id = ch.get("SW_ID", 0)
                        normalized[f"SW_{sw_id}_VOLTAGE"] = ch.get("VOLTAGE")
                        normalized[f"SW_{sw_id}_CURRENT_A"] = ch.get("CURRENT_A")
                        normalized[f"SW_{sw_id}_CURRENT"] = ch.get("CURRENT_A")
                        normalized[f"SW_{sw_id}_PREV_VOLTAGE"] = ch.get("PREV_VOLTAGE")
                        normalized[f"SW_{sw_id}_CURR_DELTA_V"] = ch.get("CURR_DELTA_V")
                        normalized[f"SW_{sw_id}_EXCEED_COUNT"] = ch.get("EXCEED_COUNT")
                        normalized[f"SW_{sw_id}_CONSECUTIVE_EXCEED"] = ch.get("CONSECUTIVE_EXCEED")
                        normalized[f"SW_{sw_id}_ANOMALY_FLAG"] = ch.get("ANOMALY_FLAG")
                        if ch.get("ANOMALY_FLAG", 0) == 1:
                            has_anomaly = True
                            anomaly_sw_ids.append(int(sw_id))
                normalized["HAS_PWR_ANOMALY"] = has_anomaly
                normalized["SW_ID_LIST"] = anomaly_sw_ids

            elif packet_type == "SAT_EVENT_QUEUE":
                event = packet.get("event", packet)
                if isinstance(event, dict):
                    normalized.update(scrub_record(event))
                normalized["packet_type"] = packet_type

                combined_crc = normalized.get("CH1_CH2_FAULT_CRC", 0)
                normalized["CH1_FAULT_CRC"] = combined_crc
                normalized["CH2_FAULT_CRC"] = combined_crc

                event_type = str(normalized.get("EVENT_TYPE", ""))
                weight = normalized.get("WEIGHT", 0)
                normalized["IS_ANOMALY"] = (
                    event_type == "ATTACK_CONFIRMED"
                    or int(weight or 0) >= 50
                )
                normalized["FALSE_POSITIVE_RESULT"] = "Y" if normalized["IS_ANOMALY"] else "N"
                normalized["FALSE_POSITIVE_WEIGHT"] = weight
                normalized["FALSE_POSITIVE_EXCEPTION"] = normalized.get("EXCEPTION_CODE", "")

                if not normalized.get("TARGET_SUBSYSTEM"):
                    file_target = infer_subsystem_from_file_path(normalized.get("FILE_PATH"))
                    if file_target:
                        normalized["TARGET_SUBSYSTEM"] = file_target
                if not normalized.get("TARGET_SUBSYSTEM"):
                    sw_id = normalized.get("SW_ID")
                    if sw_id is not None:
                        normalized["TARGET_SUBSYSTEM"] = infer_target_from_sw_ids([sw_id])

            elif packet_type == "SAT_INTEGRITY_HASH":
                normalized["packet_type"] = packet_type
                buffer_key = packet.get("_buffer_key")
                tolerance = float(
                    packet.get(
                        "_match_tolerance_sec",
                        self._threshold_config.get("packet_buffer", {}).get(
                            "RECORD_MATCH_TOLERANCE_SEC",
                            5,
                        ),
                    )
                )
                rec = select_integrity_record(
                    packet,
                    buffer_key=str(buffer_key) if buffer_key else None,
                    tolerance_sec=tolerance,
                )
                if rec:
                    normalized.update(flatten_integrity_record(rec))

            elif packet_type == "SAT_ADCS_FILTER":
                normalized["packet_type"] = packet_type
                record = select_active_record(packet)
                if record:
                    normalized.update(record)
                if "RESETSPERFORMED" in normalized:
                    normalized["PROCESSOR_RESET_COUNT"] = normalized["RESETSPERFORMED"]
                normalized.setdefault("IMU_WBN_VARIANCE", 0.0)

            else:
                normalized.update(scrub_record(packet))
                section_keys = [
                    "data",
                    "event",
                    "telemetry",
                    "tlm",
                    "SAT_TLM_HISTORY",
                    "SAT_TLM_CURRENT",
                    "SAT_PWR_HISTORY",
                    "SAT_PWR_META",
                    "SAT_EVENT_QUEUE",
                    "SAT_INTEGRITY_HASH",
                    "SAT_ADCS_FILTER",
                ]
                for key in section_keys:
                    section = packet.get(key)
                    if isinstance(section, dict):
                        normalized.update(scrub_record(section))

            for field in ("DETECTED_AT", "TIMESTAMP", "UPDATED_AT"):
                value = normalized.get(field) or packet.get(field)
                if value:
                    normalized.setdefault("UPDATED_AT", value)
                    normalized.setdefault("DETECTED_AT", value)
                    break
            normalized.setdefault(
                "UPDATED_AT",
                packet.get("UPDATED_AT")
                or packet.get("DETECTED_AT")
                or packet.get("TIMESTAMP")
                or normalized.get("UPDATED_AT")
                or "",
            )
            return normalized
        except TypeError as error:
            logger.error("packet section merge failed: %s", error)
            return dict(packet)
        except Exception as error:
            logger.error("unexpected packet section merge failure: %s", error)
            return dict(packet)

    def _validate_attack_packet(self, packet: dict[str, Any]) -> str | None:
        """Require attack target; infer from SW_ID_LIST or SW_ID when missing."""
        try:
            if not packet.get("IS_ANOMALY", False):
                return None

            target = normalize_target_subsystem(packet.get("TARGET_SUBSYSTEM"))

            if not target:
                file_target = infer_subsystem_from_file_path(packet.get("FILE_PATH"))
                if file_target:
                    packet["TARGET_SUBSYSTEM"] = file_target
                    return None

            if not target:
                sw_id_list = packet.get("SW_ID_LIST", [])
                if sw_id_list:
                    target = infer_target_from_sw_ids(sw_id_list)
                    if target:
                        packet["TARGET_SUBSYSTEM"] = target
                        return None

            if target:
                packet["TARGET_SUBSYSTEM"] = target
                return None

            sw_id = packet.get("SW_ID")
            if sw_id is not None:
                target = infer_target_from_sw_ids([sw_id])
                if target:
                    packet["TARGET_SUBSYSTEM"] = target
                    return None

            message = (
                "TARGET_SUBSYSTEM could not be determined "
                "from packet; provide TARGET_SUBSYSTEM or SW_ID_LIST"
            )
            return message
        except Exception as error:
            logger.error("attack packet validation failed: %s", error)
            return "attack packet validation failed"

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
                if corroboration_count >= 2 or single_sufficient:
                    return "SUSPECTED"
                return "PENDING"
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
                    "is_new_pattern": False,
                    "action_mapping_status": "mapped",
                    "triggered_rules": all_rules,
                    "unregistered_action_ids": [],
                    "triggered_rule_results": [],
                }
            ]
        except (TypeError, ValueError) as error:
            logger.error("pending pool flush failed: %s", error)
            return []
        except Exception as error:
            logger.error("unexpected pending pool flush failure: %s", error)
            return []

    @staticmethod
    def _is_attack_packet(packet: dict[str, Any]) -> bool:
        try:
            return bool(packet.get("IS_ANOMALY", False))
        except Exception as error:
            logger.error("attack packet check failed: %s", error)
            return False

    def _is_mapped_report(self, report: dict[str, Any]) -> bool:
        try:
            if report.get("grade") not in ("CONFIRMED", "SUSPECTED"):
                return False
            action_id = str(report.get("action_id", "") or "")
            if not action_id or action_id == "A000":
                return False
            return action_id in self._action_registry
        except Exception as error:
            logger.error("mapped report check failed: %s", error)
            return False

    def _unregistered_action_ids_from_rule_ids(self, rule_ids: list[str]) -> list[str]:
        try:
            unregistered: set[str] = set()
            for rule_id in rule_ids:
                contributes = self._rule_registry.get(rule_id, {}).get("contributes_to", {})
                for action_id in contributes:
                    if action_id not in self._action_registry:
                        unregistered.add(str(action_id))
            return sorted(unregistered)
        except Exception as error:
            logger.error("unregistered action lookup failed: %s", error)
            return []

    def _prefer_integrity_action_reports(
        self,
        reports: list[dict[str, Any]],
        latest: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Prefer CS/OBC integrity actions when IS_VIOLATED=1."""
        try:
            if int(latest.get("IS_VIOLATED", 0) or 0) != 1:
                return reports
            preferred_ids = ("A008", "A003")
            preferred = [report for report in reports if report.get("action_id") in preferred_ids]
            if not preferred:
                return reports
            others = [report for report in reports if report.get("action_id") not in preferred_ids]
            target = normalize_target_subsystem(latest.get("TARGET_SUBSYSTEM"))
            preferred = sort_reports_by_target(preferred, target, self._rule_registry)
            return preferred + others
        except Exception as error:
            logger.error("integrity report preference failed: %s", error)
            return reports

    def _promote_best_action_report(
        self,
        rule_data: dict[str, Any],
        latest: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Promote the highest-scoring mapped action when grading discarded all candidates."""
        try:
            confidence_config = self._threshold_config.get("confidence", {})
            suspected_threshold = float(confidence_config.get("SUSPECTED_THRESHOLD", 40.0))
            sequence_adjustment = float(rule_data.get("sequence_adjustment", 0.0))
            best_entry: dict[str, Any] | None = None
            best_confidence = -1.0

            for action_id, accumulator in rule_data.get("accumulators", {}).items():
                if action_id not in self._action_registry:
                    continue
                accumulated_score = float(accumulator.get("accumulated_score", 0.0))
                max_possible_score = float(accumulator.get("max_possible_score", 0.0))
                if accumulated_score <= 0.0 or max_possible_score <= 0.0:
                    continue

                action_def = self._action_registry[action_id]
                module = str(action_def.get("module", "UNKNOWN"))
                phase = int(action_def.get("phase", 0))
                action_name = str(action_def.get("name", "UNKNOWN"))
                triggered_rules = list(accumulator.get("triggered_rules", []))
                raw_confidence = accumulated_score / max_possible_score * 100.0
                confidence = round(max(0.0, min(raw_confidence + sequence_adjustment, 100.0)), 2)
                if confidence < suspected_threshold * 0.5:
                    continue

                corroboration_count = int(
                    rule_data.get("corroboration", {}).get(f"{module}::{action_id}", 0)
                )
                single_sufficient = any(
                    self._rule_registry.get(rule_id, {}).get("single_sufficient", False)
                    for rule_id in triggered_rules
                )
                grade = self._classify_grade(
                    max(confidence, suspected_threshold),
                    corroboration_count,
                    single_sufficient,
                    float(confidence_config.get("CONFIRMED_THRESHOLD", 70.0)),
                    suspected_threshold,
                    int(self._threshold_config.get("corroboration", {}).get("CONFIRMED_MIN", 2)),
                )
                if grade not in ("CONFIRMED", "SUSPECTED"):
                    grade = "SUSPECTED"
                    confidence = max(confidence, suspected_threshold)

                if confidence <= best_confidence:
                    continue
                best_confidence = confidence
                best_entry = {
                    "ma_code": f"{module}_{action_name}_P{phase}",
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
                    "is_new_pattern": False,
                    "action_mapping_status": "mapped",
                    "triggered_rules": triggered_rules,
                    "unregistered_action_ids": self._unregistered_action_ids_from_rule_ids(triggered_rules),
                    "triggered_rule_results": [
                        item for item in rule_data.get("rule_results", []) if item.get("triggered")
                    ],
                }

            if best_entry is None:
                return None
            target = normalize_target_subsystem(latest.get("TARGET_SUBSYSTEM"))
            preferred_codes = {
                "CS_INTEGRITY_CHECK_BYPASS_P3",
                "OBC+CF_SEU_DISGUISED_INTRUSION_P1",
                "ADCS_ATTITUDE_CONTROL_TAMPERING_P3",
            }
            if best_entry.get("ma_code") not in preferred_codes and target:
                for action_id, accumulator in rule_data.get("accumulators", {}).items():
                    action_def = self._action_registry.get(action_id)
                    if action_def is None:
                        continue
                    module = str(action_def.get("module", ""))
                    if target not in expand_module_tokens(module) and target not in module:
                        continue
                    triggered_rules = list(accumulator.get("triggered_rules", []))
                    if not triggered_rules:
                        continue
                    phase = int(action_def.get("phase", 0))
                    action_name = str(action_def.get("name", "UNKNOWN"))
                    candidate_code = f"{module}_{action_name}_P{phase}"
                    if candidate_code in preferred_codes or target in expand_module_tokens(module):
                        best_entry = {
                            **best_entry,
                            "ma_code": candidate_code,
                            "action_id": action_id,
                            "action_name": action_name,
                            "module": module,
                            "scenario_phase": phase,
                            "triggered_rules": triggered_rules,
                        }
                        break
            return best_entry
        except Exception as error:
            logger.error("best action promotion failed: %s", error)
            return None

    def _build_undefined_action_report(
        self,
        latest: dict[str, Any],
        rule_data: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            triggered = [
                item for item in rule_data.get("rule_results", []) if item.get("triggered")
            ]
            rule_ids = [str(item.get("rule_id", "")) for item in triggered if item.get("rule_id")]
            unregistered = self._unregistered_action_ids_from_rule_ids(rule_ids)
            evidence_keys = {
                rule_id: self._rule_registry.get(rule_id, {}).get("name", rule_id)
                for rule_id in rule_ids
            }
            top_score = max((float(item.get("score", 0.0) or 0.0) for item in triggered), default=0.0)
            target_module = normalize_target_subsystem(latest.get("TARGET_SUBSYSTEM")) or "UNKNOWN"
            return {
                "ma_code": "UNMAPPED_SATELLITE_ATTACK_P0",
                "action_id": "",
                "action_name": "UNMAPPED_ATTACK",
                "module": target_module,
                "scenario_phase": 0,
                "confidence_score": round(top_score * 100.0, 2),
                "grade": "SUSPECTED",
                "corroboration_count": len(rule_ids),
                "evidence_keys": evidence_keys,
                "is_new_pattern": True,
                "action_mapping_status": "undefined",
                "triggered_rules": rule_ids,
                "unregistered_action_ids": unregistered,
                "triggered_rule_results": triggered,
            }
        except Exception as error:
            logger.error("undefined action report build failed: %s", error)
            return {
                "ma_code": "UNMAPPED_SATELLITE_ATTACK_P0",
                "action_id": "",
                "action_name": "UNMAPPED_ATTACK",
                "module": "UNKNOWN",
                "scenario_phase": 0,
                "confidence_score": 0.0,
                "grade": "SUSPECTED",
                "corroboration_count": 0,
                "evidence_keys": {},
                "is_new_pattern": True,
                "action_mapping_status": "undefined",
                "triggered_rules": [],
                "unregistered_action_ids": [],
                "triggered_rule_results": [],
            }

    def _finalize_reports_for_action_mapping(
        self,
        reports: list[dict[str, Any]],
        rule_data: dict[str, Any],
        latest: dict[str, Any],
    ) -> list[dict[str, Any]]:
        try:
            if not self._is_attack_packet(latest):
                for report in reports:
                    report["action_mapping_status"] = "mapped"
                    report["is_new_pattern"] = False
                return reports

            mapped = [report for report in reports if self._is_mapped_report(report)]
            if mapped:
                for report in mapped:
                    report["action_mapping_status"] = "mapped"
                    report["is_new_pattern"] = False
                target = normalize_target_subsystem(latest.get("TARGET_SUBSYSTEM"))
                mapped = sort_reports_by_target(mapped, target, self._rule_registry)
                mapped = self._prefer_integrity_action_reports(mapped, latest)
                return mapped

            promoted = self._promote_best_action_report(rule_data, latest)
            if promoted is not None:
                filtered = self._prefer_integrity_action_reports([promoted], latest)
                return filtered[:1]

            return [self._build_undefined_action_report(latest, rule_data)]
        except Exception as error:
            logger.error("action mapping finalize failed: %s", error)
            return reports

    @staticmethod
    def _timestamp_to_epoch(value: Any) -> float:
        try:
            epoch = timestamp_to_epoch(value)
            if epoch is not None:
                return epoch
            return time.time()
        except Exception as error:
            logger.error("timestamp conversion failed: %s", error)
            return time.time()

    def _insert_gs_tables(self, packet: dict[str, Any]) -> int | None:
        try:
            if self._is_replay_mode:
                return None
            prepared = gs_repository.prepare_packet_for_db(packet)
            memory_id = len(self._gs_tlm_history) + 1
            prepared["HISTORY_ID"] = memory_id
            self._gs_tlm_history.append(dict(prepared))
            if not is_db_available():
                return memory_id
            history_id = gs_repository.insert_tlm_history(prepared)
            if history_id is None:
                logger.error("GS table insert returned no HISTORY_ID")
                return None
            prepared["HISTORY_ID"] = history_id
            gs_repository.insert_pwr_meta_rows(prepared, history_id=history_id)
            power_columns = {
                key: value
                for key, value in prepared.items()
                if key.startswith("SW_") or key.startswith("BUS_") or key == "BATT_VOLTAGE"
            }
            if power_columns:
                power_columns["UPDATED_AT"] = prepared.get("UPDATED_AT")
                self._gs_pwr_meta.append(power_columns)
            return history_id
        except Exception as error:
            logger.error("GS table insert failed: %s", error)
            return None

    def _insert_event_queue_row(self, row: dict[str, Any]) -> int | None:
        try:
            if self._is_replay_mode:
                return None
            stored = dict(row)
            event_queue_id = self._next_event_queue_id
            self._next_event_queue_id += 1
            stored["EVENT_QUEUE_ID"] = event_queue_id
            self._gs_event_queue.append(stored)
            if not is_db_available():
                return event_queue_id
            db_id = gs_repository.insert_event_queue_row(stored)
            if db_id is None:
                return None
            stored["EVENT_QUEUE_ID"] = db_id
            return db_id
        except Exception as error:
            logger.error("event queue insert failed: %s", error)
            return None

    def get_event_queue_records(self) -> list[dict[str, Any]]:
        try:
            return [dict(row) for row in self._gs_event_queue]
        except Exception as error:
            logger.error("get event queue records failed: %s", error)
            return []

    def _notify_ui_normal(self, packet: dict[str, Any]) -> None:
        try:
            logger.info("normal telemetry received at %s", packet.get("UPDATED_AT"))
            from api.websocket_manager import ws_manager

            ws_manager.broadcast_sync(
                {
                    "type": "STATUS_NORMAL",
                    "timestamp": packet.get("UPDATED_AT"),
                }
            )
        except Exception as error:
            logger.error("normal UI notification failed: %s", error)

    def _memory_insert_dashboard(self, report: dict[str, Any]) -> None:
        """Append one dashboard row to in-memory tables without DB writes (replay preview)."""
        try:
            from ma_detector.core.ma_onboard_view import satellite_filter_from_ma_packet

            latest = self._telemetry_window[-1] if self._telemetry_window else {}
            filter_fields = satellite_filter_from_ma_packet(latest)
            target = filter_fields.get("SATELLITE_TARGET_SUBSYSTEM") or ""
            row = {
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
                "ACTION_MAPPING_STATUS": report.get("action_mapping_status", "mapped"),
                "TRIGGERED_RULE_IDS": list(report.get("triggered_rules", [])),
                "UNREGISTERED_ACTION_IDS": list(report.get("unregistered_action_ids", [])),
                "TRIGGERED_RULE_RESULTS": list(report.get("triggered_rule_results", [])),
                "MATCHES_SATELLITE_TARGET": report_matches_target(report, target, self._rule_registry),
                **filter_fields,
            }
            detect_id = self._next_detect_id
            self._next_detect_id += 1
            row["DETECT_ID"] = detect_id
            row["DASHBOARD_ID"] = detect_id
            self._dashboard_rows.append(row)

            detail = dict(latest)
            detail["DASHBOARD_ID"] = detect_id
            detail["DETECT_ID"] = detect_id
            detail["MA_CODE"] = report.get("ma_code")
            detail["ACTION_MAPPING_STATUS"] = report.get("action_mapping_status", "mapped")
            detail["TRIGGERED_RULE_RESULTS"] = list(report.get("triggered_rule_results", []))
            detail["UNREGISTERED_ACTION_IDS"] = list(report.get("unregistered_action_ids", []))
            self._detail_rows.append(detail)
        except Exception as error:
            logger.error("memory dashboard insert failed: %s", error)

    def _db_insert_dashboard(self, report: dict[str, Any]) -> None:
        try:
            from ma_detector.core.ma_onboard_view import satellite_filter_from_ma_packet

            latest = self._telemetry_window[-1] if self._telemetry_window else {}
            filter_fields = satellite_filter_from_ma_packet(latest)
            target = filter_fields.get("SATELLITE_TARGET_SUBSYSTEM") or ""
            row = {
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
                "ACTION_MAPPING_STATUS": report.get("action_mapping_status", "mapped"),
                "TRIGGERED_RULE_IDS": list(report.get("triggered_rules", [])),
                "UNREGISTERED_ACTION_IDS": list(report.get("unregistered_action_ids", [])),
                "TRIGGERED_RULE_RESULTS": list(report.get("triggered_rule_results", [])),
                "MATCHES_SATELLITE_TARGET": report_matches_target(report, target, self._rule_registry),
                **filter_fields,
            }
            detect_id = gs_repository.insert_dashboard_row(row)
            if detect_id is None:
                detect_id = self._next_detect_id
                self._next_detect_id += 1
            else:
                self._next_detect_id = max(self._next_detect_id, detect_id + 1)
            row["DETECT_ID"] = detect_id
            row["DASHBOARD_ID"] = detect_id
            self._dashboard_rows.append(row)

            detail = dict(latest)
            detail["DASHBOARD_ID"] = detect_id
            detail["DETECT_ID"] = detect_id
            detail["MA_CODE"] = report.get("ma_code")
            detail["ACTION_MAPPING_STATUS"] = report.get("action_mapping_status", "mapped")
            detail["TRIGGERED_RULE_RESULTS"] = list(report.get("triggered_rule_results", []))
            detail["UNREGISTERED_ACTION_IDS"] = list(report.get("unregistered_action_ids", []))
            detail_row = {
                "DASHBOARD_ID": detect_id,
                "DETECT_ID": detect_id,
                "MA_CODE": report.get("ma_code"),
                "ACTION_MAPPING_STATUS": report.get("action_mapping_status", "mapped"),
                "IMU_WBN_X": latest.get("IMU_WBN_X"),
                "IMU_WBN_Y": latest.get("IMU_WBN_Y"),
                "IMU_WBN_Z": latest.get("IMU_WBN_Z"),
                "QERR_0": latest.get("QERR_0"),
                "QERR_1": latest.get("QERR_1"),
                "QERR_2": latest.get("QERR_2"),
                "QERR_3": latest.get("QERR_3"),
                "MOMENTUM_NMS_0": latest.get("MOMENTUM_NMS_0"),
                "MOMENTUM_NMS_1": latest.get("MOMENTUM_NMS_1"),
                "MOMENTUM_NMS_2": latest.get("MOMENTUM_NMS_2"),
                "RAW_MAG_X": latest.get("RAW_MAG_X"),
                "RAW_MAG_Y": latest.get("RAW_MAG_Y"),
                "RAW_MAG_Z": latest.get("RAW_MAG_Z"),
                "TRIGGERED_RULE_RESULTS": list(report.get("triggered_rule_results", [])),
                "UNREGISTERED_ACTION_IDS": list(report.get("unregistered_action_ids", [])),
            }
            gs_repository.insert_detail_row(detail_row, detail)
            self._detail_rows.append(detail)
            if report.get("is_new_pattern"):
                self._db_set_new_pattern_flag(report, detect_id)
        except Exception as error:
            logger.error("dashboard row insert failed: %s", error)

    def _db_insert_discard_log(self, report: dict[str, Any]) -> None:
        try:
            entry = {"logged_at": datetime.now(timezone.utc).isoformat(), "report": dict(report)}
            self._discard_log.append(entry)
            if self._is_replay_mode:
                self._replay_buffer.append({"target": "DISCARD_LOG", "data": dict(report)})
                return
            gs_repository.insert_discard_log(report)
        except Exception as error:
            logger.error("discard log insert failed: %s", error)

    def _db_set_new_pattern_flag(self, report: dict[str, Any], detect_id: int | None = None) -> None:
        try:
            ma_code = str(report.get("ma_code", ""))
            self._known_patterns.add(ma_code)
            if detect_id is not None:
                gs_repository.update_new_pattern_flag(int(detect_id), ma_code)
        except Exception as error:
            logger.error("new pattern flag update failed: %s", error)

    def _db_query_dashboard(self, detect_id: int) -> dict[str, Any]:
        try:
            row = gs_repository.query_dashboard(int(detect_id))
            return dict(row) if row else {}
        except (TypeError, ValueError) as error:
            logger.error("dashboard query failed: %s", error)
            return {}
        except Exception as error:
            logger.error("unexpected dashboard query failure: %s", error)
            return {}

    def _db_query_detail(self, dashboard_id: int) -> list[dict[str, Any]]:
        try:
            return gs_repository.query_detail_rows(int(dashboard_id))
        except (TypeError, ValueError) as error:
            logger.error("detail query failed: %s", error)
            return []
        except Exception as error:
            logger.error("unexpected detail query failure: %s", error)
            return []

    def _db_query_history(self, detect_time: str) -> list[dict[str, Any]]:
        try:
            if detect_time:
                return gs_repository.query_detection_history_rows(detect_time)
            return gs_repository.load_recent_tlm_history(10)
        except Exception as error:
            logger.error("history query failed: %s", error)
            return []
