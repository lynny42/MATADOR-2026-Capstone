"""JSON-driven rule activation evaluation for MA integrated detection."""

from __future__ import annotations

import logging
from typing import Any

from ma_detector.core.baseline import BaselineManager

logger = logging.getLogger(__name__)


def merge_default_activations(rule_registry: dict[str, Any]) -> None:
    """Attach built-in activation presets when a rule has no activation block."""
    try:
        for rule_id, rule_def in rule_registry.items():
            if not isinstance(rule_def, dict):
                continue
            if rule_def.get("activation"):
                continue
            preset = default_activation_for_rule(rule_id)
            if preset:
                rule_def["activation"] = preset
    except Exception as error:
        logger.error("merge default activations failed: %s", error)


def default_activation_for_rule(rule_id: str) -> dict[str, Any] | None:
    """Return the default activation definition mirroring legacy evidence rules."""
    presets = _legacy_activation_presets()
    return presets.get(rule_id)


def evaluate_rule_activation(
    activation: dict[str, Any],
    window: list[dict[str, Any]],
    baseline_manager: BaselineManager,
    z_thresholds: dict[str, float],
    absolute_thresholds: dict[str, Any],
    legacy_evaluator: Any | None = None,
    rule_id: str = "",
) -> float:
    """Evaluate one rule activation spec and return a score in [0, 1]."""
    try:
        if activation.get("op") == "legacy_builtin":
            if legacy_evaluator is None or not rule_id:
                return 0.0
            return float(legacy_evaluator(rule_id, window))

        clauses = activation.get("clauses", [])
        if not clauses:
            return 0.0

        scores: list[float] = []
        for clause in clauses:
            if not isinstance(clause, dict):
                continue
            clause_score = _evaluate_clause(
                clause,
                window,
                baseline_manager,
                z_thresholds,
                absolute_thresholds,
            )
            weight = float(clause.get("weight", 0.0) or 0.0)
            scores.append(clause_score * weight)
        total = sum(scores)
        return max(0.0, min(total, 1.0))
    except Exception as error:
        logger.error("rule activation evaluation failed: %s", error)
        return 0.0


def _evaluate_clause(
    clause: dict[str, Any],
    window: list[dict[str, Any]],
    baseline_manager: BaselineManager,
    z_thresholds: dict[str, float],
    absolute_thresholds: dict[str, Any],
) -> float:
    try:
        op = str(clause.get("op", "")).strip()
        if op == "nonzero":
            column = str(clause.get("column", ""))
            return 1.0 if any(_numeric(snapshot, column) > 0 for snapshot in window) else 0.0
        if op == "mismatch":
            left = str(clause.get("left", ""))
            right = str(clause.get("right", ""))
            return 1.0 if any(snapshot.get(left) != snapshot.get(right) for snapshot in window) else 0.0
        if op == "equals_baseline":
            column = str(clause.get("column", ""))
            for snapshot in window:
                stats = baseline_manager.get_stats(snapshot, column)
                if snapshot.get(column) == stats.mean:
                    return 1.0
            return 0.0
        if op == "changed_from_baseline":
            column = str(clause.get("column", ""))
            for snapshot in window:
                stats = baseline_manager.get_stats(snapshot, column)
                if column in snapshot and snapshot.get(column) != stats.mean:
                    return 1.0
            return 0.0
        if op == "absolute_gt":
            column = str(clause.get("column", ""))
            threshold = clause.get("threshold")
            if threshold is None:
                key = str(clause.get("threshold_key", ""))
                threshold = absolute_thresholds.get(key, 0)
            threshold_value = float(threshold)
            return 1.0 if any(_numeric(snapshot, column) > threshold_value for snapshot in window) else 0.0
        if op == "z_max":
            column = str(clause.get("column", ""))
            direction = str(clause.get("direction", "increase"))
            return _z_max(window, column, direction, baseline_manager, z_thresholds)
        if op == "step_delta":
            column = str(clause.get("column", ""))
            direction = str(clause.get("direction", "increase"))
            min_percent = float(clause.get("min_delta_percent", 0.0) or 0.0)
            return _step_delta_score(window, column, direction, min_percent)
        if op == "qerr_spike":
            threshold = float(clause.get("threshold", 0.3) or 0.3)
            return 1.0 if any(
                any(abs(_numeric(snapshot, f"QERR_{index}")) > threshold for index in range(4))
                for snapshot in window
            ) else 0.0
        return 0.0
    except Exception as error:
        logger.error("clause evaluation failed: %s", error)
        return 0.0


def compute_step_change_percent(
    column: str,
    current: dict[str, Any],
    previous: dict[str, Any] | None,
) -> float | None:
    """Return percent change between consecutive 1-second snapshots in a series."""
    try:
        if previous is None:
            return None
        current_value = current.get(column)
        previous_value = previous.get(column)
        if not isinstance(current_value, (int, float)) or not isinstance(previous_value, (int, float)):
            return None
        if float(previous_value) == 0.0:
            return 0.0 if float(current_value) == 0.0 else 100.0
        change = ((float(current_value) - float(previous_value)) / abs(float(previous_value))) * 100.0
        return round(change, 2)
    except Exception as error:
        logger.error("step change percent failed for %s: %s", column, error)
        return None


def _step_delta_score(
    window: list[dict[str, Any]],
    column: str,
    direction: str,
    min_percent: float,
) -> float:
    """Score the strongest consecutive-snapshot delta inside the analysis series."""
    try:
        if len(window) < 2:
            return 0.0
        best_score = 0.0
        for index in range(1, len(window)):
            previous = window[index - 1]
            current = window[index]
            change = compute_step_change_percent(column, current, previous)
            if change is None:
                continue
            signed = float(change)
            if direction == "decrease":
                signed = -signed
            if signed <= 0:
                continue
            if signed < min_percent:
                pair_score = min(0.3, signed / max(min_percent, 1.0))
            else:
                pair_score = min(1.0, signed / 100.0)
            best_score = max(best_score, pair_score)
        return best_score
    except Exception as error:
        logger.error("step delta score failed for %s: %s", column, error)
        return 0.0


def _z_max(
    window: list[dict[str, Any]],
    column: str,
    direction: str,
    baseline_manager: BaselineManager,
    z_thresholds: dict[str, float],
) -> float:
    try:
        scores: list[float] = []
        for snapshot in window:
            if column not in snapshot or not isinstance(snapshot[column], (int, float)):
                continue
            stats = baseline_manager.get_stats(snapshot, column)
            z_value = baseline_manager.compute_z(float(snapshot[column]), stats)
            scores.append(_z_to_score(z_value, direction, z_thresholds))
        return max(scores) if scores else 0.0
    except Exception as error:
        logger.error("z max failed for %s: %s", column, error)
        return 0.0


def _z_to_score(z: float, direction: str, z_thresholds: dict[str, float]) -> float:
    try:
        signed = z if direction == "increase" else -z
        soft = float(z_thresholds["SOFT"])
        hard = float(z_thresholds["HARD"])
        severe = float(z_thresholds["SEVERE"])
        if signed < soft:
            return 0.0
        if signed < hard:
            return min(0.3 + (signed - soft) * 0.3, 0.6)
        if signed < severe:
            return min(0.6 + (signed - hard) * 0.3, 0.9)
        return 1.0
    except Exception as error:
        logger.error("z to score failed: %s", error)
        return 0.0


def _numeric(snapshot: dict[str, Any], column: str, default: float = 0.0) -> float:
    try:
        value = snapshot.get(column, default)
        return float(value) if isinstance(value, (int, float)) else default
    except Exception as error:
        logger.error("numeric conversion failed for %s: %s", column, error)
        return default


def _legacy_activation_presets() -> dict[str, dict[str, Any]]:
    """Preset activation blocks editable in Replay (window_mode=snapshot_series)."""
    series_mode = "snapshot_series"
    return {
        "E-01": {
            "window_mode": series_mode,
            "clauses": [
                {"op": "nonzero", "column": "CH1_FAULT_CRC", "weight": 0.35},
                {"op": "nonzero", "column": "CH1_FAULT_FILE_SIZE_MISMATCH", "weight": 0.25},
                {"op": "step_delta", "column": "CHILDQUEUECOUNT", "direction": "increase", "weight": 0.20},
                {"op": "step_delta", "column": "FILEWRITEERRCOUNTER", "direction": "increase", "weight": 0.20},
            ],
        },
        "E-02": {
            "window_mode": series_mode,
            "clauses": [
                {"op": "step_delta", "column": "CMDREJECTEDCOUNTER", "direction": "increase", "weight": 0.45},
                {"op": "step_delta", "column": "PIPEOVERFLOWRRCNT", "direction": "increase", "weight": 0.30},
                {"op": "step_delta", "column": "COMBINEDPACKETSSENT", "direction": "decrease", "weight": 0.25},
            ],
        },
        "E-03": {
            "window_mode": series_mode,
            "clauses": [
                {"op": "mismatch", "left": "OBC_P_HASH", "right": "EXPECTED_CRC", "weight": 0.40},
                {"op": "step_delta", "column": "APPCSERRCOUNTER", "direction": "increase", "weight": 0.20},
                {"op": "step_delta", "column": "OSCSERRCOUNTER", "direction": "increase", "weight": 0.20},
                {"op": "changed_from_baseline", "column": "LASTVALCRC", "weight": 0.20},
            ],
        },
        "E-04": {
            "window_mode": series_mode,
            "clauses": [
                {"op": "step_delta", "column": "HEAP_FREE", "direction": "decrease", "weight": 0.40},
                {"op": "step_delta", "column": "MEMINUSE", "direction": "increase", "weight": 0.35},
                {"op": "step_delta", "column": "EXECOUNTS", "direction": "increase", "weight": 0.25},
            ],
        },
        "E-05": {"window_mode": series_mode, "op": "legacy_builtin"},
        "E-06": {
            "window_mode": series_mode,
            "clauses": [
                {"op": "absolute_gt", "column": "UTILCPUAVG", "threshold_key": "UTILCPUAVG_HIGH", "weight": 0.50},
                {"op": "step_delta", "column": "SKIPPEDSLOTSCOUNT", "direction": "increase", "weight": 0.25},
                {"op": "step_delta", "column": "ERLOGENTRIES", "direction": "increase", "weight": 0.25},
            ],
        },
        "E-07": {
            "window_mode": series_mode,
            "clauses": [
                {"op": "changed_from_baseline", "column": "DWELL_MASK", "weight": 0.35},
                {"op": "step_delta", "column": "DWELL_ADDR_COUNT", "direction": "increase", "weight": 0.35},
                {"op": "step_delta", "column": "DWELL_BYTE_COUNT", "direction": "increase", "weight": 0.30},
            ],
        },
        "E-08": {
            "window_mode": series_mode,
            "clauses": [
                {"op": "step_delta", "column": "COMBINEDPACKETSSENT", "direction": "increase", "weight": 0.45},
                {"op": "step_delta", "column": "ENABLEDROUTES", "direction": "increase", "weight": 0.30},
                {"op": "step_delta", "column": "FORWARD_ERR_COUNT", "direction": "increase", "weight": 0.25},
            ],
        },
        "E-09": {
            "window_mode": series_mode,
            "clauses": [
                {"op": "qerr_spike", "weight": 0.35},
                {"op": "step_delta", "column": "TCMD_X", "direction": "increase", "weight": 0.083},
                {"op": "step_delta", "column": "TCMD_Y", "direction": "increase", "weight": 0.083},
                {"op": "step_delta", "column": "TCMD_Z", "direction": "increase", "weight": 0.084},
                {"op": "step_delta", "column": "MOMENTUM_NMS_0", "direction": "increase", "weight": 0.083},
                {"op": "step_delta", "column": "MOMENTUM_NMS_1", "direction": "increase", "weight": 0.083},
                {"op": "step_delta", "column": "MOMENTUM_NMS_2", "direction": "increase", "weight": 0.084},
                {"op": "step_delta", "column": "DEVICE_ERR_RW0", "direction": "increase", "weight": 0.05},
                {"op": "step_delta", "column": "DEVICE_ERR_RW1", "direction": "increase", "weight": 0.05},
                {"op": "step_delta", "column": "DEVICE_ERR_RW2", "direction": "increase", "weight": 0.05},
            ],
        },
        "E-10": {
            "window_mode": series_mode,
            "clauses": [
                {"op": "step_delta", "column": "BATT_VOLTAGE", "direction": "decrease", "weight": 0.40},
                {"op": "step_delta", "column": "BUS_3P3V", "direction": "increase", "weight": 0.15},
                {"op": "step_delta", "column": "BUS_5P0V", "direction": "increase", "weight": 0.15},
                {"op": "step_delta", "column": "SW_0_CURRENT", "direction": "increase", "weight": 0.15},
                {"op": "step_delta", "column": "SW_1_CURRENT", "direction": "increase", "weight": 0.15},
            ],
        },
        "E-11": {"window_mode": series_mode, "op": "legacy_builtin"},
        "E-12": {"window_mode": series_mode, "op": "legacy_builtin"},
        "E-13": {"window_mode": series_mode, "op": "legacy_builtin"},
        "E-X1": {"window_mode": series_mode, "op": "legacy_builtin"},
        "E-X2": {"window_mode": series_mode, "op": "legacy_builtin"},
        "E-X3": {"window_mode": series_mode, "op": "legacy_builtin"},
        "E-X4": {"window_mode": series_mode, "op": "legacy_builtin"},
        "E-X5": {"window_mode": series_mode, "op": "legacy_builtin"},
    }
