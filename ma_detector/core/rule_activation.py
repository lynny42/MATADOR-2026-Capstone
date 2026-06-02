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


def _activation_eval_window(activation: dict[str, Any], window: list[dict[str, Any]]) -> list[dict[str, Any]]:
    try:
        window_mode = str(activation.get("window_mode", "snapshot_series")).strip()
        if window_mode == "step" and len(window) >= 2:
            return window[-2:]
        return window
    except Exception as error:
        logger.error("activation eval window failed: %s", error)
        return window


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
        explained = explain_rule_activation(
            activation,
            window,
            baseline_manager,
            z_thresholds,
            absolute_thresholds,
            legacy_evaluator=legacy_evaluator,
            rule_id=rule_id,
        )
        return float(explained.get("rule_score", 0.0) or 0.0)
    except Exception as error:
        logger.error("rule activation evaluation failed: %s", error)
        return 0.0


def explain_rule_activation(
    activation: dict[str, Any],
    window: list[dict[str, Any]],
    baseline_manager: BaselineManager,
    z_thresholds: dict[str, float],
    absolute_thresholds: dict[str, Any],
    *,
    legacy_evaluator: Any | None = None,
    rule_id: str = "",
    rule_name: str = "",
) -> dict[str, Any]:
    """Return rule score plus per-clause activation reasons for the UI."""
    try:
        if activation.get("op") == "legacy_builtin":
            score = 0.0
            if legacy_evaluator is not None and rule_id:
                score = float(legacy_evaluator(rule_id, window))
            hint = _legacy_rule_hint(rule_id, rule_name)
            return {
                "rule_score": round(score, 4),
                "triggered": score > 0.0,
                "clauses": [
                    {
                        "index": 0,
                        "op": "legacy_builtin",
                        "label": "내장 Evidence 룰",
                        "passed": score > 0.0,
                        "clause_score": round(score, 4),
                        "weight": 1.0,
                        "contribution": round(score, 4),
                        "reason": hint,
                    }
                ],
                "summary": hint if score > 0.0 else "이 시점 윈도우에서 내장 룰 임계치 미달",
            }

        eval_window = _activation_eval_window(activation, window)
        clauses = activation.get("clauses", [])
        if not clauses:
            return {
                "rule_score": 0.0,
                "triggered": False,
                "clauses": [],
                "summary": "activation 정의에 clause가 없습니다",
            }

        explained_clauses: list[dict[str, Any]] = []
        total = 0.0
        for index, clause in enumerate(clauses):
            if not isinstance(clause, dict):
                continue
            item = _explain_clause(
                clause,
                eval_window,
                baseline_manager,
                z_thresholds,
                absolute_thresholds,
            )
            weight = float(clause.get("weight", 0.0) or 0.0)
            contribution = float(item.get("clause_score", 0.0) or 0.0) * weight
            total += contribution
            explained_clauses.append(
                {
                    "index": index,
                    "op": str(clause.get("op", "")),
                    "label": str(item.get("label", clause.get("op", "clause"))),
                    "passed": contribution > 0.01,
                    "clause_score": round(float(item.get("clause_score", 0.0) or 0.0), 4),
                    "weight": round(weight, 4),
                    "contribution": round(contribution, 4),
                    "delta_percent": item.get("delta_percent"),
                    "delta_display": item.get("delta_display"),
                    "reason": str(item.get("reason", "")),
                }
            )

        rule_score = max(0.0, min(total, 1.0))
        passed_reasons = [item["reason"] for item in explained_clauses if item.get("passed") and item.get("reason")]
        summary = " · ".join(passed_reasons) if passed_reasons else "조건 미충족"
        return {
            "rule_score": round(rule_score, 4),
            "triggered": rule_score > 0.0,
            "clauses": explained_clauses,
            "summary": summary,
        }
    except Exception as error:
        logger.error("rule activation explain failed: %s", error)
        return {
            "rule_score": 0.0,
            "triggered": False,
            "clauses": [],
            "summary": str(error),
        }


def _legacy_rule_hint(rule_id: str, rule_name: str) -> str:
    hints = {
        "E-05": "리셋 없이 무결성 오류·해시 불일치가 동시에 지속",
        "E-11": "IMU 분산 급감·전력 상승 등 센서 재생(고스트 텔레메트리) 패턴",
        "E-12": "이벤트 로그·CRC·큐 카운터 동시 이상",
        "E-X3": "SEU 위장형: 해시 불일치·리셋·힙/CPU 복합 징후",
        "P1-X01": "Phase1 복합: CRC·큐·전력·로그 동시 급증",
        "P3-X01": "QERR·TCMD·토커 동시 이상 (자세 제어 변조 의심)",
        "S2-X01": "WBN 고착 + QERR 급증 (센서-자세 불일치)",
    }
    if rule_id in hints:
        return hints[rule_id]
    if rule_name:
        return f"{rule_name} 내장 조건 충족"
    return "내장 Evidence 룰 점수 기준 충족"


def _explain_clause(
    clause: dict[str, Any],
    window: list[dict[str, Any]],
    baseline_manager: BaselineManager,
    z_thresholds: dict[str, float],
    absolute_thresholds: dict[str, Any],
) -> dict[str, Any]:
    try:
        op = str(clause.get("op", "")).strip()
        latest = window[-1] if window else {}
        if op == "nonzero":
            column = str(clause.get("column", ""))
            values = [_numeric(snapshot, column) for snapshot in window]
            hit = any(value > 0 for value in values)
            return {
                "clause_score": 1.0 if hit else 0.0,
                "label": f"{column} > 0",
                "reason": f"{column} 비영(0 초과) 스냅샷 존재 (최신={values[-1] if values else 0})"
                if hit
                else f"{column}가 0인 상태만 관측됨",
            }
        if op == "mismatch":
            left = str(clause.get("left", ""))
            right = str(clause.get("right", ""))
            pairs = [(snapshot.get(left), snapshot.get(right)) for snapshot in window]
            hit = any(left_value != right_value for left_value, right_value in pairs)
            latest_left, latest_right = pairs[-1] if pairs else (None, None)
            return {
                "clause_score": 1.0 if hit else 0.0,
                "label": f"{left} ≠ {right}",
                "reason": f"불일치: {left}={latest_left}, {right}={latest_right}"
                if hit
                else f"{left}와 {right}가 일치함",
            }
        if op == "equals_baseline":
            column = str(clause.get("column", ""))
            stats = baseline_manager.get_stats(latest, column)
            value = latest.get(column)
            hit = value == stats.mean
            return {
                "clause_score": 1.0 if hit else 0.0,
                "label": f"{column} = baseline",
                "reason": f"{column}={value}, baseline={stats.mean}"
                if hit
                else f"{column}={value}, baseline={stats.mean} (불일치)",
            }
        if op == "changed_from_baseline":
            column = str(clause.get("column", ""))
            stats = baseline_manager.get_stats(latest, column)
            value = latest.get(column)
            hit = column in latest and value != stats.mean
            return {
                "clause_score": 1.0 if hit else 0.0,
                "label": f"{column} baseline 이탈",
                "reason": f"{column}={value}, baseline={stats.mean}"
                if hit
                else f"{column}가 baseline과 동일",
            }
        if op == "absolute_gt":
            column = str(clause.get("column", ""))
            threshold = clause.get("threshold")
            if threshold is None:
                key = str(clause.get("threshold_key", ""))
                threshold = absolute_thresholds.get(key, 0)
            threshold_value = float(threshold)
            observed = _numeric(latest, column)
            hit = observed > threshold_value
            return {
                "clause_score": 1.0 if hit else 0.0,
                "label": f"{column} > {threshold_value}",
                "reason": f"{column}={observed} (임계 {threshold_value})",
            }
        if op == "z_max":
            column = str(clause.get("column", ""))
            direction = str(clause.get("direction", "increase"))
            score = _z_max(window, column, direction, baseline_manager, z_thresholds)
            stats = baseline_manager.get_stats(latest, column)
            z_value = baseline_manager.compute_z(_numeric(latest, column), stats)
            return {
                "clause_score": score,
                "label": f"{column} z-score σ ({direction})",
                "reason": (
                    f"baseline 대비 z={z_value:.2f}σ → 정규화 점수 {score:.2f} "
                    f"(SOFT={z_thresholds.get('SOFT')}σ, % 아님)"
                ),
            }
        if op == "step_delta":
            column = str(clause.get("column", ""))
            direction = str(clause.get("direction", "increase"))
            min_percent = float(clause.get("min_delta_percent", 0.0) or 0.0)
            score, best_previous, best_current = _step_delta_best_pair(
                window,
                column,
                direction,
                min_percent,
            )
            delta_percent = None
            delta_display = None
            if best_previous is not None and best_current is not None:
                reason = format_step_change_reason(
                    column,
                    best_current,
                    best_previous,
                    direction=direction,
                    min_percent=min_percent,
                )
                delta_percent, delta_display = _step_delta_display(
                    column,
                    best_current,
                    best_previous,
                )
                if delta_display:
                    label = f"{column} 직전1초 {delta_display} ({direction})"
                else:
                    label = f"{column} 직전1초 변화 ({direction})"
            else:
                reason = "윈도우 내 유의미한 연속 변화 없음"
                label = f"{column} 직전1초 변화 없음"
            return {
                "clause_score": score,
                "label": label,
                "delta_percent": delta_percent,
                "delta_display": delta_display,
                "reason": reason,
            }
        if op == "qerr_spike":
            threshold = float(clause.get("threshold", 0.3) or 0.3)
            max_qerr = max(
                abs(_numeric(snapshot, f"QERR_{index}"))
                for snapshot in window
                for index in range(4)
            )
            hit = max_qerr > threshold
            return {
                "clause_score": 1.0 if hit else 0.0,
                "label": f"QERR spike > {threshold}",
                "reason": f"max|QERR|={max_qerr:.3f} (임계 {threshold})",
            }
        if op == "repeat_ratio":
            column = str(clause.get("column", ""))
            min_ratio = float(clause.get("min_ratio", 0.1) or 0.1)
            score = repeat_ratio_score(window, column, min_ratio)
            hits = sum(1 for snapshot in window if _numeric(snapshot, column) > 0.0)
            ratio = hits / len(window) if window else 0.0
            return {
                "clause_score": score,
                "label": f"{column} repeat_ratio",
                "reason": (
                    f"윈도우 {hits}/{len(window)}샘플 비영 "
                    f"({ratio * 100.0:.1f}%, 최소 {min_ratio * 100.0:.1f}%)"
                ),
            }
        return {"clause_score": 0.0, "label": op or "unknown", "reason": "지원하지 않는 op"}
    except Exception as error:
        logger.error("clause explain failed: %s", error)
        return {"clause_score": 0.0, "label": "error", "reason": str(error)}


def _evaluate_clause(
    clause: dict[str, Any],
    window: list[dict[str, Any]],
    baseline_manager: BaselineManager,
    z_thresholds: dict[str, float],
    absolute_thresholds: dict[str, Any],
) -> float:
    try:
        explained = _explain_clause(
            clause,
            window,
            baseline_manager,
            z_thresholds,
            absolute_thresholds,
        )
        return float(explained.get("clause_score", 0.0) or 0.0)
    except Exception as error:
        logger.error("clause evaluation failed: %s", error)
        return 0.0


def repeat_ratio_score(
    window: list[dict[str, Any]],
    column: str,
    min_ratio: float = 0.1,
) -> float:
    """Return 0..1 score from the fraction of snapshots where column is non-zero."""
    try:
        if not window or not column:
            return 0.0
        hits = sum(1 for snapshot in window if _numeric(snapshot, column) > 0.0)
        ratio = hits / len(window)
        if ratio < min_ratio:
            return min(0.35, ratio / max(min_ratio, 1e-6))
        return min(1.0, ratio / max(min_ratio * 2.0, min_ratio + 1e-6))
    except Exception as error:
        logger.error("repeat ratio score failed for %s: %s", column, error)
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
        current_value = _numeric(current, column)
        previous_value = _numeric(previous, column)
        if float(previous_value) == 0.0:
            if float(current_value) == 0.0:
                return 0.0
            return None
        change = ((float(current_value) - float(previous_value)) / abs(float(previous_value))) * 100.0
        return round(change, 2)
    except Exception as error:
        logger.error("step change percent failed for %s: %s", column, error)
        return None


def _step_delta_display(
    column: str,
    current: dict[str, Any],
    previous: dict[str, Any],
) -> tuple[float | None, str | None]:
    """Return (raw_percent, display_text) for the best step pair."""
    try:
        previous_value = _numeric(previous, column)
        current_value = _numeric(current, column)
        if float(previous_value) == 0.0:
            if float(current_value) == 0.0:
                return 0.0, "0%"
            return None, f"{previous_value:g}→{current_value:g}"
        change = compute_step_change_percent(column, current, previous)
        if change is None:
            return None, None
        return float(change), f"{change:+.1f}%"
    except Exception as error:
        logger.error("step delta display failed for %s: %s", column, error)
        return None, None


def format_step_change_reason(
    column: str,
    current: dict[str, Any],
    previous: dict[str, Any],
    *,
    direction: str = "increase",
    min_percent: float = 0.0,
) -> str:
    """Human-readable delta text; avoids misleading 100% when the previous value was zero."""
    try:
        current_value = _numeric(current, column)
        previous_value = _numeric(previous, column)
        previous_at = previous.get("UPDATED_AT", "?")
        current_at = current.get("UPDATED_AT", "?")
        if float(previous_value) == 0.0:
            if float(current_value) == 0.0:
                return f"{previous_at}→{current_at}: {column} 0→0 (변화 없음)"
            return (
                f"{previous_at}→{current_at}: {column} "
                f"{previous_value:g}→{current_value:g} (이전값 0, % 대신 절대 증가)"
            )
        change = compute_step_change_percent(column, current, previous)
        if change is None:
            return f"{previous_at}→{current_at}: {column} 변화 없음"
        signed = float(change)
        if direction == "decrease":
            signed = -signed
        if signed <= 0:
            return (
                f"{previous_at}→{current_at}: {column} "
                f"{previous_value:g}→{current_value:g} ({change:+.1f}%, {direction} 방향 미충족)"
            )
        threshold_note = f", 임계 {min_percent:g}%" if min_percent > 0 else ""
        return (
            f"{previous_at}→{current_at}: {column} "
            f"{previous_value:g}→{current_value:g} ({change:+.1f}%{threshold_note})"
        )
    except Exception as error:
        logger.error("step change reason format failed for %s: %s", column, error)
        return f"{column} 변화 설명 생성 실패"


def _step_delta_best_pair(
    window: list[dict[str, Any]],
    column: str,
    direction: str,
    min_percent: float,
) -> tuple[float, dict[str, Any] | None, dict[str, Any] | None]:
    """Return (score, previous_snapshot, current_snapshot) for the strongest qualifying step."""
    try:
        if len(window) < 2:
            return 0.0, None, None
        best_score = 0.0
        best_previous: dict[str, Any] | None = None
        best_current: dict[str, Any] | None = None
        for index in range(1, len(window)):
            previous = window[index - 1]
            current = window[index]
            change = compute_step_change_percent(column, current, previous)
            if change is None:
                previous_value = _numeric(previous, column)
                current_value = _numeric(current, column)
                if float(previous_value) == 0.0 and float(current_value) > 0.0:
                    pair_score = min(1.0, float(current_value) / max(min_percent, 1.0))
                    if direction != "decrease" and pair_score > best_score:
                        best_score = pair_score
                        best_previous = previous
                        best_current = current
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
            if pair_score > best_score:
                best_score = pair_score
                best_previous = previous
                best_current = current
        return best_score, best_previous, best_current
    except Exception as error:
        logger.error("step delta best pair failed for %s: %s", column, error)
        return 0.0, None, None


def _step_delta_score(
    window: list[dict[str, Any]],
    column: str,
    direction: str,
    min_percent: float,
) -> float:
    """Score the strongest consecutive-snapshot delta inside the analysis series."""
    try:
        score, _, _ = _step_delta_best_pair(window, column, direction, min_percent)
        return score
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
                {"op": "repeat_ratio", "column": "CH1_FAULT_CRC", "min_ratio": 0.1, "weight": 0.35},
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
                {"op": "step_delta", "column": "HEAP_FREE", "direction": "decrease", "weight": 0.60},
                {"op": "step_delta", "column": "EXECOUNTS", "direction": "increase", "weight": 0.40},
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
                {"op": "changed_from_baseline", "column": "DWELL_MASK", "weight": 1.0},
            ],
        },
        "E-08": {
            "window_mode": series_mode,
            "clauses": [
                {"op": "step_delta", "column": "ENABLEDROUTES", "direction": "increase", "weight": 0.55},
                {"op": "step_delta", "column": "FORWARD_ERR_COUNT", "direction": "increase", "weight": 0.45},
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
                {"op": "step_delta", "column": "SW_0_CURRENT", "direction": "increase", "weight": 0.50},
                {"op": "step_delta", "column": "SW_1_CURRENT", "direction": "increase", "weight": 0.50},
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
        "P1-X01": {"window_mode": series_mode, "op": "legacy_builtin"},
        "P3-X01": {"window_mode": series_mode, "op": "legacy_builtin"},
        "S2-X01": {"window_mode": series_mode, "op": "legacy_builtin"},
    }
