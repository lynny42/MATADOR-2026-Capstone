"""Satellite target_subsystem emphasis helpers (UI ordering, not rule filtering)."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

CORE_SUBSYSTEMS = ("OBC", "TCS", "EPS", "ADCS", "COM")

# Inferred from cFS app tags in rule_registry + capstone focus (OBC/ADCS/EPS/COM/TCS).
TARGET_EMPHASIS: dict[str, dict[str, set[str]]] = {
    "OBC": {
        "rule_tags": {"OBC", "CF", "CS", "DS", "ES", "MD", "SB", "SCH", "TBL", "HK"},
        "module_tokens": {"OBC", "CF", "CS", "MD", "SB", "SCH", "TBL", "DS", "ES"},
    },
    "ADCS": {
        "rule_tags": {"ADCS"},
        "module_tokens": {"ADCS"},
    },
    "EPS": {
        "rule_tags": {"EPS"},
        "module_tokens": {"EPS"},
    },
    "COM": {
        "rule_tags": {"COM", "CI", "TO", "HK"},
        "module_tokens": {"COM", "TO", "CI", "HK"},
    },
    "TCS": {
        "rule_tags": {"TCS", "HS"},
        "module_tokens": {"TCS", "HS"},
    },
}

# Power channel hints when only sw_id_list is present (Arduino/capstone SW 0~3).
SW_ID_DEFAULT_SUBSYSTEM: dict[int, str] = {
    0: "EPS",
    1: "OBC",
    2: "ADCS",
    3: "COM",
}

EXCEPTION_LIKELIHOOD_HINTS: dict[str, str] = {
    "GHOST_TELEMETRY_PATTERN": "ADCS/EPS/COM 교차 Ghost Telemetry — 센서 고착·버스·전달 오류 동시 의심",
    "GHOST_TELEMETRY_ADCS_EPS_COM": "ADCS/EPS/COM 교차 Ghost Telemetry — IMU 분산 고착·버스·전달 오류 동시 의심",
    "NO_RESET_HASH_MISMATCH": "OBC/CF 무결성 변조 — 리셋 없이 해시 불일치 지속",
    "COMMAND_REJECT_AND_ROUTE_SURGE": "COM/SB 명령 거부·라우트 급증 — 비인가 명령·외부 송신 이상 의심",
    "SAA_SINGLE_EVENT_UPSET": "단발 SEU 가능성 — Rule 단독 신호와 교차 확인 권장",
}


def normalize_target_subsystem(value: Any) -> str:
    """Return a trimmed target subsystem token or empty string."""
    try:
        if value is None:
            return ""
        return str(value).strip().upper()
    except Exception as error:
        logger.error("target normalization failed: %s", error)
        return ""


def infer_target_from_sw_ids(sw_id_list: Any) -> str:
    """Infer a primary subsystem label from power switch ids when target is missing."""
    try:
        if not isinstance(sw_id_list, list) or not sw_id_list:
            return ""
        mapped = [SW_ID_DEFAULT_SUBSYSTEM.get(int(item)) for item in sw_id_list]
        mapped = [item for item in mapped if item]
        if not mapped:
            return ""
        return mapped[0]
    except (TypeError, ValueError) as error:
        logger.error("sw_id target inference failed: %s", error)
        return ""
    except Exception as error:
        logger.error("unexpected sw_id target inference failure: %s", error)
        return ""


def infer_adcs_attack_target(
    snapshot: dict[str, Any],
    thresholds: dict[str, Any] | None = None,
) -> str:
    """Return ADCS when onboard false-positive or ADCS filter signals indicate ADCS attack."""
    try:
        section = thresholds or {}
        exception_codes = section.get("EXCEPTION_CODES", [1, 2, 3, 4])
        qerr_threshold = float(section.get("QERR_ABS_THRESHOLD", 0.15))
        tcmd_threshold = float(section.get("TCMD_ABS_THRESHOLD", 0.05))
        appcs_min = int(section.get("APPCSERRCOUNTER_MIN", 1))

        exception_code = int(snapshot.get("EXCEPTION_CODE", snapshot.get("FALSE_POSITIVE_EXCEPTION", 0)) or 0)
        if exception_code in exception_codes:
            return "ADCS"

        adcs_filter = snapshot.get("adcs_filter", snapshot.get("ADCS_FILTER", {}))
        if not isinstance(adcs_filter, dict):
            adcs_filter = {}

        qerr_values = [
            float(adcs_filter.get(f"QERR_{idx}", snapshot.get(f"QERR_{idx}", 0)) or 0)
            for idx in range(4)
        ]
        if max(abs(value) for value in qerr_values) >= qerr_threshold:
            return "ADCS"

        tcmd_values = [
            abs(float(adcs_filter.get(axis, snapshot.get(axis, 0)) or 0))
            for axis in ("TCMD_X", "TCMD_Y", "TCMD_Z")
        ]
        if max(tcmd_values) >= tcmd_threshold:
            return "ADCS"

        if int(snapshot.get("APPCSERRCOUNTER", 0) or 0) >= appcs_min:
            return "ADCS"

        return ""
    except (TypeError, ValueError) as error:
        logger.error("adcs attack target inference failed: %s", error)
        return ""
    except Exception as error:
        logger.error("unexpected adcs attack target inference failure: %s", error)
        return ""


def is_cross_link_rule(rule_def: dict[str, Any]) -> bool:
    """Return True when a rule spans multiple subsystem tags (always evaluated)."""
    try:
        subsystems = rule_def.get("subsystems", [])
        if isinstance(subsystems, list) and len(subsystems) > 1:
            return True
        name = str(rule_def.get("name", ""))
        return "연계" in name or "↔" in name
    except Exception as error:
        logger.error("cross-link rule check failed: %s", error)
        return False


def expand_module_tokens(module: str) -> set[str]:
    """Split composite module labels such as OBC+CF or MD,TO,ES."""
    try:
        raw_parts = module.replace(",", "+").split("+")
        return {part.strip().upper() for part in raw_parts if part.strip()}
    except Exception as error:
        logger.error("module token expansion failed: %s", error)
        return set()


def report_matches_target(
    report: dict[str, Any],
    target: str,
    rule_registry: dict[str, Any] | None = None,
) -> bool:
    """Return True when an MA report is related to the satellite 1st-pass target."""
    try:
        normalized_target = normalize_target_subsystem(target)
        if not normalized_target:
            return False

        emphasis = TARGET_EMPHASIS.get(normalized_target, {})
        module_tokens = expand_module_tokens(str(report.get("module", "")))
        if module_tokens & emphasis.get("module_tokens", set()):
            return True
        if normalized_target in module_tokens:
            return True

        triggered_rules = report.get("triggered_rules", [])
        if isinstance(rule_registry, dict):
            for rule_id in triggered_rules:
                rule = rule_registry.get(rule_id, {})
                rule_tags = set(rule.get("subsystems", []))
                if rule_tags & emphasis.get("rule_tags", set()):
                    return True
                if is_cross_link_rule(rule) and normalized_target in CORE_SUBSYSTEMS:
                    if rule_tags & emphasis.get("rule_tags", set()) or len(rule_tags) > 1:
                        return True

        ma_code = str(report.get("ma_code", "")).upper()
        if normalized_target in ma_code:
            return True
        return False
    except Exception as error:
        logger.error("target match check failed: %s", error)
        return False


def sort_reports_by_target(
    reports: list[dict[str, Any]],
    target: str,
    rule_registry: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Sort MA reports so target-related entries appear first, then by confidence."""
    try:
        return sorted(
            reports,
            key=lambda item: (
                0 if report_matches_target(item, target, rule_registry) else 1,
                -float(item.get("confidence_score", 0.0) or 0.0),
            ),
        )
    except Exception as error:
        logger.error("report target sort failed: %s", error)
        return reports


def build_novel_attack_advisory(
    packet: dict[str, Any],
    reports: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Build UI advisory when attack(Y) has no mapped Action in the registry (B-3)."""
    try:
        undefined_reports = [
            report
            for report in reports
            if report.get("action_mapping_status") == "undefined" or report.get("is_new_pattern")
        ]
        if not undefined_reports:
            return None

        exception_code = str(packet.get("FALSE_POSITIVE_EXCEPTION", "") or "").strip()
        target = normalize_target_subsystem(packet.get("TARGET_SUBSYSTEM"))
        likelihood = EXCEPTION_LIKELIHOOD_HINTS.get(
            exception_code,
            "Rule 근거는 있으나 action_registry에 연결된 Action이 없습니다.",
        )
        triggered_rules: list[str] = []
        unregistered_action_ids: list[str] = []
        for report in undefined_reports:
            triggered_rules.extend(report.get("triggered_rules", []))
            unregistered_action_ids.extend(report.get("unregistered_action_ids", []))
        triggered_rules = sorted(set(triggered_rules))
        unregistered_action_ids = sorted(set(unregistered_action_ids))
        codes = [str(item.get("ma_code", "")) for item in undefined_reports if item.get("ma_code")]
        return {
            "title": "등록된 Action 없음 (공격 Y만 확인)",
            "message": (
                "위성 오탐필터는 공격(Y)으로 판정했으나, 지상 action_registry에 매핑된 Action이 없습니다. "
                "Rule Lab에서 Action을 추가하고 Rule의 contributes_to에 연결한 뒤 Replay하세요. "
                f"참고: {likelihood}"
            ),
            "register_action_hint": (
                "action_registry.json에 Action(이름·module·phase)을 추가하고, "
                "발화한 Rule의 contributes_to에 action_id를 지정하세요."
            ),
            "exception_code": exception_code or None,
            "target_subsystem": target or None,
            "related_ma_codes": codes,
            "triggered_rules": triggered_rules,
            "unregistered_action_ids": unregistered_action_ids,
            "report_count": len(undefined_reports),
        }
    except Exception as error:
        logger.error("novel advisory build failed: %s", error)
        return None
