"""
지상국 SEU_SIM → 오탐 필터링(SEU) 시연 오케스트레이션.

ATTACK_SIM / ATTACK_HASH / RECOVERY(AttackSimulator) 와 별도로,
자이로·서보 실부하(INA226) 후 전력 이상 시 FPF 가 N(SEU) 판정을 내리도록
가중치·on_anomaly_detected 패치·ADCS 논리 복원을 적용한다.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, Protocol

from .. import config as demon_config
from ..core.context import RuntimeContext
from .false_positive_filter import config as fpf_config
from .false_positive_filter.fpf_scenario_injector import (
    inject_natural_adcs_tlm_bypass,
    is_attack_adcs_row,
)

logger = logging.getLogger(__name__)


class AttackSimulatorLike(Protocol):
    def start_seu_physical(self) -> bool:
        ...


class FalsePositiveFilterLike(Protocol):
    weights: dict[str, float]
    seu_experiment_mode: bool
    physical: Any
    system: Any

    def on_anomaly_detected(self, key_set: dict[str, Any]) -> None:
        ...


class AnomalyDetectorLike(Protocol):
    def reset_fpf_episode(self) -> None:
        ...

    def _refresh_series_buffers(self) -> None:
        ...


class FpfSimulator:
    """
    GScomms.handle_seu_sim / handle_recovery 에서 호출.

    start_seu(): SEU 물리 부하 + FPF SEU 모드(가중치·key_set 패치)
    stop(): FPF 패치·가중치 복원 (RECOVERY 시 AttackSimulator.stop 과 함께)
    """

    def __init__(self, ctx: RuntimeContext) -> None:
        self._ctx = ctx
        self._attack_simulator: AttackSimulatorLike | None = None
        self._fpf: FalsePositiveFilterLike | None = None
        self._anomaly_detector: AnomalyDetectorLike | None = None
        self._active = False
        self._saved_fpf: dict[str, Any] = {}
        self._original_on_anomaly: Callable[[dict[str, Any]], None] | None = None

    @property
    def is_active(self) -> bool:
        return self._active

    def set_attack_simulator(self, simulator: AttackSimulatorLike) -> None:
        try:
            self._attack_simulator = simulator
        except Exception as e:
            logger.error("FpfSimulator.set_attack_simulator 실패: %s", e)

    def set_false_positive_filter(self, fpf: FalsePositiveFilterLike) -> None:
        try:
            self._fpf = fpf
        except Exception as e:
            logger.error("FpfSimulator.set_false_positive_filter 실패: %s", e)

    def set_anomaly_detector(self, detector: AnomalyDetectorLike) -> None:
        try:
            self._anomaly_detector = detector
        except Exception as e:
            logger.error("FpfSimulator.set_anomaly_detector 실패: %s", e)

    def start_seu(self, cmd: dict[str, Any] | None = None) -> bool:
        """SEU_SIM — gyro/servo 실부하 + FPF SEU(오탐) 판정 준비."""
        try:
            if self._active:
                logger.warning("SEU_SIM 이미 활성 — start_seu 스킵")
                return True

            if self._attack_simulator is None:
                logger.error("AttackSimulator 미주입 — SEU_SIM 스킵")
                return False
            if self._fpf is None:
                logger.error("FalsePositiveFilter 미주입 — SEU_SIM 스킵")
                return False

            self._apply_seu_fpf_mode()
            self._install_seu_fpf_patch()
            self._restore_seu_logical()

            detector = self._anomaly_detector
            if detector is not None and hasattr(detector, "reset_fpf_episode"):
                detector.reset_fpf_episode()

            if not bool(self._attack_simulator.start_seu_physical()):
                self.stop()
                return False

            self._active = True
            logger.info("SEU_SIM 시작 (FPF SEU 모드 + gyro/servo 실부하)")
            return True
        except Exception as e:
            logger.error("FpfSimulator.start_seu 실패: %s", e)
            return False

    def stop(self) -> bool:
        """SEU_SIM 모드 해제 — FPF 패치·가중치 복원."""
        try:
            if not self._active and self._original_on_anomaly is None:
                return True

            self._restore_seu_fpf_patch()
            self._restore_seu_fpf_mode()
            self._active = False
            logger.info("FpfSimulator SEU 모드 해제")
            return True
        except Exception as e:
            logger.error("FpfSimulator.stop 실패: %s", e)
            return False

    def _apply_seu_fpf_mode(self) -> None:
        try:
            fpf = self._fpf
            if fpf is None:
                return
            self._saved_fpf = {
                "weights": dict(fpf.weights),
                "seu_experiment_mode": bool(getattr(fpf, "seu_experiment_mode", False)),
            }
            fpf.weights = dict(fpf_config.FALSE_POSITIVE_SCENARIO_MODULE_WEIGHTS)
            fpf.seu_experiment_mode = True
        except Exception as e:
            logger.error("_apply_seu_fpf_mode 실패: %s", e)

    def _restore_seu_fpf_mode(self) -> None:
        try:
            fpf = self._fpf
            if fpf is None or not self._saved_fpf:
                return
            fpf.weights = dict(
                self._saved_fpf.get("weights", fpf_config.MODULE_WEIGHTS),
            )
            fpf.seu_experiment_mode = bool(self._saved_fpf.get("seu_experiment_mode", False))
            self._saved_fpf = {}
        except Exception as e:
            logger.error("_restore_seu_fpf_mode 실패: %s", e)

    def _install_seu_fpf_patch(self) -> None:
        try:
            fpf = self._fpf
            if fpf is None or self._original_on_anomaly is not None:
                return
            original = fpf.on_anomaly_detected
            self._original_on_anomaly = original

            def _patched(key_set: dict[str, Any]) -> None:
                try:
                    merged = self._prepare_seu_fpf_key_set(key_set)
                    original(merged)
                except Exception as e:
                    logger.error("SEU FPF patch on_anomaly_detected 실패: %s", e)

            fpf.on_anomaly_detected = _patched  # type: ignore[method-assign]
        except Exception as e:
            logger.error("_install_seu_fpf_patch 실패: %s", e)

    def _restore_seu_fpf_patch(self) -> None:
        try:
            fpf = self._fpf
            if fpf is None or self._original_on_anomaly is None:
                return
            fpf.on_anomaly_detected = self._original_on_anomaly  # type: ignore[method-assign]
            self._original_on_anomaly = None
        except Exception as e:
            logger.error("_restore_seu_fpf_patch 실패: %s", e)

    def _restore_seu_logical(self) -> bool:
        """공격 논리 ADCS/TLM 잔존 시 정상 스냅샷으로 복원."""
        try:
            adcs = self._ctx.db.get_adcs_filter()
            if is_attack_adcs_row(adcs):
                if not inject_natural_adcs_tlm_bypass(self._ctx.db):
                    logger.warning("SEU_SIM: 공격 ADCS 복원 실패")
                    return False
                logger.info("SEU_SIM: 공격 논리 ADCS/TLM → 정상 복원")
            self._reset_detector_series()
            return True
        except Exception as e:
            logger.error("_restore_seu_logical 실패: %s", e)
            return False

    def _reset_detector_series(self) -> None:
        try:
            detector = self._anomaly_detector
            if detector is None:
                return
            adcs_series = getattr(detector, "_adcs_series", None)
            tlm_series = getattr(detector, "_tlm_series", None)
            if adcs_series is not None:
                adcs_series.clear()
            if tlm_series is not None:
                tlm_series.clear()
            detector._refresh_series_buffers()
        except Exception as e:
            logger.error("_reset_detector_series 실패: %s", e)

    def _prepare_seu_fpf_key_set(self, key_set: dict[str, Any]) -> dict[str, Any]:
        """FPF 직전 — 실측 전력 유지, DB live 1프레임만 adcs/tlm_series."""
        try:
            self._restore_seu_logical()
            fpf = self._fpf
            if fpf is not None:
                fpf.physical._prev_state.clear()
                fpf.system._prev_state.clear()

            merged = dict(key_set) if isinstance(key_set, dict) else {}
            merged.pop(fpf_config.KEY_SNAPSHOTS, None)

            adcs_row = self._ctx.db.get_adcs_filter()
            tlm_row = self._ctx.db.get_tlm_current()
            merged["adcs_series"] = [dict(adcs_row)] if adcs_row is not None else []
            merged["tlm_series"] = [dict(tlm_row)] if tlm_row is not None else []

            if adcs_row is not None:
                ch1 = int(
                    adcs_row.get(
                        "CHENNEL1",
                        adcs_row.get("channel1", demon_config.SAT_ADCS_FILTER_CHANNEL_ID),
                    ),
                )
                merged["channel1"] = ch1
                merged["CHENNEL1"] = ch1
            return merged
        except Exception as e:
            logger.error("_prepare_seu_fpf_key_set 실패: %s", e)
            return dict(key_set) if isinstance(key_set, dict) else {}
