"""
지상국 ATTACK_SIM / RECOVERY → 위성 앱에서 시리얼·DB 시뮬 오케스트레이션.

아두이노는 ATTACK 문자열을 해석하지 않는다. AttackSimulator 가 JSON 명령을 조합해 전송한다.
"""
from __future__ import annotations

import logging
from typing import Any, Protocol

from .. import config as demon_config
from ..core.context import RuntimeContext

logger = logging.getLogger(__name__)


class AnomalyDetectorLike(Protocol):
    def set_attack_mode(self, enabled: bool) -> None:
        ...


class SerialReaderLike(Protocol):
    def set_pwr_bias(self, enabled: bool) -> bool:
        ...

    def set_gyro_enabled(self, enabled: bool) -> bool:
        ...

    def run_servo_motion(self, repeat_count: int, angle_deg: int) -> bool:
        ...


class AttackSimulator:
    """
    GScomms.handle_attack_sim / handle_recovery 에서 호출.

    start(): attack_mode + 시리얼(JSON) + (선택) ADCS/TLM 주입
    stop():  시리얼 해제 + attack_mode 복구
    """

    def __init__(self, ctx: RuntimeContext) -> None:
        self._ctx = ctx
        self._anomaly_detector: AnomalyDetectorLike | None = None
        self._serial_reader: SerialReaderLike | None = None
        self._active = False

    @property
    def is_active(self) -> bool:
        return self._active

    def set_anomaly_detector(self, detector: AnomalyDetectorLike) -> None:
        try:
            self._anomaly_detector = detector
        except Exception as e:
            logger.error("AttackSimulator.set_anomaly_detector 실패: %s", e)

    def set_serial_reader(self, reader: SerialReaderLike) -> None:
        try:
            self._serial_reader = reader
        except Exception as e:
            logger.error("AttackSimulator.set_serial_reader 실패: %s", e)

    def start(self) -> bool:
        """ATTACK_SIM — 데몬이 아두이노에 JSON 명령을 순서대로 전송."""
        try:
            if self._active:
                logger.warning("AttackSimulator 이미 활성 — start 스킵")
                return True

            ok_any = False

            if self._anomaly_detector is not None:
                self._anomaly_detector.set_attack_mode(True)
                ok_any = True
            else:
                logger.error("AnomalyDetector 미주입 — attack_mode 스킵")

            if self._run_physical_attack():
                ok_any = True

            if self._config_bool("ATTACK_SIM_INJECT_LOGICAL", True):
                if self._inject_logical_attack():
                    ok_any = True

            if ok_any:
                self._active = True
                logger.info("AttackSimulator 시작 (active=True)")
            else:
                logger.error("AttackSimulator 시작 실패 — 동작 없음")
            return ok_any
        except Exception as e:
            logger.error("AttackSimulator.start 실패: %s", e)
            return False

    def stop(self) -> bool:
        """RECOVERY — 바이어스·자이로 해제."""
        try:
            if not self._active and self._anomaly_detector is None:
                logger.warning("AttackSimulator 비활성 — stop 스킵")
                return False

            ok_any = False

            if self._run_physical_recovery():
                ok_any = True

            if self._anomaly_detector is not None:
                self._anomaly_detector.set_attack_mode(False)
                ok_any = True

            self._active = False
            logger.info("AttackSimulator 종료 (active=False)")
            return ok_any
        except Exception as e:
            logger.error("AttackSimulator.stop 실패: %s", e)
            return False

    def _run_physical_attack(self) -> bool:
        """앱 → 아두이노: pwr_bias on, gyro on, (선택) servo."""
        try:
            if self._serial_reader is None:
                logger.error("SerialReader 미주입 — 물리 공격 스킵")
                return False

            ok_any = False

            if self._config_bool("ATTACK_SIM_PWR_BIAS", True):
                if self._serial_reader.set_pwr_bias(True):
                    logger.info('UART {"pwr_bias":"on"}')
                    ok_any = True
                else:
                    logger.error("set_pwr_bias(on) 실패")

            if self._config_bool("ATTACK_SIM_ENABLE_GYRO", True):
                if self._serial_reader.set_gyro_enabled(True):
                    logger.info('UART {"gyro":"on"}')
                    ok_any = True

            if self._config_bool("ATTACK_SIM_ENABLE_SERVO", True):
                repeats = int(getattr(demon_config, "ATTACK_SIM_SERVO_REPEATS", 3))
                angle = int(getattr(demon_config, "ATTACK_SIM_SERVO_ANGLE", 90))
                if self._serial_reader.run_servo_motion(repeats, angle):
                    logger.info('UART {"num":%s,"angle":%s}', repeats, angle)
                    ok_any = True

            return ok_any
        except Exception as e:
            logger.error("_run_physical_attack 실패: %s", e)
            return False

    def _run_physical_recovery(self) -> bool:
        try:
            if self._serial_reader is None:
                return False

            ok_any = False

            if self._config_bool("ATTACK_SIM_ENABLE_GYRO", True):
                if self._serial_reader.set_gyro_enabled(False):
                    logger.info('UART {"gyro":"off"}')
                    ok_any = True

            if self._config_bool("ATTACK_SIM_PWR_BIAS", True):
                if self._serial_reader.set_pwr_bias(False):
                    logger.info('UART {"pwr_bias":"off"}')
                    ok_any = True
                else:
                    logger.error("set_pwr_bias(off) 실패")

            return ok_any
        except Exception as e:
            logger.error("_run_physical_recovery 실패: %s", e)
            return False

    def _inject_logical_attack(self) -> bool:
        try:
            ok_adcs = self._ctx.db.insert_adcs_filter(self._adcs_attack_payload())
            ok_tlm = self._ctx.db.upsert_tlm_current(self._tlm_attack_payload())
            if ok_adcs:
                logger.info("공격 시뮬: SAT_ADCS_FILTER 이상 스냅샷 INSERT")
            if ok_tlm:
                logger.info("공격 시뮬: SAT_TLM_CURRENT 갱신")
            return bool(ok_adcs or ok_tlm)
        except Exception as e:
            logger.error("_inject_logical_attack 실패: %s", e)
            return False

    @staticmethod
    def _adcs_attack_payload() -> dict[str, Any]:
        return {
            "QBN_0": 0.55,
            "QBN_1": 0.55,
            "QBN_2": 0.55,
            "QBN_3": 0.55,
            "ST_QBN_0": 1.0,
            "ST_QBN_1": 0.0,
            "ST_QBN_2": 0.0,
            "ST_QBN_3": 0.0,
            "Q_VALID": 1,
            "ST_VALID": 1,
            "TCMD_X": 0.8,
            "TCMD_Y": 0.6,
            "TCMD_Z": 0.4,
            "IMU_WBN_X": 0.0,
            "IMU_WBN_Y": 0.0,
            "IMU_WBN_Z": 0.0,
            "WERR_X": 0.25,
            "WERR_Y": 0.20,
            "WERR_Z": 0.18,
            "QERR_0": 0.7,
            "QERR_1": 0.3,
            "QERR_2": 0.2,
            "QERR_3": 0.1,
            "MOMENTUM_NMS_0": 0.01,
            "MOMENTUM_NMS_1": 0.01,
            "MOMENTUM_NMS_2": 0.01,
            "DEVICE_ENABLED_RW0": 0,
            "DEVICE_ENABLED_RW1": 0,
            "DEVICE_ENABLED_RW2": 0,
            "MCMD_X": 0.1,
            "MCMD_Y": 0.1,
            "MCMD_Z": 0.1,
        }

    @staticmethod
    def _tlm_attack_payload() -> dict[str, Any]:
        return {
            "ADCS_MODE": 2,
            "MISSION_MODE": 2,
            "SUN_VALID": 0,
            "SVB_X": 0.1,
            "SVB_Y": 0.2,
            "SVB_Z": 0.9,
            "WBN_X": 0.05,
            "WBN_Y": -0.04,
            "WBN_Z": 0.03,
        }

    @staticmethod
    def _config_bool(name: str, default: bool) -> bool:
        try:
            val = getattr(demon_config, name, default)
            return bool(val)
        except Exception as e:
            logger.error("_config_bool 실패 %s: %s", name, e)
            return default
