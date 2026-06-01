"""fpf_scenario_injector — FPF 통합 실험용 실DB 시나리오 주입.

전력 이상(앞단)은 이미 발생한 상태로 SAT_PWR_META 를 세팅하고,
FPF 판정 검증을 위해 ADCS/TLM 스냅샷을 덮어쓴 뒤 누적 쓰기를 중지한다.

시나리오
    fpf_natural  — 단일 채널 전력 이상 + ADCS/TLM 정상 → FPF 기대 N (자연현상/SEU)
    fpf_attack   — 전력 이상 + ADCS 논리 변조(AttackSimulator 동일) → FPF 기대 Y (공격)
"""

from __future__ import annotations

import logging
from typing import Any

from ... import config as demon_config
from ...core.time_utils import utc_now_iso
from . import config as fpf_config

logger = logging.getLogger(fpf_config.LOGGER_NAME)

SCENARIO_FPF_NATURAL = "fpf_natural"
SCENARIO_FPF_ATTACK = "fpf_attack"

INTEGRATION_SCENARIOS = (SCENARIO_FPF_NATURAL, SCENARIO_FPF_ATTACK)

SCENARIO_EXPECTED_ATTACK = {
    SCENARIO_FPF_NATURAL: "N",
    SCENARIO_FPF_ATTACK: "Y",
}


def adcs_attack_payload() -> dict[str, Any]:
    """AttackSimulator._adcs_attack_payload 와 동일 — 논리 공격 ADCS 스냅샷."""
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


def tlm_attack_payload() -> dict[str, Any]:
    """AttackSimulator._tlm_attack_payload 와 동일 — 논리 공격 TLM 스냅샷."""
    return {
        "ADCS_MODE": fpf_config.ADCS_MODE_DETUMBLING,
        "MISSION_MODE": fpf_config.MISSION_MODE_SCIENCE,
        "SUN_VALID": 0,
        "SVB_X": 0.1,
        "SVB_Y": 0.2,
        "SVB_Z": 0.9,
        "WBN_X": 0.05,
        "WBN_Y": -0.04,
        "WBN_Z": 0.03,
    }


def _base_tlm_natural() -> dict[str, Any]:
    return {
        "MISSION_MODE": fpf_config.MISSION_MODE_SCIENCE,
        "OBC_S_TICK": 1000,
        "HEAP_FREE": 50000,
        "APPENABLESTATE": 1,
        "DWELL_MASK": 0,
        "ADCS_MODE": fpf_config.ADCS_MODE_POINTING,
        "SVB_X": 1.0,
        "SVB_Y": 0.0,
        "SVB_Z": 0.0,
        "WBN_X": 0.01,
        "WBN_Y": 0.0,
        "WBN_Z": 0.0,
        "DT": 1.0,
        "TORQUER_PERIOD": 10,
        "SUN_VALID": 1,
    }


def _base_adcs_natural() -> dict[str, Any]:
    return {
        "CMDCOUNTER": 10,
        "QBN_0": 1.0,
        "QBN_1": 0.0,
        "QBN_2": 0.0,
        "QBN_3": 0.0,
        "ST_QBN_0": 1.0,
        "ST_QBN_1": 0.0,
        "ST_QBN_2": 0.0,
        "ST_QBN_3": 0.0,
        "Q_VALID": 1,
        "ST_VALID": 1,
        "THERR_X": 0.005,
        "THERR_Y": 0.005,
        "THERR_Z": 0.005,
        "CMD_WBN_X": 0.0,
        "CMD_WBN_Y": 0.0,
        "CMD_WBN_Z": 0.0,
        "BDOT_X": 0.1,
        "BDOT_Y": 0.0,
        "BDOT_Z": 0.0,
        "H_MGMTON": 0,
        "SUN_VALID": 1,
        "DEVICE_ENABLED_RW0": 1,
        "DEVICE_ENABLED_RW1": 1,
        "DEVICE_ENABLED_RW2": 1,
        "IMU_WBN_X": 0.02,
        "IMU_WBN_Y": 0.0,
        "IMU_WBN_Z": 0.0,
        "IMU_ACC_X": 0.0,
        "IMU_ACC_Y": 0.0,
        "IMU_ACC_Z": 0.0,
        "QERR_0": 1.0,
        "QERR_1": 0.002,
        "QERR_2": 0.002,
        "QERR_3": 0.002,
        "TCMD_X": 0.02,
        "TCMD_Y": 0.0,
        "TCMD_Z": 0.0,
        "MCMD_X": 0.1,
        "MCMD_Y": 0.1,
        "MCMD_Z": 0.1,
        "WERR_X": 0.003,
        "WERR_Y": 0.0,
        "WERR_Z": 0.0,
        "MOMENTUM_NMS_0": 0.1,
        "MOMENTUM_NMS_1": 0.1,
        "MOMENTUM_NMS_2": 0.1,
        "COMBINEDPACKETSSENT": 100,
        "ERLOGENTRIES": 5,
        "SKIPPEDSLOTSCOUNT": 0,
        "LASTVALCRC": "A1",
        "ENABLEDROUTES": 2,
        "FORWARD_ERR_COUNT": 0,
        "APPCSERRCOUNTER": 0,
        "OSCSERRCOUNTER": 0,
        "SYSLOGENTRIES": 20,
        "RESETSPERFORMED": 0,
        "EXECOUNTS": 0.0,
    }


def _adcs_torque_series() -> list[dict[str, Any]]:
    """토크 증폭 검증용 2프레임 시계열 (experiment_db attack_torque 와 동일 패턴)."""
    t0 = _base_adcs_natural()
    t0.update({"TCMD_X": 0.05, "IMU_WBN_X": 0.02, "IMU_WBN_Y": 0.0, "IMU_WBN_Z": 0.0})
    t1 = dict(t0)
    t1.update({"TCMD_X": 0.05, "IMU_WBN_X": 0.35, "IMU_WBN_Y": 0.2, "IMU_WBN_Z": 0.0})
    return [t0, t1]


def _threshold_for_sw(sw_id: int) -> tuple[float, float]:
    try:
        if sw_id < len(demon_config.V_THRESHOLD_LO):
            lo = float(demon_config.V_THRESHOLD_LO[sw_id])
            hi = float(demon_config.V_THRESHOLD_HI[sw_id])
            return lo, hi
        lo = float(fpf_config.V_THRESHOLD_LO[sw_id])
        hi = float(fpf_config.V_THRESHOLD_HI[sw_id])
        return lo, hi
    except (IndexError, TypeError, ValueError) as e:
        logger.error("_threshold_for_sw 실패 sw_id=%s: %s", sw_id, e)
        return 3.0, 3.6


def _pwr_channel_count() -> int:
    return int(getattr(demon_config, "PWR_SW_ID_COUNT", fpf_config.TOTAL_PWR_CHANNELS))


def _apply_pwr_channel(
    db: Any,
    sw_id: int,
    *,
    voltage: float,
    anomaly_flag: int,
    exceed_count: int = 3,
    consecutive: int = 3,
) -> bool:
    try:
        ok_v = db.upsert_pwr_meta(
            {"sw_id": sw_id, "voltage": voltage, "current_a": 0.5},
        )
        ok_e = db.update_pwr_exceed_meta(
            {
                "sw_id": sw_id,
                "exceed_count": exceed_count,
                "consecutive_exceed": consecutive,
                "anomaly_flag": anomaly_flag,
            },
        )
        return bool(ok_v and ok_e)
    except Exception as e:
        logger.error("_apply_pwr_channel 실패 sw_id=%s: %s", sw_id, e)
        return False


def _clear_accumulated_tables(db: Any) -> None:
    try:
        db.delete_adcs_filter()
        db.reset_pwr_anomaly_state()
    except Exception as e:
        logger.error("_clear_accumulated_tables 실패: %s", e)


def is_attack_adcs_row(row: dict[str, Any] | None) -> bool:
    """AttackSimulator 논리 주입 스냅샷과 동일/유사한지 (SEU 단계 실측 복원 판단)."""
    try:
        if not row or not isinstance(row, dict):
            return False
        ref = adcs_attack_payload()
        q0 = float(row.get("QBN_0", -1.0))
        tcmd_x = float(row.get("TCMD_X", -1.0))
        qerr_0 = float(row.get("QERR_0", -1.0))
        if abs(q0 - float(ref["QBN_0"])) < 1e-4 and abs(tcmd_x - float(ref["TCMD_X"])) < 1e-4:
            return True
        if abs(qerr_0 - float(ref["QERR_0"])) < 1e-4 and abs(tcmd_x - float(ref["TCMD_X"])) < 1e-4:
            return True
        return False
    except (TypeError, ValueError) as e:
        logger.error("is_attack_adcs_row 변환 오류: %s", e)
        return False
    except Exception as e:
        logger.error("is_attack_adcs_row 실패: %s", e)
        return False


def build_natural_fpf_key_overrides(key_set: dict[str, Any] | None = None) -> dict[str, Any]:
    """(오프라인·Mock 전용) FPF N 판정용 key_set — _snapshots 로 ADCS/TLM 고정.

    run_pipeline_scenario 실측 SEU 경로에서는 사용하지 않는다.
    DB·adcs_series 실측 반영 시 build_live_fpf_key_set() 사용.
    """
    try:
        adcs = _base_adcs_natural()
        tlm = _base_tlm_natural()
        merged = dict(key_set) if isinstance(key_set, dict) else {}
        merged[fpf_config.KEY_ADCS_SERIES] = []
        merged[fpf_config.KEY_TLM_SERIES] = []
        merged[fpf_config.KEY_SNAPSHOTS] = {"adcs": dict(adcs), "tlm": dict(tlm)}
        return merged
    except Exception as e:
        logger.error("build_natural_fpf_key_overrides 실패: %s", e)
        return dict(key_set) if isinstance(key_set, dict) else {}


def inject_natural_adcs_tlm(db: Any) -> bool:
    """
    FPF N(오탐) 시연용 — SAT_TLM_CURRENT·SAT_ADCS_FILTER 에 정상 스냅샷만 DB 반영.

    전력(SAT_PWR_META)은 Serial/Detector 가 갱신하므로 건드리지 않는다.
    UDP flush 로 ADCS 행이 덮어써지기 전·후 FPF 판정 시점에 재호출한다.
    """
    try:
        ok_tlm = db.upsert_tlm_current(_base_tlm_natural())
        ok_adcs = db.insert_adcs_filter(_base_adcs_natural())
        return bool(ok_tlm and ok_adcs)
    except Exception as e:
        logger.error("inject_natural_adcs_tlm 실패: %s", e)
        return False


def inject_natural_adcs_tlm_bypass(db: Any) -> bool:
    """inject_natural_adcs_tlm — accumulation freeze 중에도 ADCS/TLM 주입 가능."""
    try:
        ctx = getattr(db, "scenario_inject_writes", None)
        if callable(ctx):
            with db.scenario_inject_writes():
                return inject_natural_adcs_tlm(db)
        return inject_natural_adcs_tlm(db)
    except Exception as e:
        logger.error("inject_natural_adcs_tlm_bypass 실패: %s", e)
        return False


def inject_attack_adcs_tlm(db: Any) -> bool:
    """
    FPF Y(공격) 시연용 — AttackSimulator 논리 주입과 동일 payload 를 DB 에 기록.

    토크 시계열 2프레임 + 최종 attack 스냅샷(사원수 위반 등)을 insert 한다.
    """
    try:
        ok_tlm = db.upsert_tlm_current(tlm_attack_payload())
        ok_any = bool(ok_tlm)
        for frame in _adcs_torque_series():
            if db.insert_adcs_filter(frame):
                ok_any = True
        if db.insert_adcs_filter(adcs_attack_payload()):
            ok_any = True
        return ok_any
    except Exception as e:
        logger.error("inject_attack_adcs_tlm 실패: %s", e)
        return False


def _inject_natural_scenario(db: Any) -> list[dict[str, Any]]:
    """단일 채널 전력 이상 + ADCS/TLM 정상."""
    inject_natural_adcs_tlm(db)

    target_sw = int(fpf_config.PWR_SW_ID_ADCS)
    lo, _hi = _threshold_for_sw(target_sw)
    anomaly_v = max(lo - 0.05, 0.1)

    for sw_id in range(_pwr_channel_count()):
        if sw_id == target_sw:
            _apply_pwr_channel(
                db,
                sw_id,
                voltage=anomaly_v,
                anomaly_flag=1,
                exceed_count=int(fpf_config.EXCEED_COUNT_THRESHOLD),
                consecutive=int(fpf_config.CONSECUTIVE_THRESHOLD),
            )
        else:
            lo_sw, hi_sw = _threshold_for_sw(sw_id)
            mid = (lo_sw + hi_sw) / 2.0
            _apply_pwr_channel(db, sw_id, voltage=mid, anomaly_flag=0)

    return []


def _inject_attack_scenario(db: Any) -> list[dict[str, Any]]:
    """AttackSimulator 논리 주입 + 다채널 전력 이상 + 토크 시계열."""
    series = _adcs_torque_series()
    inject_attack_adcs_tlm(db)

    now_ts = utc_now_iso()
    for sw_id in range(_pwr_channel_count()):
        lo, _hi = _threshold_for_sw(sw_id)
        _apply_pwr_channel(
            db,
            sw_id,
            voltage=max(lo - 0.08, 0.1),
            anomaly_flag=1,
            exceed_count=int(fpf_config.EXCEED_COUNT_THRESHOLD) + sw_id,
            consecutive=int(fpf_config.CONSECUTIVE_THRESHOLD),
        )

    for row in db.get_pwr_meta_all():
        row["UPDATED_AT"] = now_ts

    return series


class FpfScenarioInjector:
    """실DB에 FPF 통합 시나리오를 주입하고 누적 쓰기를 중지한다."""

    def __init__(self, db: Any) -> None:
        self._db = db
        self._active_scenario: str | None = None
        self._adcs_series: list[dict[str, Any]] = []

    @property
    def active_scenario(self) -> str | None:
        return self._active_scenario

    @property
    def adcs_series(self) -> list[dict[str, Any]]:
        return list(self._adcs_series)

    def prepare_scenario(self, scenario: str) -> bool:
        """시나리오 데이터로 DB 덮어쓰기 후 accumulation freeze."""
        try:
            if scenario not in INTEGRATION_SCENARIOS:
                logger.error("prepare_scenario: 알 수 없는 시나리오 %s", scenario)
                return False

            with self._db.scenario_inject_writes():
                _clear_accumulated_tables(self._db)
                if scenario == SCENARIO_FPF_NATURAL:
                    self._adcs_series = _inject_natural_scenario(self._db)
                else:
                    self._adcs_series = _inject_attack_scenario(self._db)

            self._db.set_accumulation_frozen(True)
            self._active_scenario = scenario
            logger.info("FPF 시나리오 주입 완료: %s (accumulation frozen)", scenario)
            return True
        except Exception as e:
            logger.error("prepare_scenario 실패 scenario=%s: %s", scenario, e)
            return False

    def release_scenario(self) -> None:
        """누적 freeze 해제 (다음 시나리오·운영 복귀용)."""
        try:
            self._db.set_accumulation_frozen(False)
            self._active_scenario = None
            self._adcs_series = []
        except Exception as e:
            logger.error("release_scenario 실패: %s", e)

    def build_key_set(
        self,
        scenario: str | None = None,
        *,
        sw_id: int | None = None,
    ) -> dict[str, Any]:
        """AnomalyDetector 가 넘기는 key_set 과 동일 형식."""
        try:
            scen = scenario or self._active_scenario or SCENARIO_FPF_NATURAL
            target_sw = int(sw_id if sw_id is not None else fpf_config.PWR_SW_ID_ADCS)
            sw_list = [target_sw]
            if scen == SCENARIO_FPF_ATTACK:
                sw_list = list(range(_pwr_channel_count()))

            key: dict[str, Any] = {
                "tlm_id": 1,
                "sw_id": target_sw,
                fpf_config.KEY_CHANNEL1: fpf_config.CHANNEL1_DEFAULT,
                fpf_config.KEY_EVENT_ID: fpf_config.EVENT_ID_UNASSIGNED,
                "detected_at": utc_now_iso(),
                fpf_config.KEY_SW_ID_LIST: sw_list,
            }
            if self._adcs_series:
                key[fpf_config.KEY_ADCS_SERIES] = [dict(x) for x in self._adcs_series]
            return key
        except Exception as e:
            logger.error("build_key_set 실패: %s", e)
            return {
                "tlm_id": 1,
                "sw_id": int(fpf_config.PWR_SW_ID_ADCS),
                fpf_config.KEY_CHANNEL1: fpf_config.CHANNEL1_DEFAULT,
                fpf_config.KEY_EVENT_ID: fpf_config.EVENT_ID_UNASSIGNED,
                "detected_at": utc_now_iso(),
            }
