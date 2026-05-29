"""experiment_db — Pi/네트워크 없이 FPF 실험용 Mock DB.

DBManager와 동일 메서드명(get_tlm_current, get_adcs_filter, …).
run_fpf_experiment.py 가 시나리오별 행을 주입한다.
adcs_series 가 필요한 시나리오는 self._adcs_series 에 리스트 보관.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from . import config

_TS = "2026-05-12T12:00:00Z"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _base_tlm(adcs_mode: int = 1) -> dict:
    return {
        "TLM_ID": 1,
        "UPDATED_AT": _TS,
        "MISSION_MODE": config.MISSION_MODE_SCIENCE,
        "OBC_S_TICK": 1000,
        "HEAP_FREE": 50000,
        "APPENABLESTATE": 1,
        "DWELL_MASK": 0,
        "ADCS_MODE": adcs_mode,
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


def _base_adcs(**overrides: Any) -> dict:
    row = {
        "CHENNEL1": 1,
        "channel1": 1,
        "TIMESTAMP": _TS,
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
    row.update(overrides)
    return row


def _pwr_row(
    sw_id: int,
    anomaly: int = 0,
    voltage: float = 3.3,
    updated_at: str | None = None,
) -> dict:
    lo = config.V_THRESHOLD_LO[sw_id]
    hi = config.V_THRESHOLD_HI[sw_id]
    return {
        "SW_ID": sw_id,
        "UPDATED_AT": updated_at or _utc_now(),
        "VOLTAGE": voltage,
        "PREV_VOLTAGE": voltage,
        "CURRENT_A": 0.5,
        "PREV_DELTA_V": 0.0,
        "CURR_DELTA_V": 0.0,
        "EXCEED_COUNT": 0,
        "CONSECUTIVE_EXCEED": 0,
        "ANOMALY_FLAG": anomaly,
        "V_THRESHOLD_LO": lo,
        "V_THRESHOLD_HI": hi,
    }


def _base_event(**overrides: Any) -> dict:
    row = {
        "EVENT_ID": 1,
        "DETECTED_AT": _utc_now(),
        "PIPEOVERFLOWRRCNT": 0,
        "CHILDQUEUECOUNT": 0,
        "FILEWRITEERRCOUNTER": 0,
        "CMDREJECTEDCOUNTER": 0,
        "CH1_CH2_FAULT_CRC": 0,
        "CH1_FAULT_FILE_SIZE_MISMATCH": 0,
        "PROCESSOR_RESET_COUNT": 0,
        "IS_SENT": 0,
        "TIMESTAMP": _utc_now(),
        "PRIORITY": 0,
        "EVENT_TYPE": "POWER_ANOMALY",
    }
    row.update(overrides)
    return row


class ExperimentMockDB:
    """Pi/DBManager 없이 오탐 필터 실험용."""

    def __init__(self, scenario: str = "normal"):
        self._scenario = scenario
        self._apply_scenario(scenario)

    def set_scenario(self, scenario: str) -> None:
        self._scenario = scenario
        self._apply_scenario(scenario)

    def _apply_scenario(self, scenario: str) -> None:
        self._adcs_series: list[dict] = []
        if scenario == "normal":
            self._tlm = _base_tlm(config.ADCS_MODE_POINTING)
            self._adcs = _base_adcs()
            self._adcs_series = []
            self._pwr = [_pwr_row(i, 0) for i in range(config.PWR_SW_ID_MIN, config.PWR_SW_ID_MAX + 1)]
            self._event = _base_event()
            self._integrity = [
                {
                    "FILE_ID": 1,
                    "FILE_PATH": "/cf/app",
                    "EXPECTED_HASH": "abc",
                    "LAST_VERIFIEDA_AT": _utc_now(),
                    "LAST_VERIFIED_AT": _utc_now(),
                    "UPDATED_AT": _utc_now(),
                    "IS_VIOLATED": 0,
                }
            ]
        elif scenario == "attack_torque":
            self._tlm = _base_tlm(config.ADCS_MODE_POINTING)
            t0 = _base_adcs(TCMD_X=0.05, IMU_WBN_X=0.02, IMU_WBN_Y=0.0, IMU_WBN_Z=0.0)
            t1 = _base_adcs(TCMD_X=0.05, IMU_WBN_X=0.35, IMU_WBN_Y=0.2, IMU_WBN_Z=0.0)
            self._adcs_series = [t0, t1]
            self._adcs = t1
            self._pwr = [_pwr_row(1, 1, voltage=3.2)]
            self._pwr.extend(_pwr_row(i, 0) for i in range(config.PWR_SW_ID_MAX + 1) if i != 1)
            self._event = _base_event()
            self._integrity = []
        elif scenario == "attack_multi_channel":
            self._tlm = _base_tlm(config.ADCS_MODE_POINTING)
            self._adcs = _base_adcs()
            self._adcs_series = []
            self._pwr = [
                _pwr_row(0, 1, updated_at=_TS),
                _pwr_row(1, 1, updated_at=_TS),
                _pwr_row(2, 1, updated_at=_TS),
                _pwr_row(3, 1, updated_at=_TS),
                _pwr_row(4, 1, updated_at=_TS),
            ]
            self._event = _base_event()
            self._integrity = []
        elif scenario == "attack_quaternion":
            self._tlm = _base_tlm()
            self._adcs = _base_adcs(
                QBN_0=1.2,
                ST_QBN_0=1.0,
                Q_VALID=1,
                ST_VALID=1,
            )
            self._pwr = [_pwr_row(1, 1)]
            self._event = _base_event()
            self._integrity = []
        elif scenario == "attack_mode_change":
            self._tlm = _base_tlm(config.ADCS_MODE_DETUMBLING)
            self._adcs = _base_adcs(CMDCOUNTER=10)
            self._pwr = [_pwr_row(1, 1)]
            self._event = _base_event()
            self._integrity = []
        elif scenario == "attack_system_packet_prime":
            self._tlm = _base_tlm()
            self._tlm["OBC_S_TICK"] = 1000
            self._adcs = _base_adcs(
                COMBINEDPACKETSSENT=100,
                FORWARD_ERR_COUNT=0,
                SYSLOGENTRIES=20,
            )
            self._pwr = [_pwr_row(1, 1)]
            self._event = _base_event()
            self._integrity = []
        elif scenario == "attack_system_packet":
            self._tlm = _base_tlm()
            self._tlm["OBC_S_TICK"] = 1100
            self._adcs = _base_adcs(
                COMBINEDPACKETSSENT=130,
                FORWARD_ERR_COUNT=0,
                SYSLOGENTRIES=20,
            )
            self._pwr = [_pwr_row(1, 1)]
            self._event = _base_event()
            self._integrity = []
        elif scenario == "attack_qerr_diverge":
            self._tlm = _base_tlm()
            s1 = _base_adcs(QERR_1=0.01, QERR_2=0.01, QERR_3=0.01)
            s2 = _base_adcs(QERR_1=0.04, QERR_2=0.05, QERR_3=0.04)
            s3 = _base_adcs(QERR_1=0.08, QERR_2=0.09, QERR_3=0.08)
            self._adcs_series = [s1, s2, s3]
            self._adcs = s3
            self._pwr = [_pwr_row(1, 1)]
            self._event = _base_event()
            self._integrity = []
        else:
            self._tlm = None
            self._adcs = None
            self._pwr = []
            self._event = None
            self._integrity = []

    def get_tlm_current(self) -> dict | None:
        return self._tlm

    def get_adcs_filter(self, channel1: int) -> dict | None:
        if self._adcs is None:
            return None
        row = dict(self._adcs)
        row["CHENNEL1"] = channel1
        row["channel1"] = channel1
        return row

    def get_pwr_meta(self, sw_id: int) -> dict | None:
        for row in self._pwr:
            if row.get("SW_ID") == sw_id:
                return row
        return None

    def get_pwr_meta_all(self) -> list[dict]:
        return list(self._pwr)

    def get_event(self, event_id: int) -> dict | None:
        if self._event is None:
            return None
        row = dict(self._event)
        row["EVENT_ID"] = event_id
        return row

    def get_integrity_hash(self, file_id: int | None = None):
        if not self._integrity:
            return None if file_id is not None else []
        if file_id is not None:
            for row in self._integrity:
                if row.get("FILE_ID") == file_id:
                    return row
            return None
        return list(self._integrity)


def try_real_db() -> Any | None:
    """demon DBManager 있으면 사용, 없으면 None."""
    try:
        from demon.db.db_manager import DBManager

        db = DBManager()
        db.init_db()
        return db
    except Exception:
        return None
