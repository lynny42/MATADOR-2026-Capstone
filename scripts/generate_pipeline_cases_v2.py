"""Generate pipeline_cases.json from the GScomms v2 wire-order test spec."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "backend" / "test_data" / "pipeline_cases.json"


def _adcs_tail(**overrides: object) -> dict:
    base = {
        "CMD_WBN_X": 0.0,
        "CMD_WBN_Y": 0.0,
        "CMD_WBN_Z": 0.0,
        "BDOT_X": 0.0,
        "BDOT_Y": 0.0,
        "BDOT_Z": 0.0,
        "H_MGMTON": 0,
        "SUN_VALID": 1,
        "DEVICE_ENABLED_RW0": 1,
        "DEVICE_ENABLED_RW1": 1,
        "DEVICE_ENABLED_RW2": 1,
        "IMU_ACC_X": 0.0,
        "IMU_ACC_Y": 0.0,
        "IMU_ACC_Z": 0.0,
        "MCMD_X": 0.0,
        "MCMD_Y": 0.0,
        "MCMD_Z": 0.0,
        "ST_VALID": 1,
        "SKIPPEDSLOTSCOUNT": 0,
        "ENABLEDROUTES": 7,
        "FORWARD_ERR_COUNT": 0,
        "APPCSERRCOUNTER": 0,
        "OSCSERRCOUNTER": 0,
        "RESETSPERFORMED": 0,
        "EXECOUNTS": 1.0,
    }
    base.update(overrides)
    return base


def _pwr_channels(
    updated_at: str,
    history_id: int,
    channels: list[dict],
) -> dict:
    return {
        "HISTORY_ID": history_id,
        "UPDATED_AT": updated_at,
        "channels": channels,
    }


def _channel(
    sw_id: int,
    voltage: float,
    prev_voltage: float,
    current_a: float,
    prev_delta_v: float,
    curr_delta_v: float,
    exceed_count: int,
    consecutive_exceed: int,
    anomaly_flag: int,
    lo: float,
    hi: float,
) -> dict:
    return {
        "SW_ID": sw_id,
        "VOLTAGE": voltage,
        "PREV_VOLTAGE": prev_voltage,
        "CURRENT_A": current_a,
        "PREV_DELTA_V": prev_delta_v,
        "CURR_DELTA_V": curr_delta_v,
        "EXCEED_COUNT": exceed_count,
        "CONSECUTIVE_EXCEED": consecutive_exceed,
        "ANOMALY_FLAG": anomaly_flag,
        "V_THRESHOLD_LO": lo,
        "V_THRESHOLD_HI": hi,
    }


CASES = {
    "1": {
        "title": "정상만 존재하는 경우",
        "packets": [
            {
                "packet_type": "SAT_ADCS_FILTER",
                "records": [
                    {
                        "CHENNEL1": 1,
                        "TIMESTAMP": "2026-05-30T10:00:00+00:00",
                        "CMDCOUNTER": 42,
                        "QBN_0": 0.998,
                        "QBN_1": 0.01,
                        "QBN_2": -0.02,
                        "QBN_3": 0.05,
                        "ST_QBN_0": 0.997,
                        "ST_QBN_1": 0.012,
                        "ST_QBN_2": -0.018,
                        "ST_QBN_3": 0.048,
                        "Q_VALID": 1,
                        "THERR_X": 0.5,
                        "THERR_Y": -0.3,
                        "THERR_Z": 0.2,
                        "IMU_WBN_X": 0.001,
                        "IMU_WBN_Y": -0.002,
                        "IMU_WBN_Z": 0.0005,
                        "QERR_0": 0.999,
                        "QERR_1": 0.002,
                        "QERR_2": -0.001,
                        "QERR_3": 0.001,
                        "TCMD_X": 0.01,
                        "TCMD_Y": -0.01,
                        "TCMD_Z": 0.005,
                        "WERR_X": 0.001,
                        "WERR_Y": -0.001,
                        "WERR_Z": 0.0,
                        "MOMENTUM_NMS_0": 0.05,
                        "MOMENTUM_NMS_1": -0.03,
                        "MOMENTUM_NMS_2": 0.02,
                        "COMBINEDPACKETSSENT": 1024,
                        "ERLOGENTRIES": 3,
                        "LASTVALCRC": "a1b2c3d4",
                        "SYSLOGENTRIES": 20,
                        **_adcs_tail(),
                    },
                    {
                        "CHENNEL1": 2,
                        "TIMESTAMP": "2026-05-30T10:00:01+00:00",
                        "CMDCOUNTER": 43,
                        "QBN_0": 0.997,
                        "QBN_1": 0.011,
                        "QBN_2": -0.019,
                        "QBN_3": 0.049,
                        "ST_QBN_0": 0.996,
                        "ST_QBN_1": 0.013,
                        "ST_QBN_2": -0.017,
                        "ST_QBN_3": 0.047,
                        "Q_VALID": 1,
                        "THERR_X": 0.48,
                        "THERR_Y": -0.28,
                        "THERR_Z": 0.19,
                        "IMU_WBN_X": 0.001,
                        "IMU_WBN_Y": -0.002,
                        "IMU_WBN_Z": 0.0005,
                        "QERR_0": 0.999,
                        "QERR_1": 0.002,
                        "QERR_2": -0.001,
                        "QERR_3": 0.001,
                        "TCMD_X": 0.01,
                        "TCMD_Y": -0.01,
                        "TCMD_Z": 0.005,
                        "WERR_X": 0.001,
                        "WERR_Y": -0.001,
                        "WERR_Z": 0.0,
                        "MOMENTUM_NMS_0": 0.05,
                        "MOMENTUM_NMS_1": -0.03,
                        "MOMENTUM_NMS_2": 0.02,
                        "COMBINEDPACKETSSENT": 1025,
                        "ERLOGENTRIES": 3,
                        "LASTVALCRC": "a1b2c3d4",
                        "SYSLOGENTRIES": 20,
                        **_adcs_tail(),
                    },
                ],
            },
            {
                "packet_type": "SAT_TLM_HISTORY",
                "records": [
                    {
                        "HISTORY_ID": 1001,
                        "TLM_ID": 1,
                        "UPDATED_AT": "2026-05-30T10:00:00+00:00",
                        "MISSION_MODE": 2,
                        "OBC_S_TICK": 120340,
                        "HEAP_FREE": 45000,
                        "APPENABLESTATE": 1,
                        "DWELL_MASK": 0,
                        "ADCS_MODE": 2,
                        "SVB_X": 0.12,
                        "SVB_Y": -0.05,
                        "SVB_Z": 0.99,
                        "WBN_X": 0.001,
                        "WBN_Y": -0.002,
                        "WBN_Z": 0.0005,
                        "DT": 0.1,
                        "TORQUER_PERIOD": 8,
                        "SUN_VALID": 1,
                    },
                    {
                        "HISTORY_ID": 1002,
                        "TLM_ID": 1,
                        "UPDATED_AT": "2026-05-30T10:00:01+00:00",
                        "MISSION_MODE": 2,
                        "OBC_S_TICK": 120341,
                        "HEAP_FREE": 44980,
                        "APPENABLESTATE": 1,
                        "DWELL_MASK": 0,
                        "ADCS_MODE": 2,
                        "SVB_X": 0.12,
                        "SVB_Y": -0.05,
                        "SVB_Z": 0.99,
                        "WBN_X": 0.001,
                        "WBN_Y": -0.002,
                        "WBN_Z": 0.0005,
                        "DT": 0.1,
                        "TORQUER_PERIOD": 8,
                        "SUN_VALID": 1,
                    },
                ],
            },
            {
                "packet_type": "SAT_PWR_HISTORY",
                "records": [
                    _pwr_channels(
                        "2026-05-30T10:00:00+00:00",
                        501,
                        [
                            _channel(0, 3.28, 3.27, 0.12, 0.0, 0.01, 0, 0, 0, 3.1, 3.45),
                            _channel(1, 4.85, 4.84, 0.45, 0.0, 0.01, 0, 0, 0, 4.6, 5.0),
                            _channel(2, 4.82, 4.81, 0.08, 0.0, 0.01, 0, 0, 0, 3.5, 5.0),
                            _channel(3, 3.3, 3.3, 0.0, 0.0, 0.0, 0, 0, 0, 3.0, 3.6),
                        ],
                    ),
                    _pwr_channels(
                        "2026-05-30T10:00:01+00:00",
                        502,
                        [
                            _channel(0, 3.29, 3.28, 0.12, 0.01, 0.01, 0, 0, 0, 3.1, 3.45),
                            _channel(1, 4.86, 4.85, 0.46, 0.01, 0.01, 0, 0, 0, 4.6, 5.0),
                            _channel(2, 4.83, 4.82, 0.08, 0.01, 0.01, 0, 0, 0, 3.5, 5.0),
                            _channel(3, 3.3, 3.3, 0.0, 0.0, 0.0, 0, 0, 0, 3.0, 3.6),
                        ],
                    ),
                ],
            },
        ],
    },
}


def main() -> int:
    # Cases 2-4 are loaded from companion JSON fragments written alongside this script.
    fragments_path = Path(__file__).with_name("pipeline_cases_v2_fragments.json")
    if fragments_path.exists():
        fragments = json.loads(fragments_path.read_text(encoding="utf-8"))
        CASES.update(fragments)
    payload = {"cases": CASES}
    OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {OUT} with cases: {', '.join(sorted(CASES))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
