"""Rebuild TCP attack packets from gs_tlm_history anomaly rows and send to port 6000."""

from __future__ import annotations

import argparse
import copy
import json
import logging
import struct
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ma_detector.db import config as db_config
from ma_detector.db import gs_repository
from ma_detector.db.database import init_db

logger = logging.getLogger(__name__)

CASES_PATH = ROOT / "backend" / "test_data" / "pipeline_cases.json"

ADCS_OVERLAY = {
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
    "IMU_WBN_X": 0.0,
    "IMU_WBN_Y": 0.0,
    "IMU_WBN_Z": 0.0,
    "IMU_WBN_VARIANCE": 0.0001,
    "RAW_MAG_VARIANCE": 0.0001,
    "TCMD_X": 0.8,
    "TCMD_Y": 0.6,
    "TCMD_Z": 0.4,
    "QERR_0": 0.7,
    "QERR_1": 0.3,
    "QERR_2": 0.2,
    "QERR_3": 0.1,
    "DEVICE_ENABLED_RW0": 0,
    "DEVICE_ENABLED_RW1": 0,
    "DEVICE_ENABLED_RW2": 0,
}


def _iso_now(offset_sec: int = 0) -> str:
    moment = datetime.now(timezone.utc) + timedelta(seconds=offset_sec)
    return moment.replace(microsecond=0).isoformat()


def _parse_sw_id_list(row: dict[str, Any]) -> list[int]:
    try:
        raw = row.get("sw_id_list") or row.get("SW_ID_LIST")
        if isinstance(raw, list):
            return [int(item) for item in raw]
        if isinstance(raw, str):
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [int(item) for item in parsed]
        sw_id = row.get("SW_ID")
        if sw_id is not None:
            return [int(sw_id)]
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        logger.error("sw_id_list parse failed: %s", error)
    return [0]


def _power_channels(row: dict[str, Any], event_time: str, sw_ids: list[int]) -> dict[str, Any]:
    channels: list[dict[str, Any]] = []
    for sw_id in range(4):
        voltage = float(row.get(f"SW_{sw_id}_VOLTAGE") or (4.47 if sw_id in sw_ids else 3.3))
        prev_voltage = float(row.get(f"SW_{sw_id}_PREV_VOLTAGE") or (3.28 if sw_id in sw_ids else voltage))
        current_a = float(row.get(f"SW_{sw_id}_CURRENT_A") or row.get(f"SW_{sw_id}_CURRENT") or 0.4)
        anomaly = 1 if sw_id in sw_ids else int(row.get(f"SW_{sw_id}_ANOMALY_FLAG") or 0)
        delta = float(row.get(f"SW_{sw_id}_CURR_DELTA_V") or (voltage - prev_voltage))
        lo = 4.5 if sw_id == 2 else 3.0
        hi = 5.5 if sw_id == 2 else 3.6
        channels.append(
            {
                "SW_ID": sw_id,
                "VOLTAGE": voltage,
                "PREV_VOLTAGE": prev_voltage,
                "CURRENT_A": current_a,
                "PREV_DELTA_V": 0.01,
                "CURR_DELTA_V": delta,
                "EXCEED_COUNT": 3 if anomaly else 0,
                "CONSECUTIVE_EXCEED": 3 if anomaly else 0,
                "ANOMALY_FLAG": anomaly,
                "V_THRESHOLD_LO": lo,
                "V_THRESHOLD_HI": hi,
            }
        )
    return {
        "packet_type": "SAT_PWR_HISTORY",
        "records": [
            {
                "HISTORY_ID": int(row.get("HISTORY_ID") or 9000) + 500,
                "UPDATED_AT": event_time,
                "channels": channels,
            }
        ],
    }


def _tlm_record(row: dict[str, Any], event_time: str) -> dict[str, Any]:
    return {
        "HISTORY_ID": int(row.get("HISTORY_ID") or 9000) + 100,
        "TLM_ID": 1,
        "UPDATED_AT": event_time,
        "MISSION_MODE": int(row.get("MISSION_MODE") or 2),
        "OBC_S_TICK": int(row.get("OBC_S_TICK") or 184380),
        "HEAP_FREE": int(row.get("HEAP_FREE") or 498000),
        "APPENABLESTATE": int(row.get("APPENABLESTATE") or 1),
        "DWELL_MASK": int(row.get("DWELL_MASK") or 0),
        "ADCS_MODE": int(row.get("ADCS_MODE") or 2),
        "SVB_X": float(row.get("SVB_X") or 0.1),
        "SVB_Y": float(row.get("SVB_Y") or 0.2),
        "SVB_Z": float(row.get("SVB_Z") or 0.9),
        "WBN_X": float(row.get("WBN_X") or 0.05),
        "WBN_Y": float(row.get("WBN_Y") or -0.04),
        "WBN_Z": float(row.get("WBN_Z") or 0.03),
        "DT": float(row.get("DT") or 0.25),
        "TORQUER_PERIOD": int(row.get("TORQUER_PERIOD") or 8),
        "SUN_VALID": int(row.get("SUN_VALID") or 1),
        "UTILCPUAVG": float(row.get("UTILCPUAVG") or 20.0),
        "MEMINUSE": int(row.get("MEMINUSE") or 200),
        "BUS_3P3V": float(row.get("BUS_3P3V") or 3.3),
        "BUS_5P0V": float(row.get("BUS_5P0V") or 5.0),
        "BUS_12V": float(row.get("BUS_12V") or 12.0),
    }


def _adcs_record(row: dict[str, Any], event_time: str, target: str) -> dict[str, Any]:
    record: dict[str, Any] = {
        "CHENNEL1": 3,
        "TIMESTAMP": event_time,
        "CMDCOUNTER": int(row.get("CMDCOUNTER") or 10280),
        "SUN_VALID": int(row.get("SUN_VALID") or 1),
        "COMBINEDPACKETSSENT": int(row.get("COMBINEDPACKETSSENT") or 450200),
        "ERLOGENTRIES": int(row.get("ERLOGENTRIES") or 14),
        "SKIPPEDSLOTSCOUNT": int(row.get("SKIPPEDSLOTSCOUNT") or 0),
        "LASTVALCRC": str(row.get("LASTVALCRC") or "d5f2b1a0"),
        "ENABLEDROUTES": int(row.get("ENABLEDROUTES") or 1),
        "FORWARD_ERR_COUNT": int(row.get("FORWARD_ERR_COUNT") or 0),
        "APPCSERRCOUNTER": int(row.get("APPCSERRCOUNTER") or 0),
        "OSCSERRCOUNTER": int(row.get("OSCSERRCOUNTER") or 0),
        "SYSLOGENTRIES": int(row.get("SYSLOGENTRIES") or 95),
        "RESETSPERFORMED": int(row.get("RESETSPERFORMED") or row.get("PROCESSOR_RESET_COUNT") or 0),
        "EXECOUNTS": float(row.get("EXECOUNTS") or 1.0),
        "QERR_0": float(row.get("QERR_0") or 0.99),
        "QERR_1": float(row.get("QERR_1") or 0.01),
        "QERR_2": float(row.get("QERR_2") or 0.01),
        "QERR_3": float(row.get("QERR_3") or 0.01),
        "TCMD_X": float(row.get("TCMD_X") or 0.02),
        "TCMD_Y": float(row.get("TCMD_Y") or -0.01),
        "TCMD_Z": float(row.get("TCMD_Z") or 0.01),
        "MOMENTUM_NMS_0": float(row.get("MOMENTUM_NMS_0") or 0.12),
        "MOMENTUM_NMS_1": float(row.get("MOMENTUM_NMS_1") or -0.08),
        "MOMENTUM_NMS_2": float(row.get("MOMENTUM_NMS_2") or 0.05),
        "ST_VALID": int(row.get("ST_VALID") or 1),
        "IMU_WBN_VARIANCE": float(row.get("IMU_WBN_VARIANCE") or 0.01),
        "RAW_MAG_VARIANCE": float(row.get("RAW_MAG_VARIANCE") or 0.01),
    }
    if target == "ADCS":
        record.update(ADCS_OVERLAY)
        record["IMU_WBN_VARIANCE"] = float(row.get("IMU_WBN_VARIANCE") or 0.0001)
        record["RAW_MAG_VARIANCE"] = float(row.get("RAW_MAG_VARIANCE") or 0.0001)
    return record


def _event_packet(row: dict[str, Any], event_time: str) -> dict[str, Any]:
    weight = int(row.get("FALSE_POSITIVE_WEIGHT") or row.get("WEIGHT") or row.get("FILTER_WEIGHT") or 76)
    sw_ids = _parse_sw_id_list(row)
    exception = row.get("FALSE_POSITIVE_EXCEPTION") or row.get("FILTER_EXCEPTION") or ""
    if isinstance(exception, str) and exception.isdigit():
        exception_code = int(exception)
    elif exception:
        exception_code = 2
    else:
        exception_code = int(row.get("EXCEPTION_CODE") or 0)

    event = {
        "EVENT_ID": int(row.get("EVENT_ID") or row.get("event_id") or 9001),
        "DETECTED_AT": event_time,
        "TIMESTAMP": event_time,
        "PRIORITY": 1 if weight >= 50 else 0,
        "EVENT_TYPE": "ATTACK_CONFIRMED",
        "SW_ID": sw_ids[0] if sw_ids else 0,
        "WEIGHT": weight,
        "EXCEPTION_CODE": exception_code,
        "MODULE_SCORES": row.get("MODULE_SCORES")
        or '{"physical":0.81,"statistical":0.72,"system":0.65}',
        "PIPEOVERFLOWRRCNT": int(row.get("PIPEOVERFLOWRRCNT") or 0),
        "CHILDQUEUECOUNT": int(row.get("CHILDQUEUECOUNT") or 184380),
        "FILEWRITEERRCOUNTER": int(row.get("FILEWRITEERRCOUNTER") or 0),
        "CMDREJECTEDCOUNTER": int(row.get("CMDREJECTEDCOUNTER") or 0),
        "CH1_CH2_FAULT_CRC": int(row.get("CH1_FAULT_CRC") or row.get("CH1_CH2_FAULT_CRC") or 0),
        "CH1_FAULT_FILE_SIZE_MISMATCH": int(row.get("CH1_FAULT_FILE_SIZE_MISMATCH") or 0),
        "PROCESSOR_RESET_COUNT": int(row.get("PROCESSOR_RESET_COUNT") or row.get("RESETSPERFORMED") or 0),
        "IS_SENT": int(row.get("IS_SENT") or 0),
        "CHENNEL1": 3,
    }
    if exception and not str(exception).isdigit():
        event["EXCEPTION_CODE"] = exception
    return {"packet_type": "SAT_EVENT_QUEUE", "event": event}


def _integrity_packet(row: dict[str, Any], event_time: str, target: str) -> dict[str, Any] | None:
    expected = row.get("EXPECTED_HASH") or row.get("EXPECTED_CRC") or "OK"
    actual = row.get("OBC_P_HASH") or expected
    if target != "OBC" and int(row.get("IS_VIOLATED") or 0) != 1 and actual == expected:
        return None

    violated_path = "/cf/apps/obc.so" if target == "OBC" else "/cf/apps/adcs.so"
    return {
        "packet_type": "SAT_INTEGRITY_HASH",
        "records": [
            {
                "FILE_ID": 1,
                "FILE_PATH": "/cf/apps/to_lab.so",
                "EXPECTED_HASH": "a3f2c891d4e5b6078190ab12cd34ef56",
                "LAST_VERIFIED_AT": event_time,
                "UPDATED_AT": event_time,
                "IS_VIOLATED": 0,
            },
            {
                "FILE_ID": 2,
                "FILE_PATH": violated_path,
                "EXPECTED_HASH": str(expected),
                "ACTUAL_HASH": str(actual),
                "OBC_P_HASH": str(actual),
                "LAST_VERIFIED_AT": event_time,
                "UPDATED_AT": event_time,
                "IS_VIOLATED": 1,
            },
        ],
    }


def row_to_packets(row: dict[str, Any], event_time: str | None = None) -> list[dict[str, Any]]:
    """Convert one merged gs_tlm_history anomaly row into TCP buffer packets."""
    try:
        stamp = event_time or _iso_now()
        target = str(row.get("TARGET_SUBSYSTEM") or row.get("target_subsystem") or "ADCS").upper()
        sw_ids = _parse_sw_id_list(row)
        tlm_time = _iso_now(-2) if event_time is None else (
            datetime.fromisoformat(stamp.replace("Z", "+00:00")) - timedelta(seconds=2)
        ).replace(microsecond=0).isoformat()

        packets: list[dict[str, Any]] = [_event_packet(row, stamp)]
        integrity = _integrity_packet(row, stamp, target)
        if integrity is not None:
            packets.append(integrity)

        packets.append(
            {
                "packet_type": "SAT_ADCS_FILTER",
                "records": [_adcs_record(row, stamp, target)],
            }
        )
        packets.append(
            {
                "packet_type": "SAT_TLM_HISTORY",
                "records": [_tlm_record(row, tlm_time)],
            }
        )
        packets.append(_power_channels(row, stamp, sw_ids))
        return packets
    except Exception as error:
        logger.error("row_to_packets failed: %s", error)
        return []


def _load_rows(profile: str) -> list[dict[str, Any]]:
    rows = gs_repository.load_anomaly_history(20)
    if not rows:
        raise RuntimeError("No IS_ANOMALY=1 rows found in gs_tlm_history")

    if profile == "all":
        return rows

    wanted = profile.upper()
    matched = [
        row
        for row in rows
        if str(row.get("TARGET_SUBSYSTEM") or "").upper() == wanted
    ]
    if not matched:
        raise RuntimeError(f"No anomaly row for TARGET_SUBSYSTEM={wanted}")
    return matched


def _send_packet(host: str, port: int, packet: dict[str, Any], timeout_sec: float) -> dict[str, Any]:
    import socket

    body = json.dumps(packet, ensure_ascii=False, default=str).encode("utf-8")
    frame = struct.pack(">I", len(body)) + body
    with socket.create_connection((host, port), timeout=timeout_sec) as sock:
        sock.settimeout(timeout_sec)
        sock.sendall(frame)
        header = sock.recv(4)
        if len(header) != 4:
            raise RuntimeError("ACK header incomplete")
        ack_len = struct.unpack(">I", header)[0]
        ack_body = sock.recv(ack_len)
        if len(ack_body) != ack_len:
            raise RuntimeError("ACK body incomplete")
        return json.loads(ack_body.decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Send DB-derived attack packets to ground station TCP")
    parser.add_argument("--profile", choices=("obc", "adcs", "all"), default="all")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6000)
    parser.add_argument("--delay-sec", type=float, default=0.35)
    parser.add_argument("--timeout-sec", type=float, default=10.0)
    parser.add_argument("--dry-run", action="store_true", help="Print packets only")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    init_db(
        db_config.DB_HOST,
        db_config.DB_PORT,
        db_config.DB_USER,
        db_config.DB_PASSWORD,
        db_config.DB_NAME,
        db_config.DB_POOL_SIZE,
    )

    rows = _load_rows(args.profile)
    logger.info("Loaded %d anomaly template(s) from DB", len(rows))

    for row_index, row in enumerate(rows, start=1):
        target = row.get("TARGET_SUBSYSTEM")
        history_id = row.get("HISTORY_ID")
        event_time = _iso_now(row_index * 8)
        packets = row_to_packets(row, event_time=event_time)
        logger.info(
            "Profile %s HISTORY_ID=%s TARGET=%s -> %d packets at %s",
            args.profile,
            history_id,
            target,
            len(packets),
            event_time,
        )

        if args.dry_run:
            print(json.dumps(packets, ensure_ascii=False, indent=2, default=str))
            continue

        for packet_index, packet in enumerate(packets, start=1):
            packet_type = packet.get("packet_type", "UNKNOWN")
            ack = _send_packet(args.host, args.port, packet, args.timeout_sec)
            logger.info(
                "[%d/%d] %s -> ACK %s",
                packet_index,
                len(packets),
                packet_type,
                ack,
            )
            if packet_index < len(packets) and args.delay_sec > 0:
                time.sleep(args.delay_sec)

        if row_index < len(rows) and args.delay_sec > 0:
            time.sleep(args.delay_sec * 2)

    logger.info("DB attack injection complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
