"""gs_tlm_history columns that mirror SAT_BULK_TELEMETRY JSON field names."""

from __future__ import annotations

# TLM record fields not yet in gs_tlm_history.
TLM_JSON_COLUMNS: tuple[tuple[str, str], ...] = (
    ("TLM_ID", "`TLM_ID` int DEFAULT NULL"),
    ("DT", "`DT` double DEFAULT NULL"),
    ("TORQUER_PERIOD", "`TORQUER_PERIOD` int DEFAULT NULL"),
)

# ADCS record fields (flat keys match onboard JSON).
_ADCS_DOUBLE_FIELDS = (
    "QBN_0",
    "QBN_1",
    "QBN_2",
    "QBN_3",
    "ST_QBN_0",
    "ST_QBN_1",
    "ST_QBN_2",
    "ST_QBN_3",
    "THERR_X",
    "THERR_Y",
    "THERR_Z",
    "CMD_WBN_X",
    "CMD_WBN_Y",
    "CMD_WBN_Z",
    "BDOT_X",
    "BDOT_Y",
    "BDOT_Z",
    "MCMD_X",
    "MCMD_Y",
    "MCMD_Z",
    "WERR_X",
    "WERR_Y",
    "WERR_Z",
    "MAG_BVB_X",
    "MAG_BVB_Y",
    "MAG_BVB_Z",
    "IMU_ACC_X",
    "IMU_ACC_Y",
    "IMU_ACC_Z",
)

ADCS_JSON_COLUMNS: tuple[tuple[str, str], ...] = (
    ("CMDCOUNTER", "`CMDCOUNTER` int DEFAULT NULL"),
    ("Q_VALID", "`Q_VALID` tinyint DEFAULT NULL"),
    ("H_MGMTON", "`H_MGMTON` tinyint DEFAULT NULL"),
    ("CHENNEL1", "`CHENNEL1` int DEFAULT NULL"),
    ("DEVICE_ENABLED_RW0", "`DEVICE_ENABLED_RW0` tinyint DEFAULT NULL"),
    ("DEVICE_ENABLED_RW1", "`DEVICE_ENABLED_RW1` tinyint DEFAULT NULL"),
    ("DEVICE_ENABLED_RW2", "`DEVICE_ENABLED_RW2` tinyint DEFAULT NULL"),
    *[(field, f"`{field}` double DEFAULT NULL") for field in _ADCS_DOUBLE_FIELDS],
)

# Event fields from SAT_EVENT_QUEUE.events[].
EVENT_JSON_COLUMNS: tuple[tuple[str, str], ...] = (
    ("DETECTED_AT", "`DETECTED_AT` datetime(3) DEFAULT NULL"),
    ("PRIORITY", "`PRIORITY` int DEFAULT NULL"),
    ("IS_SENT", "`IS_SENT` tinyint DEFAULT NULL"),
    ("MODULE_SCORES", "`MODULE_SCORES` json DEFAULT NULL"),
)

# Bulk envelope + lossless archive.
BULK_META_COLUMNS: tuple[tuple[str, str], ...] = (
    ("BULK_SENT_AT", "`BULK_SENT_AT` datetime(3) DEFAULT NULL"),
    ("BULK_NOTE", "`BULK_NOTE` varchar(255) DEFAULT NULL"),
    ("WIRE_PAYLOAD", "`WIRE_PAYLOAD` json DEFAULT NULL"),
    ("SOURCE_RECORDS", "`SOURCE_RECORDS` json DEFAULT NULL"),
)

# SAT_INTEGRITY_HASH (first violated row or first row merged onto sample).
INTEGRITY_JSON_COLUMNS: tuple[tuple[str, str], ...] = (
    ("INTEGRITY_FILE_ID", "`INTEGRITY_FILE_ID` int DEFAULT NULL"),
    ("INTEGRITY_FILE_PATH", "`INTEGRITY_FILE_PATH` varchar(512) DEFAULT NULL"),
    ("INTEGRITY_LAST_VERIFIED_AT", "`INTEGRITY_LAST_VERIFIED_AT` datetime(3) DEFAULT NULL"),
)

_PWR_CHANNEL_SUFFIXES: tuple[tuple[str, str], ...] = (
    ("PREV_VOLTAGE", "double DEFAULT NULL"),
    ("PREV_DELTA_V", "double DEFAULT NULL"),
    ("EXCEED_COUNT", "int DEFAULT NULL"),
    ("CONSECUTIVE_EXCEED", "int DEFAULT NULL"),
    ("V_THRESHOLD_LO", "double DEFAULT NULL"),
    ("V_THRESHOLD_HI", "double DEFAULT NULL"),
)


def pwr_channel_column_ddls() -> list[tuple[str, str]]:
    """SW_0..3 extended PWR fields matching channels[] JSON keys."""
    columns: list[tuple[str, str]] = []
    for sw_id in range(4):
        for suffix, sql_type in _PWR_CHANNEL_SUFFIXES:
            name = f"SW_{sw_id}_{suffix}"
            columns.append((name, f"`{name}` {sql_type}"))
    return columns


def all_bulk_json_column_ddls() -> list[tuple[str, str]]:
    """All JSON-mirror columns for gs_tlm_history migrations."""
    columns: list[tuple[str, str]] = []
    columns.extend(TLM_JSON_COLUMNS)
    columns.extend(ADCS_JSON_COLUMNS)
    columns.extend(EVENT_JSON_COLUMNS)
    columns.extend(BULK_META_COLUMNS)
    columns.extend(INTEGRITY_JSON_COLUMNS)
    columns.extend(pwr_channel_column_ddls())
    return columns
