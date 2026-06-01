"""Shared TLM/ADCS overlap column names for gs_tlm_history."""

from __future__ import annotations

from typing import Any

# Fields present in both SAT_TLM_HISTORY and SAT_ADCS_FILTER onboard records.
TLM_ADCS_OVERLAP_FIELDS: tuple[str, ...] = (
    "SUN_VALID",
    "ERLOGENTRIES",
    "SKIPPEDSLOTSCOUNT",
    "LASTVALCRC",
    "ENABLEDROUTES",
    "FORWARD_ERR_COUNT",
    "APPCSERRCOUNTER",
    "OSCSERRCOUNTER",
    "SYSLOGENTRIES",
    "RESETSPERFORMED",
    "EXECOUNTS",
    "COMBINEDPACKETSSENT",
)

TLM_ADCS_OVERLAP_FIELD_SET = frozenset(TLM_ADCS_OVERLAP_FIELDS)

# gs_tlm_history metadata columns for aligned bulk samples.
BULK_SAMPLE_METADATA_COLUMNS: tuple[str, ...] = (
    "SNAPSHOT_ID",
    "SNAPSHOT_AT",
    "TLM_HISTORY_ID",
    "PWR_HISTORY_ID",
    "ADCS_HISTORY_ID",
    "SAMPLE_INDEX",
    "SAMPLE_HISTORY_ID",
    "ADCS_TIMESTAMP",
)


def tlm_column(field: str) -> str:
    return f"TLM_{field}"


def adcs_column(field: str) -> str:
    return f"ADCS_{field}"


def overlap_column_ddl(field: str) -> tuple[tuple[str, str], tuple[str, str]]:
    """Return (tlm_col, ddl), (adcs_col, ddl) for schema/migration."""
    if field == "LASTVALCRC":
        return (
            (tlm_column(field), f"`{tlm_column(field)}` varchar(64) DEFAULT NULL"),
            (adcs_column(field), f"`{adcs_column(field)}` varchar(64) DEFAULT NULL"),
        )
    if field == "EXECOUNTS":
        return (
            (tlm_column(field), f"`{tlm_column(field)}` int DEFAULT NULL"),
            (adcs_column(field), f"`{adcs_column(field)}` int DEFAULT NULL"),
        )
    if field == "SUN_VALID":
        return (
            (tlm_column(field), f"`{tlm_column(field)}` tinyint DEFAULT NULL"),
            (adcs_column(field), f"`{adcs_column(field)}` tinyint DEFAULT NULL"),
        )
    return (
        (tlm_column(field), f"`{tlm_column(field)}` int DEFAULT NULL"),
        (adcs_column(field), f"`{adcs_column(field)}` int DEFAULT NULL"),
    )


def all_split_column_ddls() -> list[tuple[str, str]]:
    """All new gs_tlm_history column name + DDL fragments for migrations."""
    columns: list[tuple[str, str]] = [
        ("SNAPSHOT_ID", "`SNAPSHOT_ID` int DEFAULT NULL"),
        ("SNAPSHOT_AT", "`SNAPSHOT_AT` datetime(3) DEFAULT NULL"),
        ("TLM_HISTORY_ID", "`TLM_HISTORY_ID` bigint DEFAULT NULL"),
        ("PWR_HISTORY_ID", "`PWR_HISTORY_ID` bigint DEFAULT NULL"),
        ("ADCS_HISTORY_ID", "`ADCS_HISTORY_ID` bigint DEFAULT NULL"),
        ("SAMPLE_INDEX", "`SAMPLE_INDEX` int DEFAULT NULL"),
        ("SAMPLE_HISTORY_ID", "`SAMPLE_HISTORY_ID` bigint DEFAULT NULL"),
        ("ADCS_TIMESTAMP", "`ADCS_TIMESTAMP` datetime(3) DEFAULT NULL"),
    ]
    for field in TLM_ADCS_OVERLAP_FIELDS:
        tlm_def, adcs_def = overlap_column_ddl(field)
        columns.append(tlm_def)
        columns.append(adcs_def)
    return columns


def sync_legacy_tlm_columns(row: dict[str, Any]) -> None:
    """Copy TLM_* overlap columns into legacy unprefixed columns for rule engine."""
    for field in TLM_ADCS_OVERLAP_FIELDS:
        tlm_key = tlm_column(field)
        if row.get(field) is None and row.get(tlm_key) is not None:
            row[field] = row[tlm_key]
