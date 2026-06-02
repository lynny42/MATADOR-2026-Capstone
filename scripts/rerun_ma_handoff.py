"""Re-run MA detection on comm-3 (or any) bulk handoff without re-inserting telemetry.

Usage (repo root):
    python scripts/rerun_ma_handoff.py backend/test_data/comm-3_bulk_handoff.json
    python scripts/rerun_ma_handoff.py --reload backend/test_data/comm-3_bulk_handoff.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ma_detector import MAIntegratedDetector
from ma_detector.core.bulk_history_merge import (
    extract_bulk_event_records,
    merge_bulk_telemetry_packet,
    select_pre_attack_baseline_rows,
)
from ma_detector.core.packet_protocol import event_is_attack_anomaly
from ma_detector.db import config as db_config
from ma_detector.db import gs_repository
from ma_detector.db.database import get_connection, init_db, is_db_available, require_db
from ma_detector.db.gs_repository import refresh_column_cache

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

_MA_CLEAR_TABLES = (
    db_config.TABLE_ANOMALY_DETAIL,
    db_config.TABLE_ANOMALY_DASHBOARD,
    db_config.TABLE_ANOMALY_DISCARD_LOG,
)


def _clear_ma_tables() -> None:
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
            for table in _MA_CLEAR_TABLES:
                cursor.execute(f"DELETE FROM `{table}`")
                logger.info("cleared %s", table)
            cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
            conn.commit()
            cursor.close()
    except Exception as error:
        logger.error("MA table clear failed: %s", error)
        raise


def _load_handoff(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8-sig") as file:
            payload = json.load(file)
        if not isinstance(payload, dict):
            raise ValueError("handoff root must be a JSON object")
        return payload
    except (OSError, json.JSONDecodeError, ValueError) as error:
        logger.error("handoff load failed: %s", error)
        raise


def _prepare_bulk(handoff: dict[str, Any]) -> dict[str, Any]:
    bulk_section = handoff.get("SAT_BULK_TELEMETRY")
    if not isinstance(bulk_section, dict):
        raise ValueError("handoff missing SAT_BULK_TELEMETRY object")
    bulk = dict(bulk_section)
    event_section = handoff.get("SAT_EVENT_QUEUE")
    if isinstance(event_section, dict):
        bulk["SAT_EVENT_QUEUE"] = event_section
    comm_session = handoff.get("comm_session") or bulk.get("_comm_session")
    if comm_session:
        bulk["_comm_session"] = str(comm_session).strip()
    if bulk.get("packet_type") is None:
        bulk["packet_type"] = "SAT_BULK_TELEMETRY"
    return bulk


def _print_dashboard_summary() -> None:
    try:
        rows = gs_repository.query_recent_dashboards(50)
        if not rows:
            logger.info("dashboard: (empty)")
            return
        logger.info("dashboard rows: %s", len(rows))
        for row in rows:
            logger.info(
                "  %s | %s | grade=%s conf=%s rules=%s",
                row.get("DETECTED_AT"),
                row.get("MA_CODE"),
                row.get("GRADE"),
                row.get("CONFIDENCE_SCORE"),
                row.get("TRIGGERED_RULE_IDS"),
            )
    except Exception as error:
        logger.error("dashboard summary failed: %s", error)


def rerun_ma(handoff_path: Path, *, reload_data: bool) -> int:
    init_db(
        host=db_config.DB_HOST,
        port=db_config.DB_PORT,
        user=db_config.DB_USER,
        password=db_config.DB_PASSWORD,
        database=db_config.DB_NAME,
        pool_size=db_config.DB_POOL_SIZE,
    )
    if not is_db_available():
        logger.error("MySQL unavailable")
        return 1

    require_db()
    refresh_column_cache()

    if reload_data:
        import subprocess

        script = ROOT / "scripts" / "load_bulk_handoff.py"
        result = subprocess.run(
            [sys.executable, str(script), "--clear", str(handoff_path)],
            cwd=str(ROOT),
            check=False,
        )
        return int(result.returncode)

    handoff = _load_handoff(handoff_path)
    bulk = _prepare_bulk(handoff)
    merged = merge_bulk_telemetry_packet(bulk)
    events = extract_bulk_event_records(bulk)
    baseline_rows = select_pre_attack_baseline_rows(merged, events)

    _clear_ma_tables()

    detector = MAIntegratedDetector()
    if baseline_rows:
        detector.build_baseline(baseline_rows)
        logger.info("MA baseline: %s pre-attack row(s)", len(baseline_rows))
    else:
        detector.build_baseline(gs_repository.load_baseline_history())

    packets = gs_repository.load_attack_replay_packets()
    if not packets:
        logger.error("no attack replay packets (load handoff with load_bulk_handoff.py first)")
        return 1

    processed = 0
    for packet in packets:
        if not event_is_attack_anomaly(packet):
            continue
        error = detector.receive_telemetry(
            json.dumps(packet, ensure_ascii=False, default=str),
            skip_history_insert=True,
            reprocess=True,
        )
        if error:
            logger.error("MA reprocess failed: %s", error)
            continue
        processed += 1

    logger.info("MA reprocess complete: attacks=%s dashboard=%s", processed, len(gs_repository.query_recent_dashboards(100)))
    _print_dashboard_summary()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Re-run MA on bulk handoff data in MySQL")
    parser.add_argument("handoff_path", type=Path, help="comm-3_bulk_handoff.json path")
    parser.add_argument(
        "--reload",
        action="store_true",
        help="clear gs_* and reload handoff (includes MA on ingest)",
    )
    args = parser.parse_args()
    if not args.handoff_path.is_file():
        logger.error("handoff file not found: %s", args.handoff_path)
        return 1
    return rerun_ma(args.handoff_path, reload_data=args.reload)


if __name__ == "__main__":
    raise SystemExit(main())
