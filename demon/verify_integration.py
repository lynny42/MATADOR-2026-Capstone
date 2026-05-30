#!/usr/bin/env python3
"""통합 검증 스크립트 — demon.main 기동 전 로컬에서 DB·파서·flush 동작 확인."""
from __future__ import annotations

import logging
import sqlite3
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable

from demon import config as demon_config
from demon.core.context import DaemonConfig, RuntimeContext
from demon.db.db_manager import DBManager
from demon.workers.anomaly_detector import AnomalyDetector
from demon.workers.false_positive_filter import (
    FalsePositiveFilter,
    PhysicalConsistencyModule,
    StatisticalConsistencyModule,
    SystemResponseModule,
)
from demon.workers.false_positive_filter.experiment_db import ExperimentMockDB
from demon.workers.gs_comms import GScomms
from demon.workers.serial_reader import SerialReader
from demon.workers.udp_receiver import UDPReceiver

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("verify")


def _ok(msg: str) -> None:
    logger.info("PASS: %s", msg)


def _fail(msg: str) -> None:
    logger.error("FAIL: %s", msg)
    raise SystemExit(1)


def test_db_manager_api(tmp_db: Path) -> None:
    db = DBManager(tmp_db)
    if not db.init_db():
        _fail("DBManager.init_db")
    _ok("DBManager.init_db")

    conn = sqlite3.connect(tmp_db)
    pwr_rows = conn.execute("SELECT COUNT(*) FROM SAT_PWR_META").fetchone()[0]
    conn.close()
    if pwr_rows != demon_config.PWR_SW_ID_COUNT:
        _fail(f"SAT_PWR_META seed count={pwr_rows}")
    _ok(f"SAT_PWR_META {pwr_rows} rows seeded")

    db.upsert_pwr_meta({"sw_id": 0, "voltage": 3.1, "current_a": 0.4})
    db.upsert_pwr_meta({"sw_id": 0, "voltage": 3.4, "current_a": 0.5})
    m0 = db.get_pwr_meta(0)
    if m0 is None or abs(m0["CURR_DELTA_V"] - 0.3) > 1e-6:
        _fail(f"pwr delta expected 0.3 got {None if m0 is None else m0['CURR_DELTA_V']}")
    _ok("upsert_pwr_meta delta sliding window")

    db.update_pwr_exceed_meta(
        {"sw_id": 0, "exceed_count": 3, "consecutive_exceed": 2, "anomaly_flag": 1},
    )
    m0_flag = db.get_pwr_meta(0)
    if m0_flag is None or m0_flag["ANOMALY_FLAG"] != 1:
        _fail("update_pwr_exceed_meta")
    _ok("update_pwr_exceed_meta")

    eid = db.insert_event({"EVENT_TYPE": "VERIFY", "PRIORITY": 0})
    if eid < 1 or len(db.get_pending_events()) != 1:
        _fail("insert_event / get_pending_events")
    db.mark_event_sent(eid)
    db.delete_event(eid)
    _ok("event queue lifecycle")

    db.upsert_tlm_current({"ADCS_MODE": 2, "SUN_VALID": 1, "WBN_X": -0.001})
    if not db.is_sunlight_window():
        _fail("is_sunlight_window")
    _ok("upsert_tlm_current + is_sunlight_window")

    db.insert_adcs_filter({"QBN_0": 1.0, "SUN_VALID": 1, "_ADCS_HK_CMD_CNT": 10})
    adcs = db.get_adcs_filter(1)
    if adcs is None or adcs.get("QBN_0") != 1.0:
        _fail(f"get_adcs_filter {adcs}")
    _ok("insert_adcs_filter + get_adcs_filter")

    db.insert_adcs_filter({"QBN_0": 0.9, "SUN_VALID": 0})
    if db.get_adcs_filter(1).get("QBN_0") != 0.9:
        _fail("insert_adcs_filter UPSERT (OR REPLACE)")
    _ok("insert_adcs_filter OR REPLACE")

    tlm = db.get_tlm_current()
    if tlm is None or tlm.get("ADCS_MODE") is None:
        _fail("get_tlm_current")
    _ok("get_tlm_current")

    all_pwr = db.get_pwr_meta_all()
    if len(all_pwr) != demon_config.PWR_SW_ID_COUNT:
        _fail(f"get_pwr_meta_all count={len(all_pwr)}")
    _ok("get_pwr_meta_all")

    eid2 = db.insert_event({"EVENT_TYPE": "LOOKUP", "PRIORITY": 1})
    ev = db.get_event(eid2)
    if ev is None or ev.get("EVENT_TYPE") != "LOOKUP":
        _fail(f"get_event {ev}")
    db.delete_event(eid2)
    _ok("get_event")

    if db.get_integrity_hash(999) is not None:
        _fail("get_integrity_hash missing row")
    if db.get_integrity_hash() != []:
        _fail("get_integrity_hash empty table")
    _ok("get_integrity_hash")

    db.update_threshold(1, 3.2, 3.8)
    m1 = db.get_pwr_meta(1)
    if m1 is None or m1["V_THRESHOLD_LO"] != 3.2:
        _fail("update_threshold")
    _ok("update_threshold")

    db.close()


def test_do_flush_pending(tmp_db: Path) -> None:
    """GNC 필드 merge 후 DO MID 에서만 DB flush 되는지."""
    db = DBManager(tmp_db)
    db.init_db()
    shutdown = threading.Event()
    ctx = RuntimeContext(config=DaemonConfig(db_path=tmp_db), shutdown_event=shutdown, db=db)
    rx = UDPReceiver(ctx)

    rx._merge_tlm_pending({"ADCS_MODE": 2, "SUN_VALID": 1})
    row_mid = db.get_tlm_current()
    if row_mid is not None and row_mid.get("ADCS_MODE") == 2:
        _fail("DB updated before DO flush")

    rx._merge_tlm_pending({"WBN_X": -0.002})
    rx._flush_tlm_pending_to_db()

    row = db.get_tlm_current()
    if row is None:
        _fail("get_tlm_current after flush")
    if row.get("ADCS_MODE") != 2 or row.get("SUN_VALID") != 1:
        _fail(f"after flush ADCS_MODE/SUN_VALID {row}")
    if abs(float(row.get("WBN_X", 0)) + 0.002) > 1e-9:
        _fail(f"after flush WBN_X {row.get('WBN_X')}")
    _ok("DO-style flush: pending → SAT_TLM_CURRENT once")

    rx._merge_tlm_pending({"_DO_RW_TCMD_X": 0.5, "ADCS_MODE": 3})
    snap = DBManager.filter_tlm_current_fields(rx._tlm_pending)
    if "_DO_RW_TCMD_X" in snap or any(k.startswith("_") for k in snap):
        _fail("internal keys in filtered tlm")
    _ok("filter_tlm_current_fields strips internal keys")

    db.close()


def test_serial_reader_parsing(tmp_db: Path) -> None:
    db = DBManager(tmp_db)
    if not db.init_db():
        _fail("serial test init_db")
    shutdown = threading.Event()
    ctx = RuntimeContext(config=DaemonConfig(db_path=tmp_db), shutdown_event=shutdown, db=db)
    reader = SerialReader(ctx)

    pwr = reader._parse_serial_line("1,3.312,0.0450,60001")
    if pwr is None or pwr["sw_id"] != 1 or abs(pwr["voltage"] - 3.312) > 1e-6:
        _fail(f"parse_serial_line power {pwr}")
    _ok("parse_serial_line power CSV")

    if reader._parse_serial_line("9,3.0,0.1,1") is not None:
        _fail("parse_serial_line should reject sw_id>2")
    _ok("parse_serial_line sw_id range")

    if reader._parse_serial_line("x,y,z") is not None:
        _fail("parse_serial_line should reject non-numeric")
    _ok("parse_serial_line invalid CSV")

    light = reader._parse_light_line("L,light,60002")
    if light != "light":
        _fail(f"parse_light_line light {light}")
    dark = reader._parse_light_line("L,dark,61003")
    if dark != "dark":
        _fail(f"parse_light_line dark {dark}")
    _ok("parse_light_line L,light|dark")

    if not reader._validate_power_range({"sw_id": 0, "voltage": 3.3, "current_a": 0.1}):
        _fail("validate_power_range valid sample")
    if reader._validate_power_range({"sw_id": 0, "voltage": 99.0, "current_a": 0.1}):
        _fail("validate_power_range should reject voltage")
    _ok("validate_power_range")

    db.upsert_pwr_meta({"sw_id": 0, "voltage": 3.0, "current_a": 0.2})
    reader._dispatch_line("0,3.5,0.25,70000")
    m0 = db.get_pwr_meta(0)
    if m0 is None or abs(float(m0["VOLTAGE"]) - 3.5) > 1e-6:
        _fail(f"dispatch power line {m0}")
    _ok("dispatch_line power → upsert_pwr_meta")

    reader._dispatch_line("L,dark,80000")
    if reader.get_light_state() != "dark":
        _fail(f"dispatch light line state={reader.get_light_state()}")
    row3 = db.get_pwr_meta(3)
    if row3 is not None:
        _fail("L line must not create/update SAT_PWR_META sw_id=3")
    _ok("dispatch_line light — SW_ID 3 unchanged")

    reader._dispatch_line("# comment")
    reader._dispatch_line("")
    _ok("dispatch_line ignores # and blank")

    if reader.is_light_bright() is not False:
        _fail("is_light_bright after L,dark")
    reader._last_light = demon_config.SERIAL_LIGHT_STATE_LIGHT
    if reader.is_light_bright() is not True:
        _fail("is_light_bright after light")
    _ok("serial control helpers (is_light_bright)")

    db.close()


def test_fpf_pipeline_wiring(db_path: Path) -> None:
    """AnomalyDetector → FPF → GScomms wiring (runtime.py 와 동일 조립)."""
    db = DBManager(db_path)
    if not db.init_db():
        _fail("FPF wiring: init_db")
    shutdown = threading.Event()
    ctx = RuntimeContext(config=DaemonConfig(db_path=db_path), shutdown_event=shutdown, db=db)

    anomaly_detector = AnomalyDetector(ctx)
    gs_comms = GScomms(ctx)
    false_positive_filter = FalsePositiveFilter(
        PhysicalConsistencyModule(db),
        StatisticalConsistencyModule(db),
        SystemResponseModule(db),
        gs_comms,
    )
    anomaly_detector.set_false_positive_filter(false_positive_filter)
    anomaly_detector.set_gs_comms(gs_comms)

    if anomaly_detector._false_positive_filter is not false_positive_filter:
        _fail("FPF wiring: set_false_positive_filter")
    if false_positive_filter.gs_comms is not gs_comms:
        _fail("FPF wiring: gs_comms reference")

    mock_db = ExperimentMockDB("normal")
    fpf = FalsePositiveFilter(
        PhysicalConsistencyModule(mock_db),
        StatisticalConsistencyModule(mock_db),
        SystemResponseModule(mock_db),
        gs_comms,
    )
    key_set = {
        "tlm_id": 1,
        "sw_id": 0,
        "channel1": 1,
        "event_id": 1,
        "detected_at": "2026-05-12T12:00:00Z",
    }
    result = fpf.run_false_positive_filter(key_set)
    if "is_attack" not in result or "weighted_score" not in result:
        _fail("FPF wiring: run_false_positive_filter result keys")
    if not fpf.send_to_gscomms(result):
        _fail("FPF wiring: send_to_gscomms")
    ks = result.get("key_set") or {}
    if int(ks.get("event_id", 0)) < 1:
        _fail("FPF wiring: event_id not updated after insert_event")

    db.close()
    _ok("FPF pipeline wiring (AnomalyDetector → FPF → GScomms)")


def test_flush_trigger_mid_config() -> None:
    if demon_config.TLM_DB_FLUSH_TRIGGER_MID != demon_config.GENERIC_ADCS_DO_MID:
        _fail(
            f"flush trigger mid=0x{demon_config.TLM_DB_FLUSH_TRIGGER_MID:04x} "
            f"expected DO 0x{demon_config.GENERIC_ADCS_DO_MID:04x}",
        )
    _ok("TLM_DB_FLUSH_TRIGGER_MID == GENERIC_ADCS_DO_MID (0x0945)")


def test_gs_transmit_order(db_path: Path) -> None:
    """GScomms transmit_all — META→EVENT→ADCS→TLM→PWR 순서 및 META 필드 검증."""
    db = DBManager(db_path)
    if not db.init_db():
        _fail("GS transmit: init_db")

    shutdown = threading.Event()
    ctx = RuntimeContext(config=DaemonConfig(db_path=db_path), shutdown_event=shutdown, db=db)
    gs = GScomms(ctx)

    sent: list[dict[str, Any]] = []

    def mock_send(
        payload: dict[str, Any],
        on_ack_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> bool:
        sent.append(dict(payload))
        if on_ack_callback is not None:
            on_ack_callback({"ack": True})
        return True

    gs.send_with_retry = mock_send  # type: ignore[method-assign]

    e1 = db.insert_event(
        {
            "DETECTED_AT": "2026-05-30T12:00:00+00:00",
            "EVENT_TYPE": "ATTACK_CONFIRMED",
            "PRIORITY": 1,
            "IS_SENT": 0,
        },
    )
    e2 = db.insert_event(
        {
            "DETECTED_AT": "2026-05-30T12:00:01+00:00",
            "EVENT_TYPE": "SEU_DETECTED",
            "PRIORITY": 0,
            "IS_SENT": 0,
        },
    )
    if e1 < 1 or e2 < 1:
        _fail("GS transmit: insert_event seed")

    db.insert_adcs_filter({"Q_VALID": 1, "ST_VALID": 0})
    tlm_row = db.get_tlm_current()
    if tlm_row is None:
        _fail("GS transmit: get_tlm_current")
    if not db.insert_tlm_history(tlm_row):
        _fail("GS transmit: insert_tlm_history")
    if db.insert_pwr_history_snapshot() < 0:
        _fail("GS transmit: insert_pwr_history_snapshot")

    gs.transmit_all()

    types = [str(p.get("packet_type", "")) for p in sent]
    if not types:
        _fail("GS transmit: no packets sent")

    meta_idx = types.index(demon_config.GS_PACKET_TYPE_EVENT_META)
    if meta_idx != 0:
        _fail(f"GS transmit: META must be first, got order={types}")

    meta = sent[meta_idx]
    if int(meta.get("event_total", 0)) != 2:
        _fail(f"GS transmit: event_total expected 2 got {meta.get('event_total')}")
    meta_ids = meta.get("event_ids")
    if not isinstance(meta_ids, list) or sorted(meta_ids) != sorted([e1, e2]):
        _fail(f"GS transmit: event_ids mismatch {meta_ids}")

    event_indices = [i for i, t in enumerate(types) if t == demon_config.GS_PACKET_TYPE_EVENT]
    if len(event_indices) != 2:
        _fail(f"GS transmit: expected 2 EVENT packets, got {len(event_indices)}")

    idx_adcs = types.index(demon_config.GS_PACKET_TYPE_ADCS_FILTER)
    idx_tlm = types.index(demon_config.GS_PACKET_TYPE_TLM_HISTORY)
    idx_pwr = types.index(demon_config.GS_PACKET_TYPE_PWR_HISTORY)
    if not (max(event_indices) < idx_adcs < idx_tlm < idx_pwr):
        _fail(f"GS transmit: order ADCS<TLM<PWR violated: {types}")

    if db.get_pending_events():
        _fail("GS transmit: events should be deleted after ACK")

    db.close()
    _ok("GScomms transmit_all order (META→EVENT→ADCS→TLM→PWR)")


def main() -> int:
    try:
        test_flush_trigger_mid_config()
        tmp = Path(tempfile.mkdtemp()) / "verify.db"
        test_db_manager_api(tmp)
        test_serial_reader_parsing(Path(tempfile.mkdtemp()) / "verify_serial.db")
        test_do_flush_pending(Path(tempfile.mkdtemp()) / "verify2.db")
        test_fpf_pipeline_wiring(Path(tempfile.mkdtemp()) / "verify_fpf.db")
        test_gs_transmit_order(Path(tempfile.mkdtemp()) / "verify_gs.db")
        logger.info("=== All local integration checks passed ===")
        return 0
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 1
    except Exception as e:
        logger.error("verify 실패: %s", e)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
