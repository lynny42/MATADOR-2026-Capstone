#!/usr/bin/env python3
"""통합 검증 스크립트 — demon.main 기동 전 로컬에서 DB·파서·flush 동작 확인."""
from __future__ import annotations

import logging
import sqlite3
import sys
import tempfile
import threading
from pathlib import Path

from demon import config as demon_config
from demon.core.context import DaemonConfig, RuntimeContext
from demon.db.db_manager import DBManager
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
    m0 = db.get_pwr_meta(0)
    if m0 is not None:
        db.insert_pwr_history(m0)
    db.upsert_pwr_meta({"sw_id": 0, "voltage": 3.4, "current_a": 0.5})
    m0 = db.get_pwr_meta(0)
    if m0 is None or abs(m0["CURR_DELTA_V"] - 0.3) > 1e-6:
        _fail(f"pwr delta expected 0.3 got {None if m0 is None else m0['CURR_DELTA_V']}")
    _ok("upsert_pwr_meta delta sliding window")
    if m0 is not None:
        db.insert_pwr_history(m0)
    conn = sqlite3.connect(tmp_db)
    pwr_hist_rows = conn.execute(
        "SELECT COUNT(*) FROM SAT_PWR_HISTORY WHERE SW_ID = 0",
    ).fetchone()[0]
    conn.close()
    if pwr_hist_rows < 2:
        _fail(f"SAT_PWR_HISTORY append count={pwr_hist_rows}")
    _ok("SAT_PWR_HISTORY append")

    db.update_pwr_exceed_meta(
        {"sw_id": 0, "exceed_count": 3, "consecutive_exceed": 2, "anomaly_flag": 1},
    )
    m0_flag = db.get_pwr_meta(0)
    if m0_flag is None or m0_flag["ANOMALY_FLAG"] != 1:
        _fail("update_pwr_exceed_meta")
    _ok("update_pwr_exceed_meta")

    eid = db.insert_event({
        "EVENT_TYPE": "VERIFY",
        "PRIORITY": 0,
        "CHENNEL1": 5,
        "SW_ID": 1,
    })
    ev = db.get_event(eid)
    if ev is None or ev.get("CHENNEL1") != 5:
        _fail(f"insert_event CHENNEL1 {ev}")
    if eid < 1 or len(db.get_pending_events()) != 1:
        _fail("insert_event / get_pending_events")
    db.mark_event_sent(eid)
    db.delete_event(eid)
    _ok("event queue lifecycle")

    db.upsert_tlm_current({"ADCS_MODE": 2, "SUN_VALID": 1, "WBN_X": -0.001})
    tlm_snap = db.get_tlm_current()
    if tlm_snap is not None:
        db.insert_tlm_history(tlm_snap)
    if not db.is_sunlight_window():
        _fail("is_sunlight_window")
    _ok("upsert_tlm_current + is_sunlight_window")
    conn = sqlite3.connect(tmp_db)
    tlm_hist_rows = conn.execute("SELECT COUNT(*) FROM SAT_TLM_HISTORY").fetchone()[0]
    conn.close()
    if tlm_hist_rows < 1:
        _fail(f"SAT_TLM_HISTORY append count={tlm_hist_rows}")
    _ok("SAT_TLM_HISTORY append")

    db.insert_adcs_filter({"QBN_0": 1.0, "SUN_VALID": 1, "_ADCS_HK_CMD_CNT": 10})
    adcs = db.get_adcs_filter()
    if adcs is None or adcs.get("QBN_0") != 1.0:
        _fail(f"get_adcs_filter {adcs}")
    _ok("insert_adcs_filter + get_adcs_filter")

    db.insert_adcs_filter({"QBN_0": 0.9, "SUN_VALID": 0})
    latest = db.get_adcs_filter()
    if latest is None or latest.get("QBN_0") != 0.9:
        _fail(f"insert_adcs_filter latest row {latest}")
    all_adcs = db.get_adcs_filter_all()
    if len(all_adcs) < 2:
        _fail(f"get_adcs_filter_all count={len(all_adcs)}")
    if not db.delete_adcs_filter():
        _fail("delete_adcs_filter")
    if db.get_adcs_filter_all():
        _fail("delete_adcs_filter should clear table")
    _ok("insert_adcs_filter append + get_adcs_filter_all + delete_adcs_filter")

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
    conn = sqlite3.connect(tmp_db)
    tlm_hist = conn.execute("SELECT COUNT(*) FROM SAT_TLM_HISTORY").fetchone()[0]
    conn.close()
    if tlm_hist < 1:
        _fail(f"SAT_TLM_HISTORY after flush count={tlm_hist}")
    _ok("DO-style flush: pending → SAT_TLM_CURRENT + history")

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
    conn = sqlite3.connect(tmp_db)
    pwr_hist = conn.execute(
        "SELECT COUNT(*) FROM SAT_PWR_HISTORY WHERE SW_ID = 0",
    ).fetchone()[0]
    conn.close()
    if pwr_hist < 1:
        _fail(f"SAT_PWR_HISTORY after dispatch count={pwr_hist}")
    _ok("dispatch_line power → upsert_pwr_meta + history")

    reader._dispatch_line("L,dark,80000")
    if reader.get_light_state() != "dark":
        _fail(f"dispatch light line state={reader.get_light_state()}")
    row3 = db.get_pwr_meta(3)
    if row3 is None or float(row3["VOLTAGE"]) != 0.0:
        _fail("L line must not update SAT_PWR_META sw_id=3")
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


def test_flush_trigger_mid_config() -> None:
    if demon_config.TLM_DB_FLUSH_TRIGGER_MID != demon_config.GENERIC_ADCS_DO_MID:
        _fail(
            f"flush trigger mid=0x{demon_config.TLM_DB_FLUSH_TRIGGER_MID:04x} "
            f"expected DO 0x{demon_config.GENERIC_ADCS_DO_MID:04x}",
        )
    _ok("TLM_DB_FLUSH_TRIGGER_MID == GENERIC_ADCS_DO_MID (0x0945)")


def main() -> int:
    try:
        test_flush_trigger_mid_config()
        tmp = Path(tempfile.mkdtemp()) / "verify.db"
        test_db_manager_api(tmp)
        test_serial_reader_parsing(Path(tempfile.mkdtemp()) / "verify_serial.db")
        test_do_flush_pending(Path(tempfile.mkdtemp()) / "verify2.db")
        logger.info("=== All local integration checks passed ===")
        return 0
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 1
    except Exception as e:
        logger.error("verify 실패: %s", e)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
