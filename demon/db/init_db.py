#!/usr/bin/env python3
"""
SQLite DB 초기화: 위성체 안티탬퍼링 앱용 명세 테이블 생성.

저장소 루트에서 실행:

    python3 -m demon.db.init_db [DB경로]

기본 DB 경로: demon/database.sqlite
"""
from __future__ import annotations

import argparse
import logging
import sqlite3
from pathlib import Path

from .paths import default_db_path

# 명세 타입 매핑: INT/UINT32/TINYINT/BIT/BITMASK -> INTEGER, FLOAT -> REAL,
# TIMESTAMP/DATETIME/VARCHAR -> TEXT

logger = logging.getLogger(__name__)


def _seed_sat_tlm_current(conn: sqlite3.Connection) -> None:
    """TLM_ID=1 기본 행 — UDPReceiver가 UPDATE만 할 수 있도록 보장."""
    try:
        conn.execute(
            """
            INSERT OR IGNORE INTO SAT_TLM_CURRENT (
              TLM_ID, UPDATED_AT, MISSION_MODE, OBC_S_TICK, HEAP_FREE,
              APPENABLESTATE, DWELL_MASK, ADCS_MODE,
              SVB_X, SVB_Y, SVB_Z, WBN_X, WBN_Y, WBN_Z,
              DT, TORQUER_PERIOD, SUN_VALID
            ) VALUES (
              1, '1970-01-01T00:00:00Z', 0, 0, 0,
              0, 0, 0,
              0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
              0.0, 0, 0
            )
            """
        )
    except sqlite3.Error as e:
        logger.error("SAT_TLM_CURRENT 시드 실패: %s", e)
        raise
    except Exception as e:
        logger.error("SAT_TLM_CURRENT 시드 실패: %s", e)
        raise


DDL_STATEMENTS: list[str] = [
    # SAT_TLM_CURRENT — 위성체 상태(순환 버퍼는 앱 로직에서 관리)
    """
    CREATE TABLE IF NOT EXISTS SAT_TLM_CURRENT (
      TLM_ID INTEGER NOT NULL PRIMARY KEY,
      UPDATED_AT TEXT NOT NULL,
      MISSION_MODE INTEGER NOT NULL,
      OBC_S_TICK INTEGER NOT NULL,
      HEAP_FREE INTEGER NOT NULL,
      APPENABLESTATE INTEGER NOT NULL,
      DWELL_MASK INTEGER NOT NULL,
      ADCS_MODE INTEGER NOT NULL,
      SVB_X REAL NOT NULL,
      SVB_Y REAL NOT NULL,
      SVB_Z REAL NOT NULL,
      WBN_X REAL NOT NULL,
      WBN_Y REAL NOT NULL,
      WBN_Z REAL NOT NULL,
      DT REAL NOT NULL,
      TORQUER_PERIOD INTEGER NOT NULL,
      SUN_VALID INTEGER NOT NULL
    )
    """,
    # SAT_TLM_HISTORY — SAT_TLM_CURRENT 누적 히스토리
    """
    CREATE TABLE IF NOT EXISTS SAT_TLM_HISTORY (
      HISTORY_ID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
      TLM_ID INTEGER NOT NULL,
      UPDATED_AT TEXT NOT NULL,
      MISSION_MODE INTEGER NOT NULL,
      OBC_S_TICK INTEGER NOT NULL,
      HEAP_FREE INTEGER NOT NULL,
      APPENABLESTATE INTEGER NOT NULL,
      DWELL_MASK INTEGER NOT NULL,
      ADCS_MODE INTEGER NOT NULL,
      SVB_X REAL NOT NULL,
      SVB_Y REAL NOT NULL,
      SVB_Z REAL NOT NULL,
      WBN_X REAL NOT NULL,
      WBN_Y REAL NOT NULL,
      WBN_Z REAL NOT NULL,
      DT REAL NOT NULL,
      TORQUER_PERIOD INTEGER NOT NULL,
      SUN_VALID INTEGER NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS IDX_TLM_HISTORY_UPDATED_AT
    ON SAT_TLM_HISTORY(UPDATED_AT)
    """,
    # SAT_PWR_META — 스위치별 전력 이상
    """
    CREATE TABLE IF NOT EXISTS SAT_PWR_META (
      SW_ID INTEGER NOT NULL PRIMARY KEY,
      UPDATED_AT TEXT NOT NULL,
      VOLTAGE REAL NOT NULL,
      PREV_VOLTAGE REAL NOT NULL,
      CURRENT_A REAL NOT NULL,
      PREV_DELTA_V REAL NOT NULL,
      CURR_DELTA_V REAL NOT NULL,
      EXCEED_COUNT INTEGER NOT NULL,
      CONSECUTIVE_EXCEED INTEGER NOT NULL,
      ANOMALY_FLAG INTEGER NOT NULL,
      V_THRESHOLD_LO REAL NOT NULL,
      V_THRESHOLD_HI REAL NOT NULL
    )
    """,
    # SAT_PWR_HISTORY — SAT_PWR_META 누적 히스토리
    """
    CREATE TABLE IF NOT EXISTS SAT_PWR_HISTORY (
      HISTORY_ID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
      SW_ID INTEGER NOT NULL,
      UPDATED_AT TEXT NOT NULL,
      VOLTAGE REAL NOT NULL,
      PREV_VOLTAGE REAL NOT NULL,
      CURRENT_A REAL NOT NULL,
      PREV_DELTA_V REAL NOT NULL,
      CURR_DELTA_V REAL NOT NULL,
      EXCEED_COUNT INTEGER NOT NULL,
      CONSECUTIVE_EXCEED INTEGER NOT NULL,
      ANOMALY_FLAG INTEGER NOT NULL,
      V_THRESHOLD_LO REAL NOT NULL,
      V_THRESHOLD_HI REAL NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS IDX_PWR_HISTORY_SW_ID_UPDATED_AT
    ON SAT_PWR_HISTORY(SW_ID, UPDATED_AT)
    """,
    # SAT_INTEGRITY_HASH — 파일 무결성
    """
    CREATE TABLE IF NOT EXISTS SAT_INTEGRITY_HASH (
      FILE_ID INTEGER NOT NULL PRIMARY KEY,
      FILE_PATH TEXT NOT NULL,
      EXPECTED_HASH TEXT NOT NULL,
      LAST_VERIFIED_AT TEXT NOT NULL,
      UPDATED_AT TEXT NOT NULL,
      IS_VIOLATED INTEGER NOT NULL
    )
    """,
    # SAT_EVENT_QUEUE — CH1/2_FAULT_CRC는 식별자에 슬래시 불가 → CH1_CH2_FAULT_CRC
    """
    CREATE TABLE IF NOT EXISTS SAT_EVENT_QUEUE (
      EVENT_ID INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
      DETECTED_AT TEXT NOT NULL,
      PIPEOVERFLOWRRCNT INTEGER NOT NULL,
      CHILDQUEUECOUNT INTEGER NOT NULL,
      FILEWRITEERRCOUNTER INTEGER NOT NULL,
      CMDREJECTEDCOUNTER INTEGER NOT NULL,
      CH1_CH2_FAULT_CRC INTEGER NOT NULL,
      CH1_FAULT_FILE_SIZE_MISMATCH INTEGER NOT NULL,
      PROCESSOR_RESET_COUNT INTEGER NOT NULL,
      IS_SENT INTEGER NOT NULL,
      TIMESTAMP TEXT NOT NULL,
      PRIORITY INTEGER NOT NULL,
      EVENT_TYPE TEXT NOT NULL,
      SW_ID INTEGER NOT NULL DEFAULT 0,
      WEIGHT INTEGER NOT NULL DEFAULT 0,
      EXCEPTION_CODE INTEGER NOT NULL DEFAULT 0,
      MODULE_SCORES TEXT NOT NULL DEFAULT '',
      CHENNEL1 INTEGER NOT NULL DEFAULT 0
    )
    """,
    # SAT_ADCS_FILTER — CHENNEL1·TIMESTAMP는 명세 표기 유지; NULL 허용은 명세 Yes/No에 따름
    """
    CREATE TABLE IF NOT EXISTS SAT_ADCS_FILTER (
      CHENNEL1 INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
      TIMESTAMP TEXT NOT NULL,
      CMDCOUNTER INTEGER NOT NULL,
      QBN_0 REAL,
      QBN_1 REAL,
      QBN_2 REAL,
      QBN_3 REAL,
      ST_QBN_0 REAL,
      ST_QBN_1 REAL,
      ST_QBN_2 REAL,
      ST_QBN_3 REAL,
      Q_VALID INTEGER NOT NULL,
      THERR_X REAL,
      THERR_Y REAL,
      THERR_Z REAL,
      CMD_WBN_X REAL,
      CMD_WBN_Y REAL,
      CMD_WBN_Z REAL,
      BDOT_X REAL,
      BDOT_Y REAL,
      BDOT_Z REAL,
      H_MGMTON INTEGER NOT NULL,
      SUN_VALID INTEGER NOT NULL,
      DEVICE_ENABLED_RW0 INTEGER NOT NULL,
      DEVICE_ENABLED_RW1 INTEGER NOT NULL,
      DEVICE_ENABLED_RW2 INTEGER NOT NULL,
      IMU_WBN_X REAL,
      IMU_WBN_Y REAL,
      IMU_WBN_Z REAL,
      IMU_ACC_X REAL,
      IMU_ACC_Y REAL,
      IMU_ACC_Z REAL,
      QERR_0 REAL NOT NULL,
      QERR_1 REAL NOT NULL,
      QERR_2 REAL NOT NULL,
      QERR_3 REAL NOT NULL,
      TCMD_X REAL NOT NULL,
      TCMD_Y REAL NOT NULL,
      TCMD_Z REAL NOT NULL,
      MCMD_X REAL NOT NULL,
      MCMD_Y REAL NOT NULL,
      MCMD_Z REAL NOT NULL,
      WERR_X REAL NOT NULL,
      WERR_Y REAL NOT NULL,
      WERR_Z REAL NOT NULL,
      MOMENTUM_NMS_0 REAL NOT NULL,
      MOMENTUM_NMS_1 REAL NOT NULL,
      MOMENTUM_NMS_2 REAL NOT NULL,
      ST_VALID INTEGER NOT NULL,
      COMBINEDPACKETSSENT INTEGER NOT NULL,
      ERLOGENTRIES INTEGER NOT NULL,
      SKIPPEDSLOTSCOUNT INTEGER NOT NULL,
      LASTVALCRC TEXT NOT NULL,
      ENABLEDROUTES INTEGER NOT NULL,
      FORWARD_ERR_COUNT INTEGER NOT NULL,
      APPCSERRCOUNTER INTEGER NOT NULL,
      OSCSERRCOUNTER INTEGER NOT NULL,
      SYSLOGENTRIES INTEGER NOT NULL,
      RESETSPERFORMED INTEGER NOT NULL,
      EXECOUNTS REAL NOT NULL
    )
    """,
]


def _table_has_column(conn: sqlite3.Connection, table: str, column: str) -> bool:
    try:
        cur = conn.execute(f"PRAGMA table_info({table})")
        return any(row[1] == column for row in cur.fetchall())
    except sqlite3.Error as e:
        logger.error("table_info 조회 실패(SQLite) %s.%s: %s", table, column, e)
        return False
    except Exception as e:
        logger.error("table_info 조회 실패 %s.%s: %s", table, column, e)
        return False


def _migrate_event_queue_columns(conn: sqlite3.Connection) -> None:
    """SAT_EVENT_QUEUE 확장 컬럼 — 기존 DB 호환."""
    try:
        additions: list[tuple[str, str]] = [
            ("SW_ID", "INTEGER NOT NULL DEFAULT 0"),
            ("WEIGHT", "INTEGER NOT NULL DEFAULT 0"),
            ("EXCEPTION_CODE", "INTEGER NOT NULL DEFAULT 0"),
            ("MODULE_SCORES", "TEXT NOT NULL DEFAULT ''"),
            ("CHENNEL1", "INTEGER NOT NULL DEFAULT 0"),
        ]
        for col, col_def in additions:
            if _table_has_column(conn, "SAT_EVENT_QUEUE", col):
                continue
            conn.execute(f"ALTER TABLE SAT_EVENT_QUEUE ADD COLUMN {col} {col_def}")
            logger.info("SAT_EVENT_QUEUE: %s 컬럼 추가", col)
    except sqlite3.Error as e:
        logger.error("SAT_EVENT_QUEUE 컬럼 마이그레이션 실패(SQLite): %s", e)
        raise
    except Exception as e:
        logger.error("SAT_EVENT_QUEUE 컬럼 마이그레이션 실패: %s", e)
        raise


def _migrate_adcs_filter_autoincrement(conn: sqlite3.Connection) -> None:
    """SAT_ADCS_FILTER.CHENNEL1 을 AUTOINCREMENT PK 로 재구성 (구 스키마 호환)."""
    try:
        schema_row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='SAT_ADCS_FILTER'",
        ).fetchone()
        if schema_row is not None and schema_row[0] and "AUTOINCREMENT" in str(schema_row[0]).upper():
            return
        cur = conn.execute("PRAGMA table_info(SAT_ADCS_FILTER)")
        rows = cur.fetchall()
        if not rows:
            return
        channel_col = next((r for r in rows if r[1] == "CHENNEL1"), None)
        if channel_col is None:
            return
        col_defs: list[str] = []
        select_cols: list[str] = []
        for r in rows:
            name = r[1]
            ctype = r[2] or "INTEGER"
            notnull = " NOT NULL" if r[3] else ""
            dflt = f" DEFAULT {r[4]}" if r[4] is not None else ""
            if name == "CHENNEL1":
                col_defs.append("CHENNEL1 INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT")
                select_cols.append("CHENNEL1")
            else:
                col_defs.append(f"{name} {ctype}{notnull}{dflt}")
                select_cols.append(name)
        conn.execute(
            f"CREATE TABLE IF NOT EXISTS SAT_ADCS_FILTER_NEW ({', '.join(col_defs)})",
        )
        conn.execute(
            f"INSERT INTO SAT_ADCS_FILTER_NEW ({', '.join(select_cols)}) "
            f"SELECT {', '.join(select_cols)} FROM SAT_ADCS_FILTER",
        )
        conn.execute("DROP TABLE SAT_ADCS_FILTER")
        conn.execute("ALTER TABLE SAT_ADCS_FILTER_NEW RENAME TO SAT_ADCS_FILTER")
        logger.info("SAT_ADCS_FILTER: CHENNEL1 AUTOINCREMENT 마이그레이션 완료")
    except sqlite3.Error as e:
        logger.error("SAT_ADCS_FILTER 마이그레이션 실패(SQLite): %s", e)
        raise
    except Exception as e:
        logger.error("SAT_ADCS_FILTER 마이그레이션 실패: %s", e)
        raise


def _migrate_integrity_hash_column(conn: sqlite3.Connection) -> None:
    """구 스키마 LAST_VERIFIEDA_AT → LAST_VERIFIED_AT 컬럼명 정리."""
    try:
        if not _table_has_column(conn, "SAT_INTEGRITY_HASH", "LAST_VERIFIEDA_AT"):
            return
        if _table_has_column(conn, "SAT_INTEGRITY_HASH", "LAST_VERIFIED_AT"):
            return
        conn.execute(
            "ALTER TABLE SAT_INTEGRITY_HASH "
            "RENAME COLUMN LAST_VERIFIEDA_AT TO LAST_VERIFIED_AT",
        )
        logger.info("SAT_INTEGRITY_HASH: LAST_VERIFIEDA_AT → LAST_VERIFIED_AT 마이그레이션 완료")
    except sqlite3.Error as e:
        logger.error("SAT_INTEGRITY_HASH 컬럼 마이그레이션 실패(SQLite): %s", e)
        raise
    except Exception as e:
        logger.error("SAT_INTEGRITY_HASH 컬럼 마이그레이션 실패: %s", e)
        raise


def init_db(db_path: Path) -> None:
    conn: sqlite3.Connection | None = None
    try:
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.error("DB 디렉터리 생성 실패: %s", e)
            raise
        conn = sqlite3.connect(db_path)
        for stmt in DDL_STATEMENTS:
            conn.execute(stmt)
        _migrate_integrity_hash_column(conn)
        _migrate_event_queue_columns(conn)
        _migrate_adcs_filter_autoincrement(conn)
        _seed_sat_tlm_current(conn)
        conn.commit()
    except sqlite3.Error as e:
        logger.error("SQLite 스키마 적용 실패: %s", e)
        raise
    except Exception as e:
        logger.error("init_db 실패: %s", e)
        raise
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error as e:
                logger.error("SQLite 연결 종료 실패: %s", e)


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        p = argparse.ArgumentParser(description="Create SQLite tables for anti-tamper satellite app.")
        p.add_argument(
            "db_path",
            nargs="?",
            default=None,
            type=Path,
            help="SQLite file path (default: demon/database.sqlite)",
        )
        args = p.parse_args()
        db_path: Path = args.db_path if args.db_path is not None else default_db_path()

        try:
            init_db(db_path)
        except sqlite3.Error as e:
            logger.error("SQLite 오류: %s", e)
            return 1
        except Exception as e:
            logger.error("DB 초기화 실패: %s", e)
            return 1

        try:
            resolved = db_path.resolve()
        except OSError as e:
            logger.error("DB 경로 resolve 실패(OSError): %s", e)
            return 1
        except Exception as e:
            logger.error("DB 경로 resolve 실패: %s", e)
            return 1

        logger.info("OK: %s", resolved)
        return 0
    except SystemExit:
        raise
    except Exception as e:
        logger.error("init_db CLI 실행 실패: %s", e)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
