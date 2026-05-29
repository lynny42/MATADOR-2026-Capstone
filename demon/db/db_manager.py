"""
SQLite 런타임 접근 — 위성체 안티탬퍼링 앱 DBManager.

- 스키마 DDL 은 init_db.py 가 담당한다.
- 워커는 SQL 을 직접 실행하지 않고 이 클래스만 사용한다.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .. import config as demon_config
from .init_db import init_db as apply_schema

logger = logging.getLogger(__name__)

_TLM_COLS = frozenset(demon_config.TLM_CURRENT_UPDATEABLE_COLS)

# insert_adcs_filter: 파서 내부 키 → SAT_ADCS_FILTER 컬럼
_ADCS_FILTER_KEY_ALIASES: dict[str, str] = {
    "_ADCS_HK_CMD_CNT": "CMDCOUNTER",
}

_ADCS_FILTER_NULLABLE_COLS: frozenset[str] = frozenset({
    "QBN_0", "QBN_1", "QBN_2", "QBN_3",
    "ST_QBN_0", "ST_QBN_1", "ST_QBN_2", "ST_QBN_3",
    "THERR_X", "THERR_Y", "THERR_Z",
    "CMD_WBN_X", "CMD_WBN_Y", "CMD_WBN_Z",
    "BDOT_X", "BDOT_Y", "BDOT_Z",
    "IMU_WBN_X", "IMU_WBN_Y", "IMU_WBN_Z",
    "IMU_ACC_X", "IMU_ACC_Y", "IMU_ACC_Z",
})

_EVENT_INT_DEFAULTS: dict[str, int] = {
    "PIPEOVERFLOWRRCNT": 0,
    "CHILDQUEUECOUNT": 0,
    "FILEWRITEERRCOUNTER": 0,
    "CMDREJECTEDCOUNTER": 0,
    "CH1_CH2_FAULT_CRC": 0,
    "CH1_FAULT_FILE_SIZE_MISMATCH": 0,
    "PROCESSOR_RESET_COUNT": 0,
    "IS_SENT": 0,
    "PRIORITY": 0,
}


def _utc_now_iso() -> str:
    try:
        return datetime.now(timezone.utc).isoformat()
    except Exception as e:
        logger.error("UTC 시각 생성 실패: %s", e)
        return "1970-01-01T00:00:00+00:00"


def _mapping_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {str(k): row[k] for k in row.keys()}


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        return {}
    try:
        return _mapping_from_row(row)
    except Exception as e:
        logger.error("row→dict 변환 실패: %s", e)
        return {}


def _row_to_dict_or_none(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    try:
        return _mapping_from_row(row)
    except Exception as e:
        logger.error("row→dict 변환 실패: %s", e)
        return None


class DBManager:
    """위성체 온보드 SQLite 중간 저장소."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = Path(db_path)
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    @property
    def db_path(self) -> Path:
        return self._db_path

    def init_db(self) -> bool:
        """스키마 적용 + 연결 + SAT_PWR_META 시드(SW_ID 0~3)."""
        try:
            apply_schema(self._db_path)
        except sqlite3.Error as e:
            logger.error("스키마 적용 실패(SQLite): %s", e)
            return False
        except Exception as e:
            logger.error("스키마 적용 실패: %s", e)
            return False

        try:
            with self._lock:
                if self._conn is not None:
                    try:
                        self._conn.close()
                    except sqlite3.Error as e:
                        logger.error("기존 연결 close 실패: %s", e)
                self._conn = sqlite3.connect(
                    str(self._db_path),
                    check_same_thread=False,
                )
                self._conn.row_factory = sqlite3.Row
                self._conn.execute(
                    f"PRAGMA busy_timeout={int(demon_config.SQLITE_BUSY_TIMEOUT_MS)}",
                )
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._seed_sat_pwr_meta()
                self._conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error("DBManager 연결 실패(SQLite): %s", e)
            return False
        except Exception as e:
            logger.error("DBManager init_db 실패: %s", e)
            return False

    def close(self) -> None:
        """연결 종료."""
        try:
            with self._lock:
                if self._conn is not None:
                    self._conn.close()
                    self._conn = None
        except sqlite3.Error as e:
            logger.error("DBManager close 실패(SQLite): %s", e)
        except Exception as e:
            logger.error("DBManager close 실패: %s", e)

    def _seed_sat_pwr_meta(self) -> None:
        """SW_ID 0~3 기본 임계치 행 INSERT OR IGNORE."""
        if self._conn is None:
            return
        try:
            now = _utc_now_iso()
            for sw_id in range(demon_config.PWR_SW_ID_COUNT):
                lo = float(demon_config.V_THRESHOLD_LO[sw_id])
                hi = float(demon_config.V_THRESHOLD_HI[sw_id])
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO SAT_PWR_META (
                      SW_ID, UPDATED_AT, VOLTAGE, PREV_VOLTAGE, CURRENT_A,
                      PREV_DELTA_V, CURR_DELTA_V, EXCEED_COUNT, CONSECUTIVE_EXCEED,
                      ANOMALY_FLAG, V_THRESHOLD_LO, V_THRESHOLD_HI
                    ) VALUES (?, ?, 0.0, 0.0, 0.0, 0.0, 0.0, 0, 0, 0, ?, ?)
                    """,
                    (sw_id, now, lo, hi),
                )
        except sqlite3.Error as e:
            logger.error("SAT_PWR_META 시드 실패(SQLite): %s", e)
            raise
        except Exception as e:
            logger.error("SAT_PWR_META 시드 실패: %s", e)
            raise

    @staticmethod
    def filter_tlm_current_fields(tlm: dict[str, Any]) -> dict[str, Any]:
        """SAT_TLM_CURRENT 화이트리스트 필드만 추출 (UDP pending flush 공용)."""
        try:
            return {k: v for k, v in tlm.items() if k in _TLM_COLS}
        except Exception as e:
            logger.error("filter_tlm_current_fields 실패: %s", e)
            return {}

    def _insert_tlm_history_locked(self, tlm_row: dict[str, Any]) -> None:
        """현재 TLM 스냅샷을 SAT_TLM_HISTORY 에 append (lock 보유 상태에서 호출)."""
        try:
            if self._conn is None:
                return
            self._conn.execute(
                """
                INSERT INTO SAT_TLM_HISTORY (
                  TLM_ID, UPDATED_AT, MISSION_MODE, OBC_S_TICK, HEAP_FREE,
                  APPENABLESTATE, DWELL_MASK, ADCS_MODE,
                  SVB_X, SVB_Y, SVB_Z, WBN_X, WBN_Y, WBN_Z,
                  DT, TORQUER_PERIOD, SUN_VALID
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(tlm_row.get("TLM_ID", demon_config.SAT_TLM_ID)),
                    str(tlm_row.get("UPDATED_AT", _utc_now_iso())),
                    int(tlm_row.get("MISSION_MODE", 0)),
                    int(tlm_row.get("OBC_S_TICK", 0)),
                    int(tlm_row.get("HEAP_FREE", 0)),
                    int(tlm_row.get("APPENABLESTATE", 0)),
                    int(tlm_row.get("DWELL_MASK", 0)),
                    int(tlm_row.get("ADCS_MODE", 0)),
                    float(tlm_row.get("SVB_X", 0.0)),
                    float(tlm_row.get("SVB_Y", 0.0)),
                    float(tlm_row.get("SVB_Z", 0.0)),
                    float(tlm_row.get("WBN_X", 0.0)),
                    float(tlm_row.get("WBN_Y", 0.0)),
                    float(tlm_row.get("WBN_Z", 0.0)),
                    float(tlm_row.get("DT", 0.0)),
                    int(tlm_row.get("TORQUER_PERIOD", 0)),
                    int(tlm_row.get("SUN_VALID", 0)),
                ),
            )
        except sqlite3.Error as e:
            logger.error("SAT_TLM_HISTORY append 실패(SQLite): %s", e)
        except Exception as e:
            logger.error("SAT_TLM_HISTORY append 실패: %s", e)

    def _insert_pwr_history_locked(self, pwr_row: dict[str, Any]) -> None:
        """현재 전력 스냅샷을 SAT_PWR_HISTORY 에 append (lock 보유 상태에서 호출)."""
        try:
            if self._conn is None:
                return
            self._conn.execute(
                """
                INSERT INTO SAT_PWR_HISTORY (
                  SW_ID, UPDATED_AT, VOLTAGE, PREV_VOLTAGE, CURRENT_A,
                  PREV_DELTA_V, CURR_DELTA_V, EXCEED_COUNT, CONSECUTIVE_EXCEED,
                  ANOMALY_FLAG, V_THRESHOLD_LO, V_THRESHOLD_HI
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(pwr_row.get("SW_ID", 0)),
                    str(pwr_row.get("UPDATED_AT", _utc_now_iso())),
                    float(pwr_row.get("VOLTAGE", 0.0)),
                    float(pwr_row.get("PREV_VOLTAGE", 0.0)),
                    float(pwr_row.get("CURRENT_A", 0.0)),
                    float(pwr_row.get("PREV_DELTA_V", 0.0)),
                    float(pwr_row.get("CURR_DELTA_V", 0.0)),
                    int(pwr_row.get("EXCEED_COUNT", 0)),
                    int(pwr_row.get("CONSECUTIVE_EXCEED", 0)),
                    int(pwr_row.get("ANOMALY_FLAG", 0)),
                    float(pwr_row.get("V_THRESHOLD_LO", 0.0)),
                    float(pwr_row.get("V_THRESHOLD_HI", 0.0)),
                ),
            )
        except sqlite3.Error as e:
            logger.error("SAT_PWR_HISTORY append 실패(SQLite): %s", e)
        except Exception as e:
            logger.error("SAT_PWR_HISTORY append 실패: %s", e)

    def upsert_tlm_current(self, tlm: dict[str, Any]) -> bool:
        """SAT_TLM_CURRENT TLM_ID=1 행 부분 UPDATE."""
        try:
            safe = self.filter_tlm_current_fields(tlm)
            if not safe:
                return True

            now = _utc_now_iso()
            safe["UPDATED_AT"] = now
            cols = ["UPDATED_AT = ?"] + [f"{k} = ?" for k in safe if k != "UPDATED_AT"]
            vals = [safe["UPDATED_AT"]] + [safe[k] for k in safe if k != "UPDATED_AT"]
            sql = (
                f"UPDATE SAT_TLM_CURRENT SET {', '.join(cols)} "
                f"WHERE TLM_ID = ?"
            )
            vals.append(demon_config.SAT_TLM_ID)

            with self._lock:
                if self._conn is None:
                    logger.error("upsert_tlm_current: DB 미연결")
                    return False
                cur = self._conn.execute(sql, vals)
                if cur.rowcount == 0:
                    logger.warning("upsert_tlm_current: TLM_ID=%s 행 없음", demon_config.SAT_TLM_ID)
                    return False
                snap_cur = self._conn.execute(
                    "SELECT * FROM SAT_TLM_CURRENT WHERE TLM_ID = ?",
                    (demon_config.SAT_TLM_ID,),
                )
                snap = _row_to_dict_or_none(snap_cur.fetchone())
                if snap is not None:
                    self._insert_tlm_history_locked(snap)
                self._conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error("upsert_tlm_current 실패(SQLite): %s", e)
            return False
        except Exception as e:
            logger.error("upsert_tlm_current 실패: %s", e)
            return False

    def get_tlm_current(self) -> dict[str, Any] | None:
        """SAT_TLM_CURRENT TLM_ID=1 전체 행. 없거나 실패 시 None."""
        try:
            with self._lock:
                if self._conn is None:
                    logger.error("get_tlm_current: DB 미연결")
                    return None
                cur = self._conn.execute(
                    "SELECT * FROM SAT_TLM_CURRENT WHERE TLM_ID = ?",
                    (demon_config.SAT_TLM_ID,),
                )
                return _row_to_dict_or_none(cur.fetchone())
        except sqlite3.Error as e:
            logger.error("get_tlm_current 실패(SQLite): %s", e)
            return None
        except Exception as e:
            logger.error("get_tlm_current 실패: %s", e)
            return None

    def get_mission_mode(self) -> int:
        """SAT_TLM_CURRENT.MISSION_MODE."""
        try:
            row = self.get_tlm_current()
            if row is None:
                return 0
            if "MISSION_MODE" in row and row["MISSION_MODE"] is not None:
                return int(row["MISSION_MODE"])
            return 0
        except (ValueError, TypeError) as e:
            logger.error("get_mission_mode 변환 오류: %s", e)
            return 0
        except Exception as e:
            logger.error("get_mission_mode 실패: %s", e)
            return 0

    def is_sunlight_window(self) -> bool:
        """SUN_VALID==1 이면 일광(지상국 송신 윈도우 후보)."""
        try:
            row = self.get_tlm_current()
            if row is None:
                return False
            val = row.get("SUN_VALID")
            if val is None:
                return False
            return int(val) == 1
        except (ValueError, TypeError) as e:
            logger.error("is_sunlight_window 변환 오류: %s", e)
            return False
        except Exception as e:
            logger.error("is_sunlight_window 실패: %s", e)
            return False

    def upsert_pwr_meta(self, pwr_sample: dict[str, Any]) -> bool:
        """
        SAT_PWR_META UPSERT — 전압·전류 및 delta 슬라이딩 윈도우.

        pwr_sample: {sw_id, voltage, current_a} (timestamp 는 DBManager 가 설정)
        """
        try:
            sw_id = int(pwr_sample["sw_id"])
            voltage = float(pwr_sample["voltage"])
            current_a = float(pwr_sample["current_a"])
            now = _utc_now_iso()

            with self._lock:
                if self._conn is None:
                    logger.error("upsert_pwr_meta: DB 미연결")
                    return False
                cur = self._conn.execute(
                    "SELECT VOLTAGE, CURR_DELTA_V FROM SAT_PWR_META WHERE SW_ID = ?",
                    (sw_id,),
                )
                row = cur.fetchone()
                if row is None:
                    lo = float(demon_config.V_THRESHOLD_LO[sw_id])
                    hi = float(demon_config.V_THRESHOLD_HI[sw_id])
                    self._conn.execute(
                        """
                        INSERT INTO SAT_PWR_META (
                          SW_ID, UPDATED_AT, VOLTAGE, PREV_VOLTAGE, CURRENT_A,
                          PREV_DELTA_V, CURR_DELTA_V, EXCEED_COUNT, CONSECUTIVE_EXCEED,
                          ANOMALY_FLAG, V_THRESHOLD_LO, V_THRESHOLD_HI
                        ) VALUES (?, ?, ?, 0.0, ?, 0.0, 0.0, 0, 0, 0, ?, ?)
                        """,
                        (sw_id, now, voltage, current_a, lo, hi),
                    )
                else:
                    prev_v = float(row["VOLTAGE"])
                    prev_dv = float(row["CURR_DELTA_V"])
                    curr_dv = voltage - prev_v
                    self._conn.execute(
                        """
                        UPDATE SAT_PWR_META SET
                          UPDATED_AT = ?,
                          PREV_VOLTAGE = ?,
                          PREV_DELTA_V = ?,
                          VOLTAGE = ?,
                          CURRENT_A = ?,
                          CURR_DELTA_V = ?
                        WHERE SW_ID = ?
                        """,
                        (now, prev_v, prev_dv, voltage, current_a, curr_dv, sw_id),
                    )
                snap_cur = self._conn.execute(
                    "SELECT * FROM SAT_PWR_META WHERE SW_ID = ?",
                    (sw_id,),
                )
                snap = _row_to_dict_or_none(snap_cur.fetchone())
                if snap is not None:
                    self._insert_pwr_history_locked(snap)
                self._conn.commit()
            return True
        except (KeyError, ValueError, TypeError) as e:
            logger.error("upsert_pwr_meta 입력 오류: %s", e)
            return False
        except sqlite3.Error as e:
            logger.error("upsert_pwr_meta 실패(SQLite): %s", e)
            return False
        except Exception as e:
            logger.error("upsert_pwr_meta 실패: %s", e)
            return False

    def update_pwr_exceed_meta(self, exceed_info: dict[str, Any]) -> bool:
        """AnomalyDetector — EXCEED_COUNT / CONSECUTIVE_EXCEED / ANOMALY_FLAG 갱신."""
        try:
            sw_id = int(exceed_info["sw_id"])
            exceed_count = int(exceed_info["exceed_count"])
            consecutive = int(exceed_info["consecutive_exceed"])
            anomaly_flag = int(exceed_info["anomaly_flag"])
            now = _utc_now_iso()

            with self._lock:
                if self._conn is None:
                    logger.error("update_pwr_exceed_meta: DB 미연결")
                    return False
                self._conn.execute(
                    """
                    UPDATE SAT_PWR_META SET
                      UPDATED_AT = ?,
                      EXCEED_COUNT = ?,
                      CONSECUTIVE_EXCEED = ?,
                      ANOMALY_FLAG = ?
                    WHERE SW_ID = ?
                    """,
                    (now, exceed_count, consecutive, anomaly_flag, sw_id),
                )
                self._conn.commit()
            return True
        except (KeyError, ValueError, TypeError) as e:
            logger.error("update_pwr_exceed_meta 입력 오류: %s", e)
            return False
        except sqlite3.Error as e:
            logger.error("update_pwr_exceed_meta 실패(SQLite): %s", e)
            return False
        except Exception as e:
            logger.error("update_pwr_exceed_meta 실패: %s", e)
            return False

    def get_pwr_meta(self, sw_id: int) -> dict[str, Any] | None:
        """채널 1개 SAT_PWR_META 전체. 없거나 실패 시 None."""
        try:
            with self._lock:
                if self._conn is None:
                    logger.error("get_pwr_meta: DB 미연결")
                    return None
                cur = self._conn.execute(
                    "SELECT * FROM SAT_PWR_META WHERE SW_ID = ?",
                    (int(sw_id),),
                )
                return _row_to_dict_or_none(cur.fetchone())
        except (ValueError, TypeError) as e:
            logger.error("get_pwr_meta 입력 오류: %s", e)
            return None
        except sqlite3.Error as e:
            logger.error("get_pwr_meta 실패(SQLite): %s", e)
            return None
        except Exception as e:
            logger.error("get_pwr_meta 실패: %s", e)
            return None

    def get_pwr_meta_all(self) -> list[dict[str, Any]]:
        """전 채널 SAT_PWR_META (SW_ID 순). 실패 시 []."""
        try:
            with self._lock:
                if self._conn is None:
                    logger.error("get_pwr_meta_all: DB 미연결")
                    return []
                cur = self._conn.execute(
                    "SELECT * FROM SAT_PWR_META ORDER BY SW_ID",
                )
                return [_row_to_dict(r) for r in cur.fetchall()]
        except sqlite3.Error as e:
            logger.error("get_pwr_meta_all 실패(SQLite): %s", e)
            return []
        except Exception as e:
            logger.error("get_pwr_meta_all 실패: %s", e)
            return []

    def get_all_pwr_meta(self) -> list[dict[str, Any]]:
        """get_pwr_meta_all 별칭 (하위 호환)."""
        return self.get_pwr_meta_all()

    def get_adcs_filter(self, channel1: int | None = None) -> dict[str, Any] | None:
        """SAT_ADCS_FILTER 단일 행 (CHENNEL1=channel1). 없거나 실패 시 None."""
        try:
            ch = (
                int(channel1)
                if channel1 is not None
                else int(demon_config.SAT_ADCS_FILTER_CHANNEL_ID)
            )
            with self._lock:
                if self._conn is None:
                    logger.error("get_adcs_filter: DB 미연결")
                    return None
                cur = self._conn.execute(
                    "SELECT * FROM SAT_ADCS_FILTER WHERE CHENNEL1 = ?",
                    (ch,),
                )
                return _row_to_dict_or_none(cur.fetchone())
        except (ValueError, TypeError) as e:
            logger.error("get_adcs_filter 입력 오류: %s", e)
            return None
        except sqlite3.Error as e:
            logger.error("get_adcs_filter 실패(SQLite): %s", e)
            return None
        except Exception as e:
            logger.error("get_adcs_filter 실패: %s", e)
            return None

    def get_event(self, event_id: int) -> dict[str, Any] | None:
        """SAT_EVENT_QUEUE 단일 행. 없거나 실패 시 None."""
        try:
            eid = int(event_id)
            with self._lock:
                if self._conn is None:
                    logger.error("get_event: DB 미연결")
                    return None
                cur = self._conn.execute(
                    "SELECT * FROM SAT_EVENT_QUEUE WHERE EVENT_ID = ?",
                    (eid,),
                )
                return _row_to_dict_or_none(cur.fetchone())
        except (ValueError, TypeError) as e:
            logger.error("get_event 입력 오류: %s", e)
            return None
        except sqlite3.Error as e:
            logger.error("get_event 실패(SQLite): %s", e)
            return None
        except Exception as e:
            logger.error("get_event 실패: %s", e)
            return None

    def get_integrity_hash(
        self, file_id: int | None = None,
    ) -> dict[str, Any] | list[dict[str, Any]] | None:
        """
        SAT_INTEGRITY_HASH 조회.

        file_id 지정 시 단일 dict, None 이면 전체 list[dict]. 실패 시 None.
        """
        try:
            with self._lock:
                if self._conn is None:
                    logger.error("get_integrity_hash: DB 미연결")
                    return None
                if file_id is not None:
                    cur = self._conn.execute(
                        "SELECT * FROM SAT_INTEGRITY_HASH WHERE FILE_ID = ?",
                        (int(file_id),),
                    )
                    return _row_to_dict_or_none(cur.fetchone())
                cur = self._conn.execute(
                    "SELECT * FROM SAT_INTEGRITY_HASH ORDER BY FILE_ID",
                )
                rows = [_row_to_dict(r) for r in cur.fetchall()]
                return rows
        except (ValueError, TypeError) as e:
            logger.error("get_integrity_hash 입력 오류: %s", e)
            return None
        except sqlite3.Error as e:
            logger.error("get_integrity_hash 실패(SQLite): %s", e)
            return None
        except Exception as e:
            logger.error("get_integrity_hash 실패: %s", e)
            return None

    def insert_event(self, event: dict[str, Any]) -> int:
        """SAT_EVENT_QUEUE INSERT. 성공 시 event_id, 실패 시 -1."""
        try:
            now = _utc_now_iso()
            detected_at = str(event.get("DETECTED_AT", now))
            timestamp = str(event.get("TIMESTAMP", detected_at))
            event_type = str(event.get("EVENT_TYPE", "UNKNOWN"))
            priority = int(event.get("PRIORITY", 0))
            is_sent = int(event.get("IS_SENT", 0))

            counter_cols = [
                "PIPEOVERFLOWRRCNT",
                "CHILDQUEUECOUNT",
                "FILEWRITEERRCOUNTER",
                "CMDREJECTEDCOUNTER",
                "CH1_CH2_FAULT_CRC",
                "CH1_FAULT_FILE_SIZE_MISMATCH",
                "PROCESSOR_RESET_COUNT",
            ]
            cols = ["DETECTED_AT", *counter_cols, "IS_SENT", "TIMESTAMP", "PRIORITY", "EVENT_TYPE"]
            vals: list[Any] = [detected_at]
            for col in counter_cols:
                vals.append(int(event.get(col, _EVENT_INT_DEFAULTS.get(col, 0))))
            vals.extend([is_sent, timestamp, priority, event_type])

            placeholders = ", ".join("?" * len(cols))
            col_names = ", ".join(cols)
            sql = f"INSERT INTO SAT_EVENT_QUEUE ({col_names}) VALUES ({placeholders})"

            with self._lock:
                if self._conn is None:
                    logger.error("insert_event: DB 미연결")
                    return -1
                cur = self._conn.execute(sql, vals)
                self._conn.commit()
                event_id = int(cur.lastrowid)
            return event_id
        except (ValueError, TypeError) as e:
            logger.error("insert_event 입력 오류: %s", e)
            return -1
        except sqlite3.Error as e:
            logger.error("insert_event 실패(SQLite): %s", e)
            return -1
        except Exception as e:
            logger.error("insert_event 실패: %s", e)
            return -1

    def get_pending_events(self) -> list[dict[str, Any]]:
        """IS_SENT=0 이벤트 — PRIORITY DESC, DETECTED_AT ASC."""
        try:
            with self._lock:
                if self._conn is None:
                    logger.error("get_pending_events: DB 미연결")
                    return []
                cur = self._conn.execute(
                    """
                    SELECT * FROM SAT_EVENT_QUEUE
                    WHERE IS_SENT = 0
                    ORDER BY PRIORITY DESC, DETECTED_AT ASC
                    """,
                )
                return [_row_to_dict(r) for r in cur.fetchall()]
        except sqlite3.Error as e:
            logger.error("get_pending_events 실패(SQLite): %s", e)
            return []
        except Exception as e:
            logger.error("get_pending_events 실패: %s", e)
            return []

    def mark_event_sent(self, event_id: int) -> bool:
        """IS_SENT=1."""
        try:
            with self._lock:
                if self._conn is None:
                    logger.error("mark_event_sent: DB 미연결")
                    return False
                self._conn.execute(
                    "UPDATE SAT_EVENT_QUEUE SET IS_SENT = 1 WHERE EVENT_ID = ?",
                    (int(event_id),),
                )
                self._conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error("mark_event_sent 실패(SQLite): %s", e)
            return False
        except Exception as e:
            logger.error("mark_event_sent 실패: %s", e)
            return False

    def delete_event(self, event_id: int) -> bool:
        """ACK 후 이벤트 삭제."""
        try:
            with self._lock:
                if self._conn is None:
                    logger.error("delete_event: DB 미연결")
                    return False
                self._conn.execute(
                    "DELETE FROM SAT_EVENT_QUEUE WHERE EVENT_ID = ?",
                    (int(event_id),),
                )
                self._conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error("delete_event 실패(SQLite): %s", e)
            return False
        except Exception as e:
            logger.error("delete_event 실패: %s", e)
            return False

    def insert_adcs_filter(self, data: dict[str, Any]) -> bool:
        """이상 감지 시점 ADCS 스냅샷 — SAT_ADCS_FILTER INSERT OR REPLACE (CHENNEL1당 1행)."""
        try:
            channel = int(data.get("CHENNEL1", demon_config.SAT_ADCS_FILTER_CHANNEL_ID))
            ts = str(data.get("TIMESTAMP", _utc_now_iso()))

            row: dict[str, Any] = {
                "CHENNEL1": channel,
                "TIMESTAMP": ts,
                "CMDCOUNTER": 0,
                "Q_VALID": 0,
                "H_MGMTON": 0,
                "SUN_VALID": 0,
                "DEVICE_ENABLED_RW0": 0,
                "DEVICE_ENABLED_RW1": 0,
                "DEVICE_ENABLED_RW2": 0,
                "QERR_0": 0.0,
                "QERR_1": 0.0,
                "QERR_2": 0.0,
                "QERR_3": 0.0,
                "TCMD_X": 0.0,
                "TCMD_Y": 0.0,
                "TCMD_Z": 0.0,
                "MCMD_X": 0.0,
                "MCMD_Y": 0.0,
                "MCMD_Z": 0.0,
                "WERR_X": 0.0,
                "WERR_Y": 0.0,
                "WERR_Z": 0.0,
                "MOMENTUM_NMS_0": 0.0,
                "MOMENTUM_NMS_1": 0.0,
                "MOMENTUM_NMS_2": 0.0,
                "ST_VALID": 0,
                "COMBINEDPACKETSSENT": 0,
                "ERLOGENTRIES": 0,
                "SKIPPEDSLOTSCOUNT": 0,
                "LASTVALCRC": "",
                "ENABLEDROUTES": 0,
                "FORWARD_ERR_COUNT": 0,
                "APPCSERRCOUNTER": 0,
                "OSCSERRCOUNTER": 0,
                "SYSLOGENTRIES": 0,
                "RESETSPERFORMED": 0,
                "EXECOUNTS": 0.0,
            }

            for src_key, val in data.items():
                if val is None:
                    continue
                col = _ADCS_FILTER_KEY_ALIASES.get(src_key, src_key)
                if col in row or col in _ADCS_FILTER_NULLABLE_COLS:
                    row[col] = val

            for col in _ADCS_FILTER_NULLABLE_COLS:
                if col not in row:
                    row[col] = None

            col_names = list(row.keys())
            placeholders = ", ".join("?" * len(col_names))
            sql = (
                f"INSERT OR REPLACE INTO SAT_ADCS_FILTER ({', '.join(col_names)}) "
                f"VALUES ({placeholders})"
            )
            vals = [row[c] for c in col_names]

            with self._lock:
                if self._conn is None:
                    logger.error("insert_adcs_filter: DB 미연결")
                    return False
                self._conn.execute(sql, vals)
                self._conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error("insert_adcs_filter 실패(SQLite): %s", e)
            return False
        except Exception as e:
            logger.error("insert_adcs_filter 실패: %s", e)
            return False

    def update_threshold(self, sw_id: int, lo: float, hi: float) -> bool:
        """지상국 UPDATE_THRESHOLD — V_THRESHOLD_LO/HI 갱신."""
        try:
            now = _utc_now_iso()
            with self._lock:
                if self._conn is None:
                    logger.error("update_threshold: DB 미연결")
                    return False
                self._conn.execute(
                    """
                    UPDATE SAT_PWR_META SET
                      V_THRESHOLD_LO = ?,
                      V_THRESHOLD_HI = ?,
                      UPDATED_AT = ?
                    WHERE SW_ID = ?
                    """,
                    (float(lo), float(hi), now, int(sw_id)),
                )
                self._conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error("update_threshold 실패(SQLite): %s", e)
            return False
        except Exception as e:
            logger.error("update_threshold 실패: %s", e)
            return False

    def delete_tlm_history_by_ids(self, history_ids: list[int]) -> int:
        """
        SAT_TLM_HISTORY에서 지정된 HISTORY_ID 목록 삭제.

        삭제 조건 결정은 호출자가 수행하고, 본 메서드는 삭제만 담당.
        반환: 삭제된 행 수.
        """
        try:
            if not history_ids:
                return 0
            ids = [int(v) for v in history_ids]
            placeholders = ", ".join("?" for _ in ids)
            sql = f"DELETE FROM SAT_TLM_HISTORY WHERE HISTORY_ID IN ({placeholders})"
            with self._lock:
                if self._conn is None:
                    logger.error("delete_tlm_history_by_ids: DB 미연결")
                    return 0
                cur = self._conn.execute(sql, ids)
                self._conn.commit()
                return int(cur.rowcount if cur.rowcount is not None else 0)
        except (ValueError, TypeError) as e:
            logger.error("delete_tlm_history_by_ids 입력 오류: %s", e)
            return 0
        except sqlite3.Error as e:
            logger.error("delete_tlm_history_by_ids 실패(SQLite): %s", e)
            return 0
        except Exception as e:
            logger.error("delete_tlm_history_by_ids 실패: %s", e)
            return 0

    def delete_pwr_history_by_ids(self, history_ids: list[int]) -> int:
        """
        SAT_PWR_HISTORY에서 지정된 HISTORY_ID 목록 삭제.

        삭제 조건 결정은 호출자가 수행하고, 본 메서드는 삭제만 담당.
        반환: 삭제된 행 수.
        """
        try:
            if not history_ids:
                return 0
            ids = [int(v) for v in history_ids]
            placeholders = ", ".join("?" for _ in ids)
            sql = f"DELETE FROM SAT_PWR_HISTORY WHERE HISTORY_ID IN ({placeholders})"
            with self._lock:
                if self._conn is None:
                    logger.error("delete_pwr_history_by_ids: DB 미연결")
                    return 0
                cur = self._conn.execute(sql, ids)
                self._conn.commit()
                return int(cur.rowcount if cur.rowcount is not None else 0)
        except (ValueError, TypeError) as e:
            logger.error("delete_pwr_history_by_ids 입력 오류: %s", e)
            return 0
        except sqlite3.Error as e:
            logger.error("delete_pwr_history_by_ids 실패(SQLite): %s", e)
            return 0
        except Exception as e:
            logger.error("delete_pwr_history_by_ids 실패: %s", e)
            return 0
