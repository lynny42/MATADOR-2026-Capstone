"""
SQLite 런타임 접근 — 위성체 안티탬퍼링 앱 DBManager.

- 스키마 DDL 은 init_db.py 가 담당한다.
- 워커는 SQL 을 직접 실행하지 않고 이 클래스만 사용한다.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .. import config as demon_config
from .init_db import init_db as apply_schema
from ..core.time_utils import utc_now_iso

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
    "MAG_BVB_X", "MAG_BVB_Y", "MAG_BVB_Z",
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
    "SW_ID": 0,
    "WEIGHT": 0,
    "EXCEPTION_CODE": 0,
    "CHENNEL1": 0,
}

_EVENT_COUNTER_COLS: tuple[str, ...] = (
    "PIPEOVERFLOWRRCNT",
    "CHILDQUEUECOUNT",
    "FILEWRITEERRCOUNTER",
    "CMDREJECTEDCOUNTER",
    "CH1_CH2_FAULT_CRC",
    "CH1_FAULT_FILE_SIZE_MISMATCH",
    "PROCESSOR_RESET_COUNT",
)

_ADCS_FILTER_INSERT_COLS: tuple[str, ...] = (
    "TIMESTAMP",
    "CMDCOUNTER",
    "QBN_0",
    "QBN_1",
    "QBN_2",
    "QBN_3",
    "ST_QBN_0",
    "ST_QBN_1",
    "ST_QBN_2",
    "ST_QBN_3",
    "Q_VALID",
    "THERR_X",
    "THERR_Y",
    "THERR_Z",
    "CMD_WBN_X",
    "CMD_WBN_Y",
    "CMD_WBN_Z",
    "BDOT_X",
    "BDOT_Y",
    "BDOT_Z",
    "H_MGMTON",
    "SUN_VALID",
    "DEVICE_ENABLED_RW0",
    "DEVICE_ENABLED_RW1",
    "DEVICE_ENABLED_RW2",
    "IMU_WBN_X",
    "IMU_WBN_Y",
    "IMU_WBN_Z",
    "IMU_ACC_X",
    "IMU_ACC_Y",
    "IMU_ACC_Z",
    "MAG_BVB_X",
    "MAG_BVB_Y",
    "MAG_BVB_Z",
    "QERR_0",
    "QERR_1",
    "QERR_2",
    "QERR_3",
    "TCMD_X",
    "TCMD_Y",
    "TCMD_Z",
    "MCMD_X",
    "MCMD_Y",
    "MCMD_Z",
    "WERR_X",
    "WERR_Y",
    "WERR_Z",
    "MOMENTUM_NMS_0",
    "MOMENTUM_NMS_1",
    "MOMENTUM_NMS_2",
    "ST_VALID",
    "COMBINEDPACKETSSENT",
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
)


def _build_adcs_filter_row(data: dict[str, Any]) -> dict[str, Any]:
    """SAT_ADCS_FILTER INSERT용 행 dict (CHENNEL1·SNAPSHOT_ID 제외)."""
    try:
        ts = str(data.get("TIMESTAMP", utc_now_iso()))
        row: dict[str, Any] = {
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
            if src_key in ("CHENNEL1", demon_config.SNAPSHOT_ID_COL):
                continue
            col = _ADCS_FILTER_KEY_ALIASES.get(src_key, src_key)
            if col in row or col in _ADCS_FILTER_NULLABLE_COLS:
                row[col] = val
        for col in _ADCS_FILTER_NULLABLE_COLS:
            if col not in row:
                row[col] = None
        return row
    except Exception as e:
        logger.error("_build_adcs_filter_row 실패: %s", e)
        return {"TIMESTAMP": utc_now_iso(), "CMDCOUNTER": 0, "Q_VALID": 0, "H_MGMTON": 0,
                "SUN_VALID": 0, "DEVICE_ENABLED_RW0": 0, "DEVICE_ENABLED_RW1": 0,
                "DEVICE_ENABLED_RW2": 0, "QERR_0": 0.0, "QERR_1": 0.0, "QERR_2": 0.0,
                "QERR_3": 0.0, "TCMD_X": 0.0, "TCMD_Y": 0.0, "TCMD_Z": 0.0,
                "MCMD_X": 0.0, "MCMD_Y": 0.0, "MCMD_Z": 0.0, "WERR_X": 0.0,
                "WERR_Y": 0.0, "WERR_Z": 0.0, "MOMENTUM_NMS_0": 0.0,
                "MOMENTUM_NMS_1": 0.0, "MOMENTUM_NMS_2": 0.0, "ST_VALID": 0,
                "COMBINEDPACKETSSENT": 0, "ERLOGENTRIES": 0, "SKIPPEDSLOTSCOUNT": 0,
                "LASTVALCRC": "", "ENABLEDROUTES": 0, "FORWARD_ERR_COUNT": 0,
                "APPCSERRCOUNTER": 0, "OSCSERRCOUNTER": 0, "SYSLOGENTRIES": 0,
                "RESETSPERFORMED": 0, "EXECOUNTS": 0.0}


_ADCS_FILTER_COLS = frozenset(_ADCS_FILTER_INSERT_COLS)


def _coerce_tlm_column_value(col: str, val: Any) -> Any:
    """SAT_TLM_CURRENT/HISTORY INSERT·UPDATE용 타입 정규화."""
    try:
        if col == "LASTVALCRC":
            return str(val) if val is not None else ""
        if col in ("SVB_X", "SVB_Y", "SVB_Z", "WBN_X", "WBN_Y", "WBN_Z", "DT", "EXECOUNTS"):
            return float(val)
        return int(val)
    except (TypeError, ValueError) as e:
        logger.error("TLM 컬럼 변환 실패 col=%s val=%r: %s", col, val, e)
        if col == "LASTVALCRC":
            return ""
        if col in ("SVB_X", "SVB_Y", "SVB_Z", "WBN_X", "WBN_Y", "WBN_Z", "DT", "EXECOUNTS"):
            return 0.0
        return 0


def _tlm_history_default(col: str) -> Any:
    """history INSERT 시 tlm_row 에 키가 없을 때 기본값."""
    try:
        if col == "LASTVALCRC":
            return ""
        if col in ("SVB_X", "SVB_Y", "SVB_Z", "WBN_X", "WBN_Y", "WBN_Z", "DT", "EXECOUNTS"):
            return 0.0
        return 0
    except Exception as e:
        logger.error("TLM history 기본값 실패 col=%s: %s", col, e)
        return 0


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
        self._accumulation_frozen = False
        self._scenario_inject_active = False

    @property
    def db_path(self) -> Path:
        return self._db_path

    def set_accumulation_frozen(self, frozen: bool) -> None:
        """시나리오 주입 후 Serial/UDP/AnomalyDetector 누적 쓰기를 중지한다."""
        try:
            with self._lock:
                self._accumulation_frozen = bool(frozen)
        except Exception as e:
            logger.error("set_accumulation_frozen 실패: %s", e)

    def is_accumulation_frozen(self) -> bool:
        try:
            with self._lock:
                return bool(self._accumulation_frozen)
        except Exception as e:
            logger.error("is_accumulation_frozen 실패: %s", e)
            return False

    def _accumulation_write_blocked(self) -> bool:
        return self._accumulation_frozen and not self._scenario_inject_active

    @contextmanager
    def scenario_inject_writes(self) -> Iterator["DBManager"]:
        """FPF 시나리오 주입 시에만 누적 freeze 를 우회해 DB 를 덮어쓴다."""
        try:
            with self._lock:
                self._scenario_inject_active = True
            yield self
        except Exception as e:
            logger.error("scenario_inject_writes 실패: %s", e)
            raise
        finally:
            try:
                with self._lock:
                    self._scenario_inject_active = False
            except Exception as e:
                logger.error("scenario_inject_writes 종료 실패: %s", e)

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
                self._sync_sat_pwr_meta_thresholds()
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
            now = utc_now_iso()
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

    def _sync_sat_pwr_meta_thresholds(self) -> None:
        """기존 DB 행의 V_THRESHOLD_LO/HI를 demon/config.py 와 맞춘다 (INSERT OR IGNORE 보완)."""
        if self._conn is None:
            return
        try:
            for sw_id in range(demon_config.PWR_SW_ID_COUNT):
                lo = float(demon_config.V_THRESHOLD_LO[sw_id])
                hi = float(demon_config.V_THRESHOLD_HI[sw_id])
                self._conn.execute(
                    """
                    UPDATE SAT_PWR_META SET
                      V_THRESHOLD_LO = ?,
                      V_THRESHOLD_HI = ?
                    WHERE SW_ID = ?
                    """,
                    (lo, hi, sw_id),
                )
        except sqlite3.Error as e:
            logger.error("SAT_PWR_META 임계치 동기화 실패(SQLite): %s", e)
            raise
        except Exception as e:
            logger.error("SAT_PWR_META 임계치 동기화 실패: %s", e)
            raise

    @staticmethod
    def filter_tlm_current_fields(tlm: dict[str, Any]) -> dict[str, Any]:
        """SAT_TLM_CURRENT 화이트리스트 필드만 추출 (UDP pending flush 공용)."""
        try:
            return {k: v for k, v in tlm.items() if k in _TLM_COLS}
        except Exception as e:
            logger.error("filter_tlm_current_fields 실패: %s", e)
            return {}

    @staticmethod
    def filter_adcs_filter_fields(data: dict[str, Any]) -> dict[str, Any]:
        """SAT_ADCS_FILTER INSERT 허용 컬럼만 (내부 '_' 키 제외)."""
        try:
            out: dict[str, Any] = {}
            for key, val in data.items():
                if val is None or str(key).startswith("_"):
                    continue
                col = _ADCS_FILTER_KEY_ALIASES.get(str(key), str(key))
                if col in _ADCS_FILTER_COLS:
                    out[col] = val
            return out
        except Exception as e:
            logger.error("filter_adcs_filter_fields 실패: %s", e)
            return {}

    def insert_tlm_history(self, tlm: dict[str, Any], snapshot_id: int | None = None) -> bool:
        """SAT_TLM_HISTORY append (통합 SNAPSHOT_ID 선택)."""
        try:
            if self._accumulation_write_blocked():
                return True
            with self._lock:
                if self._conn is None:
                    logger.error("insert_tlm_history: DB 미연결")
                    return False
                self._insert_tlm_history_locked(tlm, snapshot_id)
                self._conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error("insert_tlm_history 실패(SQLite): %s", e)
            return False
        except Exception as e:
            logger.error("insert_tlm_history 실패: %s", e)
            return False

    def get_latest_snapshot_id(self) -> int:
        """SAT_SNAPSHOT 최신 SNAPSHOT_ID. 없거나 실패 시 -1."""
        try:
            with self._lock:
                if self._conn is None:
                    logger.error("get_latest_snapshot_id: DB 미연결")
                    return -1
                row = self._conn.execute(
                    "SELECT MAX(SNAPSHOT_ID) FROM SAT_SNAPSHOT",
                ).fetchone()
            if row is None or row[0] is None:
                return -1
            return int(row[0])
        except (ValueError, TypeError) as e:
            logger.error("get_latest_snapshot_id 변환 오류: %s", e)
            return -1
        except sqlite3.Error as e:
            logger.error("get_latest_snapshot_id 실패(SQLite): %s", e)
            return -1
        except Exception as e:
            logger.error("get_latest_snapshot_id 실패: %s", e)
            return -1

    def insert_unified_snapshot(self) -> int:
        """
        SAT_SNAPSHOT 1건 + PWR/TLM/ADCS history 를 동일 SNAPSHOT_ID 로 append.

        UDP DO flush 직후 호출 (TLM 한 사이클 = 1 SNAPSHOT). Returns: SNAPSHOT_ID (실패 시 -1).
        """
        try:
            if self._accumulation_write_blocked():
                return -1
            now = utc_now_iso()
            with self._lock:
                if self._conn is None:
                    logger.error("insert_unified_snapshot: DB 미연결")
                    return -1
                cur = self._conn.execute(
                    "INSERT INTO SAT_SNAPSHOT (SNAPSHOT_AT) VALUES (?)",
                    (now,),
                )
                snapshot_id = int(cur.lastrowid)
                pwr_cur = self._conn.execute(
                    "INSERT INTO SAT_PWR_HISTORY (UPDATED_AT, SNAPSHOT_ID) VALUES (?, ?)",
                    (now, snapshot_id),
                )
                pwr_history_id = int(pwr_cur.lastrowid)
                for sw_id in range(demon_config.PWR_SW_ID_COUNT):
                    meta = self._get_pwr_meta_locked(sw_id)
                    if meta is not None:
                        self._insert_pwr_history_channel_locked(pwr_history_id, meta)
                tlm_row = self._conn.execute(
                    "SELECT * FROM SAT_TLM_CURRENT WHERE TLM_ID = ?",
                    (demon_config.SAT_TLM_ID,),
                ).fetchone()
                if tlm_row is not None:
                    self._insert_tlm_history_locked(
                        _row_to_dict(tlm_row),
                        snapshot_id,
                    )
                adcs_row = self._conn.execute(
                    "SELECT * FROM SAT_ADCS_FILTER WHERE SNAPSHOT_ID IS NULL "
                    "ORDER BY CHENNEL1 DESC LIMIT 1",
                ).fetchone()
                if adcs_row is not None:
                    self._insert_adcs_history_locked(
                        _row_to_dict(adcs_row),
                        snapshot_id,
                        now,
                    )
                self._conn.commit()
            return snapshot_id
        except sqlite3.Error as e:
            logger.error("insert_unified_snapshot 실패(SQLite): %s", e)
            return -1
        except Exception as e:
            logger.error("insert_unified_snapshot 실패: %s", e)
            return -1

    def insert_pwr_history_snapshot(self) -> int:
        """하위 호환 — insert_unified_snapshot() 래퍼. Returns: SNAPSHOT_ID."""
        return self.insert_unified_snapshot()

    def insert_pwr_history(self, pwr: dict[str, Any]) -> bool:
        """하위 호환 — 단일 채널 dict 대신 insert_pwr_history_snapshot() 사용 권장."""
        del pwr
        return self.insert_pwr_history_snapshot() >= 0

    def _insert_tlm_history_locked(
        self,
        tlm_row: dict[str, Any],
        snapshot_id: int | None = None,
    ) -> None:
        """현재 TLM 스냅샷을 SAT_TLM_HISTORY 에 append (lock 보유 상태에서 호출)."""
        try:
            if self._conn is None:
                return
            data_cols = list(demon_config.TLM_CURRENT_UPDATEABLE_COLS)
            col_names = ["TLM_ID", "UPDATED_AT"]
            vals: list[Any] = [
                int(tlm_row.get("TLM_ID", demon_config.SAT_TLM_ID)),
                str(tlm_row.get("UPDATED_AT", utc_now_iso())),
            ]
            if snapshot_id is not None:
                col_names.append(demon_config.SNAPSHOT_ID_COL)
                vals.append(int(snapshot_id))
            col_names.extend(data_cols)
            for col in data_cols:
                raw = tlm_row.get(col, _tlm_history_default(col))
                vals.append(_coerce_tlm_column_value(col, raw))
            placeholders = ", ".join("?" * len(col_names))
            self._conn.execute(
                f"INSERT INTO SAT_TLM_HISTORY ({', '.join(col_names)}) "
                f"VALUES ({placeholders})",
                vals,
            )
        except sqlite3.Error as e:
            logger.error("SAT_TLM_HISTORY append 실패(SQLite): %s", e)
        except Exception as e:
            logger.error("SAT_TLM_HISTORY append 실패: %s", e)

    def _insert_adcs_history_locked(
        self,
        adcs_row: dict[str, Any],
        snapshot_id: int,
        timestamp: str | None = None,
    ) -> None:
        """SAT_ADCS_FILTER history 행 append (SNAPSHOT_ID 지정, lock 보유)."""
        try:
            if self._conn is None:
                return
            payload = dict(adcs_row)
            payload.pop("CHENNEL1", None)
            payload.pop(demon_config.SNAPSHOT_ID_COL, None)
            if timestamp is not None:
                payload["TIMESTAMP"] = timestamp
            built = _build_adcs_filter_row(payload)
            col_names = [c for c in _ADCS_FILTER_INSERT_COLS if c in built]
            col_names.append(demon_config.SNAPSHOT_ID_COL)
            placeholders = ", ".join("?" * len(col_names))
            vals = [built[c] for c in col_names if c != demon_config.SNAPSHOT_ID_COL]
            vals.append(int(snapshot_id))
            self._conn.execute(
                f"INSERT INTO SAT_ADCS_FILTER ({', '.join(col_names)}) "
                f"VALUES ({placeholders})",
                vals,
            )
        except sqlite3.Error as e:
            logger.error("_insert_adcs_history_locked 실패(SQLite): %s", e)
        except Exception as e:
            logger.error("_insert_adcs_history_locked 실패: %s", e)

    def _get_pwr_meta_locked(self, sw_id: int) -> dict[str, Any] | None:
        """lock 보유 상태에서 SAT_PWR_META 1행 조회."""
        try:
            if self._conn is None:
                return None
            cur = self._conn.execute(
                "SELECT * FROM SAT_PWR_META WHERE SW_ID = ?",
                (int(sw_id),),
            )
            return _row_to_dict_or_none(cur.fetchone())
        except sqlite3.Error as e:
            logger.error("_get_pwr_meta_locked 실패(SQLite) sw_id=%s: %s", sw_id, e)
            return None
        except Exception as e:
            logger.error("_get_pwr_meta_locked 실패 sw_id=%s: %s", sw_id, e)
            return None

    def _insert_pwr_history_channel_locked(
        self,
        history_id: int,
        pwr_row: dict[str, Any],
    ) -> None:
        """스냅샷 HISTORY_ID에 채널 1행 append (lock 보유)."""
        try:
            if self._conn is None:
                return
            self._conn.execute(
                """
                INSERT INTO SAT_PWR_HISTORY_CHANNEL (
                  HISTORY_ID, SW_ID, VOLTAGE, PREV_VOLTAGE, CURRENT_A,
                  PREV_DELTA_V, CURR_DELTA_V, EXCEED_COUNT, CONSECUTIVE_EXCEED,
                  ANOMALY_FLAG, V_THRESHOLD_LO, V_THRESHOLD_HI
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(history_id),
                    int(pwr_row.get("SW_ID", 0)),
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
            logger.error("SAT_PWR_HISTORY_CHANNEL append 실패(SQLite): %s", e)
        except Exception as e:
            logger.error("SAT_PWR_HISTORY_CHANNEL append 실패: %s", e)

    def upsert_tlm_current(self, tlm: dict[str, Any]) -> bool:
        """SAT_TLM_CURRENT TLM_ID=1 행 부분 UPDATE."""
        try:
            if self._accumulation_write_blocked():
                return True
            safe = self.filter_tlm_current_fields(tlm)
            if not safe:
                return True

            now = utc_now_iso()
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

    def upsert_pwr_meta(self, pwr_sample: dict[str, Any]) -> bool:
        """
        SAT_PWR_META UPSERT — 전압·전류 및 delta 슬라이딩 윈도우.

        pwr_sample: {sw_id, voltage, current_a} (timestamp 는 DBManager 가 설정)
        """
        try:
            if self._accumulation_write_blocked():
                return True
            sw_id = int(pwr_sample["sw_id"])
            voltage = float(pwr_sample["voltage"])
            current_a = float(pwr_sample["current_a"])
            now = utc_now_iso()

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
            if self._accumulation_write_blocked():
                return True
            sw_id = int(exceed_info["sw_id"])
            exceed_count = int(exceed_info["exceed_count"])
            consecutive = int(exceed_info["consecutive_exceed"])
            anomaly_flag = int(exceed_info["anomaly_flag"])
            now = utc_now_iso()

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
        """SAT_ADCS_FILTER live 1행 (SNAPSHOT_ID IS NULL). channel1 인자는 하위 호환용 무시."""
        del channel1
        try:
            with self._lock:
                if self._conn is None:
                    logger.error("get_adcs_filter: DB 미연결")
                    return None
                cur = self._conn.execute(
                    "SELECT * FROM SAT_ADCS_FILTER WHERE SNAPSHOT_ID IS NULL "
                    "ORDER BY CHENNEL1 DESC LIMIT 1",
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

    def upsert_integrity_hash(
        self,
        file_id: int,
        file_path: str,
        expected_hash: str,
    ) -> bool:
        """SAT_INTEGRITY_HASH INSERT/UPDATE — 기대 해시 등록·갱신."""
        try:
            now = utc_now_iso()
            path_str = str(file_path).strip()
            hash_str = str(expected_hash).strip().lower()
            if not path_str or not hash_str:
                logger.error("upsert_integrity_hash: FILE_PATH/EXPECTED_HASH 비어 있음")
                return False
            with self._lock:
                if self._conn is None:
                    logger.error("upsert_integrity_hash: DB 미연결")
                    return False
                self._conn.execute(
                    """
                    INSERT INTO SAT_INTEGRITY_HASH (
                      FILE_ID, FILE_PATH, EXPECTED_HASH,
                      LAST_VERIFIED_AT, UPDATED_AT, IS_VIOLATED
                    ) VALUES (?, ?, ?, ?, ?, 0)
                    ON CONFLICT(FILE_ID) DO UPDATE SET
                      FILE_PATH = excluded.FILE_PATH,
                      EXPECTED_HASH = excluded.EXPECTED_HASH,
                      UPDATED_AT = excluded.UPDATED_AT,
                      IS_VIOLATED = 0
                    """,
                    (int(file_id), path_str, hash_str, now, now),
                )
                self._conn.commit()
            return True
        except (ValueError, TypeError) as e:
            logger.error("upsert_integrity_hash 입력 오류: %s", e)
            return False
        except sqlite3.Error as e:
            logger.error("upsert_integrity_hash 실패(SQLite): %s", e)
            return False
        except Exception as e:
            logger.error("upsert_integrity_hash 실패: %s", e)
            return False

    def update_integrity_hash(
        self,
        file_id: int | None = None,
        file_path: str | None = None,
        expected_hash: str | None = None,
        cmd: dict[str, Any] | None = None,
    ) -> bool:
        """지상국 UPDATE_HASH — 단일 행 upsert (cmd dict 호환)."""
        try:
            payload = dict(cmd) if isinstance(cmd, dict) else {}
            if file_id is not None:
                payload["file_id"] = file_id
            if file_path is not None:
                payload["file_path"] = file_path
            if expected_hash is not None:
                payload["expected_hash"] = expected_hash
            fid = payload.get("file_id", payload.get("FILE_ID"))
            fpath = payload.get("file_path", payload.get("FILE_PATH"))
            ehash = payload.get("expected_hash", payload.get("EXPECTED_HASH"))
            if fid is None or fpath is None or ehash is None:
                logger.error("update_integrity_hash: file_id/file_path/expected_hash 필수")
                return False
            return self.upsert_integrity_hash(int(fid), str(fpath), str(ehash))
        except (ValueError, TypeError) as e:
            logger.error("update_integrity_hash 입력 오류: %s", e)
            return False
        except Exception as e:
            logger.error("update_integrity_hash 실패: %s", e)
            return False

    def _telemetry_event_counters(self) -> dict[str, int]:
        """get_tlm_current / get_adcs_filter 기반 이벤트 카운터 기본값."""
        try:
            counters = {col: int(_EVENT_INT_DEFAULTS.get(col, 0)) for col in _EVENT_COUNTER_COLS}
            tlm = self.get_tlm_current()
            if tlm is None:
                return counters
            adcs = self.get_adcs_filter()
            if adcs is None:
                return counters
            counters["PIPEOVERFLOWRRCNT"] = int(adcs.get("SKIPPEDSLOTSCOUNT", 0))
            counters["CHILDQUEUECOUNT"] = int(adcs.get("ERLOGENTRIES", 0))
            counters["FILEWRITEERRCOUNTER"] = int(adcs.get("FORWARD_ERR_COUNT", 0))
            counters["CMDREJECTEDCOUNTER"] = int(adcs.get("APPCSERRCOUNTER", 0))
            counters["CH1_CH2_FAULT_CRC"] = int(adcs.get("OSCSERRCOUNTER", 0))
            counters["CH1_FAULT_FILE_SIZE_MISMATCH"] = int(adcs.get("SKIPPEDSLOTSCOUNT", 0))
            counters["PROCESSOR_RESET_COUNT"] = int(adcs.get("RESETSPERFORMED", 0))
            if tlm.get("OBC_S_TICK") is not None:
                counters["CHILDQUEUECOUNT"] = int(tlm.get("OBC_S_TICK", counters["CHILDQUEUECOUNT"]))
            return counters
        except (ValueError, TypeError) as e:
            logger.error("_telemetry_event_counters 변환 오류: %s", e)
            return {col: int(_EVENT_INT_DEFAULTS.get(col, 0)) for col in _EVENT_COUNTER_COLS}
        except Exception as e:
            logger.error("_telemetry_event_counters 실패: %s", e)
            return {col: int(_EVENT_INT_DEFAULTS.get(col, 0)) for col in _EVENT_COUNTER_COLS}

    def insert_event(self, event: dict[str, Any]) -> int:
        """SAT_EVENT_QUEUE INSERT. 성공 시 event_id, 실패 시 -1."""
        try:
            now = utc_now_iso()
            detected_at = str(event.get("DETECTED_AT", now))
            timestamp = str(event.get("TIMESTAMP", detected_at))
            event_type = str(event.get("EVENT_TYPE", "UNKNOWN"))
            priority = int(event.get("PRIORITY", 0))
            is_sent = int(event.get("IS_SENT", 0))
            sw_id = int(event.get("SW_ID", _EVENT_INT_DEFAULTS["SW_ID"]))
            weight = int(event.get("WEIGHT", _EVENT_INT_DEFAULTS["WEIGHT"]))
            exception_code = int(event.get("EXCEPTION_CODE", _EVENT_INT_DEFAULTS["EXCEPTION_CODE"]))
            module_scores = str(event.get("MODULE_SCORES", ""))
            chennel1 = int(event.get("CHENNEL1", _EVENT_INT_DEFAULTS["CHENNEL1"]))

            telemetry_counters = self._telemetry_event_counters()
            counter_vals: list[int] = []
            for col in _EVENT_COUNTER_COLS:
                if col in event:
                    counter_vals.append(int(event[col]))
                else:
                    counter_vals.append(int(telemetry_counters.get(col, 0)))

            cols = [
                "DETECTED_AT",
                *_EVENT_COUNTER_COLS,
                "IS_SENT",
                "TIMESTAMP",
                "PRIORITY",
                "EVENT_TYPE",
                "SW_ID",
                "WEIGHT",
                "EXCEPTION_CODE",
                "MODULE_SCORES",
                "CHENNEL1",
            ]
            vals: list[Any] = [
                detected_at,
                *counter_vals,
                is_sent,
                timestamp,
                priority,
                event_type,
                sw_id,
                weight,
                exception_code,
                module_scores,
                chennel1,
            ]

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

    def upsert_adcs_current(self, data: dict[str, Any]) -> bool:
        """SAT_ADCS_FILTER live 1행 갱신 (SNAPSHOT_ID IS NULL, UDP flush용)."""
        try:
            if self._accumulation_write_blocked():
                return True
            built = _build_adcs_filter_row(data)
            col_names = [c for c in _ADCS_FILTER_INSERT_COLS if c in built]
            placeholders = ", ".join("?" * len(col_names))
            vals = [built[c] for c in col_names]
            with self._lock:
                if self._conn is None:
                    logger.error("upsert_adcs_current: DB 미연결")
                    return False
                self._conn.execute(
                    "DELETE FROM SAT_ADCS_FILTER WHERE SNAPSHOT_ID IS NULL",
                )
                self._conn.execute(
                    f"INSERT INTO SAT_ADCS_FILTER ({', '.join(col_names)}) "
                    f"VALUES ({placeholders})",
                    vals,
                )
                self._conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error("upsert_adcs_current 실패(SQLite): %s", e)
            return False
        except Exception as e:
            logger.error("upsert_adcs_current 실패: %s", e)
            return False

    def insert_adcs_filter_history(self, data: dict[str, Any], snapshot_id: int) -> bool:
        """SAT_ADCS_FILTER history append (이상 구간·통합 SNAPSHOT_ID)."""
        try:
            if self._accumulation_write_blocked():
                return True
            with self._lock:
                if self._conn is None:
                    logger.error("insert_adcs_filter_history: DB 미연결")
                    return False
                self._insert_adcs_history_locked(data, int(snapshot_id))
                self._conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error("insert_adcs_filter_history 실패(SQLite): %s", e)
            return False
        except Exception as e:
            logger.error("insert_adcs_filter_history 실패: %s", e)
            return False

    def insert_adcs_filter(self, data: dict[str, Any]) -> bool:
        """하위 호환 — live ADCS 갱신 (upsert_adcs_current)."""
        return self.upsert_adcs_current(data)

    def update_threshold(self, sw_id: int, lo: float, hi: float) -> bool:
        """지상국 UPDATE_THRESHOLD — V_THRESHOLD_LO/HI 갱신."""
        try:
            now = utc_now_iso()
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

    def get_tlm_history(self) -> list[dict[str, Any]]:
        """SAT_TLM_HISTORY 전체 — HISTORY_ID 순. 실패 시 []."""
        try:
            with self._lock:
                if self._conn is None:
                    logger.error("get_tlm_history: DB 미연결")
                    return []
                cur = self._conn.execute(
                    "SELECT * FROM SAT_TLM_HISTORY WHERE SNAPSHOT_ID IS NOT NULL "
                    "ORDER BY HISTORY_ID ASC",
                )
                return [_row_to_dict(r) for r in cur.fetchall()]
        except sqlite3.Error as e:
            logger.error("get_tlm_history 실패(SQLite): %s", e)
            return []
        except Exception as e:
            logger.error("get_tlm_history 실패: %s", e)
            return []

    def get_pwr_history(self) -> list[dict[str, Any]]:
        """
        SAT_PWR_HISTORY 스냅샷 목록 — HISTORY_ID별 4채널 channels 배열 포함.

        각 항목: {HISTORY_ID, UPDATED_AT, channels: [dict, ...]}
        """
        try:
            with self._lock:
                if self._conn is None:
                    logger.error("get_pwr_history: DB 미연결")
                    return []
                header_cur = self._conn.execute(
                    "SELECT HISTORY_ID, SNAPSHOT_ID, UPDATED_AT "
                    "FROM SAT_PWR_HISTORY WHERE SNAPSHOT_ID IS NOT NULL "
                    "ORDER BY HISTORY_ID ASC",
                )
                snapshots: list[dict[str, Any]] = []
                for header in header_cur.fetchall():
                    hid = int(header["HISTORY_ID"])
                    ch_cur = self._conn.execute(
                        """
                        SELECT SW_ID, VOLTAGE, PREV_VOLTAGE, CURRENT_A,
                               PREV_DELTA_V, CURR_DELTA_V, EXCEED_COUNT,
                               CONSECUTIVE_EXCEED, ANOMALY_FLAG,
                               V_THRESHOLD_LO, V_THRESHOLD_HI
                        FROM SAT_PWR_HISTORY_CHANNEL
                        WHERE HISTORY_ID = ?
                        ORDER BY SW_ID ASC
                        """,
                        (hid,),
                    )
                    channels = [_row_to_dict(r) for r in ch_cur.fetchall()]
                    snapshots.append({
                        "HISTORY_ID": hid,
                        "SNAPSHOT_ID": header["SNAPSHOT_ID"],
                        "UPDATED_AT": str(header["UPDATED_AT"]),
                        "channels": channels,
                    })
                return snapshots
        except sqlite3.Error as e:
            logger.error("get_pwr_history 실패(SQLite): %s", e)
            return []
        except Exception as e:
            logger.error("get_pwr_history 실패: %s", e)
            return []

    def get_adcs_filter_all(self) -> list[dict[str, Any]]:
        """SAT_ADCS_FILTER history — SNAPSHOT_ID IS NOT NULL, SNAPSHOT_ID·CHENNEL1 순."""
        try:
            with self._lock:
                if self._conn is None:
                    logger.error("get_adcs_filter_all: DB 미연결")
                    return []
                cur = self._conn.execute(
                    "SELECT * FROM SAT_ADCS_FILTER WHERE SNAPSHOT_ID IS NOT NULL "
                    "ORDER BY SNAPSHOT_ID ASC, CHENNEL1 ASC",
                )
                return [_row_to_dict(r) for r in cur.fetchall()]
        except sqlite3.Error as e:
            logger.error("get_adcs_filter_all 실패(SQLite): %s", e)
            return []
        except Exception as e:
            logger.error("get_adcs_filter_all 실패: %s", e)
            return []

    def get_snapshots_by_ids(self, snapshot_ids: list[int]) -> list[dict[str, Any]]:
        """SAT_SNAPSHOT 헤더 조회 — SNAPSHOT_ID 순."""
        try:
            if not snapshot_ids:
                return []
            ids = [int(v) for v in snapshot_ids]
            placeholders = ", ".join("?" for _ in ids)
            with self._lock:
                if self._conn is None:
                    logger.error("get_snapshots_by_ids: DB 미연결")
                    return []
                cur = self._conn.execute(
                    f"SELECT SNAPSHOT_ID, SNAPSHOT_AT FROM SAT_SNAPSHOT "
                    f"WHERE SNAPSHOT_ID IN ({placeholders}) "
                    f"ORDER BY SNAPSHOT_ID ASC",
                    ids,
                )
                return [_row_to_dict(r) for r in cur.fetchall()]
        except (ValueError, TypeError) as e:
            logger.error("get_snapshots_by_ids 변환 오류: %s", e)
            return []
        except sqlite3.Error as e:
            logger.error("get_snapshots_by_ids 실패(SQLite): %s", e)
            return []
        except Exception as e:
            logger.error("get_snapshots_by_ids 실패: %s", e)
            return []

    def delete_adcs_filter(self) -> bool:
        """SAT_ADCS_FILTER history 삭제 (ACK 후, live 행 유지)."""
        try:
            with self._lock:
                if self._conn is None:
                    logger.error("delete_adcs_filter: DB 미연결")
                    return False
                self._conn.execute(
                    "DELETE FROM SAT_ADCS_FILTER WHERE SNAPSHOT_ID IS NOT NULL",
                )
                self._conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error("delete_adcs_filter 실패(SQLite): %s", e)
            return False
        except Exception as e:
            logger.error("delete_adcs_filter 실패: %s", e)
            return False

    def delete_snapshots_by_ids(self, snapshot_ids: list[int]) -> bool:
        """SAT_SNAPSHOT 및 연결된 PWR/TLM/ADCS history 일괄 삭제."""
        try:
            if not snapshot_ids:
                return True
            ids = [int(v) for v in snapshot_ids]
            placeholders = ", ".join("?" for _ in ids)
            with self._lock:
                if self._conn is None:
                    logger.error("delete_snapshots_by_ids: DB 미연결")
                    return False
                pwr_rows = self._conn.execute(
                    f"SELECT HISTORY_ID FROM SAT_PWR_HISTORY "
                    f"WHERE SNAPSHOT_ID IN ({placeholders})",
                    ids,
                ).fetchall()
                pwr_hids = [int(r[0]) for r in pwr_rows]
                if pwr_hids:
                    ph = ", ".join("?" for _ in pwr_hids)
                    self._conn.execute(
                        f"DELETE FROM SAT_PWR_HISTORY_CHANNEL WHERE HISTORY_ID IN ({ph})",
                        pwr_hids,
                    )
                self._conn.execute(
                    f"DELETE FROM SAT_PWR_HISTORY WHERE SNAPSHOT_ID IN ({placeholders})",
                    ids,
                )
                self._conn.execute(
                    f"DELETE FROM SAT_TLM_HISTORY WHERE SNAPSHOT_ID IN ({placeholders})",
                    ids,
                )
                self._conn.execute(
                    f"DELETE FROM SAT_ADCS_FILTER WHERE SNAPSHOT_ID IN ({placeholders})",
                    ids,
                )
                self._conn.execute(
                    f"DELETE FROM SAT_SNAPSHOT WHERE SNAPSHOT_ID IN ({placeholders})",
                    ids,
                )
                self._conn.commit()
            return True
        except (ValueError, TypeError) as e:
            logger.error("delete_snapshots_by_ids 변환 오류: %s", e)
            return False
        except sqlite3.Error as e:
            logger.error("delete_snapshots_by_ids 실패(SQLite): %s", e)
            return False
        except Exception as e:
            logger.error("delete_snapshots_by_ids 실패: %s", e)
            return False

    def update_integrity_result(self, file_path: str, is_violated: int) -> bool:
        """SAT_INTEGRITY_HASH 무결성 검증 결과 갱신."""
        try:
            now = utc_now_iso()
            with self._lock:
                if self._conn is None:
                    logger.error("update_integrity_result: DB 미연결")
                    return False
                cur = self._conn.execute(
                    """
                    UPDATE SAT_INTEGRITY_HASH SET
                      IS_VIOLATED = ?,
                      LAST_VERIFIED_AT = ?,
                      UPDATED_AT = ?
                    WHERE FILE_PATH = ?
                    """,
                    (int(is_violated), now, now, str(file_path)),
                )
                self._conn.commit()
                if cur.rowcount == 0:
                    logger.warning("update_integrity_result: FILE_PATH 없음 path=%s", file_path)
                    return False
            return True
        except sqlite3.Error as e:
            logger.error("update_integrity_result 실패(SQLite): %s", e)
            return False
        except Exception as e:
            logger.error("update_integrity_result 실패: %s", e)
            return False

    def reset_pwr_anomaly_state(self) -> bool:
        """SAT_PWR_META 이상탐지 누적값 초기화 — 데몬 시작 시 호출."""
        try:
            with self._lock:
                if self._conn is None:
                    logger.error("reset_pwr_anomaly_state: DB 미연결")
                    return False
                self._conn.execute(
                    """
                    UPDATE SAT_PWR_META SET
                      EXCEED_COUNT = 0,
                      CONSECUTIVE_EXCEED = 0,
                      ANOMALY_FLAG = 0
                    """
                )
                self._conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error("reset_pwr_anomaly_state 실패(SQLite): %s", e)
            return False
        except Exception as e:
            logger.error("reset_pwr_anomaly_state 실패: %s", e)
            return False

    def reset_integrity_violations(self) -> bool:
        """SAT_INTEGRITY_HASH 전체 IS_VIOLATED → 0 (RECOVERY 시 호출)."""
        try:
            now = utc_now_iso()
            with self._lock:
                if self._conn is None:
                    logger.error("reset_integrity_violations: DB 미연결")
                    return False
                self._conn.execute(
                    "UPDATE SAT_INTEGRITY_HASH SET IS_VIOLATED = 0, UPDATED_AT = ?",
                    (now,),
                )
                self._conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error("reset_integrity_violations 실패(SQLite): %s", e)
            return False
        except Exception as e:
            logger.error("reset_integrity_violations 실패: %s", e)
            return False

    @staticmethod
    def snapshot_ids_from_records(records: list[dict[str, Any]]) -> list[int]:
        """history 행 dict 목록에서 SNAPSHOT_ID 추출 (중복 제거·오름차순)."""
        try:
            ids: set[int] = set()
            col = demon_config.SNAPSHOT_ID_COL
            for row in records:
                if not isinstance(row, dict):
                    continue
                raw = row.get(col)
                if raw is None:
                    continue
                ids.add(int(raw))
            return sorted(ids)
        except (ValueError, TypeError) as e:
            logger.error("snapshot_ids_from_records 변환 오류: %s", e)
            return []
        except Exception as e:
            logger.error("snapshot_ids_from_records 실패: %s", e)
            return []
