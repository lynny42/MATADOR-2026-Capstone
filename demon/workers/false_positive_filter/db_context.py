"""db_context — FPF 공통 DB 조회 (key_set 우선).

역할
    3개 분석 모듈이 DBManager를 직접 부르지 않고, key_set 한 곳으로 데이터 출처를 통일.

우선순위 (각 resolve_*)
    1) key_set["_snapshots"][...]  — 실험·테스트
    2) key_set["adcs_series"] / ["tlm_series"] — AnomalyDetector B안 (권장)
    3) db.get_*() — 운영 SQLite

시계열
    resolve_adcs_series: adcs_series 없으면 현재 1행만 리스트로 반환 → 모듈1은
    추가로 _prev_state(A안)로 Δ 보완.
"""

from __future__ import annotations

from typing import Any

from . import config


def _effective_event_id(key_set: dict) -> int | None:
    """event_id<=0 이면 미할당(앞단 AnomalyDetector) — DB 조회하지 않음."""
    try:
        raw = key_set.get(config.KEY_EVENT_ID, key_set.get("event_id"))
        if raw is None:
            return None
        eid = int(raw)
        if eid <= config.EVENT_ID_UNASSIGNED:
            return None
        return eid
    except (TypeError, ValueError):
        return None


def _channel1_from_key_set(key_set: dict) -> int:
    try:
        if config.KEY_CHANNEL1 in key_set:
            return int(key_set[config.KEY_CHANNEL1])
        if config.KEY_CHENNEL1_DB in key_set:
            return int(key_set[config.KEY_CHENNEL1_DB])
        return int(config.CHANNEL1_DEFAULT)
    except (TypeError, ValueError):
        return int(config.CHANNEL1_DEFAULT)


def _snapshots(key_set: dict) -> dict:
    try:
        raw = key_set.get(config.KEY_SNAPSHOTS)
        return raw if isinstance(raw, dict) else {}
    except Exception:
        return {}


def resolve_tlm(key_set: dict, db: Any) -> dict | None:
    try:
        snap = _snapshots(key_set).get("tlm")
        if snap is not None:
            return snap
        if db is None:
            return None
        return db.get_tlm_current()
    except AttributeError:
        return None
    except Exception:
        return None


def resolve_adcs(key_set: dict, db: Any) -> dict | None:
    try:
        snap = _snapshots(key_set).get("adcs")
        if snap is not None:
            return snap
        if db is None:
            return None
        channel1 = _channel1_from_key_set(key_set)
        row = db.get_adcs_filter(channel1)
        if row is not None and isinstance(row, dict):
            row = dict(row)
            row.setdefault(config.KEY_CHENNEL1_DB, channel1)
            row.setdefault(config.KEY_CHANNEL1, channel1)
        return row
    except AttributeError:
        return None
    except Exception:
        return None


def resolve_pwr_meta(key_set: dict, db: Any, sw_id: int) -> dict | None:
    try:
        snap_all = _snapshots(key_set).get("pwr_meta_all")
        if isinstance(snap_all, list):
            for row in snap_all:
                if row.get("SW_ID") == sw_id:
                    return row
        snap_one = _snapshots(key_set).get("pwr_meta")
        if snap_one is not None and snap_one.get("SW_ID") == sw_id:
            return snap_one
        if db is None:
            return None
        return db.get_pwr_meta(sw_id)
    except AttributeError:
        return None
    except Exception:
        return None


def resolve_pwr_meta_all(key_set: dict, db: Any) -> list[dict]:
    try:
        snap = _snapshots(key_set).get("pwr_meta_all")
        if isinstance(snap, list) and snap:
            return snap
        if db is None:
            return []
        return db.get_pwr_meta_all() or []
    except AttributeError:
        return []
    except Exception:
        return []


def resolve_event(key_set: dict, db: Any) -> dict | None:
    try:
        snap = _snapshots(key_set).get("event")
        if snap is not None:
            return snap
        if db is None:
            return None
        event_id = _effective_event_id(key_set)
        if event_id is None:
            return None
        return db.get_event(event_id)
    except AttributeError:
        return None
    except Exception:
        return None


def resolve_adcs_series(key_set: dict, db: Any) -> list[dict]:
    """최근 ADCS 행 시계열. key_set[adcs_series] 우선, 없으면 [현재 1행]만."""
    try:
        # 리스트 요소: get_adcs_filter(channel1)와 동일 dict. 순서: 오래된 → 최신.
        raw = key_set.get(config.KEY_ADCS_SERIES)
        if isinstance(raw, list) and raw:
            return [dict(x) for x in raw[-config.ADCS_SERIES_MAX_LEN :]]
        one = resolve_adcs(key_set, db)
        return [one] if one is not None else []
    except Exception:
        return []


def resolve_tlm_series(key_set: dict, db: Any) -> list[dict]:
    """최근 TLM 행 시계열. key_set[tlm_series] 우선."""
    try:
        raw = key_set.get(config.KEY_TLM_SERIES)
        if isinstance(raw, list) and raw:
            return raw[-config.ADCS_SERIES_MAX_LEN :]
        one = resolve_tlm(key_set, db)
        return [one] if one is not None else []
    except Exception:
        return []


def resolve_integrity_hash(key_set: dict, db: Any, file_id: int | None = None):
    try:
        snap = _snapshots(key_set).get("integrity_hash")
        if snap is not None:
            if isinstance(snap, list):
                if file_id is None:
                    return snap
                for row in snap:
                    if row.get("FILE_ID") == file_id:
                        return row
                return None
            if file_id is None or snap.get("FILE_ID") == file_id:
                return snap
        if db is None:
            return None
        return db.get_integrity_hash(file_id)
    except AttributeError:
        return None
    except Exception:
        return None
