"""
앱 타임존 시각 유틸 — DB·로그·이벤트 타임스탬프 단일 기준.

config.TIMESTAMP_TIMEZONE(기본 Asia/Seoul) 으로 저장·비교·로그를 맞춘다.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

from .. import config as demon_config

logger = logging.getLogger(__name__)

_FALLBACK_ISO = "1970-01-01T00:00:00+09:00"


def _app_tz() -> timezone:
    """config.TIMESTAMP_TIMEZONE → tzinfo."""
    try:
        return ZoneInfo(demon_config.TIMESTAMP_TIMEZONE)
    except Exception as e:
        logger.error("_app_tz 실패: %s", e)
        return timezone.utc


def now() -> datetime:
    """timezone-aware 현재 시각 (앱 타임존)."""
    try:
        return datetime.now(_app_tz())
    except Exception as e:
        logger.error("now 실패: %s", e)
        return datetime.fromtimestamp(0, tz=_app_tz())


def now_iso() -> str:
    """DB·이벤트용 ISO-8601 (앱 타임존 offset 포함)."""
    try:
        return now().isoformat()
    except Exception as e:
        logger.error("now_iso 실패: %s", e)
        return _FALLBACK_ISO


# 하위 호환 — 기존 import 경로 유지
utc_now = now
utc_now_iso = now_iso


def parse_timestamp(value: Any) -> datetime | None:
    """문자열·datetime → 앱 타임존 aware datetime. 실패 시 None."""
    try:
        if value is None:
            return None
        tz = _app_tz()
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=tz)
            return value.astimezone(tz)
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=tz)
        text = str(value).strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=tz)
        return dt.astimezone(tz)
    except (TypeError, ValueError) as e:
        logger.error("parse_timestamp 실패 value=%r: %s", value, e)
        return None
    except Exception as e:
        logger.error("parse_timestamp 실패 value=%r: %s", value, e)
        return None


parse_utc_timestamp = parse_timestamp


def seconds_between(first: Any, second: Any) -> float | None:
    """두 타임스탬프 차이(초). 파싱 실패 시 None."""
    try:
        t1 = parse_timestamp(first)
        t2 = parse_timestamp(second)
        if t1 is None or t2 is None:
            return None
        return abs((t1 - t2).total_seconds())
    except Exception as e:
        logger.error("seconds_between 실패: %s", e)
        return None


seconds_between_utc = seconds_between

# GS·DB 공통 ISO 타임스탬프 필드명
_GS_TIMESTAMP_FIELDS = (
    "UPDATED_AT",
    "TIMESTAMP",
    "DETECTED_AT",
    "LAST_VERIFIED_AT",
    "SNAPSHOT_AT",
)


def normalize_timestamp_iso(value: Any) -> str | None:
    """임의 타임스탬프 → 앱 타임존 ISO 문자열. 실패 시 None."""
    try:
        dt = parse_timestamp(value)
        if dt is None:
            return None
        return dt.isoformat()
    except Exception as e:
        logger.error("normalize_timestamp_iso 실패 value=%r: %s", value, e)
        return None


def normalize_record_timestamps(
    record: dict[str, Any],
    fields: tuple[str, ...] = _GS_TIMESTAMP_FIELDS,
) -> dict[str, Any]:
    """dict 내 시각 필드를 앱 타임존 ISO 로 통일 (GS 송신용)."""
    try:
        out = dict(record)
        for key in fields:
            if key not in out or out[key] is None:
                continue
            normalized = normalize_timestamp_iso(out[key])
            if normalized is not None:
                out[key] = normalized
        return out
    except Exception as e:
        logger.error("normalize_record_timestamps 실패: %s", e)
        return dict(record)
