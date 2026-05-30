"""
UTC 시각 유틸 — DB·로그·이벤트 타임스탬프 단일 기준.

모든 저장·비교는 UTC ISO-8601 을 사용한다. 로컬 타임존(KST 등)과 혼용하지 않는다.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    """timezone-aware UTC now."""
    try:
        return datetime.now(timezone.utc)
    except Exception as e:
        logger.error("utc_now 실패: %s", e)
        return datetime.fromtimestamp(0, tz=timezone.utc)


def utc_now_iso() -> str:
    """DB·이벤트용 UTC ISO-8601 (+00:00)."""
    try:
        return utc_now().isoformat()
    except Exception as e:
        logger.error("utc_now_iso 실패: %s", e)
        return "1970-01-01T00:00:00+00:00"


def parse_utc_timestamp(value: Any) -> datetime | None:
    """문자열·datetime → UTC aware datetime. 실패 시 None."""
    try:
        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        text = str(value).strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (TypeError, ValueError) as e:
        logger.error("parse_utc_timestamp 실패 value=%r: %s", value, e)
        return None
    except Exception as e:
        logger.error("parse_utc_timestamp 실패 value=%r: %s", value, e)
        return None


def seconds_between_utc(first: Any, second: Any) -> float | None:
    """두 UTC 타임스탬프 차이(초). 파싱 실패 시 None."""
    try:
        t1 = parse_utc_timestamp(first)
        t2 = parse_utc_timestamp(second)
        if t1 is None or t2 is None:
            return None
        return abs((t1 - t2).total_seconds())
    except Exception as e:
        logger.error("seconds_between_utc 실패: %s", e)
        return None
