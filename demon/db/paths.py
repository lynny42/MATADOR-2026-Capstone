"""SQLite DB 파일 경로 해석 (단일 정의)."""
from __future__ import annotations

import logging
from pathlib import Path

from .. import config as demon_config

logger = logging.getLogger(__name__)


def default_db_path() -> Path:
    """config.DB_PATH 가 있으면 사용, 없으면 demon/database.sqlite."""
    try:
        if demon_config.DB_PATH:
            return Path(demon_config.DB_PATH).expanduser().resolve()
        return Path(__file__).resolve().parent.parent / "database.sqlite"
    except OSError as e:
        logger.error("DB 경로 계산 실패(OSError): %s", e)
        raise
    except Exception as e:
        logger.error("DB 경로 계산 실패: %s", e)
        raise
