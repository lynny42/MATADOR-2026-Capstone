"""
로깅 초기화. main 진입점에서 한 번만 호출한다.

- 포맷·레벨은 config.py 에서 가져온다.
- LOG_FILE_PATH 가 지정되면 RotatingFileHandler 추가.
"""
from __future__ import annotations

import logging
import logging.handlers
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .. import config as demon_config

logger = logging.getLogger(__name__)


class _AppTzFormatter(logging.Formatter):
    """logging.Formatter — asctime 을 config.TIMESTAMP_TIMEZONE 으로 출력."""

    def __init__(self, *args, **kwargs) -> None:
        try:
            self._tz = ZoneInfo(demon_config.TIMESTAMP_TIMEZONE)
        except Exception as e:
            logger.error("_AppTzFormatter tz 실패: %s", e)
            self._tz = ZoneInfo("UTC")
        super().__init__(*args, **kwargs)

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        try:
            dt = datetime.fromtimestamp(record.created, tz=self._tz)
            fmt = datefmt or self.datefmt
            if fmt:
                return dt.strftime(fmt)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception as e:
            logger.error("AppTzFormatter.formatTime 실패: %s", e)
            return "1970-01-01 00:00:00"


def _attach_file_handler(formatter: logging.Formatter) -> None:
    """LOG_FILE_PATH 가 지정된 경우 RotatingFileHandler 추가. 실패해도 콘솔은 살아있음."""
    file_path = demon_config.LOG_FILE_PATH
    if not file_path:
        return
    try:
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            filename=file_path,
            maxBytes=demon_config.LOG_FILE_MAX_BYTES,
            backupCount=demon_config.LOG_FILE_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setLevel(demon_config.LOG_LEVEL)
        file_handler.setFormatter(formatter)
        logging.getLogger().addHandler(file_handler)
    except OSError as e:
        logger.error("로그 파일 핸들러 설정 실패(OSError): %s", e)
    except Exception as e:
        logger.error("로그 파일 핸들러 설정 실패: %s", e)


def setup_logging() -> None:
    """루트 로거 1회 초기화. 중복 호출 시 핸들러가 중복 추가되지 않도록 가드."""
    try:
        root = logging.getLogger()
        if getattr(root, "_matador_configured", False):
            return

        root.setLevel(demon_config.LOG_LEVEL)

        formatter = _AppTzFormatter(
            fmt=demon_config.LOG_FORMAT,
            datefmt=demon_config.LOG_DATEFMT,
        )

        console_handler = logging.StreamHandler()
        console_handler.setLevel(demon_config.LOG_LEVEL)
        console_handler.setFormatter(formatter)
        root.addHandler(console_handler)

        _attach_file_handler(formatter)

        root._matador_configured = True  # type: ignore[attr-defined]
    except (OSError, ValueError) as e:
        logger.error("setup_logging 실패(OS/Value): %s", e)
    except Exception as e:
        logger.error("setup_logging 실패: %s", e)
