from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


def _default_db_path() -> Path:
    try:
        return Path(__file__).resolve().parent.parent / "database.sqlite"
    except OSError as e:
        logger.error("기본 DB 경로 계산 실패(OSError): %s", e)
        raise
    except Exception as e:
        logger.error("기본 DB 경로 계산 실패: %s", e)
        raise


@dataclass
class DaemonConfig:
    """런타임 설정. 환경에 맞게 생성 시 덮어쓰면 됨."""

    db_path: Path = field(default_factory=_default_db_path)
    serial_port: str = "/dev/ttyUSB0"
    udp_tlm_bind: tuple[str, int] = ("0.0.0.0", 12345)


@dataclass
class RuntimeContext:
    """워커 스레드에 공통으로 넘기는 참조."""

    config: DaemonConfig
    shutdown_event: threading.Event
