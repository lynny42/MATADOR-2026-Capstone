from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path

from .. import config as demon_config

logger = logging.getLogger(__name__)


def _default_db_path() -> Path:
    """config.DB_PATH 가 지정되어 있으면 그 값, 아니면 demon 패키지 옆 database.sqlite."""
    try:
        if demon_config.DB_PATH:
            return Path(demon_config.DB_PATH).expanduser().resolve()
        return Path(__file__).resolve().parent.parent / "database.sqlite"
    except OSError as e:
        logger.error("기본 DB 경로 계산 실패(OSError): %s", e)
        raise
    except Exception as e:
        logger.error("기본 DB 경로 계산 실패: %s", e)
        raise


@dataclass
class DaemonConfig:
    """런타임 설정. 환경에 맞게 생성 시 덮어쓰면 됨.

    기본값은 모두 demon.config 모듈의 모듈 레벨 상수에서 가져온다.
    하드코딩 금지 — 새 값을 추가할 때는 반드시 demon/config.py 에 상수 정의 후 여기에 매핑.
    """

    # --- 경로 ---
    db_path: Path = field(default_factory=_default_db_path)

    # --- 시리얼 ---
    serial_port: str = demon_config.SERIAL_PORT
    serial_baud: int = demon_config.BAUD_RATE
    serial_read_timeout_sec: float = demon_config.SERIAL_READ_TIMEOUT_SEC
    serial_reopen_backoff_sec: float = demon_config.SERIAL_REOPEN_BACKOFF_SEC

    # --- UDP 텔레메트리 ---
    udp_tlm_bind: tuple[str, int] = field(
        default_factory=lambda: (
            demon_config.UDP_TLM_BIND_HOST,
            demon_config.UDP_TLM_PORT,
        ),
    )
    udp_recv_buffer_bytes: int = demon_config.UDP_RECV_BUFFER_BYTES

    # --- 지상국 ---
    gs_host: str = demon_config.GS_HOST
    gs_port: int = demon_config.GS_PORT
    gs_send_retry_max: int = demon_config.GS_SEND_RETRY_MAX
    gs_send_retry_base_sec: float = demon_config.GS_SEND_RETRY_BASE_SEC

    # --- 수집 주기 ---
    collect_interval_sec: float = demon_config.COLLECT_INTERVAL_SEC

    # --- 전력 임계치 (SW_ID 0~3) ---
    v_threshold_lo: list[float] = field(
        default_factory=lambda: list(demon_config.V_THRESHOLD_LO),
    )
    v_threshold_hi: list[float] = field(
        default_factory=lambda: list(demon_config.V_THRESHOLD_HI),
    )

    # --- 물리 범위 필터 ---
    voltage_max: float = demon_config.VOLTAGE_MAX
    current_max: float = demon_config.CURRENT_MAX

    # --- 무결성 ---
    integrity_target_dir: str = demon_config.INTEGRITY_TARGET_DIR

    # --- 이상탐지 ---
    exceed_count_threshold: int = demon_config.EXCEED_COUNT_THRESHOLD
    consecutive_threshold: int = demon_config.CONSECUTIVE_THRESHOLD


@dataclass
class RuntimeContext:
    """워커 스레드에 공통으로 넘기는 참조."""

    config: DaemonConfig
    shutdown_event: threading.Event
