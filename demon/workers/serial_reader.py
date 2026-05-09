from __future__ import annotations

import logging
import time

from ..core.context import RuntimeContext

logger = logging.getLogger(__name__)


class SerialReader:
    """아두이노 전력 데이터 수집 (pyserial 연동은 이후 구현)."""

    def __init__(self, ctx: RuntimeContext) -> None:
        self._ctx = ctx

    def run(self) -> None:
        logger.info("SerialReader started (stub)")
        try:
            while not self._ctx.shutdown_event.is_set():
                try:
                    time.sleep(0.25)
                except InterruptedError as e:
                    logger.warning("SerialReader sleep 중단: %s", e)
                    break
                except Exception as e:
                    logger.error("SerialReader sleep 실패: %s", e)
                    break
        except Exception as e:
            logger.error("SerialReader run 실패: %s", e)
        logger.info("SerialReader stopped")
