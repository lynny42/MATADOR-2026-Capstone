from __future__ import annotations

import logging
import time

from ..core.context import RuntimeContext

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """DB·텔레메트리 기반 이상 탐지 (로직은 이후 구현)."""

    def __init__(self, ctx: RuntimeContext) -> None:
        self._ctx = ctx

    def run(self) -> None:
        logger.info("AnomalyDetector started (stub)")
        try:
            while not self._ctx.shutdown_event.is_set():
                try:
                    time.sleep(0.25)
                except InterruptedError as e:
                    logger.warning("AnomalyDetector sleep 중단: %s", e)
                    break
                except Exception as e:
                    logger.error("AnomalyDetector sleep 실패: %s", e)
                    break
        except Exception as e:
            logger.error("AnomalyDetector run 실패: %s", e)
        logger.info("AnomalyDetector stopped")
