from __future__ import annotations

import logging
import time

from ..core.context import RuntimeContext

logger = logging.getLogger(__name__)


class GScomms:
    """지상국(COMOS)과의 통신 (소켓/프로토콜은 이후 구현)."""

    def __init__(self, ctx: RuntimeContext) -> None:
        self._ctx = ctx

    def run(self) -> None:
        logger.info("GScomms started (stub)")
        try:
            while not self._ctx.shutdown_event.is_set():
                try:
                    time.sleep(0.25)
                except InterruptedError as e:
                    logger.warning("GScomms sleep 중단: %s", e)
                    break
                except Exception as e:
                    logger.error("GScomms sleep 실패: %s", e)
                    break
        except Exception as e:
            logger.error("GScomms run 실패: %s", e)
        logger.info("GScomms stopped")
