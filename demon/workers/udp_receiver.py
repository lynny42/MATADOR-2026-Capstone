from __future__ import annotations

import logging
import time

from ..core.context import RuntimeContext

logger = logging.getLogger(__name__)


class UDPReceiver:
    """TO_LAB CCSDS 텔레메트리 UDP 수신 (소켓 바인드는 이후 구현)."""

    def __init__(self, ctx: RuntimeContext) -> None:
        self._ctx = ctx

    def run(self) -> None:
        logger.info("UDPReceiver started (stub)")
        try:
            while not self._ctx.shutdown_event.is_set():
                try:
                    time.sleep(0.25)
                except InterruptedError as e:
                    logger.warning("UDPReceiver sleep 중단: %s", e)
                    break
                except Exception as e:
                    logger.error("UDPReceiver sleep 실패: %s", e)
                    break
        except Exception as e:
            logger.error("UDPReceiver run 실패: %s", e)
        logger.info("UDPReceiver stopped")
