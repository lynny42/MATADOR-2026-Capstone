#!/usr/bin/env python3
"""
데몬 진입점.

저장소 루트에서 실행:

    python3 -m demon.main
"""
from __future__ import annotations

import logging

from .core import DaemonConfig, MatadorDaemon

logger = logging.getLogger(__name__)


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(threadName)s] %(name)s: %(message)s",
    )
    try:
        daemon = MatadorDaemon(DaemonConfig())
        return daemon.run()
    except Exception as e:
        logger.error("데몬 기동 실패: %s", e)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
