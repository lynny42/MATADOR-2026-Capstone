#!/usr/bin/env python3
"""
데몬 진입점.

저장소 루트에서 실행:

    python3 -m demon.main

원격 PC·파이프로 로그가 늦게 보이면:

    python3 -u -m demon.main
"""
from __future__ import annotations

import logging
import sys

from .core import DaemonConfig, setup_logging
from .core.runtime import MatadorDaemon

logger = logging.getLogger(__name__)


def main() -> int:
    setup_logging()
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(line_buffering=True)
    except OSError as e:
        logger.warning("stdout line_buffering 설정 실패(OSError): %s", e)
    except Exception as e:
        logger.error("stdout line_buffering 설정 실패: %s", e)
    try:
        daemon = MatadorDaemon(DaemonConfig())
        return daemon.run()
    except Exception as e:
        logger.error("데몬 기동 실패: %s", e)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
