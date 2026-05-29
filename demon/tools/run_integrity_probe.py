#!/usr/bin/env python3
"""
무결성 검증 1회 실행 — verify_hash_on_anomaly() 직접 호출.

전력 이상 없이 /cf 변경(추가·변조)만 확인할 때 사용.

    python3 -m demon.tools.run_integrity_probe
"""
from __future__ import annotations

import argparse
import logging
import sys
import threading

from .. import config as demon_config
from ..core.context import DaemonConfig, RuntimeContext
from pathlib import Path
from ..db.db_manager import DBManager
from ..workers.anomaly_detector import AnomalyDetector

logger = logging.getLogger(__name__)


def main() -> int:
    parser = argparse.ArgumentParser(description="SAT_INTEGRITY_HASH 검증 프로브")
    parser.add_argument("--db", default=None, help="SQLite 경로")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    cfg = DaemonConfig(db_path=args.db) if args.db else DaemonConfig()
    if cfg.db_path is None:
        logger.error("DB 경로 없음")
        return 1

    db = DBManager(cfg.db_path)
    if not db.init_db():
        logger.error("DB init 실패")
        return 1

    ctx = RuntimeContext(config=cfg, shutdown_event=threading.Event(), db=db)
    detector = AnomalyDetector(ctx)

    from ..integrity_dir_hash import compute_directory_manifest_hash

    base = Path(cfg.integrity_target_dir).expanduser()
    live = compute_directory_manifest_hash(base)
    print(f"대상 폴더: {base}")
    print(f"현재 폴더 해시: {live}")

    rec = db.get_integrity_hash(int(demon_config.INTEGRITY_DIR_FILE_ID))
    if rec:
        exp = str(rec.get("EXPECTED_HASH", ""))
        print(f"DB 기대 해시: {exp}")
        if live and exp:
            print(f"일치 여부: {live.lower() == exp.strip().lower()}")
    else:
        print("DB 기대 해시 없음 — seed_cf_integrity 먼저 실행")

    print("verify_hash_on_anomaly 실행...")
    violated = detector.verify_hash_on_anomaly()
    print(f"결과: violated={violated}")

    pending = db.get_pending_events()
    if not pending:
        print("미전송 이벤트 없음")
        return 0 if not violated else 0

    print(f"미전송 이벤트 {len(pending)}건:")
    for ev in pending:
        print(
            f"  event_id={ev.get('EVENT_ID')} type={ev.get('EVENT_TYPE')} "
            f"priority={ev.get('PRIORITY')} exc={ev.get('EXCEPTION_CODE')}",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
