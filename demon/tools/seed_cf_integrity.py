#!/usr/bin/env python3
"""
~/cfs/cpu2/cf 폴더 매니페스트 해시를 SAT_INTEGRITY_HASH 기대값(1건)으로 등록.

파일 추가·삭제·변경 전 현재 상태를 baseline 으로 고정한다.

    python3 -m demon.tools.seed_cf_integrity
    python3 -m demon.tools.seed_cf_integrity --dir ~/cfs/cpu2/cf
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .. import config as demon_config
from ..core.context import DaemonConfig
from ..db.db_manager import DBManager
from ..integrity_dir_hash import compute_directory_manifest_hash

logger = logging.getLogger(__name__)


def seed_directory_baseline(target_dir: Path, db: DBManager) -> bool:
    """폴더 매니페스트 해시 1건을 DB에 upsert."""
    try:
        resolved = target_dir.expanduser().resolve()
        digest = compute_directory_manifest_hash(resolved)
        if digest is None:
            logger.error("폴더 해시 계산 실패: %s", resolved)
            return False
        file_id = int(demon_config.INTEGRITY_DIR_FILE_ID)
        file_path = str(demon_config.INTEGRITY_DIR_FILE_PATH)
        if not db.upsert_integrity_hash(file_id, file_path, digest):
            logger.error("DB upsert 실패")
            return False
        n_files = sum(1 for p in resolved.rglob("*") if p.is_file())
        print(f"  dir={resolved}")
        print(f"  files={n_files}")
        print(f"  manifest_sha256={digest}")
        print(f"  DB FILE_ID={file_id} FILE_PATH={file_path!r}")
        return True
    except Exception as e:
        logger.error("seed_directory_baseline 실패: %s", e)
        return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="cFS cf 폴더 매니페스트 해시 baseline 등록",
    )
    parser.add_argument(
        "--dir",
        default=demon_config.INTEGRITY_TARGET_DIR,
        help="스캔 대상 (기본 ~/cfs/cpu2/cf)",
    )
    parser.add_argument("--db", default=None, help="SQLite 경로")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    target_dir = Path(args.dir)
    cfg = DaemonConfig(db_path=args.db) if args.db else DaemonConfig()
    if cfg.db_path is None:
        logger.error("DB 경로를 알 수 없음")
        return 1

    db = DBManager(cfg.db_path)
    if not db.init_db():
        logger.error("DB init 실패")
        return 1

    print(f"무결성 baseline 시드: db={cfg.db_path}")
    if not seed_directory_baseline(target_dir, db):
        return 1
    print("완료 — 이후 파일 추가/삭제/변경 시 폴더 해시가 달라지면 탐지됩니다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
