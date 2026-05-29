"""
디렉터리 무결성 — 하위 파일 목록·내용을 묶어 단일 매니페스트 SHA-256 산출.

파일 추가·삭제·내용 변경 시 폴더 해시가 달라진다.
"""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# SAT_INTEGRITY_HASH 에 폴더 1건으로 저장할 때 FILE_PATH 값
INTEGRITY_DIR_FILE_PATH = "."


def compute_file_sha256(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as e:
        logger.error("파일 해시 실패(OS) %s: %s", path, e)
        return None
    except Exception as e:
        logger.error("파일 해시 실패 %s: %s", path, e)
        return None


def compute_directory_manifest_hash(target_dir: Path) -> str | None:
    """
    target_dir 하위 모든 파일의 (상대경로 + 내용 해시)를 정렬해 합친 뒤 SHA-256.

    빈 디렉터리도 고정 해시(e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855) 반환.
    """
    try:
        resolved = target_dir.expanduser().resolve()
        if not resolved.is_dir():
            logger.warning("무결성 대상 디렉터리 없음: %s", resolved)
            return None
        lines: list[str] = []
        for path in sorted(resolved.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(resolved).as_posix()
            file_hash = compute_file_sha256(path)
            if file_hash is None:
                return None
            lines.append(f"{rel}\0{file_hash}")
        manifest = "\n".join(lines)
        return hashlib.sha256(manifest.encode("utf-8")).hexdigest()
    except OSError as e:
        logger.error("디렉터리 매니페스트 해시 실패(OS) %s: %s", target_dir, e)
        return None
    except Exception as e:
        logger.error("디렉터리 매니페스트 해시 실패 %s: %s", target_dir, e)
        return None
