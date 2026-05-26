from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from .. import config as demon_config
from ..core.context import RuntimeContext

logger = logging.getLogger(__name__)

# config.py 미정의 시 기본값 — 운영 시 config.py에 상수 추가 권장:
# ANOMALY_DELTA_V_ABS_MIN, ATTACK_MODE_THRESHOLD_SHRINK_RATIO, ANOMALY_RING_BUFFER_LEN
_DELTA_V_ABS_MIN: float = float(getattr(demon_config, "ANOMALY_DELTA_V_ABS_MIN", 0.1))
_ATTACK_MODE_SHRINK_RATIO: float = float(
    getattr(demon_config, "ATTACK_MODE_THRESHOLD_SHRINK_RATIO", 0.1),
)
_RING_BUFFER_LEN: int = int(getattr(demon_config, "ANOMALY_RING_BUFFER_LEN", 5))


class FalsePositiveFilterProtocol(Protocol):
    """오탐 필터 — GScomms 등에서 set_false_positive_filter 로 주입."""

    def on_anomaly_detected(self, key_set: dict[str, Any]) -> None:
        ...


class AnomalyDetector:
    """1초 주기 전력 이상 탐지, 무결성 검증, 오탐 필터 연동."""

    def __init__(self, ctx: RuntimeContext) -> None:
        self._ctx = ctx
        self._attack_mode = False
        self._attack_lock = threading.Lock()
        self._fp_filter: FalsePositiveFilterProtocol | None = None
        self._adcs_series: deque[dict[str, Any]] = deque(maxlen=_RING_BUFFER_LEN)
        self._tlm_series: deque[dict[str, Any]] = deque(maxlen=_RING_BUFFER_LEN)

    def set_false_positive_filter(self, fp_filter: FalsePositiveFilterProtocol | Any) -> None:
        """FalsePositiveFilter 인스턴스 주입 (런타임 wiring)."""
        try:
            self._fp_filter = fp_filter
            logger.info("FalsePositiveFilter 주입 완료")
        except Exception as e:
            logger.error("set_false_positive_filter 실패: %s", e)

    def set_attack_mode(self, enabled: bool) -> None:
        """True면 임계 범위를 중앙 기준 ATTACK_MODE_THRESHOLD_SHRINK_RATIO 만큼 축소."""
        try:
            with self._attack_lock:
                self._attack_mode = bool(enabled)
            logger.info("attack_mode=%s", enabled)
        except Exception as e:
            logger.error("set_attack_mode 실패: %s", e)

    def run(self) -> None:
        """데몬 스레드 진입점 — collect_interval_sec 주기 탐지 루프."""
        logger.info("AnomalyDetector started")
        interval = float(self._ctx.config.collect_interval_sec)
        try:
            while not self._ctx.shutdown_event.is_set():
                cycle_start = time.monotonic()
                try:
                    self._tick_cycle()
                except Exception as e:
                    logger.error("AnomalyDetector tick 실패: %s", e)
                elapsed = time.monotonic() - cycle_start
                remaining = interval - elapsed
                if remaining > 0:
                    if self._ctx.shutdown_event.wait(timeout=remaining):
                        break
        except Exception as e:
            logger.error("AnomalyDetector run 실패: %s", e)
        logger.info("AnomalyDetector stopped")

    def _tick_cycle(self) -> None:
        """1주기: 링버퍼 샘플 → 채널 0~3 파이프라인 → 이상 시 해시·오탐 필터."""
        try:
            self._sample_ring_buffers()
            for sw_id in range(demon_config.PWR_SW_ID_COUNT):
                self._run_channel_pipeline(sw_id)
            anomaly = self.detect_power_anomaly()
            if not anomaly.get("sw_id_list"):
                return
            sw_id_list = anomaly["sw_id_list"]
            logger.info("전력 이상 감지 sw_id_list=%s", sw_id_list)
            event_id = self.verify_hash_on_anomaly()
            key_set = self._build_key_set(sw_id_list, event_id)
            self._dispatch_false_positive(key_set)
        except Exception as e:
            logger.error("_tick_cycle 실패: %s", e)

    def _sample_ring_buffers(self) -> None:
        """SAT_ADCS_FILTER / SAT_TLM_CURRENT 스냅샷을 deque에 적재."""
        try:
            channel1 = int(demon_config.SAT_ADCS_FILTER_CHANNEL_ID)
            adcs = self._ctx.db.get_adcs_filter(channel1)
            if adcs is not None:
                self._adcs_series.append(dict(adcs))
            tlm = self._ctx.db.get_tlm_current()
            if tlm is not None:
                self._tlm_series.append(dict(tlm))
        except Exception as e:
            logger.error("_sample_ring_buffers 실패: %s", e)

    def _run_channel_pipeline(self, sw_id: int) -> None:
        """compute_delta → check_threshold → update_exceed_meta (채널 1개)."""
        try:
            row = self._ctx.db.get_pwr_meta(sw_id)
            if row is None:
                return
            deltas = self.compute_delta(row)
            if deltas is None:
                return
            _prev_dv, curr_dv = deltas
            voltage = float(row["VOLTAGE"])
            exceeded = self.check_threshold(sw_id, voltage)
            self.update_exceed_meta(sw_id, exceeded, curr_dv)
        except Exception as e:
            logger.error("_run_channel_pipeline sw_id=%s 실패: %s", sw_id, e)

    def compute_delta(self, pwr_row: dict[str, Any]) -> tuple[float, float] | None:
        """
        SerialReader upsert 이후 DB의 PREV_DELTA_V / CURR_DELTA_V 를 반환.

        입력: SAT_PWR_META 행 dict
        반환: (prev_delta_v, curr_delta_v) 또는 None
        """
        try:
            prev_dv = float(pwr_row["PREV_DELTA_V"])
            curr_dv = float(pwr_row["CURR_DELTA_V"])
            return (prev_dv, curr_dv)
        except (KeyError, TypeError, ValueError) as e:
            logger.error("compute_delta 입력 오류: %s", e)
            return None
        except Exception as e:
            logger.error("compute_delta 실패: %s", e)
            return None

    def check_threshold(self, sw_id: int, voltage: float) -> bool:
        """전압이 유효 임계 범위를 벗어나면 True."""
        try:
            lo, hi = self._get_effective_thresholds(sw_id)
            return voltage < lo or voltage > hi
        except (IndexError, TypeError, ValueError) as e:
            logger.error("check_threshold 입력 오류 sw_id=%s: %s", sw_id, e)
            return False
        except Exception as e:
            logger.error("check_threshold 실패 sw_id=%s: %s", sw_id, e)
            return False

    def update_exceed_meta(self, sw_id: int, exceeded: bool, curr_delta_v: float) -> None:
        """EXCEED_COUNT / CONSECUTIVE_EXCEED / ANOMALY_FLAG 갱신 후 DB 반영."""
        try:
            row = self._ctx.db.get_pwr_meta(sw_id)
            if row is None:
                return
            exceed_count = int(row.get("EXCEED_COUNT", 0))
            consecutive = int(row.get("CONSECUTIVE_EXCEED", 0))
            if exceeded:
                exceed_count += 1
                consecutive += 1
            else:
                consecutive = 0
            threshold = int(self._ctx.config.exceed_count_threshold)
            anomaly_flag = 1 if (
                exceed_count >= threshold and abs(curr_delta_v) > _DELTA_V_ABS_MIN
            ) else 0
            exceed_info = {
                "sw_id": sw_id,
                "exceed_count": exceed_count,
                "consecutive_exceed": consecutive,
                "anomaly_flag": anomaly_flag,
            }
            self._ctx.db.update_pwr_exceed_meta(exceed_info)
        except (TypeError, ValueError) as e:
            logger.error("update_exceed_meta 입력 오류 sw_id=%s: %s", sw_id, e)
        except Exception as e:
            logger.error("update_exceed_meta 실패 sw_id=%s: %s", sw_id, e)

    def detect_power_anomaly(self) -> dict[str, Any]:
        """ANOMALY_FLAG=1 채널 수집. 정상 시 빈 dict."""
        try:
            rows = self._ctx.db.get_pwr_meta_all()
            sw_id_list: list[int] = []
            for row in rows:
                if int(row.get("ANOMALY_FLAG", 0)) == 1:
                    sw_id_list.append(int(row["SW_ID"]))
            if not sw_id_list:
                return {}
            return {"sw_id_list": sw_id_list, "pk_list": list(sw_id_list)}
        except Exception as e:
            logger.error("detect_power_anomaly 실패: %s", e)
            return {}

    def verify_hash_on_anomaly(self) -> int:
        """
        integrity_target_dir 기준 파일 해시 검증.

        변조 시 SAT_EVENT_QUEUE PRIORITY=1 INSERT. 반환: event_id (없으면 0).
        """
        try:
            rows = self._ctx.db.get_integrity_hash()
            if rows is None:
                return 0
            if not isinstance(rows, list) or len(rows) == 0:
                target = Path(self._ctx.config.integrity_target_dir)
                if not target.is_dir():
                    logger.warning(
                        "무결성 baseline 없음 및 대상 디렉터리 없음: %s",
                        target,
                    )
                else:
                    logger.warning(
                        "SAT_INTEGRITY_HASH 비어 있음 — 검증 스킵 (dir=%s)",
                        target,
                    )
                return 0
            base_dir = Path(self._ctx.config.integrity_target_dir)
            violated_paths: list[str] = []
            for row in rows:
                file_path = str(row.get("FILE_PATH", ""))
                expected = str(row.get("EXPECTED_HASH", "")).strip().lower()
                if not file_path or not expected:
                    continue
                resolved = Path(file_path)
                if not resolved.is_absolute():
                    resolved = base_dir / file_path
                if not resolved.is_file():
                    violated_paths.append(str(resolved))
                    continue
                actual = self._compute_file_hash(resolved)
                if actual is None or actual.lower() != expected:
                    violated_paths.append(str(resolved))
            if not violated_paths:
                return 0
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            event_id = self._ctx.db.insert_event({
                "DETECTED_AT": now,
                "TIMESTAMP": now,
                "EVENT_TYPE": "INTEGRITY_VIOLATION",
                "PRIORITY": 1,
                "IS_SENT": 0,
            })
            if event_id < 1:
                logger.error("무결성 이벤트 INSERT 실패 paths=%s", violated_paths)
                return 0
            logger.info(
                "무결성 위반 감지 event_id=%s paths=%s",
                event_id,
                violated_paths,
            )
            return event_id
        except OSError as e:
            logger.error("verify_hash_on_anomaly IO 오류: %s", e)
            return 0
        except Exception as e:
            logger.error("verify_hash_on_anomaly 실패: %s", e)
            return 0

    def _build_key_set(self, sw_id_list: list[int], event_id: int) -> dict[str, Any]:
        """FalsePositiveFilter 전달용 key_set."""
        try:
            primary = sw_id_list[0]
            detected_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            row = self._ctx.db.get_pwr_meta(primary)
            if row is not None and row.get("UPDATED_AT"):
                detected_at = str(row["UPDATED_AT"])
            return {
                "tlm_id": int(demon_config.SAT_TLM_ID),
                "sw_id": primary,
                "channel1": int(demon_config.SAT_ADCS_FILTER_CHANNEL_ID),
                "event_id": event_id,
                "detected_at": detected_at,
                "adcs_series": list(self._adcs_series),
                "tlm_series": list(self._tlm_series),
                "sw_id_list": sw_id_list,
            }
        except Exception as e:
            logger.error("_build_key_set 실패: %s", e)
            return {
                "tlm_id": int(demon_config.SAT_TLM_ID),
                "sw_id": sw_id_list[0] if sw_id_list else 0,
                "channel1": int(demon_config.SAT_ADCS_FILTER_CHANNEL_ID),
                "event_id": event_id,
                "detected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "adcs_series": [],
                "tlm_series": [],
                "sw_id_list": sw_id_list,
            }

    def _dispatch_false_positive(self, key_set: dict[str, Any]) -> None:
        """주입된 FalsePositiveFilter.on_anomaly_detected 호출."""
        try:
            if self._fp_filter is None:
                logger.warning(
                    "FalsePositiveFilter 미주입 — key_set 스킵 sw_id=%s",
                    key_set.get("sw_id"),
                )
                return
            self._fp_filter.on_anomaly_detected(key_set)
        except AttributeError as e:
            logger.error("FalsePositiveFilter on_anomaly_detected 없음: %s", e)
        except Exception as e:
            logger.error("_dispatch_false_positive 실패: %s", e)

    def _get_effective_thresholds(self, sw_id: int) -> tuple[float, float]:
        """ctx.config 임계치; attack_mode 시 범위 축소."""
        try:
            lo = float(self._ctx.config.v_threshold_lo[sw_id])
            hi = float(self._ctx.config.v_threshold_hi[sw_id])
            with self._attack_lock:
                attack = self._attack_mode
            if not attack:
                return (lo, hi)
            center = (lo + hi) / 2.0
            half = (hi - lo) / 2.0 * (1.0 - _ATTACK_MODE_SHRINK_RATIO)
            return (center - half, center + half)
        except (IndexError, TypeError, ValueError) as e:
            logger.error("_get_effective_thresholds 입력 오류 sw_id=%s: %s", sw_id, e)
            return (0.0, 0.0)
        except Exception as e:
            logger.error("_get_effective_thresholds 실패 sw_id=%s: %s", sw_id, e)
            return (0.0, 0.0)

    def _compute_file_hash(self, path: Path) -> str | None:
        """SHA-256 hex digest."""
        try:
            digest = hashlib.sha256()
            with path.open("rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    digest.update(chunk)
            return digest.hexdigest()
        except OSError as e:
            logger.error("_compute_file_hash IO 오류 %s: %s", path, e)
            return None
        except Exception as e:
            logger.error("_compute_file_hash 실패 %s: %s", path, e)
            return None
