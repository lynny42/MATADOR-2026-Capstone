from __future__ import annotations

import hashlib
import logging
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from .. import config as demon_config
from ..core.context import RuntimeContext

logger = logging.getLogger(__name__)

# config.py 에 정의 권장 — 미정의 시 명세 기본값 사용
_DEFAULT_ANOMALY_DELTA_V = 0.1
_DEFAULT_ATTACK_THRESHOLD_SHRINK = 0.1
_EXCEPTION_CODE_HASH_MISMATCH = 1
_EXCEPTION_CODE_HASH_MISSING = 2


class FalsePositiveFilterLike(Protocol):
    """오탐 필터 — set_false_positive_filter() 로 주입."""

    def on_anomaly_detected(self, key_set: dict[str, Any]) -> None:
        ...


class GScommsLike(Protocol):
    """ADCS 누적 스냅샷 즉시 송신용 (set_gs_comms)."""

    def transmit_adcs_filter(self) -> None:
        ...


class AnomalyDetector:
    """전력 이상 탐지 — 1초 주기 SAT_PWR_META 채널 0~3 스캔."""

    def __init__(self, ctx: RuntimeContext) -> None:
        self._ctx = ctx
        self._attack_mode = False
        self._false_positive_filter: FalsePositiveFilterLike | None = None
        self._gs_comms: GScommsLike | None = None
        self._fpf_dispatched = False
        self._adcs_series: deque[dict[str, Any]] = deque(maxlen=5)
        self._tlm_series: deque[dict[str, Any]] = deque(maxlen=5)

    def set_false_positive_filter(self, fpf: FalsePositiveFilterLike) -> None:
        """FalsePositiveFilter 인스턴스 주입 (런타임 wiring)."""
        try:
            self._false_positive_filter = fpf
        except Exception as e:
            logger.error("set_false_positive_filter 실패: %s", e)

    def set_gs_comms(self, gs: GScommsLike) -> None:
        """에피소드 종료 시 ADCS 누적 송신용 GScomms 주입."""
        try:
            self._gs_comms = gs
        except Exception as e:
            logger.error("set_gs_comms 실패: %s", e)

    def set_attack_mode(self, enabled: bool) -> None:
        """True 이면 전압 임계 범위 10% 축소(민감도 상승)."""
        try:
            self._attack_mode = bool(enabled)
            logger.info("AnomalyDetector attack_mode=%s", self._attack_mode)
        except Exception as e:
            logger.error("set_attack_mode 실패: %s", e)

    def run(self) -> None:
        """anomaly_detector_thread — 1초 주기 탐지 루프."""
        logger.info("AnomalyDetector started")
        try:
            interval = float(self._ctx.config.collect_interval_sec)
            while not self._ctx.shutdown_event.is_set():
                try:
                    self._tick()
                except Exception as e:
                    logger.error("AnomalyDetector tick 실패: %s", e)
                if self._ctx.shutdown_event.wait(timeout=interval):
                    break
        except Exception as e:
            logger.error("AnomalyDetector run 실패: %s", e)
        logger.info("AnomalyDetector stopped")

    def _tick(self) -> None:
        """1회 주기: 링버퍼 갱신 → 채널별 탐지 → 이상 시 후속 처리."""
        try:
            self._refresh_series_buffers()
            for sw_id in range(demon_config.PWR_SW_ID_COUNT):
                self._process_channel(sw_id)
            if self._ctx.db.insert_pwr_history_snapshot() < 0:
                logger.warning("insert_pwr_history_snapshot 실패")

            anomaly = self.detect_power_anomaly()
            if anomaly:
                self._persist_adcs_on_anomaly()
                if not self._fpf_dispatched:
                    self._handle_power_anomaly_first(anomaly)
            else:
                if self._fpf_dispatched:
                    self._transmit_adcs_episode_end()
                self._fpf_dispatched = False
        except Exception as e:
            logger.error("_tick 실패: %s", e)

    def _refresh_series_buffers(self) -> None:
        """ADCS·TLM 스냅샷을 deque(maxlen=5) 링버퍼에 적재."""
        try:
            adcs = self._ctx.db.get_adcs_filter()
            if adcs:
                self._adcs_series.append(dict(adcs))
            tlm = self._ctx.db.get_tlm_current()
            if tlm:
                self._tlm_series.append(dict(tlm))
        except Exception as e:
            logger.error("_refresh_series_buffers 실패: %s", e)

    def _process_channel(self, sw_id: int) -> None:
        """채널 1개: compute_delta → check_threshold → update_exceed_meta → DB."""
        try:
            meta = self._ctx.db.get_pwr_meta(sw_id)
            if not meta:
                return
            self.compute_delta(meta)
            exceeded = self.check_threshold(meta, sw_id)
            exceed_info = self.update_exceed_meta(meta, exceeded)
            if not self._ctx.db.update_pwr_exceed_meta(exceed_info):
                logger.warning("update_pwr_exceed_meta 실패 sw_id=%s", sw_id)
        except Exception as e:
            logger.error("_process_channel 실패 sw_id=%s: %s", sw_id, e)

    def compute_delta(self, pwr_meta: dict[str, Any]) -> tuple[float, float] | None:
        """
        SAT_PWR_META 의 delta 읽기 (SerialReader upsert_pwr_meta 가 갱신).

        반환: (prev_delta_v, curr_delta_v). 실패 시 None.
        """
        try:
            prev_delta_v = float(pwr_meta.get("PREV_DELTA_V", 0.0))
            curr_delta_v = float(pwr_meta.get("CURR_DELTA_V", 0.0))
            return (prev_delta_v, curr_delta_v)
        except (ValueError, TypeError) as e:
            logger.error("compute_delta 변환 오류: %s", e)
            return None
        except Exception as e:
            logger.error("compute_delta 실패: %s", e)
            return None

    def check_threshold(self, pwr_meta: dict[str, Any], sw_id: int) -> bool:
        """전압이 (공격 모드 반영) 임계 범위를 벗어나면 True."""
        try:
            voltage = float(pwr_meta.get("VOLTAGE", 0.0))
            lo, hi = self._effective_thresholds(sw_id)
            return voltage < lo or voltage > hi
        except (ValueError, TypeError, IndexError) as e:
            logger.error("check_threshold 입력 오류 sw_id=%s: %s", sw_id, e)
            return False
        except Exception as e:
            logger.error("check_threshold 실패 sw_id=%s: %s", sw_id, e)
            return False

    def update_exceed_meta(
        self,
        pwr_meta: dict[str, Any],
        exceeded: bool,
    ) -> dict[str, Any]:
        """
        EXCEED_COUNT / CONSECUTIVE_EXCEED / ANOMALY_FLAG 산출.

        ANOMALY_FLAG=1: EXCEED_COUNT >= exceed_count_threshold 이고 |CURR_DELTA_V| > 임계.
        """
        try:
            sw_id = int(pwr_meta["SW_ID"])
            exceed_count = int(pwr_meta.get("EXCEED_COUNT", 0))
            consecutive = int(pwr_meta.get("CONSECUTIVE_EXCEED", 0))
            curr_delta_v = float(pwr_meta.get("CURR_DELTA_V", 0.0))

            if exceeded:
                exceed_count += 1
                consecutive += 1
            else:
                consecutive = 0

            delta_thresh = self._anomaly_delta_threshold()
            count_thresh = int(self._ctx.config.exceed_count_threshold)
            anomaly_flag = 0
            if exceed_count >= count_thresh and abs(curr_delta_v) > delta_thresh:
                anomaly_flag = 1

            return {
                "sw_id": sw_id,
                "exceed_count": exceed_count,
                "consecutive_exceed": consecutive,
                "anomaly_flag": anomaly_flag,
            }
        except (KeyError, ValueError, TypeError) as e:
            logger.error("update_exceed_meta 입력 오류: %s", e)
            sw_id = int(pwr_meta.get("SW_ID", 0))
            return {
                "sw_id": sw_id,
                "exceed_count": 0,
                "consecutive_exceed": 0,
                "anomaly_flag": 0,
            }
        except Exception as e:
            logger.error("update_exceed_meta 실패: %s", e)
            sw_id = int(pwr_meta.get("SW_ID", 0))
            return {
                "sw_id": sw_id,
                "exceed_count": 0,
                "consecutive_exceed": 0,
                "anomaly_flag": 0,
            }

    def detect_power_anomaly(self) -> dict[str, Any]:
        """ANOMALY_FLAG=1 채널 수집. 없으면 {}."""
        try:
            sw_id_list: list[int] = []
            for row in self._ctx.db.get_pwr_meta_all():
                if int(row.get("ANOMALY_FLAG", 0)) == 1:
                    sw_id_list.append(int(row["SW_ID"]))
            if not sw_id_list:
                return {}
            return {"sw_id_list": sw_id_list}
        except (ValueError, TypeError, KeyError) as e:
            logger.error("detect_power_anomaly 변환 오류: %s", e)
            return {}
        except Exception as e:
            logger.error("detect_power_anomaly 실패: %s", e)
            return {}

    def verify_hash_on_anomaly(self) -> bool:
        """
        integrity_target_dir 대상 파일 해시 검증.

        Returns:
            True — 변조·누락 감지(오탐 필터 스킵). INSERT 성공 여부와 무관.
            False — 이상 없음 또는 검증 대상 없음.
        """
        try:
            records = self._ctx.db.get_integrity_hash()
            if records is None:
                logger.warning("verify_hash_on_anomaly: 무결성 레코드 조회 실패")
                return False
            if not records:
                return False

            base_dir = Path(self._ctx.config.integrity_target_dir)
            for rec in records:
                if not isinstance(rec, dict):
                    continue
                if int(rec.get("IS_VIOLATED", 0)) == 1:
                    continue
                file_path = str(rec.get("FILE_PATH", "")).strip()
                expected = str(rec.get("EXPECTED_HASH", "")).strip().lower()
                if not file_path or not expected:
                    continue
                target = Path(file_path)
                if not target.is_absolute():
                    target = base_dir / file_path
                actual = self._compute_file_hash(target)
                if actual is None:
                    self._ctx.db.update_integrity_result(file_path, 1)
                    if not self._insert_integrity_event(
                        file_path,
                        "missing_or_unreadable",
                        _EXCEPTION_CODE_HASH_MISSING,
                    ):
                        logger.error(
                            "무결성 이벤트 INSERT 실패(누락) — 오탐 필터는 스킵 path=%s",
                            file_path,
                        )
                    return True
                if actual.lower() != expected:
                    self._ctx.db.update_integrity_result(file_path, 1)
                    if not self._insert_integrity_event(
                        file_path,
                        "hash_mismatch",
                        _EXCEPTION_CODE_HASH_MISMATCH,
                    ):
                        logger.error(
                            "무결성 이벤트 INSERT 실패(불일치) — 오탐 필터는 스킵 path=%s",
                            file_path,
                        )
                    return True
                self._ctx.db.update_integrity_result(file_path, 0)
            return False
        except Exception as e:
            logger.error("verify_hash_on_anomaly 실패: %s", e)
            return False

    def _handle_power_anomaly_first(self, anomaly: dict[str, Any]) -> None:
        """이상 에피소드 최초 1회 — 무결성 검사 → 오탐 필터 전달."""
        try:
            sw_id_list = list(anomaly.get("sw_id_list", []))
            if not sw_id_list:
                return

            if self.verify_hash_on_anomaly():
                logger.warning(
                    "무결성 위반 감지 — PRIORITY=1 이벤트 등록, 오탐 필터 스킵 sw_id_list=%s",
                    sw_id_list,
                )
                self._fpf_dispatched = True
                return

            detected_at = self._utc_now_iso()
            primary_sw_id = int(sw_id_list[0])

            adcs_row = self._ctx.db.get_adcs_filter()
            channel1 = int(
                (adcs_row or {}).get("CHENNEL1", demon_config.SAT_ADCS_FILTER_CHANNEL_ID),
            )

            key_set: dict[str, Any] = {
                "tlm_id": demon_config.SAT_TLM_ID,
                "sw_id": primary_sw_id,
                "channel1": channel1,
                "CHENNEL1": channel1,
                "event_id": 0,
                "detected_at": detected_at,
                "adcs_series": list(self._adcs_series),
                "tlm_series": list(self._tlm_series),
                "sw_id_list": sw_id_list,
            }

            if self._false_positive_filter is None:
                logger.warning(
                    "FalsePositiveFilter 미주입 — on_anomaly_detected 스킵 sw_id=%s",
                    primary_sw_id,
                )
                self._fpf_dispatched = True
                return

            self._false_positive_filter.on_anomaly_detected(key_set)
            self._fpf_dispatched = True
            logger.info(
                "전력 이상 → 오탐필터 전달 sw_id_list=%s channel1=%s",
                sw_id_list,
                channel1,
            )
        except Exception as e:
            logger.error("_handle_power_anomaly_first 실패: %s", e)

    def _persist_adcs_on_anomaly(self) -> None:
        """이상 구간 동안 ADCS 스냅샷을 SAT_ADCS_FILTER에 누적."""
        try:
            if not self._fpf_dispatched:
                for snap in self._adcs_series:
                    payload = dict(snap)
                    payload.pop("CHENNEL1", None)
                    if payload:
                        payload.setdefault("TIMESTAMP", self._utc_now_iso())
                        if not self._ctx.db.insert_adcs_filter(payload):
                            logger.warning("insert_adcs_filter 실패(시리즈)")
            if self._adcs_series:
                payload = dict(self._adcs_series[-1])
            else:
                row = self._ctx.db.get_adcs_filter()
                payload = dict(row) if row else {}
            if not payload:
                return
            payload.setdefault("TIMESTAMP", self._utc_now_iso())
            payload.pop("CHENNEL1", None)
            if not self._ctx.db.insert_adcs_filter(payload):
                logger.warning("insert_adcs_filter 실패")
        except Exception as e:
            logger.error("_persist_adcs_on_anomaly 실패: %s", e)

    def _transmit_adcs_episode_end(self) -> None:
        """이상 해제 시 누적 ADCS 스냅샷 전체를 지상국으로 송신."""
        try:
            if self._gs_comms is None:
                logger.warning("GScomms 미주입 — ADCS 에피소드 종료 송신 스킵")
                return
            self._gs_comms.transmit_adcs_filter()
            logger.info("이상 에피소드 종료 — SAT_ADCS_FILTER 누적 송신")
        except Exception as e:
            logger.error("_transmit_adcs_episode_end 실패: %s", e)

    def _effective_thresholds(self, sw_id: int) -> tuple[float, float]:
        """공격 모드 시 정상 범위 폭 10% 축소."""
        try:
            lo = float(self._ctx.config.v_threshold_lo[sw_id])
            hi = float(self._ctx.config.v_threshold_hi[sw_id])
            if not self._attack_mode:
                return lo, hi
            shrink_ratio = self._attack_threshold_shrink_ratio()
            mid = (lo + hi) / 2.0
            half = (hi - lo) / 2.0
            new_half = half * (1.0 - shrink_ratio)
            return mid - new_half, mid + new_half
        except (IndexError, ValueError, TypeError) as e:
            logger.error("_effective_thresholds 오류 sw_id=%s: %s", sw_id, e)
            return 0.0, 0.0
        except Exception as e:
            logger.error("_effective_thresholds 실패 sw_id=%s: %s", sw_id, e)
            return 0.0, 0.0

    def _anomaly_delta_threshold(self) -> float:
        try:
            val = getattr(self._ctx.config, "anomaly_delta_v_threshold", None)
            if val is not None:
                return float(val)
            return float(
                getattr(
                    demon_config,
                    "ANOMALY_DELTA_V_THRESHOLD",
                    _DEFAULT_ANOMALY_DELTA_V,
                ),
            )
        except (ValueError, TypeError) as e:
            logger.error("_anomaly_delta_threshold 변환 오류: %s", e)
            return _DEFAULT_ANOMALY_DELTA_V
        except Exception as e:
            logger.error("_anomaly_delta_threshold 실패: %s", e)
            return _DEFAULT_ANOMALY_DELTA_V

    def _attack_threshold_shrink_ratio(self) -> float:
        try:
            val = getattr(self._ctx.config, "attack_mode_threshold_shrink_ratio", None)
            if val is not None:
                return float(val)
            return float(
                getattr(
                    demon_config,
                    "ATTACK_MODE_THRESHOLD_SHRINK_RATIO",
                    _DEFAULT_ATTACK_THRESHOLD_SHRINK,
                ),
            )
        except (ValueError, TypeError) as e:
            logger.error("_attack_threshold_shrink_ratio 변환 오류: %s", e)
            return _DEFAULT_ATTACK_THRESHOLD_SHRINK
        except Exception as e:
            logger.error("_attack_threshold_shrink_ratio 실패: %s", e)
            return _DEFAULT_ATTACK_THRESHOLD_SHRINK

    def _compute_file_hash(self, path: Path) -> str | None:
        try:
            if not path.is_file():
                logger.warning("무결성 대상 파일 없음: %s", path)
                return None
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                while True:
                    chunk = handle.read(65536)
                    if not chunk:
                        break
                    digest.update(chunk)
            return digest.hexdigest()
        except OSError as e:
            logger.error("파일 해시 계산 실패(OS) %s: %s", path, e)
            return None
        except Exception as e:
            logger.error("파일 해시 계산 실패 %s: %s", path, e)
            return None

    def _insert_integrity_event(
        self,
        file_path: str,
        reason: str,
        exception_code: int,
    ) -> bool:
        """PRIORITY=1 무결성 이벤트 INSERT. 성공 시 True."""
        try:
            detected_at = self._utc_now_iso()
            event_id = self._ctx.db.insert_event({
                "DETECTED_AT": detected_at,
                "TIMESTAMP": detected_at,
                "EVENT_TYPE": f"INTEGRITY_{reason}",
                "PRIORITY": 1,
                "IS_SENT": 0,
                "SW_ID": 0,
                "WEIGHT": 100,
                "EXCEPTION_CODE": int(exception_code),
                "CHENNEL1": 0,
            })
            if event_id < 0:
                logger.error("무결성 이벤트 insert 실패 path=%s", file_path)
                return False
            logger.warning(
                "파일 무결성 위반 path=%s reason=%s event_id=%s",
                file_path,
                reason,
                event_id,
            )
            return True
        except Exception as e:
            logger.error("_insert_integrity_event 실패: %s", e)
            return False

    @staticmethod
    def _utc_now_iso() -> str:
        try:
            return datetime.now(timezone.utc).isoformat()
        except Exception as e:
            logger.error("UTC 시각 생성 실패: %s", e)
            return "1970-01-01T00:00:00+00:00"
