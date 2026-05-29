"""StatisticalConsistencyModule (모듈 2) — 전력·통계 정합성.

검증
    - check_baseline_violation: MISSION_MODE별 VOLTAGE/CURR_DELTA_V σ 이탈
    - count_multi_channel_anomaly: SW 0~4 중 동시 ANOMALY_FLAG (≥4개 → 단독 1.0, exc 4)

전력 채널: SW_ID 0~4 (5채널). ADCS 행 키 channel1 과 무관.

입력: key_set.sw_id, get_pwr_meta_all / _snapshots. 시계열은 다채널 UPDATED_AT 윈도우.
"""

import logging
import math
from typing import Any

from . import config
from . import db_context
from .exception_codes import ExceptionCode
from .module_result import ModuleResult

logger = logging.getLogger(config.LOGGER_NAME)


class StatisticalConsistencyModule:
    """자연 통계 분포 이탈 검증 모듈."""

    def __init__(
        self,
        db_manager: Any,
        sub_weights: dict | None = None,
        sigma_threshold: float | None = None,
    ):
        """
        Args:
            db_manager: DBManager 인스턴스. 다음 메서드 필요:
                - get_pwr_meta(sw_id: int) -> dict
                - get_pwr_meta_all() -> list[dict]
                - get_tlm_current() -> dict
            sub_weights: 체크별 가중치
            sigma_threshold: σ 단위 임계치
        """
        self.db = db_manager
        self.sub_weights = (
            sub_weights
            if sub_weights is not None
            else dict(config.STATISTICAL_SUB_WEIGHTS)
        )
        self.sigma_threshold = (
            sigma_threshold
            if sigma_threshold is not None
            else config.SIGMA_THRESHOLD
        )

    # ──────────────────────────────────────────────────────────────────────
    # public
    # ──────────────────────────────────────────────────────────────────────

    def analyze(self, key_set: dict) -> ModuleResult:
        """2가지 정합성 체크를 실행하고 가중 합산 (PhysicalConsistencyModule.analyze와 동일 패턴).

        베이스라인·다채널 점수를 sub_weights로 합산한 뒤, 다채널 단독 신호(코드 4)가
        있으면 score=1.0으로 올린다. 즉시 공격 판정은 FalsePositiveFilter가 코드 4를
        EXCEPTION_CODES_BYPASS_WEIGHTED_SUM에서 처리한다.

        Args:
            key_set: DB 조회용 기본키 집합

        Returns:
            ModuleResult: score 0.0~1.0, signals에 관측된 ExceptionCode 튜플
        """
        try:
            signals_acc: list[ExceptionCode] = []
            s_baseline = self.check_baseline_violation(key_set, signals_acc)
            s_multi = self.count_multi_channel_anomaly(key_set, signals_acc)

            score = (
                self.sub_weights["baseline_violation"] * s_baseline
                + self.sub_weights["multi_channel_anomaly"] * s_multi
            )
            score = max(0.0, min(1.0, score))
            if ExceptionCode.MULTI_CHANNEL_4PLUS in signals_acc:
                score = 1.0
            return ModuleResult(score, tuple(signals_acc))
        except Exception as e:
            logger.error(f"StatisticalConsistencyModule.analyze 실패: {e}")
            return ModuleResult(0.0, ())

    # ──────────────────────────────────────────────────────────────────────
    # 체크 메서드
    # ──────────────────────────────────────────────────────────────────────

    def check_baseline_violation(
        self, key_set: dict, signals_acc: list[ExceptionCode] | None = None
    ) -> float:
        """체크 ① 임무 모드별 베이스라인 정합성.

        검증:
            1) VOLTAGE의 σ 단위 편차 (3σ 초과 시 점수 상승)
            2) CURR_DELTA_V 절대값의 σ 단위 편차
            3) EXCEED_COUNT / CONSECUTIVE_EXCEED 누적 빈도

        Returns:
            float: 0.0(정상) ~ 1.0(범위 이탈)
        """
        try:
            sw_id = key_set.get("sw_id")
            if sw_id is None:
                if signals_acc is not None:
                    signals_acc.append(ExceptionCode.DATA_MISSING)
                return 0.0

            tlm = self._fetch_tlm_current(key_set)
            mission_mode = tlm.get(config.TLM_COL_MISSION_MODE) if tlm else None
            sigma_scale = config.get_mission_mode_baseline_sigma_scale(mission_mode)
            eff_sigma_threshold = self.sigma_threshold * sigma_scale

            pwr = self._fetch_pwr_meta(key_set, sw_id)
            if pwr is None:
                if signals_acc is not None:
                    signals_acc.append(ExceptionCode.DATA_MISSING)
                return 0.0

            v        = pwr.get("VOLTAGE")
            v_lo     = pwr.get("V_THRESHOLD_LO")
            v_hi     = pwr.get("V_THRESHOLD_HI")
            delta_v  = pwr.get("CURR_DELTA_V")
            exceed   = pwr.get("EXCEED_COUNT", 0)
            consec   = pwr.get("CONSECUTIVE_EXCEED", 0)

            scores = []

            # (1) VOLTAGE σ 편차
            if v is not None and v_lo is not None and v_hi is not None:
                center = (v_hi + v_lo) / 2.0
                sigma  = (v_hi - v_lo) / 6.0   # ±3σ ≈ 정상 범위 가정
                if sigma > 1e-9:
                    sigma_dev = abs(v - center) / sigma
                    if sigma_dev > eff_sigma_threshold:
                        excess = sigma_dev - eff_sigma_threshold
                        scores.append(min(1.0, excess / eff_sigma_threshold))
                    else:
                        scores.append(0.0)

            # (2) CURR_DELTA_V σ 편차 (변화율 기반)
            if delta_v is not None and v_lo is not None and v_hi is not None:
                sigma = (v_hi - v_lo) / 6.0
                if sigma > 1e-9:
                    sigma_dev = abs(delta_v) / sigma
                    if sigma_dev > eff_sigma_threshold:
                        excess = sigma_dev - eff_sigma_threshold
                        scores.append(min(1.0, excess / eff_sigma_threshold))

            # (3) 누적 빈도 (SEU 통계적 독립성 위반)
            if consec is not None and consec > config.CONSECUTIVE_THRESHOLD:
                # 임계치를 크게 상회할수록 점수 상승
                ratio = consec / config.CONSECUTIVE_THRESHOLD
                scores.append(min(1.0, max(0.0, (ratio - 1.0) / 2.0)))

            if exceed is not None and exceed > config.EXCEED_COUNT_THRESHOLD:
                ratio = exceed / config.EXCEED_COUNT_THRESHOLD
                scores.append(min(1.0, max(0.0, (ratio - 1.0) / 3.0)))

            current_a = pwr.get("CURRENT_A")
            if current_a is not None and current_a > config.CURRENT_A_ALERT_THRESHOLD:
                ratio = current_a / config.CURRENT_A_ALERT_THRESHOLD
                scores.append(min(1.0, max(0.0, (ratio - 1.0))))

            if not scores:
                return 0.0
            return sum(scores) / len(scores)

        except Exception as e:
            logger.error(f"check_baseline_violation 실패: {e}")
            return 0.0

    def count_multi_channel_anomaly(
        self, key_set: dict, signals_acc: list[ExceptionCode] | None = None
    ) -> float:
        """체크 ② 다채널 동시 이상.

        검증: 전력 SW_ID 0~3(4채널) 중 동시각(±윈도우) ANOMALY_FLAG=1 채널 수 집계.
        1개=낮음 / 2개=중간 / 3개 이상=단독 1.0 + 예외 코드 4

        Returns:
            float: 동시 이상 채널 수에 따른 점수
        """
        try:
            detected_at = key_set.get("detected_at")
            all_pwr = self._fetch_pwr_meta_all(key_set)
            if not all_pwr:
                if signals_acc is not None:
                    signals_acc.append(ExceptionCode.DATA_MISSING)
                return 0.0

            # 동시각 ± 윈도우 내에서 ANOMALY_FLAG=1인 채널 수 집계
            window_sec = config.MULTI_CHANNEL_TIME_WINDOW_SEC
            count = 0
            for row in all_pwr:
                if row.get("ANOMALY_FLAG") != 1:
                    continue
                if detected_at is None:
                    # detected_at이 없으면 시간 비교 없이 단순 집계
                    count += 1
                    continue
                updated = row.get("UPDATED_AT")
                if updated is None:
                    count += 1
                    continue
                if self._within_time_window(detected_at, updated, window_sec):
                    count += 1

            # 단독 판정: 4채널 중 3개 이상 동시 이상
            if count >= config.MULTI_CHANNEL_STANDALONE_THRESHOLD:
                logger.warning(f"다채널 동시 이상 {count}개 — 단독 1.0")
                if signals_acc is not None:
                    signals_acc.append(ExceptionCode.MULTI_CHANNEL_4PLUS)
                return 1.0

            # 채널 수 기반 점수 매핑
            return config.MULTI_CHANNEL_SCORE_MAP.get(count, 0.0)

        except Exception as e:
            logger.error(f"count_multi_channel_anomaly 실패: {e}")
            return 0.0

    # ──────────────────────────────────────────────────────────────────────
    # 데이터 조회 헬퍼
    # ──────────────────────────────────────────────────────────────────────

    def _fetch_tlm_current(self, key_set: dict) -> dict | None:
        try:
            return db_context.resolve_tlm(key_set, self.db)
        except Exception as e:
            logger.error(f"SAT_TLM_CURRENT 조회 실패: {e}")
            return None

    def _fetch_pwr_meta(self, key_set: dict, sw_id: int) -> dict | None:
        try:
            return db_context.resolve_pwr_meta(key_set, self.db, sw_id)
        except Exception as e:
            logger.error(f"SAT_PWR_META 조회 실패 (sw_id={sw_id}): {e}")
            return None

    def _fetch_pwr_meta_all(self, key_set: dict) -> list[dict]:
        try:
            return db_context.resolve_pwr_meta_all(key_set, self.db)
        except Exception as e:
            logger.error(f"SAT_PWR_META 전체 조회 실패: {e}")
            return []

    # ──────────────────────────────────────────────────────────────────────
    # 시간 비교 유틸
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _within_time_window(t1: Any, t2: Any, window_sec: float) -> bool:
        """t1, t2 사이의 차이가 window_sec 이내인지 (datetime/문자열/숫자 모두 허용)."""
        try:
            from datetime import datetime
            if isinstance(t1, str):
                t1 = datetime.fromisoformat(t1)
            if isinstance(t2, str):
                t2 = datetime.fromisoformat(t2)
            if isinstance(t1, (int, float)) and isinstance(t2, (int, float)):
                return abs(t1 - t2) <= window_sec
            return abs((t1 - t2).total_seconds()) <= window_sec
        except Exception as e:
            logger.error(f"시간 윈도우 비교 실패: {e}")
            return False
