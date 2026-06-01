"""FalsePositiveFilter — 오탐 필터 메인 컨트롤러.

입력
    on_anomaly_detected(key_set): AnomalyDetector가 넘긴 DB PK·시각·(권장) adcs_series.

처리
    1) physical / statistical / system → ModuleResult(score, signals)
    2) check_exception: 단일 exception_code (DATA_MISSING 최우선, 1~4 바이패스)
    3) make_final_decision: 가중 합산 → is_attack Y/N, weighted_score 0~1

출력
    run_false_positive_filter → 내부 dict (weight 없음)
    send_to_gscomms → GScomms.insert_event(payload + weight int 1~100)

의존성 주입
    생성 시 3모듈 + gs_comms 인스턴스를 받는다 (main/AnomalyDetector에서 조립).
"""

import logging
from typing import Any

from . import config
from .exception_codes import ExceptionCode
from .module_result import ModuleResult

logger = logging.getLogger(config.LOGGER_NAME)


class FalsePositiveFilter:
    """오탐 필터링 메인 컨트롤러.

    Attributes:
        weights (dict): 모듈별 최상위 가중치
        physical: PhysicalConsistencyModule 인스턴스
        statistical: StatisticalConsistencyModule 인스턴스
        system: SystemResponseModule 인스턴스
        confidence_threshold (float): Y/N 판정 임계치
        gs_comms: GScomms 인스턴스
    """

    def __init__(
        self,
        physical: Any,
        statistical: Any,
        system: Any,
        gs_comms: Any,
        weights: dict | None = None,
        confidence_threshold: float | None = None,
    ):
        """모듈/통신 인스턴스를 외부에서 주입받는다 (의존성 주입).

        Args:
            physical: 모듈 1 인스턴스 (analyze(key_set) -> ModuleResult)
            statistical: 모듈 2 인스턴스 (동일)
            system: 모듈 3 인스턴스 (동일)
            gs_comms: GScomms 인스턴스 (insert_event(result) 메서드 보유)
            weights: 모듈별 가중치. None이면 config.MODULE_WEIGHTS 사용
            confidence_threshold: Y/N 판정 임계치. None이면 config 값 사용
        """
        self.physical = physical
        self.statistical = statistical
        self.system = system
        self.gs_comms = gs_comms
        self.weights = weights if weights is not None else dict(config.MODULE_WEIGHTS)
        self.confidence_threshold = (
            confidence_threshold
            if confidence_threshold is not None
            else config.CONFIDENCE_THRESHOLD
        )
        # run_pipeline_scenario attack/false_positive: exc 1~5 비표시, score=1.0 바이패스 없이 가중합만
        self.seu_experiment_mode = False

    # ──────────────────────────────────────────────────────────────────────
    # public
    # ──────────────────────────────────────────────────────────────────────

    def on_anomaly_detected(self, key_set: dict) -> None:
        """AnomalyDetector로부터 이상 데이터셋 수신 → 분석 → 전송.

        Args:
            key_set: 필수 tlm_id=1, sw_id(0~4), channel1(=1), event_id, detected_at(ISO UTC).
                     권장 adcs_series(3~5 dict), 선택 tlm_series, sw_id_list, _snapshots.
                     상세: false_positive_filter/README.md
        """
        try:
            result = self.run_false_positive_filter(key_set)
            self.send_to_gscomms(result)
        except Exception as e:
            logger.error(f"on_anomaly_detected 실패: {e}")
            return None

    def run_false_positive_filter(self, key_set: dict) -> dict:
        """3개 모듈 순차 실행 + 예외 검사 + 최종 결정.

        Args:
            key_set: DB 조회용 기본키 집합

        Returns:
            dict: 최종 판정 결과 (내부용, float만)
                {is_attack, weighted_score, module_scores, exception_code, key_set, detected_at}
                GScomms 정수 weight는 send_to_gscomms() 직전에만 부여한다.
                insert_event에는 기본적으로 module_scores 미포함(config 참고).
        """
        # 1) 3개 모듈 순차 실행 → ModuleResult(score, signals)
        module_results: dict[str, ModuleResult] = {}
        for name, mod in (
            ("physical", self.physical),
            ("statistical", self.statistical),
            ("system", self.system),
        ):
            try:
                module_results[name] = mod.analyze(key_set)
            except Exception as e:
                logger.error(f"모듈 analyze 실행 실패 ({name}): {e}")
                module_results[name] = ModuleResult(0.0, ())

        # 2) 예외 코드 병합 (모든 모듈 신호 수집 후 단일 코드)
        exception_code = self.check_exception(module_results)

        # 3) 최종 판정 (바이패스 / DATA_MISSING 모듈 제외 가중합)
        decision = self.make_final_decision(module_results, exception_code)

        # 4) 결과 dict 조립 (내부 연산은 전부 float; weight 미포함)
        result = {
            "is_attack":      decision["is_attack"],
            "weighted_score": decision["weighted_score"],
            "module_scores":  decision["module_scores"],
            "exception_code": int(exception_code),
            "key_set":        key_set,
            "detected_at":    key_set.get("detected_at"),
        }

        weight_int = config.weighted_score_to_gs_int(result["weighted_score"])
        if config.LOG_EXPERIMENT_DETAIL:
            ms = result.get("module_scores", {})
            logger.info(
                "오탐 필터링 | Y/N=%s | score=%.3f | weight=%d | exc=%d | "
                "physical=%.3f statistical=%.3f system=%.3f",
                result["is_attack"],
                result["weighted_score"],
                weight_int,
                result["exception_code"],
                ms.get("physical", 0.0),
                ms.get("statistical", 0.0),
                ms.get("system", 0.0),
            )
        else:
            logger.info(
                f"오탐 필터링 결과: is_attack={result['is_attack']}, "
                f"weighted_score={result['weighted_score']:.3f}, "
                f"exception_code={result['exception_code']}"
            )
        return result

    def send_to_gscomms(self, result: dict) -> bool:
        """최종 결과를 GScomms로 전달.

        weighted_score(0.0~1.0) → 정수 weight(1~100) 변환은 본 메서드에서만 수행한다.

        Args:
            result: run_false_positive_filter()의 반환 dict (weight 키 없음)

        Returns:
            bool: 전달 성공 여부
        """
        try:
            weight = config.weighted_score_to_gs_int(result.get("weighted_score", 0.0))
            payload = dict(result)
            payload["weight"] = weight
            key_set = payload.get("key_set")
            if isinstance(key_set, dict):
                ch1 = key_set.get(config.KEY_CHANNEL1, config.CHANNEL1_DEFAULT)
                key_set.setdefault(config.KEY_CHENNEL1_DB, ch1)
            if not config.GS_INSERT_EVENT_INCLUDE_MODULE_SCORES:
                payload.pop("module_scores", None)
            event_id = self.gs_comms.insert_event(payload)
            if event_id < 0:
                return False
            if isinstance(key_set, dict):
                key_set[config.KEY_EVENT_ID] = event_id
            return True
        except AttributeError as e:
            logger.error(f"GScomms 인터페이스 오류: {e}")
            return False
        except Exception as e:
            logger.error(f"GScomms 전송 실패: {e}")
            return False

    # ──────────────────────────────────────────────────────────────────────
    # private
    # ──────────────────────────────────────────────────────────────────────

    def make_final_decision(
        self, module_results: dict[str, ModuleResult], exception_code: ExceptionCode
    ) -> dict:
        """모듈 점수에 가중치 적용 → Y/N 판정.

        - DATA_MISSING(코드 5)이 어느 모듈에서든 한 번이라도 감지되면 우선순위에 의해
          exception_code가 5로 고정되며, BYPASS 분기는 자동으로 스킵된다. DATA_MISSING
          신호를 가진 모듈만 가중 합산에서 제외하고 남은 모듈 가중치를 재정규화한다.
        - DATA_MISSING이 없고 병합된 exception_code가 EXCEPTION_CODES_BYPASS_WEIGHTED_SUM
          (코드 1~4)에 있으면 가중 합산을 건너뛰고 weighted_score=1.0, is_attack=\"Y\".

        Args:
            module_results: 모듈명 → ModuleResult
            exception_code: check_exception()에서 병합된 단일 코드

        Returns:
            dict: {is_attack: \"Y\"|\"N\", weighted_score: float, module_scores: dict}
        """
        try:
            scores_float = {k: v.score for k, v in module_results.items()}

            if (
                not self.seu_experiment_mode
                and exception_code in config.EXCEPTION_CODES_BYPASS_WEIGHTED_SUM
            ):
                return {
                    "is_attack": "Y",
                    "weighted_score": 1.0,
                    "module_scores": scores_float,
                }

            effective: list[str] = []
            for name in ("physical", "statistical", "system"):
                mr = module_results.get(name)
                if mr is None:
                    continue
                skip = any(
                    sig in config.EXCEPTION_CODES_EXCLUDE_MODULE_FROM_WEIGHTED_SUM
                    for sig in mr.signals
                )
                if not skip:
                    effective.append(name)

            if not effective:
                return {
                    "is_attack": "N",
                    "weighted_score": 0.0,
                    "module_scores": scores_float,
                }

            total_w = sum(self.weights.get(n, 0.0) for n in effective)
            if total_w <= 0.0:
                return {
                    "is_attack": "N",
                    "weighted_score": 0.0,
                    "module_scores": scores_float,
                }

            weighted_score = sum(
                (self.weights.get(n, 0.0) / total_w) * module_results[n].score
                for n in effective
            )
            weighted_score = max(0.0, min(1.0, weighted_score))
            is_attack = "Y" if weighted_score >= self.confidence_threshold else "N"
            return {
                "is_attack": is_attack,
                "weighted_score": weighted_score,
                "module_scores": scores_float,
            }
        except Exception as e:
            logger.error(f"make_final_decision 실패: {e}")
            return {
                "is_attack": "N",
                "weighted_score": 0.0,
                "module_scores": {k: v.score for k, v in module_results.items()},
            }

    def check_exception(self, module_results: dict[str, ModuleResult]) -> ExceptionCode:
        """모든 모듈이 수집한 signals를 병합 후 config 우선순위로 단일 코드 선택.

        Args:
            module_results: 모듈명 → ModuleResult

        Returns:
            ExceptionCode
        """
        try:
            merged: list[ExceptionCode] = []
            for mr in module_results.values():
                merged.extend(mr.signals)

            if self.seu_experiment_mode:
                merged = [
                    code
                    for code in merged
                    if code not in config.EXCEPTION_CODES_SUPPRESS_FOR_DEMO
                ]

            for code in config.EXCEPTION_CODE_RESOLUTION_PRIORITY:
                if code != ExceptionCode.NORMAL and code in merged:
                    return code
            return ExceptionCode.NORMAL
        except Exception as e:
            logger.error(f"check_exception 실패: {e}")
            return ExceptionCode.NORMAL
