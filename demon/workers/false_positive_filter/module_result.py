"""module_result — analyze() 공통 반환 타입 ModuleResult.

각 모듈은 score(0~1)와 signals( ExceptionCode 튜플 )만 반환.
최종 Y/N·exception_code 병합은 FalsePositiveFilter 전담.
"""

from dataclasses import dataclass
from typing import Tuple

from .exception_codes import ExceptionCode


@dataclass(frozen=True)
class ModuleResult:
    """단일 분석 모듈의 출력.

    Attributes:
        score: 0.0(정합·자연현상에 가까움) ~ 1.0(불일치·공격 의심)
        signals: 해당 모듈이 관측한 단독 신호 목록. 없으면 빈 튜플.
    """

    score: float
    signals: Tuple[ExceptionCode, ...] = ()
