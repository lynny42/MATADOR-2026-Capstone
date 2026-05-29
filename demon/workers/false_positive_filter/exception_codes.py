"""exception_codes — FPF 예외·단독 신호 정수 코드.

FalsePositiveFilter.check_exception / make_final_decision / GScomms.exception_code 에 사용.
1~4: 가중합 바이패스(weighted_score=1.0, Y). 5: DATA_MISSING(해당 모듈 가중 제외).
config.EXCEPTION_CODE_RESOLUTION_PRIORITY 와 동기화 유지.
"""

from enum import IntEnum


class ExceptionCode(IntEnum):
    """오탐 필터링 단독 강한 신호 / 예외 상황 코드."""

    NORMAL = 0
    """정상 — 단독 강한 신호 없음, 가중 합산 결과를 그대로 사용."""

    UNIT_QUATERNION_VIOLATION = 1
    """모듈 1: VALID 플래그 1인데 단위 사원수 조건 깨짐 — 명백한 변조."""

    TORQUE_AMPLIFICATION = 2
    """모듈 1: 토크 명령 대비 각속도 변화율 200% 이상 — 공격 1 토크 증폭."""

    WHEEL_DISABLED_BUT_COMMANDED = 3
    """모듈 1: 휠 비활성 상태에서 모멘텀 명령 발행 — 휠 무력화 공격 의심."""

    MULTI_CHANNEL_4PLUS = 4
    """모듈 2: 전력 4채널(SW_ID 0~3) 중 3개 이상 동시 ANOMALY_FLAG=1 — 자연 SEU로 설명 불가."""

    DATA_MISSING = 5
    """모든 모듈 공통: 핵심 컬럼 NULL 또는 행 부재로 분석 불가."""

    UNAUTHORIZED_MODE_CHANGE = 6
    """모듈 3: 명령 이력 없는 ADCS_MODE 변경 — 공격 직접 변경."""

    UNAUTHORIZED_ROUTE_ENABLED = 7
    """모듈 3: 정당한 명령 없이 ENABLEDROUTES 증가 — 공격 2 데이터 유출 채널."""
