"""False Positive Filter 전역 설정 (단일 정본).

역할
    오탐 필터 패키지의 임계치·DB 컬럼명·key_set 키 이름·GS 페이로드 정책을 한곳에서 관리한다.
    모듈 1/2/3·FalsePositiveFilter·db_context는 본 파일만 import 한다 (하드코딩 금지).

팀 합의 (반영 완료)
    - 전력 SW_ID: 0~4 (5채널)
    - SAT_ADCS_FILTER 행 키: key_set["channel1"] (기본 1)
    - 무결성 검증 시각 컬럼: LAST_VERIFIED_AT (FPF·명세 정본)

외부 연동 (앞단 합의 반영)
    - GScomms.insert_event: is_attack, weight, exception_code, WEIGHT, CHENNEL1, MODULE_SCORES
    - AnomalyDetector key_set: adcs_series / tlm_series / channel1 / event_id=0(미할당)
    - DB DDL: SAT_EVENT_QUEUE·SAT_ADCS_FILTER 컬럼명 CHENNEL1(명세 오타) 유지
"""

import logging

from .exception_codes import ExceptionCode

# ──────────────────────────────────────────────────────────────────────────────
# FalsePositiveFilter (메인) 설정
# ──────────────────────────────────────────────────────────────────────────────

# 모듈별 최상위 가중치 (3개 모듈 가중 합산). 운영 중 dict 주입으로 동적 변경 가능.
# 팀 가이드: Physical / Statistical / System 비율
MODULE_WEIGHTS = {
    "physical":    0.5,
    "statistical": 0.3,
    "system":      0.2,
}

# run_pipeline_scenario false_positive (SEU·오탐 실험) 전용 — 종료 후 MODULE_WEIGHTS·seu_experiment_mode 복원
# attack 시나리오는 MODULE_WEIGHTS 유지 + seu_experiment_mode 만 켬 (exc 1~5·바이패스 비활성)
# system 가중치를 올려 전력 이상만 있고 ADCS/시스템 반응이 정상인 SEU 케이스에서 N 유도
FALSE_POSITIVE_SCENARIO_MODULE_WEIGHTS = {
    "physical":    0.20,
    "statistical": 0.25,
    "system":      0.55,
}

# 최종 Y/N 판정 임계치 (weighted_score >= threshold → "Y")
CONFIDENCE_THRESHOLD = 0.5

# GScomms.insert_event(payload) 계약 — demon/workers/gs_comms.py 와 동기화
# 필수: is_attack "Y"|"N", weight int 1~100, exception_code int, key_set, detected_at
# weighted_score(float)는 FPF 내부만; GScomms가 EVENT_TYPE/PRIORITY/WEIGHT/CHENNEL1 매핑
GS_INSERT_EVENT_INCLUDE_MODULE_SCORES = True

# 실험 시 모듈별 점수·Y/N 상세 로그
LOG_EXPERIMENT_DETAIL = True
# 데몬 운용 시 판정 요약(공격 확정 / SEU) — LOG_EXPERIMENT_DETAIL 과 무관하게 항상 출력
FPF_LOG_VERDICT_ALWAYS = True

# key_set 내 DB 스냅샷 주입 (실험·AnomalyDetector 직전 프레임 전달)
KEY_SNAPSHOTS = "_snapshots"

# 내부 연산은 float 0.0~1.0 유지. GScomms로 나가는 정수 weight는 send 직전에만
# weighted_score_to_gs_int()로 산출한다 (가이드: max(1, min(100, round(score*100)))).
GS_WEIGHT_INT_MIN = 1
GS_WEIGHT_INT_MAX = 100

# 여러 모듈에서 신호가 동시에 올 때 result["exception_code"]에 쓸 단일 코드 선택 순서
# (앞에 올수록 우선). exception_codes.ExceptionCode와 동기화 유지.
# DATA_MISSING(5)은 최우선 — 어느 모듈에서든 한 번 감지되면 최종 코드 5로 고정.
EXCEPTION_CODE_RESOLUTION_PRIORITY = (
    ExceptionCode.DATA_MISSING,
    ExceptionCode.MULTI_CHANNEL_4PLUS,
    ExceptionCode.UNIT_QUATERNION_VIOLATION,
    ExceptionCode.TORQUE_AMPLIFICATION,
    ExceptionCode.WHEEL_DISABLED_BUT_COMMANDED,
    ExceptionCode.UNAUTHORIZED_MODE_CHANGE,
    ExceptionCode.UNAUTHORIZED_ROUTE_ENABLED,
    ExceptionCode.NORMAL,
)

# 단독 강한 신호: 예외 코드 1~4만 가중 합산과 무관하게 weighted_score=1.0, is_attack=Y
# (6·7 등은 모듈 점수·일반 가중합으로 반영)
EXCEPTION_CODES_BYPASS_WEIGHTED_SUM = frozenset(
    {
        ExceptionCode.UNIT_QUATERNION_VIOLATION,
        ExceptionCode.TORQUE_AMPLIFICATION,
        ExceptionCode.WHEEL_DISABLED_BUT_COMMANDED,
        ExceptionCode.MULTI_CHANNEL_4PLUS,
    }
)

# run_pipeline_scenario attack / false_positive: GS·터미널에 exc 1~5 미표시, 가중합만으로 Y/N
EXCEPTION_CODES_SUPPRESS_FOR_DEMO = frozenset(
    {
        ExceptionCode.UNIT_QUATERNION_VIOLATION,
        ExceptionCode.TORQUE_AMPLIFICATION,
        ExceptionCode.WHEEL_DISABLED_BUT_COMMANDED,
        ExceptionCode.MULTI_CHANNEL_4PLUS,
        ExceptionCode.DATA_MISSING,
    }
)

# 모듈 출력에 이 신호가 있으면 해당 모듈 점수는 가중 합산에서 제외(가중치 재정규화)
EXCEPTION_CODES_EXCLUDE_MODULE_FROM_WEIGHTED_SUM = frozenset({ExceptionCode.DATA_MISSING})


# ──────────────────────────────────────────────────────────────────────────────
# PhysicalConsistencyModule (모듈 1) 설정
# ──────────────────────────────────────────────────────────────────────────────
# 실험 시 변경해도 되는 임시값 ← grep으로 질문10·튜닝용 임계치 일괄 검색

# 모듈 1 내부 체크 가중치 (sub_weights) — 가이드: CP:SP:STC = 0.5:0.3:0.2
PHYSICAL_SUB_WEIGHTS = {
    "command_outcome":      0.5,   # CP 명령 결과
    "attitude_consistency": 0.3,   # SP 센서·자세
    "mode_behavior":        0.2,   # STC 모드 거동
}

# 사원수 각도 차이 임계치 (rad, 약 5도)
QUATERNION_ANGLE_THRESHOLD_RAD = 0.0872665  # 실험 시 변경해도 되는 임시값

# 단위 사원수 조건 허용 오차 (|q0² + q1² + q2² + q3² - 1| <= 이 값이면 정상)
UNIT_QUATERNION_TOLERANCE = 0.05

# 토크 명령 vs 각속도 변화율 허용 비율 (±20%)
TORQUE_OUTCOME_TOLERANCE = 0.20  # 실험 시 변경해도 되는 임시값

# 토크 명령 대비 각속도 변화율 단독 판정 임계치 (200% 이상 → 단독 1.0)
TORQUE_AMPLIFICATION_THRESHOLD = 2.00  # 실험 시 변경해도 되는 임시값

# 모드 전환 직후 패턴 검증 시간 윈도우 (DT의 배수)
MODE_TRANSITION_WINDOW_MULTIPLIER = 5

# 제어 오차·지향 오차 (단발 + 시계열 수렴)
QERR_VEC_NORM_THRESHOLD = 0.05
QERR_CONVERGED_NORM_SQ = 0.002   # q1²+q2²+q3² 이하면 “수렴”
QERR_DIVERGE_RATIO = 1.2         # 마지막/첫 샘플 비율 초과 시 발산 의심
WERR_MAG_THRESHOLD = 0.01
THERR_MAG_THRESHOLD = 0.05
CMD_WBN_POINTING_MAX = 0.01

# B-dot 대비 토크 크기 비율 허용 편차 (DETUMBLING)
BDOT_TCMD_RATIO_TOLERANCE = 0.5

# IMU 적분 vs 사원수 변화 불일치 임계 (rad/s)
IMU_QUAT_INCONSISTENCY_THRESHOLD = 0.15

# 전류 이상 단발 (A) — 베이스라인 σ 근사용
CURRENT_A_ALERT_THRESHOLD = 2.0


# ──────────────────────────────────────────────────────────────────────────────
# StatisticalConsistencyModule (모듈 2) 설정
# ──────────────────────────────────────────────────────────────────────────────

# 모듈 2 내부 체크 가중치 — 가이드: 베이스라인 s1 : 다채널 s2 = 0.6 : 0.4
STATISTICAL_SUB_WEIGHTS = {
    "baseline_violation":     0.6,
    "multi_channel_anomaly":  0.4,
}

# 베이스라인 σ 단위 임계치
SIGMA_THRESHOLD = 3.0  # 실험 시 변경해도 되는 임시값

# 다채널 동시 이상 판정 윈도우 (초)
MULTI_CHANNEL_TIME_WINDOW_SEC = 3.0  # 실험 시 변경해도 되는 임시값

# 다채널 동시 이상 채널 수에 따른 점수
# 1개=낮음 / 2개=중간 / 3개 이상=단독 1.0
MULTI_CHANNEL_SCORE_MAP = {
    1: 0.1,
    2: 0.6,
}
MULTI_CHANNEL_STANDALONE_THRESHOLD = 4   # 이 값 이상이면 단독 1.0 (SW 0~4, 5채널 중 4+ 동시 이상)

# ──────────────────────────────────────────────────────────────────────────────
# 전력 SW_ID / 아두이노 스위치 (DB 명세 SAT_PWR_META.SW_ID, 팀 하드 기준)
# ──────────────────────────────────────────────────────────────────────────────
# 팀 합의: SW_ID 0~4 (5채널). (전력 SW_ID ≠ SAT_ADCS_FILTER 행 키 channel1.)
PWR_SW_ID_MIN = 0
PWR_SW_ID_MAX = 4
PWR_SW_ID_ADCS = 1
TOTAL_PWR_CHANNELS = PWR_SW_ID_MAX - PWR_SW_ID_MIN + 1  # 5

V_THRESHOLD_LO = [3.0, 3.0, 4.5, 3.0, 3.0]
V_THRESHOLD_HI = [3.6, 3.6, 5.5, 3.6, 3.6]

# ──────────────────────────────────────────────────────────────────────────────
# SAT_ADCS_FILTER 행 키 — DB 명세의 channel1 / CHANNEL1 (ADCS 연결 행)
# ──────────────────────────────────────────────────────────────────────────────
# AnomalyDetector→FalsePositiveFilter key_set 키 이름. NOS3 MISSION_MODE·전력 SW_ID와 별개.
KEY_CHANNEL1 = "channel1"
KEY_CHENNEL1_DB = "CHENNEL1"  # SAT_ADCS_FILTER·SAT_EVENT_QUEUE DB 컬럼(명세 표기)
CHANNEL1_DEFAULT = 1

# AnomalyDetector → key_set (B안 시계열)
KEY_EVENT_ID = "event_id"
EVENT_ID_UNASSIGNED = 0  # FPF→GScomms INSERT 후 실제 EVENT_ID로 갱신
KEY_ADCS_SERIES = "adcs_series"
KEY_TLM_SERIES = "tlm_series"
KEY_SW_ID_LIST = "sw_id_list"
MIN_SAMPLES_FOR_DELTA = 2
MIN_SAMPLES_FOR_CONVERGENCE = 3
ADCS_SERIES_MAX_LEN = 5

# AnomalyDetector 측에서 사용하는 누적 임계치 (참조용 — 모듈 2의 EXCEED_COUNT 검증)
EXCEED_COUNT_THRESHOLD = 3
CONSECUTIVE_THRESHOLD = 3


# ──────────────────────────────────────────────────────────────────────────────
# SystemResponseModule (모듈 3) 설정
# ──────────────────────────────────────────────────────────────────────────────

# 모듈 3 내부 체크 가중치 — 가이드: 명령 이력 : 로그 동반 : 카운터 = 0.45 : 0.30 : 0.25
SYSTEM_SUB_WEIGHTS = {
    "command_history":         0.45,
    "log_concordance":         0.30,
    "counter_synchronization": 0.25,
}

# 시계열 비교 윈도우 (초) — "변경 직전/직후" 대조용
SYSTEM_TIMESERIES_WINDOW_SEC = 30.0

# 카운터 비율 정합성 허용 편차 (예: 평소 비율 대비 ±50% 벗어나면 비정합)
COUNTER_RATIO_TOLERANCE = 0.5

# CMDREJECTEDCOUNTER 급증 판정 임계치 (단위 시간당 증가량)
CMD_REJECT_SURGE_THRESHOLD = 5  # 실험 시 변경해도 되는 임시값

# APPCSERRCOUNTER + OSCSERRCOUNTER 합이 이 값을 넘기면 “심각” 구간으로 간주 (질문11)
CRITICAL_CHECKSUM_ERR_THRESHOLD = 3  # 실험 시 변경해도 되는 임시값

# LASTVALCRC 변화 후 SAT_INTEGRITY_HASH.LAST_VERIFIED_AT이 이 시간(초) 안에 갱신됐는지
INTEGRITY_VERIFICATION_RECENCY_SEC = 60.0

# 카운터 급증·대량 패킷 전송 등 단순 휴리스틱
PIPE_OVERFLOW_SURGE_DELTA = 5
SKIPPED_SLOTS_SURGE_DELTA = 5

# 패킷 급증 + forward_err=0 (Ghost/재전송 의심). 1초 수집·시뮬 기준(정상 Δ≈0~10).
HIGH_PACKET_DELTA_THRESHOLD = 12
SUSPICIOUS_PACKET_FLOW_SCORE = 0.75


# ──────────────────────────────────────────────────────────────────────────────
# DB 컬럼명 — DB 명세.pdf 정본 (설계 PDF의 OBC_P_HASH, EXPECTED_CRC 등과 혼동 금지)
# ──────────────────────────────────────────────────────────────────────────────

# SAT_INTEGRITY_HASH — “현재 해시” 컬럼 없음. 기대값은 EXPECTED_HASH, 변조 플래그는 IS_VIOLATED.
INTEGRITY_HASH_COL_FILE_ID = "FILE_ID"
INTEGRITY_HASH_COL_FILE_PATH = "FILE_PATH"
INTEGRITY_HASH_COL_EXPECTED_HASH = "EXPECTED_HASH"
INTEGRITY_HASH_COL_IS_VIOLATED = "IS_VIOLATED"
INTEGRITY_HASH_COL_LAST_VERIFIED_AT = "LAST_VERIFIED_AT"
INTEGRITY_HASH_COL_UPDATED_AT = "UPDATED_AT"

# SAT_TLM_CURRENT — 모듈 1·2·3
TLM_COL_OBC_S_TICK = "OBC_S_TICK"
# NOS3·위성체 임무 모드 (Diagnostic / Safe / Science). SAT_ADCS_FILTER channel1 과 무관.
TLM_COL_MISSION_MODE = "MISSION_MODE"
# 비행 ADCS 소프트웨어 자세/제어 모드 정수(SUNSAFE 등). DB 컬럼명 그대로 — channel1 행 키와 무관.
TLM_COL_ADCS_MODE = "ADCS_MODE"

# SC_HKTLM → SAT_TLM_CURRENT.MISSION_MODE 정수 (NOS3, 팀 UDPReceiver / 클래스 명세와 동일)
MISSION_MODE_DIAGNOSTIC = 0
MISSION_MODE_SAFE = 1
MISSION_MODE_SCIENCE = 2

# 임무 모드별 베이스라인(σ) 민감도 배율. 1.0 = SIGMA_THRESHOLD와 동일 동작.
# 운영 데이터로 튜닝; 미등록 정수 코드는 get_mission_mode_baseline_sigma_scale()에서 1.0 처리.
MISSION_MODE_BASELINE_SIGMA_SCALE = {
    MISSION_MODE_DIAGNOSTIC: 1.0,
    MISSION_MODE_SAFE: 1.0,
    MISSION_MODE_SCIENCE: 1.0,
}

# SAT_TLM_CURRENT.ADCS_MODE 정수 — 비행 ADCS SW 자세/제어 모드 (SUNSAFE 등). DB 명세 코드표 기준.
# (key_set channel1 / SAT_ADCS_FILTER 행 키와 다른 개념.)
ADCS_MODE_SUNSAFE = 0
ADCS_MODE_POINTING = 1
ADCS_MODE_DETUMBLING = 2

# SAT_ADCS_FILTER — 통신·CRC·카운터 (명세상 SAT_EVENT_QUEUE가 아님)
ADCS_FILTER_COL_CMDCOUNTER = "CMDCOUNTER"
ADCS_FILTER_COL_COMBINEDPACKETSSENT = "COMBINEDPACKETSSENT"
ADCS_FILTER_COL_SYSLOGENTRIES = "SYSLOGENTRIES"
ADCS_FILTER_COL_RESETSPERFORMED = "RESETSPERFORMED"
ADCS_FILTER_COL_ERLOGENTRIES = "ERLOGENTRIES"
ADCS_FILTER_COL_LASTVALCRC = "LASTVALCRC"
ADCS_FILTER_COL_ENABLEDROUTES = "ENABLEDROUTES"
ADCS_FILTER_COL_FORWARD_ERR_COUNT = "FORWARD_ERR_COUNT"
ADCS_FILTER_COL_SKIPPEDSLOTSCOUNT = "SKIPPEDSLOTSCOUNT"
ADCS_FILTER_COL_EXECOUNTS = "EXECOUNTS"
ADCS_FILTER_COL_APPCSERRCOUNTER = "APPCSERRCOUNTER"
ADCS_FILTER_COL_OSCSERRCOUNTER = "OSCSERRCOUNTER"

# SAT_EVENT_QUEUE — 모듈 3에서 참조하는 컬럼 (DB 명세.pdf)
EVENT_QUEUE_COL_PROCESSOR_RESET_COUNT = "PROCESSOR_RESET_COUNT"
EVENT_QUEUE_COL_CMDREJECTEDCOUNTER = "CMDREJECTEDCOUNTER"
EVENT_QUEUE_COL_PIPEOVERFLOWRRCNT = "PIPEOVERFLOWRRCNT"

# _prev_state 갱신 시 순회용 (문자열 리터럴 중복 방지)
SYSTEM_MODULE_ADCS_CACHE_KEYS = (
    ADCS_FILTER_COL_SYSLOGENTRIES,
    ADCS_FILTER_COL_COMBINEDPACKETSSENT,
    ADCS_FILTER_COL_ERLOGENTRIES,
    ADCS_FILTER_COL_APPCSERRCOUNTER,
    ADCS_FILTER_COL_OSCSERRCOUNTER,
    ADCS_FILTER_COL_RESETSPERFORMED,
    ADCS_FILTER_COL_SKIPPEDSLOTSCOUNT,
    ADCS_FILTER_COL_ENABLEDROUTES,
    ADCS_FILTER_COL_CMDCOUNTER,
    ADCS_FILTER_COL_LASTVALCRC,
    ADCS_FILTER_COL_FORWARD_ERR_COUNT,
)
SYSTEM_MODULE_EVENT_CACHE_KEYS = (
    EVENT_QUEUE_COL_PROCESSOR_RESET_COUNT,
    EVENT_QUEUE_COL_CMDREJECTEDCOUNTER,
    EVENT_QUEUE_COL_PIPEOVERFLOWRRCNT,
)


# ──────────────────────────────────────────────────────────────────────────────
# 데이터 누락 처리
# ──────────────────────────────────────────────────────────────────────────────

# 모듈 내 체크 누락 비율이 이 값 이상이면 예외 코드 5 (DATA_MISSING) 후보.
# 질문12: “체크 절반 이상 누락” → 비율 0.5. 런타임은 모듈별 signals와 병행해 해석.
DATA_MISSING_RATIO_THRESHOLD = 0.5  # 실험 시 변경해도 되는 임시값


def get_mission_mode_baseline_sigma_scale(mission_mode):
    """MISSION_MODE별 베이스라인 σ 임계 배율. None·미등록 코드는 1.0.

    StatisticalConsistencyModule이 SIGMA_THRESHOLD에 곱해 모드별 민감도를 분기한다.
    """
    if mission_mode is None:
        return 1.0
    try:
        key = int(mission_mode)
    except (TypeError, ValueError):
        return 1.0
    return float(MISSION_MODE_BASELINE_SIGMA_SCALE.get(key, 1.0))


# ──────────────────────────────────────────────────────────────────────────────
# 로깅
# ──────────────────────────────────────────────────────────────────────────────

LOGGER_NAME = "false_positive_filter"

_logger = logging.getLogger(LOGGER_NAME)


def weighted_score_to_gs_int(final_score: float) -> int:
    """내부 최종 점수(0.0~1.0) → GScomms 전송용 정수 weight(1~100).

    공식: max(GS_WEIGHT_INT_MIN, min(GS_WEIGHT_INT_MAX, round(final_score * GS_WEIGHT_INT_MAX)))
    """
    try:
        s = float(final_score)
        return max(
            GS_WEIGHT_INT_MIN,
            min(GS_WEIGHT_INT_MAX, round(s * GS_WEIGHT_INT_MAX)),
        )
    except (TypeError, ValueError) as e:
        _logger.error(f"weighted_score_to_gs_int 타입/값 오류: {e}")
        return GS_WEIGHT_INT_MIN
    except Exception as e:
        _logger.error(f"weighted_score_to_gs_int 실패: {e}")
        return GS_WEIGHT_INT_MIN
