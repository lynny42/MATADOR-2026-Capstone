"""False Positive Filter 패키지 (MATADOR 2026 오탐 필터링).

위치
    AnomalyDetector → **본 패키지** → GScomms → 지상국 MA/UI

구성
    - FalsePositiveFilter: 3모듈 orchestration, Y/N, exception_code 병합
    - PhysicalConsistencyModule: ADCS 물리·토크·QERR (adcs_series 우선)
    - StatisticalConsistencyModule: 전력 베이스라인·다채널(0~4)
    - SystemResponseModule: 로그·명령·카운터 Δ (_prev_state)
    - db_context: key_set 스냅샷 / adcs_series / DBManager 조회
    - config: 모든 상수
    - run_fpf_experiment: Mock·--real-db 표 실험

연동
    AnomalyDetector는 key_set 필수 5키 + 권장 adcs_series(3~5프레임).
    상세: README.md, config.py 주석.
"""
from .false_positive_filter import FalsePositiveFilter
from .physical_consistency_module import PhysicalConsistencyModule
from .statistical_consistency_module import StatisticalConsistencyModule
from .system_response_module import SystemResponseModule
from .exception_codes import ExceptionCode
from .module_result import ModuleResult
from .experiment_db import ExperimentMockDB, try_real_db

__all__ = [
    "FalsePositiveFilter",
    "PhysicalConsistencyModule",
    "StatisticalConsistencyModule",
    "SystemResponseModule",
    "ExceptionCode",
    "ModuleResult",
    "ExperimentMockDB",
    "try_real_db",
]
