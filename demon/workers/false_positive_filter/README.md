# false_positive_filter (오탐 필터)

위성체 파이프라인: `AnomalyDetector` → **FalsePositiveFilter** → `GScomms` → (지상국) MA 통합 탐지.

## 실행 (로컬 실험)

```bash
cd <repo_root>
py -m false_positive_filter.run_fpf_experiment
py -m false_positive_filter.run_fpf_experiment --real-db
```

## AnomalyDetector가 넣어야 하는 key_set

```python
{
    "tlm_id": 1,
    "sw_id": 0,              # 0~4, 이상 난 전력 스위치
    "channel1": 1,           # SAT_ADCS_FILTER 행 (ADCS=1)
    "event_id": 123,
    "detected_at": "2026-05-12T12:00:00Z",
    "sw_id_list": [0, 1],    # 선택: 동시 이상 SW 목록
    "adcs_series": [...],    # 권장: 최근 3~5프레임 (오래된→최신)
    "tlm_series": [...],     # 선택
}
```

## 시계열 정책

| 우선순위 | 방식 |
|----------|------|
| 1 | `key_set["adcs_series"]` (B안, AnomalyDetector 링버퍼) |
| 2 | FPF `_prev_state` (A안, 동일 프로세스 연속 호출) |
| 3 | (2차) DB `get_adcs_filter_range` — HISTORY 테이블 합의 후 |

## 설정

모든 임계치·컬럼명: `config.py` (하드코딩 금지).

## GitHub

저장소: `MATADOR-2026-Capstone` (팀 브랜치 예: `feat/false-positive-filter`).
