"""SystemResponseModule (모듈 3) — 시스템 반응·카운터 정합성.

검증
    - check_log_concordance: 체크섬 에러 ↔ ERLOG / 무결성 LAST_VERIFIED_AT
    - verify_command_history: ADCS_MODE·ENABLEDROUTES ↔ CMDCOUNTER
    - check_counter_synchronization: OBC_S_TICK 대비 카운터 Δ (패킷·로그·PIPE 등)

시계열 1차: 동일 인스턴스 self._prev_state (직전 호출 대비 Δ).
    adcs_series는 모듈1·2가 우선 사용; 모듈3은 현 구조 유지.

조회 테이블·컬럼은 **DB 명세.pdf** 정본이다 (설계 PDF와 불일치 시 명세 우선).

SAT_TLM_CURRENT (발췌, 모듈 3 사용분)
    MISSION_MODE, OBC_S_TICK, ADCS_MODE

SAT_ADCS_FILTER
    CMDCOUNTER, COMBINEDPACKETSSENT, SYSLOGENTRIES, RESETSPERFORMED,
    ERLOGENTRIES, APPCSERRCOUNTER, OSCSERRCOUNTER, LASTVALCRC, ENABLEDROUTES,
    FORWARD_ERR_COUNT, SKIPPEDSLOTSCOUNT, EXECOUNTS
    위 카운터·통신 필드는 명세상 **본 테이블**에 있으며 SAT_EVENT_QUEUE에 없다.

SAT_EVENT_QUEUE (명세)
    EVENT_ID, DETECTED_AT, PIPEOVERFLOWRRCNT, CHILDQUEUECOUNT,
    FILEWRITEERRCOUNTER, CMDREJECTEDCOUNTER, CH1/2_FAULT_CRC,
    CH1_FAULT_FILE_SIZE_MISMATCH, PROCESSOR_RESET_COUNT, IS_SENT, TIMESTAMP,
    PRIORITY, EVENT_TYPE

SAT_INTEGRITY_HASH (명세)
    FILE_ID, FILE_PATH, EXPECTED_HASH, IS_VIOLATED, LAST_VERIFIED_AT, UPDATED_AT
    설계 PDF의 OBC_P_HASH(현재 해시)·EXPECTED_CRC 명칭은 명세에 없다.
    기대 해시는 EXPECTED_HASH. 런타임 CRC 스냅샷은 SAT_ADCS_FILTER.LASTVALCRC이며
    문자열 EXPECTED_HASH와 동일 비교용이 아니다(역할 분리). 교차 검증은
    LASTVALCRC 변화 대비 LAST_VERIFIED_AT 갱신 여부 등으로만 본다.
"""

import logging
from typing import Any

from . import config
from . import db_context
from .exception_codes import ExceptionCode
from .module_result import ModuleResult

logger = logging.getLogger(config.LOGGER_NAME)

_SYSTEM_FORCE_SCORE_ONE = frozenset(
    {
        ExceptionCode.UNAUTHORIZED_MODE_CHANGE,
        ExceptionCode.UNAUTHORIZED_ROUTE_ENABLED,
    }
)


class SystemResponseModule:
    """시스템 반응 정합성 분석 모듈."""

    def __init__(self, db_manager: Any, sub_weights: dict | None = None):
        """
        Args:
            db_manager: DBManager 인스턴스. 다음 메서드 필요:
                - get_tlm_current() -> dict
                - get_adcs_filter(channel1: int) -> dict
                - get_event(event_id: int) -> dict
                - get_integrity_hash(file_id: int = None) -> dict | list[dict]
                - (선택) get_adcs_filter_range(channel1, start, end) -> list[dict]
                - (선택) get_events_range(start, end) -> list[dict]
            sub_weights: 체크별 가중치
        """
        self.db = db_manager
        self.sub_weights = (
            sub_weights
            if sub_weights is not None
            else dict(config.SYSTEM_SUB_WEIGHTS)
        )

        # 시계열 비교용 이전 값 캐시
        # 1차: 동일 FPF 인스턴스 _prev_state. 2차: key_set[adcs_series]/tlm_series (AnomalyDetector).
        # 현재는 in-memory dict로 단순 보관 (재시작 시 초기화됨).
        self._prev_state: dict[str, Any] = {}

    # ──────────────────────────────────────────────────────────────────────
    # public
    # ──────────────────────────────────────────────────────────────────────

    def analyze(self, key_set: dict) -> ModuleResult:
        """3가지 정합성 체크 + 단독 판정.

        Args:
            key_set: DB 조회용 기본키 집합

        Returns:
            ModuleResult: score 0.0~1.0, signals에 무단 모드/경로 변경 등
        """
        try:
            signals_acc: list[ExceptionCode] = []
            s_log = self.check_log_concordance(key_set, signals_acc)
            s_command = self.verify_command_history(key_set, signals_acc)
            s_counter = self.check_counter_synchronization(key_set, signals_acc)

            score = (
                self.sub_weights["command_history"] * s_command
                + self.sub_weights["log_concordance"] * s_log
                + self.sub_weights["counter_synchronization"] * s_counter
            )
            score = max(0.0, min(1.0, score))
            if _SYSTEM_FORCE_SCORE_ONE.intersection(signals_acc):
                score = 1.0
            elif s_command >= 0.99:
                score = 1.0
            return ModuleResult(score, tuple(signals_acc))
        except Exception as e:
            logger.error(f"SystemResponseModule.analyze 실패: {e}")
            return ModuleResult(0.0, ())

    # ──────────────────────────────────────────────────────────────────────
    # 체크 메서드
    # ──────────────────────────────────────────────────────────────────────

    def check_log_concordance(
        self, key_set: dict, signals_acc: list[ExceptionCode] | None = None
    ) -> float:
        """체크 ① 무결성 이상 ↔ 시스템 로그 동반성.

        검증:
            1) APPCSERRCOUNTER/OSCSERRCOUNTER 증가 ↔ SYSLOGENTRIES 증가 동반
            2) 체크섬 에러 임계 이상 ↔ PROCESSOR_RESET_COUNT/RESETSPERFORMED 동반
            3) SAT_ADCS_FILTER.LASTVALCRC 변경 ↔ SAT_INTEGRITY_HASH.LAST_VERIFIED_AT
               최근 갱신 동반 (EXPECTED_HASH와의 동등 비교는 명세상 역할이 다름)

        Returns:
            float: 0.0(동반 정상) ~ 1.0(반응 누락)
        """
        try:
            adcs = self._fetch_adcs_filter(key_set)
            event = self._fetch_event(key_set)
            hashes = self._fetch_integrity_hash_all(key_set)
            if adcs is None and event is None and (hashes is None or not hashes):
                if signals_acc is not None:
                    signals_acc.append(ExceptionCode.DATA_MISSING)
                return 0.0

            scores = []

            # 이전 값 가져오기 (in-memory 캐시)
            prev = self._prev_state
            c = config

            # (1) 체크섬 에러 ↔ 시스템 로그 동조 증가
            if adcs is not None:
                appc_curr = adcs.get(c.ADCS_FILTER_COL_APPCSERRCOUNTER)
                oscs_curr = adcs.get(c.ADCS_FILTER_COL_OSCSERRCOUNTER)
                syslog_curr = adcs.get(c.ADCS_FILTER_COL_SYSLOGENTRIES)

                appc_prev   = prev.get(c.ADCS_FILTER_COL_APPCSERRCOUNTER)
                oscs_prev   = prev.get(c.ADCS_FILTER_COL_OSCSERRCOUNTER)
                syslog_prev = prev.get(c.ADCS_FILTER_COL_SYSLOGENTRIES)

                checksum_increased = (
                    self._increased(appc_curr, appc_prev)
                    or self._increased(oscs_curr, oscs_prev)
                )
                syslog_increased = self._increased(syslog_curr, syslog_prev)

                if checksum_increased and not syslog_increased:
                    # 체크섬 에러는 증가했는데 로그가 그대로 → 강한 공격 신호
                    scores.append(0.9)
                elif checksum_increased and syslog_increased:
                    scores.append(0.0)

                # 캐시 갱신
                if appc_curr is not None:
                    prev[c.ADCS_FILTER_COL_APPCSERRCOUNTER] = appc_curr
                if oscs_curr is not None:
                    prev[c.ADCS_FILTER_COL_OSCSERRCOUNTER] = oscs_curr
                if syslog_curr is not None:
                    prev[c.ADCS_FILTER_COL_SYSLOGENTRIES] = syslog_curr

            # (2) 심각한 에러 시 리셋 동반 여부 (event_id 미할당 시 ADCS RESETSPERFORMED만 사용)
            if adcs is not None:
                appc = adcs.get(c.ADCS_FILTER_COL_APPCSERRCOUNTER, 0) or 0
                oscs = adcs.get(c.ADCS_FILTER_COL_OSCSERRCOUNTER, 0) or 0
                if (appc + oscs) > c.CRITICAL_CHECKSUM_ERR_THRESHOLD:
                    resets_perf = adcs.get(c.ADCS_FILTER_COL_RESETSPERFORMED, 0) or 0
                    resets_perf_prev = prev.get(c.ADCS_FILTER_COL_RESETSPERFORMED, 0) or 0
                    reset_ok = resets_perf > resets_perf_prev
                    if event is not None:
                        reset_curr = event.get(c.EVENT_QUEUE_COL_PROCESSOR_RESET_COUNT, 0) or 0
                        reset_prev = prev.get(c.EVENT_QUEUE_COL_PROCESSOR_RESET_COUNT, 0) or 0
                        reset_ok = reset_ok or reset_curr > reset_prev
                        prev[c.EVENT_QUEUE_COL_PROCESSOR_RESET_COUNT] = reset_curr
                    if not reset_ok:
                        scores.append(0.7)
                    prev[c.ADCS_FILTER_COL_RESETSPERFORMED] = resets_perf

            # (3) LASTVALCRC(런타임) 변화 ↔ 무결성 검증 시각(EXPECTED_HASH 검증 루프) 동반
            if adcs is not None and hashes:
                lastval_curr = adcs.get(c.ADCS_FILTER_COL_LASTVALCRC)
                lastval_prev = prev.get(c.ADCS_FILTER_COL_LASTVALCRC)
                if (
                    lastval_curr is not None
                    and lastval_prev is not None
                    and lastval_curr != lastval_prev
                ):
                    lv_col = c.INTEGRITY_HASH_COL_LAST_VERIFIED_AT
                    any_verified = any(
                        self._is_recently_updated(h.get(lv_col), c.INTEGRITY_VERIFICATION_RECENCY_SEC)
                        for h in hashes
                    )
                    if not any_verified:
                        scores.append(0.95)
                if lastval_curr is not None:
                    prev[c.ADCS_FILTER_COL_LASTVALCRC] = lastval_curr

            if not scores:
                return 0.0
            return min(1.0, sum(scores) / len(scores))

        except Exception as e:
            logger.error(f"check_log_concordance 실패: {e}")
            return 0.0

    def verify_command_history(
        self, key_set: dict, signals_acc: list[ExceptionCode] | None = None
    ) -> float:
        """체크 ② 모드/설정 변경 ↔ 명령 이력 정합성.

        검증:
            1) ADCS_MODE 변경 시점에 CMDCOUNTER 증가 동반 여부
            2) ENABLEDROUTES 변경 시 정당한 명령 이력 존재 여부 (단독 1.0 가능)
            3) CMDREJECTEDCOUNTER 비정상 급증 여부

        Returns:
            float: 0.0(정당 이력 존재) ~ 1.0(이력 부재)
                   무단 모드 변경 또는 무단 경로 활성 시 즉시 1.0
        """
        try:
            tlm = self._fetch_tlm_current(key_set)
            adcs = self._fetch_adcs_filter(key_set)
            event = self._fetch_event(key_set)
            if tlm is None and adcs is None and event is None:
                if signals_acc is not None:
                    signals_acc.append(ExceptionCode.DATA_MISSING)
                return 0.0

            prev = self._prev_state
            scores = []

            # (1) ADCS_MODE 변경 ↔ CMDCOUNTER 증가
            if tlm is not None and adcs is not None:
                mode_curr = tlm.get(config.TLM_COL_ADCS_MODE)
                mode_prev = prev.get(config.TLM_COL_ADCS_MODE)
                cmd_curr = adcs.get(config.ADCS_FILTER_COL_CMDCOUNTER)
                cmd_prev = prev.get(config.ADCS_FILTER_COL_CMDCOUNTER)

                if (
                    mode_curr is not None
                    and mode_prev is not None
                    and mode_curr != mode_prev
                ):
                    # 모드 변경됨 → CMDCOUNTER 증가 동반?
                    if not self._increased(cmd_curr, cmd_prev):
                        # 명령 이력 없는 모드 변경 → 단독 1.0
                        logger.warning(
                            f"명령 이력 없는 ADCS_MODE 변경: "
                            f"{mode_prev} → {mode_curr}"
                        )
                        if signals_acc is not None:
                            signals_acc.append(ExceptionCode.UNAUTHORIZED_MODE_CHANGE)
                        # 캐시 갱신 후 1.0 반환
                        prev[config.TLM_COL_ADCS_MODE] = mode_curr
                        if cmd_curr is not None:
                            prev[config.ADCS_FILTER_COL_CMDCOUNTER] = cmd_curr
                        return 1.0

                if mode_curr is not None:
                    prev[config.TLM_COL_ADCS_MODE] = mode_curr
                if cmd_curr is not None:
                    prev[config.ADCS_FILTER_COL_CMDCOUNTER] = cmd_curr

            # (2) ENABLEDROUTES 변경 검증
            if adcs is not None:
                routes_curr = adcs.get(config.ADCS_FILTER_COL_ENABLEDROUTES)
                routes_prev = prev.get(config.ADCS_FILTER_COL_ENABLEDROUTES)

                if (
                    routes_curr is not None
                    and routes_prev is not None
                    and routes_curr > routes_prev
                ):
                    # 경로 증가 → 정당한 명령 이력 동반 확인
                    cmd_curr = adcs.get(config.ADCS_FILTER_COL_CMDCOUNTER)
                    cmd_prev = prev.get(config.ADCS_FILTER_COL_CMDCOUNTER)
                    if not self._increased(cmd_curr, cmd_prev):
                        # 명령 없이 경로 증가 → 공격 2 데이터 유출 채널 의심
                        logger.warning(
                            f"무단 ENABLEDROUTES 증가: "
                            f"{routes_prev} → {routes_curr}"
                        )
                        if signals_acc is not None:
                            signals_acc.append(ExceptionCode.UNAUTHORIZED_ROUTE_ENABLED)
                        prev[config.ADCS_FILTER_COL_ENABLEDROUTES] = routes_curr
                        return 1.0

                if routes_curr is not None:
                    prev[config.ADCS_FILTER_COL_ENABLEDROUTES] = routes_curr

            # (3) CMDREJECTEDCOUNTER 급증 (event 없으면 ADCS APPCSERR Δ로 대체)
            rej_curr = None
            rej_prev = None
            if event is not None:
                rej_curr = event.get(config.EVENT_QUEUE_COL_CMDREJECTEDCOUNTER)
                rej_prev = prev.get(config.EVENT_QUEUE_COL_CMDREJECTEDCOUNTER)
            elif adcs is not None:
                rej_curr = adcs.get(config.ADCS_FILTER_COL_APPCSERRCOUNTER)
                rej_prev = prev.get(config.ADCS_FILTER_COL_APPCSERRCOUNTER)
            if rej_curr is not None and rej_prev is not None:
                delta = rej_curr - rej_prev
                if delta > config.CMD_REJECT_SURGE_THRESHOLD:
                    ratio = delta / config.CMD_REJECT_SURGE_THRESHOLD
                    scores.append(min(0.9, ratio / 5.0))
            if rej_curr is not None:
                if event is not None:
                    prev[config.EVENT_QUEUE_COL_CMDREJECTEDCOUNTER] = rej_curr
                else:
                    prev[config.ADCS_FILTER_COL_APPCSERRCOUNTER] = rej_curr

            if not scores:
                return 0.0
            return min(1.0, sum(scores) / len(scores))

        except Exception as e:
            logger.error(f"verify_command_history 실패: {e}")
            return 0.0

    def check_counter_synchronization(
        self, key_set: dict, signals_acc: list[ExceptionCode] | None = None
    ) -> float:
        """체크 ③ 카운터 동조 정합성.

        검증: OBC_S_TICK 시간 흐름 대비
            - COMBINEDPACKETSSENT, SYSLOGENTRIES, PROCESSOR_RESET_COUNT,
              ERLOGENTRIES의 비율 정합성
            - 특정 카운터만 정체되거나 비율 이탈 시 점수 상승

        Returns:
            float: 0.0(자연 동조) ~ 1.0(비정합 패턴)
        """
        try:
            tlm = self._fetch_tlm_current(key_set)
            adcs = self._fetch_adcs_filter(key_set)
            event = self._fetch_event(key_set)
            if tlm is None or adcs is None:
                if signals_acc is not None:
                    signals_acc.append(ExceptionCode.DATA_MISSING)
                return 0.0

            prev = self._prev_state
            scores = []

            tick_curr = tlm.get(config.TLM_COL_OBC_S_TICK)
            tick_prev = prev.get(config.TLM_COL_OBC_S_TICK)
            if tick_curr is None or tick_prev is None or tick_curr <= tick_prev:
                # 첫 호출이거나 시간이 흐르지 않음 → 비교 불가
                if tick_curr is not None:
                    prev[config.TLM_COL_OBC_S_TICK] = tick_curr
                # 다른 카운터들도 캐시
                self._cache_counters(adcs, event)
                return 0.0

            tick_delta = tick_curr - tick_prev

            # 패턴 1: OBC_S_TICK 흐름 대비 SYSLOGENTRIES 정체
            sys_curr = adcs.get(config.ADCS_FILTER_COL_SYSLOGENTRIES)
            sys_prev = prev.get(config.ADCS_FILTER_COL_SYSLOGENTRIES)
            if sys_curr is not None and sys_prev is not None:
                sys_delta = sys_curr - sys_prev
                # 시간은 흐르는데 로그가 정체 → 로그 위변조
                if tick_delta > 0 and sys_delta == 0:
                    scores.append(0.8)

            # 패턴 2: COMBINEDPACKETSSENT 증가 vs FORWARD_ERR_COUNT 부재
            pkt_curr = adcs.get(config.ADCS_FILTER_COL_COMBINEDPACKETSSENT)
            pkt_prev = prev.get(config.ADCS_FILTER_COL_COMBINEDPACKETSSENT)
            fwd_err = adcs.get(config.ADCS_FILTER_COL_FORWARD_ERR_COUNT, 0) or 0
            if pkt_curr is not None and pkt_prev is not None:
                pkt_delta = pkt_curr - pkt_prev
                # 1초 주기: COMBINEDPACKETSSENT Δ가 크고 FORWARD_ERR=0 → 재전송/고스트 텔레메트리 의심
                if pkt_delta > config.HIGH_PACKET_DELTA_THRESHOLD and fwd_err == 0:
                    scores.append(config.SUSPICIOUS_PACKET_FLOW_SCORE)

            # 패턴 3: 체크섬 에러 증가 vs ERLOGENTRIES 정체
            appc_curr = adcs.get(config.ADCS_FILTER_COL_APPCSERRCOUNTER, 0) or 0
            oscs_curr = adcs.get(config.ADCS_FILTER_COL_OSCSERRCOUNTER, 0) or 0
            appc_prev = prev.get(config.ADCS_FILTER_COL_APPCSERRCOUNTER, 0) or 0
            oscs_prev = prev.get(config.ADCS_FILTER_COL_OSCSERRCOUNTER, 0) or 0
            err_increased = (
                appc_curr > appc_prev or oscs_curr > oscs_prev
            )
            erlog_curr = adcs.get(config.ADCS_FILTER_COL_ERLOGENTRIES)
            erlog_prev = prev.get(config.ADCS_FILTER_COL_ERLOGENTRIES)
            if (
                err_increased
                and erlog_curr is not None
                and erlog_prev is not None
                and erlog_curr == erlog_prev
            ):
                scores.append(0.85)

            # SKIPPEDSLOTSCOUNT, PIPEOVERFLOWRRCNT 급증 → 시스템 교란
            if event is not None:
                pipe_curr = event.get(config.EVENT_QUEUE_COL_PIPEOVERFLOWRRCNT)
                pipe_prev = prev.get(config.EVENT_QUEUE_COL_PIPEOVERFLOWRRCNT)
                if pipe_curr is not None and pipe_prev is not None:
                    if pipe_curr - pipe_prev > config.PIPE_OVERFLOW_SURGE_DELTA:
                        scores.append(0.5)
                if pipe_curr is not None:
                    prev[config.EVENT_QUEUE_COL_PIPEOVERFLOWRRCNT] = pipe_curr

            skip_curr = adcs.get(config.ADCS_FILTER_COL_SKIPPEDSLOTSCOUNT)
            skip_prev = prev.get(config.ADCS_FILTER_COL_SKIPPEDSLOTSCOUNT)
            if skip_curr is not None and skip_prev is not None:
                if skip_curr - skip_prev > config.SKIPPED_SLOTS_SURGE_DELTA:
                    scores.append(0.5)

            # 캐시 갱신
            prev[config.TLM_COL_OBC_S_TICK] = tick_curr
            self._cache_counters(adcs, event)

            if not scores:
                return 0.0
            return min(1.0, sum(scores) / len(scores))

        except Exception as e:
            logger.error(f"check_counter_synchronization 실패: {e}")
            return 0.0

    # ──────────────────────────────────────────────────────────────────────
    # 캐시 / 데이터 조회 헬퍼
    # ──────────────────────────────────────────────────────────────────────

    def _cache_counters(self, adcs: dict | None, event: dict | None) -> None:
        """카운터들을 prev_state에 갱신."""
        if adcs is not None:
            for k in config.SYSTEM_MODULE_ADCS_CACHE_KEYS:
                v = adcs.get(k)
                if v is not None:
                    self._prev_state[k] = v
        if event is not None:
            for k in config.SYSTEM_MODULE_EVENT_CACHE_KEYS:
                v = event.get(k)
                if v is not None:
                    self._prev_state[k] = v

    def _fetch_tlm_current(self, key_set: dict) -> dict | None:
        try:
            return db_context.resolve_tlm(key_set, self.db)
        except Exception as e:
            logger.error(f"SAT_TLM_CURRENT 조회 실패: {e}")
            return None

    def _fetch_adcs_filter(self, key_set: dict) -> dict | None:
        try:
            return db_context.resolve_adcs(key_set, self.db)
        except Exception as e:
            logger.error(f"SAT_ADCS_FILTER 조회 실패: {e}")
            return None

    def _fetch_event(self, key_set: dict) -> dict | None:
        try:
            return db_context.resolve_event(key_set, self.db)
        except Exception as e:
            logger.error(f"SAT_EVENT_QUEUE 조회 실패: {e}")
            return None

    def _fetch_integrity_hash_all(self, key_set: dict) -> list[dict] | None:
        try:
            result = db_context.resolve_integrity_hash(key_set, self.db, None)
            if result is None:
                return None
            if isinstance(result, dict):
                return [result]
            return result
        except Exception as e:
            logger.error(f"SAT_INTEGRITY_HASH 조회 실패: {e}")
            return None

    # ──────────────────────────────────────────────────────────────────────
    # 유틸
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _increased(curr: Any, prev: Any) -> bool:
        """현재 값이 이전 값보다 증가했는지 (둘 다 숫자여야 True 가능)."""
        if curr is None or prev is None:
            return False
        try:
            return curr > prev
        except TypeError:
            return False

    @staticmethod
    def _is_recently_updated(ts: Any, threshold_sec: float = 60.0) -> bool:
        """타임스탬프가 최근 threshold_sec 이내인지 (UTC 기준)."""
        if ts is None:
            return False
        try:
            from ...core.time_utils import parse_utc_timestamp, utc_now

            parsed = parse_utc_timestamp(ts)
            if parsed is None:
                return False
            return abs((utc_now() - parsed).total_seconds()) <= threshold_sec
        except Exception as e:
            logger.error("최근 갱신 여부 판단 실패: %s", e)
            return False
