"""PhysicalConsistencyModule (모듈 1) — ADCS 물리 정합성.

검증 축 (가중치 config.PHYSICAL_SUB_WEIGHTS)
    - command_outcome: TCMD↔IMU dω/dt, MCMD↔휠, QERR/WERR/THERR (adcs_series 추세)
    - attitude_consistency: ST_QBN↔QBN, IMU↔사원수, 단위 사원수
    - mode_behavior: ADCS_MODE별 SUNSAFE/POINTING/DETUMBLING 거동

시계열 (프로젝트 1차)
    - key_set["adcs_series"] 2+ → 토크 Δ, 3+ → QERR 발산/미수렴
    - 없으면 self._prev_state (동일 FPF 인스턴스·연속 호출 필요)

단독 신호 (가중합 무시, exception 1~3)
    UNIT_QUATERNION_VIOLATION, TORQUE_AMPLIFICATION, WHEEL_DISABLED_BUT_COMMANDED

입력: key_set + DBManager(주입). 조회는 db_context 경유.
"""

import logging
import math
from typing import Any

from . import config
from . import db_context
from .exception_codes import ExceptionCode
from .module_result import ModuleResult

logger = logging.getLogger(config.LOGGER_NAME)

_PHYSICAL_FORCE_SCORE_ONE = frozenset(
    {
        ExceptionCode.UNIT_QUATERNION_VIOLATION,
        ExceptionCode.TORQUE_AMPLIFICATION,
        ExceptionCode.WHEEL_DISABLED_BUT_COMMANDED,
    }
)


class PhysicalConsistencyModule:
    """ADCS 인과 사슬 정합성 분석 모듈."""

    def __init__(self, db_manager: Any, sub_weights: dict | None = None):
        """
        Args:
            db_manager: DBManager 인스턴스. 다음 메서드 필요:
                - get_tlm_current() -> dict
                - get_adcs_filter(channel1: int) -> dict
            analyze() 반환: ModuleResult(score, signals)
            sub_weights: 체크별 가중치. None이면 config 값 사용
        """
        self.db = db_manager
        self.sub_weights = (
            sub_weights
            if sub_weights is not None
            else dict(config.PHYSICAL_SUB_WEIGHTS)
        )
        self._prev_state: dict[str, Any] = {}

    # ──────────────────────────────────────────────────────────────────────
    # public
    # ──────────────────────────────────────────────────────────────────────

    def analyze(self, key_set: dict) -> ModuleResult:
        """3가지 정합성 체크를 실행하고 가중 합산.

        Args:
            key_set: DB 조회용 기본키 집합

        Returns:
            ModuleResult: score 0.0~1.0, signals는 관측된 ExceptionCode 튜플
        """
        try:
            signals_acc: list[ExceptionCode] = []
            s_attitude = self.check_attitude_consistency(key_set, signals_acc)
            s_command = self.check_command_outcome(key_set, signals_acc)
            s_mode = self.check_mode_behavior(key_set, signals_acc)

            adcs = self._fetch_adcs_filter(key_set)
            if adcs is not None:
                self._cache_adcs_state(adcs, key_set)

            score = (
                self.sub_weights["command_outcome"] * s_command
                + self.sub_weights["attitude_consistency"] * s_attitude
                + self.sub_weights["mode_behavior"] * s_mode
            )
            score = max(0.0, min(1.0, score))
            if _PHYSICAL_FORCE_SCORE_ONE.intersection(signals_acc):
                score = 1.0
            elif max(s_attitude, s_command, s_mode) >= 0.99:
                score = 1.0
            return ModuleResult(score, tuple(signals_acc))
        except Exception as e:
            logger.error(f"PhysicalConsistencyModule.analyze 실패: {e}")
            return ModuleResult(0.0, ())

    # ──────────────────────────────────────────────────────────────────────
    # private — 체크 메서드
    # ──────────────────────────────────────────────────────────────────────

    def check_attitude_consistency(
        self, key_set: dict, signals_acc: list[ExceptionCode] | None = None
    ) -> float:
        """체크 ① 센서 ↔ 자세 결정 일관성 (S ↔ P).

        검증:
            1) ST_QBN vs QBN 각도 차이
            2) IMU 각속도 적분 vs 사원수 변화량
            3) 단위 사원수 조건 (q0² + q1² + q2² + q3² = 1)

        Returns:
            float: 0.0(정합) ~ 1.0(불일치)
        """
        try:
            adcs = self._fetch_adcs_filter(key_set)
            if adcs is None:
                if signals_acc is not None:
                    signals_acc.append(ExceptionCode.DATA_MISSING)
                return 0.0

            scores = []

            # (1) 두 사원수의 각도 차이
            st_valid = adcs.get("ST_VALID", 0)
            q_valid  = adcs.get("Q_VALID", 0)
            if st_valid == 1 and q_valid == 1:
                st_q  = self._extract_quaternion(adcs, prefix="ST_QBN_")
                gnc_q = self._extract_quaternion(adcs, prefix="QBN_")
                if st_q is not None and gnc_q is not None:
                    angle = self._quaternion_angle_diff(st_q, gnc_q)
                    if angle is not None:
                        # 임계치 5도 초과 시 점수 비례 상승
                        ratio = angle / config.QUATERNION_ANGLE_THRESHOLD_RAD
                        scores.append(min(1.0, max(0.0, (ratio - 1.0))))

            # (2) IMU 각속도 vs 사원수 변화량 (_prev_state 캐시)
            tlm = db_context.resolve_tlm(key_set, self.db)
            dt = self._get_dt(tlm)
            gnc_q = self._extract_quaternion(adcs, prefix="QBN_")
            prev_q = self._prev_state.get("QBN")
            imu = self._extract_xyz(adcs, prefix="IMU_WBN_")
            if (
                prev_q is not None
                and gnc_q is not None
                and imu is not None
                and dt > 1e-9
            ):
                angle_change = self._quaternion_angle_diff(prev_q, gnc_q)
                omega_mag = math.sqrt(sum(w * w for w in imu))
                expected = omega_mag * dt
                if angle_change is not None and expected > 1e-9:
                    mismatch = abs(angle_change - expected) / expected
                    if mismatch > config.IMU_QUAT_INCONSISTENCY_THRESHOLD:
                        scores.append(
                            min(1.0, mismatch / config.IMU_QUAT_INCONSISTENCY_THRESHOLD)
                        )

            # (3) 단위 사원수 조건 검증
            for prefix, valid in [("ST_QBN_", st_valid), ("QBN_", q_valid)]:
                if valid != 1:
                    continue
                q = self._extract_quaternion(adcs, prefix=prefix)
                if q is None:
                    continue
                norm_sq = sum(qi * qi for qi in q)
                if abs(norm_sq - 1.0) > config.UNIT_QUATERNION_TOLERANCE:
                    # 명백한 변조 — 단독 1.0 (analyze에서 단독 판정 트리거)
                    logger.warning(
                        f"단위 사원수 조건 위반: {prefix} norm²={norm_sq:.4f}"
                    )
                    if signals_acc is not None:
                        signals_acc.append(ExceptionCode.UNIT_QUATERNION_VIOLATION)
                    return 1.0

            if not scores:
                return 0.0
            return sum(scores) / len(scores)

        except Exception as e:
            logger.error(f"check_attitude_consistency 실패: {e}")
            return 0.0

    def check_command_outcome(
        self, key_set: dict, signals_acc: list[ExceptionCode] | None = None
    ) -> float:
        """체크 ② 명령 ↔ 결과 일관성 (C ↔ P).

        검증:
            1) TCMD vs IMU_WBN 변화 비례 (각운동량 보존)
            2) MCMD vs MOMENTUM_NMS 변화 비례
            3) QERR / WERR / THERR 수렴성

        Returns:
            float: 0.0(정합) ~ 1.0(불일치)
        """
        try:
            adcs = self._fetch_adcs_filter(key_set)
            if adcs is None:
                if signals_acc is not None:
                    signals_acc.append(ExceptionCode.DATA_MISSING)
                return 0.0

            scores = []

            tlm = db_context.resolve_tlm(key_set, self.db)
            dt = self._get_dt(tlm)
            tcmd = self._extract_xyz(adcs, prefix="TCMD_")
            wbn = self._extract_xyz(adcs, prefix="IMU_WBN_")
            series = db_context.resolve_adcs_series(key_set, self.db)
            torque_score = self._score_torque_outcome(
                tcmd, wbn, dt, series, signals_acc
            )
            if torque_score is not None:
                if torque_score >= 1.0:
                    return 1.0
                scores.append(torque_score)

            # (2) 모멘텀 명령 vs 휠 각운동량
            mcmd     = self._extract_xyz(adcs, prefix="MCMD_")
            momentum = [
                adcs.get(f"MOMENTUM_NMS_{i}") for i in range(3)
            ]
            wheels_enabled = [
                adcs.get(f"DEVICE_ENABLED_RW{i}", 0) for i in range(3)
            ]

            # 휠 비활성 + 명령 발행 → 휠 무력화 공격 단독 강한 신호
            if mcmd is not None and any(c is not None for c in mcmd):
                cmd_present = any(abs(c) > 1e-6 for c in mcmd if c is not None)
                if cmd_present and all(w == 0 for w in wheels_enabled):
                    logger.warning("휠 비활성 상태에서 모멘텀 명령 발행")
                    if signals_acc is not None:
                        signals_acc.append(ExceptionCode.WHEEL_DISABLED_BUT_COMMANDED)
                    return 1.0

            if mcmd is not None and all(m is not None for m in momentum):
                mcmd_mag = math.sqrt(sum(c * c for c in mcmd if c is not None))
                mom_mag  = math.sqrt(sum(m * m for m in momentum))
                if mcmd_mag > 1e-9:
                    ratio = mom_mag / mcmd_mag
                    deviation = abs(ratio - 1.0)
                    scores.append(
                        min(1.0, deviation / config.TORQUE_OUTCOME_TOLERANCE)
                    )

            # (3) 제어 오차 수렴성 — adcs_series 있으면 추세, 없으면 단발 절대값
            conv_score = self._score_qerr_convergence(series if series else [adcs])
            if conv_score is not None:
                scores.append(conv_score)

            werr = self._extract_xyz(adcs, prefix="WERR_")
            if werr is not None:
                werr_mag = math.sqrt(sum(w * w for w in werr))
                scores.append(min(1.0, werr_mag / config.WERR_MAG_THRESHOLD))

            therr = self._extract_xyz(adcs, prefix="THERR_")
            if therr is not None:
                therr_mag = math.sqrt(sum(t * t for t in therr))
                scores.append(min(1.0, therr_mag / config.THERR_MAG_THRESHOLD))

            if not scores:
                return 0.0
            return sum(scores) / len(scores)

        except Exception as e:
            logger.error(f"check_command_outcome 실패: {e}")
            return 0.0

    def check_mode_behavior(
        self, key_set: dict, signals_acc: list[ExceptionCode] | None = None
    ) -> float:
        """체크 ③ 모드 ↔ 거동 일관성 (ST ↔ C).

        검증: ADCS_MODE에 따라 분기하여 명령 패턴 정합성 확인.

        Returns:
            float: 0.0(정합) ~ 1.0(불일치)
        """
        try:
            tlm = db_context.resolve_tlm(key_set, self.db)
            adcs = self._fetch_adcs_filter(key_set)
            if tlm is None or adcs is None:
                if signals_acc is not None:
                    signals_acc.append(ExceptionCode.DATA_MISSING)
                return 0.0

            adcs_mode = tlm.get(config.TLM_COL_ADCS_MODE)
            if adcs_mode is None:
                if signals_acc is not None:
                    signals_acc.append(ExceptionCode.DATA_MISSING)
                return 0.0

            scores = []

            # DB 명세.pdf SAT_TLM_CURRENT.ADCS_MODE 정수 → config 상수와 동기화
            if adcs_mode == config.ADCS_MODE_SUNSAFE:
                scores.append(self._check_sunsafe_mode(tlm, adcs))
            elif adcs_mode == config.ADCS_MODE_POINTING:
                scores.append(self._check_pointing_mode(tlm, adcs))
            elif adcs_mode == config.ADCS_MODE_DETUMBLING:
                scores.append(self._check_detumbling_mode(tlm, adcs))

            # 모멘텀 관리 검증 (모드 무관)
            scores.append(self._check_momentum_management(adcs))

            if not scores:
                return 0.0
            return sum(scores) / len(scores)

        except Exception as e:
            logger.error(f"check_mode_behavior 실패: {e}")
            return 0.0

    # ──────────────────────────────────────────────────────────────────────
    # 모드별 검증 헬퍼
    # ──────────────────────────────────────────────────────────────────────

    def _check_sunsafe_mode(self, tlm: dict, adcs: dict) -> float:
        """SUNSAFE 모드: 태양 벡터 추적 방향으로 토크 명령 발행 여부."""
        sun_valid = tlm.get("SUN_VALID", 0)
        if sun_valid == 0:
            # SUNSAFE 모드인데 SUN_VALID=0 → 비정합
            return 0.8

        svb  = self._extract_xyz(tlm, prefix="SVB_")
        tcmd = self._extract_xyz(adcs, prefix="TCMD_")
        if svb is None or tcmd is None:
            return 0.0

        # 토크 명령 벡터와 태양 벡터의 코사인 유사도 (간소화)
        svb_mag  = math.sqrt(sum(s * s for s in svb))
        tcmd_mag = math.sqrt(sum(c * c for c in tcmd))
        if svb_mag < 1e-9 or tcmd_mag < 1e-9:
            return 0.0
        dot = sum(s * c for s, c in zip(svb, tcmd))
        cos_sim = dot / (svb_mag * tcmd_mag)
        # 양의 상관관계가 정상. 음수(반대 방향)이면 점수 상승
        if cos_sim < 0:
            return min(1.0, abs(cos_sim))
        return 0.0

    def _check_pointing_mode(self, tlm: dict, adcs: dict) -> float:
        """POINTING 모드: CMD_WBN ≈ 0, QERR이 [1,0,0,0]에 수렴."""
        scores = []
        cmd_wbn = self._extract_xyz(adcs, prefix="CMD_WBN_")
        if cmd_wbn is not None:
            mag = math.sqrt(sum(w * w for w in cmd_wbn))
            if mag > config.CMD_WBN_POINTING_MAX:
                scores.append(min(1.0, mag / config.CMD_WBN_POINTING_MAX))
        qerr = [adcs.get(f"QERR_{i}") for i in range(4)]
        if all(q is not None for q in qerr):
            qerr_vec_norm_sq = sum(q * q for q in qerr[1:])
            scores.append(min(1.0, qerr_vec_norm_sq / config.QERR_VEC_NORM_THRESHOLD))
        if not scores:
            return 0.0
        return sum(scores) / len(scores)

    def _check_detumbling_mode(self, tlm: dict, adcs: dict) -> float:
        """DETUMBLING 모드: B-dot 제어, 토크 = -k·dB/dt 형태."""
        bdot = self._extract_xyz(adcs, prefix="BDOT_")
        tcmd = self._extract_xyz(adcs, prefix="TCMD_")
        if bdot is None or tcmd is None:
            return 0.0

        bdot_mag = math.sqrt(sum(b * b for b in bdot))
        tcmd_mag = math.sqrt(sum(c * c for c in tcmd))
        if bdot_mag < 1e-9 or tcmd_mag < 1e-9:
            return 0.0
        dot = sum(b * c for b, c in zip(bdot, tcmd))
        cos_sim = dot / (bdot_mag * tcmd_mag)
        # B-dot 제어는 -k·dB/dt이므로 cos_sim이 음수여야 정상
        if cos_sim > 0:
            scores_dir = min(1.0, cos_sim)
        else:
            scores_dir = 0.0
        ratio = tcmd_mag / bdot_mag
        if ratio > 1.0 + config.BDOT_TCMD_RATIO_TOLERANCE:
            scores_mag = min(1.0, (ratio - 1.0) / config.BDOT_TCMD_RATIO_TOLERANCE)
        else:
            scores_mag = 0.0
        return max(scores_dir, scores_mag)

    def _score_torque_outcome(
        self,
        tcmd: list[float] | None,
        wbn: list[float] | None,
        dt: float,
        series: list[dict],
        signals_acc: list[ExceptionCode] | None,
    ) -> float | None:
        """TCMD 대비 dω/dt(2샘플 이상). series·_prev_state 순으로 이전 IMU 사용."""
        try:
            if tcmd is None or wbn is None:
                return None
            tcmd_mag = math.sqrt(sum(c * c for c in tcmd))
            if tcmd_mag <= 1e-9:
                return None

            prev_wbn = None
            if len(series) >= config.MIN_SAMPLES_FOR_DELTA:
                prev_row = series[-2]
                prev_wbn = self._extract_xyz(prev_row, prefix="IMU_WBN_")
            if prev_wbn is None:
                prev_wbn = self._prev_state.get("IMU_WBN")

            if prev_wbn is not None and dt > 1e-9:
                dw = [(wbn[i] - prev_wbn[i]) / dt for i in range(3)]
                dw_mag = math.sqrt(sum(d * d for d in dw))
                ratio = dw_mag / tcmd_mag
                if ratio > config.TORQUE_AMPLIFICATION_THRESHOLD:
                    logger.warning(f"토크 증폭 의심: ratio={ratio:.2f}")
                    if signals_acc is not None:
                        signals_acc.append(ExceptionCode.TORQUE_AMPLIFICATION)
                    return 1.0
                return min(1.0, abs(ratio - 1.0) / config.TORQUE_OUTCOME_TOLERANCE)

            wbn_mag = math.sqrt(sum(w * w for w in wbn))
            ratio = wbn_mag / tcmd_mag
            if ratio > config.TORQUE_AMPLIFICATION_THRESHOLD:
                if signals_acc is not None:
                    signals_acc.append(ExceptionCode.TORQUE_AMPLIFICATION)
                return 1.0
            return min(1.0, abs(ratio - 1.0) / config.TORQUE_OUTCOME_TOLERANCE)
        except Exception as e:
            logger.error(f"_score_torque_outcome 실패: {e}")
            return None

    @staticmethod
    def _qerr_vector_norm_sq(adcs: dict) -> float | None:
        try:
            qerr = [adcs.get(f"QERR_{i}") for i in range(4)]
            if not all(q is not None for q in qerr):
                return None
            return sum(q * q for q in qerr[1:])
        except Exception:
            return None

    def _score_qerr_convergence(self, series: list[dict]) -> float | None:
        """QERR 벡터 노름 추세. 3샘플 이상이면 수렴/발산, 아니면 마지막 1샘플 절대값."""
        try:
            if len(series) >= config.MIN_SAMPLES_FOR_CONVERGENCE:
                norms: list[float] = []
                for row in series[-config.MIN_SAMPLES_FOR_CONVERGENCE :]:
                    n = self._qerr_vector_norm_sq(row)
                    if n is None:
                        return None
                    norms.append(n)
                if norms[-1] > norms[0] * config.QERR_DIVERGE_RATIO:
                    return min(
                        1.0,
                        (norms[-1] - norms[0]) / config.QERR_VEC_NORM_THRESHOLD,
                    )
                if norms[-1] > config.QERR_CONVERGED_NORM_SQ:
                    return min(1.0, norms[-1] / config.QERR_VEC_NORM_THRESHOLD)
                return 0.0
            last = series[-1] if series else None
            if last is None:
                return None
            n = self._qerr_vector_norm_sq(last)
            if n is None:
                return None
            return min(1.0, n / config.QERR_VEC_NORM_THRESHOLD)
        except Exception as e:
            logger.error(f"_score_qerr_convergence 실패: {e}")
            return None

    def _check_momentum_management(self, adcs: dict) -> float:
        """모멘텀 관리: H_MGMTON=1인데 휠 각운동량이 단조 증가하는지."""
        h_mgmton = adcs.get("H_MGMTON", 0)
        if h_mgmton != 1:
            return 0.0
        prev_mom = self._prev_state.get("MOMENTUM_NMS")
        curr = [
            adcs.get(f"MOMENTUM_NMS_{i}") for i in range(3)
        ]
        if prev_mom is None or any(m is None for m in curr):
            return 0.0
        prev_mag = math.sqrt(sum(m * m for m in prev_mom))
        curr_mag = math.sqrt(sum(m * m for m in curr))
        if curr_mag > prev_mag * 1.05:
            return min(1.0, (curr_mag - prev_mag) / max(prev_mag, 1e-9))
        return 0.0

    # ──────────────────────────────────────────────────────────────────────
    # 데이터 조회 헬퍼
    # ──────────────────────────────────────────────────────────────────────

    def _fetch_adcs_filter(self, key_set: dict) -> dict | None:
        """SAT_ADCS_FILTER 조회 (스냅샷 우선)."""
        try:
            return db_context.resolve_adcs(key_set, self.db)
        except Exception as e:
            logger.error(f"SAT_ADCS_FILTER 조회 실패: {e}")
            return None

    def _cache_adcs_state(self, adcs: dict, key_set: dict) -> None:
        """다음 주기 비교용 캐시."""
        try:
            q = self._extract_quaternion(adcs, prefix="QBN_")
            if q is not None:
                self._prev_state["QBN"] = q
            imu = self._extract_xyz(adcs, prefix="IMU_WBN_")
            if imu is not None:
                self._prev_state["IMU_WBN"] = imu
            mom = [adcs.get(f"MOMENTUM_NMS_{i}") for i in range(3)]
            if all(m is not None for m in mom):
                self._prev_state["MOMENTUM_NMS"] = [float(m) for m in mom]
            tlm = db_context.resolve_tlm(key_set, self.db)
            if tlm is not None:
                self._prev_state[config.TLM_COL_ADCS_MODE] = tlm.get(config.TLM_COL_ADCS_MODE)
        except Exception as e:
            logger.error(f"_cache_adcs_state 실패: {e}")

    @staticmethod
    def _get_dt(tlm: dict | None) -> float:
        try:
            if tlm is None:
                return 1.0
            return max(1e-9, float(tlm.get("DT", 1.0)))
        except (TypeError, ValueError):
            return 1.0

    # ──────────────────────────────────────────────────────────────────────
    # 수치 계산 유틸
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_quaternion(row: dict, prefix: str) -> list[float] | None:
        """row에서 prefix0~3 컬럼을 사원수로 추출."""
        try:
            q = [row.get(f"{prefix}{i}") for i in range(4)]
            if any(qi is None for qi in q):
                return None
            return [float(qi) for qi in q]
        except (TypeError, ValueError) as e:
            logger.error(f"사원수 추출 실패 ({prefix}): {e}")
            return None

    @staticmethod
    def _extract_xyz(row: dict, prefix: str) -> list[float] | None:
        """row에서 prefix{X,Y,Z} 컬럼을 3축 벡터로 추출."""
        try:
            v = [row.get(f"{prefix}{ax}") for ax in ("X", "Y", "Z")]
            if any(vi is None for vi in v):
                return None
            return [float(vi) for vi in v]
        except (TypeError, ValueError) as e:
            logger.error(f"3축 벡터 추출 실패 ({prefix}): {e}")
            return None

    @staticmethod
    def _quaternion_angle_diff(q1: list[float], q2: list[float]) -> float | None:
        """두 단위 사원수 사이의 회전 각도(rad).

        q_diff = q1⁻¹ ⊗ q2의 스칼라 성분으로부터 θ = 2·acos(|q0|)
        """
        try:
            # q1 켤레 (단위 사원수의 역원)
            q1_conj = [q1[0], -q1[1], -q1[2], -q1[3]]
            # q1_conj ⊗ q2 (Hamilton product)
            w1, x1, y1, z1 = q1_conj
            w2, x2, y2, z2 = q2
            w = w1 * w2 - x1 * x2 - y1 * y2 - z1 * z2
            # 안정성 위해 클램핑
            w = max(-1.0, min(1.0, w))
            return 2.0 * math.acos(abs(w))
        except Exception as e:
            logger.error(f"사원수 각도 차이 계산 실패: {e}")
            return None
