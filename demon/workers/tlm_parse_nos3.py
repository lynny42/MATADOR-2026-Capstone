"""
NOS3 generic_* 앱 텔레메트리 바이너리 파싱.

참조(저장소 옆 nos3):
- components/generic_adcs/fsw/cfs/src/generic_adcs_msg.h
- components/generic_adcs/fsw/cfs/platform_inc/generic_adcs_msgids.h
- components/generic_imu/fsw/cfs/src/generic_imu_msg.h
- components/generic_mag/fsw/cfs/src/generic_mag_msg.h
- components/mgr/fsw/cfs/src/mgr_msg.h
- fsw/cfe/modules/msg/option_inc/default_cfe_msg_hdr_pri{,ext}.h
  (CFE_MSG_TelemetryHeader_t 총 16바이트; 그 뒤가 앱 페이로드)
"""
from __future__ import annotations

import logging
import struct
from typing import Any

from .. import config as demon_config

logger = logging.getLogger(__name__)

_E = demon_config.TLM_STRUCT_ENDIAN

# ===========================================================================
# 페이로드 길이 (struct.calcsize 와 selftest 로 검증)
# ===========================================================================
# Generic_ADCS_DI_Tlm_Payload_t
#   Mag(56) + Fss(57) + Css(265) + Imu(105) + Rw(120) + St(65) = 668
_LEN_ADCS_DI_PAYLOAD = 668
# Generic_ADCS_AD_Tlm_Payload_t
#   Mag(24) + Sol(26) + Imu(82) + ST(33) = 165
_LEN_ADCS_AD_PAYLOAD = 165
# Generic_ADCS_GNC_Tlm_Payload_t
_LEN_ADCS_GNC_PAYLOAD = 311
# Generic_ADCS_AC_Tlm_Payload_t
#   Bdot(64) + Sunsafe(185) + Inertial(248) = 497
_LEN_ADCS_AC_PAYLOAD = 497
# Generic_ADCS_DO_Tlm_Payload_t
#   Trq(56) + Rw(96) = 152
_LEN_ADCS_DO_PAYLOAD = 152

# ===========================================================================
# CCSDS 헤더 분리
# ===========================================================================
def cfe_tlm_user_bytes(full_packet: bytes) -> bytes | None:
    """
    UDP 수신 CCSDS Space Packet 전체 버퍼에서 앱 텔레메트리(사용자) 페이로드만 분리.

    NOS3 cFE 텔레메트리 레이아웃:
        [CFE_MSG_TelemetryHeader_t = 16B (Primary 6B + Sec 6B + Ext/Spare 4B)][user payload...]

    sec_hdr_flag = 0 인 드문 케이스는 Primary(6B) 만 건너뛴다.
    """
    try:
        need = demon_config.CCSDS_PRIMARY_HEADER_BYTES
        if len(full_packet) < need:
            return None
        w0 = (full_packet[0] << 8) | full_packet[1]
        sec = (w0 >> 11) & 0x1
        skip = demon_config.CFE_SB_TLM_MSG_HDR_BYTES if sec else need
        if len(full_packet) < skip:
            return None
        return full_packet[skip:]
    except (IndexError, MemoryError) as e:
        logger.error("cfe_tlm_user_bytes 실패(Index/Memory): %s", e)
        return None
    except Exception as e:
        logger.error("cfe_tlm_user_bytes 실패: %s", e)
        return None


# ===========================================================================
# ADCS GNC (0x0943) — Generic_ADCS_GNC_Tlm_Payload_t (311B)
# ===========================================================================
def _adcs_gnc_unpack(ub: bytes) -> dict[str, Any]:
    """
    필드 순서대로 stepwise unpack. 구조체:
      double DT, MaxMcmd;
      uint8 Mode, HmgmtOn;
      Generic_ADCS_GNC_Hmgmt_t Hmgmt;   // Kb(8)+b_range(8)+loFrac(8)+hiFrac(8) + mm_active[3](3) + Mcmd[3](24) = 63
      double bvb[3], svb[3];
      uint8 SunValid;
      double wbn[3], HwhlMaxB[3], HwhlB[3], Mcmd[3], Tcmd[3];
      uint8 qValid;
      double qbn[4], qErr[4];

    예외 발생 시 호출자가 잡도록 그대로 raise.
    """
    try:
        off = 0
        dt, max_mcmd = struct.unpack_from(f"{_E}2d", ub, off)
        off += 16
        mode, hmgmt_on = struct.unpack_from(f"{_E}BB", ub, off)
        off += 2
        # Hmgmt: Kb, b_range, loFrac, hiFrac
        struct.unpack_from(f"{_E}4d", ub, off)
        off += 32
        # Hmgmt: mm_active[3]
        struct.unpack_from(f"{_E}3B", ub, off)
        off += 3
        # Hmgmt.Mcmd[3]
        struct.unpack_from(f"{_E}3d", ub, off)
        off += 24
        # bvb[3]
        struct.unpack_from(f"{_E}3d", ub, off)
        off += 24
        svb_x, svb_y, svb_z = struct.unpack_from(f"{_E}3d", ub, off)
        off += 24
        (sun_valid,) = struct.unpack_from(f"{_E}B", ub, off)
        off += 1
        wbn_x, wbn_y, wbn_z = struct.unpack_from(f"{_E}3d", ub, off)
        off += 24
        # HwhlMaxB[3]
        struct.unpack_from(f"{_E}3d", ub, off)
        off += 24
        hwhl_b = struct.unpack_from(f"{_E}3d", ub, off)
        off += 24
        mcmd = struct.unpack_from(f"{_E}3d", ub, off)
        off += 24
        tcmd = struct.unpack_from(f"{_E}3d", ub, off)
        off += 24
        (q_valid,) = struct.unpack_from(f"{_E}B", ub, off)
        off += 1
        qbn = struct.unpack_from(f"{_E}4d", ub, off)
        off += 32
        qerr = struct.unpack_from(f"{_E}4d", ub, off)
        off += 32

        if off != _LEN_ADCS_GNC_PAYLOAD:
            raise struct.error(f"GNC payload walk end off={off} expected {_LEN_ADCS_GNC_PAYLOAD}")
        return {
            "ADCS_MODE": int(mode) & 0xFF,
            "DT": float(dt),
            "SUN_VALID": int(sun_valid) & 0xFF,
            "SVB_X": float(svb_x), "SVB_Y": float(svb_y), "SVB_Z": float(svb_z),
            "WBN_X": float(wbn_x), "WBN_Y": float(wbn_y), "WBN_Z": float(wbn_z),
            # 명세 SAT_ADCS_FILTER 매핑
            "Q_VALID": int(q_valid) & 0xFF,
            "QBN_0": float(qbn[0]), "QBN_1": float(qbn[1]),
            "QBN_2": float(qbn[2]), "QBN_3": float(qbn[3]),
            "QERR_0": float(qerr[0]), "QERR_1": float(qerr[1]),
            "QERR_2": float(qerr[2]), "QERR_3": float(qerr[3]),
            "MOMENTUM_NMS_0": float(hwhl_b[0]),
            "MOMENTUM_NMS_1": float(hwhl_b[1]),
            "MOMENTUM_NMS_2": float(hwhl_b[2]),
            "TCMD_X": float(tcmd[0]), "TCMD_Y": float(tcmd[1]), "TCMD_Z": float(tcmd[2]),
            "MCMD_X": float(mcmd[0]), "MCMD_Y": float(mcmd[1]), "MCMD_Z": float(mcmd[2]),
            "_HMGMTON": int(hmgmt_on) & 0xFF,
            "_MAX_MCMD": float(max_mcmd),
        }
    except struct.error as e:
        logger.error("_adcs_gnc_unpack struct 오류: %s", e)
        raise
    except (IndexError, MemoryError) as e:
        logger.error("_adcs_gnc_unpack 실패(Index/Memory): %s", e)
        raise
    except Exception as e:
        logger.error("_adcs_gnc_unpack 실패: %s", e)
        raise


def _parse_adcs_gnc(full_packet: bytes) -> dict[str, Any]:
    """GENERIC_ADCS_GNC_MID (0x0943) — 311 byte payload."""
    try:
        ub = cfe_tlm_user_bytes(full_packet)
        if ub is None or len(ub) < _LEN_ADCS_GNC_PAYLOAD:
            logger.warning(
                "ADCS GNC 페이로드 길이 부족: need>=%s have=%s",
                _LEN_ADCS_GNC_PAYLOAD,
                0 if ub is None else len(ub),
            )
            return {}
        raw = _adcs_gnc_unpack(ub[:_LEN_ADCS_GNC_PAYLOAD])
        return _strip_internal_keys(raw)
    except struct.error as e:
        logger.error("ADCS GNC struct 오류: %s", e)
        return {}
    except (IndexError, MemoryError) as e:
        logger.error("ADCS GNC 파싱 실패(Index/Memory): %s", e)
        return {}
    except Exception as e:
        logger.error("ADCS GNC 파싱 실패: %s", e)
        return {}


# ===========================================================================
# ADCS AD (0x0942) — Generic_ADCS_AD_Tlm_Payload_t (165B)
# ===========================================================================
def _parse_adcs_ad(full_packet: bytes) -> dict[str, Any]:
    """
    구조체:
      Mag.bvb[3]                                          (24)  off 0
      Sol: SunValid(1), FssValid(1), svb[3](24)           (26)  off 24
      Imu: init(1), alpha(8), valid(1), wbn_prev[3](24),
           wbn[3](24), acc[3](24)                         (82)  off 50
      ST:  Valid(1), qbn[4](32)                           (33)  off 132
    """
    try:
        ub = cfe_tlm_user_bytes(full_packet)
        if ub is None or len(ub) < _LEN_ADCS_AD_PAYLOAD:
            logger.warning(
                "ADCS AD 페이로드 길이 부족: need>=%s have=%s",
                _LEN_ADCS_AD_PAYLOAD,
                0 if ub is None else len(ub),
            )
            return {}
        # Sol
        (sun_valid_ad,) = struct.unpack_from(f"{_E}B", ub, 24)
        (fss_valid,) = struct.unpack_from(f"{_E}B", ub, 25)
        # Imu (wbn at off 50 + 1 + 8 + 1 + 24 = 84, acc at 84+24 = 108)
        wbn = struct.unpack_from(f"{_E}3d", ub, 84)
        acc = struct.unpack_from(f"{_E}3d", ub, 108)
        # ST
        (st_valid,) = struct.unpack_from(f"{_E}B", ub, 132)
        st_qbn = struct.unpack_from(f"{_E}4d", ub, 133)
        return {
            # 모듈 1 PhysicalConsistency 가 사용
            "ST_VALID": int(st_valid) & 0xFF,
            "ST_QBN_0": float(st_qbn[0]),
            "ST_QBN_1": float(st_qbn[1]),
            "ST_QBN_2": float(st_qbn[2]),
            "ST_QBN_3": float(st_qbn[3]),
            "IMU_WBN_X": float(wbn[0]),
            "IMU_WBN_Y": float(wbn[1]),
            "IMU_WBN_Z": float(wbn[2]),
            "IMU_ACC_X": float(acc[0]),
            "IMU_ACC_Y": float(acc[1]),
            "IMU_ACC_Z": float(acc[2]),
            # GNC.SunValid 와 별도. AD 단계에서의 유효성. 디버그용 internal.
            "_AD_SUN_VALID": int(sun_valid_ad) & 0xFF,
            "_AD_FSS_VALID": int(fss_valid) & 0xFF,
        }
    except struct.error as e:
        logger.error("ADCS AD struct 오류: %s", e)
        return {}
    except (IndexError, MemoryError) as e:
        logger.error("ADCS AD 파싱 실패(Index/Memory): %s", e)
        return {}
    except Exception as e:
        logger.error("ADCS AD 파싱 실패: %s", e)
        return {}


# ===========================================================================
# ADCS AC (0x0944) — Generic_ADCS_AC_Tlm_Payload_t (497B)
# ===========================================================================
def _parse_adcs_ac(full_packet: bytes) -> dict[str, Any]:
    """
    구조체:
      Bdot:     b_range(8), Kb(8), bold[3](24), bdot[3](24)                    = 64
      Sunsafe:  Kp[3], Kr[3], sside[3], vmax, cmd_wbn[3], h_mgmt(1),
                therr[3], werr[3], Tcmd[3], err_t                              = 185
      Inertial: Kp[3], Kr[3], Ki[3], phiErr_max, qbn_cmd[4], h_mgmt(8=long),
                therr[3], sumtherr[3], qErr[4], werr[3], Tcmd[3]               = 248

    SUNSAFE 모드일 때의 명령 산출이 핵심(현재 캡처 ADCS_MODE=2). Inertial 도 보조 추출.
    """
    try:
        ub = cfe_tlm_user_bytes(full_packet)
        if ub is None or len(ub) < _LEN_ADCS_AC_PAYLOAD:
            logger.warning(
                "ADCS AC 페이로드 길이 부족: need>=%s have=%s",
                _LEN_ADCS_AC_PAYLOAD,
                0 if ub is None else len(ub),
            )
            return {}

        # === Bdot (off 0..63) — bdot[3] 위치 = 8+8+24 = 40 ===
        bdot = struct.unpack_from(f"{_E}3d", ub, 40)

        # === Sunsafe (off 64..248) ===
        ss_off = 64
        # cmd_wbn: Kp(24)+Kr(24)+sside(24)+vmax(8) = 80 → off ss_off + 80
        cmd_wbn = struct.unpack_from(f"{_E}3d", ub, ss_off + 80)
        # h_mgmt(1) 직후: off ss_off + 80 + 24 = ss_off + 104
        (h_mgmt_ss,) = struct.unpack_from(f"{_E}B", ub, ss_off + 104)
        # therr: off ss_off + 105
        therr = struct.unpack_from(f"{_E}3d", ub, ss_off + 105)
        # werr: off ss_off + 129
        werr = struct.unpack_from(f"{_E}3d", ub, ss_off + 129)
        # Tcmd(sunsafe): off ss_off + 153 — 참고용
        # err_t: off ss_off + 177 — 단일 double, 참고용

        return {
            # SAT_ADCS_FILTER 매핑
            "BDOT_X": float(bdot[0]),
            "BDOT_Y": float(bdot[1]),
            "BDOT_Z": float(bdot[2]),
            "CMD_WBN_X": float(cmd_wbn[0]),
            "CMD_WBN_Y": float(cmd_wbn[1]),
            "CMD_WBN_Z": float(cmd_wbn[2]),
            "H_MGMTON": int(h_mgmt_ss) & 0xFF,
            "THERR_X": float(therr[0]),
            "THERR_Y": float(therr[1]),
            "THERR_Z": float(therr[2]),
            "WERR_X": float(werr[0]),
            "WERR_Y": float(werr[1]),
            "WERR_Z": float(werr[2]),
        }
    except struct.error as e:
        logger.error("ADCS AC struct 오류: %s", e)
        return {}
    except (IndexError, MemoryError) as e:
        logger.error("ADCS AC 파싱 실패(Index/Memory): %s", e)
        return {}
    except Exception as e:
        logger.error("ADCS AC 파싱 실패: %s", e)
        return {}


# ===========================================================================
# ADCS DI (0x0941) — Generic_ADCS_DI_Tlm_Payload_t (668B)
# ===========================================================================
def _parse_adcs_di(full_packet: bytes) -> dict[str, Any]:
    """
    구조체:
      Mag: qbs[4](32) + bvb[3](24)                                         (56)  off 0
      Fss: qbs[4](32) + valid(1) + svb[3](24)                              (57)  off 56
      Css: Sensor[6] (each 40B = 240) + valid(1) + svb[3](24)              (265) off 113
      Imu: qbs[4](32) + pos[3](24) + valid(1) + wbn[3](24) + acc[3](24)    (105) off 378
      Rw:  whl_axis[3][3](72) + H_maxB[3](24) + HwhlB[3](24)               (120) off 483
      St:  qbs[4](32) + q[4](32) + valid(1)                                (65)  off 603

    명세 SAT_ADCS_FILTER 의 IMU_WBN/ACC, ST_VALID 는 AD 가 정사용. DI 는 raw 센서 유효성용.
    """
    try:
        ub = cfe_tlm_user_bytes(full_packet)
        if ub is None or len(ub) < _LEN_ADCS_DI_PAYLOAD:
            logger.warning(
                "ADCS DI 페이로드 길이 부족: need>=%s have=%s",
                _LEN_ADCS_DI_PAYLOAD,
                0 if ub is None else len(ub),
            )
            return {}
        # 핵심 validity 만 추출 (위변조 탐지에 의미 있는 신호)
        (fss_valid,) = struct.unpack_from(f"{_E}B", ub, 56 + 32)        # 88
        (css_valid,) = struct.unpack_from(f"{_E}B", ub, 113 + 240)      # 353
        (imu_valid,) = struct.unpack_from(f"{_E}B", ub, 378 + 56)       # 434
        (st_valid,) = struct.unpack_from(f"{_E}B", ub, 603 + 64)        # 667
        return {
            "_DI_FSS_VALID": int(fss_valid) & 0xFF,
            "_DI_CSS_VALID": int(css_valid) & 0xFF,
            "_DI_IMU_VALID": int(imu_valid) & 0xFF,
            "_DI_ST_VALID": int(st_valid) & 0xFF,
        }
    except struct.error as e:
        logger.error("ADCS DI struct 오류: %s", e)
        return {}
    except (IndexError, MemoryError) as e:
        logger.error("ADCS DI 파싱 실패(Index/Memory): %s", e)
        return {}
    except Exception as e:
        logger.error("ADCS DI 파싱 실패: %s", e)
        return {}


# ===========================================================================
# ADCS DO (0x0945) — Generic_ADCS_DO_Tlm_Payload_t (152B)
# ===========================================================================
def _parse_adcs_do(full_packet: bytes) -> dict[str, Any]:
    """
    구조체:
      Trq: qba[4](32) + Mcmd[3](24)            (56)  off 0
      Rw:  axis[3][3](72) + Tcmd[3](24)        (96)  off 56

    GNC.Mcmd/Tcmd 가 우선 소스라 DO 는 길이 검증 + 디버그 필드만 추출.
    """
    try:
        ub = cfe_tlm_user_bytes(full_packet)
        if ub is None or len(ub) < _LEN_ADCS_DO_PAYLOAD:
            logger.warning(
                "ADCS DO 페이로드 길이 부족: need>=%s have=%s",
                _LEN_ADCS_DO_PAYLOAD,
                0 if ub is None else len(ub),
            )
            return {}
        trq_mcmd = struct.unpack_from(f"{_E}3d", ub, 32)
        rw_tcmd = struct.unpack_from(f"{_E}3d", ub, 56 + 72)
        return {
            "_DO_TRQ_MCMD_X": float(trq_mcmd[0]),
            "_DO_TRQ_MCMD_Y": float(trq_mcmd[1]),
            "_DO_TRQ_MCMD_Z": float(trq_mcmd[2]),
            "_DO_RW_TCMD_X": float(rw_tcmd[0]),
            "_DO_RW_TCMD_Y": float(rw_tcmd[1]),
            "_DO_RW_TCMD_Z": float(rw_tcmd[2]),
        }
    except struct.error as e:
        logger.error("ADCS DO struct 오류: %s", e)
        return {}
    except (IndexError, MemoryError) as e:
        logger.error("ADCS DO 파싱 실패(Index/Memory): %s", e)
        return {}
    except Exception as e:
        logger.error("ADCS DO 파싱 실패: %s", e)
        return {}


# ===========================================================================
# ADCS HK (0x0940) — Generic_ADCS_Hk_tlm_t
# ===========================================================================
def _parse_adcs_hk(full_packet: bytes) -> dict[str, Any]:
    """CommandErrorCount(1) + CommandCount(1) — 명세 CMDCOUNTER 후보."""
    try:
        ub = cfe_tlm_user_bytes(full_packet)
        if ub is None or len(ub) < 2:
            return {}
        cmd_err, cmd_cnt = struct.unpack_from(f"{_E}BB", ub, 0)
        return {
            "_ADCS_HK_CMD_ERR": int(cmd_err) & 0xFF,
            "_ADCS_HK_CMD_CNT": int(cmd_cnt) & 0xFF,
        }
    except struct.error as e:
        logger.error("ADCS HK struct 오류: %s", e)
        return {}
    except (IndexError, MemoryError) as e:
        logger.error("ADCS HK 파싱 실패(Index/Memory): %s", e)
        return {}
    except Exception as e:
        logger.error("ADCS HK 파싱 실패: %s", e)
        return {}


# ===========================================================================
# 라우팅
# ===========================================================================
def parse_adcs_tlm(mid: int, full_packet: bytes) -> dict[str, Any]:
    """ADCS 텔레메트리 → SAT_TLM_CURRENT / SAT_ADCS_FILTER 컬럼 부분집합."""
    try:
        if mid == demon_config.GENERIC_ADCS_GNC_MID:
            return _parse_adcs_gnc(full_packet)
        if mid == demon_config.GENERIC_ADCS_DI_MID:
            return _parse_adcs_di(full_packet)
        if mid == demon_config.GENERIC_ADCS_AD_MID:
            return _parse_adcs_ad(full_packet)
        if mid == demon_config.GENERIC_ADCS_AC_MID:
            return _parse_adcs_ac(full_packet)
        if mid == demon_config.GENERIC_ADCS_DO_MID:
            return _parse_adcs_do(full_packet)
        if mid == demon_config.GENERIC_ADCS_HK_TLM_MID:
            return _parse_adcs_hk(full_packet)
        return {}
    except Exception as e:
        logger.error("parse_adcs_tlm 실패: %s", e)
        return {}


def parse_imu_tlm(mid: int, full_packet: bytes) -> dict[str, Any]:
    """IMU 텔레메트리(추후 WBN 등 매핑). 현재 ADCS AD/GNC 에서 받음."""
    try:
        _ = (mid, full_packet)
        return {}
    except Exception as e:
        logger.error("parse_imu_tlm 실패: %s", e)
        return {}


def parse_mag_tlm(mid: int, full_packet: bytes) -> dict[str, Any]:
    """MAG 텔레메트리(추후 매핑). 현재 ADCS GNC.bvb 에서 받음."""
    try:
        _ = (mid, full_packet)
        return {}
    except Exception as e:
        logger.error("parse_mag_tlm 실패: %s", e)
        return {}


# ===========================================================================
# MGR HK (0x08F8) — MGR_Hk_tlm_t → SpacecraftMode → SAT_TLM_CURRENT.MISSION_MODE
# ===========================================================================
def parse_mgr_hktlm(full_packet: bytes) -> dict[str, Any]:
    """
    MGR_Hk_tlm_t 사용자 영역 레이아웃:
      offset 0 : CommandErrorCount (uint8)
      offset 1 : CommandCount      (uint8)
      offset 2 : SpacecraftMode    (uint8)   ← MISSION_MODE 원본
    """
    try:
        ub = cfe_tlm_user_bytes(full_packet)
        if ub is None or len(ub) <= demon_config.MGR_HKTLM_SPACECRAFT_MODE_OFFSET:
            logger.warning(
                "MGR HK 페이로드 길이 부족: have=%s need>%s",
                0 if ub is None else len(ub),
                demon_config.MGR_HKTLM_SPACECRAFT_MODE_OFFSET,
            )
            return {}
        mode = ub[demon_config.MGR_HKTLM_SPACECRAFT_MODE_OFFSET]
        return {"MISSION_MODE": int(mode) & 0xFF}
    except (IndexError, MemoryError) as e:
        logger.error("MGR HK 파싱 실패(Index/Memory): %s", e)
        return {}
    except Exception as e:
        logger.error("MGR HK 파싱 실패: %s", e)
        return {}


# ===========================================================================
# 유틸
# ===========================================================================
def _strip_internal_keys(d: dict[str, Any]) -> dict[str, Any]:
    """DB 갱신 화이트리스트에 없는 내부 키('_'로 시작) 제거. 로그에는 별도 노출 가능."""
    try:
        return {k: v for k, v in d.items() if not k.startswith("_")}
    except Exception as e:
        logger.error("dict 내부 키 정리 실패: %s", e)
        return {}


# ===========================================================================
# 모듈 로드 시 길이 selftest — generic_adcs_msg.h 와 일치 검증
# ===========================================================================
def _selftest_payload_sizes() -> None:
    try:
        di_fmt = (
            _E
            + "4d3d"                     # Mag.qbs[4] + bvb[3]
            + "4d" + "B" + "3d"          # Fss.qbs[4] + valid + svb[3]
            + ("3dd" + "d") * 6          # Css.Sensor[6]: axis[3] + scale + percenton
            + "B" + "3d"                 # Css.valid + svb[3]
            + "4d3dB3d3d"                # Imu.qbs[4] + pos[3] + valid + wbn[3] + acc[3]
            + "9d" + "3d3d"              # Rw.whl_axis[3][3] + H_maxB[3] + HwhlB[3]
            + "4d4dB"                    # St.qbs[4] + q[4] + valid
        )
        ad_fmt = (
            _E
            + "3d"                       # Mag.bvb[3]
            + "BB3d"                     # Sol.SunValid + FssValid + svb[3]
            + "Bd" + "B" + "3d3d3d"      # Imu.init + alpha + valid + wbn_prev + wbn + acc
            + "B4d"                      # ST.Valid + qbn[4]
        )
        gnc_fmt = (
            _E
            + "2d" + "BB"                # DT, MaxMcmd, Mode, HmgmtOn
            + "4d3B3d"                   # Hmgmt: Kb,b_range,loFrac,hiFrac + mm_active[3] + Mcmd[3]
            + "3d3d" + "B"               # bvb, svb, SunValid
            + "3d3d3d3d3d"               # wbn, HwhlMaxB, HwhlB, Mcmd, Tcmd
            + "B4d4d"                    # qValid, qbn[4], qErr[4]
        )
        ac_fmt = (
            _E
            + "dd3d3d"                                  # Bdot
            + "3d3d3ddB3d3d3dd" + "3d3d"                # Sunsafe (Kp,Kr,sside,vmax,h_mgmt(1),therr,werr,Tcmd,err_t + cmd_wbn 위치 보정)
        )
        # Sunsafe 순서가 헤더 정의와 일치하도록 수동 재구성:
        ac_fmt = (
            _E
            + "dd3d3d"                                  # Bdot: b_range, Kb, bold[3], bdot[3] = 64
            + "3d3d3d" + "d" + "3d" + "B"               # Sunsafe: Kp[3],Kr[3],sside[3], vmax, cmd_wbn[3], h_mgmt(1)
            + "3d3d3d" + "d"                            # Sunsafe: therr[3], werr[3], Tcmd[3], err_t
            + "3d3d3d" + "d" + "4d" + "q"               # Inertial: Kp,Kr,Ki, phiErr_max, qbn_cmd[4], h_mgmt(long=8B on ARM64)
            + "3d3d4d3d3d"                              # Inertial: therr, sumtherr, qErr[4], werr, Tcmd
        )
        do_fmt = (
            _E
            + "4d3d"                     # Trq.qba[4] + Mcmd[3]
            + "9d3d"                     # Rw.axis[3][3] + Tcmd[3]
        )

        checks = [
            ("DI", di_fmt, _LEN_ADCS_DI_PAYLOAD),
            ("AD", ad_fmt, _LEN_ADCS_AD_PAYLOAD),
            ("GNC", gnc_fmt, _LEN_ADCS_GNC_PAYLOAD),
            ("AC", ac_fmt, _LEN_ADCS_AC_PAYLOAD),
            ("DO", do_fmt, _LEN_ADCS_DO_PAYLOAD),
        ]
        for name, fmt, expect in checks:
            actual = struct.calcsize(fmt)
            if actual != expect:
                logger.error("ADCS %s 길이 selftest 실패: calc=%s expect=%s", name, actual, expect)
    except struct.error as e:
        logger.error("ADCS 길이 selftest struct 오류: %s", e)
    except Exception as e:
        logger.error("ADCS 길이 selftest 실패: %s", e)


_selftest_payload_sizes()
