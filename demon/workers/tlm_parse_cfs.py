"""
NOS3 cFE / cFS 앱 HK 텔레메트리 파싱.

참조: nos3/gsw/cosmos/config/targets/CFS/cmd_tlm/*.txt
      nos3/fsw/cfe/modules/*/config/default_cfe_*_msgstruct.h
"""
from __future__ import annotations

import logging
import struct
from typing import Any

from .. import config as demon_config
from .tlm_parse_nos3 import cfe_tlm_user_bytes

logger = logging.getLogger(__name__)

_E = demon_config.TLM_STRUCT_ENDIAN


def parse_ccsds_seconds(full_packet: bytes) -> int | None:
    """CCSDS 2차 헤더 Seconds — OBC_S_TICK 보조."""
    try:
        need = demon_config.CCSDS_PRIMARY_HEADER_BYTES
        if len(full_packet) < need + 4:
            return None
        w0 = (full_packet[0] << 8) | full_packet[1]
        sec_hdr_flag = (w0 >> 11) & 0x1
        if not sec_hdr_flag:
            return None
        (seconds,) = struct.unpack_from(">I", full_packet, need)
        return int(seconds)
    except struct.error as e:
        logger.error("parse_ccsds_seconds struct 오류: %s", e)
        return None
    except (IndexError, MemoryError) as e:
        logger.error("parse_ccsds_seconds 실패(Index/Memory): %s", e)
        return None
    except Exception as e:
        logger.error("parse_ccsds_seconds 실패: %s", e)
        return None


def _parse_es_hk(full_packet: bytes) -> dict[str, Any]:
    """CFE_ES_HKPACKET (0x0800)."""
    try:
        ub = cfe_tlm_user_bytes(full_packet)
        if ub is None or len(ub) < 144:
            return {}
        off = 20
        syslog_entries = struct.unpack_from(f"{_E}I", ub, off + 8)[0]
        erlog_entries = struct.unpack_from(f"{_E}I", ub, off + 20)[0]
        processor_resets = struct.unpack_from(f"{_E}I", ub, off + 48)[0]
        heap_free = struct.unpack_from(f"{_E}I", ub, 140)[0]
        return {
            "HEAP_FREE": int(heap_free),
            "SYSLOGENTRIES": int(syslog_entries),
            "ERLOGENTRIES": int(erlog_entries),
            "RESETSPERFORMED": int(processor_resets),
        }
    except struct.error as e:
        logger.error("ES HK struct 오류: %s", e)
        return {}
    except Exception as e:
        logger.error("ES HK 파싱 실패: %s", e)
        return {}


def _parse_sb_hk(full_packet: bytes) -> dict[str, Any]:
    """CFE_SB_HKMSG (0x0803) — PIPEOVERFLOW는 이벤트용, ADCS 미포함."""
    try:
        ub = cfe_tlm_user_bytes(full_packet)
        if ub is None or len(ub) < 14:
            return {}
        pipe_overflow = struct.unpack_from(f"{_E}H", ub, 12)[0]
        if pipe_overflow:
            return {"_SB_PIPEOVERFLOW": int(pipe_overflow)}
        return {}
    except struct.error as e:
        logger.error("SB HK struct 오류: %s", e)
        return {}
    except Exception as e:
        logger.error("SB HK 파싱 실패: %s", e)
        return {}


def _parse_tbl_hk(full_packet: bytes) -> dict[str, Any]:
    """CFE_TBL_HKPACKET (0x0804)."""
    try:
        ub = cfe_tlm_user_bytes(full_packet)
        if ub is None or len(ub) < 12:
            return {}
        lastval_crc = struct.unpack_from(f"{_E}I", ub, 8)[0]
        return {"LASTVALCRC": f"{int(lastval_crc):08X}"}
    except struct.error as e:
        logger.error("TBL HK struct 오류: %s", e)
        return {}
    except Exception as e:
        logger.error("TBL HK 파싱 실패: %s", e)
        return {}


def _parse_time_hk(full_packet: bytes) -> dict[str, Any]:
    """CFE_TIME_HKPACKET (0x0805) — MET seconds → OBC_S_TICK."""
    try:
        ub = cfe_tlm_user_bytes(full_packet)
        if ub is None or len(ub) < 12:
            return {}
        seconds_met = struct.unpack_from(f"{_E}I", ub, 8)[0]
        return {"OBC_S_TICK": int(seconds_met)}
    except struct.error as e:
        logger.error("TIME HK struct 오류: %s", e)
        return {}
    except Exception as e:
        logger.error("TIME HK 파싱 실패: %s", e)
        return {}


def _parse_to_hk(full_packet: bytes) -> dict[str, Any]:
    """TO HK (0x0880) — ENABLEDROUTES."""
    try:
        ub = cfe_tlm_user_bytes(full_packet)
        if ub is None or len(ub) < 18:
            return {}
        enabled_routes = struct.unpack_from(f"{_E}H", ub, 16)[0]
        return {"ENABLEDROUTES": int(enabled_routes)}
    except struct.error as e:
        logger.error("TO HK struct 오류: %s", e)
        return {}
    except Exception as e:
        logger.error("TO HK 파싱 실패: %s", e)
        return {}


def _parse_hk_app_hk(full_packet: bytes) -> dict[str, Any]:
    """HK HK_HKPACKET (0x089B)."""
    try:
        ub = cfe_tlm_user_bytes(full_packet)
        if ub is None or len(ub) < 6:
            return {}
        combined = struct.unpack_from(f"{_E}H", ub, 4)[0]
        return {"COMBINEDPACKETSSENT": int(combined)}
    except struct.error as e:
        logger.error("HK app HK struct 오류: %s", e)
        return {}
    except Exception as e:
        logger.error("HK app HK 파싱 실패: %s", e)
        return {}


def _parse_sch_hk(full_packet: bytes) -> dict[str, Any]:
    """SCH HK (0x0897)."""
    try:
        ub = cfe_tlm_user_bytes(full_packet)
        if ub is None or len(ub) < 22:
            return {}
        slots_processed = struct.unpack_from(f"{_E}I", ub, 12)[0]
        skipped_slots = struct.unpack_from(f"{_E}H", ub, 20)[0]
        return {
            "SKIPPEDSLOTSCOUNT": int(skipped_slots),
            "EXECOUNTS": float(slots_processed),
        }
    except struct.error as e:
        logger.error("SCH HK struct 오류: %s", e)
        return {}
    except Exception as e:
        logger.error("SCH HK 파싱 실패: %s", e)
        return {}


def _parse_md_hk(full_packet: bytes) -> dict[str, Any]:
    """MD HK (0x0890) — DWELLENABLEDMASK → DWELL_MASK."""
    try:
        ub = cfe_tlm_user_bytes(full_packet)
        if ub is None or len(ub) < 6:
            return {}
        dwell_mask = struct.unpack_from(f"{_E}H", ub, 4)[0]
        return {"DWELL_MASK": int(dwell_mask)}
    except struct.error as e:
        logger.error("MD HK struct 오류: %s", e)
        return {}
    except Exception as e:
        logger.error("MD HK 파싱 실패: %s", e)
        return {}


def _parse_cs_hk(full_packet: bytes) -> dict[str, Any]:
    """CS HK (0x08A4)."""
    try:
        ub = cfe_tlm_user_bytes(full_packet)
        if ub is None or len(ub) < 24:
            return {}
        app_cs_err = struct.unpack_from(f"{_E}H", ub, 16)[0]
        os_cs_err = struct.unpack_from(f"{_E}H", ub, 22)[0]
        return {
            "APPCSERRCOUNTER": int(app_cs_err),
            "OSCSERRCOUNTER": int(os_cs_err),
        }
    except struct.error as e:
        logger.error("CS HK struct 오류: %s", e)
        return {}
    except Exception as e:
        logger.error("CS HK 파싱 실패: %s", e)
        return {}


def _parse_ds_hk(full_packet: bytes) -> dict[str, Any]:
    """DS HK (0x08B8) — 일부 필드 LE (COSMOS 정의)."""
    try:
        ub = cfe_tlm_user_bytes(full_packet)
        if ub is None or len(ub) < 12:
            return {}
        app_enable = int(ub[6])
        file_write_err = struct.unpack_from("<H", ub, 10)[0]
        return {
            "APPENABLESTATE": app_enable,
            "_DS_FILEWRITEERR": int(file_write_err),
        }
    except struct.error as e:
        logger.error("DS HK struct 오류: %s", e)
        return {}
    except Exception as e:
        logger.error("DS HK 파싱 실패: %s", e)
        return {}


def _parse_fm_hk(full_packet: bytes) -> dict[str, Any]:
    """FM HK (0x088A) — CHILDQUEUECOUNT (이벤트 매핑용 내부 키)."""
    try:
        ub = cfe_tlm_user_bytes(full_packet)
        if ub is None or len(ub) < 8:
            return {}
        child_queue = int(ub[7])
        return {"_FM_CHILDQUEUECOUNT": child_queue}
    except Exception as e:
        logger.error("FM HK 파싱 실패: %s", e)
        return {}


def _parse_radio_hk(full_packet: bytes) -> dict[str, Any]:
    """GENERIC_RADIO HK (0x0930)."""
    try:
        ub = cfe_tlm_user_bytes(full_packet)
        if ub is None or len(ub) < 5:
            return {}
        forward_err = int(ub[4])
        return {"FORWARD_ERR_COUNT": forward_err}
    except Exception as e:
        logger.error("RADIO HK 파싱 실패: %s", e)
        return {}


def parse_cfs_hk(mid: int, full_packet: bytes) -> dict[str, Any]:
    """cFS HK MID → SAT_TLM_CURRENT / SAT_ADCS_FILTER 컬럼 부분집합."""
    try:
        parsers = {
            demon_config.CFE_ES_HK_TLM_MID: _parse_es_hk,
            demon_config.CFE_SB_HK_TLM_MID: _parse_sb_hk,
            demon_config.CFE_TBL_HK_TLM_MID: _parse_tbl_hk,
            demon_config.CFE_TIME_HK_TLM_MID: _parse_time_hk,
            demon_config.TO_HK_TLM_MID: _parse_to_hk,
            demon_config.HK_APP_HK_TLM_MID: _parse_hk_app_hk,
            demon_config.SCH_HK_TLM_MID: _parse_sch_hk,
            demon_config.MD_HK_TLM_MID: _parse_md_hk,
            demon_config.CS_HK_TLM_MID: _parse_cs_hk,
            demon_config.DS_HK_TLM_MID: _parse_ds_hk,
            demon_config.FM_HK_TLM_MID: _parse_fm_hk,
            demon_config.GENERIC_RADIO_HK_TLM_MID: _parse_radio_hk,
        }
        fn = parsers.get(mid)
        if fn is None:
            return {}
        fields = fn(full_packet)
        if not fields:
            return fields
        ccsds_sec = parse_ccsds_seconds(full_packet)
        if ccsds_sec is not None and "OBC_S_TICK" not in fields:
            fields.setdefault("_CCSDS_SECONDS", ccsds_sec)
        return fields
    except Exception as e:
        logger.error("parse_cfs_hk 실패 mid=0x%04x: %s", mid, e)
        return {}
