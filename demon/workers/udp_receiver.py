from __future__ import annotations

import logging
import socket
import struct
import threading
from typing import Any

from .. import config as demon_config
from ..core.context import RuntimeContext
from ..db.db_manager import DBManager
from . import tlm_parse_nos3

logger = logging.getLogger(__name__)


def _application_zone(data_field: bytes, sec_hdr_flag: int) -> bytes:
    """CCSDS 데이터 필드에서 cFE 2차 헤더(있으면) 제거 후 앱 텔레메트리 영역."""
    try:
        if sec_hdr_flag:
            n = demon_config.CFE_TLM_SEC_HDR_BYTES
            if len(data_field) < n:
                return b""
            return data_field[n:]
        return data_field
    except (IndexError, MemoryError) as e:
        logger.error("application_zone 실패(Index/Memory): %s", e)
        return b""
    except Exception as e:
        logger.error("application_zone 실패: %s", e)
        return b""


def _derive_mid_from_ccsds_packet(pkt: bytes) -> int | None:
    """단일 CCSDS 패킷에서 MID_DERIVE_MODE에 따라 MsgId/StreamId 산출."""
    try:
        need_hdr = demon_config.CCSDS_PRIMARY_HEADER_BYTES
        if len(pkt) < need_hdr + 1:
            return None
        w0 = (pkt[0] << 8) | pkt[1]
        w2 = (pkt[4] << 8) | pkt[5]
        sec_hdr_flag = (w0 >> 11) & 0x1
        apid = w0 & 0x7FF
        pdl = w2 & 0xFFFF
        total = need_hdr + pdl + 1
        if len(pkt) < total:
            return None
        payload = bytes(pkt[need_hdr:total])
        if demon_config.MID_DERIVE_MODE == "stream_id":
            return int((pkt[0] << 8) | pkt[1])
        if demon_config.MID_DERIVE_MODE == "payload_u16":
            app = _application_zone(payload, sec_hdr_flag)
            if len(app) < 2:
                return None
            return int(struct.unpack(demon_config.CFE_SB_STREAMID_STRUCT, app[0:2])[0])
        return int(apid)
    except struct.error as e:
        logger.error("MID 산출 struct 오류: %s", e)
        return None
    except (IndexError, MemoryError) as e:
        logger.error("MID 산출 실패(Index/Memory): %s", e)
        return None
    except Exception as e:
        logger.error("MID 산출 실패: %s", e)
        return None


def parse_all_ccsds_packets(data: bytes) -> list[tuple[int, bytes]]:
    """
    UDP 페이로드에서 CCSDS 패킷 여러 개 추출.

    각 프레임마다 MID_DERIVE_MODE로 MID를 산출해 (mid, 단일 CCSDS 패킷)으로 반환한다.
    """
    try:
        packets: list[tuple[int, bytes]] = []
        offset = 0
        need = demon_config.CCSDS_PRIMARY_HEADER_BYTES
        while offset + need <= len(data):
            pdl = (data[offset + 4] << 8) | data[offset + 5]
            total = need + pdl + 1
            if offset + total > len(data):
                break
            pkt = bytes(data[offset : offset + total])
            mid = _derive_mid_from_ccsds_packet(pkt)
            if mid is not None:
                packets.append((mid, pkt))
            offset += total
        return packets
    except (IndexError, MemoryError) as e:
        logger.error("parse_all_ccsds_packets 실패(Index/Memory): %s", e)
        return []
    except Exception as e:
        logger.error("parse_all_ccsds_packets 실패: %s", e)
        return []


def _format_parsed_fields(fields: dict[str, Any]) -> str:
    """로그용 짧은 필드 나열."""
    try:
        if not fields:
            return "(no mapped fields)"
        parts: list[str] = []
        for k in sorted(fields):
            v = fields[k]
            if isinstance(v, float):
                parts.append(f"{k}={v:.6g}")
            else:
                parts.append(f"{k}={v}")
        return " ".join(parts)
    except Exception as e:
        logger.error("파싱 필드 포맷 실패: %s", e)
        return "(format error)"


class UDPReceiver:
    """
    cFS TO_LAB CCSDS 텔레메트리 UDP 수신.
    설계: udp_receiver_thread → parse_all_ccsds_packets → dispatch_tlm(각 프레임) → 파서.
    """

    def __init__(self, ctx: RuntimeContext) -> None:
        self._ctx = ctx
        self._mission_mode: int = 0
        self._mission_lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._logged_first_ok_packet: bool = False
        # ADCS DI/AD/GNC/AC/DO 파싱 결과 최신값 캐시.
        # AnomalyDetector 가 이상 감지 시 이 캐시를 SAT_ADCS_FILTER 에 INSERT 한다.
        self._latest_adcs_data: dict[str, Any] = {}
        self._adcs_lock = threading.Lock()
        # SAT_TLM_CURRENT flush 전까지 merge (DO 0x0945 수신 시 1회 DB 반영)
        self._tlm_pending: dict[str, Any] = {}
        self._tlm_pending_lock = threading.Lock()

    def run(self) -> None:
        """스레드 진입점 — 설계상 `udp_receiver_thread`와 동일 역할."""
        try:
            self.udp_receiver_thread()
        except Exception as e:
            logger.error("UDPReceiver run 실패: %s", e)

    def udp_receiver_thread(self) -> None:
        try:
            host, port = self._ctx.config.udp_tlm_bind
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except OSError as e:
                logger.warning("SO_REUSEADDR 설정 실패(OSError): %s", e)
            except Exception as e:
                logger.error("SO_REUSEADDR 설정 실패: %s", e)
            sock.bind((host, port))
            sock.settimeout(0.5)
            self._sock = sock
            logger.info("UDPReceiver bound %s:%s", host, port)
            while not self._ctx.shutdown_event.is_set():
                try:
                    data, addr = sock.recvfrom(demon_config.UDP_RECV_BUFFER_BYTES)
                except socket.timeout:
                    continue
                except OSError as e:
                    if self._ctx.shutdown_event.is_set():
                        break
                    logger.error("UDP recv 실패(OSError): %s", e)
                    continue
                except Exception as e:
                    logger.error("UDP recv 실패: %s", e)
                    continue
                packet_list = parse_all_ccsds_packets(data)
                if not packet_list:
                    continue
                if not self._logged_first_ok_packet:
                    try:
                        mid0, pkt0 = packet_list[0]
                        need = demon_config.CCSDS_PRIMARY_HEADER_BYTES
                        w2 = (pkt0[4] << 8) | pkt0[5]
                        pdl = w2 & 0xFFFF
                        payload_len = pdl + 1
                        logger.info(
                            "telemetry: first CCSDS OK from %s mid=%d (0x%04x) "
                            "udp_bytes=%s frames=%s first_frame_bytes=%s first_payload_bytes=%s",
                            addr,
                            mid0,
                            mid0,
                            len(data),
                            len(packet_list),
                            len(pkt0),
                            payload_len,
                        )
                        self._logged_first_ok_packet = True
                    except Exception as e:
                        logger.error("첫 텔레메트리 로그 실패: %s", e)
                for mid, pkt in packet_list:
                    try:
                        self._dispatch_tlm(mid, pkt)
                    except TypeError as e:
                        logger.error("dispatch_tlm 인자 오류: %s", e)
                    except Exception as e:
                        logger.error("dispatch_tlm 실패: %s", e)
        except OSError as e:
            logger.error("UDP 소켓 바인드/수신 실패(OSError): %s", e)
        except Exception as e:
            logger.error("udp_receiver_thread 실패: %s", e)
        finally:
            self._close_socket_safely()
            self._sock = None
            logger.info("UDPReceiver stopped")

    def _dispatch_tlm(self, mid: int, full_packet: bytes) -> None:
        """MID로 MGR / SC / ADCS / IMU / MAG / 일반 텔레메트리 분기 후 SAT_TLM_CURRENT 반영."""
        try:
            if demon_config.MID_MISSION_MODE_TLM and mid in demon_config.MID_MISSION_MODE_TLM:
                mm = tlm_parse_nos3.parse_mgr_mission_mode(full_packet)
                self._log_parsed_telemetry(
                    mid,
                    "mgr",
                    {} if mm < 0 else {"MISSION_MODE": mm},
                    note="" if mm >= 0 else "spacecraft_mode parse failed",
                )
                if mm is not None and mm >= 0:
                    with self._mission_lock:
                        self._mission_mode = mm
                    self._merge_tlm_pending({"MISSION_MODE": mm})
            elif demon_config.MID_SC_HKTLM and mid in demon_config.MID_SC_HKTLM:
                self._log_parsed_telemetry(mid, "sc", {}, note="SC HK counters only")
            elif demon_config.MID_ADCS_TLM and mid in demon_config.MID_ADCS_TLM:
                adcs = tlm_parse_nos3.parse_adcs_tlm(mid, full_packet)
                self._log_parsed_telemetry(mid, "adcs", adcs)
                if adcs:
                    self._merge_tlm_pending(adcs)
                    with self._adcs_lock:
                        self._latest_adcs_data.update(adcs)
                    if mid == demon_config.TLM_DB_FLUSH_TRIGGER_MID:
                        self._flush_tlm_pending_to_db()
            elif demon_config.MID_IMU_TLM and mid in demon_config.MID_IMU_TLM:
                imu = tlm_parse_nos3.parse_imu_tlm(mid, full_packet)
                self._log_parsed_telemetry(mid, "imu", imu)
                if imu:
                    self._merge_tlm_pending(imu)
            elif demon_config.MID_MAG_TLM and mid in demon_config.MID_MAG_TLM:
                mag = tlm_parse_nos3.parse_mag_tlm(mid, full_packet)
                self._log_parsed_telemetry(mid, "mag", mag)
                if mag:
                    self._merge_tlm_pending(mag)
            else:
                try:
                    if demon_config.LOG_UNREGISTERED_TLM:
                        logger.info(
                            "tlm unregistered mid=0x%04x total_bytes=%s",
                            mid,
                            len(full_packet),
                        )
                except Exception as e:
                    logger.error("tlm unregistered 로그 실패: %s", e)
        except Exception as e:
            logger.error("dispatch_tlm 실패: %s", e)

    def _log_parsed_telemetry(
        self,
        mid: int,
        route: str,
        fields: dict[str, Any],
        note: str = "",
    ) -> None:
        """파싱 결과를 INFO로 출력."""
        try:
            if not demon_config.LOG_PARSED_TLM:
                return
            body = _format_parsed_fields(fields)
            suffix = f" | {note}" if note else ""
            logger.info("tlm parsed mid=0x%04x route=%s %s%s", mid, route, body, suffix)
        except Exception as e:
            logger.error("tlm parsed 로그 실패: %s", e)

    def _close_socket_safely(self) -> None:
        """UDP 소켓 안전 close. finally 절에서 호출."""
        if self._sock is None:
            return
        try:
            self._sock.close()
        except OSError as e:
            logger.error("UDP 소켓 close 실패(OSError): %s", e)
        except Exception as e:
            logger.error("UDP 소켓 close 실패: %s", e)

    def get_latest_adcs_data(self) -> dict[str, Any]:
        """
        AnomalyDetector 가 이상 감지 시점에 호출.
        DI/AD/GNC/AC/DO 에서 누적된 최신 ADCS 필드의 shallow copy 반환.
        """
        try:
            with self._adcs_lock:
                return dict(self._latest_adcs_data)
        except Exception as e:
            logger.error("get_latest_adcs_data 실패: %s", e)
            return {}

    def get_mission_mode(self) -> int:
        """
        현재 MISSION_MODE 반환.

        MGR HK 는 DO flush 전 pending 에만 있을 수 있어 메모리 캐시 우선,
        미수신(0)이면 DB fallback.
        """
        try:
            with self._mission_lock:
                if self._mission_mode != 0:
                    return int(self._mission_mode)
            return self._ctx.db.get_mission_mode()
        except Exception as e:
            logger.error("get_mission_mode 실패: %s", e)
            return 0

    def _merge_tlm_pending(self, fields: dict[str, Any]) -> None:
        """SAT_TLM_CURRENT 화이트리스트 필드만 pending 에 merge."""
        try:
            filtered = DBManager.filter_tlm_current_fields(fields)
            if not filtered:
                return
            with self._tlm_pending_lock:
                self._tlm_pending.update(filtered)
        except Exception as e:
            logger.error("_merge_tlm_pending 실패: %s", e)

    def _flush_tlm_pending_to_db(self) -> None:
        """ADCS DO(0x0945) 수신 후 pending → SAT_TLM_CURRENT 1회 반영 + ADCS 스냅샷 누적."""
        try:
            with self._tlm_pending_lock:
                snapshot = dict(self._tlm_pending)
            if not snapshot:
                return
            if not self._ctx.db.upsert_tlm_current(snapshot):
                return
            tlm_row = self._ctx.db.get_tlm_current()
            if tlm_row is not None:
                self._ctx.db.insert_tlm_history(tlm_row)
            with self._adcs_lock:
                adcs_snapshot = dict(self._latest_adcs_data)
            if adcs_snapshot:
                if not self._ctx.db.insert_adcs_filter(adcs_snapshot):
                    logger.warning("ADCS 주기 스냅샷 insert_adcs_filter 실패")
        except Exception as e:
            logger.error("_flush_tlm_pending_to_db 실패: %s", e)
