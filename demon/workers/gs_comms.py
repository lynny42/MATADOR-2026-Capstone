from __future__ import annotations

import json
import logging
import socket
import struct
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from .. import config as demon_config
from ..core.context import RuntimeContext

logger = logging.getLogger(__name__)

# db_manager.insert_event 확장 전까지 SAT_EVENT_QUEUE 선택 컬럼 (추가 시 자동 반영)
_OPTIONAL_EVENT_COLS: tuple[str, ...] = (
    "EXCEPTION_CODE",
    "SW_ID",
    "CHANNEL1",
    "MODULE_SCORES",
)

# config.py 에 GS_CMD_* / GS_PACKET_TYPE_* 정의 권장 — 미정의 시 아래 기본값
_DEFAULT_GS_CMD_ATTACK_SIM = "ATTACK_SIM"
_DEFAULT_GS_CMD_RECOVERY = "RECOVERY"
_DEFAULT_GS_CMD_UPDATE_THRESHOLD = "UPDATE_THRESHOLD"
_DEFAULT_GS_CMD_UPDATE_HASH = "UPDATE_HASH"
_DEFAULT_GS_CMD_ACK = "ACK"
_DEFAULT_GS_PACKET_TLM = "SAT_TLM_CURRENT"
_DEFAULT_GS_PACKET_PWR = "SAT_PWR_META"
_DEFAULT_GS_PACKET_EVENT = "SAT_EVENT_QUEUE"
_DEFAULT_GS_PACKET_INTEGRITY = "SAT_INTEGRITY_HASH"
_DEFAULT_GS_CMD_LISTEN_HOST = "0.0.0.0"
_DEFAULT_GS_CMD_LISTEN_PORT_OFFSET = 1
_DEFAULT_SOCKET_TIMEOUT_SEC = 5.0
_DEFAULT_ACK_WAIT_SEC = 3.0
_WEIGHT_MIN = 1
_WEIGHT_MAX = 100


class AnomalyDetectorLike(Protocol):
    def set_attack_mode(self, enabled: bool) -> None:
        ...


class SerialReaderLike(Protocol):
    def send_uart_command(self, cmd: str) -> bool:
        ...


class GScomms:
    """지상국(COSMOS) TCP 송수신 — 일광 윈도우 송신·커맨드 수신·오탐 결과 이벤트 등록."""

    def __init__(self, ctx: RuntimeContext) -> None:
        self._ctx = ctx
        self._anomaly_detector: AnomalyDetectorLike | None = None
        self._serial_reader: SerialReaderLike | None = None
        self._listen_sock: socket.socket | None = None
        self._recv_thread: threading.Thread | None = None
        self._last_transmit_sun_valid: bool = False

    def set_anomaly_detector(self, detector: AnomalyDetectorLike) -> None:
        try:
            self._anomaly_detector = detector
        except Exception as e:
            logger.error("set_anomaly_detector 실패: %s", e)

    def set_serial_reader(self, reader: SerialReaderLike) -> None:
        try:
            self._serial_reader = reader
        except Exception as e:
            logger.error("set_serial_reader 실패: %s", e)

    def run(self) -> None:
        """gs_comms_thread — 수신 스레드 기동 + 일광 윈도우 송신 루프."""
        logger.info("GScomms started")
        try:
            self._start_command_listener()
            poll_sec = self._gs_poll_interval_sec()
            while not self._ctx.shutdown_event.is_set():
                try:
                    self._poll_sunlight_transmit()
                except Exception as e:
                    logger.error("GScomms poll 실패: %s", e)
                if self._ctx.shutdown_event.wait(timeout=poll_sec):
                    break
        except Exception as e:
            logger.error("GScomms run 실패: %s", e)
        finally:
            self._stop_command_listener()
        logger.info("GScomms stopped")

    def insert_event(self, result: dict[str, Any]) -> int:
        """
        FalsePositiveFilter → SAT_EVENT_QUEUE INSERT.

        result: is_attack, weight(1~100), exception_code, module_scores(선택), key_set(선택) 등.
        Returns: event_id (실패 시 -1).
        """
        try:
            is_attack = self._resolve_is_attack(result)
            weight = self._parse_weight(result)
            key_set = result.get("key_set") or {}
            if not isinstance(key_set, dict):
                key_set = {}

            sw_id = int(key_set.get("sw_id", 0))
            channel1 = int(
                key_set.get(
                    "channel1",
                    demon_config.SAT_ADCS_FILTER_CHANNEL_ID,
                ),
            )
            detected_at = str(
                result.get("detected_at")
                or key_set.get("detected_at")
                or self._utc_now_iso(),
            )

            if is_attack == "Y":
                event_type = self._config_str("GS_EVENT_ATTACK_CONFIRMED", "ATTACK_CONFIRMED")
                priority = 1
            else:
                event_type = self._config_str("GS_EVENT_SEU_DETECTED", "SEU_DETECTED")
                priority = 0

            module_scores = result.get("module_scores")
            module_scores_text = ""
            if module_scores is not None:
                try:
                    module_scores_text = json.dumps(module_scores, separators=(",", ":"))
                except (TypeError, ValueError) as e:
                    logger.error("module_scores JSON 변환 실패: %s", e)
                    module_scores_text = ""

            event_payload: dict[str, Any] = {
                "DETECTED_AT": detected_at,
                "TIMESTAMP": detected_at,
                "EVENT_TYPE": event_type,
                "PRIORITY": priority,
                "IS_SENT": 0,
                "EXCEPTION_CODE": int(result.get("exception_code", 0)),
                "SW_ID": sw_id,
                "CHANNEL1": channel1,
                "MODULE_SCORES": module_scores_text,
            }

            event_id = self._db_insert_event_flexible(event_payload)
            if event_id < 0:
                logger.error("insert_event DB 실패 is_attack=%s", is_attack)
                return -1

            logger.info(
                "오탐필터 이벤트 INSERT event_id=%s type=%s weight=%s sw_id=%s",
                event_id,
                event_type,
                weight,
                sw_id,
            )
            return event_id
        except (ValueError, TypeError) as e:
            logger.error("insert_event 입력 오류: %s", e)
            return -1
        except Exception as e:
            logger.error("insert_event 실패: %s", e)
            return -1

    def transmit_all(self) -> None:
        """교신 윈도우 — tlm → pwr → events → integrity 순차 송신."""
        try:
            self.transmit_tlm()
            self.transmit_pwr_meta()
            self.transmit_event_queue()
            self.transmit_integrity()
        except Exception as e:
            logger.error("transmit_all 실패: %s", e)

    def transmit_tlm(self) -> None:
        """SAT_TLM_CURRENT 1행 송신."""
        try:
            row = self._ctx.db.get_tlm_current()
            if not row:
                return
            payload = {
                "packet_type": self._config_str("GS_PACKET_TYPE_TLM", _DEFAULT_GS_PACKET_TLM),
                "data": row,
            }

            def on_ack(_ack: dict[str, Any]) -> None:
                logger.info("SAT_TLM_CURRENT 송신 ACK 수신")

            self.send_with_retry(payload, on_ack)
        except Exception as e:
            logger.error("transmit_tlm 실패: %s", e)

    def transmit_pwr_meta(self) -> None:
        """SAT_PWR_META 전 채널 배열 송신 — ACK 시 카운터 초기화."""
        try:
            channels = self._ctx.db.get_pwr_meta_all()
            if not channels:
                return
            payload = {
                "packet_type": self._config_str("GS_PACKET_TYPE_PWR", _DEFAULT_GS_PACKET_PWR),
                "channels": channels,
            }

            def on_ack(_ack: dict[str, Any]) -> None:
                self._reset_pwr_meta_counters()

            self.send_with_retry(payload, on_ack)
        except Exception as e:
            logger.error("transmit_pwr_meta 실패: %s", e)

    def transmit_event_queue(self) -> None:
        """미전송 이벤트 개별 순차 송신 — ACK 시 delete_event."""
        try:
            pending = self._ctx.db.get_pending_events()
            for event in pending:
                event_id = int(event.get("EVENT_ID", -1))
                if event_id < 0:
                    continue
                payload = {
                    "packet_type": self._config_str(
                        "GS_PACKET_TYPE_EVENT",
                        _DEFAULT_GS_PACKET_EVENT,
                    ),
                    "event": event,
                }
                captured_id = event_id

                def on_ack(
                    _ack: dict[str, Any],
                    eid: int = captured_id,
                ) -> None:
                    if not self._ctx.db.delete_event(eid):
                        logger.warning("delete_event 실패 event_id=%s", eid)

                if not self.send_with_retry(payload, on_ack):
                    logger.warning("이벤트 송신 실패 event_id=%s", event_id)
                    break
        except Exception as e:
            logger.error("transmit_event_queue 실패: %s", e)

    def transmit_integrity(self) -> None:
        """SAT_INTEGRITY_HASH 전체 송신 — 삭제 없음."""
        try:
            records = self._ctx.db.get_integrity_hash()
            if records is None or not records:
                return
            if isinstance(records, dict):
                records = [records]
            payload = {
                "packet_type": self._config_str(
                    "GS_PACKET_TYPE_INTEGRITY",
                    _DEFAULT_GS_PACKET_INTEGRITY,
                ),
                "records": records,
            }

            def on_ack(_ack: dict[str, Any]) -> None:
                logger.info("SAT_INTEGRITY_HASH 송신 ACK 수신")

            self.send_with_retry(payload, on_ack)
        except Exception as e:
            logger.error("transmit_integrity 실패: %s", e)

    def dispatch_command(self, cmd: dict[str, Any]) -> None:
        """지상국 커맨드 라우팅."""
        try:
            name = str(
                cmd.get("cmd") or cmd.get("command") or cmd.get("COMMAND") or "",
            ).strip().upper()
            if not name:
                logger.warning("빈 커맨드 패킷 무시")
                return

            attack_sim = self._config_str("GS_CMD_ATTACK_SIM", _DEFAULT_GS_CMD_ATTACK_SIM).upper()
            recovery = self._config_str("GS_CMD_RECOVERY", _DEFAULT_GS_CMD_RECOVERY).upper()
            update_thr = self._config_str(
                "GS_CMD_UPDATE_THRESHOLD",
                _DEFAULT_GS_CMD_UPDATE_THRESHOLD,
            ).upper()
            update_hash = self._config_str(
                "GS_CMD_UPDATE_HASH",
                _DEFAULT_GS_CMD_UPDATE_HASH,
            ).upper()
            ack_cmd = self._config_str("GS_CMD_ACK", _DEFAULT_GS_CMD_ACK).upper()

            if name == ack_cmd:
                return
            if name == attack_sim:
                self.handle_attack_sim()
                return
            if name == recovery:
                self.handle_recovery()
                return
            if name == update_thr:
                self.update_threshold(cmd)
                return
            if name == update_hash:
                self.update_integrity_hash(cmd)
                return

            logger.warning("지원하지 않는 커맨드: %s", name)
        except Exception as e:
            logger.error("dispatch_command 실패: %s", e)

    def handle_attack_sim(self) -> None:
        try:
            if self._anomaly_detector is None:
                logger.error("AnomalyDetector 미주입 — ATTACK_SIM 스킵")
                return
            self._anomaly_detector.set_attack_mode(True)
            if self._serial_reader is None:
                logger.error("SerialReader 미주입 — UART ATTACK 스킵")
                return
            self._serial_reader.send_uart_command(demon_config.UART_CMD_ATTACK)
        except Exception as e:
            logger.error("handle_attack_sim 실패: %s", e)

    def handle_recovery(self) -> None:
        try:
            if self._anomaly_detector is None:
                logger.error("AnomalyDetector 미주입 — RECOVERY 스킵")
                return
            self._anomaly_detector.set_attack_mode(False)
            if self._serial_reader is None:
                logger.error("SerialReader 미주입 — UART RECOVERY 스킵")
                return
            self._serial_reader.send_uart_command(demon_config.UART_CMD_RECOVERY)
        except Exception as e:
            logger.error("handle_recovery 실패: %s", e)

    def update_threshold(self, cmd: dict[str, Any]) -> None:
        """UPDATE_THRESHOLD — SAT_PWR_META 임계치 갱신."""
        try:
            sw_id = int(cmd.get("sw_id", cmd.get("SW_ID", -1)))
            lo = float(cmd.get("lo", cmd.get("V_THRESHOLD_LO")))
            hi = float(cmd.get("hi", cmd.get("V_THRESHOLD_HI")))
            if not self._ctx.db.update_threshold(sw_id, lo, hi):
                logger.error("update_threshold DB 실패 sw_id=%s", sw_id)
                return
            logger.info("임계치 갱신 sw_id=%s lo=%s hi=%s", sw_id, lo, hi)
        except (KeyError, ValueError, TypeError) as e:
            logger.error("update_threshold 입력 오류: %s", e)
        except Exception as e:
            logger.error("update_threshold 실패: %s", e)

    def update_integrity_hash(self, cmd: dict[str, Any]) -> None:
        """UPDATE_HASH — SAT_INTEGRITY_HASH 갱신 (db_manager 메서드 위임)."""
        try:
            updater = getattr(self._ctx.db, "update_integrity_hash", None)
            if not callable(updater):
                logger.error(
                    "db_manager.update_integrity_hash 미구현 — UPDATE_HASH 스킵. "
                    "cmd=%s",
                    cmd,
                )
                return
            file_id = cmd.get("file_id", cmd.get("FILE_ID"))
            file_path = cmd.get("file_path", cmd.get("FILE_PATH"))
            expected_hash = cmd.get(
                "expected_hash",
                cmd.get("EXPECTED_HASH"),
            )
            kwargs: dict[str, Any] = {}
            if file_id is not None:
                kwargs["file_id"] = int(file_id)
            if file_path is not None:
                kwargs["file_path"] = str(file_path)
            if expected_hash is not None:
                kwargs["expected_hash"] = str(expected_hash)
            if not kwargs and not isinstance(cmd, dict):
                logger.error("UPDATE_HASH 필수 필드 없음")
                return
            try:
                ok = bool(updater(**kwargs)) if kwargs else bool(updater(cmd))
            except TypeError:
                ok = bool(updater(cmd))
            if not ok:
                logger.error("update_integrity_hash DB 실패")
                return
            logger.info("SAT_INTEGRITY_HASH 갱신 완료 file_id=%s", kwargs.get("file_id"))
        except (ValueError, TypeError) as e:
            logger.error("update_integrity_hash 입력 오류: %s", e)
        except Exception as e:
            logger.error("update_integrity_hash 실패: %s", e)

    def send_packet(self, sock: socket.socket, payload: dict[str, Any]) -> bool:
        """[4B big-endian length][UTF-8 JSON] 전송."""
        try:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            header = struct.pack(">I", len(body))
            sock.sendall(header + body)
            return True
        except (OSError, TypeError, ValueError) as e:
            logger.error("send_packet 실패: %s", e)
            return False
        except Exception as e:
            logger.error("send_packet 실패: %s", e)
            return False

    def recv_packet(self, sock: socket.socket) -> dict[str, Any] | None:
        """4B 길이 헤더 + UTF-8 JSON 수신."""
        try:
            header = self._recv_exact(sock, 4)
            if header is None or len(header) < 4:
                return None
            (length,) = struct.unpack(">I", header)
            if length <= 0 or length > self._max_packet_bytes():
                logger.error("비정상 패킷 길이: %s", length)
                return None
            body = self._recv_exact(sock, length)
            if body is None:
                return None
            text = body.decode("utf-8")
            parsed = json.loads(text)
            if not isinstance(parsed, dict):
                logger.error("JSON 루트가 dict 가 아님")
                return None
            return parsed
        except json.JSONDecodeError as e:
            logger.error("recv_packet JSON 파싱 실패: %s", e)
            return None
        except UnicodeError as e:
            logger.error("recv_packet 디코딩 실패: %s", e)
            return None
        except Exception as e:
            logger.error("recv_packet 실패: %s", e)
            return None

    def send_with_retry(
        self,
        payload: dict[str, Any],
        on_ack_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> bool:
        """ACK 확인·지수 백오프 재시도. 성공 시 True."""
        try:
            max_retries = int(self._ctx.config.gs_send_retry_max)
            base_sec = float(self._ctx.config.gs_send_retry_base_sec)
            for attempt in range(max_retries + 1):
                sock = self._open_send_socket()
                if sock is None:
                    if attempt >= max_retries:
                        return False
                    self._backoff_sleep(base_sec, attempt)
                    continue
                try:
                    if not self.send_packet(sock, payload):
                        if attempt >= max_retries:
                            return False
                        self._backoff_sleep(base_sec, attempt)
                        continue
                    ack = self._wait_for_ack(sock)
                    if ack is not None:
                        if on_ack_callback is not None:
                            on_ack_callback(ack)
                        return True
                finally:
                    self._close_socket(sock)
                if attempt >= max_retries:
                    logger.error("send_with_retry ACK 실패 packet_type=%s", payload.get("packet_type"))
                    return False
                self._backoff_sleep(base_sec, attempt)
            return False
        except Exception as e:
            logger.error("send_with_retry 실패: %s", e)
            return False

    def _poll_sunlight_transmit(self) -> None:
        try:
            sun_ok = self._ctx.db.is_sunlight_window()
            if sun_ok and not self._last_transmit_sun_valid:
                logger.info("일광 윈도우 진입 — transmit_all 시작")
                self.transmit_all()
            self._last_transmit_sun_valid = sun_ok
        except Exception as e:
            logger.error("_poll_sunlight_transmit 실패: %s", e)

    def _start_command_listener(self) -> None:
        try:
            host = self._config_str("gs_cmd_listen_host", _DEFAULT_GS_CMD_LISTEN_HOST)
            port = self._cmd_listen_port()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(5)
            sock.settimeout(1.0)
            self._listen_sock = sock
            self._recv_thread = threading.Thread(
                target=self._command_listener_loop,
                name="GScomms-Recv",
                daemon=True,
            )
            self._recv_thread.start()
            logger.info("GScomms 커맨드 수신 대기 %s:%s", host, port)
        except OSError as e:
            logger.error("커맨드 리스너 시작 실패(OSError): %s", e)
        except Exception as e:
            logger.error("커맨드 리스너 시작 실패: %s", e)

    def _stop_command_listener(self) -> None:
        try:
            if self._listen_sock is not None:
                try:
                    self._listen_sock.close()
                except OSError as e:
                    logger.error("리스너 소켓 close 실패: %s", e)
                self._listen_sock = None
            if self._recv_thread is not None and self._recv_thread.is_alive():
                self._recv_thread.join(timeout=2.0)
            self._recv_thread = None
        except Exception as e:
            logger.error("_stop_command_listener 실패: %s", e)

    def _command_listener_loop(self) -> None:
        while not self._ctx.shutdown_event.is_set():
            listen_sock = self._listen_sock
            if listen_sock is None:
                return
            try:
                conn, addr = listen_sock.accept()
            except socket.timeout:
                continue
            except OSError as e:
                if self._ctx.shutdown_event.is_set():
                    return
                logger.error("accept 실패(OSError): %s", e)
                continue
            except Exception as e:
                logger.error("accept 실패: %s", e)
                continue
            try:
                conn.settimeout(self._socket_timeout_sec())
                logger.info("지상국 커맨드 연결: %s", addr)
                while not self._ctx.shutdown_event.is_set():
                    pkt = self.recv_packet(conn)
                    if pkt is None:
                        break
                    self.dispatch_command(pkt)
            except Exception as e:
                logger.error("커맨드 세션 처리 실패: %s", e)
            finally:
                self._close_socket(conn)

    def _open_send_socket(self) -> socket.socket | None:
        host = self._ctx.config.gs_host
        port = int(self._ctx.config.gs_port)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self._socket_timeout_sec())
            sock.connect((host, port))
            return sock
        except OSError as e:
            logger.error("지상국 연결 실패(OSError) %s:%s: %s", host, port, e)
            return None
        except Exception as e:
            logger.error("지상국 연결 실패: %s", e)
            return None

    def _wait_for_ack(self, sock: socket.socket) -> dict[str, Any] | None:
        try:
            sock.settimeout(self._ack_wait_sec())
            pkt = self.recv_packet(sock)
            if pkt is None:
                return None
            if self._is_ack_packet(pkt):
                return pkt
            self.dispatch_command(pkt)
            return None
        except Exception as e:
            logger.error("_wait_for_ack 실패: %s", e)
            return None

    @staticmethod
    def _is_ack_packet(pkt: dict[str, Any]) -> bool:
        try:
            if pkt.get("ack") is True:
                return True
            cmd = str(pkt.get("cmd", pkt.get("command", ""))).strip().upper()
            ack_name = getattr(demon_config, "GS_CMD_ACK", _DEFAULT_GS_CMD_ACK)
            return cmd == str(ack_name).upper()
        except Exception as e:
            logger.error("_is_ack_packet 실패: %s", e)
            return False

    def _reset_pwr_meta_counters(self) -> None:
        try:
            for row in self._ctx.db.get_pwr_meta_all():
                sw_id = int(row.get("SW_ID", -1))
                if sw_id < 0:
                    continue
                info = {
                    "sw_id": sw_id,
                    "exceed_count": 0,
                    "consecutive_exceed": 0,
                    "anomaly_flag": 0,
                }
                if not self._ctx.db.update_pwr_exceed_meta(info):
                    logger.warning("전력 카운터 초기화 실패 sw_id=%s", sw_id)
            logger.info("SAT_PWR_META 카운터 초기화 완료")
        except Exception as e:
            logger.error("_reset_pwr_meta_counters 실패: %s", e)

    def _db_insert_event_flexible(self, event: dict[str, Any]) -> int:
        """
        insert_event 호출 — db_manager 가 확장되면 OPTIONAL 컬럼 자동 포함.

        db_manager.insert_event 가 _OPTIONAL_EVENT_COLS 를 읽도록 갱신되면
        event dict 의 키가 그대로 INSERT 에 반영된다.
        """
        try:
            insert_fn = getattr(self._ctx.db, "insert_event", None)
            if not callable(insert_fn):
                logger.error("db.insert_event 없음")
                return -1
            event_id = int(insert_fn(event))
            if event_id >= 0:
                return event_id
            extended = getattr(self._ctx.db, "insert_event_extended", None)
            if callable(extended):
                return int(extended(event))
            stripped = {k: v for k, v in event.items() if k not in _OPTIONAL_EVENT_COLS}
            return int(insert_fn(stripped))
        except Exception as e:
            logger.error("_db_insert_event_flexible 실패: %s", e)
            return -1

    def _resolve_is_attack(self, result: dict[str, Any]) -> str:
        try:
            raw = result.get("is_attack", result.get("decision", "N"))
            return str(raw).strip().upper()
        except Exception as e:
            logger.error("_resolve_is_attack 실패: %s", e)
            return "N"

    def _parse_weight(self, result: dict[str, Any]) -> int:
        try:
            weight = int(result.get("weight", 0))
            if weight < _WEIGHT_MIN or weight > _WEIGHT_MAX:
                logger.warning(
                    "weight 범위 이탈(1~100): %s — 로그만 남기고 INSERT 진행",
                    weight,
                )
            return weight
        except (ValueError, TypeError) as e:
            logger.warning("weight 파싱 실패: %s", e)
            return 0
        except Exception as e:
            logger.error("_parse_weight 실패: %s", e)
            return 0

    def _recv_exact(self, sock: socket.socket, nbytes: int) -> bytes | None:
        try:
            chunks: list[bytes] = []
            remaining = nbytes
            while remaining > 0:
                part = sock.recv(remaining)
                if not part:
                    return None
                chunks.append(part)
                remaining -= len(part)
            return b"".join(chunks)
        except OSError as e:
            logger.error("_recv_exact 실패(OSError): %s", e)
            return None
        except Exception as e:
            logger.error("_recv_exact 실패: %s", e)
            return None

    def _backoff_sleep(self, base_sec: float, attempt: int) -> None:
        try:
            delay = base_sec * (2 ** attempt)
            if self._ctx.shutdown_event.wait(timeout=delay):
                return
        except Exception as e:
            logger.error("_backoff_sleep 실패: %s", e)

    @staticmethod
    def _close_socket(sock: socket.socket | None) -> None:
        if sock is None:
            return
        try:
            sock.close()
        except OSError as e:
            logger.error("소켓 close 실패: %s", e)
        except Exception as e:
            logger.error("소켓 close 실패: %s", e)

    @staticmethod
    def _utc_now_iso() -> str:
        try:
            return datetime.now(timezone.utc).isoformat()
        except Exception as e:
            logger.error("UTC 시각 생성 실패: %s", e)
            return "1970-01-01T00:00:00+00:00"

    def _cmd_listen_port(self) -> int:
        try:
            val = getattr(self._ctx.config, "gs_cmd_listen_port", None)
            if val is not None:
                return int(val)
            return int(self._ctx.config.gs_port) + _DEFAULT_GS_CMD_LISTEN_PORT_OFFSET
        except (ValueError, TypeError) as e:
            logger.error("_cmd_listen_port 변환 오류: %s", e)
            return int(self._ctx.config.gs_port) + 1
        except Exception as e:
            logger.error("_cmd_listen_port 실패: %s", e)
            return 6001

    def _gs_poll_interval_sec(self) -> float:
        try:
            val = getattr(self._ctx.config, "gs_poll_interval_sec", None)
            if val is not None:
                return float(val)
            return float(self._ctx.config.collect_interval_sec)
        except Exception as e:
            logger.error("_gs_poll_interval_sec 실패: %s", e)
            return 1.0

    def _socket_timeout_sec(self) -> float:
        try:
            val = getattr(self._ctx.config, "gs_socket_timeout_sec", None)
            if val is not None:
                return float(val)
            return _DEFAULT_SOCKET_TIMEOUT_SEC
        except Exception as e:
            logger.error("_socket_timeout_sec 실패: %s", e)
            return _DEFAULT_SOCKET_TIMEOUT_SEC

    def _ack_wait_sec(self) -> float:
        try:
            val = getattr(self._ctx.config, "gs_ack_wait_sec", None)
            if val is not None:
                return float(val)
            return _DEFAULT_ACK_WAIT_SEC
        except Exception as e:
            logger.error("_ack_wait_sec 실패: %s", e)
            return _DEFAULT_ACK_WAIT_SEC

    def _max_packet_bytes(self) -> int:
        try:
            val = getattr(self._ctx.config, "gs_max_packet_bytes", None)
            if val is not None:
                return int(val)
            return int(self._ctx.config.udp_recv_buffer_bytes)
        except Exception as e:
            logger.error("_max_packet_bytes 실패: %s", e)
            return 65535

    @staticmethod
    def _config_str(name: str, default: str) -> str:
        try:
            val = getattr(demon_config, name, None)
            if val is not None:
                return str(val)
            return default
        except Exception as e:
            logger.error("_config_str 실패 %s: %s", name, e)
            return default
