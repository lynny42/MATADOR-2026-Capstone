from __future__ import annotations

import json
import logging
import socket
import struct
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from .. import config as demon_config
from ..core.context import RuntimeContext

logger = logging.getLogger(__name__)

# config.py 미정의 시 기본값 — 운영 시 config.py에 상수 추가 권장:
# GS_CMD_BIND_HOST, GS_CMD_BIND_PORT_OFFSET, GS_SOCKET_TIMEOUT_SEC, GS_ACK_TIMEOUT_SEC
_CMD_BIND_HOST: str = str(getattr(demon_config, "GS_CMD_BIND_HOST", "0.0.0.0"))
_CMD_BIND_PORT_OFFSET: int = int(getattr(demon_config, "GS_CMD_BIND_PORT_OFFSET", 1))
_SOCKET_TIMEOUT_SEC: float = float(getattr(demon_config, "GS_SOCKET_TIMEOUT_SEC", 5.0))
_ACK_TIMEOUT_SEC: float = float(getattr(demon_config, "GS_ACK_TIMEOUT_SEC", 3.0))

# insert_event 확장 컬럼 — db_manager.insert_event 반영 시 자동 저장됨
_EVENT_EXTRA_COLS: tuple[str, ...] = (
    "EXCEPTION_CODE",
    "SW_ID",
    "CHANNEL1",
    "MODULE_SCORES",
)


class GScomms:
    """지상국 TCP 송수신 — 일광 윈도우 송신, 커맨드 수신, 오탐 결과 이벤트 적재."""

    def __init__(self, ctx: RuntimeContext) -> None:
        self._ctx = ctx
        self._anomaly_detector: Any | None = None
        self._serial_reader: Any | None = None
        self._rx_thread: threading.Thread | None = None
        self._cmd_listen_sock: socket.socket | None = None
        self._sock_lock = threading.Lock()

    def set_anomaly_detector(self, detector: Any) -> None:
        """AnomalyDetector 주입 (ATTACK_SIM / RECOVERY)."""
        try:
            self._anomaly_detector = detector
            logger.info("AnomalyDetector 주입 완료 (GScomms)")
        except Exception as e:
            logger.error("set_anomaly_detector 실패: %s", e)

    def set_serial_reader(self, reader: Any) -> None:
        """SerialReader 주입 (UART ATTACK/RECOVERY)."""
        try:
            self._serial_reader = reader
            logger.info("SerialReader 주입 완료 (GScomms)")
        except Exception as e:
            logger.error("set_serial_reader 실패: %s", e)

    def run(self) -> None:
        """메인 루프: 일광 시 transmit_all, 커맨드 수신은 별도 스레드."""
        logger.info("GScomms started")
        self._start_command_listener()
        interval = float(self._ctx.config.collect_interval_sec)
        try:
            while not self._ctx.shutdown_event.is_set():
                cycle_start = time.monotonic()
                try:
                    if self._ctx.db.is_sunlight_window():
                        self.transmit_all()
                except Exception as e:
                    logger.error("GScomms transmit 주기 실패: %s", e)
                elapsed = time.monotonic() - cycle_start
                remaining = interval - elapsed
                if remaining > 0 and self._ctx.shutdown_event.wait(timeout=remaining):
                    break
        except Exception as e:
            logger.error("GScomms run 실패: %s", e)
        finally:
            self._stop_command_listener()
        logger.info("GScomms stopped")

    def _start_command_listener(self) -> None:
        """지상국 커맨드 수신 스레드 기동."""
        try:
            self._rx_thread = threading.Thread(
                target=self._command_listener_thread,
                name="GScommsCmdRx",
                daemon=True,
            )
            self._rx_thread.start()
        except RuntimeError as e:
            logger.error("커맨드 수신 스레드 기동 실패(RuntimeError): %s", e)
        except Exception as e:
            logger.error("커맨드 수신 스레드 기동 실패: %s", e)

    def _stop_command_listener(self) -> None:
        """수신 스레드 종료 유도."""
        try:
            sock = self._cmd_listen_sock
            if sock is not None:
                try:
                    sock.close()
                except OSError as e:
                    logger.error("커맨드 listen 소켓 close 실패(OSError): %s", e)
            if self._rx_thread is not None and self._rx_thread.is_alive():
                self._rx_thread.join(timeout=2.0)
        except Exception as e:
            logger.error("_stop_command_listener 실패: %s", e)

    def _command_listener_thread(self) -> None:
        """TCP 서버 — gs_port+offset 에서 커맨드 대기."""
        listen_port = int(self._ctx.config.gs_port) + _CMD_BIND_PORT_OFFSET
        server: socket.socket | None = None
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.settimeout(1.0)
            server.bind((_CMD_BIND_HOST, listen_port))
            server.listen(5)
            self._cmd_listen_sock = server
            logger.info("GScomms 커맨드 수신 bind %s:%s", _CMD_BIND_HOST, listen_port)
            while not self._ctx.shutdown_event.is_set():
                try:
                    conn, addr = server.accept()
                except socket.timeout:
                    continue
                except OSError as e:
                    if self._ctx.shutdown_event.is_set():
                        break
                    logger.error("커맨드 accept 실패(OSError): %s", e)
                    continue
                except Exception as e:
                    logger.error("커맨드 accept 실패: %s", e)
                    continue
                try:
                    conn.settimeout(_SOCKET_TIMEOUT_SEC)
                    self._handle_command_connection(conn, addr)
                except Exception as e:
                    logger.error("커맨드 연결 처리 실패 %s: %s", addr, e)
                finally:
                    try:
                        conn.close()
                    except OSError as e:
                        logger.error("커맨드 conn close 실패(OSError): %s", e)
        except OSError as e:
            logger.error("커맨드 listen 실패(OSError): %s", e)
        except Exception as e:
            logger.error("커맨드 listener 실패: %s", e)
        finally:
            if server is not None:
                try:
                    server.close()
                except OSError as e:
                    logger.error("커맨드 server close 실패(OSError): %s", e)
            self._cmd_listen_sock = None

    def _handle_command_connection(
        self, conn: socket.socket, addr: tuple[str, int],
    ) -> None:
        """연결 1건에서 커맨드 패킷 수신·처리."""
        try:
            while not self._ctx.shutdown_event.is_set():
                packet = self.recv_packet(conn)
                if packet is None:
                    break
                self.dispatch_command(packet)
        except Exception as e:
            logger.error("_handle_command_connection %s 실패: %s", addr, e)

    def transmit_all(self) -> None:
        """transmit_tlm → pwr_meta → event_queue → integrity."""
        sock: socket.socket | None = None
        try:
            sock = self._open_send_socket()
            if sock is None:
                return
            self.transmit_tlm(sock)
            self.transmit_pwr_meta(sock)
            self.transmit_event_queue(sock)
            self.transmit_integrity(sock)
        except Exception as e:
            logger.error("transmit_all 실패: %s", e)
        finally:
            self._close_socket(sock)

    def transmit_tlm(self, sock: socket.socket | None = None) -> None:
        """SAT_TLM_CURRENT 1행 송신."""
        own_sock = False
        try:
            if sock is None:
                sock = self._open_send_socket()
                own_sock = sock is not None
            if sock is None:
                return
            row = self._ctx.db.get_tlm_current()
            if row is None:
                return
            payload = {
                "type": "TLM_CURRENT",
                "msg_id": self._new_msg_id(),
                "data": row,
            }

            def on_ack() -> None:
                deleter = getattr(self._ctx.db, "delete_tlm_current", None)
                if callable(deleter):
                    deleter()
                    logger.info("SAT_TLM_CURRENT ACK — 행 삭제")
                else:
                    logger.info("SAT_TLM_CURRENT ACK 수신")

            self.send_with_retry(sock, payload, on_ack)
        except Exception as e:
            logger.error("transmit_tlm 실패: %s", e)
        finally:
            if own_sock:
                self._close_socket(sock)

    def transmit_pwr_meta(self, sock: socket.socket | None = None) -> None:
        """SAT_PWR_META 전 채널 송신 — ACK 시 카운터 초기화."""
        own_sock = False
        try:
            if sock is None:
                sock = self._open_send_socket()
                own_sock = sock is not None
            if sock is None:
                return
            rows = self._ctx.db.get_pwr_meta_all()
            if not rows:
                return
            payload = {
                "type": "PWR_META",
                "msg_id": self._new_msg_id(),
                "data": rows,
            }

            def on_ack() -> None:
                self._reset_pwr_counters_after_ack()
                logger.info("SAT_PWR_META ACK — 카운터 초기화 완료")

            self.send_with_retry(sock, payload, on_ack)
        except Exception as e:
            logger.error("transmit_pwr_meta 실패: %s", e)
        finally:
            if own_sock:
                self._close_socket(sock)

    def transmit_event_queue(self, sock: socket.socket | None = None) -> None:
        """미전송 이벤트 개별 순차 송신 — ACK 시 mark_sent + delete."""
        own_sock = False
        try:
            if sock is None:
                sock = self._open_send_socket()
                own_sock = sock is not None
            if sock is None:
                return
            events = self._ctx.db.get_pending_events()
            for event in events:
                if self._ctx.shutdown_event.is_set():
                    break
                eid = int(event["EVENT_ID"])
                payload = {
                    "type": "EVENT",
                    "msg_id": self._new_msg_id(),
                    "event_id": eid,
                    "data": event,
                }

                def on_ack(event_id: int = eid) -> None:
                    try:
                        self._ctx.db.mark_event_sent(event_id)
                        self._ctx.db.delete_event(event_id)
                        logger.info("이벤트 ACK event_id=%s", event_id)
                    except Exception as exc:
                        logger.error("이벤트 ACK 처리 실패 event_id=%s: %s", event_id, exc)

                if not self.send_with_retry(sock, payload, on_ack):
                    logger.warning("이벤트 송신 실패 event_id=%s", eid)
                    break
        except Exception as e:
            logger.error("transmit_event_queue 실패: %s", e)
        finally:
            if own_sock:
                self._close_socket(sock)

    def transmit_integrity(self, sock: socket.socket | None = None) -> None:
        """SAT_INTEGRITY_HASH 전체 송신 (삭제 없음)."""
        own_sock = False
        try:
            if sock is None:
                sock = self._open_send_socket()
                own_sock = sock is not None
            if sock is None:
                return
            rows = self._ctx.db.get_integrity_hash()
            if rows is None or not isinstance(rows, list) or len(rows) == 0:
                return
            payload = {
                "type": "INTEGRITY",
                "msg_id": self._new_msg_id(),
                "data": rows,
            }
            self.send_with_retry(sock, payload, lambda: None)
        except Exception as e:
            logger.error("transmit_integrity 실패: %s", e)
        finally:
            if own_sock:
                self._close_socket(sock)

    def send_packet(self, sock: socket.socket, payload: dict[str, Any]) -> bool:
        """[4B 빅엔디안 길이 + UTF-8 JSON] 전송."""
        try:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            header = struct.pack(">I", len(body))
            with self._sock_lock:
                sock.sendall(header + body)
            return True
        except (TypeError, ValueError) as e:
            logger.error("send_packet 직렬화 오류: %s", e)
            return False
        except OSError as e:
            logger.error("send_packet IO 오류: %s", e)
            return False
        except Exception as e:
            logger.error("send_packet 실패: %s", e)
            return False

    def recv_packet(self, sock: socket.socket) -> dict[str, Any] | None:
        """4B 길이 헤더 + JSON 페이로드 수신."""
        try:
            header = self._recv_exact(sock, 4)
            if header is None or len(header) < 4:
                return None
            length = struct.unpack(">I", header)[0]
            if length <= 0 or length > 16 * 1024 * 1024:
                logger.error("recv_packet 비정상 길이: %s", length)
                return None
            body = self._recv_exact(sock, length)
            if body is None:
                return None
            return json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as e:
            logger.error("recv_packet JSON 오류: %s", e)
            return None
        except OSError as e:
            logger.error("recv_packet IO 오류: %s", e)
            return None
        except Exception as e:
            logger.error("recv_packet 실패: %s", e)
            return None

    def send_with_retry(
        self,
        sock: socket.socket,
        payload: dict[str, Any],
        on_ack_callback: Callable[[], None],
    ) -> bool:
        """ACK 확인 후 지수 백오프 재시도 (최대 gs_send_retry_max)."""
        try:
            max_retry = int(self._ctx.config.gs_send_retry_max)
            base_sec = float(self._ctx.config.gs_send_retry_base_sec)
            msg_id = str(payload.get("msg_id", ""))
            for attempt in range(max_retry):
                if not self.send_packet(sock, payload):
                    if attempt + 1 < max_retry:
                        time.sleep(base_sec * (2 ** attempt))
                    continue
                if self._wait_for_ack(sock, msg_id):
                    try:
                        on_ack_callback()
                    except Exception as e:
                        logger.error("on_ack_callback 실패: %s", e)
                    return True
                if attempt + 1 < max_retry:
                    time.sleep(base_sec * (2 ** attempt))
            logger.warning(
                "ACK 미수신 msg_id=%s type=%s",
                msg_id,
                payload.get("type"),
            )
            return False
        except Exception as e:
            logger.error("send_with_retry 실패: %s", e)
            return False

    def dispatch_command(self, cmd: dict[str, Any]) -> None:
        """수신 커맨드를 핸들러로 라우팅."""
        try:
            name = str(cmd.get("cmd", cmd.get("command", ""))).upper()
            if name == "ATTACK_SIM":
                self.handle_attack_sim()
            elif name == "RECOVERY":
                self.handle_recovery()
            elif name == "UPDATE_THRESHOLD":
                self.update_threshold(cmd)
            elif name == "UPDATE_HASH":
                self.update_integrity_hash(cmd)
            else:
                logger.warning("알 수 없는 커맨드: %s", name)
        except Exception as e:
            logger.error("dispatch_command 실패: %s", e)

    def handle_attack_sim(self) -> None:
        """ATTACK_SIM — 탐지 민감도 상향 + UART ATTACK."""
        try:
            if self._anomaly_detector is not None:
                setter = getattr(self._anomaly_detector, "set_attack_mode", None)
                if callable(setter):
                    setter(True)
                else:
                    logger.warning("set_attack_mode 미구현")
            else:
                logger.warning("AnomalyDetector 미주입 — ATTACK_SIM 스킵")
            self._send_uart_command("ATTACK")
        except Exception as e:
            logger.error("handle_attack_sim 실패: %s", e)

    def handle_recovery(self) -> None:
        """RECOVERY — 탐지 정상화 + UART RECOVERY."""
        try:
            if self._anomaly_detector is not None:
                setter = getattr(self._anomaly_detector, "set_attack_mode", None)
                if callable(setter):
                    setter(False)
                else:
                    logger.warning("set_attack_mode 미구현")
            else:
                logger.warning("AnomalyDetector 미주입 — RECOVERY 스킵")
            self._send_uart_command("RECOVERY")
        except Exception as e:
            logger.error("handle_recovery 실패: %s", e)

    def update_threshold(self, cmd: dict[str, Any]) -> None:
        """UPDATE_THRESHOLD — SAT_PWR_META 임계치 갱신."""
        try:
            sw_id = int(cmd["sw_id"])
            lo = float(cmd["lo"])
            hi = float(cmd["hi"])
            if not self._ctx.db.update_threshold(sw_id, lo, hi):
                logger.error("update_threshold DB 실패 sw_id=%s", sw_id)
        except (KeyError, TypeError, ValueError) as e:
            logger.error("update_threshold 파싱 오류: %s", e)
        except Exception as e:
            logger.error("update_threshold 실패: %s", e)

    def update_integrity_hash(self, cmd: dict[str, Any]) -> None:
        """UPDATE_HASH — SAT_INTEGRITY_HASH 갱신 (db 메서드 있으면 위임)."""
        try:
            updater = getattr(self._ctx.db, "update_integrity_hash", None)
            if not callable(updater):
                logger.warning(
                    "ctx.db.update_integrity_hash 미구현 — db_manager 추가 필요",
                )
                return
            file_id = cmd.get("file_id")
            file_path = cmd.get("file_path")
            expected_hash = cmd.get("expected_hash")
            if file_id is not None:
                updater(int(file_id), str(file_path or ""), str(expected_hash or ""))
            else:
                updater(cmd)
        except (TypeError, ValueError) as e:
            logger.error("update_integrity_hash 입력 오류: %s", e)
        except Exception as e:
            logger.error("update_integrity_hash 실패: %s", e)

    def insert_event(self, result: dict[str, Any]) -> None:
        """
        FalsePositiveFilter.send_to_gscomms() 진입점.

        is_attack Y/N → EVENT_TYPE·PRIORITY, key_set·module_scores → 확장 컬럼(준비).
        """
        try:
            is_attack = str(result.get("is_attack", "N")).upper()
            weight = int(result.get("weight", 0))
            if weight < 1 or weight > 100:
                logger.warning("insert_event weight 범위 이탈(1~100): %s", weight)
            else:
                logger.info("insert_event weight=%s is_attack=%s", weight, is_attack)

            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            detected_at = str(result.get("detected_at", now))
            key_set = result.get("key_set") or {}
            if not isinstance(key_set, dict):
                key_set = {}

            if is_attack == "Y":
                event_type = "ATTACK_CONFIRMED"
                priority = 1
            else:
                event_type = "SEU_DETECTED"
                priority = 0

            module_scores = result.get("module_scores")
            module_scores_text: str | None = None
            if module_scores is not None:
                try:
                    module_scores_text = json.dumps(module_scores, ensure_ascii=False)
                except (TypeError, ValueError) as e:
                    logger.error("module_scores JSON 변환 실패: %s", e)

            event_row: dict[str, Any] = {
                "DETECTED_AT": detected_at,
                "TIMESTAMP": detected_at,
                "EVENT_TYPE": event_type,
                "PRIORITY": priority,
                "IS_SENT": 0,
                "EXCEPTION_CODE": int(result.get("exception_code", 0)),
            }
            if key_set.get("sw_id") is not None:
                event_row["SW_ID"] = int(key_set["sw_id"])
            if key_set.get("channel1") is not None:
                event_row["CHANNEL1"] = int(key_set["channel1"])
            if module_scores_text is not None:
                event_row["MODULE_SCORES"] = module_scores_text

            event_id = self._insert_sat_event_flexible(event_row)
            if event_id < 1:
                logger.error("insert_event DB INSERT 실패")
            else:
                logger.info("insert_event 완료 event_id=%s type=%s", event_id, event_type)
        except (TypeError, ValueError) as e:
            logger.error("insert_event 입력 오류: %s", e)
        except Exception as e:
            logger.error("insert_event 실패: %s", e)

    def _insert_sat_event_flexible(self, event: dict[str, Any]) -> int:
        """
        SAT_EVENT_QUEUE INSERT.

        db_manager.insert_event 가 확장 컬럼을 지원하면 event 내 extras 가 함께 저장된다.
        미지원 시에도 핵심 필드는 insert_event 로 적재된다.
        """
        try:
            inserter = getattr(self._ctx.db, "insert_event", None)
            if not callable(inserter):
                logger.error("ctx.db.insert_event 없음")
                return -1
            extended = getattr(self._ctx.db, "insert_event_extended", None)
            if callable(extended):
                return int(extended(event))
            return int(inserter(event))
        except Exception as e:
            logger.error("_insert_sat_event_flexible 실패: %s", e)
            return -1

    def _open_send_socket(self) -> socket.socket | None:
        """지상국 송신용 TCP 클라이언트 연결."""
        host = str(self._ctx.config.gs_host)
        port = int(self._ctx.config.gs_port)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(_SOCKET_TIMEOUT_SEC)
            sock.connect((host, port))
            return sock
        except OSError as e:
            logger.error("지상국 연결 실패(OSError) %s:%s: %s", host, port, e)
            return None
        except Exception as e:
            logger.error("지상국 연결 실패 %s:%s: %s", host, port, e)
            return None

    def _close_socket(self, sock: socket.socket | None) -> None:
        """송신 소켓 close."""
        if sock is None:
            return
        try:
            sock.close()
        except OSError as e:
            logger.error("소켓 close 실패(OSError): %s", e)
        except Exception as e:
            logger.error("소켓 close 실패: %s", e)

    def _wait_for_ack(self, sock: socket.socket, msg_id: str) -> bool:
        """송신 직후 ACK 패킷 대기."""
        try:
            deadline = time.monotonic() + _ACK_TIMEOUT_SEC
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                sock.settimeout(max(0.1, remaining))
                packet = self.recv_packet(sock)
                if packet is None:
                    continue
                if str(packet.get("type", "")).upper() == "ACK":
                    ack_id = str(packet.get("msg_id", packet.get("ack_msg_id", "")))
                    if not msg_id or ack_id == msg_id or ack_id == "":
                        return True
            return False
        except OSError as e:
            logger.error("_wait_for_ack IO 오류: %s", e)
            return False
        except Exception as e:
            logger.error("_wait_for_ack 실패: %s", e)
            return False

    def _recv_exact(self, sock: socket.socket, nbytes: int) -> bytes | None:
        """정확히 nbytes 수신."""
        try:
            chunks: list[bytes] = []
            received = 0
            while received < nbytes:
                part = sock.recv(nbytes - received)
                if not part:
                    return None
                chunks.append(part)
                received += len(part)
            return b"".join(chunks)
        except OSError as e:
            logger.error("_recv_exact IO 오류: %s", e)
            return None
        except Exception as e:
            logger.error("_recv_exact 실패: %s", e)
            return None

    def _new_msg_id(self) -> str:
        """송신 패킷 msg_id."""
        try:
            return uuid.uuid4().hex
        except Exception as e:
            logger.error("_new_msg_id 실패: %s", e)
            return str(time.time())

    def _send_uart_command(self, cmd: str) -> None:
        """SerialReader.send_uart_command 위임."""
        try:
            if self._serial_reader is None:
                logger.warning("SerialReader 미주입 — UART %s 스킵", cmd)
                return
            sender = getattr(self._serial_reader, "send_uart_command", None)
            if callable(sender):
                sender(cmd)
            else:
                logger.warning("send_uart_command 미구현 — UART %s 스킵", cmd)
        except Exception as e:
            logger.error("_send_uart_command 실패: %s", e)

    def _reset_pwr_counters_after_ack(self) -> None:
        """PWR_META ACK 후 EXCEED/ANOMALY 카운터 초기화."""
        try:
            resetter = getattr(self._ctx.db, "reset_pwr_meta_after_transmit", None)
            if callable(resetter):
                resetter()
                return
            rows = self._ctx.db.get_pwr_meta_all()
            for row in rows:
                sw_id = int(row["SW_ID"])
                self._ctx.db.update_pwr_exceed_meta({
                    "sw_id": sw_id,
                    "exceed_count": 0,
                    "consecutive_exceed": 0,
                    "anomaly_flag": 0,
                })
        except Exception as e:
            logger.error("_reset_pwr_counters_after_ack 실패: %s", e)
