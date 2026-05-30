from __future__ import annotations

import json
import logging
import socket
import struct
import threading
from typing import Any, Callable, Protocol

from .. import config as demon_config
from ..core.context import RuntimeContext
from ..core.time_utils import utc_now_iso

logger = logging.getLogger(__name__)

# db_manager.insert_event 확장 전까지 SAT_EVENT_QUEUE 선택 컬럼 (추가 시 자동 반영)
_OPTIONAL_EVENT_COLS: tuple[str, ...] = (
    "EXCEPTION_CODE",
    "SW_ID",
    "WEIGHT",
    "CHENNEL1",
    "MODULE_SCORES",
)

# config.GS_CMD_* 미정의 시 fallback (일반적으로 config 사용)
_DEFAULT_GS_CMD_ATTACK_SIM = "ATTACK_SIM"
_DEFAULT_GS_CMD_ATTACK_HASH = "ATTACK_HASH"
_DEFAULT_GS_CMD_RECOVERY = "RECOVERY"
_DEFAULT_GS_CMD_UPDATE_THRESHOLD = "UPDATE_THRESHOLD"
_DEFAULT_GS_CMD_UPDATE_HASH = "UPDATE_HASH"
_DEFAULT_GS_CMD_ACK = "ACK"
_DEFAULT_GS_CMD_LISTEN_HOST = "0.0.0.0"
_DEFAULT_GS_CMD_LISTEN_PORT_OFFSET = 1
_DEFAULT_SOCKET_TIMEOUT_SEC = 5.0
_DEFAULT_ACK_WAIT_SEC = 3.0
_WEIGHT_MIN = 1
_WEIGHT_MAX = 100


def _event_ids_from_pending(pending: list[dict[str, Any]]) -> list[int]:
    """get_pending_events 순서 유지 — 유효 EVENT_ID 만 추출."""
    try:
        ids: list[int] = []
        for event in pending:
            try:
                event_id = int(event.get("EVENT_ID", -1))
            except (TypeError, ValueError):
                continue
            if event_id >= 0:
                ids.append(event_id)
        return ids
    except Exception as e:
        logger.error("_event_ids_from_pending 실패: %s", e)
        return []


class AnomalyDetectorLike(Protocol):
    def set_attack_mode(self, enabled: bool) -> None:
        ...


class SerialReaderLike(Protocol):
    def set_pwr_bias(self, enabled: bool) -> bool:
        ...

    def set_gyro_enabled(self, enabled: bool) -> bool:
        ...

    def get_light_state(self) -> str | None:
        ...


class GScomms:
    """지상국(COSMOS) TCP 송수신 — 조도 엣지 bulk 송신·커맨드 수신·오탐 결과 이벤트 등록."""

    def __init__(self, ctx: RuntimeContext) -> None:
        self._ctx = ctx
        self._anomaly_detector: AnomalyDetectorLike | None = None
        self._serial_reader: SerialReaderLike | None = None
        self._attack_simulator: object | None = None
        self._listen_sock: socket.socket | None = None
        self._recv_thread: threading.Thread | None = None
        self._prev_light_state: str | None = None

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

    def set_attack_simulator(self, simulator: object) -> None:
        """AttackSimulator — ATTACK_SIM / RECOVERY 위임."""
        try:
            self._attack_simulator = simulator
        except Exception as e:
            logger.error("set_attack_simulator 실패: %s", e)

    def run(self) -> None:
        """gs_comms_thread — 수신 스레드 기동 + 조도 엣지 bulk 송신 루프."""
        logger.info("GScomms started")
        try:
            self._start_command_listener()
            poll_sec = self._gs_poll_interval_sec()
            while not self._ctx.shutdown_event.is_set():
                try:
                    self._poll_light_edge_transmit()
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
            chennel1 = int(
                key_set.get(
                    "channel1",
                    key_set.get("CHENNEL1", 0),
                ),
            )
            detected_at = str(
                result.get("detected_at")
                or key_set.get("detected_at")
                or utc_now_iso(),
            )

            if is_attack == "Y":
                event_type = demon_config.GS_EVENT_ATTACK_CONFIRMED
                priority = 1
            else:
                event_type = demon_config.GS_EVENT_SEU_DETECTED
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
                "WEIGHT": weight,
                "CHENNEL1": chennel1,
                "MODULE_SCORES": module_scores_text,
            }

            event_id = self._db_insert_event_flexible(event_payload)
            if event_id < 0:
                logger.error("insert_event DB 실패 is_attack=%s", is_attack)
                return -1

            logger.info(
                "오탐필터 이벤트 INSERT event_id=%s type=%s weight=%s sw_id=%s chennel1=%s "
                "(조도 dark→light 시 송신)",
                event_id,
                event_type,
                weight,
                sw_id,
                chennel1,
            )
            return event_id
        except (ValueError, TypeError) as e:
            logger.error("insert_event 입력 오류: %s", e)
            return -1
        except Exception as e:
            logger.error("insert_event 실패: %s", e)
            return -1

    def transmit_all(self) -> None:
        """
        조도 dark→light 엣지 bulk 송신.

        순서: EVENT(META→본문) → INTEGRITY(HASH) → ADCS → TLM → PWR
        """
        try:
            self.transmit_event_queue()
            if self._should_transmit_integrity():
                self.transmit_integrity()
            self.transmit_adcs_filter()
            self.transmit_tlm_history()
            self.transmit_pwr_history()
        except Exception as e:
            logger.error("transmit_all 실패: %s", e)

    def _should_transmit_integrity(self) -> bool:
        """무결성 해시 패킷 — INTEGRITY 이벤트·위반 시에만 (attack 경로)."""
        try:
            pending = self._ctx.db.get_pending_events()
            if pending:
                for ev in pending:
                    if not isinstance(ev, dict):
                        continue
                    event_type = str(ev.get("EVENT_TYPE", ""))
                    if event_type.startswith("INTEGRITY_"):
                        return True
            records = self._ctx.db.get_integrity_hash()
            if records is None:
                return False
            if isinstance(records, dict):
                records = [records]
            if isinstance(records, list):
                for rec in records:
                    if isinstance(rec, dict) and int(rec.get("IS_VIOLATED", 0)) == 1:
                        return True
            return False
        except Exception as e:
            logger.error("_should_transmit_integrity 실패: %s", e)
            return False

    def transmit_tlm_history(self) -> None:
        """SAT_TLM_HISTORY 배치 송신 — ACK 시 해당 배치만 delete_tlm_history."""
        try:
            records = self._ctx.db.get_tlm_history()
            if not records:
                return
            self._transmit_history_in_batches(
                records,
                demon_config.GS_PACKET_TYPE_TLM_HISTORY,
                self._ctx.db.delete_tlm_history,
                "SAT_TLM_HISTORY",
            )
        except Exception as e:
            logger.error("transmit_tlm_history 실패: %s", e)

    def transmit_pwr_history(self) -> None:
        """SAT_PWR_HISTORY 배치 송신 — ACK 시 해당 배치만 delete_pwr_history."""
        try:
            records = self._ctx.db.get_pwr_history()
            if not records:
                return
            self._transmit_history_in_batches(
                records,
                demon_config.GS_PACKET_TYPE_PWR_HISTORY,
                self._ctx.db.delete_pwr_history,
                "SAT_PWR_HISTORY",
            )
        except Exception as e:
            logger.error("transmit_pwr_history 실패: %s", e)

    def _transmit_history_in_batches(
        self,
        records: list[dict[str, Any]],
        packet_type: str,
        delete_fn: Callable[[list[int]], bool],
        label: str,
    ) -> None:
        """history records 를 GS_HISTORY_BATCH_SIZE 건씩 나눠 송신."""
        try:
            batch_size = int(
                getattr(self._ctx.config, "gs_history_batch_size", 30),
            )
            if batch_size < 1:
                batch_size = 30
            total = len(records)
            for start in range(0, total, batch_size):
                chunk = records[start : start + batch_size]
                history_ids = self._ctx.db.history_ids_from_records(chunk)
                payload = {
                    "packet_type": packet_type,
                    "records": chunk,
                }

                def on_ack(
                    _ack: dict[str, Any],
                    ids: list[int] = history_ids,
                    _delete: Callable[[list[int]], bool] = delete_fn,
                ) -> None:
                    if not _delete(ids):
                        logger.warning("%s delete 실패 ids=%s", label, ids)

                logger.info(
                    "%s 배치 송신 %s~%s / %s",
                    label,
                    start + 1,
                    min(start + len(chunk), total),
                    total,
                )
                if not self.send_with_retry(payload, on_ack):
                    logger.warning("%s 배치 송신 실패 — 이후 배치 중단", label)
                    break
        except Exception as e:
            logger.error("_transmit_history_in_batches 실패 label=%s: %s", label, e)

    def transmit_adcs_filter(self) -> None:
        """SAT_ADCS_FILTER 전체 송신 — ACK 시 delete_adcs_filter."""
        try:
            records = self._ctx.db.get_adcs_filter_all()
            if not records:
                return
            payload = {
                "packet_type": demon_config.GS_PACKET_TYPE_ADCS_FILTER,
                "records": records,
            }

            def on_ack(_ack: dict[str, Any]) -> None:
                if not self._ctx.db.delete_adcs_filter():
                    logger.warning("delete_adcs_filter 실패")

            if not self.send_with_retry(payload, on_ack):
                logger.warning("SAT_ADCS_FILTER 송신 실패 — 삭제하지 않음")
        except Exception as e:
            logger.error("transmit_adcs_filter 실패: %s", e)

    def transmit_event_queue(self) -> None:
        """미전송 이벤트 — META 선송신 후 개별 순차 송신, ACK 시 delete_event."""
        try:
            pending = self._ctx.db.get_pending_events()
            event_ids = _event_ids_from_pending(pending)
            if not event_ids:
                return
            if not self._transmit_event_queue_meta(event_ids):
                logger.warning("SAT_EVENT_QUEUE_META 송신 실패 — 이벤트 본문 송신 중단")
                return
            id_set = set(event_ids)
            for event in pending:
                try:
                    event_id = int(event.get("EVENT_ID", -1))
                except (TypeError, ValueError) as e:
                    logger.error("EVENT_ID 변환 실패: %s", e)
                    continue
                if event_id not in id_set:
                    continue
                payload = {
                    "packet_type": demon_config.GS_PACKET_TYPE_EVENT,
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

    def _transmit_event_queue_meta(self, event_ids: list[int]) -> bool:
        """SAT_EVENT_QUEUE 본문 송신 전 event_total·event_ids 메타데이터 1회 송신."""
        try:
            payload = {
                "packet_type": demon_config.GS_PACKET_TYPE_EVENT_META,
                "event_total": len(event_ids),
                "event_ids": list(event_ids),
            }
            logger.info(
                "SAT_EVENT_QUEUE_META 송신 event_total=%s ids=%s",
                payload["event_total"],
                payload["event_ids"],
            )
            return self.send_with_retry(payload, None)
        except Exception as e:
            logger.error("_transmit_event_queue_meta 실패: %s", e)
            return False

    def transmit_integrity(self) -> None:
        """SAT_INTEGRITY_HASH(HASH) 전체 송신 — 삭제 없음."""
        try:
            records = self._ctx.db.get_integrity_hash()
            if records is None or not records:
                return
            if isinstance(records, dict):
                records = [records]
            payload = {
                "packet_type": demon_config.GS_PACKET_TYPE_INTEGRITY,
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
            attack_hash = self._config_str(
                "GS_CMD_ATTACK_HASH",
                _DEFAULT_GS_CMD_ATTACK_HASH,
            ).upper()
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
                self.handle_attack_sim(cmd)
                return
            if name == attack_hash:
                self.handle_attack_hash(cmd)
                return
            if name == recovery:
                self.handle_recovery(cmd)
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

    def handle_attack_sim(self, cmd: dict[str, Any] | None = None) -> None:
        try:
            sim = self._attack_simulator
            if sim is not None and hasattr(sim, "start"):
                if not bool(sim.start(cmd)):
                    logger.error("AttackSimulator.start 실패")
                return
            self._handle_attack_sim_legacy()
        except Exception as e:
            logger.error("handle_attack_sim 실패: %s", e)

    def handle_attack_hash(self, cmd: dict[str, Any] | None = None) -> None:
        try:
            sim = self._attack_simulator
            if sim is not None and hasattr(sim, "start_hash"):
                if not bool(sim.start_hash(cmd)):
                    logger.error("AttackSimulator.start_hash 실패")
                return
            logger.error("AttackSimulator 미주입 — ATTACK_HASH 스킵")
        except Exception as e:
            logger.error("handle_attack_hash 실패: %s", e)

    def handle_recovery(self, cmd: dict[str, Any] | None = None) -> None:
        try:
            sim = self._attack_simulator
            if sim is not None and hasattr(sim, "stop"):
                if not bool(sim.stop(cmd)):
                    logger.error("AttackSimulator.stop 실패")
            else:
                self._handle_recovery_legacy()
            if not self._ctx.db.reset_integrity_violations():
                logger.warning("reset_integrity_violations 실패")
            else:
                logger.info("RECOVERY: SAT_INTEGRITY_HASH IS_VIOLATED → 0")
        except Exception as e:
            logger.error("handle_recovery 실패: %s", e)

    def _handle_attack_sim_legacy(self) -> None:
        """AttackSimulator 미주입 시 최소 동작."""
        try:
            if self._anomaly_detector is not None:
                self._anomaly_detector.set_attack_mode(True)
            if self._serial_reader is not None:
                self._serial_reader.set_pwr_bias(True)
        except Exception as e:
            logger.error("_handle_attack_sim_legacy 실패: %s", e)

    def _handle_recovery_legacy(self) -> None:
        try:
            if self._serial_reader is not None:
                self._serial_reader.set_pwr_bias(False)
                self._serial_reader.set_gyro_enabled(False)
            if self._anomaly_detector is not None:
                self._anomaly_detector.set_attack_mode(False)
        except Exception as e:
            logger.error("_handle_recovery_legacy 실패: %s", e)

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
                        logger.info(
                            "GS ACK 수신 packet_type=%s",
                            payload.get("packet_type", "?"),
                        )
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

    def _poll_light_edge_transmit(self) -> None:
        """조도 L,dark → L,light 엣지 1회에 transmit_all."""
        try:
            if not getattr(self._ctx.config, "gs_transmit_on_light_edge", True):
                return
            if self._serial_reader is None:
                return
            curr = self._serial_reader.get_light_state()
            if curr is None:
                return
            prev = self._prev_light_state
            dark = demon_config.SERIAL_LIGHT_STATE_DARK
            light = demon_config.SERIAL_LIGHT_STATE_LIGHT
            if curr == light and prev == dark:
                logger.info("조도 dark→light — transmit_all 시작")
                self.transmit_all()
            if curr in (dark, light):
                self._prev_light_state = curr
        except Exception as e:
            logger.error("_poll_light_edge_transmit 실패: %s", e)

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
