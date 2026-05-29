from __future__ import annotations

import json
import logging
import threading
from typing import Any

from .. import config as demon_config
from ..core.context import RuntimeContext

logger = logging.getLogger(__name__)

try:
    import serial
    from serial import SerialException
except ImportError:
    serial = None  # type: ignore[assignment]

    class SerialException(OSError):
        """pyserial 미설치 시 대체 예외."""


class SerialReader:
    """
    아두이노 UART 전력·조도 수집 및 제어.

    - 전력 시뮬: send_attack_sim / send_recovery (ATTACK|RECOVERY)
    - 모터·자이로: run_servo_motion / set_gyro_enabled (JSON, sat_power_monitor.ino)
    - 조도: get_light_state (L,light|dark 수신만, 송신 제어 없음)
    """

    def __init__(self, ctx: RuntimeContext) -> None:
        self._ctx = ctx
        self._conn_lock = threading.Lock()
        self._serial: Any | None = None
        self._last_light: str | None = None

    def run(self) -> None:
        """serial_reader_thread — 포트 오픈·수신 루프."""
        logger.info("SerialReader started")
        try:
            while not self._ctx.shutdown_event.is_set():
                if not self._open_serial_port():
                    if self._ctx.shutdown_event.wait(
                        timeout=self._ctx.config.serial_reopen_backoff_sec,
                    ):
                        break
                    continue
                try:
                    self._read_loop()
                except SerialException as e:
                    logger.error("SerialReader 수신 오류(Serial): %s", e)
                except OSError as e:
                    logger.error("SerialReader 수신 오류(OS): %s", e)
                except Exception as e:
                    logger.error("SerialReader 수신 오류: %s", e)
                finally:
                    self._close_serial_port()
                if self._ctx.shutdown_event.wait(
                    timeout=self._ctx.config.serial_reopen_backoff_sec,
                ):
                    break
        except Exception as e:
            logger.error("SerialReader run 실패: %s", e)
        logger.info("SerialReader stopped")

    def get_light_state(self) -> str | None:
        """최근 L,light|dark 파싱 결과 ('light'|'dark', 없으면 None)."""
        try:
            return self._last_light
        except Exception as e:
            logger.error("get_light_state 실패: %s", e)
            return None

    def is_light_bright(self) -> bool | None:
        """조도가 light 이면 True, dark 이면 False, 미수신이면 None."""
        try:
            state = self._last_light
            if state == demon_config.SERIAL_LIGHT_STATE_LIGHT:
                return True
            if state == demon_config.SERIAL_LIGHT_STATE_DARK:
                return False
            return None
        except Exception as e:
            logger.error("is_light_bright 실패: %s", e)
            return None

    def send_attack_sim(self) -> bool:
        """전력 이상 시뮬 — 아두이노 ATTACK."""
        return self.send_uart_command(demon_config.UART_CMD_ATTACK)

    def send_recovery(self) -> bool:
        """전력 시뮬 해제 — 아두이노 RECOVERY."""
        return self.send_uart_command(demon_config.UART_CMD_RECOVERY)

    def send_uart_command(self, cmd: str) -> bool:
        """ATTACK / RECOVERY 한 줄 UART 전송."""
        try:
            text = (cmd or "").strip()
            if text not in (
                demon_config.UART_CMD_ATTACK,
                demon_config.UART_CMD_RECOVERY,
            ):
                logger.warning("지원하지 않는 UART 커맨드: %s", text)
                return False
            return self._send_uart_line(text)
        except Exception as e:
            logger.error("send_uart_command 실패: %s", e)
            return False

    def set_gyro_enabled(self, enabled: bool) -> bool:
        """
        MPU6050 전원/측정 on·off — {"gyro":"on"|"off"}.

        sat_power_monitor.ino handleGyroCommand 와 동일 프로토콜.
        """
        try:
            state = (
                demon_config.UART_JSON_GYRO_ON
                if enabled
                else demon_config.UART_JSON_GYRO_OFF
            )
            return self._send_json_command({"gyro": state})
        except Exception as e:
            logger.error("set_gyro_enabled 실패: %s", e)
            return False

    def run_servo_motion(self, repeat_count: int, angle_deg: int) -> bool:
        """
        서보 데모 — {"num": repeat_count, "angle": angle_deg}.

        repeat_count 회 반복, angle 0~180 (config SERVO_* 범위로 clamp).
        """
        try:
            repeat = int(repeat_count)
            angle = int(angle_deg)
            repeat = max(
                demon_config.SERVO_REPEAT_MIN,
                min(repeat, demon_config.SERVO_REPEAT_MAX),
            )
            angle = max(
                demon_config.SERVO_ANGLE_MIN,
                min(angle, demon_config.SERVO_ANGLE_MAX),
            )
            return self._send_json_command({"num": repeat, "angle": angle})
        except (ValueError, TypeError) as e:
            logger.error("run_servo_motion 입력 오류: %s", e)
            return False
        except Exception as e:
            logger.error("run_servo_motion 실패: %s", e)
            return False

    def _send_json_command(self, payload: dict[str, Any]) -> bool:
        """아두이노 JSON 한 줄 전송."""
        try:
            line = json.dumps(payload, separators=(",", ":"))
            return self._send_uart_line(line)
        except (TypeError, ValueError) as e:
            logger.error("JSON 직렬화 실패: %s", e)
            return False
        except Exception as e:
            logger.error("_send_json_command 실패: %s", e)
            return False

    def _send_uart_line(self, line: str) -> bool:
        """UART 한 줄 전송 (개행 포함). 성공 시 True."""
        try:
            text = (line or "").strip()
            if not text:
                logger.warning("UART 빈 줄 전송 스킵")
                return False
            payload = (text + "\n").encode("ascii")
            with self._conn_lock:
                if self._serial is None or not getattr(self._serial, "is_open", False):
                    logger.error("UART 포트 미연결 — 전송 스킵: %s", text)
                    return False
                self._serial.write(payload)
                self._serial.flush()
            logger.info("UART 전송: %s", text)
            return True
        except SerialException as e:
            logger.error("UART 전송 실패(Serial): %s", e)
            return False
        except OSError as e:
            logger.error("UART 전송 실패(OS): %s", e)
            return False
        except Exception as e:
            logger.error("UART 전송 실패: %s", e)
            return False

    def _open_serial_port(self) -> bool:
        try:
            if serial is None:
                logger.error("pyserial 미설치 — pip install pyserial")
                return False
            with self._conn_lock:
                if self._serial is not None and getattr(self._serial, "is_open", False):
                    return True
                self._serial = serial.Serial(
                    port=self._ctx.config.serial_port,
                    baudrate=self._ctx.config.serial_baud,
                    timeout=self._ctx.config.serial_read_timeout_sec,
                )
            logger.info(
                "시리얼 포트 오픈: %s @ %d",
                self._ctx.config.serial_port,
                self._ctx.config.serial_baud,
            )
            return True
        except SerialException as e:
            logger.error("시리얼 포트 오픈 실패(Serial): %s", e)
            return False
        except OSError as e:
            logger.error("시리얼 포트 오픈 실패(OS): %s", e)
            return False
        except Exception as e:
            logger.error("시리얼 포트 오픈 실패: %s", e)
            return False

    def _close_serial_port(self) -> None:
        try:
            with self._conn_lock:
                if self._serial is not None:
                    if getattr(self._serial, "is_open", False):
                        self._serial.close()
                    self._serial = None
        except SerialException as e:
            logger.error("시리얼 포트 close 실패(Serial): %s", e)
        except OSError as e:
            logger.error("시리얼 포트 close 실패(OS): %s", e)
        except Exception as e:
            logger.error("시리얼 포트 close 실패: %s", e)

    def _read_loop(self) -> None:
        while not self._ctx.shutdown_event.is_set():
            try:
                with self._conn_lock:
                    ser = self._serial
                if ser is None:
                    return
                raw = ser.readline()
            except SerialException as e:
                logger.error("readline 실패(Serial): %s", e)
                return
            except OSError as e:
                logger.error("readline 실패(OS): %s", e)
                return
            except Exception as e:
                logger.error("readline 실패: %s", e)
                return

            if not raw:
                continue
            try:
                line = raw.decode("utf-8", errors="replace")
            except UnicodeError as e:
                logger.error("시리얼 디코딩 실패: %s", e)
                continue
            except Exception as e:
                logger.error("시리얼 디코딩 실패: %s", e)
                continue

            self._dispatch_line(line)

    def _dispatch_line(self, line: str) -> None:
        try:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                return

            tag = demon_config.SERIAL_LIGHT_TAG
            if stripped[0] == tag or stripped.startswith(f"{tag},"):
                light_state = self._parse_light_line(stripped)
                if light_state is None:
                    return
                self._last_light = light_state
                if demon_config.SERIAL_LOG_PARSED:
                    logger.info("serial light=%s", light_state)
                return

            if not self._looks_like_power_csv(stripped):
                return

            sample = self._parse_serial_line(stripped)
            if sample is None:
                return
            if not self._validate_power_range(sample):
                return
            if not self._ctx.db.upsert_pwr_meta(sample):
                logger.warning("upsert_pwr_meta 실패 sw_id=%s", sample.get("sw_id"))
                return
            pwr_row = self._ctx.db.get_pwr_meta(int(sample["sw_id"]))
            if pwr_row is not None:
                self._ctx.db.insert_pwr_history(pwr_row)
            if demon_config.SERIAL_LOG_PARSED:
                logger.info(
                    "serial pwr sw_id=%s V=%.3f A=%.4f",
                    sample["sw_id"],
                    sample["voltage"],
                    sample["current_a"],
                )
        except Exception as e:
            logger.error("_dispatch_line 실패: %s", e)

    def _looks_like_power_csv(self, line: str) -> bool:
        """0~2,전압,전류 형태만 True — MPU 보정 문구 등은 False."""
        try:
            if not line or line[0] not in "012":
                return False
            parts = line.split(",")
            if len(parts) < 3:
                return False
            sw_id = int(parts[0].strip())
            return 0 <= sw_id <= demon_config.SERIAL_PWR_SW_ID_MAX
        except ValueError:
            return False
        except Exception as e:
            logger.error("_looks_like_power_csv 실패: %s", e)
            return False

    def _parse_serial_line(self, line: str) -> dict[str, Any] | None:
        """
        CSV: SW_ID,VOLTAGE,CURRENT_A[,TIMESTAMP]

        반환: {sw_id, voltage, current_a} — TIMESTAMP 는 DB 가 설정.
        """
        try:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 3:
                return None
            sw_id = int(parts[0])
            if sw_id < 0 or sw_id > demon_config.SERIAL_PWR_SW_ID_MAX:
                logger.error("전력 SW_ID 범위 오류: %s", sw_id)
                return None
            voltage = float(parts[1])
            current_a = float(parts[2])
            return {"sw_id": sw_id, "voltage": voltage, "current_a": current_a}
        except ValueError as e:
            logger.error("전력 CSV 파싱 실패(ValueError): %s — line=%s", e, line)
            return None
        except Exception as e:
            logger.error("전력 CSV 파싱 실패: %s — line=%s", e, line)
            return None

    def _parse_light_line(self, line: str) -> str | None:
        """
        L,light|dark[,TIMESTAMP]

        반환: 'light' | 'dark' (SAT_PWR_META SW_ID 3 미갱신).
        """
        try:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 2:
                return None
            if parts[0].upper() != demon_config.SERIAL_LIGHT_TAG:
                return None
            state = parts[1].lower()
            if state not in ("light", "dark"):
                return None
            return state
        except Exception as e:
            logger.error("조도 CSV 파싱 실패: %s — line=%s", e, line)
            return None

    def _validate_power_range(self, pwr_sample: dict[str, Any]) -> bool:
        """voltage ∈ [0, VOLTAGE_MAX], current_a ∈ [0, CURRENT_MAX]."""
        try:
            voltage = float(pwr_sample["voltage"])
            current_a = float(pwr_sample["current_a"])
            vmax = float(self._ctx.config.voltage_max)
            cmax = float(self._ctx.config.current_max)
            if voltage < 0.0 or voltage > vmax:
                logger.warning(
                    "전압 범위 이탈 sw_id=%s V=%s (max=%s)",
                    pwr_sample.get("sw_id"),
                    voltage,
                    vmax,
                )
                return False
            if current_a < 0.0 or current_a > cmax:
                logger.warning(
                    "전류 범위 이탈 sw_id=%s A=%s (max=%s)",
                    pwr_sample.get("sw_id"),
                    current_a,
                    cmax,
                )
                return False
            return True
        except (KeyError, ValueError, TypeError) as e:
            logger.error("validate_power_range 입력 오류: %s", e)
            return False
        except Exception as e:
            logger.error("validate_power_range 실패: %s", e)
            return False
