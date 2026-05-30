"""
데몬 전역 설정. 모든 환경별 상수는 여기 한 곳에서만 정의한다.

- 임무 ICD에 맞게 텔레메트리 MID/오프셋을 조정한다.
- NOS3 generic_* / SC MID는 저장소 옆 nos3 트리의 msgids.h 와 일치시킨다.
- 절대 워커 코드 안에 매직넘버를 하드코딩하지 말 것.
"""
from __future__ import annotations

import logging

# ============================================================
# 시리얼 (아두이노 전력 수집)
# ============================================================
SERIAL_PORT = "/dev/ttyUSB0"
BAUD_RATE = 9600
SERIAL_READ_TIMEOUT_SEC = 1.0
SERIAL_REOPEN_BACKOFF_SEC = 5.0
# 아두이노 전력 CSV SW_ID 상한 (0~2 INA226, 3번은 L,light|dark 별도 라인)
SERIAL_PWR_SW_ID_MAX = 2
SERIAL_LIGHT_TAG = "L"
# 아두이노 JSON — AttackSimulator 가 개별 전송 (ATTACK/RECOVERY 문자열 미사용)
UART_JSON_PWR_BIAS_ON = "on"
UART_JSON_PWR_BIAS_OFF = "off"
UART_JSON_GYRO_ON = "on"
UART_JSON_GYRO_OFF = "off"
SERVO_ANGLE_MIN = 0
SERVO_ANGLE_MAX = 180
SERVO_REPEAT_MIN = 1
SERVO_REPEAT_MAX = 20
# 조도 L,light|dark 는 수신 전용(제어 명령 없음)
SERIAL_LIGHT_STATE_LIGHT = "light"
SERIAL_LIGHT_STATE_DARK = "dark"
# True 면 수신·파싱·DB 반영 시 INFO (시리얼 디버그용)
SERIAL_LOG_PARSED = False

# ============================================================
# UDP (cFS TO 텔레메트리 수신)
# ============================================================
UDP_TLM_BIND_HOST = "0.0.0.0"
UDP_TLM_PORT = 5020
UDP_RECV_BUFFER_BYTES = 65535
GS_MAX_PACKET_BYTES = 2_000_000

# ============================================================
# 지상국 TCP (송수신)
# ============================================================
GS_HOST = "192.168.0.29"
GS_PORT = 6000
GS_SEND_RETRY_MAX = 3
GS_SEND_RETRY_BASE_SEC = 1.0
# 지상국 → 위성 커맨드 이름 (GScomms.dispatch_command)
GS_CMD_ATTACK_SIM = "ATTACK_SIM"
GS_CMD_ATTACK_HASH = "ATTACK_HASH"
GS_CMD_RECOVERY = "RECOVERY"
GS_CMD_UPDATE_THRESHOLD = "UPDATE_THRESHOLD"
GS_CMD_UPDATE_HASH = "UPDATE_HASH"
GS_CMD_ACK = "ACK"
GS_CMD_LISTEN_HOST = "0.0.0.0"
GS_CMD_LISTEN_PORT_OFFSET = 1
# 지상국 → 위성 커맨드 송신 목적 (GScomms 수신 포트 = GS_PORT + OFFSET)
# 현재 동일 PC 테스트: 127.0.0.1 / 추후 위성: 192.168.0.7
GS_CMD_SAT_HOST = "127.0.0.1"
GS_CMD_SAT_PORT = GS_PORT + GS_CMD_LISTEN_PORT_OFFSET
# 지상국 bulk 송신: 조도 L,dark → L,light 엣지 1회 (SUN_VALID 미사용)
GS_TRANSMIT_ON_LIGHT_EDGE = True
GS_POLL_INTERVAL_SEC = 1.0
# PWR/TLM history 송신 배치 크기 (HISTORY_ID 건수, 패킷 분할)
GS_HISTORY_BATCH_SIZE = 30
# 지상국 송신 packet_type (GScomms JSON)
GS_PACKET_TYPE_EVENT_META = "SAT_EVENT_QUEUE_META"
GS_PACKET_TYPE_EVENT = "SAT_EVENT_QUEUE"
GS_PACKET_TYPE_INTEGRITY = "SAT_INTEGRITY_HASH"
GS_PACKET_TYPE_ADCS_FILTER = "SAT_ADCS_FILTER"
GS_PACKET_TYPE_TLM_HISTORY = "SAT_TLM_HISTORY"
GS_PACKET_TYPE_PWR_HISTORY = "SAT_PWR_HISTORY"
# bulk 송신 순서: EVENT(META→본문) → INTEGRITY(HASH) → ADCS → TLM → PWR
GS_EVENT_ATTACK_CONFIRMED = "ATTACK_CONFIRMED"
GS_EVENT_SEU_DETECTED = "SEU_DETECTED"

# ============================================================
# DB
# ============================================================
# 운영 시: "/var/sat_monitor/sat_monitor.db" 등 절대 경로 권장.
# 개발 시: None 이면 demon 패키지 옆 database.sqlite 를 사용 (core.context 가 처리).
DB_PATH: str | None = None
SQLITE_BUSY_TIMEOUT_MS = 5000
SAT_TLM_ID = 1
SAT_ADCS_FILTER_CHANNEL_ID = 1
PWR_SW_ID_COUNT = 3

# SAT_TLM_CURRENT / SAT_TLM_HISTORY 공통 데이터 컬럼 (UDP pending flush·history INSERT)
TLM_CURRENT_UPDATEABLE_COLS: tuple[str, ...] = (
    "MISSION_MODE",
    "OBC_S_TICK",
    "HEAP_FREE",
    "APPENABLESTATE",
    "DWELL_MASK",
    "ADCS_MODE",
    "SVB_X",
    "SVB_Y",
    "SVB_Z",
    "WBN_X",
    "WBN_Y",
    "WBN_Z",
    "DT",
    "TORQUER_PERIOD",
    "SUN_VALID",
    # cFS / NOS3 HK — tlm_parse_cfs.py
    "SYSLOGENTRIES",
    "ERLOGENTRIES",
    "RESETSPERFORMED",
    "LASTVALCRC",
    "ENABLEDROUTES",
    "COMBINEDPACKETSSENT",
    "SKIPPEDSLOTSCOUNT",
    "EXECOUNTS",
    "APPCSERRCOUNTER",
    "OSCSERRCOUNTER",
    "FORWARD_ERR_COUNT",
)

# generic_imu / generic_mag device 페이로드 (CFE 헤더 제외, generic_*_device.h)
GENERIC_IMU_DEVICE_DATA_BYTES = 24
GENERIC_MAG_DEVICE_DATA_BYTES = 12

# ============================================================
# 수집 주기
# ============================================================
COLLECT_INTERVAL_SEC = 1.0

# ============================================================
# 전력 초기 임계치 (SW_ID 0~3) — 아두이노 INA226 실측 기준 (2026-05)
#   SW_0 MPU rail:  대기 ~3.27V, ATTACK ~4.47V
#   SW_1 RPi rail:  대기 ~4.82V (구 3.0~3.6V 는 3.3V 논리전압 가정으로 부적합)
#   SW_2 Servo:     대기 ~4.81V, 서보 부하 시 ~3.85V
#   SW_3:           조도 전용 — 전력 CSV 미갱신, 시드용
# ============================================================
V_THRESHOLD_LO = [3.10, 4.60, 3.50, 3.0]
V_THRESHOLD_HI = [3.45, 5.00, 5.00, 3.6]

# ============================================================
# 물리적 범위 필터 (parse_serial_line 1차 필터)
# ============================================================
VOLTAGE_MAX = 6.0
CURRENT_MAX = 5.0

# ============================================================
# 무결성 검증 (cFS cpu2 cf — 폴더 매니페스트 해시 1건)
# ============================================================
INTEGRITY_TARGET_DIR = "~/cfs/cpu2/cf"
INTEGRITY_DIR_FILE_ID = 1
INTEGRITY_DIR_FILE_PATH = "."

# ============================================================
# 이상탐지 기준
# ============================================================
EXCEED_COUNT_THRESHOLD = 3
CONSECUTIVE_THRESHOLD = 3
ANOMALY_DELTA_V_THRESHOLD = 0.1
ATTACK_MODE_THRESHOLD_SHRINK_RATIO = 0.1

# ============================================================
# 공격 시뮬레이터 (지상국 ATTACK_SIM → AttackSimulator)
# ============================================================
# 물리: SerialReader JSON — pwr_bias / gyro / servo (아두이노는 명령만 수행)
ATTACK_SIM_PWR_BIAS = True
ATTACK_SIM_ENABLE_GYRO = True
ATTACK_SIM_ENABLE_SERVO = True
ATTACK_SIM_SERVO_REPEATS = 5
ATTACK_SIM_SERVO_ANGLE = 90
# 논리: SAT_ADCS_FILTER / SAT_TLM_CURRENT 에 오탐필터용 이상 스냅샷 주입
ATTACK_SIM_INJECT_LOGICAL = True
# cf 무결성 — ATTACK_HASH 전용 (ATTACK_SIM 과 분리)
ATTACK_HASH_SERVO_REPEATS = 5
ATTACK_HASH_CF_FILENAME = "matador_gs_inject.txt"
ATTACK_HASH_CF_PAYLOAD = "MATADOR ground-station cf file injection\n"

# ============================================================
# 시각 / 로깅
# ============================================================
# DB·로그·이벤트 공통 타임존 (IANA). KST 운용 시 Asia/Seoul.
TIMESTAMP_TIMEZONE = "Asia/Seoul"
LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)s %(levelname)s [%(threadName)s] %(name)s: %(message)s"
# 로그 asctime — TIMESTAMP_TIMEZONE 과 동일 (DB UPDATED_AT 과 날짜 불일치 방지)
LOG_DATEFMT = "%Y-%m-%d %H:%M:%S KST"
# None 이면 stdout 만. 경로 지정 시 파일 핸들러 추가.
LOG_FILE_PATH: str | None = None
LOG_FILE_MAX_BYTES = 10 * 1024 * 1024
LOG_FILE_BACKUP_COUNT = 5

# ============================================================
# CCSDS / cFE 헤더 레이아웃
# ============================================================
# CCSDS Primary Header 길이(바이트)
CCSDS_PRIMARY_HEADER_BYTES = 6

# cFE 텔레메트리 CCSDS 데이터 필드 앞부분(시간 2차 헤더) — 레거시/별도 경로용
CFE_TLM_SEC_HDR_BYTES = 6

# CFE_MSG_TelemetryHeader_t 직후 = generic_* TlmHeader 뒤 앱 페이로드 시작.
# pri.h: Pri(6)+Sec(6)+Spare(4)=16 / priext.h: (Pri+Ext)(10)+Sec(6)=16 — 동일 총바이트.
CFE_SB_TLM_MSG_HDR_BYTES = 16

# generic_adcs_msg.h 등 packed 구조체 struct.unpack 엔디안 ("<"=리틀엔디안, ARM cFS 일반)
TLM_STRUCT_ENDIAN = "<"

# MID 산출 방식:
# - "stream_id": UDP 첫 2바이트 = CCSDS 식별 워드(대개 APID 등) — SB MsgId 와 다를 수 있음.
# - "payload_u16": CCSDS 데이터 필드에서 Tlm 2차 헤더(있으면 6B) 제거 후, 남은 영역 앞 2B = cFE SB StreamId/MsgId.
MID_DERIVE_MODE = "stream_id"

# payload_u16 에서 StreamId 언패킹 (cFE ICD·타깃 엔디안에 맞출 것)
CFE_SB_STREAMID_STRUCT = ">H"

# ============================================================
# 텔레메트리 MID — NOS3 nos3/components/*/fsw/cfs/platform_inc/*_msgids.h 와 일치
# ============================================================
# generic_adcs
GENERIC_ADCS_HK_TLM_MID = 0x0940
GENERIC_ADCS_DI_MID = 0x0941
GENERIC_ADCS_AD_MID = 0x0942
GENERIC_ADCS_GNC_MID = 0x0943
GENERIC_ADCS_AC_MID = 0x0944
GENERIC_ADCS_DO_MID = 0x0945

# ADCS 한 사이클 수신 후 DB flush (나중에 GENERIC_ADCS_GNC_MID 로 줄일 수 있음)
TLM_DB_FLUSH_TRIGGER_MID = GENERIC_ADCS_DO_MID

# generic_imu
GENERIC_IMU_HK_TLM_MID = 0x0925
GENERIC_IMU_DEVICE_TLM_MID = 0x0926

# generic_mag
GENERIC_MAG_HK_TLM_MID = 0x092A
GENERIC_MAG_DEVICE_TLM_MID = 0x092B

# SC
SC_HK_TLM_MID = 0x08AA

# cFE core / cFS 앱 HK — nos3/gsw/cosmos/config/targets/CFS/cmd_tlm/*.txt
CFE_ES_HK_TLM_MID = 0x0800
CFE_SB_HK_TLM_MID = 0x0803
CFE_TBL_HK_TLM_MID = 0x0804
CFE_TIME_HK_TLM_MID = 0x0805
TO_HK_TLM_MID = 0x0880
FM_HK_TLM_MID = 0x088A
HK_APP_HK_TLM_MID = 0x089B
MD_HK_TLM_MID = 0x0890
SCH_HK_TLM_MID = 0x0897
CS_HK_TLM_MID = 0x08A4
DS_HK_TLM_MID = 0x08B8

# generic_reaction_wheel / generic_star_tracker / generic_radio
GENERIC_RW_HK_TLM_MID = 0x0993
GENERIC_STAR_TRACKER_HK_TLM_MID = 0x0935
GENERIC_STAR_TRACKER_DEVICE_TLM_MID = 0x0936
GENERIC_RADIO_HK_TLM_MID = 0x0930

# MGR (Mission Manager — NOS3에서 SpacecraftMode 보유)
# components/mgr/fsw/cfs/platform_inc/mgr_msgids.h
MGR_HK_TLM_MID = 0x08F8

# MID 라우팅 집합 — UDPReceiver.dispatch_tlm 이 사용
# 명세 parse_sc_hktlm 은 미션 모드 추출용. NOS3 에서 실제 소스는 MGR HK 이므로 여기 매핑한다.
MID_MISSION_MODE_TLM: tuple[int, ...] = (MGR_HK_TLM_MID,)
MID_SC_HKTLM: tuple[int, ...] = (SC_HK_TLM_MID,)
MID_ADCS_TLM: tuple[int, ...] = (
    GENERIC_ADCS_HK_TLM_MID,
    GENERIC_ADCS_DI_MID,
    GENERIC_ADCS_AD_MID,
    GENERIC_ADCS_GNC_MID,
    GENERIC_ADCS_AC_MID,
    GENERIC_ADCS_DO_MID,
)
MID_IMU_TLM: tuple[int, ...] = (GENERIC_IMU_HK_TLM_MID, GENERIC_IMU_DEVICE_TLM_MID)
MID_MAG_TLM: tuple[int, ...] = (GENERIC_MAG_HK_TLM_MID, GENERIC_MAG_DEVICE_TLM_MID)
MID_CFS_HK_TLM: tuple[int, ...] = (
    CFE_ES_HK_TLM_MID,
    CFE_SB_HK_TLM_MID,
    CFE_TBL_HK_TLM_MID,
    CFE_TIME_HK_TLM_MID,
    TO_HK_TLM_MID,
    FM_HK_TLM_MID,
    HK_APP_HK_TLM_MID,
    MD_HK_TLM_MID,
    SCH_HK_TLM_MID,
    CS_HK_TLM_MID,
    DS_HK_TLM_MID,
    GENERIC_RADIO_HK_TLM_MID,
)
MID_RW_TLM: tuple[int, ...] = (GENERIC_RW_HK_TLM_MID,)
MID_STAR_TRACKER_TLM: tuple[int, ...] = (
    GENERIC_STAR_TRACKER_HK_TLM_MID,
    GENERIC_STAR_TRACKER_DEVICE_TLM_MID,
)

# MGR HK 페이로드(사용자 영역) 내 SpacecraftMode 오프셋.
# 구조: CommandErrorCount(1) + CommandCount(1) + SpacecraftMode(1) ... → offset 2
MGR_HKTLM_SPACECRAFT_MODE_OFFSET = 2

# NOS3 MGR SpacecraftMode 값 (mgr_app.h) — 로그/UI 해석용 (파서는 정수 그대로 저장)
MGR_SAFE_MODE = 1
MGR_SAFE_REBOOT_MODE = 2
MGR_SCIENCE_MODE = 3
MGR_SCIENCE_REBOOT_MODE = 4

# ============================================================
# 디버그 토글
# ============================================================
# 등록되지 않은 MID 수신 시 INFO 1줄(원격에서 라우팅 미스 확인용; 안정화 후 False 권장)
LOG_UNREGISTERED_TLM = False

# True 면 매 텔레메트리 패킷마다 파싱 요약을 INFO 출력(주기 높음 — 안정화 후 False 권장)
LOG_PARSED_TLM = True
