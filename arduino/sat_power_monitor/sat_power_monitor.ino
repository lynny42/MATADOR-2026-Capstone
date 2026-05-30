/**
 * 위성 전력 모니터 — demon SerialReader 명세 연동
 *
 * 전력 출력 (1 Hz, demon 파싱용) — 숫자 채널:
 *   SW_ID,VOLTAGE,CURRENT_A,TIMESTAMP
 *   - SW_ID 0: MPU-6050 rail   (INA226 0x40)
 *   - SW_ID 1: Raspberry Pi    (INA226 0x41)
 *   - SW_ID 2: Servo           (INA226 0x44)
 *
 * 조도 출력 (전력 채널 번호 대신 알파벳 태그 L):
 *   L,light,TIMESTAMP   또는   L,dark,TIMESTAMP
 *   조도: 아날로그 AO 사용 (analogRead > LIGHT_AO_THRESHOLD → light)
 *   (SAT_PWR_META SW_ID 3 은 미갱신 — DB 시드 0 유지)
 *
 * 데몬 UART 명령 (한 줄 JSON — AttackSimulator 가 조합 전송):
 *   {"pwr_bias":"on"|"off"}  — MPU rail 전압 바이어스 (이상 탐지 데모)
 *   {"gyro":"on"|"off"}      — MPU6050 전원
 *   {"num":N,"angle":D}      — 서보 N회, 각도 0~180
 *
 * (레거시 ATTACK/RECOVERY 문자열은 사용하지 않음)
 *
 * 보드레이트: 9600 (demon config.py BAUD_RATE 와 동일)
 */
#include <Wire.h>
#include <Servo.h>
#include <INA226_WE.h>
#include <MPU6050_tockn.h>

// demon PWR_SW_ID 0~3
#define SW_ID_MPU    0
#define SW_ID_RPI    1
#define SW_ID_SERVO  2

#define INA226_MPU_ADDR   0x40
#define INA226_RPI_ADDR   0x41
#define INA226_SERVO_ADDR 0x44

#define LIGHT_AO A0
#define LIGHT_DO 8
#define SERVO_PIN 9

#define SERIAL_BAUD 9600
#define POWER_INTERVAL_MS 1000

// 조도: 아날로그 AO (A0 핀). analogRead < LIGHT_AO_THRESHOLD → light (밝음=LOW)
#define LIGHT_AO_THRESHOLD      700
#define LIGHT_TAG 'L'

// ATTACK 시뮬: 전력 채널 전압 바이어스 (V)
#define ATTACK_BIAS_MPU    1.2f
#define ATTACK_BIAS_RPI    0.0f
#define ATTACK_BIAS_SERVO  0.0f

// 1 이면 한글 디버그 출력 (demon 은 CSV 줄만 사용)
#define DEBUG_HUMAN_OUTPUT 0

INA226_WE inaMPU(INA226_MPU_ADDR);
INA226_WE inaRPI(INA226_RPI_ADDR);
INA226_WE inaServo(INA226_SERVO_ADDR);

MPU6050 mpu(Wire);
Servo servo;

bool gyroActive = false;
bool pwrBiasActive = false;

char cmdLine[128];
uint8_t cmdLen = 0;

// 서보 비블로킹 상태
enum ServoState { SERVO_IDLE, SERVO_TO_ANGLE, SERVO_TO_ZERO };
ServoState servoState = SERVO_IDLE;
int servoTargetAngle = 0;
int servoRemainingReps = 0;
unsigned long servoStepStart = 0;
#define SERVO_STEP_MS 500

unsigned long lastPowerEmitMs = 0;

void setupINA226(INA226_WE &ina) {
    ina.init();
    ina.setResistorRange(0.1, 1.0);
    ina.setCorrectionFactor(1.0);
}

float readBusVoltage_V(INA226_WE &ina) {
    return ina.getBusVoltage_V();
}

float readCurrent_A(INA226_WE &ina) {
    return ina.getCurrent_mA() / 1000.0f;
}

float applyAttackBias(uint8_t swId, float voltage) {
    if (!pwrBiasActive) {
        return voltage;
    }
    switch (swId) {
        case SW_ID_MPU:
            return voltage + ATTACK_BIAS_MPU;
        case SW_ID_RPI:
            return voltage + ATTACK_BIAS_RPI;
        case SW_ID_SERVO:
            return voltage + ATTACK_BIAS_SERVO;
        default:
            return voltage;
    }
}

void printPowerCsv(uint8_t swId, float voltage, float currentA) {
    unsigned long ms = millis();
    Serial.print(swId);
    Serial.print(',');
    Serial.print(voltage, 3);
    Serial.print(',');
    Serial.print(currentA, 4);
    Serial.print(',');
    Serial.print(ms);
    Serial.println();
}

void emitPowerSample(uint8_t swId, INA226_WE &ina, float fallbackVoltage, float fallbackCurrentA) {
    float v = readBusVoltage_V(ina);
    float a = readCurrent_A(ina);
    if (v < 0.01f && fallbackVoltage > 0.0f) {
        v = fallbackVoltage;
        a = fallbackCurrentA;
    }
    v = applyAttackBias(swId, v);
    printPowerCsv(swId, v, a);
}

bool readLightAnalogBright(int *outAoVal) {
    int val = analogRead(LIGHT_AO);
    if (outAoVal != NULL) {
        *outAoVal = val;
    }
    return val < LIGHT_AO_THRESHOLD;
}

bool isLightBright(int *outAoVal) {
    return readLightAnalogBright(outAoVal);
}

void emitLightStatus() {
    bool bright = isLightBright(NULL);

    Serial.print(LIGHT_TAG);
    Serial.print(',');
    if (bright) {
        Serial.print(F("light"));
    } else {
        Serial.print(F("dark"));
    }
    Serial.print(',');
    Serial.println(millis());
}

void emitAllPowerCsv() {
    emitPowerSample(SW_ID_MPU, inaMPU, 0.0f, 0.0f);
    emitPowerSample(SW_ID_RPI, inaRPI, 0.0f, 0.0f);
    emitPowerSample(SW_ID_SERVO, inaServo, 0.0f, 0.0f);
    emitLightStatus();
}

#if DEBUG_HUMAN_OUTPUT
void printPowerHuman(INA226_WE &ina, const __FlashStringHelper *label) {
    float voltage = ina.getBusVoltage_V();
    float current = ina.getCurrent_mA();
    float power = ina.getBusPower();
    Serial.print(F("["));
    Serial.print(label);
    Serial.print(F("] 전압: "));
    Serial.print(voltage, 3);
    Serial.print(F(" V | 전류: "));
    Serial.print(current, 1);
    Serial.print(F(" mA | 전력: "));
    Serial.print(power, 1);
    Serial.println(F(" mW"));
}
#endif

String extractValue(const String &json, const String &key) {
    int idx = json.indexOf(key);
    if (idx < 0) {
        return "";
    }
    idx = json.indexOf(':', idx) + 1;
    while (idx < (int)json.length() && json[idx] == ' ') {
        idx++;
    }
    if (idx >= (int)json.length()) {
        return "";
    }
    if (json[idx] == '"') {
        idx++;
        int end = json.indexOf('"', idx);
        if (end < 0) {
            return "";
        }
        return json.substring(idx, end);
    }
    int end = idx;
    while (end < (int)json.length()) {
        char c = json[end];
        if ((c >= '0' && c <= '9') || c == '.' || c == '-') {
            end++;
        } else {
            break;
        }
    }
    return json.substring(idx, end);
}

void handlePwrBiasCommand(const String &biasVal) {
    if (biasVal == "on") {
        pwrBiasActive = true;
        Serial.println(F("# pwr_bias on"));
    } else if (biasVal == "off") {
        pwrBiasActive = false;
        Serial.println(F("# pwr_bias off"));
    }
}

void handleGyroCommand(const String &gyroVal) {
    if (gyroVal == "on") {
        gyroActive = true;
        Wire.beginTransmission(0x68);
        Wire.write(0x6B);
        Wire.write(0x00);
        Wire.endTransmission();
        Serial.println(F("# gyro on"));
    } else if (gyroVal == "off") {
        gyroActive = false;
        Wire.beginTransmission(0x68);
        Wire.write(0x6B);
        Wire.write(0x40);
        Wire.endTransmission();
        Serial.println(F("# gyro off"));
    }
}

void startServoMotion(int num, int angle) {
    servoTargetAngle = angle;
    servoRemainingReps = num;
    servo.write(angle);
    servoState = SERVO_TO_ANGLE;
    servoStepStart = millis();
}

void updateServo() {
    if (servoState == SERVO_IDLE) return;
    if (millis() - servoStepStart < SERVO_STEP_MS) return;

    if (servoState == SERVO_TO_ANGLE) {
        servo.write(0);
        servoState = SERVO_TO_ZERO;
        servoStepStart = millis();
    } else if (servoState == SERVO_TO_ZERO) {
        servoRemainingReps--;
        if (servoRemainingReps <= 0) {
            servoState = SERVO_IDLE;
            Serial.println(F("# servo done"));
        } else {
            servo.write(servoTargetAngle);
            servoState = SERVO_TO_ANGLE;
            servoStepStart = millis();
        }
    }
}

void handleMotorCommand(const String &numVal, const String &angleVal) {
    if (numVal.length() == 0 || angleVal.length() == 0) {
        return;
    }
    int num = numVal.toInt();
    int angle = constrain(angleVal.toInt(), 0, 180);
    Serial.print(F("# servo "));
    Serial.print(num);
    Serial.print(F(" x angle "));
    Serial.println(angle);
    startServoMotion(num, angle);
}

void handleJsonCommand(const String &input) {
    String biasVal = extractValue(input, "pwr_bias");
    if (biasVal.length() > 0) {
        handlePwrBiasCommand(biasVal);
    }
    String gyroVal = extractValue(input, "gyro");
    if (gyroVal.length() > 0) {
        handleGyroCommand(gyroVal);
    }
    String numVal = extractValue(input, "num");
    String angleVal = extractValue(input, "angle");
    if (numVal.length() > 0 && angleVal.length() > 0) {
        handleMotorCommand(numVal, angleVal);
    }
}

void handleDaemonCommand(const String &input) {
    String line = input;
    line.trim();
    if (line.length() == 0) {
        return;
    }
    if (line.charAt(0) == '{') {
        handleJsonCommand(line);
        Serial.print(F("# json: "));
        Serial.println(line);
        return;
    }
    Serial.print(F("# unknown cmd (use JSON): "));
    Serial.println(line);
}

void pollSerialCommands() {
    while (Serial.available() > 0) {
        char c = (char)Serial.read();
        if (c == '\r') {
            continue;
        }
        if (c == '\n') {
            cmdLine[cmdLen] = '\0';
            handleDaemonCommand(String(cmdLine));
            cmdLen = 0;
            continue;
        }
        if (cmdLen < sizeof(cmdLine) - 1) {
            cmdLine[cmdLen++] = c;
        }
    }
}

#if DEBUG_HUMAN_OUTPUT
void printHumanSensors() {
    int aoVal = 0;
    bool bright = isLightBright(&aoVal);
    Serial.print(F("[조도] "));
    Serial.print(bright ? F("light") : F("dark"));
    Serial.print(F(" (AO="));
    Serial.print(aoVal);
    Serial.println(F(")"));

    if (gyroActive) {
        mpu.update();
        Serial.print(F("[MPU] X="));
        Serial.print(mpu.getAngleX());
        Serial.print(F(" Y="));
        Serial.print(mpu.getAngleY());
        Serial.print(F(" Z="));
        Serial.println(mpu.getAngleZ());
    } else {
        Serial.println(F("[MPU] off"));
    }

    printPowerHuman(inaMPU, F("MPU rail"));
    printPowerHuman(inaRPI, F("RPi rail"));
    printPowerHuman(inaServo, F("Servo rail"));
    Serial.println(F("---"));
}
#endif

void setup() {
    Serial.begin(SERIAL_BAUD);
    while (!Serial && millis() < 3000) {
        ;
    }

    Wire.begin();
    setupINA226(inaMPU);
    setupINA226(inaRPI);
    setupINA226(inaServo);

    mpu.begin();
    // true 이면 시리얼에 보정 문구 출력 → demon CSV 파싱 방해
    mpu.calcGyroOffsets(false);
    Wire.beginTransmission(0x68);
    Wire.write(0x6B);
    Wire.write(0x40);
    Wire.endTransmission();

    servo.attach(SERVO_PIN);
    servo.write(0);
    // LIGHT_AO: 아날로그 핀은 pinMode 불필요

    cmdLen = 0;
    Serial.println(F("# sat_power_monitor ready"));
    Serial.println(F("# power: 0,1,2 = CSV | light: L,light|dark (AO threshold=700)"));
    Serial.println(F("# CMD: JSON pwr_bias | gyro | num+angle"));
}

void loop() {
    pollSerialCommands();
    updateServo();

    unsigned long now = millis();
    if (now - lastPowerEmitMs >= POWER_INTERVAL_MS) {
        lastPowerEmitMs = now;
        emitAllPowerCsv();
#if DEBUG_HUMAN_OUTPUT
        printHumanSensors();
#endif
    }
}
