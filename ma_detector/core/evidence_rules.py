"""Evidence rule scoring functions for MA integrated detection."""

from __future__ import annotations

import logging
import statistics
from typing import Any, Callable

from ma_detector.core.baseline import BaselineManager
from ma_detector.core.rule_activation import evaluate_rule_activation, repeat_ratio_score

logger = logging.getLogger(__name__)


class EvidenceRules:
    """Evaluates configured evidence rule IDs against a telemetry window."""

    def __init__(self, baseline_manager: BaselineManager, threshold_config: dict[str, Any]) -> None:
        try:
            self.bm = baseline_manager
            self.z_thr = threshold_config["z_score"]
            self.abs_thr = threshold_config["absolute"]
            self._func_map: dict[str, Callable[[list[dict[str, Any]]], float]] = {
                "E-01": self._e01,
                "E-02": self._e02,
                "E-03": self._e03,
                "E-04": self._e04,
                "E-05": self._e05,
                "E-06": self._e06,
                "E-07": self._e07,
                "E-08": self._e08,
                "E-09": self._e09,
                "E-10": self._e10,
                "E-11": self._e11,
                "E-12": self._e12,
                "E-13": self._e13,
                "E-X1": self._ex1,
                "E-X2": self._ex2,
                "E-X3": self._ex3,
                "E-X4": self._ex4,
                "E-X5": self._ex5,
                "P1-X01": self._p1_x01,
                "P3-X01": self._p3_x01,
                "S2-X01": self._s2_x01,
            }
        except KeyError as error:
            logger.error("threshold config missing key: %s", error)
            self.bm = baseline_manager
            self.z_thr = {"SOFT": 2.0, "HARD": 3.0, "SEVERE": 4.0}
            self.abs_thr = {}
            self._func_map = {}
        except Exception as error:
            logger.error("evidence rule initialization failed: %s", error)
            self.bm = baseline_manager
            self.z_thr = {"SOFT": 2.0, "HARD": 3.0, "SEVERE": 4.0}
            self.abs_thr = {}
            self._func_map = {}

    def evaluate(
        self,
        rule_id: str,
        window: list[dict[str, Any]],
        rule_def: dict[str, Any] | None = None,
    ) -> float:
        """Evaluate one rule by ID and clamp the result to the 0.0 to 1.0 range."""
        try:
            activation = (rule_def or {}).get("activation")
            if activation:
                return self._clamp(
                    evaluate_rule_activation(
                        activation,
                        window,
                        self.bm,
                        self.z_thr,
                        self.abs_thr,
                        legacy_evaluator=self._evaluate_legacy,
                        rule_id=rule_id,
                    )
                )
            func = self._func_map.get(rule_id)
            if func is None:
                logger.warning("unknown evidence rule id: %s", rule_id)
                return 0.0
            return self._clamp(func(window))
        except (TypeError, ValueError) as error:
            logger.error("rule evaluation failed for %s: %s", rule_id, error)
            return 0.0
        except Exception as error:
            logger.error("unexpected rule evaluation failure for %s: %s", rule_id, error)
            return 0.0

    def _evaluate_legacy(self, rule_id: str, window: list[dict[str, Any]]) -> float:
        try:
            func = self._func_map.get(rule_id)
            if func is None:
                return 0.0
            return self._clamp(func(window))
        except Exception as error:
            logger.error("legacy rule evaluation failed for %s: %s", rule_id, error)
            return 0.0

    @staticmethod
    def _clamp(value: float) -> float:
        try:
            return max(0.0, min(float(value), 1.0))
        except (TypeError, ValueError) as error:
            logger.error("score clamp failed: %s", error)
            return 0.0
        except Exception as error:
            logger.error("unexpected score clamp failure: %s", error)
            return 0.0

    @staticmethod
    def _numeric(snapshot: dict[str, Any], column: str, default: float = 0.0) -> float:
        try:
            value = snapshot.get(column, default)
            return float(value) if isinstance(value, (int, float)) else default
        except (TypeError, ValueError) as error:
            logger.error("numeric conversion failed for %s: %s", column, error)
            return default
        except Exception as error:
            logger.error("unexpected numeric conversion failure for %s: %s", column, error)
            return default

    def _z_max(self, window: list[dict[str, Any]], column: str, direction: str) -> float:
        try:
            scores = []
            for snapshot in window:
                if column not in snapshot or not isinstance(snapshot[column], (int, float)):
                    continue
                z_value = self.bm.compute_z(snapshot[column], self.bm.get_stats(snapshot, column))
                scores.append(self.bm.z_to_score(z_value, direction, self.z_thr))
            return max(scores) if scores else 0.0
        except (TypeError, ValueError) as error:
            logger.error("z max calculation failed for %s: %s", column, error)
            return 0.0
        except Exception as error:
            logger.error("unexpected z max failure for %s: %s", column, error)
            return 0.0

    def _flag_nonzero(self, window: list[dict[str, Any]], column: str) -> float:
        try:
            return 1.0 if any(self._numeric(snapshot, column) > 0 for snapshot in window) else 0.0
        except Exception as error:
            logger.error("nonzero flag failed for %s: %s", column, error)
            return 0.0

    def _flag_mismatch(self, window: list[dict[str, Any]], col_a: str, col_b: str) -> float:
        try:
            return 1.0 if any(snapshot.get(col_a) != snapshot.get(col_b) for snapshot in window) else 0.0
        except Exception as error:
            logger.error("mismatch flag failed for %s/%s: %s", col_a, col_b, error)
            return 0.0

    def _flag_changed_from_baseline(self, window: list[dict[str, Any]], column: str) -> float:
        try:
            for snapshot in window:
                if column in snapshot and snapshot.get(column) != self.bm.get_stats(snapshot, column).mean:
                    return 1.0
            return 0.0
        except Exception as error:
            logger.error("baseline changed flag failed for %s: %s", column, error)
            return 0.0

    def _e01(self, window: list[dict[str, Any]]) -> float:
        try:
            return (
                repeat_ratio_score(window, "CH1_FAULT_CRC", 0.1) * 0.35
                + self._flag_nonzero(window, "CH1_FAULT_FILE_SIZE_MISMATCH") * 0.25
                + self._z_max(window, "CHILDQUEUECOUNT", "increase") * 0.20
                + self._z_max(window, "FILEWRITEERRCOUNTER", "increase") * 0.20
            )
        except Exception as error:
            logger.error("E-01 scoring failed: %s", error)
            return 0.0

    def _e02(self, window: list[dict[str, Any]]) -> float:
        try:
            return (
                self._z_max(window, "CMDREJECTEDCOUNTER", "increase") * 0.45
                + self._z_max(window, "PIPEOVERFLOWRRCNT", "increase") * 0.30
                + self._z_max(window, "COMBINEDPACKETSSENT", "decrease") * 0.25
            )
        except Exception as error:
            logger.error("E-02 scoring failed: %s", error)
            return 0.0

    def _e03(self, window: list[dict[str, Any]]) -> float:
        try:
            return (
                self._flag_mismatch(window, "OBC_P_HASH", "EXPECTED_CRC") * 0.40
                + self._z_max(window, "APPCSERRCOUNTER", "increase") * 0.20
                + self._z_max(window, "OSCSERRCOUNTER", "increase") * 0.20
                + self._flag_changed_from_baseline(window, "LASTVALCRC") * 0.20
            )
        except Exception as error:
            logger.error("E-03 scoring failed: %s", error)
            return 0.0

    def _e04(self, window: list[dict[str, Any]]) -> float:
        try:
            return (
                self._z_max(window, "HEAP_FREE", "decrease") * 0.40
                + self._z_max(window, "MEMINUSE", "increase") * 0.35
                + self._z_max(window, "EXECOUNTS", "increase") * 0.25
            )
        except Exception as error:
            logger.error("E-04 scoring failed: %s", error)
            return 0.0

    def _e05(self, window: list[dict[str, Any]]) -> float:
        try:
            scores = []
            for index, snapshot in enumerate(window):
                integrity_fault = (
                    snapshot.get("OBC_P_HASH") != snapshot.get("EXPECTED_CRC")
                    or self._numeric(snapshot, "APPCSERRCOUNTER") > 0
                    or self._numeric(snapshot, "IS_VIOLATED") == 1
                )

                if index > 0:
                    prev_reset = self._numeric(window[index - 1], "PROCESSOR_RESET_COUNT")
                    no_reset = self._numeric(snapshot, "PROCESSOR_RESET_COUNT") == prev_reset
                else:
                    reset_stats = self.bm.get_stats(snapshot, "PROCESSOR_RESET_COUNT")
                    no_reset = self._numeric(snapshot, "PROCESSOR_RESET_COUNT") == reset_stats.mean

                if not (integrity_fault and no_reset):
                    scores.append(0.0)
                    continue

                tick_drop = self._numeric(snapshot, "OBC_S_TICK") < self.bm.get_stats(snapshot, "OBC_S_TICK").mean
                app_z = self.bm.compute_z(
                    self._numeric(snapshot, "APPCSERRCOUNTER"),
                    self.bm.get_stats(snapshot, "APPCSERRCOUNTER"),
                )
                fault_score = self.bm.z_to_score(app_z, "increase", self.z_thr)
                scores.append(1.0 * 0.50 + fault_score * 0.30 + (0.8 if tick_drop else 0.0) * 0.20)
            return max(scores) if scores else 0.0
        except Exception as error:
            logger.error("E-05 scoring failed: %s", error)
            return 0.0

    def _e06(self, window: list[dict[str, Any]]) -> float:
        try:
            cpu_high = float(self.abs_thr.get("UTILCPUAVG_HIGH", 80.0))
            cpu_score = max((0.9 if self._numeric(snapshot, "UTILCPUAVG") > cpu_high else 0.0) for snapshot in window)
            return (
                cpu_score * 0.50
                + self._z_max(window, "SKIPPEDSLOTSCOUNT", "increase") * 0.25
                + self._z_max(window, "ERLOGENTRIES", "increase") * 0.25
            )
        except ValueError as error:
            logger.error("E-06 scoring failed: %s", error)
            return 0.0
        except Exception as error:
            logger.error("unexpected E-06 scoring failure: %s", error)
            return 0.0

    def _e07(self, window: list[dict[str, Any]]) -> float:
        try:
            return (
                self._flag_changed_from_baseline(window, "DWELL_MASK") * 0.35
                + self._z_max(window, "DWELL_ADDR_COUNT", "increase") * 0.35
                + self._z_max(window, "DWELL_BYTE_COUNT", "increase") * 0.30
            )
        except Exception as error:
            logger.error("E-07 scoring failed: %s", error)
            return 0.0

    def _e08(self, window: list[dict[str, Any]]) -> float:
        try:
            return (
                self._z_max(window, "COMBINEDPACKETSSENT", "increase") * 0.45
                + self._z_max(window, "ENABLEDROUTES", "increase") * 0.30
                + self._z_max(window, "FORWARD_ERR_COUNT", "increase") * 0.25
            )
        except Exception as error:
            logger.error("E-08 scoring failed: %s", error)
            return 0.0

    def _e09(self, window: list[dict[str, Any]]) -> float:
        try:
            qerr_score = max(
                (
                    0.9
                    if any(abs(self._numeric(snapshot, f"QERR_{index}")) > 0.3 for index in range(4))
                    else 0.0
                )
                for snapshot in window
            )
            tcmd_score = max(self._z_max(window, f"TCMD_{axis}", "increase") for axis in ["X", "Y", "Z"])
            momentum_score = max(self._z_max(window, f"MOMENTUM_NMS_{index}", "increase") for index in range(3))
            rw_score = max(self._z_max(window, f"DEVICE_ERR_RW{index}", "increase") for index in range(3))
            return qerr_score * 0.35 + tcmd_score * 0.25 + momentum_score * 0.25 + rw_score * 0.15
        except ValueError as error:
            logger.error("E-09 scoring failed: %s", error)
            return 0.0
        except Exception as error:
            logger.error("unexpected E-09 scoring failure: %s", error)
            return 0.0

    def _e10(self, window: list[dict[str, Any]]) -> float:
        try:
            bus_score = max(self._z_max(window, column, "increase") for column in ["BUS_3P3V", "BUS_5P0V"])
            sw_score = max(self._z_max(window, f"SW_{index}_CURRENT", "increase") for index in range(8))
            return self._z_max(window, "BATT_VOLTAGE", "decrease") * 0.40 + bus_score * 0.30 + sw_score * 0.30
        except ValueError as error:
            logger.error("E-10 scoring failed: %s", error)
            return 0.0
        except Exception as error:
            logger.error("unexpected E-10 scoring failure: %s", error)
            return 0.0

    def _e11(self, window: list[dict[str, Any]]) -> float:
        try:
            scores = []
            imu_max = float(self.abs_thr.get("IMU_WBN_VARIANCE_MAX", 0.001))
            mag_max = float(self.abs_thr.get("RAW_MAG_VARIANCE_MAX", 0.001))
            for snapshot in window:
                if self._numeric(snapshot, "IMU_WBN_VARIANCE", 1.0) >= imu_max:
                    scores.append(0.0)
                    continue
                mag_frozen = self._numeric(snapshot, "RAW_MAG_VARIANCE", 1.0) < mag_max
                st_invalid = self._numeric(snapshot, "ST_VALID", 1.0) == 0
                scores.append(min(0.6 + (0.2 if mag_frozen else 0.0) + (0.2 if st_invalid else 0.0), 1.0))
            return max(scores) if scores else 0.0
        except Exception as error:
            logger.error("E-11 scoring failed: %s", error)
            return 0.0

    def _e12(self, window: list[dict[str, Any]]) -> float:
        try:
            scores = []
            for snapshot in window:
                log_frozen = snapshot.get("SYSLOGENTRIES") == self.bm.get_stats(snapshot, "SYSLOGENTRIES").mean
                crc_changed = snapshot.get("LASTVALCRC") != self.bm.get_stats(snapshot, "LASTVALCRC").mean
                if not (log_frozen and crc_changed):
                    scores.append(0.0)
                    continue
                is_sent_zero = self._numeric(snapshot, "IS_SENT", 1.0) == 0
                cmd_z = self.bm.compute_z(
                    self._numeric(snapshot, "CMDREJECTEDCOUNTER"),
                    self.bm.get_stats(snapshot, "CMDREJECTEDCOUNTER"),
                )
                cmd_score = self.bm.z_to_score(cmd_z, "increase", self.z_thr)
                scores.append(min(0.70 + (0.15 if is_sent_zero else 0.0) + cmd_score * 0.15, 1.0))
            return max(scores) if scores else 0.0
        except Exception as error:
            logger.error("E-12 scoring failed: %s", error)
            return 0.0

    def _e13(self, window: list[dict[str, Any]]) -> float:
        try:
            scores = []
            for snapshot in window:
                fwd_z = self.bm.compute_z(
                    self._numeric(snapshot, "FORWARD_ERR_COUNT"),
                    self.bm.get_stats(snapshot, "FORWARD_ERR_COUNT"),
                )
                if fwd_z < self.z_thr["HARD"]:
                    scores.append(0.0)
                    continue
                crc_hidden = (
                    self._numeric(snapshot, "CH1_FAULT_CRC", 1.0) == 0
                    and self._numeric(snapshot, "CH2_FAULT_CRC", 1.0) == 0
                )
                erlog_static = snapshot.get("ERLOGENTRIES") == self.bm.get_stats(snapshot, "ERLOGENTRIES").mean
                fwd_score = self.bm.z_to_score(fwd_z, "increase", self.z_thr)
                scores.append(min(fwd_score * 0.60 + (0.20 if crc_hidden else 0.0) + (0.20 if erlog_static else 0.0), 1.0))
            return max(scores) if scores else 0.0
        except Exception as error:
            logger.error("E-13 scoring failed: %s", error)
            return 0.0

    def _ex1(self, window: list[dict[str, Any]]) -> float:
        try:
            scores = []
            imu_max = float(self.abs_thr.get("IMU_WBN_VARIANCE_MAX", 0.001))
            tcmd_ratio = float(self.abs_thr.get("TCMD_BASELINE_RATIO", 1.1))
            for snapshot in window:
                tcmd_mag = max(abs(self._numeric(snapshot, f"TCMD_{axis}")) for axis in ["X", "Y", "Z"])
                base_tcmd = max(abs(self.bm.get_stats(snapshot, f"TCMD_{axis}").mean) for axis in ["X", "Y", "Z"])
                no_maneuver = tcmd_mag < max(base_tcmd * tcmd_ratio, 0.000001)
                rw_zs = [
                    self.bm.compute_z(
                        self._numeric(snapshot, f"SW_{index}_CURRENT"),
                        self.bm.get_stats(snapshot, f"SW_{index}_CURRENT"),
                    )
                    for index in range(3)
                ]
                rw_up = any(z_value >= self.z_thr["SOFT"] for z_value in rw_zs)
                rw_score = self.bm.z_to_score(max(rw_zs), "increase", self.z_thr)
                imu_frozen = self._numeric(snapshot, "IMU_WBN_VARIANCE", 1.0) < imu_max

                if not (no_maneuver and rw_up):
                    scores.append(0.0)
                    continue
                scores.append(min(rw_score * 0.60 + 0.20 + (0.20 if imu_frozen else 0.0), 1.0))
            return max(scores) if scores else 0.0
        except ValueError as error:
            logger.error("E-X1 scoring failed: %s", error)
            return 0.0
        except Exception as error:
            logger.error("unexpected E-X1 scoring failure: %s", error)
            return 0.0

    def _ex2(self, window: list[dict[str, Any]]) -> float:
        try:
            scores = []
            for snapshot in window:
                fwd_z = self.bm.compute_z(
                    self._numeric(snapshot, "FORWARD_ERR_COUNT"),
                    self.bm.get_stats(snapshot, "FORWARD_ERR_COUNT"),
                )
                if fwd_z < self.z_thr["HARD"]:
                    scores.append(0.0)
                    continue
                crc_hidden = (
                    self._numeric(snapshot, "CH1_FAULT_CRC", 1.0) == 0
                    and self._numeric(snapshot, "CH2_FAULT_CRC", 1.0) == 0
                )
                if not crc_hidden:
                    scores.append(0.0)
                    continue
                erlog_static = snapshot.get("ERLOGENTRIES") == self.bm.get_stats(snapshot, "ERLOGENTRIES").mean
                fwd_score = self.bm.z_to_score(fwd_z, "increase", self.z_thr)
                scores.append(min(fwd_score * 0.60 + 0.20 + (0.20 if erlog_static else 0.0), 1.0))
            return max(scores) if scores else 0.0
        except Exception as error:
            logger.error("E-X2 scoring failed: %s", error)
            return 0.0

    def _ex3(self, window: list[dict[str, Any]]) -> float:
        try:
            scores = []
            for index, snapshot in enumerate(window):
                if "OBC_P_HASH" in snapshot and "EXPECTED_CRC" in snapshot:
                    hash_mismatch = snapshot.get("OBC_P_HASH") != snapshot.get("EXPECTED_CRC")
                else:
                    hash_mismatch = self._numeric(snapshot, "IS_VIOLATED") == 1

                if index > 0:
                    prev_reset = self._numeric(window[index - 1], "PROCESSOR_RESET_COUNT")
                    no_reset = self._numeric(snapshot, "PROCESSOR_RESET_COUNT") == prev_reset
                else:
                    no_reset = (
                        self._numeric(snapshot, "PROCESSOR_RESET_COUNT")
                        == self.bm.get_stats(snapshot, "PROCESSOR_RESET_COUNT").mean
                    )

                file_crc = self._numeric(snapshot, "CH1_FAULT_CRC") > 0 or self._numeric(snapshot, "CH2_FAULT_CRC") > 0
                hit_count = sum([hash_mismatch, no_reset, file_crc])
                if hit_count == 0:
                    scores.append(0.0)
                    continue
                heap_z = self.bm.compute_z(self._numeric(snapshot, "HEAP_FREE"), self.bm.get_stats(snapshot, "HEAP_FREE"))
                cpu_z = self.bm.compute_z(self._numeric(snapshot, "UTILCPUAVG"), self.bm.get_stats(snapshot, "UTILCPUAVG"))
                scores.append(
                    (hit_count / 3.0) * 0.60
                    + self.bm.z_to_score(heap_z, "decrease", self.z_thr) * 0.20
                    + self.bm.z_to_score(cpu_z, "increase", self.z_thr) * 0.20
                )
            return max(scores) if scores else 0.0
        except Exception as error:
            logger.error("E-X3 scoring failed: %s", error)
            return 0.0

    def _ex4(self, window: list[dict[str, Any]]) -> float:
        try:
            scores = []
            cpu_high = float(self.abs_thr.get("UTILCPUAVG_HIGH", 80.0))
            for snapshot in window:
                dwell_z = self.bm.compute_z(
                    self._numeric(snapshot, "DWELL_ADDR_COUNT"),
                    self.bm.get_stats(snapshot, "DWELL_ADDR_COUNT"),
                )
                dwell_active = (
                    dwell_z >= self.z_thr["SOFT"]
                    or snapshot.get("DWELL_MASK") != self.bm.get_stats(snapshot, "DWELL_MASK").mean
                )
                dwell_score = self.bm.z_to_score(dwell_z, "increase", self.z_thr)
                packet_z = self.bm.compute_z(
                    self._numeric(snapshot, "COMBINEDPACKETSSENT"),
                    self.bm.get_stats(snapshot, "COMBINEDPACKETSSENT"),
                )
                packet_surge = packet_z >= self.z_thr["HARD"]
                packet_score = self.bm.z_to_score(packet_z, "increase", self.z_thr)
                high_cpu = self._numeric(snapshot, "UTILCPUAVG") > cpu_high

                if sum([dwell_active, packet_surge, high_cpu]) < 2:
                    scores.append(0.0)
                    continue
                scores.append(min(dwell_score * 0.40 + packet_score * 0.35 + (0.8 if high_cpu else 0.0) * 0.25, 1.0))
            return max(scores) if scores else 0.0
        except Exception as error:
            logger.error("E-X4 scoring failed: %s", error)
            return 0.0

    def _ex5(self, window: list[dict[str, Any]]) -> float:
        try:
            scores = []
            imu_max = float(self.abs_thr.get("IMU_WBN_VARIANCE_MAX", 0.001))
            for snapshot in window:
                imu_frozen = self._numeric(snapshot, "IMU_WBN_VARIANCE", 1.0) < imu_max
                bus_zs = [
                    abs(self.bm.compute_z(self._numeric(snapshot, column), self.bm.get_stats(snapshot, column)))
                    for column in ["BUS_3P3V", "BUS_5P0V", "BUS_12V"]
                ]
                bus_abnormal = any(z_value >= self.z_thr["SOFT"] for z_value in bus_zs)
                bus_score = self.bm.z_to_score(max(bus_zs), "increase", self.z_thr)
                fwd_z = self.bm.compute_z(
                    self._numeric(snapshot, "FORWARD_ERR_COUNT"),
                    self.bm.get_stats(snapshot, "FORWARD_ERR_COUNT"),
                )
                fwd_high = fwd_z >= self.z_thr["SOFT"]
                crc_hidden = (
                    self._numeric(snapshot, "CH1_FAULT_CRC", 1.0) == 0
                    and self._numeric(snapshot, "CH2_FAULT_CRC", 1.0) == 0
                )
                com_conflict = fwd_high and crc_hidden
                com_score = self.bm.z_to_score(fwd_z, "increase", self.z_thr) if com_conflict else 0.0
                signal_count = sum([imu_frozen, bus_abnormal, com_conflict])

                if signal_count < 2:
                    scores.append(0.0)
                    continue
                scores.append(
                    min(
                        (0.8 if imu_frozen else 0.0) * 0.35
                        + bus_score * 0.30
                        + com_score * 0.35
                        + (0.2 if signal_count == 3 else 0.0),
                        1.0,
                    )
                )
            return max(scores) if scores else 0.0
        except ValueError as error:
            logger.error("E-X5 scoring failed: %s", error)
            return 0.0
        except Exception as error:
            logger.error("unexpected E-X5 scoring failure: %s", error)
            return 0.0

    def _p1_x01(self, window: list[dict[str, Any]]) -> float:
        """CF file fault AND TBL security flag change in same window (simultaneous required)."""
        try:
            cf_crc_ratio = repeat_ratio_score(window, "CH1_FAULT_CRC", 0.1)
            cf_size_flag = self._flag_nonzero(window, "CH1_FAULT_FILE_SIZE_MISMATCH")
            write_err_score = self._z_max(window, "FILEWRITEERRCOUNTER", "increase")

            cf_active = (
                cf_crc_ratio > 0.0
                or cf_size_flag > 0.0
                or write_err_score > 0.0
            )
            tbl_active = self._flag_changed_from_baseline(window, "LASTVALCRC") > 0.0

            if not (cf_active and tbl_active):
                return 0.0

            return (
                cf_crc_ratio * 0.35
                + cf_size_flag * 0.20
                + write_err_score * 0.20
                + 1.0 * 0.25
            )
        except Exception as error:
            logger.error("P1-X01 scoring failed: %s", error)
            return 0.0

    def _p3_x01(self, window: list[dict[str, Any]]) -> float:
        """ADCS tamper: valid star tracker flag, attitude error spike, excessive torque."""
        try:
            qerr_threshold = 0.3
            torquer_high = float(self.abs_thr.get("TORQUER_PERCENT_HIGH", 75.0))
            tcmd_ratio = float(self.abs_thr.get("TCMD_BASELINE_RATIO", 1.1))
            scores: list[float] = []
            for snapshot in window:
                st_valid = self._numeric(snapshot, "ST_VALID", 1.0) == 1.0
                qerr_spike = any(
                    abs(self._numeric(snapshot, f"QERR_{index}")) > qerr_threshold for index in range(4)
                )
                if not (st_valid and qerr_spike):
                    scores.append(0.0)
                    continue

                tcmd_mag = max(abs(self._numeric(snapshot, f"TCMD_{axis}")) for axis in ["X", "Y", "Z"])
                base_tcmd = max(
                    abs(self.bm.get_stats(snapshot, f"TCMD_{axis}").mean) for axis in ["X", "Y", "Z"]
                )
                tcmd_high = tcmd_mag >= max(base_tcmd * tcmd_ratio, 0.02)

                torquer_on = max(
                    self._numeric(snapshot, f"TORQUER_PERCENT_ON_{index}") for index in range(3)
                )
                torquer_high = torquer_on >= torquer_high

                qerr_score = min(
                    max(abs(self._numeric(snapshot, f"QERR_{index}")) for index in range(4)) / 0.5,
                    1.0,
                )
                tcmd_score = 0.85 if tcmd_high else 0.2
                torquer_score = 0.9 if torquer_high else 0.15
                scores.append(min(qerr_score * 0.40 + tcmd_score * 0.35 + torquer_score * 0.25, 1.0))
            return max(scores) if scores else 0.0
        except Exception as error:
            logger.error("P3-X01 scoring failed: %s", error)
            return 0.0

    def _s2_x01(self, window: list[dict[str, Any]]) -> float:
        """Attitude-sensor mismatch: body rate stuck while QERR spikes (uses TLM WBN_*)."""
        try:
            if len(window) < 2:
                return 0.0
            wbn_stuck_max = float(self.abs_thr.get("WBN_STUCK_RANGE_MAX", 0.002))
            qerr_threshold = 0.3
            imu_var_max = float(self.abs_thr.get("IMU_WBN_VARIANCE_MAX", 0.001))
            scores: list[float] = []

            for snapshot in window:
                qerr_spike = any(
                    abs(self._numeric(snapshot, f"QERR_{index}")) > qerr_threshold
                    for index in range(4)
                )
                if not qerr_spike:
                    scores.append(0.0)
                    continue

                wbn_stdevs: list[float] = []
                for axis in ["X", "Y", "Z"]:
                    values = [self._numeric(item, f"WBN_{axis}") for item in window]
                    if len(values) >= 2:
                        try:
                            wbn_stdevs.append(statistics.stdev(values))
                        except statistics.StatisticsError:
                            wbn_stdevs.append(0.0)
                    else:
                        wbn_stdevs.append(0.0)
                wbn_stuck = all(std_value <= wbn_stuck_max for std_value in wbn_stdevs)

                imu_variance = self._numeric(snapshot, "IMU_WBN_VARIANCE", 1.0)
                imu_frozen = (
                    imu_variance < imu_var_max
                    if "IMU_WBN_VARIANCE" in snapshot
                    else wbn_stuck
                )

                svb_mag = sum(
                    abs(self._numeric(snapshot, f"SVB_{axis}")) for axis in ["X", "Y", "Z"]
                )
                svb_present = svb_mag > 0.1

                qerr_score = min(
                    max(abs(self._numeric(snapshot, f"QERR_{index}")) for index in range(4)) / 0.5,
                    1.0,
                )
                stuck_score = 0.9 if (wbn_stuck or imu_frozen) else 0.0
                svb_score = 0.1 if svb_present else 0.0
                scores.append(min(qerr_score * 0.55 + stuck_score * 0.35 + svb_score, 1.0))

            return max(scores) if scores else 0.0
        except Exception as error:
            logger.error("S2-X01 scoring failed: %s", error)
            return 0.0
