"""Baseline statistics used by the MA integrated detector."""

from __future__ import annotations

import logging
import statistics
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ColumnStats:
    """Mean and standard deviation for one telemetry column."""

    mean: float = 0.0
    std: float = 1.0


class BaselineManager:
    """Builds and serves normal-operation statistics grouped by mission state."""

    def __init__(self) -> None:
        self._stats: dict[tuple[Any, ...], dict[str, ColumnStats]] = {}

    def build_from_history(
        self,
        history: list[dict[str, Any]],
        group_keys: list[str] | None = None,
    ) -> None:
        """Build baseline statistics from verified-normal telemetry history."""
        try:
            keys = group_keys or ["MISSION_MODE", "ADCS_MODE"]
            grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)

            for record in history:
                key = tuple(record.get(group_key, "UNKNOWN") for group_key in keys)
                grouped[key].append(record)

            next_stats: dict[tuple[Any, ...], dict[str, ColumnStats]] = {}
            for key, records in grouped.items():
                next_stats[key] = {}
                all_columns: set[str] = set()
                for record in records:
                    all_columns.update(record.keys())

                for column in all_columns:
                    values = [
                        float(record[column])
                        for record in records
                        if column in record and isinstance(record[column], (int, float))
                    ]
                    if not values:
                        continue

                    mean = statistics.mean(values)
                    std = statistics.stdev(values) if len(values) > 1 else 1.0
                    next_stats[key][column] = ColumnStats(mean=mean, std=std if std > 0 else 1.0)

            self._stats = next_stats
        except (TypeError, ValueError, statistics.StatisticsError) as error:
            logger.error("baseline build failed: %s", error)
        except Exception as error:
            logger.error("unexpected baseline build failure: %s", error)

    def get_stats(
        self,
        snapshot: dict[str, Any],
        column: str,
        group_keys: list[str] | None = None,
    ) -> ColumnStats:
        """Return baseline statistics for a snapshot group and column."""
        try:
            keys = group_keys or ["MISSION_MODE", "ADCS_MODE"]
            key = tuple(snapshot.get(group_key, "UNKNOWN") for group_key in keys)
            return self._stats.get(key, {}).get(column, ColumnStats())
        except TypeError as error:
            logger.error("baseline stats lookup failed: %s", error)
            return ColumnStats()
        except Exception as error:
            logger.error("unexpected baseline stats lookup failure: %s", error)
            return ColumnStats()

    def compute_z(self, value: float, stats: ColumnStats) -> float:
        """Compute z-score for a value and stored baseline stats."""
        try:
            if stats.std == 0:
                return 0.0
            return (float(value) - stats.mean) / stats.std
        except (TypeError, ValueError) as error:
            logger.error("z-score calculation failed: %s", error)
            return 0.0
        except Exception as error:
            logger.error("unexpected z-score calculation failure: %s", error)
            return 0.0

    def z_to_score(self, z: float, direction: str, z_thr: dict[str, float]) -> float:
        """Convert a z-score to a normalized rule score from 0.0 to 1.0."""
        try:
            signed = z if direction == "increase" else -z
            soft = float(z_thr["SOFT"])
            hard = float(z_thr["HARD"])
            severe = float(z_thr["SEVERE"])

            if signed < soft:
                return 0.0
            if signed < hard:
                return min(0.3 + (signed - soft) * 0.3, 0.6)
            if signed < severe:
                return min(0.6 + (signed - hard) * 0.3, 0.9)
            return 1.0
        except (KeyError, TypeError, ValueError) as error:
            logger.error("z-score conversion failed: %s", error)
            return 0.0
        except Exception as error:
            logger.error("unexpected z-score conversion failure: %s", error)
            return 0.0
