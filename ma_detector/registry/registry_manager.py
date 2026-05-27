"""JSON registry loader and updater for the MA integrated detector."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class RegistryManager:
    """Manages action, rule, and threshold JSON configuration files."""

    def __init__(self, config_dir: str | Path | None = None) -> None:
        try:
            default_dir = Path(__file__).resolve().parents[1] / "config"
            self._dir = Path(config_dir) if config_dir is not None else default_dir
            self._action_path = self._dir / "action_registry.json"
            self._rule_path = self._dir / "rule_registry.json"
            self._threshold_path = self._dir / "threshold_config.json"
        except TypeError as error:
            logger.error("registry manager initialization failed: %s", error)
            default_dir = Path(__file__).resolve().parents[1] / "config"
            self._dir = default_dir
            self._action_path = self._dir / "action_registry.json"
            self._rule_path = self._dir / "rule_registry.json"
            self._threshold_path = self._dir / "threshold_config.json"
        except Exception as error:
            logger.error("unexpected registry manager initialization failure: %s", error)
            default_dir = Path(__file__).resolve().parents[1] / "config"
            self._dir = default_dir
            self._action_path = self._dir / "action_registry.json"
            self._rule_path = self._dir / "rule_registry.json"
            self._threshold_path = self._dir / "threshold_config.json"

    def load_all(self) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        """Load action registry, rule registry, and threshold configuration."""
        try:
            return (
                self._load(self._action_path),
                self._load(self._rule_path),
                self._load(self._threshold_path),
            )
        except (OSError, json.JSONDecodeError) as error:
            logger.error("registry load failed: %s", error)
            return {}, {}, {}
        except Exception as error:
            logger.error("unexpected registry load failure: %s", error)
            return {}, {}, {}

    def add_action(self, action_id: str, definition: dict[str, Any]) -> bool:
        """Add or replace an action definition."""
        try:
            registry = self._load(self._action_path)
            registry[action_id] = definition
            self._save(self._action_path, registry)
            return True
        except (OSError, json.JSONDecodeError, TypeError) as error:
            logger.error("add action failed: %s", error)
            return False
        except Exception as error:
            logger.error("unexpected add action failure: %s", error)
            return False

    def update_action(self, action_id: str, updates: dict[str, Any]) -> bool:
        """Update an existing action definition."""
        try:
            registry = self._load(self._action_path)
            if action_id not in registry:
                raise KeyError(f"Action {action_id} not found")
            registry[action_id].update(updates)
            self._save(self._action_path, registry)
            return True
        except (KeyError, OSError, json.JSONDecodeError, TypeError) as error:
            logger.error("update action failed: %s", error)
            return False
        except Exception as error:
            logger.error("unexpected update action failure: %s", error)
            return False

    def delete_action(self, action_id: str) -> bool:
        """Delete an action definition if it exists."""
        try:
            registry = self._load(self._action_path)
            registry.pop(action_id, None)
            self._save(self._action_path, registry)
            return True
        except (OSError, json.JSONDecodeError) as error:
            logger.error("delete action failed: %s", error)
            return False
        except Exception as error:
            logger.error("unexpected delete action failure: %s", error)
            return False

    def add_rule(self, rule_id: str, definition: dict[str, Any]) -> bool:
        """Add or replace a rule definition."""
        try:
            registry = self._load(self._rule_path)
            registry[rule_id] = definition
            self._save(self._rule_path, registry)
            return True
        except (OSError, json.JSONDecodeError, TypeError) as error:
            logger.error("add rule failed: %s", error)
            return False
        except Exception as error:
            logger.error("unexpected add rule failure: %s", error)
            return False

    def update_rule(self, rule_id: str, updates: dict[str, Any]) -> bool:
        """Update an existing rule definition."""
        try:
            registry = self._load(self._rule_path)
            if rule_id not in registry:
                raise KeyError(f"Rule {rule_id} not found")
            registry[rule_id].update(updates)
            self._save(self._rule_path, registry)
            return True
        except (KeyError, OSError, json.JSONDecodeError, TypeError) as error:
            logger.error("update rule failed: %s", error)
            return False
        except Exception as error:
            logger.error("unexpected update rule failure: %s", error)
            return False

    def delete_rule(self, rule_id: str) -> bool:
        """Delete a rule definition if it exists."""
        try:
            registry = self._load(self._rule_path)
            registry.pop(rule_id, None)
            self._save(self._rule_path, registry)
            return True
        except (OSError, json.JSONDecodeError) as error:
            logger.error("delete rule failed: %s", error)
            return False
        except Exception as error:
            logger.error("unexpected delete rule failure: %s", error)
            return False

    def replace_rules(self, rules: dict[str, Any]) -> bool:
        """Replace the whole rule registry."""
        try:
            self._save(self._rule_path, rules)
            return True
        except (OSError, TypeError) as error:
            logger.error("replace rules failed: %s", error)
            return False
        except Exception as error:
            logger.error("unexpected replace rules failure: %s", error)
            return False

    def replace_actions(self, actions: dict[str, Any]) -> bool:
        """Replace the whole action registry."""
        try:
            self._save(self._action_path, actions)
            return True
        except (OSError, TypeError) as error:
            logger.error("replace actions failed: %s", error)
            return False
        except Exception as error:
            logger.error("unexpected replace actions failure: %s", error)
            return False

    def toggle_rule(self, rule_id: str, enabled: bool) -> bool:
        """Enable or disable a rule."""
        try:
            return self.update_rule(rule_id, {"enabled": enabled})
        except Exception as error:
            logger.error("toggle rule failed: %s", error)
            return False

    def update_contribution(self, rule_id: str, action_id: str, score: float) -> bool:
        """Update one rule-to-action contribution score."""
        try:
            registry = self._load(self._rule_path)
            if rule_id not in registry:
                raise KeyError(f"Rule {rule_id} not found")
            registry[rule_id].setdefault("contributes_to", {})[action_id] = score
            self._save(self._rule_path, registry)
            return True
        except (KeyError, OSError, json.JSONDecodeError, TypeError) as error:
            logger.error("update contribution failed: %s", error)
            return False
        except Exception as error:
            logger.error("unexpected update contribution failure: %s", error)
            return False

    def update_threshold(self, category: str, key: str, value: float) -> bool:
        """Update one threshold config value."""
        try:
            config = self._load(self._threshold_path)
            if category not in config:
                raise KeyError(f"Category {category} not found")
            config[category][key] = value
            self._save(self._threshold_path, config)
            return True
        except (KeyError, OSError, json.JSONDecodeError, TypeError) as error:
            logger.error("update threshold failed: %s", error)
            return False
        except Exception as error:
            logger.error("unexpected update threshold failure: %s", error)
            return False

    def replace_thresholds(self, thresholds: dict[str, Any]) -> bool:
        """Replace the whole threshold configuration."""
        try:
            self._save(self._threshold_path, thresholds)
            return True
        except (OSError, TypeError) as error:
            logger.error("replace thresholds failed: %s", error)
            return False
        except Exception as error:
            logger.error("unexpected replace thresholds failure: %s", error)
            return False

    @staticmethod
    def _load(path: Path) -> dict[str, Any]:
        with path.open("r", encoding="utf-8-sig") as file:
            return json.load(file)

    @staticmethod
    def _save(path: Path, data: dict[str, Any]) -> None:
        with path.open("w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False, indent=2)
            file.write("\n")
