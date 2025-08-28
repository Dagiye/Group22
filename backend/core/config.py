# backend/core/config.py

import os
import yaml
from typing import Any, Dict


class ConfigError(Exception):
    pass


class Config:
    """
    Handles loading and accessing configuration for the scanner.
    Supports YAML files with layered defaults and overrides.
    """

    def __init__(self, config_path: str = None):
        """
        Initialize the configuration.
        :param config_path: Path to custom YAML configuration file
        """
        self.config_data: Dict[str, Any] = {}
        self.load_defaults()
        if config_path:
            self.load_file(config_path)

    def load_defaults(self):
        """Load default configuration from backend/config/defaults.yaml"""
        default_path = os.path.join(os.path.dirname(__file__), "../config/defaults.yaml")
        if not os.path.exists(default_path):
            raise ConfigError(f"Default configuration not found at {default_path}")
        self.load_file(default_path)

    def load_file(self, path: str):
        """Load a YAML configuration file and merge it"""
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f) or {}
            self.merge(data)
        except Exception as e:
            raise ConfigError(f"Failed to load config file {path}: {str(e)}")

    def merge(self, override_data: Dict[str, Any]):
        """Merge override data into current config"""
        self.config_data = self._deep_merge(self.config_data, override_data)

    @staticmethod
    def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge dictionaries"""
        result = base.copy()
        for k, v in override.items():
            if isinstance(v, dict) and k in result and isinstance(result[k], dict):
                result[k] = Config._deep_merge(result[k], v)
            else:
                result[k] = v
        return result

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.
        Example: get("scanner.timeout")
        """
        keys = key.split(".")
        value = self.config_data
        for k in keys:
            if not isinstance(value, dict) or k not in value:
                return default
            value = value[k]
        return value

    def set(self, key: str, value: Any):
        """
        Set a configuration value using dot notation.
        Example: set("scanner.timeout", 30)
        """
        keys = key.split(".")
        d = self.config_data
        for k in keys[:-1]:
            d = d.setdefault(k, {})
        d[keys[-1]] = value

    def all(self) -> Dict[str, Any]:
        """Return the full configuration as a dict"""
        return self.config_data


# Example usage:
# cfg = Config("backend/config/aggressive.yaml")
# timeout = cfg.get("scanner.timeout", 20)
# cfg.set("scanner.retries", 5)
# print(cfg.all())
