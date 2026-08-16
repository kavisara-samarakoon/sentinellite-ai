from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATH = Path("config/default.yaml")


class ConfigError(Exception):
    """Raised when SentinelLite configuration cannot be loaded or validated."""


def load_config(config_path: str | Path = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    path = Path(config_path)

    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as file:
            config = yaml.safe_load(file)
    except yaml.YAMLError as error:
        raise ConfigError(f"Invalid YAML config file: {error}") from error

    if not isinstance(config, dict):
        raise ConfigError("Config file must contain a YAML object at the top level.")

    validate_config(config)

    return config


def validate_config(config: dict[str, Any]) -> None:
    required_sections = ["app", "monitoring", "reporting", "risk"]

    for section in required_sections:
        if section not in config:
            raise ConfigError(f"Missing required config section: {section}")

    monitoring = config.get("monitoring")

    if not isinstance(monitoring, dict):
        raise ConfigError("The 'monitoring' section must be a YAML object.")

    required_modules = ["authentication", "process", "network", "file_integrity"]

    for module_name in required_modules:
        module_config = monitoring.get(module_name)

        if not isinstance(module_config, dict):
            raise ConfigError(f"Missing or invalid monitoring module config: {module_name}")

        if "enabled" not in module_config:
            raise ConfigError(f"Missing 'enabled' value for monitoring module: {module_name}")
