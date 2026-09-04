import tomllib
from collections.abc import Mapping
from importlib.resources import files
from pathlib import Path
from typing import Any, overload

import yaml

from sentinellite.config.models import (
    ModulesConfig,
    ReportingConfig,
    RulesConfig,
    SentinelLiteConfig,
)
from sentinellite.detection.rules import DEFAULT_RULES

DEFAULT_CONFIG_RESOURCE = "default.yaml"

_TOP_LEVEL_KEYS = frozenset({"config_version", "reporting", "modules", "rules"})
_REPORTING_KEYS = frozenset({"output_dir", "include_explanations"})
_MODULE_KEYS = frozenset(
    {"authentication", "process", "network", "file_integrity"}
)
_RULE_KEYS = frozenset({"disabled_ids"})
_REGISTERED_RULE_IDS = frozenset(rule.rule_id for rule in DEFAULT_RULES)


class ConfigError(Exception):
    """Raised when SentinelLite configuration cannot be loaded or validated."""


def default_config() -> SentinelLiteConfig:
    """Return the built-in defaults for explicit TOML-configurable behavior."""
    return SentinelLiteConfig()


def parse_config_data(
    data: Mapping[str, object], *, base_dir: Path | None = None
) -> SentinelLiteConfig:
    """Validate parsed TOML data and return an immutable configuration."""
    if not isinstance(data, Mapping):
        raise ConfigError("Config data must be a TOML table at the top level.")

    _reject_unknown_keys(data, _TOP_LEVEL_KEYS, "top level")
    defaults = default_config()

    config_version = data.get("config_version", defaults.config_version)
    if type(config_version) is not int:
        raise ConfigError("'config_version' must be the integer 1.")
    if config_version != 1:
        raise ConfigError(
            f"Unsupported config_version: {config_version}. Only version 1 is supported."
        )

    reporting_data = _read_section(data, "reporting")
    _reject_unknown_keys(reporting_data, _REPORTING_KEYS, "reporting")
    output_dir_value = reporting_data.get("output_dir", str(defaults.reporting.output_dir))
    if not isinstance(output_dir_value, str) or not output_dir_value.strip():
        raise ConfigError("'reporting.output_dir' must be a non-empty string.")
    output_dir = Path(output_dir_value)
    if base_dir is not None and not output_dir.is_absolute():
        output_dir = base_dir / output_dir

    include_explanations = reporting_data.get(
        "include_explanations", defaults.reporting.include_explanations
    )
    _require_bool(include_explanations, "reporting.include_explanations")

    modules_data = _read_section(data, "modules")
    _reject_unknown_keys(modules_data, _MODULE_KEYS, "modules")
    authentication = modules_data.get(
        "authentication", defaults.modules.authentication
    )
    process = modules_data.get("process", defaults.modules.process)
    network = modules_data.get("network", defaults.modules.network)
    file_integrity = modules_data.get(
        "file_integrity", defaults.modules.file_integrity
    )
    for field_name, value in (
        ("authentication", authentication),
        ("process", process),
        ("network", network),
        ("file_integrity", file_integrity),
    ):
        _require_bool(value, f"modules.{field_name}")

    rules_data = _read_section(data, "rules")
    _reject_unknown_keys(rules_data, _RULE_KEYS, "rules")
    disabled_ids_value = rules_data.get(
        "disabled_ids", list(defaults.rules.disabled_ids)
    )
    disabled_ids = _parse_disabled_rule_ids(disabled_ids_value)

    return SentinelLiteConfig(
        config_version=config_version,
        reporting=ReportingConfig(
            output_dir=output_dir,
            include_explanations=include_explanations,
        ),
        modules=ModulesConfig(
            authentication=authentication,
            process=process,
            network=network,
            file_integrity=file_integrity,
        ),
        rules=RulesConfig(disabled_ids=disabled_ids),
    )


@overload
def load_config() -> dict[str, Any]: ...


@overload
def load_config(config_path: str | Path) -> SentinelLiteConfig: ...


def load_config(
    config_path: str | Path | None = None,
) -> SentinelLiteConfig | dict[str, Any]:
    """Load typed TOML, preserving the existing no-argument YAML call for the CLI."""
    if config_path is None:
        return _load_packaged_default_config()

    path = Path(config_path)
    try:
        with path.open("rb") as file:
            data = tomllib.load(file)
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as error:
        raise ConfigError(f"Invalid TOML config file: {error}") from error
    except FileNotFoundError as error:
        raise ConfigError(f"Config file not found: {path}") from error
    except OSError as error:
        raise ConfigError(f"Could not read config file '{path}': {error}") from error

    return parse_config_data(data, base_dir=path.parent)


def _read_section(
    data: Mapping[str, object], section_name: str
) -> Mapping[str, object]:
    section = data.get(section_name, {})
    if not isinstance(section, Mapping):
        raise ConfigError(f"'{section_name}' must be a TOML table.")
    return section


def _reject_unknown_keys(
    data: Mapping[str, object], allowed_keys: frozenset[str], location: str
) -> None:
    unknown_keys = sorted(str(key) for key in data if key not in allowed_keys)
    if unknown_keys:
        joined_keys = ", ".join(unknown_keys)
        raise ConfigError(f"Unknown key(s) in {location}: {joined_keys}")


def _require_bool(value: object, field_name: str) -> None:
    if type(value) is not bool:
        raise ConfigError(f"'{field_name}' must be a boolean.")


def _parse_disabled_rule_ids(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ConfigError("'rules.disabled_ids' must be a list of unique strings.")
    if any(not isinstance(rule_id, str) for rule_id in value):
        raise ConfigError("'rules.disabled_ids' must contain only strings.")

    disabled_ids = tuple(value)
    if len(set(disabled_ids)) != len(disabled_ids):
        raise ConfigError("'rules.disabled_ids' must not contain duplicate rule IDs.")

    unknown_ids = sorted(set(disabled_ids) - _REGISTERED_RULE_IDS)
    if unknown_ids:
        joined_ids = ", ".join(unknown_ids)
        raise ConfigError(f"Unknown disabled rule ID(s): {joined_ids}")

    return disabled_ids


def _load_packaged_default_config() -> dict[str, Any]:
    """Load the legacy status configuration from the installed package."""
    try:
        config_resource = files("sentinellite.config").joinpath(
            DEFAULT_CONFIG_RESOURCE
        )
        with config_resource.open("r", encoding="utf-8") as file:
            config = yaml.safe_load(file)
    except yaml.YAMLError as error:
        raise ConfigError(f"Invalid packaged default config: {error}") from error
    except OSError as error:
        raise ConfigError(
            f"Could not read packaged default config: {error}"
        ) from error

    if not isinstance(config, dict):
        raise ConfigError("Config file must contain a YAML object at the top level.")

    validate_config(config)
    return config


def validate_config(config: dict[str, Any]) -> None:
    """Validate the legacy YAML configuration used by the current CLI."""
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
            raise ConfigError(
                f"Missing or invalid monitoring module config: {module_name}"
            )
        if "enabled" not in module_config:
            raise ConfigError(
                f"Missing 'enabled' value for monitoring module: {module_name}"
            )
