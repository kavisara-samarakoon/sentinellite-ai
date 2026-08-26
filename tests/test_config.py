import tomllib
from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from sentinellite.config import (
    DEFAULT_CONFIG_TEMPLATE,
    ConfigError,
    ModulesConfig,
    ReportingConfig,
    RulesConfig,
    SentinelLiteConfig,
    default_config,
    load_config,
    parse_config_data,
    write_default_config,
)


def write_toml(tmp_path: Path, content: str) -> Path:
    config_path = tmp_path / "sentinellite.toml"
    config_path.write_text(content, encoding="utf-8")
    return config_path


def test_default_config_matches_v04_behavior() -> None:
    assert default_config() == SentinelLiteConfig(
        config_version=1,
        reporting=ReportingConfig(
            output_dir=Path("reports"),
            include_explanations=False,
        ),
        modules=ModulesConfig(
            authentication=True,
            process=True,
            network=True,
            file_integrity=True,
        ),
        rules=RulesConfig(disabled_ids=()),
    )


def test_config_models_are_immutable() -> None:
    config = default_config()

    with pytest.raises(FrozenInstanceError):
        config.config_version = 2  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        config.reporting.output_dir = Path("elsewhere")  # type: ignore[misc]


def test_load_full_toml_config(tmp_path: Path) -> None:
    config_path = write_toml(
        tmp_path,
        """config_version = 1

[reporting]
output_dir = "custom-reports"
include_explanations = true

[modules]
authentication = false
process = true
network = false
file_integrity = true

[rules]
disabled_ids = ["AUTH-001", "NET-003"]
""",
    )

    config = load_config(config_path)

    assert config == SentinelLiteConfig(
        config_version=1,
        reporting=ReportingConfig(
            output_dir=tmp_path / "custom-reports",
            include_explanations=True,
        ),
        modules=ModulesConfig(
            authentication=False,
            process=True,
            network=False,
            file_integrity=True,
        ),
        rules=RulesConfig(disabled_ids=("AUTH-001", "NET-003")),
    )


def test_partial_config_merges_with_defaults() -> None:
    config = parse_config_data({"modules": {"network": False}})

    assert config == SentinelLiteConfig(
        modules=ModulesConfig(network=False),
    )


def test_empty_config_uses_all_defaults() -> None:
    assert parse_config_data({}) == default_config()


def test_malformed_toml_raises_config_error(tmp_path: Path) -> None:
    config_path = write_toml(tmp_path, "[reporting\noutput_dir = 'reports'")

    with pytest.raises(ConfigError, match="Invalid TOML config file"):
        load_config(config_path)


@pytest.mark.parametrize("value", [2, 0, -1])
def test_unsupported_config_version_fails(value: int) -> None:
    with pytest.raises(ConfigError, match="Unsupported config_version"):
        parse_config_data({"config_version": value})


@pytest.mark.parametrize("value", [True, "1", 1.0, None])
def test_config_version_must_be_an_integer(value: object) -> None:
    with pytest.raises(ConfigError, match="must be the integer 1"):
        parse_config_data({"config_version": value})


@pytest.mark.parametrize("value", ["", "   ", 123, False, None])
def test_output_dir_must_be_a_non_empty_string(value: object) -> None:
    with pytest.raises(ConfigError, match="reporting.output_dir"):
        parse_config_data({"reporting": {"output_dir": value}})


@pytest.mark.parametrize("value", ["true", 1, 0, None, []])
def test_reporting_include_explanations_must_be_bool(value: object) -> None:
    with pytest.raises(ConfigError, match="reporting.include_explanations"):
        parse_config_data({"reporting": {"include_explanations": value}})


@pytest.mark.parametrize(
    ("module_name", "value"),
    [
        ("authentication", "true"),
        ("process", 1),
        ("network", None),
        ("file_integrity", []),
    ],
)
def test_module_values_must_be_bool(module_name: str, value: object) -> None:
    with pytest.raises(ConfigError, match=f"modules.{module_name}"):
        parse_config_data({"modules": {module_name: value}})


@pytest.mark.parametrize("section_name", ["reporting", "modules", "rules"])
@pytest.mark.parametrize("value", [False, "table", 1, []])
def test_known_sections_must_be_tables(section_name: str, value: object) -> None:
    with pytest.raises(ConfigError, match=f"'{section_name}'.*TOML table"):
        parse_config_data({section_name: value})


def test_unknown_top_level_section_fails() -> None:
    with pytest.raises(ConfigError, match="Unknown key.*telemetry"):
        parse_config_data({"telemetry": {}})


@pytest.mark.parametrize(
    ("section_name", "unknown_key"),
    [
        ("reporting", "format"),
        ("modules", "kernel"),
        ("rules", "enabled_ids"),
    ],
)
def test_unknown_keys_inside_sections_fail(
    section_name: str, unknown_key: str
) -> None:
    with pytest.raises(ConfigError, match=f"Unknown key.*{unknown_key}"):
        parse_config_data({section_name: {unknown_key: True}})


def test_unknown_disabled_rule_id_fails() -> None:
    with pytest.raises(ConfigError, match="Unknown disabled rule ID.*AUTH-999"):
        parse_config_data({"rules": {"disabled_ids": ["AUTH-999"]}})


def test_case_mismatched_disabled_rule_id_fails() -> None:
    with pytest.raises(ConfigError, match="Unknown disabled rule ID.*auth-001"):
        parse_config_data({"rules": {"disabled_ids": ["auth-001"]}})


def test_duplicate_disabled_rule_ids_fail() -> None:
    with pytest.raises(ConfigError, match="duplicate rule IDs"):
        parse_config_data(
            {"rules": {"disabled_ids": ["AUTH-001", "AUTH-001"]}}
        )


@pytest.mark.parametrize("value", ["AUTH-001", (), {}, None, True])
def test_disabled_rule_ids_must_be_a_list(value: object) -> None:
    with pytest.raises(ConfigError, match="list of unique strings"):
        parse_config_data({"rules": {"disabled_ids": value}})


@pytest.mark.parametrize("value", [1, False, None, ["AUTH-001"]])
def test_disabled_rule_ids_must_contain_strings(value: object) -> None:
    with pytest.raises(ConfigError, match="contain only strings"):
        parse_config_data({"rules": {"disabled_ids": [value]}})


def test_relative_output_dir_resolves_against_config_directory(tmp_path: Path) -> None:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    config_path = write_toml(config_dir, '[reporting]\noutput_dir = "artifacts"\n')

    config = load_config(config_path)

    assert config.reporting.output_dir == config_dir / "artifacts"


def test_absolute_output_dir_remains_absolute(tmp_path: Path) -> None:
    absolute_output_dir = tmp_path / "absolute-reports"

    config = parse_config_data(
        {"reporting": {"output_dir": str(absolute_output_dir)}},
        base_dir=tmp_path / "config",
    )

    assert config.reporting.output_dir == absolute_output_dir


def test_parse_config_data_does_not_mutate_input_or_defaults() -> None:
    data: dict[str, object] = {
        "reporting": {"output_dir": "custom"},
        "modules": {"process": False},
        "rules": {"disabled_ids": ["PROC-001"]},
    }
    original_data = deepcopy(data)
    defaults_before = default_config()

    parsed = parse_config_data(data)

    assert data == original_data
    assert default_config() == defaults_before
    assert parsed.rules.disabled_ids == ("PROC-001",)
    assert parsed.reporting is not defaults_before.reporting
    assert parsed.modules is not defaults_before.modules
    assert parsed.rules is not defaults_before.rules


def test_write_default_config_creates_valid_toml_and_loads_as_defaults(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)

    output_path = write_default_config("sentinellite.toml")
    parsed_toml = tomllib.loads(output_path.read_text(encoding="utf-8"))

    assert output_path == Path("sentinellite.toml")
    assert parsed_toml == tomllib.loads(DEFAULT_CONFIG_TEMPLATE)
    assert load_config(output_path) == default_config()


def test_write_default_config_refuses_overwrite_and_preserves_existing_file(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "sentinellite.toml"
    original_content = "existing user configuration\n"
    config_path.write_text(original_content, encoding="utf-8")

    with pytest.raises(ConfigError, match="already exists"):
        write_default_config(config_path)

    assert config_path.read_text(encoding="utf-8") == original_content


def test_write_default_config_does_not_create_parent_directories(
    tmp_path: Path,
) -> None:
    missing_parent = tmp_path / "missing" / "sentinellite.toml"

    with pytest.raises(ConfigError, match="parent directory does not exist"):
        write_default_config(missing_parent)

    assert not missing_parent.parent.exists()
    assert not missing_parent.exists()
