import tomllib
from importlib import metadata, resources
from pathlib import Path

import pytest

from sentinellite import __version__
from sentinellite.config import (
    ConfigError,
    SentinelLiteConfig,
    load_config,
    parse_config_data,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_pyproject() -> dict[str, object]:
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as file:
        return tomllib.load(file)


def test_package_version_has_single_expected_source() -> None:
    pyproject = load_pyproject()
    project = pyproject["project"]
    setuptools_config = pyproject["tool"]["setuptools"]

    assert __version__ == "1.0.0-beta"
    assert metadata.version("sentinellite-ai") == "1.0.0b0"
    assert project["dynamic"] == ["version"]
    assert "version" not in project
    assert setuptools_config["dynamic"]["version"] == {
        "attr": "sentinellite.__version__"
    }


def test_build_system_uses_setuptools_and_wheel() -> None:
    build_system = load_pyproject()["build-system"]

    assert build_system["build-backend"] == "setuptools.build_meta"
    assert "wheel" in build_system["requires"]
    assert any(
        requirement.startswith("setuptools")
        for requirement in build_system["requires"]
    )


def test_project_metadata_declares_runtime_dependencies() -> None:
    project = load_pyproject()["project"]
    dependency_names = {
        dependency.lower() for dependency in project["dependencies"]
    }

    assert project["name"] == "sentinellite-ai"
    assert project["authors"] == [{"name": "Kavisara Samarakoon"}]
    assert dependency_names == {"psutil", "pyyaml", "rich", "typer"}


def test_dev_extra_declares_required_quality_tools() -> None:
    project = load_pyproject()["project"]
    dev_dependencies = {
        dependency.lower()
        for dependency in project["optional-dependencies"]["dev"]
    }

    assert {"build", "pytest", "ruff"} <= dev_dependencies


def test_mit_license_is_declared_and_included_in_installed_wheel() -> None:
    project = load_pyproject()["project"]
    license_path = PROJECT_ROOT / "LICENSE"
    license_text = license_path.read_text(encoding="utf-8")

    assert license_text
    assert license_text.startswith("MIT License\n")
    assert "Copyright (c) 2026 Kavisara Samarakoon" in license_text
    assert "Permission is hereby granted, free of charge" in license_text
    assert 'THE SOFTWARE IS PROVIDED "AS IS"' in license_text
    assert project["license"] == "MIT"
    assert project["license-files"] == ["LICENSE"]

    distribution = metadata.distribution("sentinellite-ai")
    assert distribution.metadata["License-Expression"] == "MIT"
    assert distribution.metadata.get_all("License-File") == ["LICENSE"]
    distribution_files = distribution.files or []
    installed_license_paths = [
        path
        for path in distribution_files
        if path.as_posix().endswith(".dist-info/licenses/LICENSE")
    ]
    assert len(installed_license_paths) == 1
    installed_license = distribution.locate_file(installed_license_paths[0])
    assert installed_license.read_text(encoding="utf-8") == license_text


def test_console_script_uses_shared_cli_callable() -> None:
    project = load_pyproject()["project"]

    assert project["scripts"] == {
        "sentinellite": "sentinellite.main:cli"
    }


def test_requirements_file_delegates_to_dev_extra() -> None:
    requirements = (PROJECT_ROOT / "requirements.txt").read_text(
        encoding="utf-8"
    )

    assert requirements == "-e .[dev]\n"


def test_default_config_is_an_in_package_resource() -> None:
    config_resource = resources.files("sentinellite.config").joinpath(
        "default.yaml"
    )
    pyproject = load_pyproject()
    package_data = pyproject["tool"]["setuptools"]["package-data"]

    assert config_resource.is_file()
    assert "default.yaml" in package_data["sentinellite.config"]


def test_default_config_loads_outside_repository(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)

    config = load_config()

    assert isinstance(config, dict)
    assert config["app"]["name"] == "SentinelLite AI"
    assert "version" not in config["app"]
    assert config["reporting"]["json_reports"]["output_dir"] == "reports"


def test_default_loader_ignores_process_relative_config_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    relative_config_dir = tmp_path / "config"
    relative_config_dir.mkdir()
    (relative_config_dir / "default.yaml").write_text(
        "invalid: process-relative config\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    config = load_config()

    assert isinstance(config, dict)
    assert config["app"]["name"] == "SentinelLite AI"


def test_explicit_config_path_still_overrides_defaults(tmp_path: Path) -> None:
    config_path = tmp_path / "sentinellite.toml"
    config_path.write_text(
        """config_version = 1

[reporting]
output_dir = "explicit-reports"

[modules]
network = false
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert isinstance(config, SentinelLiteConfig)
    assert config.reporting.output_dir == tmp_path / "explicit-reports"
    assert config.modules.network is False


def test_unknown_config_key_validation_is_unchanged() -> None:
    with pytest.raises(ConfigError, match="Unknown key.*telemetry"):
        parse_config_data({"telemetry": {}})
