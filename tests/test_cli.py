import json
import tomllib
from pathlib import Path

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from sentinellite.config import default_config, load_config
from sentinellite.detection.rules import DEFAULT_RULES, DetectionRule
from sentinellite.main import app
from sentinellite.pipeline.auth_scan import AuthScanSummary
from sentinellite.pipeline.file_integrity_baseline_scan import (
    FileIntegrityBaselineScanSummary,
)
from sentinellite.pipeline.file_integrity_scan import FileIntegrityScanSummary
from sentinellite.pipeline.network_scan import NetworkScanSummary
from sentinellite.pipeline.process_scan import ProcessScanSummary
from sentinellite.scoring.risk import ScoredAlert

runner = CliRunner()
REPORT_KEYS = {
    "report_id",
    "report_type",
    "generated_at",
    "alert_count",
    "alerts",
}


def write_reporting_config(
    tmp_path: Path,
    *,
    output_dir: str = "configured-reports",
    include_explanations: bool = False,
    disabled_ids: tuple[str, ...] = (),
) -> Path:
    disabled_ids_toml = ", ".join(f'"{rule_id}"' for rule_id in disabled_ids)
    config_path = tmp_path / "sentinellite.toml"
    config_path.write_text(
        "\n".join(
            [
                "config_version = 1",
                "",
                "[reporting]",
                f'output_dir = "{output_dir}"',
                f"include_explanations = {str(include_explanations).lower()}",
                "",
                "[rules]",
                f"disabled_ids = [{disabled_ids_toml}]",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return config_path


def test_config_init_creates_valid_default_toml(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["config-init"])

    config_path = tmp_path / "sentinellite.toml"
    assert result.exit_code == 0
    assert config_path.exists()
    assert tomllib.loads(config_path.read_text(encoding="utf-8")) == {
        "config_version": 1,
        "reporting": {
            "output_dir": "reports",
            "include_explanations": False,
        },
        "modules": {
            "authentication": True,
            "process": True,
            "network": True,
            "file_integrity": True,
        },
        "rules": {"disabled_ids": []},
    }
    assert load_config(Path("sentinellite.toml")) == default_config()
    assert "Created default config" in result.stdout
    assert "sentinellite.toml" in result.stdout
    assert "--config" in result.stdout
    assert "scan-auth" in result.stdout
    normalized_output = result.stdout.lower()
    assert "--ai" not in normalized_output
    assert "--llm" not in normalized_output


def test_config_init_refuses_overwrite_without_modifying_existing_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "sentinellite.toml"
    original_content = "existing user configuration\n"
    config_path.write_text(original_content, encoding="utf-8")

    result = runner.invoke(app, ["config-init"])

    assert result.exit_code != 0
    assert "Configuration error" in result.stdout
    assert "already exists" in result.stdout
    assert "Traceback" not in result.stdout
    assert config_path.read_text(encoding="utf-8") == original_content


def test_config_init_path_option_creates_selected_file(tmp_path: Path) -> None:
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    config_path = config_dir / "custom.toml"

    result = runner.invoke(app, ["config-init", "--path", str(config_path)])

    assert result.exit_code == 0
    assert config_path.exists()
    assert tomllib.loads(config_path.read_text(encoding="utf-8"))["config_version"] == 1
    assert str(config_path) in result.stdout.replace("\n", "")


def test_config_init_missing_parent_fails_cleanly(tmp_path: Path) -> None:
    config_path = tmp_path / "missing" / "sentinellite.toml"

    result = runner.invoke(app, ["config-init", "--path", str(config_path)])

    assert result.exit_code != 0
    assert "Configuration error" in result.stdout
    assert "parent directory does not exist" in result.stdout
    assert "Traceback" not in result.stdout
    assert not config_path.parent.exists()
    assert not config_path.exists()


def test_config_init_handles_writer_oserror_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_oserror(_path: Path) -> Path:
        raise OSError("simulated write failure")

    monkeypatch.setattr("sentinellite.main.write_default_config", raise_oserror)

    result = runner.invoke(app, ["config-init"])

    assert result.exit_code != 0
    assert "Configuration error" in result.stdout
    assert "simulated write failure" in result.stdout
    assert "Traceback" not in result.stdout


def test_scan_auth_command_displays_deterministic_explanation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "auth.log"
    report_path = tmp_path / "auth-alerts.json"
    scored_alert = ScoredAlert(
        alert_id="alert-1",
        rule_id="AUTH-001",
        rule_name="Failed SSH Login",
        category="authentication",
        severity="medium",
        base_score=50,
        risk_score=50,
        risk_level="medium",
        event_id="event-1",
        event_type="ssh_failed_login",
        source="auth_log",
        message="Failed SSH login for root from 192.0.2.10",
        description="A failed SSH login attempt was detected.",
        recommendation="Review the authentication context.",
        evidence={"username": "root", "source_address": "192.0.2.10"},
    )

    def fake_run_auth_scan(
        log_path: Path,
        output_dir: Path,
        *,
        include_explanations: bool,
        rules: list[DetectionRule] | None,
    ) -> tuple[AuthScanSummary, list[ScoredAlert]]:
        assert log_path == tmp_path / "auth.log"
        assert output_dir == tmp_path
        assert include_explanations is False
        assert rules is None
        return (
            AuthScanSummary(
                log_path=str(log_path),
                auth_events_count=1,
                security_events_count=1,
                detection_matches_count=1,
                scored_alerts_count=1,
                report_path=str(report_path),
            ),
            [scored_alert],
        )

    monkeypatch.setattr("sentinellite.main.run_auth_scan", fake_run_auth_scan)

    result = runner.invoke(
        app,
        ["scan-auth", str(log_path), "--output-dir", str(tmp_path)],
    )

    assert result.exit_code == 0
    assert "Generated Alerts" in result.stdout
    assert "Deterministic Alert Explanations" in result.stdout
    assert "Alert Explanation" in result.stdout
    assert "Failed SSH Login Attempt" in result.stdout
    assert "AUTH-001" in result.stdout
    assert "ssh_failed_login" in result.stdout
    normalized_output = result.stdout.lower()
    assert "ai detected" not in normalized_output
    assert "malware" not in normalized_output
    assert "is compromised" not in normalized_output
    assert "confirmed compromise" not in normalized_output


def test_scan_auth_command_keeps_no_alert_output_without_explanations(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "auth.log"

    monkeypatch.setattr(
        "sentinellite.main.run_auth_scan",
        lambda log_path, output_dir, **_kwargs: (
            AuthScanSummary(
                log_path=str(log_path),
                auth_events_count=0,
                security_events_count=0,
                detection_matches_count=0,
                scored_alerts_count=0,
                report_path=str(output_dir / "auth-alerts.json"),
            ),
            [],
        ),
    )

    result = runner.invoke(
        app,
        ["scan-auth", str(log_path), "--output-dir", str(tmp_path)],
    )

    assert result.exit_code == 0
    assert "No alerts generated." in result.stdout
    assert "Deterministic Alert Explanations" not in result.stdout
    assert "Alert Explanation" not in result.stdout


@pytest.mark.parametrize(
    "command_name",
    [
        "scan-auth",
        "scan-process",
        "scan-network",
        "scan-files",
        "scan-files-baseline",
    ],
)
def test_scan_command_registers_json_explanation_flag(command_name: str) -> None:
    root_command = get_command(app)
    scan_command = root_command.commands[command_name]
    registered_options = {
        option
        for parameter in scan_command.params
        for option in (
            *getattr(parameter, "opts", ()),
            *getattr(parameter, "secondary_opts", ()),
        )
    }
    assert "--include-explanations" in registered_options
    assert "--no-include-explanations" in registered_options

    explanation_option = next(
        parameter
        for parameter in scan_command.params
        if "--include-explanations" in getattr(parameter, "opts", ())
    )

    assert explanation_option.help == (
        "Include deterministic alert explanations in the JSON report."
    )
    assert "--ai" not in registered_options
    assert "--llm" not in registered_options


def test_root_command_registers_config_without_ai_or_llm_options() -> None:
    root_command = get_command(app)
    registered_options = {
        option
        for parameter in root_command.params
        for option in (
            *getattr(parameter, "opts", ()),
            *getattr(parameter, "secondary_opts", ()),
        )
    }

    assert "--config" in registered_options
    assert "--ai" not in registered_options
    assert "--llm" not in registered_options


def test_scan_auth_without_config_uses_builtin_reporting_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run_auth_scan(
        log_path: Path,
        output_dir: Path,
        *,
        include_explanations: bool,
        rules: list[DetectionRule] | None,
    ) -> tuple[AuthScanSummary, list[ScoredAlert]]:
        captured.update(
            output_dir=output_dir,
            include_explanations=include_explanations,
            rules=rules,
        )
        return (
            AuthScanSummary(
                log_path=str(log_path),
                auth_events_count=0,
                security_events_count=0,
                detection_matches_count=0,
                scored_alerts_count=0,
                report_path="reports/auth-alerts.json",
            ),
            [],
        )

    monkeypatch.setattr("sentinellite.main.run_auth_scan", fake_run_auth_scan)

    result = runner.invoke(app, ["scan-auth", "auth.log"])

    assert result.exit_code == 0
    assert captured == {
        "output_dir": Path("reports"),
        "include_explanations": False,
        "rules": None,
    }


@pytest.mark.parametrize(
    ("command_args", "pipeline_name"),
    [
        (["scan-auth", "auth.log"], "run_auth_scan"),
        (["scan-process"], "run_process_scan"),
        (["scan-network"], "run_network_scan"),
        (["scan-files", "selected.txt"], "run_file_integrity_scan"),
        (
            ["scan-files-baseline", "--baseline-path", "baseline.json"],
            "run_file_integrity_baseline_scan",
        ),
    ],
)
def test_json_scan_commands_apply_configured_reporting_and_rule_settings(
    command_args: list[str],
    pipeline_name: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "sentinellite.toml"
    config_path.write_text(
        """config_version = 1

[reporting]
output_dir = "configured-reports"
include_explanations = true

[modules]
authentication = true
process = true
network = true
file_integrity = true

[rules]
disabled_ids = ["AUTH-001", "PROC-001", "NET-001", "FIM-001", "FIM-004"]
""",
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    def fake_pipeline(*_args: object, **kwargs: object) -> object:
        captured.update(kwargs)
        report_path = tmp_path / "configured-reports" / "alerts.json"
        if pipeline_name == "run_auth_scan":
            return (
                AuthScanSummary(
                    log_path=str(kwargs["log_path"]),
                    auth_events_count=0,
                    security_events_count=0,
                    detection_matches_count=0,
                    scored_alerts_count=0,
                    report_path=str(report_path),
                ),
                [],
            )
        if pipeline_name == "run_process_scan":
            return ProcessScanSummary(0, 0, 0, 0, str(report_path))
        if pipeline_name == "run_network_scan":
            return NetworkScanSummary(0, 0, 0, 0, str(report_path))
        if pipeline_name == "run_file_integrity_scan":
            return FileIntegrityScanSummary(0, 0, 0, 0, str(report_path))
        return FileIntegrityBaselineScanSummary(
            baseline_path=Path("baseline.json"),
            files_checked_count=0,
            comparisons_count=0,
            security_events_count=0,
            detection_matches_count=0,
            scored_alerts_count=0,
            report_path=report_path,
        )

    monkeypatch.setattr(f"sentinellite.main.{pipeline_name}", fake_pipeline)

    result = runner.invoke(
        app,
        ["--config", str(config_path), *command_args],
    )

    assert result.exit_code == 0
    assert captured["output_dir"] == tmp_path / "configured-reports"
    assert captured["include_explanations"] is True
    disabled_ids = {"AUTH-001", "PROC-001", "NET-001", "FIM-001", "FIM-004"}
    rules = captured["rules"]
    assert isinstance(rules, list)
    assert [rule.rule_id for rule in rules] == [
        rule.rule_id for rule in DEFAULT_RULES if rule.rule_id not in disabled_ids
    ]


@pytest.mark.parametrize(
    ("command_name", "pipeline_name", "module_name", "disabled_message"),
    [
        (
            "scan-auth",
            "run_auth_scan",
            "authentication",
            "Authentication monitoring is disabled by configuration.",
        ),
        (
            "scan-process",
            "run_process_scan",
            "process",
            "Process monitoring is disabled by configuration.",
        ),
        (
            "scan-network",
            "run_network_scan",
            "network",
            "Network monitoring is disabled by configuration.",
        ),
        (
            "scan-files",
            "run_file_integrity_scan",
            "file_integrity",
            "File integrity monitoring is disabled by configuration.",
        ),
        (
            "baseline-files",
            "create_file_integrity_baseline",
            "file_integrity",
            "File integrity monitoring is disabled by configuration.",
        ),
        (
            "scan-files-baseline",
            "run_file_integrity_baseline_scan",
            "file_integrity",
            "File integrity monitoring is disabled by configuration.",
        ),
    ],
)
def test_disabled_module_blocks_command_before_pipeline_or_baseline_write(
    command_name: str,
    pipeline_name: str,
    module_name: str,
    disabled_message: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "sentinellite.toml"
    config_path.write_text(
        "\n".join(
            [
                "config_version = 1",
                "",
                "[reporting]",
                'output_dir = "configured-reports"',
                "include_explanations = true",
                "",
                "[modules]",
                f"{module_name} = false",
                "",
            ]
        ),
        encoding="utf-8",
    )
    pipeline_called = False

    def fake_pipeline(*_args: object, **_kwargs: object) -> None:
        nonlocal pipeline_called
        pipeline_called = True

    monkeypatch.setattr(f"sentinellite.main.{pipeline_name}", fake_pipeline)
    selected_path = tmp_path / "selected.txt"
    baseline_path = tmp_path / "baseline.json"
    command_args = {
        "scan-auth": ["scan-auth", str(tmp_path / "auth.log")],
        "scan-process": ["scan-process"],
        "scan-network": ["scan-network"],
        "scan-files": ["scan-files", str(selected_path)],
        "baseline-files": [
            "baseline-files",
            str(selected_path),
            "--baseline-path",
            str(baseline_path),
        ],
        "scan-files-baseline": [
            "scan-files-baseline",
            "--baseline-path",
            str(baseline_path),
        ],
    }

    result = runner.invoke(
        app,
        ["--config", str(config_path), *command_args[command_name]],
    )

    assert result.exit_code != 0
    assert disabled_message in result.stdout
    assert "Traceback" not in result.stdout
    assert pipeline_called is False
    assert not (tmp_path / "configured-reports").exists()
    assert not baseline_path.exists()


def test_missing_modules_section_keeps_scan_enabled(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = write_reporting_config(tmp_path)
    pipeline_called = False

    def fake_run_auth_scan(
        log_path: Path,
        output_dir: Path,
        *,
        include_explanations: bool,
        rules: list[DetectionRule] | None,
    ) -> tuple[AuthScanSummary, list[ScoredAlert]]:
        nonlocal pipeline_called
        pipeline_called = True
        assert output_dir == tmp_path / "configured-reports"
        assert include_explanations is False
        assert rules is None
        return (
            AuthScanSummary(
                log_path=str(log_path),
                auth_events_count=0,
                security_events_count=0,
                detection_matches_count=0,
                scored_alerts_count=0,
                report_path=str(output_dir / "auth-alerts.json"),
            ),
            [],
        )

    monkeypatch.setattr("sentinellite.main.run_auth_scan", fake_run_auth_scan)

    result = runner.invoke(
        app,
        ["--config", str(config_path), "scan-auth", "auth.log"],
    )

    assert result.exit_code == 0
    assert pipeline_called is True


def test_config_disabling_auth_rule_suppresses_only_failed_login_alerts(
    tmp_path: Path,
) -> None:
    config_path = write_reporting_config(
        tmp_path,
        disabled_ids=("AUTH-001",),
    )

    result = runner.invoke(
        app,
        [
            "--config",
            str(config_path),
            "scan-auth",
            "examples/auth_logs/sample_auth.log",
        ],
    )

    assert result.exit_code == 0
    report_path = next((tmp_path / "configured-reports").glob("*.json"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert set(report) == REPORT_KEYS
    assert [alert["rule_id"] for alert in report["alerts"]] == [
        "AUTH-002",
        "AUTH-003",
    ]
    assert "AUTH-001" not in result.stdout


def test_disabled_auth_rule_has_no_json_or_terminal_explanation(
    tmp_path: Path,
) -> None:
    config_path = write_reporting_config(
        tmp_path,
        include_explanations=True,
        disabled_ids=("AUTH-001",),
    )

    result = runner.invoke(
        app,
        [
            "--config",
            str(config_path),
            "scan-auth",
            "examples/auth_logs/sample_auth.log",
        ],
    )

    assert result.exit_code == 0
    report_path = next((tmp_path / "configured-reports").glob("*.json"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert [alert["rule_id"] for alert in report["alerts"]] == [
        "AUTH-002",
        "AUTH-003",
    ]
    assert [alert["explanation"]["rule_id"] for alert in report["alerts"]] == [
        "AUTH-002",
        "AUTH-003",
    ]
    assert "AUTH-001" not in json.dumps(report["alerts"])
    assert "AUTH-001" not in result.stdout
    assert "Deterministic Alert Explanations" in result.stdout


def test_config_with_no_disabled_rules_preserves_default_auth_alerts(
    tmp_path: Path,
) -> None:
    config_path = write_reporting_config(tmp_path, disabled_ids=())

    result = runner.invoke(
        app,
        [
            "--config",
            str(config_path),
            "scan-auth",
            "examples/auth_logs/sample_auth.log",
        ],
    )

    assert result.exit_code == 0
    report_path = next((tmp_path / "configured-reports").glob("*.json"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert [alert["rule_id"] for alert in report["alerts"]] == [
        "AUTH-001",
        "AUTH-001",
        "AUTH-002",
        "AUTH-003",
    ]


def test_config_disabling_file_integrity_rule_flows_through_scan_files(
    tmp_path: Path,
) -> None:
    missing_path = tmp_path / "missing.txt"
    config_path = write_reporting_config(
        tmp_path,
        disabled_ids=("FIM-001",),
    )

    result = runner.invoke(
        app,
        [
            "--config",
            str(config_path),
            "scan-files",
            str(missing_path),
        ],
    )

    assert result.exit_code == 0
    report_path = next((tmp_path / "configured-reports").glob("*.json"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert [alert["rule_id"] for alert in report["alerts"]] == ["FIM-002"]
    assert "FIM-001" not in result.stdout


def test_config_disabling_changed_file_rule_flows_through_baseline_scan(
    tmp_path: Path,
) -> None:
    monitored_path = tmp_path / "monitored.txt"
    monitored_path.write_text("original", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    baseline_result = runner.invoke(
        app,
        [
            "baseline-files",
            str(monitored_path),
            "--baseline-path",
            str(baseline_path),
        ],
    )
    assert baseline_result.exit_code == 0
    monitored_path.write_text("changed", encoding="utf-8")
    config_path = write_reporting_config(
        tmp_path,
        disabled_ids=("FIM-004",),
    )

    result = runner.invoke(
        app,
        [
            "--config",
            str(config_path),
            "scan-files-baseline",
            "--baseline-path",
            str(baseline_path),
        ],
    )

    assert result.exit_code == 0
    report_path = next((tmp_path / "configured-reports").glob("*.json"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert set(report) == REPORT_KEYS
    assert report["alerts"] == []
    assert "FIM-004" not in result.stdout
    assert "No baseline file integrity alerts generated." in result.stdout


def test_invalid_disabled_rule_fails_before_scan_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = write_reporting_config(
        tmp_path,
        disabled_ids=("AUTH-999",),
    )
    pipeline_called = False

    def fake_run_auth_scan(**_kwargs: object) -> None:
        nonlocal pipeline_called
        pipeline_called = True

    monkeypatch.setattr("sentinellite.main.run_auth_scan", fake_run_auth_scan)

    result = runner.invoke(
        app,
        ["--config", str(config_path), "scan-auth", "auth.log"],
    )

    assert result.exit_code != 0
    assert "Failed to load configuration" in result.stdout
    assert "Unknown disabled rule ID" in result.stdout
    assert "AUTH-999" in result.stdout
    assert "Traceback" not in result.stdout
    assert pipeline_called is False
    assert not (tmp_path / "configured-reports").exists()


def test_config_output_dir_and_false_explanations_write_legacy_json(
    tmp_path: Path,
) -> None:
    config_path = write_reporting_config(tmp_path, include_explanations=False)
    configured_output_dir = tmp_path / "configured-reports"

    result = runner.invoke(
        app,
        [
            "--config",
            str(config_path),
            "scan-auth",
            "examples/auth_logs/sample_auth.log",
        ],
    )

    assert result.exit_code == 0
    report_paths = list(configured_output_dir.glob("*.json"))
    assert len(report_paths) == 1
    report = json.loads(report_paths[0].read_text(encoding="utf-8"))
    assert set(report) == REPORT_KEYS
    assert report["alerts"]
    assert all("explanation" not in alert for alert in report["alerts"])
    assert "Deterministic Alert Explanations" in result.stdout


def test_cli_output_dir_overrides_config_output_dir(tmp_path: Path) -> None:
    config_path = write_reporting_config(tmp_path)
    cli_output_dir = tmp_path / "cli-reports"

    result = runner.invoke(
        app,
        [
            "--config",
            str(config_path),
            "scan-auth",
            "examples/auth_logs/sample_auth.log",
            "--output-dir",
            str(cli_output_dir),
        ],
    )

    assert result.exit_code == 0
    assert len(list(cli_output_dir.glob("*.json"))) == 1
    assert not (tmp_path / "configured-reports").exists()


def test_config_true_writes_nested_json_explanations(tmp_path: Path) -> None:
    config_path = write_reporting_config(tmp_path, include_explanations=True)

    result = runner.invoke(
        app,
        [
            "--config",
            str(config_path),
            "scan-auth",
            "examples/auth_logs/sample_auth.log",
        ],
    )

    assert result.exit_code == 0
    report_path = next((tmp_path / "configured-reports").glob("*.json"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert set(report) == REPORT_KEYS
    assert report["alerts"]
    assert all("explanation" in alert for alert in report["alerts"])
    assert "explanations" not in report


def test_cli_include_explanations_overrides_config_false(tmp_path: Path) -> None:
    config_path = write_reporting_config(tmp_path, include_explanations=False)

    result = runner.invoke(
        app,
        [
            "--config",
            str(config_path),
            "scan-auth",
            "examples/auth_logs/sample_auth.log",
            "--include-explanations",
        ],
    )

    assert result.exit_code == 0
    report_path = next((tmp_path / "configured-reports").glob("*.json"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert all("explanation" in alert for alert in report["alerts"])


def test_cli_no_include_explanations_overrides_config_true(tmp_path: Path) -> None:
    config_path = write_reporting_config(tmp_path, include_explanations=True)

    result = runner.invoke(
        app,
        [
            "--config",
            str(config_path),
            "scan-auth",
            "examples/auth_logs/sample_auth.log",
            "--no-include-explanations",
        ],
    )

    assert result.exit_code == 0
    report_path = next((tmp_path / "configured-reports").glob("*.json"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert all("explanation" not in alert for alert in report["alerts"])


def test_invalid_config_fails_before_scan_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "invalid.toml"
    config_path.write_text("[reporting\noutput_dir = 'reports'", encoding="utf-8")
    pipeline_called = False

    def fake_run_auth_scan(**_kwargs: object) -> None:
        nonlocal pipeline_called
        pipeline_called = True

    monkeypatch.setattr("sentinellite.main.run_auth_scan", fake_run_auth_scan)

    result = runner.invoke(
        app,
        ["--config", str(config_path), "scan-auth", "auth.log"],
    )

    assert result.exit_code != 0
    assert "Failed to load configuration" in result.stdout
    assert "Invalid TOML config file" in result.stdout
    assert "Traceback" not in result.stdout
    assert pipeline_called is False
    assert not (tmp_path / "reports").exists()


def test_missing_config_fails_before_scan_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "missing.toml"
    pipeline_called = False

    def fake_run_auth_scan(**_kwargs: object) -> None:
        nonlocal pipeline_called
        pipeline_called = True

    monkeypatch.setattr("sentinellite.main.run_auth_scan", fake_run_auth_scan)

    result = runner.invoke(
        app,
        ["--config", str(config_path), "scan-auth", "auth.log"],
    )

    assert result.exit_code != 0
    assert "Failed to load configuration" in result.stdout
    assert "Config file not found" in result.stdout
    assert "Traceback" not in result.stdout
    assert pipeline_called is False


def test_config_file_in_current_directory_is_not_auto_discovered(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    write_reporting_config(tmp_path, include_explanations=True)
    captured: dict[str, object] = {}

    def fake_run_auth_scan(
        log_path: Path,
        output_dir: Path,
        *,
        include_explanations: bool,
        rules: list[DetectionRule] | None,
    ) -> tuple[AuthScanSummary, list[ScoredAlert]]:
        captured.update(
            output_dir=output_dir,
            include_explanations=include_explanations,
            rules=rules,
        )
        return (
            AuthScanSummary(
                log_path=str(log_path),
                auth_events_count=0,
                security_events_count=0,
                detection_matches_count=0,
                scored_alerts_count=0,
                report_path="reports/auth-alerts.json",
            ),
            [],
        )

    monkeypatch.setattr("sentinellite.main.run_auth_scan", fake_run_auth_scan)

    result = runner.invoke(app, ["scan-auth", "auth.log"])

    assert result.exit_code == 0
    assert captured == {
        "output_dir": Path("reports"),
        "include_explanations": False,
        "rules": None,
    }


def test_scan_auth_command_without_flag_writes_legacy_json(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan-auth",
            "examples/auth_logs/sample_auth.log",
            "--output-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0
    report_paths = list(tmp_path.glob("*.json"))
    assert len(report_paths) == 1
    report = json.loads(report_paths[0].read_text(encoding="utf-8"))
    assert set(report) == REPORT_KEYS
    assert report["alerts"]
    assert all("explanation" not in alert for alert in report["alerts"])
    assert "Deterministic Alert Explanations" in result.stdout


def test_scan_auth_command_with_flag_writes_json_explanations(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan-auth",
            "examples/auth_logs/sample_auth.log",
            "--output-dir",
            str(tmp_path),
            "--include-explanations",
        ],
    )

    assert result.exit_code == 0
    report_paths = list(tmp_path.glob("*.json"))
    assert len(report_paths) == 1
    report = json.loads(report_paths[0].read_text(encoding="utf-8"))
    assert set(report) == REPORT_KEYS
    assert report["alerts"]
    assert all("explanation" in alert for alert in report["alerts"])
    assert "Deterministic Alert Explanations" in result.stdout

    explanation_text = json.dumps(
        [alert["explanation"] for alert in report["alerts"]]
    ).lower()
    assert "ai detected" not in explanation_text
    assert "malware detected" not in explanation_text
    assert "confirmed compromise" not in explanation_text
    assert "is compromised" not in explanation_text


def test_default_status_describes_implemented_and_planned_modules() -> None:
    result = runner.invoke(app)

    assert result.exit_code == 0
    assert "SentinelLite AI v0.5.0-alpha" in result.stdout
    assert "│ Authentication Monitor  │ Enabled │" in result.stdout
    assert "│ Process Monitor         │ Enabled │" in result.stdout
    assert "│ Network Monitor         │ Enabled │" in result.stdout
    assert "│ File Integrity Monitor  │ Enabled │" in result.stdout
    assert "│ JSON Reporting          │ Enabled │" in result.stdout
    assert "│ AI-Assisted Explanation │ Planned │" in result.stdout
    assert "Monitor active network connections and" in result.stdout
    assert "Observe selected file paths for" in result.stdout
    assert "Not implemented; planned for a future" not in result.stdout


def test_scan_process_command_displays_summary_and_alerts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "process-alerts.json"

    def fake_run_process_scan(
        output_dir: Path,
        *,
        include_explanations: bool,
        rules: list[DetectionRule] | None,
    ) -> ProcessScanSummary:
        assert output_dir == tmp_path
        assert include_explanations is False
        assert rules is None
        return ProcessScanSummary(
            processes_count=3,
            security_events_count=3,
            detection_matches_count=1,
            scored_alerts_count=1,
            report_path=str(report_path),
        )

    monkeypatch.setattr(
        "sentinellite.main.run_process_scan",
        fake_run_process_scan,
    )
    monkeypatch.setattr(
        "sentinellite.main.read_alert_report",
        lambda _report_path: {
            "alerts": [
                {
                    "rule_id": "PROC-001",
                    "risk_level": "medium",
                    "risk_score": 60,
                    "message": "Observed process 'worker' with PID 200",
                }
            ]
        },
    )

    result = runner.invoke(
        app,
        ["scan-process", "--output-dir", str(tmp_path)],
    )

    assert result.exit_code == 0
    assert "Process Scan Complete" in result.stdout
    assert "Processes found" in result.stdout
    assert "Security events created" in result.stdout
    assert "Detection matches" in result.stdout
    assert "Scored alerts" in result.stdout
    assert "JSON report" in result.stdout
    assert "PROC-001" in result.stdout
    assert "MEDIUM (60)" in result.stdout
    assert "Observed process 'worker' with PID 200" in result.stdout
    assert "Deterministic Alert Explanations" in result.stdout
    assert "Process Running From Temporary Path" in result.stdout


def test_scan_process_command_displays_safe_no_alert_message(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "process-alerts.json"

    monkeypatch.setattr(
        "sentinellite.main.run_process_scan",
        lambda output_dir, **_kwargs: ProcessScanSummary(
            processes_count=1,
            security_events_count=1,
            detection_matches_count=0,
            scored_alerts_count=0,
            report_path=str(report_path),
        ),
    )

    result = runner.invoke(
        app,
        ["scan-process", "--output-dir", str(tmp_path)],
    )

    assert result.exit_code == 0
    assert "Process Scan Complete" in result.stdout
    assert "No process alerts generated." in result.stdout
    assert "Deterministic Alert Explanations" not in result.stdout
    assert "Alert Explanation" not in result.stdout


def test_scan_network_command_displays_summary_and_alerts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "network-alerts.json"

    def fake_run_network_scan(
        output_dir: Path,
        *,
        include_explanations: bool,
        rules: list[DetectionRule] | None,
    ) -> NetworkScanSummary:
        assert output_dir == tmp_path
        assert include_explanations is False
        assert rules is None
        return NetworkScanSummary(
            connections_count=3,
            security_events_count=3,
            detection_matches_count=1,
            scored_alerts_count=1,
            report_path=str(report_path),
        )

    monkeypatch.setattr(
        "sentinellite.main.run_network_scan",
        fake_run_network_scan,
    )
    monkeypatch.setattr(
        "sentinellite.main.read_alert_report",
        lambda _report_path: {
            "alerts": [
                {
                    "rule_id": "NET-001",
                    "risk_level": "medium",
                    "risk_score": 55,
                    "message": (
                        "Observed network connection at 127.0.0.1:8080 "
                        "with no remote endpoint"
                    ),
                }
            ]
        },
    )

    result = runner.invoke(
        app,
        ["scan-network", "--output-dir", str(tmp_path)],
    )

    assert result.exit_code == 0
    assert "Network Scan Complete" in result.stdout
    assert "Connections found" in result.stdout
    assert "Security events created" in result.stdout
    assert "Detection matches" in result.stdout
    assert "Scored alerts" in result.stdout
    assert "JSON report" in result.stdout
    assert "NET-001" in result.stdout
    assert "MEDIUM (55)" in result.stdout
    assert "Observed network connection at 127.0.0.1:8080" in result.stdout
    assert "Deterministic Alert Explanations" in result.stdout
    assert "Listening Service on Unusual Port" in result.stdout


def test_scan_network_command_displays_safe_no_alert_message(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "network-alerts.json"

    monkeypatch.setattr(
        "sentinellite.main.run_network_scan",
        lambda output_dir, **_kwargs: NetworkScanSummary(
            connections_count=1,
            security_events_count=1,
            detection_matches_count=0,
            scored_alerts_count=0,
            report_path=str(report_path),
        ),
    )

    result = runner.invoke(
        app,
        ["scan-network", "--output-dir", str(tmp_path)],
    )

    assert result.exit_code == 0
    assert "Network Scan Complete" in result.stdout
    assert "No network alerts generated." in result.stdout
    assert "Deterministic Alert Explanations" not in result.stdout
    assert "Alert Explanation" not in result.stdout


def test_scan_files_command_displays_summary_and_alerts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "file-integrity-alerts.json"
    selected_paths = [Path("/selected/config.txt"), Path("/selected/missing.txt")]

    def fake_run_file_integrity_scan(
        paths: list[Path],
        output_dir: Path,
        *,
        include_explanations: bool,
        rules: list[DetectionRule] | None,
    ) -> FileIntegrityScanSummary:
        assert paths == selected_paths
        assert output_dir == tmp_path
        assert include_explanations is False
        assert rules is None
        return FileIntegrityScanSummary(
            files_checked_count=2,
            security_events_count=2,
            detection_matches_count=2,
            scored_alerts_count=2,
            report_path=str(report_path),
        )

    monkeypatch.setattr(
        "sentinellite.main.run_file_integrity_scan",
        fake_run_file_integrity_scan,
    )
    monkeypatch.setattr(
        "sentinellite.main.read_alert_report",
        lambda _report_path: {
            "alerts": [
                {
                    "rule_id": "FIM-001",
                    "risk_level": "medium",
                    "risk_score": 60,
                    "message": "Observed missing file at /selected/missing.txt",
                }
            ]
        },
    )

    result = runner.invoke(
        app,
        [
            "scan-files",
            *[str(path) for path in selected_paths],
            "--output-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0
    assert "File Integrity Scan Complete" in result.stdout
    assert "Files checked" in result.stdout
    assert "Security events created" in result.stdout
    assert "Detection matches" in result.stdout
    assert "Scored alerts" in result.stdout
    assert "JSON report" in result.stdout
    assert "FIM-001" in result.stdout
    assert "MEDIUM (60)" in result.stdout
    assert "Observed missing file at /selected/missing.txt" in result.stdout
    assert "Deterministic Alert Explanations" in result.stdout
    assert "Monitored File Is Missing" in result.stdout


def test_scan_files_command_displays_safe_no_alert_message(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    selected_path = Path("/selected/config.txt")
    report_path = tmp_path / "file-integrity-alerts.json"

    def fake_run_file_integrity_scan(
        paths: list[Path],
        output_dir: Path,
        *,
        include_explanations: bool,
        rules: list[DetectionRule] | None,
    ) -> FileIntegrityScanSummary:
        assert paths == [selected_path]
        assert output_dir == tmp_path
        assert include_explanations is False
        assert rules is None
        return FileIntegrityScanSummary(
            files_checked_count=1,
            security_events_count=1,
            detection_matches_count=0,
            scored_alerts_count=0,
            report_path=str(report_path),
        )

    monkeypatch.setattr(
        "sentinellite.main.run_file_integrity_scan",
        fake_run_file_integrity_scan,
    )

    result = runner.invoke(
        app,
        ["scan-files", str(selected_path), "--output-dir", str(tmp_path)],
    )

    assert result.exit_code == 0
    assert "File Integrity Scan Complete" in result.stdout
    assert "Files checked" in result.stdout
    assert "Security events created" in result.stdout
    assert "Detection matches" in result.stdout
    assert "Scored alerts" in result.stdout
    assert "JSON report" in result.stdout
    assert "No file integrity alerts generated." in result.stdout
    assert "Deterministic Alert Explanations" not in result.stdout
    assert "Alert Explanation" not in result.stdout


def test_scan_files_command_requires_explicit_path() -> None:
    result = runner.invoke(app, ["scan-files"])

    assert result.exit_code != 0
    assert "Missing argument 'paths'" in result.stderr


def test_baseline_files_command_creates_json_and_displays_summary(tmp_path: Path) -> None:
    first_path = tmp_path / "first.txt"
    second_path = tmp_path / "second.txt"
    first_path.write_text("first", encoding="utf-8")
    second_path.write_text("second", encoding="utf-8")
    baseline_path = tmp_path / "file-integrity-baseline.json"

    result = runner.invoke(
        app,
        [
            "baseline-files",
            str(first_path),
            str(second_path),
            "--baseline-path",
            str(baseline_path),
        ],
    )

    assert result.exit_code == 0
    assert baseline_path.exists()
    assert "File Integrity Baseline Created" in result.stdout
    assert "Files checked" in result.stdout
    assert "Baseline entries" in result.stdout
    assert "Baseline JSON path" in result.stdout
    assert "file-integrity-baseline.json" in result.stdout
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "file-integrity-baseline.json",
        "first.txt",
        "second.txt",
    ]


def test_scan_files_baseline_unchanged_writes_report_and_displays_summary(
    tmp_path: Path,
) -> None:
    monitored_path = tmp_path / "unchanged.txt"
    monitored_path.write_text("unchanged", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    output_dir = tmp_path / "reports"
    create_result = runner.invoke(
        app,
        [
            "baseline-files",
            str(monitored_path),
            "--baseline-path",
            str(baseline_path),
        ],
    )
    assert create_result.exit_code == 0

    result = runner.invoke(
        app,
        [
            "scan-files-baseline",
            "--baseline-path",
            str(baseline_path),
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0
    assert len(list(output_dir.glob("*.json"))) == 1
    assert "File Integrity Baseline Scan Complete" in result.stdout
    assert "Baseline path" in result.stdout
    assert "Files checked" in result.stdout
    assert "Comparisons" in result.stdout
    assert "Security events" in result.stdout
    assert "Detection matches" in result.stdout
    assert "Scored alerts" in result.stdout
    assert "JSON report path" in result.stdout
    assert "No baseline file integrity alerts generated." in result.stdout
    assert "Deterministic Alert Explanations" not in result.stdout
    assert "Alert Explanation" not in result.stdout


def test_scan_files_baseline_displays_alert_after_file_changes(tmp_path: Path) -> None:
    monitored_path = tmp_path / "changed.txt"
    monitored_path.write_text("original", encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    output_dir = tmp_path / "reports"
    create_result = runner.invoke(
        app,
        [
            "baseline-files",
            str(monitored_path),
            "--baseline-path",
            str(baseline_path),
        ],
    )
    assert create_result.exit_code == 0
    monitored_path.write_text("changed content", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan-files-baseline",
            "--baseline-path",
            str(baseline_path),
            "--output-dir",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0
    assert "FIM-004" in result.stdout
    assert "MEDIUM (70)" in result.stdout
    assert "File changed compared with baseline" in result.stdout
    assert "Deterministic Alert Explanations" in result.stdout
    assert "File Changed Compared With Baseline" in result.stdout
    assert "Evidence summary" in result.stdout
    assert "status" in result.stdout
    assert "changed" in result.stdout

    report_paths = list(output_dir.glob("*.json"))
    assert len(report_paths) == 1
    report = json.loads(report_paths[0].read_text(encoding="utf-8"))
    assert set(report) == {
        "report_id",
        "report_type",
        "generated_at",
        "alert_count",
        "alerts",
    }
    assert all("explanation" not in alert for alert in report["alerts"])


def test_scan_files_baseline_missing_file_fails_cleanly(tmp_path: Path) -> None:
    missing_baseline_path = tmp_path / "missing-baseline.json"

    result = runner.invoke(
        app,
        [
            "scan-files-baseline",
            "--baseline-path",
            str(missing_baseline_path),
            "--output-dir",
            str(tmp_path / "reports"),
        ],
    )

    assert result.exit_code == 1
    normalized_stdout = result.stdout.replace("\n", "")
    assert "missing-baseline.json" in normalized_stdout
    assert "No such file or directory" in result.stdout
