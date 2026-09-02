import json
import tomllib
from pathlib import Path

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from sentinellite.collectors.auth_sources import (
    DEFAULT_AUTH_LOG_CANDIDATES,
    AuthLogSourceEntry,
)
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
NOTIFICATION_KEYS = {
    "schema_version",
    "output_type",
    "source",
    "alert_count",
    "included_alert_count",
    "omitted_alert_count",
    "severity_counts",
    "risk_level_counts",
    "alerts",
}
NOTIFICATION_ALERT_KEYS = {
    "rule_id",
    "category",
    "severity",
    "risk_score",
    "risk_level",
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


def review_alert(**overrides: object) -> dict[str, object]:
    alert: dict[str, object] = {
        "rule_id": "AUTH-001",
        "severity": "medium",
        "risk_level": "medium",
        "risk_score": 50,
        "category": "authentication",
        "message": "Failed SSH login attempt",
    }
    alert.update(overrides)
    return alert


def write_review_report(
    report_dir: Path,
    *,
    filename: str = "alerts-valid.json",
    generated_at: str = "2026-08-28T10:00:00+00:00",
    alerts: list[dict[str, object]] | None = None,
) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / filename
    report_alerts = [review_alert()] if alerts is None else alerts
    report_path.write_text(
        json.dumps(
            {
                "report_id": f"sentinellite-report-{generated_at}",
                "report_type": "sentinellite_alert_report",
                "generated_at": generated_at,
                "alert_count": len(report_alerts),
                "alerts": report_alerts,
            }
        ),
        encoding="utf-8",
    )
    return report_path


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
    assert "SentinelLite AI v0.7.0-alpha" in result.stdout
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


def test_auth_sources_command_group_registers_list() -> None:
    root_command = get_command(app)

    auth_sources_command = root_command.commands["auth-sources"]

    assert "list" in auth_sources_command.commands


def test_auth_sources_list_displays_default_candidates_and_all_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = tuple(
        AuthLogSourceEntry(
            family=candidate.family,
            path=candidate.path,
            status="missing",
            error=f"Authentication log file not found: {candidate.path}",
        )
        for candidate in DEFAULT_AUTH_LOG_CANDIDATES
    )

    def fake_discovery(candidates: object) -> tuple[AuthLogSourceEntry, ...]:
        assert candidates == DEFAULT_AUTH_LOG_CANDIDATES
        return entries

    monkeypatch.setattr(
        "sentinellite.main.discover_auth_log_sources",
        fake_discovery,
    )

    result = runner.invoke(app, ["auth-sources", "list"])
    normalized_output = result.stdout.replace("\n", "")

    assert result.exit_code == 0
    assert "Family" in result.stdout
    assert "Path" in result.stdout
    assert "Status" in result.stdout
    assert "Diagnostic" in result.stdout
    assert "debian_ubuntu" in result.stdout
    assert "rhel_fedora" in result.stdout
    assert "/var/log/auth.log" in normalized_output
    assert "/var/log/secure" in normalized_output
    assert result.stdout.count("missing") >= 2
    assert "Traceback" not in result.stdout


def test_auth_sources_list_shows_available_and_missing_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    available_path = Path("/tmp/auth.log")
    entries = (
        AuthLogSourceEntry("debian_ubuntu", available_path, "available", None),
        AuthLogSourceEntry(
            "rhel_fedora",
            Path("/var/log/secure"),
            "missing",
            "Authentication log file not found: /var/log/secure",
        ),
    )
    monkeypatch.setattr(
        "sentinellite.main.discover_auth_log_sources",
        lambda _candidates: entries,
    )

    result = runner.invoke(app, ["auth-sources", "list"])

    assert result.exit_code == 0
    assert "available" in result.stdout
    assert "missing" in result.stdout
    assert available_path.name in result.stdout


def test_auth_sources_list_shows_unsupported_and_unreadable_statuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = (
        AuthLogSourceEntry(
            "debian_ubuntu",
            Path("/var/log/auth.log"),
            "unsupported",
            "Authentication log path is not a regular file: /var/log/auth.log",
        ),
        AuthLogSourceEntry(
            "rhel_fedora",
            Path("/var/log/secure"),
            "unreadable",
            "Unable to open authentication log '/var/log/secure': permission denied",
        ),
    )
    monkeypatch.setattr(
        "sentinellite.main.discover_auth_log_sources",
        lambda _candidates: entries,
    )

    result = runner.invoke(app, ["auth-sources", "list"])

    assert result.exit_code == 0
    assert "unsupported" in result.stdout
    assert "unreadable" in result.stdout
    assert "not a regular file" in result.stdout
    assert "permission denied" in result.stdout
    assert "Traceback" not in result.stdout


def test_auth_sources_list_does_not_print_contents_and_renders_literal_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    log_path = Path("[p]auth.log")
    secret_content = "private-authentication-log-content"
    log_path.write_text(secret_content, encoding="utf-8")
    original_content = log_path.read_text(encoding="utf-8")
    entries = (
        AuthLogSourceEntry("[f]", log_path, "[s]", "[d]\nline"),
    )
    monkeypatch.setattr(
        "sentinellite.main.discover_auth_log_sources",
        lambda _candidates: entries,
    )

    result = runner.invoke(app, ["auth-sources", "list"])
    normalized_output = result.stdout.replace("\n", "")

    assert result.exit_code == 0
    assert "[f]" in normalized_output
    assert "[p]" in normalized_output
    assert "[s]" in normalized_output
    assert "[d]" in normalized_output
    assert secret_content not in result.stdout
    assert log_path.read_text(encoding="utf-8") == original_content


def test_auth_sources_list_does_not_invoke_auth_scan_pipeline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "sentinellite.main.discover_auth_log_sources",
        lambda _candidates: (),
    )

    def fail_if_scanned(*_args: object, **_kwargs: object) -> None:
        pytest.fail("auth-sources list must not invoke the scan pipeline")

    monkeypatch.setattr("sentinellite.main.run_auth_scan", fail_if_scanned)

    result = runner.invoke(app, ["auth-sources", "list"])

    assert result.exit_code == 0
    assert "Authentication Scan Complete" not in result.stdout


def test_auth_sources_list_is_not_blocked_by_disabled_authentication_module(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "disabled-auth.toml"
    config_path.write_text(
        """config_version = 1

[modules]
authentication = false
process = true
network = true
file_integrity = true
""",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "sentinellite.main.discover_auth_log_sources",
        lambda _candidates: (),
    )

    result = runner.invoke(
        app,
        ["--config", str(config_path), "auth-sources", "list"],
    )

    assert result.exit_code == 0
    assert "disabled by configuration" not in result.stdout


def test_auth_sources_list_ignores_reporting_and_disabled_rules(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = write_reporting_config(
        tmp_path,
        output_dir="unused-source-inventory-output",
        disabled_ids=("AUTH-001",),
    )
    monkeypatch.setattr(
        "sentinellite.main.discover_auth_log_sources",
        lambda _candidates: (),
    )

    result = runner.invoke(
        app,
        ["--config", str(config_path), "auth-sources", "list"],
    )

    assert result.exit_code == 0
    assert "unused-source-inventory-output" not in result.stdout
    assert "AUTH-001" not in result.stdout


def test_auth_sources_list_displays_non_linux_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "sentinellite.main.discover_auth_log_sources",
        lambda _candidates: (),
    )
    monkeypatch.setattr("sentinellite.main.platform.system", lambda: "Darwin")

    result = runner.invoke(app, ["auth-sources", "list"])
    normalized_output = result.stdout.replace("\n", "")

    assert result.exit_code == 0
    assert "Linux authentication log candidates" in result.stdout
    assert "Explicit sample or custom paths remain supported" in normalized_output


def test_auth_sources_and_scan_auth_register_no_auto_ai_or_llm_options() -> None:
    root_command = get_command(app)
    auth_sources_command = root_command.commands["auth-sources"]
    list_command = auth_sources_command.commands["list"]
    scan_auth_command = root_command.commands["scan-auth"]
    registered_options = {
        option
        for parameter in (
            *auth_sources_command.params,
            *list_command.params,
            *scan_auth_command.params,
        )
        for option in (
            *getattr(parameter, "opts", ()),
            *getattr(parameter, "secondary_opts", ()),
        )
    }

    assert "--auto" not in registered_options
    assert "--ai" not in registered_options
    assert "--llm" not in registered_options


def test_scan_auth_missing_source_fails_cleanly_without_report(tmp_path: Path) -> None:
    log_path = tmp_path / "missing-auth.log"
    report_dir = tmp_path / "reports"

    result = runner.invoke(
        app,
        ["scan-auth", str(log_path), "--output-dir", str(report_dir)],
    )
    normalized_output = result.stdout.replace("\n", "")

    assert result.exit_code == 1
    assert "Authentication log source error" in result.stdout
    assert "Authentication log file not found" in result.stdout
    assert log_path.name in normalized_output
    assert "Traceback" not in result.stdout
    assert not report_dir.exists()


def test_scan_auth_directory_source_fails_cleanly_without_report(tmp_path: Path) -> None:
    log_path = tmp_path / "auth-directory"
    log_path.mkdir()
    report_dir = tmp_path / "reports"

    result = runner.invoke(
        app,
        ["scan-auth", str(log_path), "--output-dir", str(report_dir)],
    )
    normalized_output = result.stdout.replace("\n", "")

    assert result.exit_code == 1
    assert "Authentication log source error" in result.stdout
    assert "not a regular file" in normalized_output
    assert "Traceback" not in result.stdout
    assert not report_dir.exists()


def test_scan_auth_invalid_utf8_source_fails_cleanly_without_report(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "invalid-auth.log"
    log_path.write_bytes(b"private-prefix\n\xff\xfe")
    report_dir = tmp_path / "reports"

    result = runner.invoke(
        app,
        ["scan-auth", str(log_path), "--output-dir", str(report_dir)],
    )

    assert result.exit_code == 1
    assert "Authentication log source error" in result.stdout
    assert "not valid UTF-8" in result.stdout
    assert "private-prefix" not in result.stdout
    assert "Traceback" not in result.stdout
    assert not report_dir.exists()


def test_scan_auth_permission_error_fails_cleanly_without_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "protected-auth.log"
    log_path.write_text("private authentication content\n", encoding="utf-8")
    report_dir = tmp_path / "reports"
    original_open = Path.open

    def deny_selected_path(path: Path, *args: object, **kwargs: object):
        if path == log_path:
            raise PermissionError("simulated permission denial")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_selected_path)

    result = runner.invoke(
        app,
        ["scan-auth", str(log_path), "--output-dir", str(report_dir)],
    )
    compact_output = "".join(result.stdout.split())

    assert result.exit_code == 1
    assert "Authentication log source error" in result.stdout
    assert "simulatedpermissiondenial" in compact_output
    assert "private authentication content" not in result.stdout
    assert "Traceback" not in result.stdout
    assert not report_dir.exists()


@pytest.mark.parametrize(
    ("fixture_path", "output_name"),
    [
        (
            Path("examples/auth_logs/sample_ubuntu_auth.log"),
            "ubuntu-reports",
        ),
        (
            Path("examples/auth_logs/sample_rhel_secure.log"),
            "rhel-reports",
        ),
    ],
)
def test_scan_auth_traditional_linux_fixture_supports_report_review_commands(
    fixture_path: Path,
    output_name: str,
    tmp_path: Path,
) -> None:
    report_dir = tmp_path / output_name

    scan_result = runner.invoke(
        app,
        ["scan-auth", str(fixture_path), "--output-dir", str(report_dir)],
        terminal_width=180,
    )

    report_paths = sorted(report_dir.glob("*.json"))
    assert scan_result.exit_code == 0
    assert "Authentication Scan Complete" in scan_result.stdout
    assert "Auth events found" in scan_result.stdout
    assert len(report_paths) == 1

    list_result = runner.invoke(
        app,
        ["reports", "list", "--report-dir", str(report_dir)],
        terminal_width=180,
    )

    assert list_result.exit_code == 0
    assert "alerts-" in list_result.stdout
    assert "valid" in list_result.stdout

    show_result = runner.invoke(
        app,
        ["reports", "show", str(report_paths[0])],
        terminal_width=180,
    )

    assert show_result.exit_code == 0
    assert "SentinelLite Alert Report Summary" in show_result.stdout
    assert "Stored Alerts" in show_result.stdout
    assert "AUTH-001" in show_result.stdout
    assert "AUTH-002" in show_result.stdout
    assert "AUTH-003" in show_result.stdout


def test_auth_sources_list_does_not_scan_compatibility_fixtures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ubuntu_fixture = Path("examples/auth_logs/sample_ubuntu_auth.log").resolve()
    rhel_fixture = Path("examples/auth_logs/sample_rhel_secure.log").resolve()
    original_contents = {
        ubuntu_fixture: ubuntu_fixture.read_bytes(),
        rhel_fixture: rhel_fixture.read_bytes(),
    }
    entries = (
        AuthLogSourceEntry("debian_ubuntu", ubuntu_fixture, "available", None),
        AuthLogSourceEntry("rhel_fedora", rhel_fixture, "available", None),
    )
    monkeypatch.setattr(
        "sentinellite.main.discover_auth_log_sources",
        lambda _candidates: entries,
    )

    def fail_if_scanned(*_args: object, **_kwargs: object) -> None:
        pytest.fail("auth-sources list must not scan compatibility fixtures")

    monkeypatch.setattr("sentinellite.main.run_auth_scan", fail_if_scanned)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["auth-sources", "list"], terminal_width=180)

    assert result.exit_code == 0
    assert result.stdout.count("available") == 2
    assert list(tmp_path.iterdir()) == []
    assert ubuntu_fixture.read_bytes() == original_contents[ubuntu_fixture]
    assert rhel_fixture.read_bytes() == original_contents[rhel_fixture]


def test_reports_command_group_registers_list_show_and_export_notification() -> None:
    root_command = get_command(app)

    reports_command = root_command.commands["reports"]

    assert "list" in reports_command.commands
    assert "show" in reports_command.commands
    assert "export-notification" in reports_command.commands


def test_reports_list_empty_directory_exits_zero(tmp_path: Path) -> None:
    report_dir = tmp_path / "empty-reports"
    report_dir.mkdir()

    result = runner.invoke(
        app,
        ["reports", "list", "--report-dir", str(report_dir)],
    )

    assert result.exit_code == 0
    assert "No JSON alert reports found in" in result.stdout
    assert str(report_dir) in result.stdout.replace("\n", "")
    assert list(report_dir.iterdir()) == []


def test_reports_list_displays_valid_report_without_modifying_it(tmp_path: Path) -> None:
    report_path = write_review_report(tmp_path / "reports")
    original_content = report_path.read_text(encoding="utf-8")

    result = runner.invoke(
        app,
        ["reports", "list", "--report-dir", str(report_path.parent)],
    )

    assert result.exit_code == 0
    assert "Generated At" in result.stdout
    assert "Alerts" in result.stdout
    assert "Report Type" in result.stdout
    assert "Status" in result.stdout
    assert "File" in result.stdout
    assert "2026-08-28" in result.stdout
    assert "valid" in result.stdout
    assert report_path.name in result.stdout
    assert report_path.read_text(encoding="utf-8") == original_content


def test_reports_list_uses_builtin_default_reports_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    report_path = write_review_report(tmp_path / "reports", filename="default.json")

    result = runner.invoke(app, ["reports", "list"])

    assert result.exit_code == 0
    assert report_path.name in result.stdout


def test_reports_list_uses_configured_reporting_directory(tmp_path: Path) -> None:
    config_path = write_reporting_config(tmp_path)
    report_path = write_review_report(
        tmp_path / "configured-reports",
        filename="configured.json",
    )

    result = runner.invoke(
        app,
        ["--config", str(config_path), "reports", "list"],
    )

    assert result.exit_code == 0
    assert report_path.name in result.stdout


def test_reports_list_report_dir_overrides_configured_directory(
    tmp_path: Path,
) -> None:
    config_path = write_reporting_config(tmp_path)
    configured_report = write_review_report(
        tmp_path / "configured-reports",
        filename="configured.json",
    )
    override_dir = tmp_path / "override-reports"
    override_report = write_review_report(override_dir, filename="override.json")

    result = runner.invoke(
        app,
        [
            "--config",
            str(config_path),
            "reports",
            "list",
            "--report-dir",
            str(override_dir),
        ],
    )

    assert result.exit_code == 0
    assert override_report.name in result.stdout
    assert configured_report.name not in result.stdout


def test_reports_list_missing_directory_fails_cleanly(tmp_path: Path) -> None:
    missing_dir = tmp_path / "missing-reports"

    result = runner.invoke(
        app,
        ["reports", "list", "--report-dir", str(missing_dir)],
    )
    normalized_output = result.stdout.replace("\n", "")

    assert result.exit_code == 1
    assert "Report directory not found" in result.stdout
    assert "missing-reports" in normalized_output
    assert "Traceback" not in result.stdout


def test_reports_list_non_directory_path_fails_cleanly(tmp_path: Path) -> None:
    report_path = write_review_report(tmp_path)

    result = runner.invoke(
        app,
        ["reports", "list", "--report-dir", str(report_path)],
    )
    normalized_output = result.stdout.replace("\n", "")

    assert result.exit_code == 1
    assert "not a directory" in result.stdout
    assert report_path.name in normalized_output
    assert "Traceback" not in result.stdout


def test_reports_list_shows_valid_and_invalid_entries_then_exits_nonzero(
    tmp_path: Path,
) -> None:
    report_dir = tmp_path / "mixed-reports"
    valid_path = write_review_report(report_dir, filename="valid.json")
    invalid_path = report_dir / "invalid.json"
    invalid_path.write_text("not JSON", encoding="utf-8")

    result = runner.invoke(
        app,
        ["reports", "list", "--report-dir", str(report_dir)],
    )

    assert result.exit_code == 1
    assert valid_path.name in result.stdout
    assert invalid_path.name in result.stdout
    assert "valid" in result.stdout
    assert "invalid" in result.stdout
    assert "Malformed JSON" in result.stdout
    assert "not JSON" not in result.stdout
    assert "Traceback" not in result.stdout


def test_reports_list_renders_report_filename_as_literal_text(tmp_path: Path) -> None:
    report_dir = tmp_path / "literal-reports"
    report_path = write_review_report(
        report_dir,
        filename="[red]literal.json",
    )

    result = runner.invoke(
        app,
        ["reports", "list", "--report-dir", str(report_dir)],
    )

    assert result.exit_code == 0
    assert report_path.name in result.stdout


def test_reports_list_config_error_occurs_before_listing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "invalid.toml"
    config_path.write_text("[reporting\n", encoding="utf-8")
    listing_called = False

    def fake_list_report_entries(_report_dir: Path) -> list[object]:
        nonlocal listing_called
        listing_called = True
        return []

    monkeypatch.setattr(
        "sentinellite.main.list_report_entries",
        fake_list_report_entries,
    )

    result = runner.invoke(
        app,
        ["--config", str(config_path), "reports", "list"],
    )

    assert result.exit_code == 1
    assert "Failed to load configuration" in result.stdout
    assert "Traceback" not in result.stdout
    assert listing_called is False


def test_reports_list_is_not_blocked_by_disabled_modules(tmp_path: Path) -> None:
    report_dir = tmp_path / "disabled-module-reports"
    report_path = write_review_report(report_dir)
    config_path = tmp_path / "disabled-modules.toml"
    config_path.write_text(
        f"""config_version = 1

[reporting]
output_dir = "{report_dir}"

[modules]
authentication = false
process = false
network = false
file_integrity = false
""",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["--config", str(config_path), "reports", "list"],
    )

    assert result.exit_code == 0
    assert report_path.name in result.stdout
    assert "disabled by configuration" not in result.stdout


def test_reports_list_ignores_disabled_rule_selection(tmp_path: Path) -> None:
    config_path = write_reporting_config(tmp_path, disabled_ids=("AUTH-001",))
    report_path = write_review_report(tmp_path / "configured-reports")

    result = runner.invoke(
        app,
        ["--config", str(config_path), "reports", "list"],
    )

    assert result.exit_code == 0
    assert report_path.name in result.stdout


def test_reports_commands_register_no_filters_ai_or_llm_options() -> None:
    root_command = get_command(app)
    reports_command = root_command.commands["reports"]
    list_command = reports_command.commands["list"]
    show_command = reports_command.commands["show"]
    export_command = reports_command.commands["export-notification"]
    registered_options = {
        option
        for parameter in (
            *reports_command.params,
            *list_command.params,
            *show_command.params,
            *export_command.params,
        )
        for option in (
            *getattr(parameter, "opts", ()),
            *getattr(parameter, "secondary_opts", ()),
        )
    }

    assert "--report-dir" in registered_options
    assert "--rule-id" not in registered_options
    assert "--severity" not in registered_options
    assert "--risk-level" not in registered_options
    assert "--ai" not in registered_options
    assert "--llm" not in registered_options


def test_reports_export_notification_registers_only_local_output_option() -> None:
    root_command = get_command(app)
    export_command = root_command.commands["reports"].commands["export-notification"]
    registered_options = {
        option
        for parameter in export_command.params
        for option in (
            *getattr(parameter, "opts", ()),
            *getattr(parameter, "secondary_opts", ()),
        )
    }

    assert "--output" in registered_options
    for forbidden_option in (
        "--send",
        "--webhook",
        "--slack",
        "--discord",
        "--email",
        "--sms",
        "--provider",
        "--token",
        "--ai",
        "--llm",
    ):
        assert forbidden_option not in registered_options


def test_reports_show_displays_report_summary_fields_without_modifying_file(
    tmp_path: Path,
) -> None:
    report_path = write_review_report(tmp_path / "reports", filename="summary.json")
    original_content = report_path.read_text(encoding="utf-8")

    result = runner.invoke(
        app,
        ["reports", "show", str(report_path)],
        terminal_width=180,
    )

    assert result.exit_code == 0
    assert "SentinelLite Alert Report Summary" in result.stdout
    assert "File path" in result.stdout
    assert str(report_path)[:30] in result.stdout
    assert "Report ID" in result.stdout
    assert "sentinellite-report-2026-08-28T10:00:00+00:00" in result.stdout
    assert "Report type" in result.stdout
    assert "sentinellite_alert_report" in result.stdout
    assert "Generated timestamp" in result.stdout
    assert "2026-08-28T10:00:00+00:00" in result.stdout
    assert "Alert count" in result.stdout
    assert "Stored explanation count" in result.stdout
    assert "Rule IDs" in result.stdout
    assert "AUTH-001" in result.stdout
    assert "Severity counts" in result.stdout
    assert "medium: 1" in result.stdout
    assert "Risk level counts" in result.stdout
    assert report_path.read_text(encoding="utf-8") == original_content


def test_reports_show_displays_compact_alert_table(tmp_path: Path) -> None:
    report_path = write_review_report(tmp_path / "reports")

    result = runner.invoke(
        app,
        ["reports", "show", str(report_path)],
        terminal_width=180,
    )

    assert result.exit_code == 0
    assert "Stored Alerts" in result.stdout
    assert "Rule ID" in result.stdout
    assert "Severity" in result.stdout
    assert "Risk" in result.stdout
    assert "Category" in result.stdout
    assert "Message" in result.stdout
    assert "Explanation" in result.stdout
    assert "AUTH-001" in result.stdout
    assert "medium (50)" in result.stdout
    assert "authentic" in result.stdout
    assert "Failed SSH" in result.stdout
    assert "login" in result.stdout
    assert "attempt" in result.stdout


def test_reports_show_counts_and_marks_stored_explanations_without_body(
    tmp_path: Path,
) -> None:
    report_path = write_review_report(
        tmp_path / "reports",
        alerts=[
            review_alert(
                explanation={
                    "summary": "NEVER_RENDER_STORED_EXPLANATION_BODY",
                    "recommended_actions": ["Do not render this"],
                }
            ),
            review_alert(
                rule_id="NET-001",
                category="network",
                message="Network observation",
            ),
        ],
    )

    result = runner.invoke(
        app,
        ["reports", "show", str(report_path)],
        terminal_width=180,
    )

    normalized_output = " ".join(result.stdout.split())
    assert result.exit_code == 0
    assert "Stored explanation count │ 1 │" in normalized_output
    assert "yes" in result.stdout
    assert "no" in result.stdout
    assert "NEVER_RENDER_STORED_EXPLANATION_BODY" not in result.stdout
    assert "Do not render this" not in result.stdout


def test_reports_show_valid_empty_report(tmp_path: Path) -> None:
    report_path = write_review_report(tmp_path / "reports", alerts=[])

    result = runner.invoke(
        app,
        ["reports", "show", str(report_path)],
        terminal_width=180,
    )

    normalized_output = " ".join(result.stdout.split())
    assert result.exit_code == 0
    assert "Alert count │ 0 │" in normalized_output
    assert "Stored explanation count │ 0 │" in normalized_output
    assert "Stored Alerts" in result.stdout
    assert "No alerts stored in this report." in result.stdout


def test_reports_show_missing_file_fails_cleanly(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing.json"

    result = runner.invoke(app, ["reports", "show", str(missing_path)])
    normalized_output = result.stdout.replace("\n", "")

    assert result.exit_code == 1
    assert "Report file not found" in result.stdout
    assert "missing.json" in normalized_output
    assert "Traceback" not in result.stdout


def test_reports_show_malformed_json_fails_cleanly_without_dumping_content(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "malformed.json"
    report_path.write_text('{"secret": "RAW_REPORT_CONTENT"', encoding="utf-8")

    result = runner.invoke(app, ["reports", "show", str(report_path)])

    assert result.exit_code == 1
    assert "Malformed JSON" in result.stdout
    assert "line 1" in result.stdout
    assert "RAW_REPORT_CONTENT" not in result.stdout
    assert "Traceback" not in result.stdout


def test_reports_show_incompatible_shape_fails_cleanly_without_raw_json(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "incompatible.json"
    report_path.write_text(
        json.dumps({"secret": "INCOMPATIBLE_RAW_CONTENT"}),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["reports", "show", str(report_path)])

    assert result.exit_code == 1
    assert "supportedreport_type" in "".join(result.stdout.split())
    assert "INCOMPATIBLE_RAW_CONTENT" not in result.stdout
    assert "Traceback" not in result.stdout


def test_reports_show_does_not_print_evidence_or_raw_json(tmp_path: Path) -> None:
    report_path = write_review_report(
        tmp_path / "reports",
        alerts=[
            review_alert(
                evidence={
                    "username": "SENSITIVE_EVIDENCE_USERNAME",
                    "source_ip": "192.0.2.10",
                }
            )
        ],
    )

    result = runner.invoke(
        app,
        ["reports", "show", str(report_path)],
        terminal_width=180,
    )

    assert result.exit_code == 0
    assert "SENSITIVE_EVIDENCE_USERNAME" not in result.stdout
    assert "192.0.2.10" not in result.stdout
    assert '"alerts"' not in result.stdout
    assert '"evidence"' not in result.stdout


def test_reports_show_does_not_regenerate_explanations(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = write_review_report(
        tmp_path / "reports",
        alerts=[review_alert(explanation={"summary": "Stored only"})],
    )

    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("reports show must not regenerate explanations")

    monkeypatch.setattr(
        "sentinellite.main.generate_alert_explanation",
        fail_if_called,
    )

    result = runner.invoke(app, ["reports", "show", str(report_path)])

    assert result.exit_code == 0
    assert "yes" in result.stdout


def test_reports_show_renders_markup_literally_and_removes_control_characters(
    tmp_path: Path,
) -> None:
    report_path = write_review_report(
        tmp_path / "reports",
        alerts=[
            review_alert(
                rule_id="[red]X",
                message="safe\x1bcontrol",
            )
        ],
    )

    result = runner.invoke(
        app,
        ["reports", "show", str(report_path)],
        terminal_width=180,
    )

    assert result.exit_code == 0
    assert "[red]X" in result.stdout
    assert "safe control" in result.stdout
    assert "\x1b" not in result.stdout


def test_reports_show_is_not_blocked_by_disabled_modules(tmp_path: Path) -> None:
    report_path = write_review_report(tmp_path / "explicit-reports")
    config_path = tmp_path / "disabled-modules-show.toml"
    config_path.write_text(
        """config_version = 1

[reporting]
output_dir = "unrelated-reports"

[modules]
authentication = false
process = false
network = false
file_integrity = false
""",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["--config", str(config_path), "reports", "show", str(report_path)],
        terminal_width=180,
    )

    assert result.exit_code == 0
    assert "AUTH-001" in result.stdout
    assert "disabled by configuration" not in result.stdout


def test_reports_show_ignores_disabled_rule_selection(tmp_path: Path) -> None:
    config_path = write_reporting_config(tmp_path, disabled_ids=("AUTH-001",))
    report_path = write_review_report(tmp_path / "explicit-reports")

    result = runner.invoke(
        app,
        ["--config", str(config_path), "reports", "show", str(report_path)],
        terminal_width=180,
    )

    assert result.exit_code == 0
    assert "AUTH-001" in result.stdout


def test_reports_export_notification_writes_exact_schema_and_preserves_source(
    tmp_path: Path,
) -> None:
    report_path = write_review_report(
        tmp_path / "reports",
        alerts=[
            review_alert(rule_id="AUTH-LOW", risk_score=10, risk_level="info"),
            review_alert(rule_id="AUTH-HIGH", risk_score=90, risk_level="critical"),
        ],
    )
    source_before = report_path.read_bytes()
    output_path = tmp_path / "notifications" / "notification.json"
    output_path.parent.mkdir()

    result = runner.invoke(
        app,
        [
            "reports",
            "export-notification",
            str(report_path),
            "--output",
            str(output_path),
        ],
        terminal_width=180,
    )

    assert result.exit_code == 0
    assert report_path.read_bytes() == source_before
    notification = json.loads(output_path.read_text(encoding="utf-8"))
    assert set(notification) == NOTIFICATION_KEYS
    assert notification["schema_version"] == 1
    assert notification["output_type"] == "sentinellite_notification_summary"
    assert notification["source"] == {
        "report_id": "sentinellite-report-2026-08-28T10:00:00+00:00",
        "generated_at": "2026-08-28T10:00:00+00:00",
    }
    assert notification["alert_count"] == 2
    assert notification["included_alert_count"] == 2
    assert notification["omitted_alert_count"] == 0
    assert [alert["rule_id"] for alert in notification["alerts"]] == [
        "AUTH-HIGH",
        "AUTH-LOW",
    ]
    assert all(set(alert) == NOTIFICATION_ALERT_KEYS for alert in notification["alerts"])
    assert "Notification summary exported successfully" in result.stdout
    assert "Source report ID" in result.stdout
    assert "Total alerts" in result.stdout
    assert "Included alerts" in result.stdout
    assert "Omitted alerts" in result.stdout
    assert str(output_path) in result.stdout.replace("\n", "")


def test_reports_export_notification_existing_output_fails_cleanly(
    tmp_path: Path,
) -> None:
    report_path = write_review_report(tmp_path / "reports")
    output_path = tmp_path / "notification.json"
    output_path.write_text("preserve output", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "reports",
            "export-notification",
            str(report_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 1
    assert "Notification export error" in result.stdout
    assert "overwrite refused" in result.stdout
    assert "Traceback" not in result.stdout
    assert output_path.read_text(encoding="utf-8") == "preserve output"


def test_reports_export_notification_missing_output_parent_fails_cleanly(
    tmp_path: Path,
) -> None:
    report_path = write_review_report(tmp_path / "reports")
    output_path = tmp_path / "missing" / "notification.json"

    result = runner.invoke(
        app,
        [
            "reports",
            "export-notification",
            str(report_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 1
    assert "parentdirectorydoesnotexist" in "".join(result.stdout.split())
    assert "Traceback" not in result.stdout
    assert not output_path.exists()


def test_reports_export_notification_directory_output_fails_cleanly(
    tmp_path: Path,
) -> None:
    report_path = write_review_report(tmp_path / "reports")
    output_path = tmp_path / "notification.json"
    output_path.mkdir()

    result = runner.invoke(
        app,
        [
            "reports",
            "export-notification",
            str(report_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 1
    assert "existingdirectory" in "".join(result.stdout.split())
    assert "Traceback" not in result.stdout
    assert output_path.is_dir()


def test_reports_export_notification_refuses_source_report_as_output(
    tmp_path: Path,
) -> None:
    report_path = write_review_report(tmp_path / "reports")
    source_before = report_path.read_bytes()

    result = runner.invoke(
        app,
        [
            "reports",
            "export-notification",
            str(report_path),
            "--output",
            str(report_path),
        ],
    )

    assert result.exit_code == 1
    assert "mustdifferfromthesourcereport" in "".join(result.stdout.split())
    assert "Traceback" not in result.stdout
    assert report_path.read_bytes() == source_before


def test_reports_export_notification_invalid_report_fails_cleanly(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "invalid.json"
    report_path.write_text(
        json.dumps({"output_type": "NOT_RAW_PRIVATE_CONTENT"}),
        encoding="utf-8",
    )
    output_path = tmp_path / "notification.json"

    result = runner.invoke(
        app,
        [
            "reports",
            "export-notification",
            str(report_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 1
    assert "Report review error" in result.stdout
    assert "supportedreport_type" in "".join(result.stdout.split())
    assert "NOT_RAW_PRIVATE_CONTENT" not in result.stdout
    assert "Traceback" not in result.stdout
    assert not output_path.exists()


def test_reports_export_notification_malformed_report_fails_cleanly(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "malformed.json"
    report_path.write_text('{"private": "RAW_PRIVATE_CONTENT"', encoding="utf-8")
    output_path = tmp_path / "notification.json"

    result = runner.invoke(
        app,
        [
            "reports",
            "export-notification",
            str(report_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 1
    assert "Malformed JSON" in result.stdout
    assert "RAW_PRIVATE_CONTENT" not in result.stdout
    assert "Traceback" not in result.stdout
    assert not output_path.exists()


def test_reports_export_notification_omits_private_content_from_cli_and_json(
    tmp_path: Path,
) -> None:
    private_values = (
        "PRIVATE_ALERT_MESSAGE",
        "PRIVATE_USERNAME",
        "192.0.2.77",
        "PRIVATE_COMMAND",
        "PRIVATE_PROCESS",
        "PRIVATE_HASH",
        "PRIVATE_EXPLANATION_BODY",
    )
    report_path = write_review_report(
        tmp_path / "reports",
        alerts=[
            review_alert(
                message=" ".join(private_values[:4]),
                evidence={
                    "process_name": private_values[4],
                    "sha256": private_values[5],
                    "username": private_values[1],
                    "source_ip": private_values[2],
                },
                explanation={"summary": private_values[6]},
            )
        ],
    )
    output_path = tmp_path / "notification.json"

    result = runner.invoke(
        app,
        [
            "reports",
            "export-notification",
            str(report_path),
            "--output",
            str(output_path),
        ],
        terminal_width=180,
    )
    written_text = output_path.read_text(encoding="utf-8")

    assert result.exit_code == 0
    for private_value in private_values:
        assert private_value not in result.stdout
        assert private_value not in written_text
    assert '"alerts"' not in result.stdout
    assert '"evidence"' not in result.stdout
    assert '"explanation"' not in result.stdout


def test_reports_export_notification_ignores_disabled_modules_and_rules(
    tmp_path: Path,
) -> None:
    report_path = write_review_report(tmp_path / "explicit-reports")
    output_path = tmp_path / "notification.json"
    config_path = tmp_path / "disabled.toml"
    config_path.write_text(
        """config_version = 1

[modules]
authentication = false
process = false
network = false
file_integrity = false

[rules]
disabled_ids = ["AUTH-001"]
""",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "--config",
            str(config_path),
            "reports",
            "export-notification",
            str(report_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert output_path.exists()
    assert "disabled by configuration" not in result.stdout


def test_reports_export_notification_does_not_run_active_processing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = write_review_report(tmp_path / "reports")
    output_path = tmp_path / "notification.json"

    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("notification export must use only the stored reviewed report")

    for target in (
        "sentinellite.main.run_auth_scan",
        "sentinellite.main.run_process_scan",
        "sentinellite.main.run_network_scan",
        "sentinellite.main.run_file_integrity_scan",
        "sentinellite.main.run_file_integrity_baseline_scan",
        "sentinellite.main.create_file_integrity_baseline",
        "sentinellite.main.generate_alert_explanation",
        "sentinellite.detection.engine.detect_events",
        "sentinellite.scoring.risk.score_rule_matches",
    ):
        monkeypatch.setattr(target, fail_if_called)

    result = runner.invoke(
        app,
        [
            "reports",
            "export-notification",
            str(report_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert output_path.exists()


def test_reports_list_marks_mixed_notification_summary_as_invalid(
    tmp_path: Path,
) -> None:
    report_dir = tmp_path / "mixed-reports"
    report_path = write_review_report(report_dir, filename="alerts.json")
    notification_path = report_dir / "notification.json"

    export_result = runner.invoke(
        app,
        [
            "reports",
            "export-notification",
            str(report_path),
            "--output",
            str(notification_path),
        ],
    )
    list_result = runner.invoke(
        app,
        ["reports", "list", "--report-dir", str(report_dir)],
    )

    assert export_result.exit_code == 0
    assert list_result.exit_code == 1
    assert report_path.name in list_result.stdout
    assert notification_path.name in list_result.stdout
    assert "valid" in list_result.stdout
    assert "invalid" in list_result.stdout
    assert "supported report_type" in list_result.stdout
