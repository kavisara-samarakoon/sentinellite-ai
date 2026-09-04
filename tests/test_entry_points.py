import json
import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest

CONSOLE_SCRIPT = Path(sysconfig.get_path("scripts")) / "sentinellite"
CONSOLE_COMMAND = (str(CONSOLE_SCRIPT),)
MODULE_COMMAND = (sys.executable, "-m", "sentinellite")
PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_COMMANDS = {
    "auth-sources",
    "baseline-files",
    "config-init",
    "reports",
    "scan-auth",
    "scan-files",
    "scan-files-baseline",
    "scan-network",
    "scan-process",
}
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


def run_entry_point(
    command: tuple[str, ...],
    *arguments: str,
    cwd: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*command, *arguments],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def test_console_script_is_installed() -> None:
    assert CONSOLE_SCRIPT.is_file()


def test_entry_point_versions_agree_outside_checkout(tmp_path: Path) -> None:
    console_result = run_entry_point(
        CONSOLE_COMMAND,
        "--version",
        cwd=tmp_path,
    )
    module_result = run_entry_point(
        MODULE_COMMAND,
        "--version",
        cwd=tmp_path,
    )

    expected_output = "SentinelLite AI v1.0.0-beta\n"
    assert console_result.returncode == 0
    assert module_result.returncode == 0
    assert console_result.stdout == expected_output
    assert module_result.stdout == expected_output
    assert console_result.stderr == ""
    assert module_result.stderr == ""


@pytest.mark.parametrize("command", [CONSOLE_COMMAND, MODULE_COMMAND])
def test_bare_entry_point_status_works_outside_checkout(
    command: tuple[str, ...],
    tmp_path: Path,
) -> None:
    result = run_entry_point(command, cwd=tmp_path)

    assert result.returncode == 0
    assert "SentinelLite AI v1.0.0-beta" in result.stdout
    assert "Local Defensive Observation CLI" in result.stdout
    assert "Status: AVAILABLE" in result.stdout
    assert "Configuration error" not in result.stdout
    assert result.stderr == ""


@pytest.mark.parametrize("command", [CONSOLE_COMMAND, MODULE_COMMAND])
def test_entry_point_status_reflects_explicit_toml_config(
    command: tuple[str, ...],
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "sentinellite.toml"
    config_path.write_text(
        """[modules]
authentication = false
process = false
network = false
file_integrity = false
""",
        encoding="utf-8",
    )

    result = run_entry_point(
        command,
        "--config",
        str(config_path),
        cwd=tmp_path,
    )

    normalized_output = " ".join(result.stdout.split())
    assert result.returncode == 0
    for capability_name in (
        "Authentication Scan",
        "Process Scan",
        "Network Observation",
        "File Integrity Check",
    ):
        assert capability_name in normalized_output
    assert normalized_output.count("Disabled") == 4
    assert "Status: AVAILABLE" in result.stdout
    assert result.stderr == ""


@pytest.mark.parametrize("command", [CONSOLE_COMMAND, MODULE_COMMAND])
def test_entry_points_expose_expected_command_tree(
    command: tuple[str, ...],
    tmp_path: Path,
) -> None:
    result = run_entry_point(command, "--help", cwd=tmp_path)

    assert result.returncode == 0
    for command_name in EXPECTED_COMMANDS:
        assert command_name in result.stdout


def test_installed_console_fixture_scan_preserves_separate_schemas(
    tmp_path: Path,
) -> None:
    fixture_path = (
        PROJECT_ROOT / "examples/auth_logs/sample_ubuntu_auth.log"
    )
    report_dir = tmp_path / "reports"
    notification_dir = tmp_path / "notifications"
    notification_dir.mkdir()
    notification_path = notification_dir / "alert-summary.json"

    scan_result = run_entry_point(
        CONSOLE_COMMAND,
        "scan-auth",
        str(fixture_path),
        "--output-dir",
        str(report_dir),
        cwd=tmp_path,
    )

    assert scan_result.returncode == 0
    report_paths = sorted(report_dir.glob("*.json"))
    assert len(report_paths) == 1
    report_path = report_paths[0]
    source_bytes = report_path.read_bytes()

    export_result = run_entry_point(
        CONSOLE_COMMAND,
        "reports",
        "export-notification",
        str(report_path),
        "--output",
        str(notification_path),
        cwd=tmp_path,
    )

    assert export_result.returncode == 0
    assert report_path.read_bytes() == source_bytes
    report = json.loads(source_bytes)
    notification = json.loads(notification_path.read_text(encoding="utf-8"))
    assert set(report) == REPORT_KEYS
    assert report["report_type"] == "sentinellite_alert_report"
    assert "explanations" not in report
    assert set(notification) == NOTIFICATION_KEYS
    assert notification["output_type"] == "sentinellite_notification_summary"
    assert notification["source"] == {
        "report_id": report["report_id"],
        "generated_at": report["generated_at"],
    }
