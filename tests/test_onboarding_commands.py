import json
import shlex
from contextlib import contextmanager
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinellite import __version__
from sentinellite.config import ConfigError
from sentinellite.main import app
from sentinellite.reporting.review import load_review_report

runner = CliRunner()
REPORT_KEYS = {"report_id", "report_type", "generated_at", "alert_count", "alerts"}


@pytest.fixture
def local_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Onboarding must not observe the host or use the network")

    for target in (
        "sentinellite.main.show_status",
        "sentinellite.main.collect_system_info",
        "sentinellite.main.discover_auth_log_sources",
        "sentinellite.main.run_auth_scan",
        "sentinellite.main.run_process_scan",
        "sentinellite.main.run_network_scan",
        "sentinellite.main.run_file_integrity_scan",
        "sentinellite.main.run_file_integrity_baseline_scan",
        "sentinellite.main.create_file_integrity_baseline",
        "sentinellite.pipeline.auth_scan.collect_auth_events_from_file",
        "sentinellite.collectors.auth.collect_auth_events_from_file",
        "sentinellite.collectors.auth_sources.validate_auth_log_path",
        "sentinellite.collectors.process.collect_processes",
        "sentinellite.collectors.network.collect_network_connections",
        "sentinellite.collectors.file_integrity.collect_file_integrity",
        "psutil.process_iter",
        "psutil.net_connections",
        "psutil.Process",
        "socket.gethostname",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.create_connection",
        "socket.socket.connect",
        "socket.socket.connect_ex",
        "socket.socket.sendto",
        "subprocess.Popen",
        "os.system",
    ):
        monkeypatch.setattr(target, forbidden)


def test_demo_writes_reviewable_synthetic_report_without_reading_files(
    local_only: None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    original_open = Path.open

    def write_only(path: Path, mode: str = "r", *args: object, **kwargs: object):
        assert mode == "w", f"Demo must not read files: {path}"
        assert path.parent == Path("reports")
        return original_open(path, mode, *args, **kwargs)

    with monkeypatch.context() as guard:
        guard.setattr(Path, "open", write_only)
        result = runner.invoke(app, ["demo"])

    assert result.exit_code == 0, result.output
    assert "Demo complete: 3 synthetic events, 3 alerts" in result.stdout
    assert "no real logs" in result.stdout
    reports = list((tmp_path / "reports").glob("*.json"))
    assert len(reports) == 1
    report_path = reports[0]
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert set(report) == REPORT_KEYS
    assert report["report_type"] == "sentinellite_alert_report"
    assert report["alert_count"] == 3
    assert [alert["rule_id"] for alert in report["alerts"]] == ["AUTH-001", "AUTH-002", "AUTH-003"]
    assert all(alert["evidence"]["username"] == "demo-user" for alert in report["alerts"])
    assert all("explanation" not in alert for alert in report["alerts"])
    assert load_review_report(report_path).alert_count == 3
    relative_path = report_path.relative_to(tmp_path)
    assert f"Saved report: {relative_path}" in result.stdout
    assert "sentinellite reports list\n" in result.stdout
    assert f"sentinellite reports show {relative_path}" in result.stdout
    assert runner.invoke(app, ["reports", "list"]).exit_code == 0
    assert runner.invoke(app, ["reports", "show", str(report_path)]).exit_code == 0


@pytest.mark.parametrize("override", [False, True])
def test_demo_respects_reporting_settings_and_prints_runnable_commands(
    local_only: None,
    tmp_path: Path,
    override: bool,
) -> None:
    config_path = tmp_path / "settings.toml"
    config_path.write_text(
        '[reporting]\noutput_dir = "configured reports"\ninclude_explanations = true\n'
        "[modules]\nauthentication = false\nprocess = false\nnetwork = false\n"
        'file_integrity = false\n[rules]\ndisabled_ids = ["AUTH-001"]\n',
        encoding="utf-8",
    )
    output_dir = tmp_path / ("override [reports]" if override else "configured reports")
    arguments = ["--config", str(config_path), "demo"]
    if override:
        arguments += ["--output-dir", str(output_dir)]

    result = runner.invoke(app, arguments)

    assert result.exit_code == 0, result.output
    (report_path,) = output_dir.glob("*.json")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert set(report) == REPORT_KEYS
    assert report["alert_count"] == 3  # Demo always uses built-in rules, without collection.
    assert all("explanation" in alert for alert in report["alerts"])
    assert f"Saved report: {report_path}" in result.stdout
    suggested = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip().startswith("sentinellite reports")
    ]
    assert len(suggested) == 2
    for command in suggested:
        review = runner.invoke(app, shlex.split(command)[1:])
        assert review.exit_code == 0, review.output
        assert "No JSON alert reports" not in review.stdout
    if override:
        assert not (tmp_path / "configured reports").exists()


def test_demo_does_not_overwrite_previous_report(local_only: None, tmp_path: Path) -> None:
    assert runner.invoke(app, ["demo"]).exit_code == 0
    (first_path,) = (tmp_path / "reports").glob("*.json")
    original = first_path.read_bytes()

    assert runner.invoke(app, ["demo"]).exit_code == 0

    assert first_path.read_bytes() == original
    assert len(list((tmp_path / "reports").glob("*.json"))) == 2


def test_demo_output_failure_is_actionable(local_only: None, tmp_path: Path) -> None:
    blocked = tmp_path / "reports"
    blocked.write_text("existing file", encoding="utf-8")

    result = runner.invoke(app, ["demo"])

    assert result.exit_code == 1
    assert "Demo failed" in result.stdout
    assert "reports" in result.stdout
    assert "Demo complete" not in result.stdout
    assert "Next commands" not in result.stdout
    assert "Traceback" not in result.output
    assert blocked.read_text(encoding="utf-8") == "existing file"


def test_demo_does_not_accept_log_input(local_only: None, tmp_path: Path) -> None:
    result = runner.invoke(app, ["demo", "/var/log/auth.log"])

    assert result.exit_code == 2
    assert not (tmp_path / "reports").exists()


@pytest.mark.parametrize(("system", "outcome"), [("Linux", "PASS"), ("Darwin", "WARNING")])
def test_doctor_checks_local_environment_and_removes_probe(
    local_only: None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    system: str,
    outcome: str,
) -> None:
    monkeypatch.setattr("sentinellite.doctor.platform.system", lambda: system)
    monkeypatch.setattr("sentinellite.doctor.platform.release", lambda: "test-release")
    monkeypatch.setattr("sentinellite.doctor.platform.machine", lambda: "test-architecture")
    original_open = Path.open

    def config_only(path: Path, *args: object, **kwargs: object):
        assert path.name == "default.yaml"
        assert path.parent.name == "config"
        return original_open(path, *args, **kwargs)

    with monkeypatch.context() as guard:
        guard.setattr(Path, "open", config_only)
        result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0, result.output
    for expected in (
        f"[PASS] SentinelLite version: {__version__}",
        "[PASS] Python version:",
        f"Platform/system: {system} test-release",
        "[PASS] Machine architecture: test-architecture",
        "[PASS] Default config:",
        "[PASS] Report output directory: reports: writable",
        "[PASS] Dependency psutil:",
        "[PASS] Dependency PyYAML:",
        "[PASS] Dependency rich:",
        "[PASS] Dependency typer:",
        f"Summary: {outcome}",
        "0 failed",
        "no root required",
        "not endpoint security",
    ):
        assert expected in result.stdout
    assert (tmp_path / "reports").is_dir()
    assert list((tmp_path / "reports").iterdir()) == []


def test_doctor_preserves_existing_reports_and_honors_output_override(
    local_only: None,
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "settings.toml"
    config_path.write_text('[reporting]\noutput_dir = "configured"\n', encoding="utf-8")
    assert runner.invoke(app, ["--config", str(config_path), "doctor"]).exit_code == 0
    assert list((tmp_path / "configured").iterdir()) == []
    output_dir = tmp_path / "selected [reports]"
    output_dir.mkdir()
    report_path = output_dir / "existing.json"
    report_path.write_bytes(b"leave this report alone")

    result = runner.invoke(
        app, ["--config", str(config_path), "doctor", "--output-dir", str(output_dir)]
    )

    assert result.exit_code == 0, result.output
    assert str(output_dir) in result.stdout
    assert list(output_dir.iterdir()) == [report_path]
    assert report_path.read_bytes() == b"leave this report alone"
    assert not (tmp_path / "reports").exists()


def test_doctor_reports_config_and_directory_failures_and_continues(
    local_only: None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def broken_config():
        raise ConfigError("packaged defaults unavailable")

    monkeypatch.setattr("sentinellite.doctor.load_config", broken_config)
    (tmp_path / "reports").write_text("existing file", encoding="utf-8")

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 1
    assert "[FAIL] Default config: packaged defaults unavailable" in result.stdout
    assert "[FAIL] Report output directory:" in result.stdout
    assert "[PASS] Dependency typer:" in result.stdout
    assert "Summary: FAIL" in result.stdout
    assert "2 failed" in result.stdout
    assert "Traceback" not in result.output


def test_doctor_write_failure_cleans_up_probe_and_continues(
    local_only: None,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from tempfile import NamedTemporaryFile

    class UnwritableProbe:
        def write(self, _data: bytes):
            raise PermissionError("simulated write denied")

    @contextmanager
    def failed_probe(**kwargs: object):
        with NamedTemporaryFile(**kwargs):
            yield UnwritableProbe()

    monkeypatch.setattr("sentinellite.doctor.NamedTemporaryFile", failed_probe)

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 1
    assert "[FAIL] Report output directory:" in result.stdout
    assert "simulated write denied" in result.stdout
    assert "[PASS] Dependency typer:" in result.stdout
    assert "1 failed" in result.stdout
    assert list((tmp_path / "reports").iterdir()) == []


@pytest.mark.parametrize("missing", ["psutil", "yaml", "rich", "typer"])
@pytest.mark.parametrize("error_type", [ImportError, OSError])
def test_doctor_reports_each_failed_dependency_and_finishes_checks(
    local_only: None,
    monkeypatch: pytest.MonkeyPatch,
    missing: str,
    error_type: type[Exception],
) -> None:
    from importlib import import_module

    checked = []

    def import_dependency(name: str):
        checked.append(name)
        if name == missing:
            raise error_type(f"cannot import {name}")
        return import_module(name)

    monkeypatch.setattr("sentinellite.doctor.import_module", import_dependency)

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 1
    assert set(checked) == {"psutil", "yaml", "rich", "typer"}
    display_name = "PyYAML" if missing == "yaml" else missing
    assert f"[FAIL] Dependency {display_name}: cannot import {missing}" in result.stdout
    assert "Summary: FAIL" in result.stdout
    assert "1 failed" in result.stdout
    assert "Traceback" not in result.output
