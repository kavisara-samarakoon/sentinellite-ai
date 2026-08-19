from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinellite.main import app
from sentinellite.pipeline.file_integrity_scan import FileIntegrityScanSummary
from sentinellite.pipeline.network_scan import NetworkScanSummary
from sentinellite.pipeline.process_scan import ProcessScanSummary

runner = CliRunner()


def test_default_status_describes_implemented_and_planned_modules() -> None:
    result = runner.invoke(app)

    assert result.exit_code == 0
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

    def fake_run_process_scan(output_dir: Path) -> ProcessScanSummary:
        assert output_dir == tmp_path
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


def test_scan_process_command_displays_safe_no_alert_message(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "process-alerts.json"

    monkeypatch.setattr(
        "sentinellite.main.run_process_scan",
        lambda output_dir: ProcessScanSummary(
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


def test_scan_network_command_displays_summary_and_alerts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "network-alerts.json"

    def fake_run_network_scan(output_dir: Path) -> NetworkScanSummary:
        assert output_dir == tmp_path
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


def test_scan_network_command_displays_safe_no_alert_message(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "network-alerts.json"

    monkeypatch.setattr(
        "sentinellite.main.run_network_scan",
        lambda output_dir: NetworkScanSummary(
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


def test_scan_files_command_displays_summary_and_alerts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "file-integrity-alerts.json"
    selected_paths = [Path("/selected/config.txt"), Path("/selected/missing.txt")]

    def fake_run_file_integrity_scan(
        paths: list[Path],
        output_dir: Path,
    ) -> FileIntegrityScanSummary:
        assert paths == selected_paths
        assert output_dir == tmp_path
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


def test_scan_files_command_displays_safe_no_alert_message(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    selected_path = Path("/selected/config.txt")
    report_path = tmp_path / "file-integrity-alerts.json"

    def fake_run_file_integrity_scan(
        paths: list[Path],
        output_dir: Path,
    ) -> FileIntegrityScanSummary:
        assert paths == [selected_path]
        assert output_dir == tmp_path
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
    assert "missing-baseline.json" in result.stdout
