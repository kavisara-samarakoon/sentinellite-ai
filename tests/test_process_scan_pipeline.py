from pathlib import Path

import pytest

from sentinellite.collectors.process import ProcessInfo
from sentinellite.pipeline.process_scan import ProcessScanSummary, run_process_scan
from sentinellite.reporting.json_reporter import read_alert_report


def create_process(
    *,
    pid: int,
    name: str,
    exe: str,
    cmdline: list[str],
) -> ProcessInfo:
    return ProcessInfo(
        pid=pid,
        name=name,
        username="analyst",
        exe=exe,
        cmdline=cmdline,
        cpu_percent=1.0,
        memory_percent=1.0,
        status="running",
    )


def test_process_scan_writes_expected_suspicious_process_alert(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    processes = [
        create_process(
            pid=100,
            name="systemd",
            exe="/usr/lib/systemd/systemd",
            cmdline=["/usr/lib/systemd/systemd", "--system"],
        ),
        create_process(
            pid=200,
            name="worker",
            exe="/tmp/worker",
            cmdline=["/tmp/worker"],
        ),
    ]
    monkeypatch.setattr(
        "sentinellite.pipeline.process_scan.collect_processes",
        lambda: processes,
    )

    summary = run_process_scan(output_dir=tmp_path)

    assert isinstance(summary, ProcessScanSummary)
    assert summary.processes_count == 2
    assert summary.security_events_count == 2
    assert summary.detection_matches_count == 1
    assert summary.scored_alerts_count == 1

    report_path = Path(summary.report_path)
    assert report_path.exists()

    report_data = read_alert_report(report_path)
    assert report_data["alert_count"] == 1
    assert report_data["alerts"][0]["rule_id"] == "PROC-001"
    assert "explanation" not in report_data["alerts"][0]
    assert "explanations" not in report_data

    summary_data = summary.to_dict()
    assert summary_data["processes_count"] == 2
    assert summary_data["report_path"] == str(report_path)


def test_process_scan_includes_explanation_when_requested(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "sentinellite.pipeline.process_scan.collect_processes",
        lambda: [
            create_process(
                pid=200,
                name="worker",
                exe="/tmp/worker",
                cmdline=["/tmp/worker"],
            )
        ],
    )

    summary = run_process_scan(output_dir=tmp_path, include_explanations=True)
    report_data = read_alert_report(summary.report_path)

    alert = report_data["alerts"][0]
    assert alert["rule_id"] == "PROC-001"
    assert alert["explanation"]["rule_id"] == "PROC-001"
    assert "explanations" not in report_data


def test_process_scan_writes_empty_report_for_normal_process(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    processes = [
        create_process(
            pid=100,
            name="systemd",
            exe="/usr/lib/systemd/systemd",
            cmdline=["/usr/lib/systemd/systemd", "--system"],
        )
    ]
    monkeypatch.setattr(
        "sentinellite.pipeline.process_scan.collect_processes",
        lambda: processes,
    )

    summary = run_process_scan(output_dir=tmp_path, include_explanations=True)

    assert summary.processes_count == 1
    assert summary.security_events_count == 1
    assert summary.detection_matches_count == 0
    assert summary.scored_alerts_count == 0

    report_path = Path(summary.report_path)
    assert report_path.exists()

    report_data = read_alert_report(report_path)
    assert report_data["alert_count"] == 0
    assert report_data["alerts"] == []
    assert "explanations" not in report_data
    assert "explanation" not in report_data
