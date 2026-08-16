from pathlib import Path

import pytest

from sentinellite.pipeline.auth_scan import AuthScanSummary, run_auth_scan
from sentinellite.reporting.json_reporter import read_alert_report
from sentinellite.scoring.risk import ScoredAlert


def test_run_auth_scan_with_sample_log(tmp_path: Path) -> None:
    sample_log = Path("examples/auth_logs/sample_auth.log")

    summary, scored_alerts = run_auth_scan(
        sample_log,
        output_dir=tmp_path,
        report_filename="auth-scan-test.json",
    )

    assert isinstance(summary, AuthScanSummary)
    assert summary.auth_events_count == 4
    assert summary.security_events_count == 4
    assert summary.detection_matches_count == 4
    assert summary.scored_alerts_count == 4
    assert summary.report_path.endswith("auth-scan-test.json")

    assert len(scored_alerts) == 4
    assert all(isinstance(alert, ScoredAlert) for alert in scored_alerts)


def test_auth_scan_report_is_written(tmp_path: Path) -> None:
    sample_log = Path("examples/auth_logs/sample_auth.log")

    summary, _ = run_auth_scan(
        sample_log,
        output_dir=tmp_path,
        report_filename="auth-scan-report.json",
    )

    report_path = Path(summary.report_path)

    assert report_path.exists()

    report_data = read_alert_report(report_path)

    assert report_data["report_type"] == "sentinellite_alert_report"
    assert report_data["alert_count"] == 4
    assert report_data["alerts"][0]["rule_id"] == "AUTH-001"


def test_auth_scan_summary_to_dict(tmp_path: Path) -> None:
    sample_log = Path("examples/auth_logs/sample_auth.log")

    summary, _ = run_auth_scan(
        sample_log,
        output_dir=tmp_path,
        report_filename="auth-scan-summary.json",
    )

    summary_dict = summary.to_dict()

    assert summary_dict["auth_events_count"] == 4
    assert summary_dict["scored_alerts_count"] == 4
    assert "report_path" in summary_dict


def test_run_auth_scan_missing_file_raises_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        run_auth_scan(
            "examples/auth_logs/missing.log",
            output_dir=tmp_path,
        )
