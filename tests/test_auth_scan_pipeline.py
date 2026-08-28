from pathlib import Path

import pytest

from sentinellite.collectors.auth_sources import MalformedAuthLogError
from sentinellite.detection.rules import active_rules_from_disabled_ids
from sentinellite.pipeline.auth_scan import AuthScanSummary, run_auth_scan
from sentinellite.reporting.json_reporter import read_alert_report
from sentinellite.reporting.review import load_review_report
from sentinellite.scoring.risk import ScoredAlert

REPORT_KEYS = {
    "report_id",
    "report_type",
    "generated_at",
    "alert_count",
    "alerts",
}


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
    assert all("explanation" not in alert for alert in report_data["alerts"])
    assert "explanations" not in report_data


@pytest.mark.parametrize(
    ("fixture_path", "report_filename"),
    [
        (
            Path("examples/auth_logs/sample_ubuntu_auth.log"),
            "ubuntu-auth-report.json",
        ),
        (
            Path("examples/auth_logs/sample_rhel_secure.log"),
            "rhel-secure-report.json",
        ),
    ],
)
def test_traditional_linux_fixture_report_preserves_review_compatibility(
    fixture_path: Path,
    report_filename: str,
    tmp_path: Path,
) -> None:
    summary, scored_alerts = run_auth_scan(
        fixture_path,
        output_dir=tmp_path,
        report_filename=report_filename,
    )
    report_path = Path(summary.report_path)

    report_data = read_alert_report(report_path)
    reviewed_report = load_review_report(report_path)

    assert summary.auth_events_count == 3
    assert summary.detection_matches_count == 3
    assert summary.scored_alerts_count == 3
    assert [alert.rule_id for alert in scored_alerts] == [
        "AUTH-001",
        "AUTH-002",
        "AUTH-003",
    ]
    assert set(report_data) == REPORT_KEYS
    assert report_data["report_type"] == "sentinellite_alert_report"
    assert report_data["alert_count"] == 3
    assert len(report_data["alerts"]) == 3
    assert reviewed_report.path == report_path
    assert reviewed_report.alert_count == 3
    assert len(reviewed_report.alerts) == 3


def test_auth_scan_report_includes_explanations_when_requested(tmp_path: Path) -> None:
    sample_log = Path("examples/auth_logs/sample_auth.log")

    summary, _ = run_auth_scan(
        sample_log,
        output_dir=tmp_path,
        report_filename="auth-scan-explanations.json",
        include_explanations=True,
    )

    report_data = read_alert_report(summary.report_path)

    assert report_data["alerts"]
    assert all("explanation" in alert for alert in report_data["alerts"])
    assert all(
        alert["explanation"]["rule_id"] == alert["rule_id"]
        for alert in report_data["alerts"]
    )
    assert "explanations" not in report_data


def test_auth_scan_can_disable_failed_login_rule_and_preserve_other_alerts(
    tmp_path: Path,
) -> None:
    sample_log = Path("examples/auth_logs/sample_auth.log")
    rules = active_rules_from_disabled_ids(["AUTH-001"])

    summary, scored_alerts = run_auth_scan(
        sample_log,
        output_dir=tmp_path,
        report_filename="auth-filtered-rules.json",
        rules=rules,
    )

    assert summary.detection_matches_count == 2
    assert summary.scored_alerts_count == 2
    assert [alert.rule_id for alert in scored_alerts] == ["AUTH-002", "AUTH-003"]
    report_data = read_alert_report(summary.report_path)
    assert [alert["rule_id"] for alert in report_data["alerts"]] == [
        "AUTH-002",
        "AUTH-003",
    ]
    assert "explanations" not in report_data


def test_auth_scan_empty_report_has_no_explanation_container(tmp_path: Path) -> None:
    empty_log = tmp_path / "empty-auth.log"
    empty_log.write_text("", encoding="utf-8")

    summary, scored_alerts = run_auth_scan(
        empty_log,
        output_dir=tmp_path,
        report_filename="empty-auth-report.json",
        include_explanations=True,
    )

    report_data = read_alert_report(summary.report_path)
    assert scored_alerts == []
    assert report_data["alerts"] == []
    assert "explanations" not in report_data
    assert "explanation" not in report_data


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


def test_auth_scan_input_failure_does_not_write_report(tmp_path: Path) -> None:
    log_path = tmp_path / "invalid-auth.log"
    log_path.write_bytes(b"\xff\xfe")
    report_dir = tmp_path / "reports"

    with pytest.raises(MalformedAuthLogError):
        run_auth_scan(log_path, output_dir=report_dir)

    assert not report_dir.exists()
