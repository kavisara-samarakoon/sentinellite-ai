import json
from pathlib import Path

import pytest

from sentinellite.detection.engine import detect_event
from sentinellite.models.security_event import create_security_event
from sentinellite.reporting.json_reporter import (
    AlertReport,
    create_alert_report,
    read_alert_report,
    write_alert_report,
)
from sentinellite.scoring.risk import score_rule_match


def create_sample_scored_alert():
    event = create_security_event(
        source="sshd",
        event_type="ssh_failed_login",
        severity="medium",
        message="Failed SSH login attempt for user admin from 192.168.1.50",
        evidence={"username": "admin", "source_ip": "192.168.1.50"},
    )

    rule_match = detect_event(event)[0]
    return score_rule_match(rule_match)


def test_create_alert_report() -> None:
    scored_alert = create_sample_scored_alert()

    report = create_alert_report([scored_alert])

    assert isinstance(report, AlertReport)
    assert report.report_type == "sentinellite_alert_report"
    assert report.alert_count == 1
    assert len(report.alerts) == 1
    assert report.alerts[0]["rule_id"] == "AUTH-001"


def test_alert_report_to_dict() -> None:
    scored_alert = create_sample_scored_alert()
    report = create_alert_report([scored_alert])

    report_dict = report.to_dict()

    assert isinstance(report_dict, dict)
    assert report_dict["report_type"] == "sentinellite_alert_report"
    assert report_dict["alert_count"] == 1
    assert report_dict["alerts"][0]["event_type"] == "ssh_failed_login"


def test_write_alert_report(tmp_path: Path) -> None:
    scored_alert = create_sample_scored_alert()

    report_path = write_alert_report(
        [scored_alert],
        output_dir=tmp_path,
        filename="test-alert-report.json",
    )

    assert report_path.exists()
    assert report_path.name == "test-alert-report.json"

    with report_path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    assert data["report_type"] == "sentinellite_alert_report"
    assert data["alert_count"] == 1
    assert data["alerts"][0]["rule_id"] == "AUTH-001"


def test_read_alert_report(tmp_path: Path) -> None:
    scored_alert = create_sample_scored_alert()

    report_path = write_alert_report(
        [scored_alert],
        output_dir=tmp_path,
        filename="read-test-report.json",
    )

    data = read_alert_report(report_path)

    assert data["report_type"] == "sentinellite_alert_report"
    assert data["alert_count"] == 1


def test_read_missing_alert_report_raises_error() -> None:
    with pytest.raises(FileNotFoundError):
        read_alert_report("missing-report.json")
