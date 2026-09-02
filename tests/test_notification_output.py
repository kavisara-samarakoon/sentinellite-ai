from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinellite.reporting.notification import (
    MAX_INCLUDED_ALERTS,
    NOTIFICATION_OUTPUT_TYPE,
    NOTIFICATION_SCHEMA_VERSION,
    NotificationAlertSummary,
    NotificationSummary,
    build_notification_summary,
    notification_summary_to_dict,
)
from sentinellite.reporting.review import ReviewedAlert, ReviewedReport, validate_report_data

EXPECTED_TOP_LEVEL_KEYS = {
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
EXPECTED_ALERT_KEYS = {
    "rule_id",
    "category",
    "severity",
    "risk_score",
    "risk_level",
}


def reviewed_alert(
    rule_id: str = "AUTH-001",
    *,
    category: str = "authentication",
    severity: str = "medium",
    risk_score: int = 50,
    risk_level: str = "medium",
    message: str = "Failed SSH login for root from 192.0.2.10",
    has_explanation: bool = False,
) -> ReviewedAlert:
    return ReviewedAlert(
        rule_id=rule_id,
        severity=severity,
        risk_level=risk_level,
        risk_score=risk_score,
        category=category,
        message=message,
        has_explanation=has_explanation,
    )


def reviewed_report(
    alerts: tuple[ReviewedAlert, ...] = (),
    *,
    path: Path = Path("private/reports/alerts-sensitive.json"),
    report_id: str = "sentinellite-report-2026-09-02T10:00:00+00:00",
    generated_at: datetime = datetime(2026, 9, 2, 10, 0, tzinfo=UTC),
) -> ReviewedReport:
    return ReviewedReport(
        path=path,
        report_id=report_id,
        report_type="sentinellite_alert_report",
        generated_at=generated_at,
        alert_count=len(alerts),
        alerts=alerts,
    )


def test_notification_constants_and_dataclasses_are_frozen_and_slotted() -> None:
    assert NOTIFICATION_SCHEMA_VERSION == 1
    assert NOTIFICATION_OUTPUT_TYPE == "sentinellite_notification_summary"
    assert MAX_INCLUDED_ALERTS == 20
    assert NotificationAlertSummary.__slots__
    assert NotificationSummary.__slots__

    summary = build_notification_summary(reviewed_report())
    with pytest.raises(FrozenInstanceError):
        summary.alert_count = 1  # type: ignore[misc]


def test_notification_serializer_uses_exact_schema_keys() -> None:
    data = notification_summary_to_dict(
        build_notification_summary(reviewed_report((reviewed_alert(),)))
    )

    assert set(data) == EXPECTED_TOP_LEVEL_KEYS
    assert data["schema_version"] == NOTIFICATION_SCHEMA_VERSION
    assert data["output_type"] == NOTIFICATION_OUTPUT_TYPE
    assert data["source"] == {
        "report_id": "sentinellite-report-2026-09-02T10:00:00+00:00",
        "generated_at": "2026-09-02T10:00:00+00:00",
    }
    alerts = data["alerts"]
    assert isinstance(alerts, list)
    assert set(alerts[0]) == EXPECTED_ALERT_KEYS


def test_zero_alert_report_produces_empty_summary() -> None:
    summary = build_notification_summary(reviewed_report())

    assert summary.alert_count == 0
    assert summary.included_alert_count == 0
    assert summary.omitted_alert_count == 0
    assert summary.severity_counts == {}
    assert summary.risk_level_counts == {}
    assert summary.alerts == ()


def test_builder_counts_severity_and_risk_levels_deterministically() -> None:
    report = reviewed_report(
        (
            reviewed_alert(severity="low", risk_level="info", risk_score=10),
            reviewed_alert("AUTH-002", severity="medium", risk_level="low", risk_score=30),
            reviewed_alert("AUTH-003", severity="medium", risk_level="medium", risk_score=50),
        )
    )

    summary = build_notification_summary(report)

    assert summary.severity_counts == {"low": 1, "medium": 2}
    assert summary.risk_level_counts == {"info": 1, "low": 1, "medium": 1}


def test_builder_orders_by_descending_stored_risk_score_with_stable_ties() -> None:
    report = reviewed_report(
        (
            reviewed_alert("LOW", risk_score=10),
            reviewed_alert("FIRST-TIE", risk_score=80),
            reviewed_alert("SECOND-TIE", risk_score=80),
            reviewed_alert("MIDDLE", risk_score=40),
        )
    )

    summary = build_notification_summary(report)

    assert [alert.rule_id for alert in summary.alerts] == [
        "FIRST-TIE",
        "SECOND-TIE",
        "MIDDLE",
        "LOW",
    ]
    assert [alert.risk_score for alert in summary.alerts] == [80, 80, 40, 10]


def test_builder_truncates_to_maximum_and_records_omitted_count() -> None:
    alerts = tuple(
        reviewed_alert(f"RULE-{index:03d}", risk_score=index)
        for index in range(MAX_INCLUDED_ALERTS + 7)
    )

    summary = build_notification_summary(reviewed_report(alerts))

    assert summary.alert_count == MAX_INCLUDED_ALERTS + 7
    assert summary.included_alert_count == MAX_INCLUDED_ALERTS
    assert summary.omitted_alert_count == 7
    assert len(summary.alerts) == MAX_INCLUDED_ALERTS
    assert summary.alerts[0].risk_score == MAX_INCLUDED_ALERTS + 6
    assert summary.alerts[-1].risk_score == 7


def test_builder_and_serializer_do_not_mutate_reviewed_report() -> None:
    report = reviewed_report(
        (
            reviewed_alert("LOW", risk_score=10),
            reviewed_alert("HIGH", risk_score=90, has_explanation=True),
        )
    )
    before = deepcopy(report)

    summary = build_notification_summary(report)
    notification_summary_to_dict(summary)

    assert report == before


def test_serialized_output_excludes_report_location_and_private_alert_content() -> None:
    sensitive_values = {
        "private/reports/alerts-sensitive.json",
        "alerts-sensitive.json",
        "root",
        "192.0.2.10",
        "/home/root/private.txt",
        "sudo cat /etc/shadow",
        "suspicious-process",
        "d2d2d2d2-private-hash",
        "stored explanation body",
        "stored explanation recommendation",
    }
    report = validate_report_data(
        {
            "report_id": "sentinellite-report-2026-09-02T10:00:00+00:00",
            "report_type": "sentinellite_alert_report",
            "generated_at": "2026-09-02T10:00:00+00:00",
            "alert_count": 1,
            "alerts": [
                {
                    "rule_id": "AUTH-001",
                    "category": "authentication",
                    "severity": "medium",
                    "risk_score": 50,
                    "risk_level": "medium",
                    "message": (
                        "User root at 192.0.2.10 accessed /home/root/private.txt; "
                        "command=sudo cat /etc/shadow; process=suspicious-process"
                    ),
                    "evidence": {
                        "username": "root",
                        "source_ip": "192.0.2.10",
                        "path": "/home/root/private.txt",
                        "command": "sudo cat /etc/shadow",
                        "process_name": "suspicious-process",
                        "sha256": "d2d2d2d2-private-hash",
                    },
                    "explanation": {
                        "summary": "stored explanation body",
                        "recommended_actions": [
                            "stored explanation recommendation"
                        ],
                        "evidence_summary": {"username": "root"},
                    },
                }
            ],
        },
        Path("private/reports/alerts-sensitive.json"),
    )

    data = notification_summary_to_dict(build_notification_summary(report))
    rendered = repr(data)

    for sensitive_value in sensitive_values:
        assert sensitive_value not in rendered
    assert "message" not in rendered
    assert "evidence" not in rendered
    assert "explanation" not in rendered
    assert "description" not in rendered
    assert "recommendation" not in rendered
    assert "event_id" not in rendered
    assert "alert_id" not in rendered


def test_stored_explanation_presence_does_not_change_notification_output() -> None:
    without_explanation = reviewed_report((reviewed_alert(has_explanation=False),))
    with_explanation = reviewed_report((reviewed_alert(has_explanation=True),))

    assert notification_summary_to_dict(
        build_notification_summary(without_explanation)
    ) == notification_summary_to_dict(build_notification_summary(with_explanation))


def test_builder_uses_stored_risk_score_without_rescoring() -> None:
    report = reviewed_report(
        (
            reviewed_alert(
                "STORED-LOW-SEVERITY-HIGH-SCORE",
                severity="info",
                risk_score=99,
                risk_level="custom-stored-level",
            ),
            reviewed_alert(
                "STORED-HIGH-SEVERITY-LOW-SCORE",
                severity="critical",
                risk_score=1,
                risk_level="another-stored-level",
            ),
        )
    )

    summary = build_notification_summary(report)

    assert [alert.rule_id for alert in summary.alerts] == [
        "STORED-LOW-SEVERITY-HIGH-SCORE",
        "STORED-HIGH-SEVERITY-LOW-SCORE",
    ]
    assert [alert.risk_score for alert in summary.alerts] == [99, 1]
    assert [alert.risk_level for alert in summary.alerts] == [
        "custom-stored-level",
        "another-stored-level",
    ]
