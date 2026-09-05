import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from sentinellite.detection.engine import detect_event
from sentinellite.explanations.evidence import build_alert_evidence_summary
from sentinellite.models.security_event import create_security_event
from sentinellite.reporting.json_reporter import (
    AlertReport,
    create_alert_report,
    read_alert_report,
    write_alert_report,
)
from sentinellite.scoring.risk import ScoredAlert, score_rule_match

LEGACY_REPORT_KEYS = {
    "report_id",
    "report_type",
    "generated_at",
    "alert_count",
    "alerts",
}
EXPLANATION_KEYS = {
    "rule_id",
    "title",
    "summary",
    "why_it_matched",
    "possible_causes",
    "recommended_actions",
    "evidence_summary",
    "confidence",
}


def create_sample_scored_alert() -> ScoredAlert:
    event = create_security_event(
        source="sshd",
        event_type="ssh_failed_login",
        severity="medium",
        message="Failed SSH login attempt for user admin from 192.0.2.50",
        evidence={"username": "admin", "source_ip": "192.0.2.50"},
    )

    rule_match = detect_event(event)[0]
    return score_rule_match(rule_match)


def test_build_alert_evidence_summary_accepts_mapping_without_mutation() -> None:
    alert = {
        "rule_id": "FIM-004",
        "severity": "medium",
        "risk_score": 70,
        "event_type": "file_integrity_baseline_changed",
        "source": "file_integrity_baseline",
        "message": "File changed compared with baseline",
        "evidence": {
            "path": "/selected/config.txt",
            "status": "changed",
            "ignored": "not exported",
        },
        "ignored": "not exported",
    }
    original = deepcopy(alert)

    summary = build_alert_evidence_summary(alert)

    assert type(summary) is dict
    assert summary == {
        "rule_id": "FIM-004",
        "severity": "medium",
        "score": 70,
        "event_type": "file_integrity_baseline_changed",
        "source": "file_integrity_baseline",
        "message": "File changed compared with baseline",
        "path": "/selected/config.txt",
        "status": "changed",
    }
    assert alert == original


def test_create_alert_report_default_preserves_exact_legacy_shape() -> None:
    scored_alert = create_sample_scored_alert()

    report = create_alert_report([scored_alert])
    report_dict = report.to_dict()

    assert isinstance(report, AlertReport)
    assert set(report_dict) == LEGACY_REPORT_KEYS
    assert report_dict == {
        "report_id": report.report_id,
        "report_type": "sentinellite_alert_report",
        "generated_at": report.generated_at,
        "alert_count": 1,
        "alerts": [scored_alert.to_dict()],
    }
    assert "explanation" not in report.alerts[0]


def test_create_alert_report_explicit_false_matches_omitted_behavior() -> None:
    scored_alert = create_sample_scored_alert()
    default_report = create_alert_report([scored_alert])
    explicit_false_report = create_alert_report(
        [scored_alert],
        include_explanations=False,
    )

    assert default_report.report_type == explicit_false_report.report_type
    assert default_report.alert_count == explicit_false_report.alert_count
    assert default_report.alerts == explicit_false_report.alerts
    assert default_report.alerts == [scored_alert.to_dict()]
    assert all("explanation" not in alert for alert in explicit_false_report.alerts)


def test_create_alert_report_with_explanations_adds_nested_explanation() -> None:
    scored_alert = create_sample_scored_alert()
    original_evidence = deepcopy(scored_alert.evidence)

    report = create_alert_report([scored_alert], include_explanations=True)

    alert = report.alerts[0]
    explanation = alert["explanation"]
    assert set(report.to_dict()) == LEGACY_REPORT_KEYS
    assert set(explanation) == EXPLANATION_KEYS
    assert explanation["rule_id"] == scored_alert.rule_id
    assert explanation["confidence"] == "medium"
    assert explanation["evidence_summary"] == {
        "rule_id": scored_alert.rule_id,
        "severity": scored_alert.severity,
        "score": scored_alert.risk_score,
        "event_type": scored_alert.event_type,
        "source": scored_alert.source,
        "message": scored_alert.message,
    }
    assert "username" not in explanation["evidence_summary"]
    assert "source_ip" not in explanation["evidence_summary"]
    assert scored_alert.evidence == original_evidence
    assert "explanation" not in scored_alert.to_dict()


def test_create_alert_report_with_explanations_preserves_order_and_association() -> None:
    first_alert = create_sample_scored_alert()
    second_alert = replace(
        first_alert,
        alert_id="alert-unknown",
        rule_id="CUSTOM-999",
        rule_name="Custom Rule",
    )

    report = create_alert_report(
        (first_alert, second_alert),
        include_explanations=True,
    )

    assert [alert["rule_id"] for alert in report.alerts] == ["AUTH-001", "CUSTOM-999"]
    assert [alert["explanation"]["rule_id"] for alert in report.alerts] == [
        "AUTH-001",
        "CUSTOM-999",
    ]
    assert report.alerts[0]["explanation"]["confidence"] == "medium"
    assert report.alerts[1]["explanation"]["confidence"] == "low"


def test_create_empty_alert_report_keeps_legacy_top_level_shape() -> None:
    report = create_alert_report([], include_explanations=True)
    report_dict = report.to_dict()

    assert set(report_dict) == LEGACY_REPORT_KEYS
    assert report.alert_count == 0
    assert report.alerts == []
    assert "explanations" not in report_dict
    assert "explanation" not in report_dict


def test_unknown_rule_uses_generic_low_confidence_explanation() -> None:
    unknown_alert = replace(
        create_sample_scored_alert(),
        rule_id="CUSTOM-999",
        rule_name="Custom Rule",
    )

    report = create_alert_report([unknown_alert], include_explanations=True)
    explanation = report.alerts[0]["explanation"]

    assert explanation["rule_id"] == "CUSTOM-999"
    assert explanation["title"] == "General Alert Explanation"
    assert explanation["confidence"] == "low"
    assert explanation["evidence_summary"]["rule_id"] == "CUSTOM-999"


def test_explanation_wording_does_not_claim_ai_malware_or_compromise() -> None:
    scored_alert = create_sample_scored_alert()
    report = create_alert_report([scored_alert], include_explanations=True)
    explanation_text = json.dumps(report.alerts[0]["explanation"]).lower()

    for prohibited_wording in (
        "ai detected",
        "ai analysis found",
        "malware detected",
        "confirmed malware",
        "confirmed compromise",
        "is compromised",
    ):
        assert prohibited_wording not in explanation_text


def test_write_alert_report_default_preserves_legacy_output(tmp_path: Path) -> None:
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

    assert set(data) == LEGACY_REPORT_KEYS
    assert data["alerts"] == [scored_alert.to_dict()]
    assert "explanation" not in data["alerts"][0]


def test_write_alert_report_with_explanations_writes_nested_objects(
    tmp_path: Path,
) -> None:
    scored_alert = create_sample_scored_alert()

    report_path = write_alert_report(
        [scored_alert],
        output_dir=tmp_path,
        filename="explained-alert-report.json",
        include_explanations=True,
    )

    data = json.loads(report_path.read_text(encoding="utf-8"))

    assert set(data) == LEGACY_REPORT_KEYS
    assert set(data["alerts"][0]["explanation"]) == EXPLANATION_KEYS
    assert data["alerts"][0]["explanation"]["rule_id"] == scored_alert.rule_id
    assert data["alerts"][0]["explanation"]["evidence_summary"]["score"] == (
        scored_alert.risk_score
    )


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
