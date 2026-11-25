from dataclasses import replace

import pytest

from sentinellite.detection.engine import detect_event
from sentinellite.explanations.models import ALLOWED_CONFIDENCE_VALUES
from sentinellite.models.security_event import ALLOWED_SEVERITIES, create_security_event
from sentinellite.reporting.json_reporter import create_alert_report
from sentinellite.reporting.schema import (
    ALERT_ALLOWED_KEYS,
    ALERT_OPTIONAL_KEYS,
    ALERT_REPORT_SCHEMA_VERSION,
    ALERT_REPORT_TYPE,
    ALERT_REQUIRED_KEYS,
    ALERT_SCORE_MAX,
    ALERT_SCORE_MIN,
    EXPLANATION_CONFIDENCE_VALUES,
    EXPLANATION_REQUIRED_KEYS,
    LEGACY_ALERT_ALLOWED_KEYS,
    LEGACY_ALERT_REQUIRED_KEYS,
    LEGACY_REPORT_TOP_LEVEL_KEYS,
    RISK_LEVEL_VALUES,
    SCHEMA_V1_REPORT_TOP_LEVEL_KEYS,
    SEVERITY_VALUES,
    ReportContract,
    ReportValidationOutcome,
)
from sentinellite.scoring.risk import clamp_score, get_risk_level, score_rule_match


def test_schema_v1_top_level_contract_is_exact() -> None:
    assert ALERT_REPORT_SCHEMA_VERSION == 1
    assert ALERT_REPORT_TYPE == "sentinellite_alert_report"
    assert SCHEMA_V1_REPORT_TOP_LEVEL_KEYS == {
        "schema_version",
        "report_id",
        "report_type",
        "generated_at",
        "alert_count",
        "alerts",
    }


def test_legacy_top_level_contract_is_exact() -> None:
    assert LEGACY_REPORT_TOP_LEVEL_KEYS == {
        "report_id",
        "report_type",
        "generated_at",
        "alert_count",
        "alerts",
    }
    assert "schema_version" not in LEGACY_REPORT_TOP_LEVEL_KEYS


def test_alert_contract_matches_verified_generated_shape() -> None:
    assert ALERT_REQUIRED_KEYS == {
        "alert_id",
        "rule_id",
        "rule_name",
        "category",
        "severity",
        "base_score",
        "risk_score",
        "risk_level",
        "event_id",
        "event_type",
        "source",
        "message",
        "description",
        "recommendation",
        "evidence",
    }
    assert ALERT_OPTIONAL_KEYS == {"explanation"}
    assert ALERT_ALLOWED_KEYS == ALERT_REQUIRED_KEYS | ALERT_OPTIONAL_KEYS


def test_legacy_generated_alert_contract_matches_verified_history() -> None:
    assert LEGACY_ALERT_REQUIRED_KEYS == {
        "alert_id",
        "rule_id",
        "rule_name",
        "category",
        "severity",
        "base_score",
        "risk_score",
        "risk_level",
        "event_id",
        "event_type",
        "source",
        "message",
        "description",
        "recommendation",
        "evidence",
    }
    assert LEGACY_ALERT_ALLOWED_KEYS == LEGACY_ALERT_REQUIRED_KEYS | {"explanation"}
    assert LEGACY_ALERT_REQUIRED_KEYS == ALERT_REQUIRED_KEYS
    assert LEGACY_ALERT_ALLOWED_KEYS == ALERT_ALLOWED_KEYS


def test_explanation_contract_is_exact() -> None:
    assert EXPLANATION_REQUIRED_KEYS == {
        "rule_id",
        "title",
        "summary",
        "why_it_matched",
        "possible_causes",
        "recommended_actions",
        "evidence_summary",
        "confidence",
    }


def test_schema_enums_and_score_bounds_are_explicit() -> None:
    expected_levels = {"info", "low", "medium", "high", "critical"}

    assert SEVERITY_VALUES == expected_levels
    assert SEVERITY_VALUES == ALLOWED_SEVERITIES
    assert RISK_LEVEL_VALUES == expected_levels
    assert all(get_risk_level(score) in RISK_LEVEL_VALUES for score in range(101))
    custom_thresholds = {"low": 10, "medium": 20, "high": 40, "critical": 90}
    assert get_risk_level(50, custom_thresholds) in RISK_LEVEL_VALUES
    assert EXPLANATION_CONFIDENCE_VALUES == {"low", "medium", "high"}
    assert EXPLANATION_CONFIDENCE_VALUES == ALLOWED_CONFIDENCE_VALUES
    assert ALERT_SCORE_MIN == 0
    assert ALERT_SCORE_MAX == 100
    assert clamp_score(-1) == ALERT_SCORE_MIN
    assert clamp_score(101) == ALERT_SCORE_MAX


@pytest.mark.parametrize("include_explanations", [False, True])
@pytest.mark.parametrize("rule_id", ["AUTH-001", "CUSTOM-999"])
def test_contract_matches_generated_report(
    include_explanations: bool,
    rule_id: str,
) -> None:
    event = create_security_event(
        source="sshd",
        event_type="ssh_failed_login",
        severity="medium",
        message="Synthetic failed SSH login attempt",
        host_id="synthetic-schema-test",
        evidence={"username": "demo-user"},
    )
    scored_alert = replace(score_rule_match(detect_event(event)[0]), rule_id=rule_id)

    report = create_alert_report(
        [scored_alert],
        include_explanations=include_explanations,
    ).to_dict()

    assert set(report) == SCHEMA_V1_REPORT_TOP_LEVEL_KEYS
    assert type(report["schema_version"]) is int
    assert report["schema_version"] == ALERT_REPORT_SCHEMA_VERSION
    assert report["report_type"] == ALERT_REPORT_TYPE
    assert report["alert_count"] == len(report["alerts"]) == 1
    alert = report["alerts"][0]
    if include_explanations:
        assert set(alert) == ALERT_ALLOWED_KEYS
        assert set(alert["explanation"]) == EXPLANATION_REQUIRED_KEYS
        assert alert["explanation"]["rule_id"] == alert["rule_id"] == rule_id
        assert alert["explanation"]["confidence"] in EXPLANATION_CONFIDENCE_VALUES
    else:
        assert set(alert) == ALERT_REQUIRED_KEYS
    assert {key: alert[key] for key in ALERT_REQUIRED_KEYS} == scored_alert.to_dict()


@pytest.mark.parametrize("include_explanations", [False, True])
def test_contract_matches_generated_empty_report(include_explanations: bool) -> None:
    report = create_alert_report([], include_explanations=include_explanations).to_dict()

    assert set(report) == SCHEMA_V1_REPORT_TOP_LEVEL_KEYS
    assert type(report["schema_version"]) is int
    assert report["schema_version"] == ALERT_REPORT_SCHEMA_VERSION
    assert report["report_type"] == ALERT_REPORT_TYPE
    assert report["alert_count"] == 0
    assert report["alerts"] == []


def test_report_contract_identifiers_are_distinct() -> None:
    assert ReportContract.SCHEMA_V1 == "schema-v1"
    assert ReportContract.LEGACY_UNVERSIONED == "legacy-unversioned"


def test_validation_outcomes_are_explicit() -> None:
    assert {outcome.value for outcome in ReportValidationOutcome} == {
        "valid-schema-v1",
        "valid-legacy-unversioned",
        "malformed",
        "incompatible",
        "unsupported-schema",
    }
