import pytest

from sentinellite.detection.engine import detect_event
from sentinellite.detection.rules import (
    DEFAULT_RULES,
    FILE_INTEGRITY_BASELINE_EVENT_TYPE,
)
from sentinellite.models.security_event import SecurityEvent, create_security_event


def create_baseline_comparison_event(
    status: object = "unchanged",
    *,
    event_type: str = FILE_INTEGRITY_BASELINE_EVENT_TYPE,
) -> SecurityEvent:
    return create_security_event(
        source="file_integrity_baseline",
        event_type=event_type,
        severity="info",
        message="File integrity baseline comparison for rule testing",
        evidence={
            "path": "README.md",
            "status": status,
            "changed_fields": [],
            "baseline_entry": None,
            "current_entry": {},
        },
    )


def test_fim_004_matches_changed_status() -> None:
    matches = detect_event(create_baseline_comparison_event("changed"))

    assert [match.rule_id for match in matches] == ["FIM-004"]
    assert matches[0].rule_name == "File Changed Compared With Baseline"
    assert matches[0].category == "file_integrity_baseline"
    assert matches[0].severity == "medium"
    assert matches[0].base_score == 70


def test_fim_005_matches_missing_now_status() -> None:
    matches = detect_event(create_baseline_comparison_event("missing_now"))

    assert [match.rule_id for match in matches] == ["FIM-005"]
    assert matches[0].rule_name == "File Missing Compared With Baseline"
    assert matches[0].category == "file_integrity_baseline"
    assert matches[0].severity == "medium"
    assert matches[0].base_score == 65


def test_fim_006_matches_appeared_now_status() -> None:
    matches = detect_event(create_baseline_comparison_event("appeared_now"))

    assert [match.rule_id for match in matches] == ["FIM-006"]
    assert matches[0].rule_name == "File Appeared Compared With Baseline"
    assert matches[0].category == "file_integrity_baseline"
    assert matches[0].severity == "low"
    assert matches[0].base_score == 35


def test_fim_007_matches_type_changed_status() -> None:
    matches = detect_event(create_baseline_comparison_event("type_changed"))

    assert [match.rule_id for match in matches] == ["FIM-007"]
    assert matches[0].rule_name == "File Type Changed Compared With Baseline"
    assert matches[0].category == "file_integrity_baseline"
    assert matches[0].severity == "medium"
    assert matches[0].base_score == 60


def test_fim_008_matches_current_error_status() -> None:
    matches = detect_event(create_baseline_comparison_event("current_error"))

    assert [match.rule_id for match in matches] == ["FIM-008"]
    assert matches[0].rule_name == "File Integrity Baseline Comparison Error"
    assert matches[0].category == "file_integrity_baseline"
    assert matches[0].severity == "low"
    assert matches[0].base_score == 35


@pytest.mark.parametrize("status", ["unchanged", "not_in_baseline"])
def test_non_alerting_baseline_statuses_do_not_match(status: str) -> None:
    assert detect_event(create_baseline_comparison_event(status)) == []


def test_wrong_event_type_does_not_match_baseline_rules() -> None:
    event = create_baseline_comparison_event(
        "changed",
        event_type="file_integrity_observation",
    )

    assert detect_event(event) == []


@pytest.mark.parametrize("status", [None, "", 0, False, [], {}])
def test_missing_or_invalid_status_evidence_is_handled_safely(status: object) -> None:
    assert detect_event(create_baseline_comparison_event(status)) == []


def test_missing_status_evidence_is_handled_safely() -> None:
    event = create_security_event(
        source="file_integrity_baseline",
        event_type=FILE_INTEGRITY_BASELINE_EVENT_TYPE,
        severity="info",
        message="Incomplete baseline comparison event",
        evidence={"path": "README.md"},
    )

    assert detect_event(event) == []


def test_baseline_rules_are_registered_after_existing_rule_families() -> None:
    rule_ids = [rule.rule_id for rule in DEFAULT_RULES]

    assert rule_ids == [
        "AUTH-001",
        "AUTH-002",
        "AUTH-003",
        "PROC-001",
        "PROC-002",
        "PROC-003",
        "NET-001",
        "NET-002",
        "NET-003",
        "FIM-001",
        "FIM-002",
        "FIM-003",
        "FIM-004",
        "FIM-005",
        "FIM-006",
        "FIM-007",
        "FIM-008",
    ]
