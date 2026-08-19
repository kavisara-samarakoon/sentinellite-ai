import pytest

from sentinellite.detection.engine import detect_event
from sentinellite.detection.rules import DEFAULT_RULES
from sentinellite.models.security_event import SecurityEvent, create_security_event


def create_file_integrity_event(**evidence_overrides) -> SecurityEvent:
    evidence = {
        "path": "/selected/config.txt",
        "exists": True,
        "is_file": True,
        "size_bytes": 128,
        "modified_time_epoch": 1_725_000_000.5,
        "sha256": "a" * 64,
        "error": None,
    }
    evidence.update(evidence_overrides)

    return create_security_event(
        source="file_integrity",
        event_type="file_integrity_observation",
        severity="info",
        message="Observed file integrity state for rule testing",
        evidence=evidence,
    )


def test_fim_001_matches_missing_monitored_file() -> None:
    event = create_file_integrity_event(
        exists=False,
        is_file=False,
        size_bytes=None,
        modified_time_epoch=None,
        sha256=None,
    )

    matches = detect_event(event)

    assert [match.rule_id for match in matches] == ["FIM-001"]
    assert matches[0].rule_name == "Missing Monitored File"
    assert matches[0].category == "file_integrity"
    assert matches[0].severity == "medium"
    assert matches[0].base_score == 60


def test_fim_001_does_not_match_existing_normal_file() -> None:
    event = create_file_integrity_event()

    assert all(match.rule_id != "FIM-001" for match in detect_event(event))


def test_fim_002_matches_error_record() -> None:
    event = create_file_integrity_event(
        sha256=None,
        error="Unable to read file: permission denied",
    )

    matches = detect_event(event)

    assert [match.rule_id for match in matches] == ["FIM-002"]
    assert matches[0].rule_name == "File Integrity Check Error"
    assert matches[0].category == "file_integrity"
    assert matches[0].severity == "low"
    assert matches[0].base_score == 35


@pytest.mark.parametrize("error", [None, "", "   "])
def test_fim_002_does_not_match_empty_error(error: str | None) -> None:
    event = create_file_integrity_event(error=error)

    assert all(match.rule_id != "FIM-002" for match in detect_event(event))


def test_fim_003_matches_directory_record() -> None:
    event = create_file_integrity_event(
        path="/selected/directory",
        is_file=False,
        size_bytes=None,
        modified_time_epoch=None,
        sha256=None,
    )

    matches = detect_event(event)

    assert [match.rule_id for match in matches] == ["FIM-003"]
    assert matches[0].rule_name == "Directory Supplied for File Integrity Check"
    assert matches[0].category == "file_integrity"
    assert matches[0].severity == "info"
    assert matches[0].base_score == 20


def test_fim_003_does_not_match_normal_file() -> None:
    event = create_file_integrity_event()

    assert all(match.rule_id != "FIM-003" for match in detect_event(event))


def test_missing_record_with_error_matches_both_applicable_rules() -> None:
    event = create_file_integrity_event(
        exists=False,
        is_file=False,
        size_bytes=None,
        modified_time_epoch=None,
        sha256=None,
        error="Path does not exist: /selected/config.txt",
    )

    matches = detect_event(event)

    assert [match.rule_id for match in matches] == ["FIM-001", "FIM-002"]


@pytest.mark.parametrize(
    "evidence",
    [
        {},
        {"exists": None, "is_file": None, "error": None},
        {"exists": "false", "is_file": "false", "error": 123},
        {"exists": 0, "is_file": 0, "error": []},
    ],
)
def test_file_integrity_rules_handle_missing_or_invalid_evidence_safely(evidence) -> None:
    event = create_security_event(
        source="file_integrity",
        event_type="file_integrity_observation",
        severity="info",
        message="Incomplete file integrity observation",
        evidence=evidence,
    )

    assert detect_event(event) == []


def test_file_integrity_rules_are_registered_after_existing_rules() -> None:
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
