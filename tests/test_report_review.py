import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path

import pytest

from sentinellite.reporting.json_reporter import write_alert_report
from sentinellite.reporting.review import (
    MAX_REPORT_SIZE_BYTES,
    IncompatibleReportError,
    MalformedReportError,
    ReportReviewError,
    ReviewedAlert,
    build_report_summary,
    discover_report_paths,
    list_report_entries,
    load_review_report,
    validate_report_data,
)
from sentinellite.scoring.risk import ScoredAlert


def sample_alert(**overrides: object) -> dict[str, object]:
    alert: dict[str, object] = {
        "rule_id": "AUTH-001",
        "severity": "medium",
        "risk_level": "medium",
        "risk_score": 50,
        "category": "authentication",
        "message": "Failed SSH login attempt",
    }
    alert.update(overrides)
    return alert


def sample_report(
    *,
    generated_at: str = "2026-08-28T10:00:00+00:00",
    alerts: list[object] | None = None,
) -> dict[str, object]:
    report_alerts = [sample_alert()] if alerts is None else alerts
    return {
        "report_id": f"sentinellite-report-{generated_at}",
        "report_type": "sentinellite_alert_report",
        "generated_at": generated_at,
        "alert_count": len(report_alerts),
        "alerts": report_alerts,
    }


def write_json(path: Path, data: object) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_validate_valid_report_with_alerts() -> None:
    path = Path("reports/valid.json")

    report = validate_report_data(sample_report(), path)

    assert report.path == path
    assert report.report_type == "sentinellite_alert_report"
    assert report.generated_at == datetime.fromisoformat("2026-08-28T10:00:00+00:00")
    assert report.alert_count == 1
    assert report.alerts == (
        ReviewedAlert(
            rule_id="AUTH-001",
            severity="medium",
            risk_level="medium",
            risk_score=50,
            category="authentication",
            message="Failed SSH login attempt",
            has_explanation=False,
        ),
    )


def test_validate_valid_empty_report() -> None:
    report = validate_report_data(sample_report(alerts=[]), Path("empty.json"))

    assert report.alert_count == 0
    assert report.alerts == ()


def test_validate_report_with_nested_explanation() -> None:
    data = sample_report(alerts=[sample_alert(explanation={"summary": "Review it."})])

    report = validate_report_data(data, Path("explained.json"))

    assert report.alerts[0].has_explanation is True


def test_non_object_explanation_is_not_counted_as_an_explanation() -> None:
    data = sample_report(alerts=[sample_alert(explanation="not an object")])

    report = validate_report_data(data, Path("non-object-explanation.json"))

    assert report.alerts[0].has_explanation is False


def test_unknown_fields_are_tolerated_without_mutating_input() -> None:
    data = sample_report(
        alerts=[sample_alert(extra_alert_field={"kept": True})],
    )
    data["extra_report_field"] = ["future", "data"]
    original = deepcopy(data)

    report = validate_report_data(data, Path("future-fields.json"))

    assert report.alert_count == 1
    assert data == original


def test_discover_report_paths_is_non_recursive_and_sorted(tmp_path: Path) -> None:
    write_json(tmp_path / "z-report.json", sample_report())
    write_json(tmp_path / "a-report.json", sample_report())
    nested_dir = tmp_path / "nested"
    nested_dir.mkdir()
    write_json(nested_dir / "nested-report.json", sample_report())

    paths = discover_report_paths(tmp_path)

    assert paths == [tmp_path / "a-report.json", tmp_path / "z-report.json"]


def test_discover_report_paths_only_includes_lowercase_json_files(
    tmp_path: Path,
) -> None:
    included = write_json(tmp_path / "included.json", sample_report())
    write_json(tmp_path / "excluded.JSON", sample_report())
    (tmp_path / "excluded.json.txt").write_text("{}", encoding="utf-8")
    (tmp_path / "directory.json").mkdir()

    assert discover_report_paths(tmp_path) == [included]


def test_discover_missing_report_directory_fails(tmp_path: Path) -> None:
    missing_dir = tmp_path / "missing"

    with pytest.raises(ReportReviewError, match="Report directory not found"):
        discover_report_paths(missing_dir)


def test_discover_non_directory_report_path_fails(tmp_path: Path) -> None:
    report_file = write_json(tmp_path / "report.json", sample_report())

    with pytest.raises(ReportReviewError, match="not a directory"):
        discover_report_paths(report_file)


def test_load_missing_report_file_fails(tmp_path: Path) -> None:
    missing_file = tmp_path / "missing.json"

    with pytest.raises(ReportReviewError, match="Report file not found"):
        load_review_report(missing_file)


def test_load_non_file_report_path_fails(tmp_path: Path) -> None:
    with pytest.raises(ReportReviewError, match="not a regular file"):
        load_review_report(tmp_path)


def test_load_malformed_json_fails_with_location(tmp_path: Path) -> None:
    path = tmp_path / "malformed.json"
    path.write_text('{"alerts": [}', encoding="utf-8")

    with pytest.raises(MalformedReportError, match=r"line 1, column \d+"):
        load_review_report(path)


def test_load_invalid_utf8_fails_cleanly(tmp_path: Path) -> None:
    path = tmp_path / "invalid-utf8.json"
    path.write_bytes(b"\xff\xfe")

    with pytest.raises(MalformedReportError, match="not valid UTF-8"):
        load_review_report(path)


@pytest.mark.parametrize("data", [[], "report", 7, None])
def test_top_level_non_object_fails(data: object) -> None:
    with pytest.raises(IncompatibleReportError, match="top level"):
        validate_report_data(data, Path("invalid.json"))


@pytest.mark.parametrize(
    "field_name",
    ["report_id", "report_type", "generated_at", "alert_count", "alerts"],
)
def test_missing_required_report_fields_fail(field_name: str) -> None:
    data = sample_report()
    del data[field_name]

    with pytest.raises(IncompatibleReportError, match=field_name):
        validate_report_data(data, Path("missing-field.json"))


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("report_id", 7),
        ("generated_at", 7),
        ("alert_count", "1"),
        ("alerts", {}),
    ],
)
def test_wrongly_typed_report_fields_fail(field_name: str, value: object) -> None:
    data = sample_report()
    data[field_name] = value

    with pytest.raises(IncompatibleReportError, match=field_name):
        validate_report_data(data, Path("wrong-type.json"))


@pytest.mark.parametrize(
    "field_name",
    ["rule_id", "severity", "risk_level", "risk_score", "category", "message"],
)
def test_missing_required_alert_fields_fail(field_name: str) -> None:
    alert = sample_alert()
    del alert[field_name]
    data = sample_report(alerts=[alert])

    with pytest.raises(IncompatibleReportError, match=field_name):
        validate_report_data(data, Path("missing-alert-field.json"))


@pytest.mark.parametrize(
    "field_name",
    ["rule_id", "severity", "risk_level", "category", "message"],
)
def test_wrongly_typed_alert_string_fields_fail(field_name: str) -> None:
    data = sample_report(alerts=[sample_alert(**{field_name: 7})])

    with pytest.raises(IncompatibleReportError, match=field_name):
        validate_report_data(data, Path("wrong-alert-type.json"))


def test_unsupported_report_type_fails() -> None:
    data = sample_report()
    data["report_type"] = "file_integrity_baseline"

    with pytest.raises(IncompatibleReportError, match="supported report_type"):
        validate_report_data(data, Path("unsupported.json"))


@pytest.mark.parametrize("generated_at", ["not-a-date", "2026-08-28T10:00:00"])
def test_invalid_or_timezone_naive_generated_at_fails(generated_at: str) -> None:
    with pytest.raises(IncompatibleReportError, match="generated_at"):
        validate_report_data(
            sample_report(generated_at=generated_at),
            Path("invalid-date.json"),
        )


def test_negative_alert_count_fails() -> None:
    data = sample_report(alerts=[])
    data["alert_count"] = -1

    with pytest.raises(IncompatibleReportError, match="non-negative integer"):
        validate_report_data(data, Path("negative-count.json"))


def test_boolean_alert_count_fails() -> None:
    data = sample_report(alerts=[sample_alert()])
    data["alert_count"] = True

    with pytest.raises(IncompatibleReportError, match="non-negative integer"):
        validate_report_data(data, Path("boolean-count.json"))


def test_alert_count_length_mismatch_fails() -> None:
    data = sample_report(alerts=[])
    data["alert_count"] = 1

    with pytest.raises(IncompatibleReportError, match="does not match"):
        validate_report_data(data, Path("count-mismatch.json"))


def test_non_object_alert_fails() -> None:
    data = sample_report(alerts=["not an object"])

    with pytest.raises(IncompatibleReportError, match="index 0"):
        validate_report_data(data, Path("non-object-alert.json"))


def test_boolean_risk_score_fails() -> None:
    data = sample_report(alerts=[sample_alert(risk_score=True)])

    with pytest.raises(IncompatibleReportError, match="risk_score"):
        validate_report_data(data, Path("boolean-risk-score.json"))


def test_oversized_report_fails_before_json_parsing(tmp_path: Path) -> None:
    path = tmp_path / "oversized.json"
    path.write_bytes(b" " * (MAX_REPORT_SIZE_BYTES + 1))

    with pytest.raises(ReportReviewError, match="size limit") as captured:
        load_review_report(path)

    assert not isinstance(captured.value, MalformedReportError)


def test_list_report_entries_keeps_valid_and_invalid_reports(tmp_path: Path) -> None:
    valid_path = write_json(tmp_path / "valid.json", sample_report())
    invalid_path = tmp_path / "invalid.json"
    invalid_path.write_text("not-json", encoding="utf-8")

    entries = list_report_entries(tmp_path)

    assert [entry.path for entry in entries] == [valid_path, invalid_path]
    assert entries[0].status == "valid"
    assert entries[0].error is None
    assert entries[1].status == "invalid"
    assert entries[1].generated_at is None
    assert entries[1].alert_count is None
    assert entries[1].report_type is None
    assert "Malformed JSON" in str(entries[1].error)


def test_list_report_entries_sorts_valid_newest_first_then_invalid(
    tmp_path: Path,
) -> None:
    write_json(
        tmp_path / "b-newest.json",
        sample_report(generated_at="2026-08-28T12:00:00+00:00"),
    )
    write_json(
        tmp_path / "a-newest.json",
        sample_report(generated_at="2026-08-28T12:00:00+00:00"),
    )
    write_json(
        tmp_path / "older.json",
        sample_report(generated_at="2026-08-27T12:00:00+00:00"),
    )
    (tmp_path / "z-invalid.json").write_text("invalid", encoding="utf-8")
    (tmp_path / "a-invalid.json").write_text("invalid", encoding="utf-8")

    entries = list_report_entries(tmp_path)

    assert [entry.path.name for entry in entries] == [
        "a-newest.json",
        "b-newest.json",
        "older.json",
        "a-invalid.json",
        "z-invalid.json",
    ]


def test_build_report_summary_counts_safe_fields_only() -> None:
    data = sample_report(
        alerts=[
            sample_alert(explanation={"summary": "Stored explanation"}),
            sample_alert(
                rule_id="NET-001",
                severity="high",
                risk_level="high",
                risk_score=80,
                category="network",
                message="Network observation",
                evidence={"sensitive": "not exported"},
            ),
            sample_alert(
                rule_id="AUTH-001",
                severity="medium",
                risk_level="medium",
                risk_score=50,
                category="authentication",
                message="Another authentication observation",
            ),
        ]
    )
    report = validate_report_data(data, Path("summary.json"))

    summary = build_report_summary(report)

    assert summary == {
        "path": "summary.json",
        "report_id": "sentinellite-report-2026-08-28T10:00:00+00:00",
        "report_type": "sentinellite_alert_report",
        "generated_at": "2026-08-28T10:00:00+00:00",
        "alert_count": 3,
        "explanation_count": 1,
        "rule_ids": ["AUTH-001", "NET-001"],
        "severity_counts": {"high": 1, "medium": 2},
        "risk_level_counts": {"high": 1, "medium": 2},
    }
    assert "evidence" not in summary
    assert "explanations" not in summary


def test_existing_json_writer_output_is_accepted(tmp_path: Path) -> None:
    alert = ScoredAlert(
        alert_id="alert-1",
        rule_id="AUTH-001",
        rule_name="Failed SSH Login",
        category="authentication",
        severity="medium",
        base_score=50,
        risk_score=50,
        risk_level="medium",
        event_id="event-1",
        event_type="ssh_failed_login",
        source="sshd",
        message="Failed SSH login attempt",
        description="A failed SSH login attempt was detected.",
        recommendation="Review the authentication context.",
        evidence={"username": "admin"},
    )
    path = write_alert_report(
        [alert],
        output_dir=tmp_path,
        filename="writer-output.json",
    )

    report = load_review_report(path)

    assert report.path == path
    assert report.alert_count == 1
    assert report.alerts[0].rule_id == "AUTH-001"
    assert report.alerts[0].has_explanation is False
