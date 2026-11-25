import json
import re
import sys
from contextlib import contextmanager
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
    UnsupportedSchemaError,
    build_report_summary,
    discover_report_paths,
    list_report_entries,
    load_review_report,
    validate_report_data,
)
from sentinellite.reporting.schema import ReportContract, ReportValidationOutcome
from sentinellite.reporting.validation import (
    IncompatibleReportError as CanonicalIncompatibleReportError,
)
from sentinellite.reporting.validation import ReportSchemaError, parse_report_json
from sentinellite.scoring.risk import ScoredAlert

REPORT_FIXTURES = Path(__file__).parent / "fixtures" / "report_schema"


@contextmanager
def incompatible_report(detail: str):
    with pytest.raises(IncompatibleReportError, match="Incompatible report") as captured:
        yield
    assert captured.value.outcome is ReportValidationOutcome.INCOMPATIBLE
    assert isinstance(captured.value.__cause__, CanonicalIncompatibleReportError)
    assert re.search(detail, str(captured.value.__cause__))


def sample_explanation(**overrides: object) -> dict[str, object]:
    explanation = json.loads(
        (REPORT_FIXTURES / "legacy_unversioned_explanation.json").read_text(encoding="utf-8")
    )["alerts"][0]["explanation"]
    explanation.update(overrides)
    return explanation


def sample_alert(**overrides: object) -> dict[str, object]:
    alert = json.loads(
        (REPORT_FIXTURES / "legacy_unversioned_alert.json").read_text(encoding="utf-8")
    )["alerts"][0]
    alert.update(risk_level="medium", message="Failed SSH login attempt")
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
    data = sample_report(
        alerts=[sample_alert(explanation=sample_explanation(summary="Review it."))]
    )

    report = validate_report_data(data, Path("explained.json"))

    assert report.alerts[0].has_explanation is True


def test_non_object_explanation_is_rejected() -> None:
    data = sample_report(alerts=[sample_alert(explanation="not an object")])

    with pytest.raises(IncompatibleReportError):
        validate_report_data(data, Path("non-object-explanation.json"))


def test_unknown_fields_are_rejected_without_mutating_input() -> None:
    data = sample_report(
        alerts=[sample_alert(extra_alert_field={"kept": True})],
    )
    data["extra_report_field"] = ["future", "data"]
    original = deepcopy(data)

    with pytest.raises(IncompatibleReportError):
        validate_report_data(data, Path("future-fields.json"))
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
    with incompatible_report("top level"):
        validate_report_data(data, Path("invalid.json"))


@pytest.mark.parametrize(
    "field_name",
    ["report_id", "report_type", "generated_at", "alert_count", "alerts"],
)
def test_missing_required_report_fields_fail(field_name: str) -> None:
    data = sample_report()
    del data[field_name]

    with incompatible_report(field_name):
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

    with incompatible_report(field_name):
        validate_report_data(data, Path("wrong-type.json"))


@pytest.mark.parametrize(
    "field_name",
    ["rule_id", "severity", "risk_level", "risk_score", "category", "message"],
)
def test_missing_required_alert_fields_fail(field_name: str) -> None:
    alert = sample_alert()
    del alert[field_name]
    data = sample_report(alerts=[alert])

    with incompatible_report(field_name):
        validate_report_data(data, Path("missing-alert-field.json"))


@pytest.mark.parametrize(
    "field_name",
    ["rule_id", "severity", "risk_level", "category", "message"],
)
def test_wrongly_typed_alert_string_fields_fail(field_name: str) -> None:
    data = sample_report(alerts=[sample_alert(**{field_name: 7})])

    with incompatible_report(field_name):
        validate_report_data(data, Path("wrong-alert-type.json"))


def test_unsupported_report_type_fails() -> None:
    data = sample_report()
    data["report_type"] = "file_integrity_baseline"

    with incompatible_report("report_type"):
        validate_report_data(data, Path("unsupported.json"))


@pytest.mark.parametrize("generated_at", ["not-a-date", "2026-08-28T10:00:00"])
def test_invalid_or_timezone_naive_generated_at_fails(generated_at: str) -> None:
    with incompatible_report("generated_at"):
        validate_report_data(
            sample_report(generated_at=generated_at),
            Path("invalid-date.json"),
        )


def test_negative_alert_count_fails() -> None:
    data = sample_report(alerts=[])
    data["alert_count"] = -1

    with incompatible_report("non-negative integer"):
        validate_report_data(data, Path("negative-count.json"))


def test_boolean_alert_count_fails() -> None:
    data = sample_report(alerts=[sample_alert()])
    data["alert_count"] = True

    with incompatible_report("non-negative integer"):
        validate_report_data(data, Path("boolean-count.json"))


def test_alert_count_length_mismatch_fails() -> None:
    data = sample_report(alerts=[])
    data["alert_count"] = 1

    with incompatible_report("does not match"):
        validate_report_data(data, Path("count-mismatch.json"))


def test_non_object_alert_fails() -> None:
    data = sample_report(alerts=["not an object"])

    with incompatible_report(r"alerts\[0\]"):
        validate_report_data(data, Path("non-object-alert.json"))


def test_boolean_risk_score_fails() -> None:
    data = sample_report(alerts=[sample_alert(risk_score=True)])

    with incompatible_report("risk_score"):
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
            sample_alert(explanation=sample_explanation(summary="Stored explanation")),
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
        "contract": "legacy-unversioned",
        "schema_version": None,
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


FIXTURE_OUTCOMES = [
    ("schema_v1_alert.json", ReportValidationOutcome.VALID_SCHEMA_V1),
    ("schema_v1_explanation.json", ReportValidationOutcome.VALID_SCHEMA_V1),
    ("schema_v1_empty.json", ReportValidationOutcome.VALID_SCHEMA_V1),
    ("legacy_unversioned_alert.json", ReportValidationOutcome.VALID_LEGACY_UNVERSIONED),
    ("legacy_unversioned_explanation.json", ReportValidationOutcome.VALID_LEGACY_UNVERSIONED),
    ("unsupported_schema_version.json", ReportValidationOutcome.UNSUPPORTED_SCHEMA),
    ("incompatible_missing_alert_field.json", ReportValidationOutcome.INCOMPATIBLE),
    ("incompatible_alert_count.json", ReportValidationOutcome.INCOMPATIBLE),
    ("incompatible_boolean_risk_score.json", ReportValidationOutcome.INCOMPATIBLE),
    ("incompatible_report_type.json", ReportValidationOutcome.INCOMPATIBLE),
    ("incompatible_incomplete_explanation.json", ReportValidationOutcome.INCOMPATIBLE),
    ("incompatible_explanation_rule_id.json", ReportValidationOutcome.INCOMPATIBLE),
    ("malformed_json_syntax.json", ReportValidationOutcome.MALFORMED),
    ("malformed_duplicate_top_level_key.json", ReportValidationOutcome.MALFORMED),
    ("malformed_duplicate_nested_key.json", ReportValidationOutcome.MALFORMED),
    ("malformed_non_finite_numbers.json", ReportValidationOutcome.MALFORMED),
]


@pytest.mark.parametrize(("filename", "outcome"), FIXTURE_OUTCOMES)
def test_review_classifies_all_approved_fixtures(
    filename: str,
    outcome: ReportValidationOutcome,
    tmp_path: Path,
) -> None:
    path = tmp_path / filename
    original = (REPORT_FIXTURES / filename).read_bytes()
    path.write_bytes(original)
    if outcome in (
        ReportValidationOutcome.VALID_SCHEMA_V1,
        ReportValidationOutcome.VALID_LEGACY_UNVERSIONED,
    ):
        report = load_review_report(path)
        assert report.outcome is outcome
        assert report.contract is (
            ReportContract.SCHEMA_V1
            if outcome is ReportValidationOutcome.VALID_SCHEMA_V1
            else ReportContract.LEGACY_UNVERSIONED
        )
        assert report.schema_version == (1 if report.contract is ReportContract.SCHEMA_V1 else None)
        assert report.alert_count == len(report.alerts)
        if report.alerts:
            assert report.alerts[0].risk_score == 50
            assert report.alerts[0].risk_level == "high"
            assert report.alerts[0].has_explanation == ("explanation" in filename)
    else:
        error_type = {
            ReportValidationOutcome.MALFORMED: MalformedReportError,
            ReportValidationOutcome.INCOMPATIBLE: IncompatibleReportError,
            ReportValidationOutcome.UNSUPPORTED_SCHEMA: UnsupportedSchemaError,
        }[outcome]
        with pytest.raises(error_type) as captured:
            load_review_report(path)
        assert captured.value.outcome is outcome
        if outcome is ReportValidationOutcome.UNSUPPORTED_SCHEMA:
            assert captured.value.schema_version == 2
    assert path.read_bytes() == original


def test_mixed_fixture_listing_retains_all_outcomes_and_no_partial_metadata(tmp_path: Path) -> None:
    for filename, _ in reversed(FIXTURE_OUTCOMES):
        (tmp_path / filename).write_bytes((REPORT_FIXTURES / filename).read_bytes())
    entries = list_report_entries(tmp_path)
    expected = dict(FIXTURE_OUTCOMES)
    valid = [entry for entry in entries if entry.status == "valid"]
    invalid = [entry for entry in entries if entry.status == "invalid"]
    assert len(valid) == 5
    assert len(invalid) == 11
    assert [entry.path.name for entry in valid] == sorted(entry.path.name for entry in valid)
    assert [entry.path.name for entry in invalid] == sorted(entry.path.name for entry in invalid)
    for entry in entries:
        assert entry.outcome is expected[entry.path.name]
        if entry.status == "invalid":
            assert entry.contract is None
            assert entry.generated_at is entry.alert_count is entry.report_type is None
            assert entry.error
        else:
            assert entry.contract is not None
            assert entry.error is None


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity", "1e9999"])
def test_review_rejects_non_finite_numbers_as_malformed(token: str, tmp_path: Path) -> None:
    text = json.dumps(sample_report(alerts=[sample_alert(evidence={"private": "TOKEN"})]))
    path = tmp_path / "non-finite.json"
    path.write_text(text.replace('"TOKEN"', token), encoding="utf-8")
    with pytest.raises(MalformedReportError) as captured:
        load_review_report(path)
    assert captured.value.outcome is ReportValidationOutcome.MALFORMED


@pytest.mark.parametrize("depth", [30, sys.getrecursionlimit() + 100])
def test_review_deep_input_is_classified_without_arbitrary_depth_limit(
    depth: int,
    tmp_path: Path,
) -> None:
    text = json.dumps(sample_report(alerts=[sample_alert(evidence={"nested": "TOKEN"})]))
    path = tmp_path / "deep.json"
    path.write_text(text.replace('"TOKEN"', "[" * depth + "null" + "]" * depth), encoding="utf-8")
    outcome = ReportValidationOutcome.VALID_LEGACY_UNVERSIONED
    if depth == 30:
        assert load_review_report(path).outcome is outcome
    else:
        # Assert the adapter retains whichever canonical boundary actually fails.
        with pytest.raises(ReportSchemaError, match="recursion capacity") as canonical:
            parse_report_json(path.read_bytes())
        with pytest.raises((MalformedReportError, IncompatibleReportError)) as captured:
            load_review_report(path)
        outcome = canonical.value.outcome
        assert captured.value.outcome is outcome
        assert captured.value.__cause__.outcome is outcome
    valid = write_json(tmp_path / "valid.json", sample_report())
    entries = list_report_entries(tmp_path)
    assert entries[0].status == "valid"
    assert any(entry.path == valid and entry.status == "valid" for entry in entries)
    assert next(entry for entry in entries if entry.path == path).outcome is outcome


def test_review_incompatible_diagnostic_does_not_expose_evidence_keys(tmp_path: Path) -> None:
    path = write_json(
        tmp_path / "private.json",
        sample_report(alerts=[sample_alert(evidence={"PRIVATE_EVIDENCE_KEY": "\ud800"})]),
    )
    with pytest.raises(IncompatibleReportError) as captured:
        load_review_report(path)
    assert "PRIVATE_EVIDENCE_KEY" in str(captured.value.__cause__)
    assert "PRIVATE_EVIDENCE_KEY" not in str(captured.value)
    entry = list_report_entries(tmp_path)[0]
    assert entry.outcome is ReportValidationOutcome.INCOMPATIBLE
    assert "PRIVATE_EVIDENCE_KEY" not in entry.error


def test_future_schema_body_is_never_projected_and_large_version_is_safe(tmp_path: Path) -> None:
    version = 10 ** (sys.get_int_max_str_digits() + 1)
    for future_version in (2, version):
        with pytest.raises(UnsupportedSchemaError) as captured:
            validate_report_data(
                {
                    "report_type": "sentinellite_alert_report",
                    "schema_version": future_version,
                    "alerts": "UNKNOWN_PRIVATE_BODY",
                },
                tmp_path / "future.json",
            )
        assert captured.value.schema_version == future_version
        assert captured.value.outcome is ReportValidationOutcome.UNSUPPORTED_SCHEMA
        assert "Unsupported" in str(captured.value)
        assert "UNKNOWN_PRIVATE_BODY" not in str(captured.value)


@pytest.mark.parametrize("field_name", ["alert_id", "rule_name", "base_score", "evidence"])
def test_abbreviated_legacy_alert_is_rejected(field_name: str) -> None:
    alert = sample_alert()
    del alert[field_name]
    with incompatible_report(field_name):
        validate_report_data(sample_report(alerts=[alert]), Path("abbreviated.json"))


@pytest.mark.parametrize("location", ["report", "alert", "explanation"])
def test_unknown_fields_are_rejected_at_each_contract_level(location: str) -> None:
    data = sample_report(alerts=[sample_alert(explanation=sample_explanation())])
    target = data if location == "report" else data["alerts"][0]
    if location == "explanation":
        target = target["explanation"]
    target["PRIVATE_UNKNOWN_FIELD"] = "PRIVATE_UNKNOWN_VALUE"
    original = deepcopy(data)
    with incompatible_report("unexpected fields"):
        validate_report_data(data, Path("unknown-field.json"))
    assert data == original


def test_bounded_read_rejects_file_growth_before_parser(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from io import BytesIO

    path = write_json(tmp_path / "growing.json", sample_report())
    reads = []

    class GrowingFile(BytesIO):
        def read(self, size: int = -1) -> bytes:
            reads.append(size)
            return super().read(size)

    monkeypatch.setattr(
        Path, "open", lambda *args, **kwargs: GrowingFile(b" " * (MAX_REPORT_SIZE_BYTES + 10))
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("Oversized input must be rejected before parsing")

    monkeypatch.setattr("sentinellite.reporting.review.parse_report_json", forbidden)
    with pytest.raises(ReportReviewError, match="size limit"):
        load_review_report(path)
    assert reads == [MAX_REPORT_SIZE_BYTES + 1]


@pytest.mark.parametrize("encoded", [b"\xff\xfe", '{"secret":"PRIVATE"}'.encode("utf-16")])
def test_invalid_utf8_does_not_block_other_reports(encoded: bytes, tmp_path: Path) -> None:
    valid = write_json(tmp_path / "valid.json", sample_report())
    (tmp_path / "invalid.json").write_bytes(encoded)
    entries = list_report_entries(tmp_path)
    assert entries[0].path == valid
    assert entries[1].outcome is ReportValidationOutcome.MALFORMED
    assert "PRIVATE" not in entries[1].error


def test_parser_recursion_error_is_malformed_at_review_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = write_json(tmp_path / "report.json", sample_report())

    def fail(*args, **kwargs):
        raise RecursionError("PRIVATE_DECODER_DETAIL")

    monkeypatch.setattr("sentinellite.reporting.validation.json.loads", fail)
    with pytest.raises(MalformedReportError, match="parser recursion capacity") as captured:
        load_review_report(path)
    assert captured.value.outcome is ReportValidationOutcome.MALFORMED
    assert "PRIVATE_DECODER_DETAIL" not in str(captured.value)


def test_validation_recursion_error_is_incompatible_at_review_boundary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = write_json(tmp_path / "report.json", sample_report())

    def fail(*args, **kwargs):
        raise RecursionError("PRIVATE_VALIDATION_DETAIL")

    monkeypatch.setattr("sentinellite.reporting.validation._copy_json_value", fail)
    with pytest.raises(IncompatibleReportError) as captured:
        load_review_report(path)
    assert captured.value.outcome is ReportValidationOutcome.INCOMPATIBLE
    assert "validation recursion capacity" in str(captured.value.__cause__)
    assert "PRIVATE_VALIDATION_DETAIL" not in str(captured.value)


@pytest.mark.parametrize(
    "filename", ["schema_v1_explanation.json", "legacy_unversioned_explanation.json"]
)
def test_summary_projection_omits_evidence_and_explanation_bodies(
    filename: str, tmp_path: Path
) -> None:
    data = json.loads((REPORT_FIXTURES / filename).read_bytes())
    data["alerts"][0]["evidence"] = {"PRIVATE_EVIDENCE": "PRIVATE_VALUE"}
    data["alerts"][0]["explanation"]["summary"] = "PRIVATE_EXPLANATION_BODY"
    data["alerts"][0]["explanation"]["evidence_summary"] = {"PRIVATE_SUMMARY": "PRIVATE_VALUE"}
    path = write_json(tmp_path / "report.json", data)
    report = load_review_report(path)
    summary = build_report_summary(report)
    assert summary["contract"] == report.contract.value
    assert summary["schema_version"] == report.schema_version
    assert summary["explanation_count"] == 1
    for private in (
        "PRIVATE_EVIDENCE",
        "PRIVATE_VALUE",
        "PRIVATE_EXPLANATION_BODY",
        "PRIVATE_SUMMARY",
    ):
        assert private not in repr(report)
        assert private not in repr(summary)
    assert not hasattr(report.alerts[0], "evidence")
    assert not hasattr(report.alerts[0], "explanation")


def test_review_preserves_empty_display_text_and_lowercase_utc_marker() -> None:
    data = sample_report(
        generated_at="2026-08-28t10:00:00z",
        alerts=[
            sample_alert(
                category="",
                message="",
                source="",
                rule_name="",
                description="",
                recommendation="",
            )
        ],
    )
    report = validate_report_data(data, Path("empty-text.json"))
    assert report.alerts[0].category == report.alerts[0].message == ""
    assert report.generated_at == datetime.fromisoformat("2026-08-28T10:00:00+00:00")


def test_discovery_keeps_excluding_symlinks(tmp_path: Path) -> None:
    target = write_json(tmp_path / "report.json", sample_report())
    (tmp_path / "linked.json").symlink_to(target)
    assert discover_report_paths(tmp_path) == [target]


def test_existing_size_limit_accepts_exact_boundary(tmp_path: Path) -> None:
    assert MAX_REPORT_SIZE_BYTES == 2 * 1024 * 1024
    encoded = json.dumps(sample_report()).encode()
    path = tmp_path / "boundary.json"
    path.write_bytes(encoded + b" " * (MAX_REPORT_SIZE_BYTES - len(encoded)))
    assert load_review_report(path).alert_count == 1
