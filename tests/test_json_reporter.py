import json
import sys
from collections import OrderedDict, UserDict, namedtuple
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from sentinellite.detection.engine import detect_event
from sentinellite.explanations.evidence import build_alert_evidence_summary
from sentinellite.explanations.generator import generate_alert_explanation
from sentinellite.models.security_event import create_security_event
from sentinellite.reporting.json_reporter import (
    AlertReport,
    create_alert_report,
    read_alert_report,
    write_alert_report,
)
from sentinellite.reporting.schema import (
    ALERT_REQUIRED_KEYS,
    ReportContract,
    ReportValidationOutcome,
)
from sentinellite.reporting.validation import IncompatibleReportError, parse_report_json
from sentinellite.scoring.risk import ScoredAlert, score_rule_match

SCHEMA_V1_REPORT_KEYS = {
    "schema_version",
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


def test_create_alert_report_default_emits_exact_schema_v1_shape() -> None:
    scored_alert = create_sample_scored_alert()

    report = create_alert_report([scored_alert])
    report_dict = report.to_dict()

    assert isinstance(report, AlertReport)
    assert set(report_dict) == SCHEMA_V1_REPORT_KEYS
    assert type(report_dict["schema_version"]) is int
    assert report_dict["schema_version"] == 1
    assert report_dict == {
        "schema_version": 1,
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
    assert set(report.to_dict()) == SCHEMA_V1_REPORT_KEYS
    assert type(report.schema_version) is int
    assert report.schema_version == 1
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


def test_create_empty_alert_report_emits_schema_v1_shape() -> None:
    report = create_alert_report([], include_explanations=True)
    report_dict = report.to_dict()

    assert set(report_dict) == SCHEMA_V1_REPORT_KEYS
    assert type(report_dict["schema_version"]) is int
    assert report_dict["schema_version"] == 1
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


def test_write_alert_report_default_emits_schema_v1_output(tmp_path: Path) -> None:
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

    assert set(data) == SCHEMA_V1_REPORT_KEYS
    assert type(data["schema_version"]) is int
    assert data["schema_version"] == 1
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

    assert set(data) == SCHEMA_V1_REPORT_KEYS
    assert type(data["schema_version"]) is int
    assert data["schema_version"] == 1
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


@dataclass
class DataclassEvidence:
    value: str = "must not become a JSON object"


class DictEvidence(dict):
    pass


class ListEvidence(list):
    pass


@pytest.mark.parametrize("include_explanations", [False, True])
@pytest.mark.parametrize(
    "evidence",
    [
        {"nested": {1: "non-string key"}},
        {"nested": {None: "non-string key"}},
        {"nested": {True: "non-string key"}},
        {"nested": {("key",): "non-string key"}},
        {"nested": [float("nan")]},
        {"nested": [float("inf")]},
        {"nested": [float("-inf")]},
        {"nested": [("tuple",)]},
        {"nested": [{"set"}]},
        {"nested": [frozenset({"set"})]},
        {"nested": [b"bytes"]},
        {"nested": [bytearray(b"bytes")]},
        {"nested": [Path("python-path")]},
        {"nested": [DataclassEvidence()]},
        {"nested": [namedtuple("Evidence", "value")("tuple")]},
        {"nested": [DictEvidence(value="dict subclass")]},
        {"nested": [ListEvidence(["list subclass"])]},
        {"nested": [OrderedDict(value="ordered dict")]},
        {"nested": [UserDict(value="mapping")]},
        {"nested": ["\ud800"]},
        {"\ud800": "invalid Unicode key"},
        [],
        DictEvidence(value="top-level dict subclass"),
    ],
    ids=[
        "integer-key",
        "null-key",
        "boolean-key",
        "tuple-key",
        "nan",
        "infinity",
        "negative-infinity",
        "tuple",
        "set",
        "frozenset",
        "bytes",
        "bytearray",
        "path",
        "dataclass",
        "namedtuple",
        "dict-subclass",
        "list-subclass",
        "ordered-dict",
        "user-dict",
        "surrogate-value",
        "surrogate-key",
        "non-object-evidence",
        "evidence-dict-subclass",
    ],
)
def test_producer_rejects_non_json_evidence_before_persistence(
    evidence: Any,
    include_explanations: bool,
    tmp_path: Path,
) -> None:
    alert = replace(create_sample_scored_alert(), evidence=evidence)
    target = tmp_path / "existing.json"
    original = b"existing report bytes"
    target.write_bytes(original)

    with pytest.raises(IncompatibleReportError, match="evidence"):
        create_alert_report([alert], include_explanations=include_explanations)
    with pytest.raises(IncompatibleReportError, match="evidence"):
        write_alert_report(
            [alert],
            output_dir=tmp_path,
            filename=target.name,
            include_explanations=include_explanations,
        )

    assert target.read_bytes() == original
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize("include_explanations", [False, True])
@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("alert_id", " "),
        ("rule_id", ""),
        ("event_id", ""),
        ("base_score", True),
        ("base_score", -1),
        ("base_score", 101),
        ("risk_score", 50.0),
        ("risk_score", False),
        ("risk_score", 101),
        ("severity", "urgent"),
        ("risk_level", "urgent"),
        ("message", None),
        ("message", "\udfff"),
        ("category", 1),
    ],
)
def test_producer_rejects_invalid_alert_fields(
    field_name: str,
    value: Any,
    include_explanations: bool,
    tmp_path: Path,
) -> None:
    alert = replace(create_sample_scored_alert(), **{field_name: value})

    with pytest.raises(IncompatibleReportError):
        create_alert_report([alert], include_explanations=include_explanations)
    with pytest.raises(IncompatibleReportError):
        write_alert_report([alert], tmp_path, include_explanations=include_explanations)

    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("include_explanations", [False, True])
def test_producer_rejects_cyclic_evidence(
    include_explanations: bool,
    tmp_path: Path,
) -> None:
    evidence: dict[str, Any] = {}
    evidence["cycle"] = evidence
    alert = replace(create_sample_scored_alert(), evidence=evidence)

    with pytest.raises(IncompatibleReportError, match="cyclic"):
        create_alert_report([alert], include_explanations=include_explanations)
    with pytest.raises(IncompatibleReportError, match="cyclic"):
        write_alert_report([alert], tmp_path, include_explanations=include_explanations)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("include_explanations", [False, True])
def test_producer_handles_validation_recursion_failure(
    include_explanations: bool,
    tmp_path: Path,
) -> None:
    evidence: dict[str, Any] = {}
    nested = evidence
    for _ in range(sys.getrecursionlimit() + 100):
        nested["next"] = {}
        nested = nested["next"]
    alert = replace(create_sample_scored_alert(), evidence=evidence)

    with pytest.raises(IncompatibleReportError, match="recursion capacity"):
        create_alert_report([alert], include_explanations=include_explanations)
    with pytest.raises(IncompatibleReportError, match="recursion capacity"):
        write_alert_report([alert], tmp_path, include_explanations=include_explanations)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("rule_id", "OTHER-001"),
        ("title", None),
        ("confidence", "certain"),
        ("possible_causes", ("tuple must not become a list",)),
        ("recommended_actions", [1]),
        ("evidence_summary", {"nested": [float("nan")]}),
        ("evidence_summary", {"nested": {1: "non-string key"}}),
        ("evidence_summary", {"nested": DataclassEvidence()}),
    ],
)
def test_producer_validates_optional_explanation_before_persistence(
    field_name: str,
    value: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    alert = create_sample_scored_alert()
    explanation = replace(
        generate_alert_explanation(alert.rule_id, build_alert_evidence_summary(alert)),
        **{field_name: value},
    )
    monkeypatch.setattr(
        "sentinellite.reporting.json_reporter.generate_alert_explanation",
        lambda *args, **kwargs: explanation,
    )

    with pytest.raises(IncompatibleReportError, match="explanation"):
        create_alert_report([alert], include_explanations=True)
    with pytest.raises(IncompatibleReportError, match="explanation"):
        write_alert_report([alert], tmp_path, include_explanations=True)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("include_explanations", [None, False, True])
@pytest.mark.parametrize("empty", [False, True])
def test_producer_round_trip_validates_exact_schema_v1(
    include_explanations: bool | None,
    empty: bool,
    tmp_path: Path,
) -> None:
    alert = replace(
        create_sample_scored_alert(),
        evidence={"nested": [None, True, False, 0, -5, 1.25, "සිංහල 😀", {"": []}]},
    )
    alerts = [] if empty else [alert]
    options = {} if include_explanations is None else {"include_explanations": include_explanations}
    report = create_alert_report(alerts, **options)
    data = report.to_dict()
    result = parse_report_json(json.dumps(data, allow_nan=False))
    path = write_alert_report(alerts, tmp_path / "nested" / "reports", **options)
    persisted = parse_report_json(path.read_bytes())

    assert result.contract is persisted.contract is ReportContract.SCHEMA_V1
    assert result.outcome is persisted.outcome is ReportValidationOutcome.VALID_SCHEMA_V1
    assert result.data == data
    for payload in (data, persisted.data):
        assert set(payload) == SCHEMA_V1_REPORT_KEYS
        assert len(payload) == 6
        assert type(payload["schema_version"]) is int
        assert payload["schema_version"] == 1
        assert payload["alert_count"] == len(payload["alerts"]) == len(alerts)
        assert payload["report_id"] == f"sentinellite-report-{payload['generated_at']}"
        assert datetime.fromisoformat(payload["generated_at"]).utcoffset() == UTC.utcoffset(None)
        for generated_alert in payload["alerts"]:
            assert set(generated_alert) == ALERT_REQUIRED_KEYS | (
                {"explanation"} if include_explanations else set()
            )
            assert {key: generated_alert[key] for key in ALERT_REQUIRED_KEYS} == alert.to_dict()
    timestamp = persisted.data["generated_at"].replace(":", "-").replace("+", "_")
    assert path == tmp_path / "nested" / "reports" / f"alerts-{timestamp}.json"


def test_report_preserves_detached_evidence_snapshots() -> None:
    alert = replace(create_sample_scored_alert(), evidence={"nested": [{"value": "original"}]})
    report = create_alert_report([alert], include_explanations=True)
    snapshot = report.to_dict()

    alert.evidence["nested"][0]["value"] = "input changed"
    report.alerts[0]["evidence"]["nested"][0]["value"] = "report changed"
    snapshot["alerts"][0]["explanation"]["evidence_summary"]["rule_id"] = "snapshot changed"

    assert snapshot["alerts"][0]["evidence"]["nested"][0]["value"] == "original"
    assert report.alerts[0]["explanation"]["evidence_summary"]["rule_id"] == alert.rule_id


def test_writer_revalidates_mutated_report_before_opening_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report = create_alert_report([create_sample_scored_alert()])
    report.alerts[0]["evidence"]["bad"] = ("tuple",)
    monkeypatch.setattr(
        "sentinellite.reporting.json_reporter.create_alert_report",
        lambda *args, **kwargs: report,
    )
    target = tmp_path / "existing.json"
    target.write_bytes(b"existing bytes")

    with pytest.raises(IncompatibleReportError, match="JSON-native"):
        write_alert_report([], tmp_path, filename=target.name)

    assert target.read_bytes() == b"existing bytes"


def test_alert_report_keeps_existing_positional_constructor() -> None:
    report = AlertReport(
        "report-id",
        "sentinellite_alert_report",
        "2026-10-09T00:00:00+00:00",
        0,
        [],
    )
    assert report.schema_version == 1
    assert set(report.to_dict()) == SCHEMA_V1_REPORT_KEYS
