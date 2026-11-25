"""Check fixture contents directly, without a canonical report validator."""

import json
import math
from collections import Counter
from datetime import datetime
from pathlib import Path

import pytest

from sentinellite.reporting.schema import (
    ALERT_REPORT_SCHEMA_VERSION,
    ALERT_REPORT_TYPE,
    ALERT_REQUIRED_KEYS,
    ALERT_SCORE_MAX,
    ALERT_SCORE_MIN,
    EXPLANATION_CONFIDENCE_VALUES,
    EXPLANATION_REQUIRED_KEYS,
    LEGACY_ALERT_REQUIRED_KEYS,
    LEGACY_REPORT_TOP_LEVEL_KEYS,
    RISK_LEVEL_VALUES,
    SCHEMA_V1_REPORT_TOP_LEVEL_KEYS,
    SEVERITY_VALUES,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "report_schema"


def load_fixture(filename: str) -> dict:
    return json.loads((FIXTURE_DIR / filename).read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("filename", "versioned", "alert_count", "explained"),
    [
        ("schema_v1_alert.json", True, 1, False),
        ("schema_v1_explanation.json", True, 1, True),
        ("schema_v1_empty.json", True, 0, False),
        ("legacy_unversioned_alert.json", False, 1, False),
        ("legacy_unversioned_explanation.json", False, 1, True),
    ],
)
def test_valid_fixture_contract(
    filename: str, versioned: bool, alert_count: int, explained: bool
) -> None:
    report = load_fixture(filename)

    expected_keys = SCHEMA_V1_REPORT_TOP_LEVEL_KEYS if versioned else LEGACY_REPORT_TOP_LEVEL_KEYS
    assert set(report) == expected_keys
    assert len(report) == (6 if versioned else 5)
    if versioned:
        assert type(report["schema_version"]) is int
        assert report["schema_version"] == ALERT_REPORT_SCHEMA_VERSION
    else:
        assert "schema_version" not in report
    assert isinstance(report["report_id"], str) and report["report_id"].strip()
    assert report["report_type"] == ALERT_REPORT_TYPE
    timestamp = datetime.fromisoformat(report["generated_at"])
    assert timestamp.tzinfo is not None and timestamp.utcoffset() is not None
    assert type(report["alert_count"]) is int
    assert isinstance(report["alerts"], list)
    assert report["alert_count"] == len(report["alerts"]) == alert_count

    required_keys = ALERT_REQUIRED_KEYS if versioned else LEGACY_ALERT_REQUIRED_KEYS
    assert len(required_keys) == 15
    for alert in report["alerts"]:
        assert set(alert) == required_keys | ({"explanation"} if explained else set())
        for key in required_keys - {"base_score", "risk_score", "evidence"}:
            assert isinstance(alert[key], str) and alert[key].strip()
        for key in ("base_score", "risk_score"):
            assert type(alert[key]) is int
            assert ALERT_SCORE_MIN <= alert[key] <= ALERT_SCORE_MAX
        assert alert["severity"] in SEVERITY_VALUES
        assert alert["risk_level"] in RISK_LEVEL_VALUES
        # Preserve an independently valid level; do not infer it from default thresholds.
        assert (alert["risk_score"], alert["risk_level"]) == (50, "high")
        assert isinstance(alert["evidence"], dict)
        assert alert["evidence"]["details"] == {
            "labels": ["synthetic", "contract"],
            "optional_value": None,
            "measurements": [0, 1.25, False],
        }
        if explained:
            explanation = alert["explanation"]
            assert set(explanation) == EXPLANATION_REQUIRED_KEYS
            assert len(explanation) == 8
            assert explanation["rule_id"] == alert["rule_id"]
            for key in ("rule_id", "title", "summary", "why_it_matched", "confidence"):
                assert isinstance(explanation[key], str) and explanation[key].strip()
            for key in ("possible_causes", "recommended_actions"):
                assert isinstance(explanation[key], list)
                assert all(isinstance(item, str) for item in explanation[key])
            assert isinstance(explanation["evidence_summary"], dict)
            assert explanation["confidence"] in EXPLANATION_CONFIDENCE_VALUES

    # A strict JSON round trip covers finite JSON-native evidence at every depth.
    assert json.loads(json.dumps(report, allow_nan=False)) == report


@pytest.mark.parametrize("suffix", ["alert", "explanation"])
def test_legacy_fixture_only_differs_from_schema_v1_by_version(suffix: str) -> None:
    versioned = load_fixture(f"schema_v1_{suffix}.json")
    legacy = load_fixture(f"legacy_unversioned_{suffix}.json")

    del versioned["schema_version"]

    assert legacy == versioned


def test_future_schema_fixture_remains_structurally_recognizable() -> None:
    report = load_fixture("unsupported_schema_version.json")
    expected = load_fixture("schema_v1_alert.json")

    assert type(report["schema_version"]) is int
    assert report["schema_version"] > ALERT_REPORT_SCHEMA_VERSION
    expected["schema_version"] = report["schema_version"]
    assert report == expected


def test_missing_alert_field_fixture_has_only_the_intended_defect() -> None:
    expected = load_fixture("schema_v1_alert.json")
    del expected["alerts"][0]["evidence"]

    assert load_fixture("incompatible_missing_alert_field.json") == expected


def test_alert_count_fixture_has_only_the_intended_defect() -> None:
    expected = load_fixture("schema_v1_alert.json")
    expected["alert_count"] = 2

    assert load_fixture("incompatible_alert_count.json") == expected


def test_boolean_score_fixture_has_only_the_intended_defect() -> None:
    expected = load_fixture("schema_v1_alert.json")
    expected["alerts"][0]["risk_score"] = True
    report = load_fixture("incompatible_boolean_risk_score.json")

    assert report == expected
    assert type(report["alerts"][0]["risk_score"]) is bool


def test_report_type_fixture_has_only_the_intended_defect() -> None:
    expected = load_fixture("schema_v1_alert.json")
    expected["report_type"] = "synthetic_other_report"

    assert load_fixture("incompatible_report_type.json") == expected


def test_incomplete_explanation_fixture_has_only_the_intended_defect() -> None:
    expected = load_fixture("schema_v1_explanation.json")
    del expected["alerts"][0]["explanation"]["why_it_matched"]

    assert load_fixture("incompatible_incomplete_explanation.json") == expected


def test_explanation_rule_id_fixture_has_only_the_intended_defect() -> None:
    expected = load_fixture("schema_v1_explanation.json")
    expected["alerts"][0]["explanation"]["rule_id"] = "AUTH-002"

    assert load_fixture("incompatible_explanation_rule_id.json") == expected


def test_malformed_syntax_fixture_cannot_be_loaded_as_json() -> None:
    with pytest.raises(json.JSONDecodeError):
        load_fixture("malformed_json_syntax.json")


@pytest.mark.parametrize(
    ("filename", "duplicate_key"),
    [
        ("malformed_duplicate_top_level_key.json", "schema_version"),
        ("malformed_duplicate_nested_key.json", "synthetic"),
    ],
)
def test_duplicate_key_fixtures_preserve_duplicate_pairs(
    filename: str, duplicate_key: str
) -> None:
    object_pairs: list[list[tuple[str, object]]] = []

    def record_pairs(pairs: list[tuple[str, object]]) -> dict:
        object_pairs.append(pairs)
        return dict(pairs)

    text = (FIXTURE_DIR / filename).read_text(encoding="utf-8")
    report = json.loads(text, object_pairs_hook=record_pairs)
    duplicates = [
        (key, count)
        for pairs in object_pairs
        for key, count in Counter(key for key, _ in pairs).items()
        if count > 1
    ]

    assert duplicates == [(duplicate_key, 2)]
    assert report == load_fixture("schema_v1_alert.json")


def test_non_finite_fixture_preserves_all_three_json_extensions() -> None:
    filename = "malformed_non_finite_numbers.json"
    constants: list[str] = []
    text = (FIXTURE_DIR / filename).read_text(encoding="utf-8")
    json.loads(text, parse_constant=constants.append)

    assert constants == ["NaN", "Infinity", "-Infinity"]
    report = load_fixture(filename)
    measurements = report["alerts"][0]["evidence"]["details"]["measurements"]
    assert measurements[0] == 0
    assert math.isnan(measurements[1])
    assert measurements[2:4] == [math.inf, -math.inf]
    assert measurements[4] is False
    with pytest.raises(ValueError):
        json.dumps(report, allow_nan=False)


def test_fixture_inventory_is_explicit() -> None:
    assert {path.name for path in FIXTURE_DIR.glob("*.json")} == {
        "schema_v1_alert.json",
        "schema_v1_explanation.json",
        "schema_v1_empty.json",
        "legacy_unversioned_alert.json",
        "legacy_unversioned_explanation.json",
        "unsupported_schema_version.json",
        "incompatible_missing_alert_field.json",
        "incompatible_alert_count.json",
        "incompatible_boolean_risk_score.json",
        "incompatible_report_type.json",
        "incompatible_incomplete_explanation.json",
        "incompatible_explanation_rule_id.json",
        "malformed_json_syntax.json",
        "malformed_duplicate_top_level_key.json",
        "malformed_duplicate_nested_key.json",
        "malformed_non_finite_numbers.json",
    }
