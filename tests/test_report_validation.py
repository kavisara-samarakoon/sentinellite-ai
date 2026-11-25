"""Canonical parser tests using the approved fixtures, plus negative mutations."""

import json
import sys
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from sentinellite.detection.engine import detect_event
from sentinellite.explanations.models import AlertExplanation
from sentinellite.models.security_event import create_security_event
from sentinellite.reporting import validation
from sentinellite.reporting.json_reporter import create_alert_report
from sentinellite.reporting.schema import (
    ALERT_REQUIRED_KEYS,
    EXPLANATION_REQUIRED_KEYS,
    LEGACY_REPORT_TOP_LEVEL_KEYS,
    SCHEMA_V1_REPORT_TOP_LEVEL_KEYS,
    ReportContract,
    ReportValidationOutcome,
)
from sentinellite.reporting.validation import (
    IncompatibleReportError,
    MalformedReportError,
    ReportSchemaError,
    UnsupportedSchemaError,
    detect_report_contract,
    parse_report_json,
    validate_report_data,
)
from sentinellite.scoring.risk import ScoredAlert, score_rule_match

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "report_schema"
CONTRACTS = [ReportContract.SCHEMA_V1, ReportContract.LEGACY_UNVERSIONED]


def report_data(contract: ReportContract = ReportContract.SCHEMA_V1) -> dict:
    data = json.loads((FIXTURE_DIR / "schema_v1_explanation.json").read_bytes())
    if contract is ReportContract.LEGACY_UNVERSIONED:
        del data["schema_version"]
    return data


@pytest.mark.parametrize(
    ("filename", "outcome"),
    [
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
    ],
)
def test_approved_fixture_outcomes(filename: str, outcome: ReportValidationOutcome) -> None:
    source = (FIXTURE_DIR / filename).read_bytes()
    if outcome in (
        ReportValidationOutcome.VALID_SCHEMA_V1,
        ReportValidationOutcome.VALID_LEGACY_UNVERSIONED,
    ):
        result = parse_report_json(source)
        assert result.outcome is outcome
        assert result.data == json.loads(source)
        expected = (
            ReportContract.SCHEMA_V1
            if outcome is ReportValidationOutcome.VALID_SCHEMA_V1
            else ReportContract.LEGACY_UNVERSIONED
        )
        assert result.contract is expected
        assert result.schema_version == (1 if expected is ReportContract.SCHEMA_V1 else None)
    else:
        with pytest.raises(ReportSchemaError) as captured:
            parse_report_json(source)
        assert captured.value.outcome is outcome


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize("source_type", [str, bytes, bytearray])
def test_parser_inputs_and_unicode_are_preserved(
    contract: ReportContract, source_type: type
) -> None:
    data = report_data(contract)
    data["alerts"][0]["evidence"] = {"text": "සිංහල 🛡", "": "empty keys are JSON-native"}
    source = json.dumps(data, ensure_ascii=False)
    if source_type is not str:
        source = source_type(source.encode("utf-8"))
    result = parse_report_json(source)
    assert result.contract is contract
    assert result.data == data


@pytest.mark.parametrize("source", [None, {}, [], 1, memoryview(b"{}")])
def test_wrong_parser_api_types_raise_type_error(source: object) -> None:
    with pytest.raises(TypeError, match="text or UTF-8 bytes"):
        parse_report_json(source)


@pytest.mark.parametrize(
    "source",
    [
        "",
        " ",
        "{",
        '{"a":1,}',
        "// comment\n{}",
        "{}{}",
        '{"a":01}',
        '{"a":"\x00"}',
        b"\xff",
        b'"\xc0\xaf"',
        b'"\xed\xa0\x80"',
        b'"\xf4\x90\x80\x80"',
        b'"\xe2\x82"',
        '"\ud800"',
        b"\xef\xbb\xbf{}",
        "{}".encode("utf-16"),
        "{}".encode("utf-32"),
    ],
)
def test_malformed_json_and_utf8_fail_safely(source: str | bytes) -> None:
    with pytest.raises(MalformedReportError) as captured:
        parse_report_json(source)
    assert captured.value.outcome is ReportValidationOutcome.MALFORMED


def test_syntax_error_includes_location() -> None:
    with pytest.raises(MalformedReportError, match="line 2, column"):
        parse_report_json('{\n"alerts": [}')


@pytest.mark.parametrize(
    "source",
    [
        '{"report_type": "x", "report_type": "y"}',
        '{"a": {"b": 1, "b": 1}}',
        '[{"a": 1, "\\u0061": 2}]',
        '{"a": [{"b": [{"c": 1, "c": 1}]}]}',
        '{"a": null, "a": null}',
    ],
)
def test_duplicate_keys_at_every_depth_precede_contract_detection(source: str) -> None:
    with pytest.raises(MalformedReportError, match="Duplicate"):
        parse_report_json(source)


@pytest.mark.parametrize("number", ["NaN", "Infinity", "-Infinity", "1e309", "-1e9999"])
@pytest.mark.parametrize("location", ["top", "evidence", "summary"])
def test_non_finite_tokens_and_overflow_are_malformed(number: str, location: str) -> None:
    if location == "top":
        source = number
    else:
        data = report_data()
        target = data["alerts"][0]["evidence"]
        if location == "summary":
            target = data["alerts"][0]["explanation"]["evidence_summary"]
        target["nested"] = [{"number": "NUMBER_TOKEN"}]
        source = json.dumps(data).replace('"NUMBER_TOKEN"', number)
    with pytest.raises(MalformedReportError, match="Non-finite"):
        parse_report_json(source)


def test_huge_integer_conversion_failure_is_malformed_when_limit_enabled() -> None:
    if not hasattr(sys, "get_int_max_str_digits") or not sys.get_int_max_str_digits():
        pytest.skip("Interpreter integer conversion limit is disabled.")
    with pytest.raises(MalformedReportError):
        parse_report_json("1" * (sys.get_int_max_str_digits() + 1))


@pytest.mark.parametrize("contract", CONTRACTS)
def test_detection_is_only_contract_selection(contract: ReportContract) -> None:
    data = {"report_type": "sentinellite_alert_report"}
    if contract is ReportContract.SCHEMA_V1:
        data["schema_version"] = 1
    assert detect_report_contract(data) is contract
    with pytest.raises(IncompatibleReportError, match="missing required"):
        validate_report_data(data)


@pytest.mark.parametrize("version", [True, False, 1.0, "1", None, [], {}, 0, -1])
def test_invalid_version_is_incompatible_without_legacy_fallback(version: object) -> None:
    data = report_data()
    data["schema_version"] = version
    for operation in (detect_report_contract, validate_report_data):
        with pytest.raises(IncompatibleReportError, match="schema_version"):
            operation(data)
    with pytest.raises(IncompatibleReportError):
        parse_report_json(json.dumps(data))


@pytest.mark.parametrize("version", [2, 999])
def test_future_version_is_unsupported_without_applying_v1_body_rules(version: int) -> None:
    data = {"report_type": "sentinellite_alert_report", "schema_version": version, "future": []}
    for operation in (detect_report_contract, validate_report_data):
        with pytest.raises(UnsupportedSchemaError) as captured:
            operation(data)
        assert captured.value.schema_version == version
        assert captured.value.outcome is ReportValidationOutcome.UNSUPPORTED_SCHEMA
    with pytest.raises(UnsupportedSchemaError):
        parse_report_json(json.dumps(data))


def test_large_native_future_version_has_safe_error_metadata() -> None:
    version = 10**5000
    data = {"report_type": "sentinellite_alert_report", "schema_version": version}
    with pytest.raises(UnsupportedSchemaError) as captured:
        validate_report_data(data)
    assert captured.value.schema_version == version
    assert captured.value.outcome is ReportValidationOutcome.UNSUPPORTED_SCHEMA


@pytest.mark.parametrize("report_type", [None, [], True, 7, "", "other_report"])
def test_unrelated_future_report_is_incompatible(report_type: object) -> None:
    data = {"schema_version": 2, "report_type": report_type}
    with pytest.raises(IncompatibleReportError, match="report_type"):
        validate_report_data(data)


def test_malformed_future_report_takes_precedence() -> None:
    with pytest.raises(MalformedReportError):
        parse_report_json('{"report_type":"sentinellite_alert_report","schema_version":2,"x":NaN}')


@pytest.mark.parametrize("data", [None, [], "report", 7, True, 1.25])
def test_non_object_report_is_incompatible(data: object) -> None:
    with pytest.raises(IncompatibleReportError, match="top level"):
        parse_report_json(json.dumps(data))


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize("key", sorted(LEGACY_REPORT_TOP_LEVEL_KEYS))
def test_every_required_envelope_field(contract: ReportContract, key: str) -> None:
    data = report_data(contract)
    del data[key]
    with pytest.raises(IncompatibleReportError, match=key):
        validate_report_data(data)


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize("key", sorted(ALERT_REQUIRED_KEYS))
def test_every_required_alert_field(contract: ReportContract, key: str) -> None:
    data = report_data(contract)
    del data["alerts"][0][key]
    with pytest.raises(IncompatibleReportError, match=key):
        validate_report_data(data)


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize("key", sorted(EXPLANATION_REQUIRED_KEYS))
def test_every_required_explanation_field(contract: ReportContract, key: str) -> None:
    data = report_data(contract)
    del data["alerts"][0]["explanation"][key]
    with pytest.raises(IncompatibleReportError, match=key):
        validate_report_data(data)


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize("location", ["report", "alert", "explanation"])
def test_exact_contracts_reject_unknown_fields(contract: ReportContract, location: str) -> None:
    data = report_data(contract)
    target = data if location == "report" else data["alerts"][0]
    if location == "explanation":
        target = target["explanation"]
    target["extra"] = "unexpected"
    with pytest.raises(IncompatibleReportError, match="unexpected fields"):
        validate_report_data(data)


STRING_FIELDS = [
    ("report", "report_id"),
    *[
        ("alert", key)
        for key in sorted(ALERT_REQUIRED_KEYS - {"base_score", "risk_score", "evidence"})
    ],
    *[("explanation", key) for key in ("rule_id", "title", "summary", "why_it_matched")],
]


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize(("location", "key"), STRING_FIELDS)
@pytest.mark.parametrize("value", [None, True, 3, [], {}])
def test_required_strings_require_string_types(
    contract: ReportContract, location: str, key: str, value: object
) -> None:
    data = report_data(contract)
    target = data if location == "report" else data["alerts"][0]
    if location == "explanation":
        target = target["explanation"]
    target[key] = value
    with pytest.raises(IncompatibleReportError, match=key):
        validate_report_data(data)


IDENTIFIER_FIELDS = [
    ("report", "report_id"),
    *[("alert", key) for key in ("alert_id", "rule_id", "event_id")],
    ("explanation", "rule_id"),
]
ORDINARY_TEXT_FIELDS = [
    *[
        ("alert", key)
        for key in (
            "rule_name",
            "category",
            "event_type",
            "source",
            "message",
            "description",
            "recommendation",
        )
    ],
    *[("explanation", key) for key in ("title", "summary", "why_it_matched")],
]


SURROGATES = ["\ud800", "\udbff", "\udc00", "\udfff"]


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize(
    ("location", "key"),
    [*STRING_FIELDS, ("report", "generated_at"), ("explanation", "confidence")],
)
@pytest.mark.parametrize("surrogate", SURROGATES)
def test_escaped_lone_surrogates_in_report_text_are_incompatible(
    contract: ReportContract, location: str, key: str, surrogate: str
) -> None:
    data = report_data(contract)
    target = data if location == "report" else data["alerts"][0]
    if location == "explanation":
        target = target["explanation"]
    target[key] = f"before{surrogate}after"
    # The source is valid UTF-8 JSON containing an escaped surrogate; the decoded
    # string violates the Unicode-scalar contract, so this is incompatible.
    source = json.dumps(data, ensure_ascii=True).encode("utf-8")
    for operation, value in ((validate_report_data, data), (parse_report_json, source)):
        with pytest.raises(IncompatibleReportError, match="invalid Unicode scalar") as captured:
            operation(value)
        assert captured.value.outcome is ReportValidationOutcome.INCOMPATIBLE
        str(captured.value).encode("utf-8", errors="strict")


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize("location", ["evidence", "summary"])
@pytest.mark.parametrize("part", ["key", "value"])
@pytest.mark.parametrize("surrogate", SURROGATES)
def test_escaped_lone_surrogates_in_nested_evidence_are_incompatible(
    contract: ReportContract, location: str, part: str, surrogate: str
) -> None:
    data = report_data(contract)
    target = data["alerts"][0]["evidence"]
    if location == "summary":
        target = data["alerts"][0]["explanation"]["evidence_summary"]
    target["nested"] = [{surrogate: "text"} if part == "key" else {"text": surrogate}]
    source = json.dumps(data, ensure_ascii=True).encode("utf-8")
    for operation, value in ((validate_report_data, data), (parse_report_json, source)):
        with pytest.raises(IncompatibleReportError, match="invalid Unicode scalar") as captured:
            operation(value)
        str(captured.value).encode("utf-8", errors="strict")


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize("key", ["possible_causes", "recommended_actions"])
@pytest.mark.parametrize("surrogate", SURROGATES)
def test_escaped_lone_surrogates_in_explanation_lists_are_incompatible(
    contract: ReportContract, key: str, surrogate: str
) -> None:
    data = report_data(contract)
    data["alerts"][0]["explanation"][key] = ["valid", surrogate]
    with pytest.raises(IncompatibleReportError, match="invalid Unicode scalar"):
        validate_report_data(data)
    with pytest.raises(IncompatibleReportError, match="invalid Unicode scalar"):
        parse_report_json(json.dumps(data))


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize(
    "text",
    [
        pytest.param(chr(0xD800) * 2, id="high-high"),
        pytest.param(chr(0xDC00) + chr(0xD800), id="low-high"),
        pytest.param(chr(0xDFFF) * 2, id="low-low"),
    ],
)
def test_invalid_surrogate_sequences_are_incompatible(contract: ReportContract, text: str) -> None:
    data = report_data(contract)
    data["alerts"][0]["message"] = text
    with pytest.raises(IncompatibleReportError, match="invalid Unicode scalar"):
        parse_report_json(json.dumps(data))


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize("ensure_ascii", [False, True])
def test_valid_unicode_and_escaped_control_text_render_as_utf8(
    contract: ReportContract, ensure_ascii: bool
) -> None:
    data = report_data(contract)
    text = "සිංහල 😀 🛡 " + "".join(chr(code) for code in range(32)) + "\x7f\ufdd0\ufffe\U0010ffff"
    alert = data["alerts"][0]
    for location, key in ORDINARY_TEXT_FIELDS:
        target = alert if location == "alert" else alert["explanation"]
        target[key] = text
    alert["explanation"]["possible_causes"] = ["", text]
    alert["explanation"]["recommended_actions"] = [text]
    evidence = {text: [None, False, 0, 1.25, {"text": text, "": ""}]}
    alert["evidence"] = evidence
    alert["explanation"]["evidence_summary"] = evidence
    result = parse_report_json(json.dumps(data, ensure_ascii=ensure_ascii).encode("utf-8"))
    assert result.data == data
    assert validate_report_data(data).data == data
    rendered = json.dumps(result.to_dict(), ensure_ascii=False, allow_nan=False).encode("utf-8")
    assert json.loads(rendered) == data
    assert result.data["alerts"][0]["message"].encode("utf-8").decode("utf-8") == text


@pytest.mark.parametrize("contract", CONTRACTS)
def test_valid_json_surrogate_pair_decodes_to_an_emoji_scalar(contract: ReportContract) -> None:
    data = report_data(contract)
    data["alerts"][0]["message"] = "😀"
    source = json.dumps(data, ensure_ascii=True)
    assert r"\ud83d\ude00" in source
    result = parse_report_json(source)
    assert result.data == data
    assert result.data["alerts"][0]["message"].encode("utf-8") == b"\xf0\x9f\x98\x80"
    # Already-decoded Python strings must contain scalars; validation does not
    # silently repair a native string containing surrogate code points.
    data["alerts"][0]["message"] = "\ud83d\ude00"
    with pytest.raises(IncompatibleReportError, match="invalid Unicode scalar"):
        validate_report_data(data)


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize(("location", "key"), IDENTIFIER_FIELDS)
@pytest.mark.parametrize("value", ["", " \t\n"])
def test_identifiers_still_require_non_empty_content(
    contract: ReportContract, location: str, key: str, value: str
) -> None:
    data = report_data(contract)
    target = data if location == "report" else data["alerts"][0]
    if location == "explanation":
        target = target["explanation"]
    target[key] = value
    with pytest.raises(IncompatibleReportError, match=rf"{key}.*non-empty identifier"):
        validate_report_data(data)
    with pytest.raises(IncompatibleReportError):
        parse_report_json(json.dumps(data))


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize(("location", "key"), ORDINARY_TEXT_FIELDS)
@pytest.mark.parametrize("value", ["", " \t\n"])
def test_ordinary_text_has_no_minimum_content_requirement(
    contract: ReportContract, location: str, key: str, value: str
) -> None:
    data = report_data(contract)
    target = data["alerts"][0]
    if location == "explanation":
        target = target["explanation"]
    target[key] = value
    assert validate_report_data(data).data == data
    assert parse_report_json(json.dumps(data)).data == data


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize("value", ["", " \t\n"])
def test_empty_ordinary_text_matches_historical_models(
    contract: ReportContract, value: str
) -> None:
    data = report_data(contract)
    alert = data["alerts"][0]
    for location, key in ORDINARY_TEXT_FIELDS:
        target = alert if location == "alert" else alert["explanation"]
        target[key] = value
    alert["explanation"]["possible_causes"] = [value]
    alert["explanation"]["recommended_actions"] = [value]
    assert AlertExplanation.from_dict(alert["explanation"]).to_dict() == alert["explanation"]
    core_alert = {key: alert[key] for key in ALERT_REQUIRED_KEYS}
    assert ScoredAlert(**core_alert).to_dict() == core_alert
    assert validate_report_data(data).data == data
    assert parse_report_json(json.dumps(data)).data == data


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize("key", ["base_score", "risk_score"])
@pytest.mark.parametrize("value", [-1, 101, True, False, 50.0, "50", None, [], {}])
def test_scores_require_bounded_exact_integers(
    contract: ReportContract, key: str, value: object
) -> None:
    data = report_data(contract)
    data["alerts"][0][key] = value
    with pytest.raises(IncompatibleReportError, match=key):
        validate_report_data(data)


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize("score", [0, 100])
@pytest.mark.parametrize("level", ["info", "low", "medium", "high", "critical"])
def test_scores_and_stored_levels_are_independent(
    contract: ReportContract, score: int, level: str
) -> None:
    data = report_data(contract)
    alert = data["alerts"][0]
    alert.update(base_score=score, risk_score=score, risk_level=level, severity=level)
    result = validate_report_data(data)
    assert result.data == data


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize("key", ["severity", "risk_level", "confidence"])
@pytest.mark.parametrize("value", ["HIGH", "unknown", " high ", "", " \t\n", None, True, 7, [], {}])
def test_enums_reject_invalid_values(contract: ReportContract, key: str, value: object) -> None:
    data = report_data(contract)
    target = data["alerts"][0]
    if key == "confidence":
        target = target["explanation"]
    target[key] = value
    with pytest.raises(IncompatibleReportError, match=key):
        validate_report_data(data)


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize("confidence", ["low", "medium", "high"])
def test_all_explanation_confidences(contract: ReportContract, confidence: str) -> None:
    data = report_data(contract)
    data["alerts"][0]["explanation"]["confidence"] = confidence
    assert validate_report_data(data).data == data


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize("count", [-1, True, False, 1.0, "1", None, [], {}, 2])
def test_alert_count_is_strict_and_matches_array(contract: ReportContract, count: object) -> None:
    data = report_data(contract)
    data["alert_count"] = count
    with pytest.raises(IncompatibleReportError, match="alert_count"):
        validate_report_data(data)


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize("location", ["alerts", "alert", "evidence", "explanation", "summary"])
@pytest.mark.parametrize("value", [None, True, "text", 3])
def test_container_types_are_strict(contract: ReportContract, location: str, value: object) -> None:
    data = report_data(contract)
    alert = data["alerts"][0]
    if location == "alerts":
        data["alerts"] = value
    elif location == "alert":
        data["alerts"][0] = value
    elif location == "summary":
        alert["explanation"]["evidence_summary"] = value
    else:
        alert[location] = value
    with pytest.raises(IncompatibleReportError):
        validate_report_data(data)


@pytest.mark.parametrize(("key", "value"), [("alerts", {}), ("evidence", []), ("summary", [])])
def test_array_object_confusion_is_rejected(key: str, value: object) -> None:
    data = report_data()
    if key == "alerts":
        data[key] = value
    elif key == "evidence":
        data["alerts"][0][key] = value
    else:
        data["alerts"][0]["explanation"]["evidence_summary"] = value
    with pytest.raises(IncompatibleReportError):
        validate_report_data(data)


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize(
    "timestamp",
    [
        None,
        7,
        True,
        "",
        "not-a-date",
        "2026-01-01",
        "2026-01-01T00:00:00",
        "2026-01-01T00:00",
        "2026-01-01T00:00+00:60",
        "2026-01-01T00:60Z",
        "2026-02-30T00:00Z",
        "2026-01-01T00:00+24:00",
        "2026-01-01T00:00:00+00:00:60",
        "2026-02-30T00:00:00Z",
        "2026-01-01T24:00:00Z",
        "2026-01-01T00:60:00Z",
        "2026-01-01T00:00:60Z",
        "2026-01-01X00:00:00Z",
        "2026-01-01T00:00:00+24:00",
        "2026-01-01T00:00:00+00:60",
        "2026-01-01T00:00:00+01:99",
        "2026-01-01T00:00:00Z\n",
        " 2026-01-01T00:00:00Z",
    ],
)
def test_invalid_timestamps(contract: ReportContract, timestamp: object) -> None:
    data = report_data(contract)
    data["generated_at"] = timestamp
    with pytest.raises(IncompatibleReportError, match="generated_at"):
        validate_report_data(data)


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:00:00.123456+05:30",
        "2026-01-01T00:00:00-07:00",
        "2024-02-29T23:59:59.5Z",
        "2026-01-01t00:00:00z",
        "2026-01-01T00:00Z",
        "2026-01-01T00:00+00:00",
        "2026-01-01T12:34+05:30",
        "2026-01-01T12:34-07:00",
        "2024-02-29T23:59Z",
        "2026-01-01t00:00z",
        "2026-01-01 12:34+05:30",
        "20260101T1234+0530",
        "20260101T123456Z",
        "2026-W01-4T12:34+05:30",
        "2026W014T1234Z",
        "2026-01-01T12+05",
        "2026-01-01T12:34:56,5Z",
        "2026-01-01T12:34:56+05:30:15",
    ],
)
def test_valid_timestamp_text_is_preserved(contract: ReportContract, timestamp: str) -> None:
    data = report_data(contract)
    data["generated_at"] = timestamp
    assert validate_report_data(data).data["generated_at"] == timestamp
    assert parse_report_json(json.dumps(data)).data == data


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize("key", ["possible_causes", "recommended_actions"])
@pytest.mark.parametrize(
    "value", [None, {}, "text", [1], [True], [None], [["nested"]], ["valid", 1]]
)
def test_explanation_lists_are_strict(contract: ReportContract, key: str, value: object) -> None:
    data = report_data(contract)
    data["alerts"][0]["explanation"][key] = value
    with pytest.raises(IncompatibleReportError, match=key):
        validate_report_data(data)


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize("key", ["possible_causes", "recommended_actions"])
@pytest.mark.parametrize("value", [[], [""], [" \t\n"], ["", " \t\n", "guidance"]])
def test_explanation_lists_allow_empty_content(
    contract: ReportContract, key: str, value: list[str]
) -> None:
    data = report_data(contract)
    data["alerts"][0]["explanation"][key] = value
    assert validate_report_data(data).data == data
    assert parse_report_json(json.dumps(data)).data == data


@pytest.mark.parametrize("contract", CONTRACTS)
def test_empty_explanation_lists_and_evidence_are_json_compatible(contract: ReportContract) -> None:
    data = report_data(contract)
    alert = data["alerts"][0]
    alert["evidence"] = {}
    alert["explanation"].update(possible_causes=[], recommended_actions=[], evidence_summary={})
    assert validate_report_data(data).data == data


@pytest.mark.parametrize("contract", CONTRACTS)
def test_rule_id_consistency_and_unknown_rule_ids(contract: ReportContract) -> None:
    data = report_data(contract)
    data["alerts"][0]["rule_id"] = "CUSTOM-999"
    with pytest.raises(IncompatibleReportError, match="parent alert rule_id"):
        validate_report_data(data)
    data["alerts"][0]["explanation"]["rule_id"] = "CUSTOM-999"
    assert validate_report_data(data).data == data


NON_JSON_VALUES = [
    {1: "non-string key"},
    {None: "non-string key"},
    (1, 2),
    {1, 2},
    b"bytes",
    bytearray(b"bytes"),
    Decimal("1.2"),
    Path("x"),
    datetime(2026, 1, 1, tzinfo=UTC),
    object(),
    float("nan"),
    float("inf"),
    float("-inf"),
]


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize("location", ["evidence", "summary"])
@pytest.mark.parametrize("value", NON_JSON_VALUES)
def test_recursive_evidence_requires_native_json(
    contract: ReportContract, location: str, value: object
) -> None:
    data = report_data(contract)
    target = data["alerts"][0]["evidence"]
    if location == "summary":
        target = data["alerts"][0]["explanation"]["evidence_summary"]
    target["nested"] = [{"deeper": value}]
    with pytest.raises(IncompatibleReportError):
        validate_report_data(data)


@pytest.mark.parametrize("contract", CONTRACTS)
@pytest.mark.parametrize("cycle_type", ["dict", "list"])
def test_cycles_fail_cleanly(contract: ReportContract, cycle_type: str) -> None:
    data = report_data(contract)
    evidence = data["alerts"][0]["evidence"]
    if cycle_type == "dict":
        evidence["self"] = evidence
    else:
        items = []
        items.append(items)
        evidence["self"] = items
    with pytest.raises(IncompatibleReportError, match="cyclic"):
        validate_report_data(data)


def test_shared_acyclic_json_values_are_allowed_and_copied() -> None:
    data = report_data()
    shared = {"values": [None, True, False, -1, 1.25, "text"]}
    data["alerts"][0]["evidence"] = {"a": shared, "b": shared}
    result = validate_report_data(data)
    shared["values"].append("later")
    assert result.data["alerts"][0]["evidence"] == {
        "a": {"values": [None, True, False, -1, 1.25, "text"]},
        "b": {"values": [None, True, False, -1, 1.25, "text"]},
    }


def test_deep_json_fails_cleanly_at_parser_or_validation_capacity() -> None:
    # Some decoders support deeper nesting than recursive Python validation.
    # The outcome must identify the boundary that actually rejected the input.
    depth = sys.getrecursionlimit() + 100
    data = report_data()
    data["alerts"][0]["evidence"]["nested"] = "DEEP_JSON_TOKEN"
    source = json.dumps(data).replace('"DEEP_JSON_TOKEN"', "[" * depth + "0" + "]" * depth)
    with pytest.raises((MalformedReportError, IncompatibleReportError)) as captured:
        parse_report_json(source)
    assert "recursion capacity" in str(captured.value)
    if isinstance(captured.value, MalformedReportError):
        assert captured.value.outcome is ReportValidationOutcome.MALFORMED
    else:
        assert captured.value.outcome is ReportValidationOutcome.INCOMPATIBLE


def test_parser_recursion_error_boundary(monkeypatch) -> None:
    def fail(*args, **kwargs):
        raise RecursionError("synthetic decoder recursion")

    monkeypatch.setattr(validation.json, "loads", fail)
    with pytest.raises(MalformedReportError, match="parser recursion"):
        parse_report_json("{}")


def test_validation_recursion_failure_is_incompatible() -> None:
    data = report_data()
    nested = data["alerts"][0]["evidence"]
    for _ in range(sys.getrecursionlimit() + 100):
        child = {}
        nested["child"] = child
        nested = child
    with pytest.raises(IncompatibleReportError, match="validation recursion"):
        validate_report_data(data)


def test_decoded_json_validation_recursion_failure_is_incompatible(monkeypatch) -> None:
    # Isolate the post-decoding boundary without depending on relative decoder
    # and validator recursion capacities across supported Python versions.
    def fail(*args, **kwargs):
        raise RecursionError("synthetic validation recursion")

    monkeypatch.setattr(validation, "_copy_json_value", fail)
    with pytest.raises(IncompatibleReportError, match="validation recursion"):
        parse_report_json((FIXTURE_DIR / "schema_v1_alert.json").read_bytes())


def test_moderate_nesting_has_no_arbitrary_fixed_limit() -> None:
    data = report_data()
    nested = data["alerts"][0]["evidence"]
    for _ in range(50):
        child = {}
        nested["child"] = child
        nested = child
    assert parse_report_json(json.dumps(data)).data == data


@pytest.mark.parametrize("contract", CONTRACTS)
def test_validated_snapshot_provenance_and_input_preservation(contract: ReportContract) -> None:
    data = report_data(contract)
    original = deepcopy(data)
    result = validate_report_data(data)
    assert data == original
    data["alerts"][0]["evidence"]["details"]["labels"].append("mutated input")
    exposed = result.data
    exposed["alerts"][0]["explanation"]["rule_id"] = "mutated output"
    serialized = result.to_dict()
    serialized["alerts"].clear()
    assert result.data == original
    assert result.contract is contract
    assert result.schema_version == (1 if contract is ReportContract.SCHEMA_V1 else None)
    with pytest.raises(FrozenInstanceError):
        result.contract = ReportContract.SCHEMA_V1
    assert (
        "schema_version" in result.data
        if contract is ReportContract.SCHEMA_V1
        else ("schema_version" not in result.data)
    )


@pytest.mark.parametrize("contract", CONTRACTS)
def test_invalid_input_is_not_mutated(contract: ReportContract) -> None:
    data = report_data(contract)
    data["alerts"][0]["risk_score"] = True
    original = deepcopy(data)
    with pytest.raises(IncompatibleReportError):
        validate_report_data(data)
    assert data == original


@pytest.mark.parametrize("contract", CONTRACTS)
def test_validates_all_alerts_and_preserves_order(contract: ReportContract) -> None:
    data = report_data(contract)
    second = deepcopy(data["alerts"][0])
    second["alert_id"] = "second-alert"
    second["rule_id"] = "CUSTOM-999"
    second["explanation"]["rule_id"] = "CUSTOM-999"
    data["alerts"].append(second)
    data["alert_count"] = 2
    assert validate_report_data(data).data == data
    second["risk_score"] = 101
    with pytest.raises(IncompatibleReportError, match=r"alerts\[1\].risk_score"):
        validate_report_data(data)


@pytest.mark.parametrize("include_explanations", [False, True])
@pytest.mark.parametrize("rule_id", ["AUTH-001", "CUSTOM-999"])
def test_schema_v1_writer_output_and_custom_thresholds(
    include_explanations: bool, rule_id: str
) -> None:
    event = create_security_event(
        source="sshd",
        event_type="ssh_failed_login",
        message="Synthetic failed login",
        evidence={"details": [None, 1.25, False]},
        host_id="synthetic-validation-test",
    )
    alert = replace(
        score_rule_match(
            detect_event(event)[0],
            thresholds={"low": 10, "medium": 20, "high": 40, "critical": 90},
        ),
        rule_id=rule_id,
    )
    data = create_alert_report([alert], include_explanations=include_explanations).to_dict()
    result = parse_report_json(json.dumps(data))
    assert set(result.data) == SCHEMA_V1_REPORT_TOP_LEVEL_KEYS
    assert result.contract is ReportContract.SCHEMA_V1
    assert result.outcome is ReportValidationOutcome.VALID_SCHEMA_V1
    assert result.schema_version == 1
    assert result.data == data
    assert result.data["alerts"][0]["risk_level"] == alert.risk_level


@pytest.mark.parametrize("include_explanations", [False, True])
def test_generated_empty_reports_use_schema_v1(include_explanations: bool) -> None:
    data = create_alert_report([], include_explanations=include_explanations).to_dict()
    result = validate_report_data(data)
    assert result.contract is ReportContract.SCHEMA_V1
    assert result.schema_version == 1
    assert set(result.data) == SCHEMA_V1_REPORT_TOP_LEVEL_KEYS
    assert result.data == data
