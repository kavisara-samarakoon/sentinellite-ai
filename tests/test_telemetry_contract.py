"""Contract, privacy, nesting-depth, and boundary tests for sentinellite.reporting.telemetry."""

from __future__ import annotations

import json
import traceback
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from sentinellite.reporting.schema import RISK_LEVEL_VALUES, SEVERITY_VALUES
from sentinellite.reporting.telemetry import (
    MAX_GROUPS,
    MAX_INPUT_ALERTS,
    MAX_INPUT_BYTES,
    MAX_JSON_NESTING_DEPTH,
    MAX_OUTPUT_BYTES,
    MAX_SAVED_TELEMETRY_BYTES,
    TELEMETRY_ALLOWED_RULE_IDS,
    TELEMETRY_GROUP_KEYS,
    TELEMETRY_OUTPUT_TYPE,
    TELEMETRY_SCHEMA_VERSION,
    TELEMETRY_TOP_LEVEL_KEYS,
    TelemetryError,
    TelemetryLimitExceededError,
    TelemetryOutcome,
    check_json_nesting_depth,
    parse_telemetry_json,
    project_telemetry_from_bytes,
    serialize_telemetry_json,
    validate_telemetry_data,
)
from sentinellite.reporting.validation import IncompatibleReportError, parse_report_json

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = PROJECT_ROOT / "tests/fixtures/report_schema"
FIXED_EXPORT_ID = "12345678-1234-4123-8123-123456789abc"
FIXED_EXPORTED_AT = "2026-11-27T12:00:00Z"


def _make_alert(
    index: int = 1,
    *,
    rule_id: str = "AUTH-001",
    severity: str = "medium",
    risk_level: str = "medium",
    canary: str = "SAFE",
    evidence: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "alert_id": f"alert-{index}",
        "rule_id": rule_id,
        "rule_name": f"Rule {canary}",
        "category": f"cat-{canary}",
        "severity": severity,
        "base_score": 50,
        "risk_score": 50,
        "risk_level": risk_level,
        "event_id": f"event-{index}",
        "event_type": "ssh_failed_login",
        "source": f"/var/log/{canary}",
        "message": f"User {canary} from 192.0.2.10",
        "description": f"Desc {canary}",
        "recommendation": f"Rec {canary}",
        "evidence": {"user": canary, "ip": "192.0.2.10"} if evidence is None else evidence,
    }


def _make_report(
    alerts: list[dict[str, object]],
    *,
    schema_version: int | None = 1,
    report_id: str = "report-001",
    generated_at: str = "2026-01-01T00:00:00+00:00",
) -> bytes:
    payload: dict[str, object] = {
        "report_id": report_id,
        "report_type": "sentinellite_alert_report",
        "generated_at": generated_at,
        "alert_count": len(alerts),
        "alerts": alerts,
    }
    if schema_version is not None:
        payload["schema_version"] = schema_version
    return json.dumps(payload).encode("utf-8")


def _make_telemetry_dict(
    *,
    schema_version: object = 1,
    output_type: object = TELEMETRY_OUTPUT_TYPE,
    export_id: object = FIXED_EXPORT_ID,
    exported_at: object = FIXED_EXPORTED_AT,
    alert_count: object = 0,
    groups: object = None,
) -> dict[str, object]:
    return {
        "schema_version": schema_version,
        "output_type": output_type,
        "export_id": export_id,
        "exported_at": exported_at,
        "alert_count": alert_count,
        "groups": [] if groups is None else groups,
    }


def _make_128_group_alerts() -> list[dict[str, object]]:
    alerts: list[dict[str, object]] = []
    idx = 0
    for rule_id in sorted(TELEMETRY_ALLOWED_RULE_IDS):
        for sev in sorted(SEVERITY_VALUES):
            for rl in sorted(RISK_LEVEL_VALUES):
                if idx < MAX_GROUPS:
                    alerts.append(_make_alert(idx, rule_id=rule_id, severity=sev, risk_level=rl))
                    idx += 1
    return alerts


@pytest.mark.parametrize(
    "fixture_name",
    [
        "schema_v1_alert.json",
        "schema_v1_explanation.json",
        "legacy_unversioned_alert.json",
        "legacy_unversioned_explanation.json",
    ],
)
def test_schema_v1_and_legacy_fixtures_project_valid_telemetry(fixture_name: str) -> None:
    path = FIXTURES_DIR / fixture_name
    before = path.read_bytes()
    exported = project_telemetry_from_bytes(
        before, _export_id=FIXED_EXPORT_ID, _exported_at=FIXED_EXPORTED_AT
    )
    assert exported.schema_version == TELEMETRY_SCHEMA_VERSION
    assert exported.output_type == TELEMETRY_OUTPUT_TYPE
    assert exported.alert_count >= 1
    assert set(exported.to_dict()) == TELEMETRY_TOP_LEVEL_KEYS
    assert path.read_bytes() == before

    with pytest.raises(FrozenInstanceError):
        exported.alert_count = 999  # type: ignore[misc]


def test_empty_report_produces_zero_alerts_and_empty_groups() -> None:
    raw = (FIXTURES_DIR / "schema_v1_empty.json").read_bytes()
    exported = project_telemetry_from_bytes(
        raw, _export_id=FIXED_EXPORT_ID, _exported_at=FIXED_EXPORTED_AT
    )
    assert exported.alert_count == 0
    assert exported.groups == ()
    encoded = serialize_telemetry_json(exported)
    parsed = parse_telemetry_json(encoded)
    assert parsed == exported


def test_aggregation_and_deterministic_lexicographical_ordering() -> None:
    alerts = [
        _make_alert(1, rule_id="FIM-004", severity="high", risk_level="critical"),
        _make_alert(2, rule_id="AUTH-001", severity="medium", risk_level="medium"),
        _make_alert(3, rule_id="AUTH-001", severity="high", risk_level="high"),
        _make_alert(4, rule_id="AUTH-001", severity="medium", risk_level="medium"),
    ]
    exported = project_telemetry_from_bytes(
        _make_report(alerts),
        _export_id=FIXED_EXPORT_ID,
        _exported_at=FIXED_EXPORTED_AT,
    )
    assert exported.alert_count == 4
    assert [g.to_dict() for g in exported.groups] == [
        {"rule_id": "AUTH-001", "severity": "high", "risk_level": "high", "count": 1},
        {"rule_id": "AUTH-001", "severity": "medium", "risk_level": "medium", "count": 2},
        {"rule_id": "FIM-004", "severity": "high", "risk_level": "critical", "count": 1},
    ]


def test_all_17_allowed_rule_ids_accepted() -> None:
    assert len(TELEMETRY_ALLOWED_RULE_IDS) == 17
    alerts = [
        _make_alert(idx, rule_id=rule_id)
        for idx, rule_id in enumerate(sorted(TELEMETRY_ALLOWED_RULE_IDS))
    ]
    exported = project_telemetry_from_bytes(_make_report(alerts))
    assert exported.alert_count == 17
    assert {g.rule_id for g in exported.groups} == TELEMETRY_ALLOWED_RULE_IDS


@pytest.mark.parametrize(
    "bad_rule",
    ["CUSTOM-001", "AUTH-004", "AUTH-999", "user:alice", "AUTH-001; DROP TABLE"],
)
def test_unknown_and_arbitrary_rule_ids_rejected(bad_rule: str) -> None:
    raw = _make_report([_make_alert(1, rule_id=bad_rule)])
    with pytest.raises(TelemetryError) as exc:
        project_telemetry_from_bytes(raw)
    assert exc.value.outcome is TelemetryOutcome.UNSUPPORTED_RULE
    assert bad_rule not in str(exc.value)


def test_c01_genuine_nested_evidence_confidentiality() -> None:
    canary_key = "CANARY_SECRET_EVIDENCE_KEY_ALPHA99"
    nested_report = {
        "schema_version": 1,
        "report_id": "report-c01",
        "report_type": "sentinellite_alert_report",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "alert_count": 1,
        "alerts": [
            _make_alert(
                1,
                evidence={canary_key: {"inner_detail": "\ud800"}},
            )
        ],
    }
    raw = json.dumps(nested_report).encode("utf-8")

    # 1. Verify canonical parser directly exposes the canary key in its diagnostic path.
    with pytest.raises(IncompatibleReportError) as canonical_exc:
        parse_report_json(raw)
    assert canary_key in str(canonical_exc.value)

    # 2. Verify telemetry projection suppresses the parser chain and hides the canary.
    try:
        project_telemetry_from_bytes(raw)
    except TelemetryError as exc:
        tb = traceback.format_exc()
        assert exc.outcome is TelemetryOutcome.INCOMPATIBLE
        assert canary_key not in str(exc)
        assert canary_key not in tb
        assert exc.__cause__ is None
    else:
        raise AssertionError("Expected TelemetryError for invalid nested Unicode scalar.")


def test_canary_exclusion_across_all_omitted_source_fields() -> None:
    canary = "CANARY_SENSITIVE_VALUE_98765"
    alert = _make_alert(1, canary=canary)
    alert["explanation"] = {
        "rule_id": "AUTH-001",
        "title": f"Title {canary}",
        "summary": f"Summary {canary}",
        "why_it_matched": f"Why {canary}",
        "possible_causes": [canary],
        "recommended_actions": [canary],
        "evidence_summary": {"rule_id": "AUTH-001", "message": canary},
        "confidence": "high",
    }
    raw = _make_report(
        [alert],
        report_id=f"rep-{canary}",
        generated_at="2026-01-02T03:04:05+00:00",
    )
    encoded = serialize_telemetry_json(project_telemetry_from_bytes(raw)).decode("utf-8")
    assert canary not in encoded
    assert "2026-01-02T03:04:05" not in encoded
    parsed = json.loads(encoded)
    assert set(parsed) == TELEMETRY_TOP_LEVEL_KEYS
    for group in parsed["groups"]:
        assert set(group) == TELEMETRY_GROUP_KEYS


def test_independent_exports_generate_fresh_identities_and_saved_preserves() -> None:
    raw = _make_report([_make_alert(1)])
    first = project_telemetry_from_bytes(raw)
    second = project_telemetry_from_bytes(raw)
    assert first.export_id != second.export_id

    saved_bytes = serialize_telemetry_json(first)
    reparsed = parse_telemetry_json(saved_bytes)
    assert reparsed.export_id == first.export_id
    assert reparsed.exported_at == first.exported_at


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("schema_version", True, TelemetryOutcome.INCOMPATIBLE),
        ("schema_version", 0, TelemetryOutcome.INCOMPATIBLE),
        ("schema_version", -1, TelemetryOutcome.INCOMPATIBLE),
        ("schema_version", 2, TelemetryOutcome.UNSUPPORTED_SCHEMA),
        ("output_type", "sentinellite_notification_summary", TelemetryOutcome.INCOMPATIBLE),
        ("alert_count", False, TelemetryOutcome.INCOMPATIBLE),
        ("alert_count", -1, TelemetryOutcome.INCOMPATIBLE),
        ("alert_count", 1.5, TelemetryOutcome.INCOMPATIBLE),
        ("export_id", "not-a-uuid", TelemetryOutcome.INCOMPATIBLE),
        ("export_id", FIXED_EXPORT_ID.upper(), TelemetryOutcome.INCOMPATIBLE),
        ("exported_at", "2026-11-27T12:00:00+00:00", TelemetryOutcome.INCOMPATIBLE),
        ("exported_at", "2026-02-29T12:00:00Z", TelemetryOutcome.INCOMPATIBLE),
        ("exported_at", "2026-04-31T00:00:00Z", TelemetryOutcome.INCOMPATIBLE),
        ("exported_at", "2026-13-01T00:00:00Z", TelemetryOutcome.INCOMPATIBLE),
        ("exported_at", "2026-11-27T24:00:00Z", TelemetryOutcome.INCOMPATIBLE),
        ("exported_at", "2026-11-27T12:00:00.123Z", TelemetryOutcome.INCOMPATIBLE),
    ],
)
def test_invalid_scalar_types_dates_and_schema_versions(
    field: str, value: object, expected: TelemetryOutcome
) -> None:
    payload = _make_telemetry_dict()
    payload[field] = value
    with pytest.raises(TelemetryError) as exc:
        validate_telemetry_data(payload)
    assert exc.value.outcome is expected


def test_valid_leap_year_utc_timestamp() -> None:
    payload = _make_telemetry_dict(exported_at="2024-02-29T23:59:59.123456Z")
    assert validate_telemetry_data(payload).exported_at == "2024-02-29T23:59:59.123456Z"


def test_group_invariants_and_malformed_saved_inputs() -> None:
    # Mismatched total count
    with pytest.raises(TelemetryError) as exc1:
        validate_telemetry_data(
            _make_telemetry_dict(
                alert_count=2,
                groups=[
                    {
                        "rule_id": "AUTH-001",
                        "severity": "medium",
                        "risk_level": "medium",
                        "count": 1,
                    }
                ],
            )
        )
    assert exc1.value.outcome is TelemetryOutcome.INCOMPATIBLE

    # Duplicate groups
    with pytest.raises(TelemetryError) as exc2:
        validate_telemetry_data(
            _make_telemetry_dict(
                alert_count=2,
                groups=[
                    {
                        "rule_id": "AUTH-001",
                        "severity": "medium",
                        "risk_level": "medium",
                        "count": 1,
                    },
                    {
                        "rule_id": "AUTH-001",
                        "severity": "medium",
                        "risk_level": "medium",
                        "count": 1,
                    },
                ],
            )
        )
    assert exc2.value.outcome is TelemetryOutcome.INCOMPATIBLE

    # Unsorted groups
    with pytest.raises(TelemetryError) as exc3:
        validate_telemetry_data(
            _make_telemetry_dict(
                alert_count=2,
                groups=[
                    {"rule_id": "FIM-004", "severity": "high", "risk_level": "high", "count": 1},
                    {
                        "rule_id": "AUTH-001",
                        "severity": "medium",
                        "risk_level": "medium",
                        "count": 1,
                    },
                ],
            )
        )
    assert exc3.value.outcome is TelemetryOutcome.INCOMPATIBLE

    # Duplicate JSON keys, nonfinite, invalid UTF-8, lone surrogates, malformed JSON
    for bad_bytes, outcome in (
        (b'{"schema_version": 1, "schema_version": 1}', TelemetryOutcome.MALFORMED),
        (b'{"schema_version": NaN}', TelemetryOutcome.MALFORMED),
        (b'{"schema_version": Infinity}', TelemetryOutcome.MALFORMED),
        (b"\xff\xfe", TelemetryOutcome.MALFORMED),
        (b'{"export_id": "\\ud800"}', TelemetryOutcome.INCOMPATIBLE),
        (b"{broken", TelemetryOutcome.MALFORMED),
    ):
        with pytest.raises(TelemetryError) as exc:
            parse_telemetry_json(bad_bytes)
        assert exc.value.outcome is outcome


def test_c02_explicit_nesting_depth_enforcement() -> None:
    assert MAX_JSON_NESTING_DEPTH == 64

    # Depth 64 mixed objects/arrays accepted by depth guard
    depth_64 = ('{"a":[' * 32) + "1" + ("]}" * 32)
    check_json_nesting_depth(depth_64)

    # Depth 65 rejected
    depth_65 = ('{"a":[' * 32) + '{"b":1}' + ("]}" * 32)
    with pytest.raises(TelemetryLimitExceededError) as exc:
        check_json_nesting_depth(depth_65)
    assert exc.value.outcome is TelemetryOutcome.LIMIT_EXCEEDED

    # Delimiters, escaped quotes, and escaped backslashes inside strings do NOT count
    string_heavy = '{"a": "{{{[[[\\"\\\\\\"[[[\\"}]]", "b": "\\\\\\\\[[[", "c": [1, 2]}'
    check_json_nesting_depth(string_heavy, max_depth=2)

    # Malformed deeply nested source bytes fail closed at depth 65 before parse_report_json
    with pytest.raises(TelemetryLimitExceededError):
        project_telemetry_from_bytes(("[" * 65).encode("utf-8"))

    # Valid report with depth 64 in nested evidence is accepted
    nested_evidence: dict[str, object] = {"leaf": "ok"}
    # Root report(1) -> alerts[](2) -> alert{}(3) -> evidence{}(4) -> 60 more dicts = 64
    cur: dict[str, object] = nested_evidence
    for i in range(60):
        nxt: dict[str, object] = {"n": i}
        cur["sub"] = nxt
        cur = nxt
    raw_64 = _make_report([_make_alert(1, evidence=nested_evidence)])
    assert project_telemetry_from_bytes(raw_64).alert_count == 1

    # Depth 65 in evidence is rejected
    cur["sub"] = {"too_deep": 1}
    raw_65 = _make_report([_make_alert(1, evidence=nested_evidence)])
    with pytest.raises(TelemetryLimitExceededError):
        project_telemetry_from_bytes(raw_65)


def test_resource_limit_exact_boundaries() -> None:
    # Exactly 2 MiB accepted, 2 MiB + 1 rejected
    base = _make_report([_make_alert(1)])
    exact_2mib = base + b" " * (MAX_INPUT_BYTES - len(base))
    assert len(exact_2mib) == MAX_INPUT_BYTES
    assert project_telemetry_from_bytes(exact_2mib).alert_count == 1
    with pytest.raises(TelemetryLimitExceededError):
        project_telemetry_from_bytes(exact_2mib + b" ")

    # Exactly 1,000 alerts accepted, 1,001 rejected
    alerts_1000 = [_make_alert(i) for i in range(MAX_INPUT_ALERTS)]
    assert project_telemetry_from_bytes(_make_report(alerts_1000)).alert_count == 1000
    with pytest.raises(TelemetryLimitExceededError):
        project_telemetry_from_bytes(_make_report([*alerts_1000, _make_alert(1001)]))

    # Exactly 128 groups accepted, 129 rejected; largest feasible payload < 64 KiB
    alerts_128 = _make_128_group_alerts()
    largest_export = project_telemetry_from_bytes(
        _make_report(alerts_128),
        _export_id=FIXED_EXPORT_ID,
        _exported_at=FIXED_EXPORTED_AT,
    )
    assert len(largest_export.groups) == MAX_GROUPS
    largest_bytes = serialize_telemetry_json(largest_export)
    assert len(largest_bytes) < MAX_OUTPUT_BYTES

    alerts_129 = [
        *alerts_128,
        _make_alert(999, rule_id="FIM-008", severity="critical", risk_level="critical"),
    ]
    with pytest.raises(TelemetryLimitExceededError):
        project_telemetry_from_bytes(_make_report(alerts_129))

    # Serialization guard exercised at exact boundary and -1
    assert (
        serialize_telemetry_json(largest_export, _max_output_bytes=len(largest_bytes))
        == largest_bytes
    )
    with pytest.raises(TelemetryLimitExceededError):
        serialize_telemetry_json(largest_export, _max_output_bytes=len(largest_bytes) - 1)

    # Saved telemetry 64 KiB vs 64 KiB + 1
    padded_saved = largest_bytes + b" " * (MAX_SAVED_TELEMETRY_BYTES - len(largest_bytes))
    assert len(padded_saved) == MAX_SAVED_TELEMETRY_BYTES
    assert parse_telemetry_json(padded_saved).alert_count == MAX_GROUPS
    with pytest.raises(TelemetryLimitExceededError):
        parse_telemetry_json(padded_saved + b" ")
