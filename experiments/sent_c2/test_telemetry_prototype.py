"""Synthetic validation tests for the isolated SENT-C2 telemetry prototype."""

from __future__ import annotations

import json
import socket
import traceback
import urllib.request
from pathlib import Path

import pytest

from experiments.sent_c2.telemetry_prototype import (
    MAX_GROUPS,
    MAX_INPUT_ALERTS,
    MAX_INPUT_BYTES,
    MAX_OUTPUT_BYTES,
    TELEMETRY_GROUP_KEYS,
    TELEMETRY_OUTPUT_TYPE,
    TELEMETRY_SCHEMA_VERSION,
    TELEMETRY_TOP_LEVEL_KEYS,
    TelemetryError,
    TelemetryOutcome,
    export_telemetry_bytes,
    parse_telemetry_json,
    serialize_telemetry_json,
    validate_telemetry_data,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = PROJECT_ROOT / "tests/fixtures/report_schema"

FIXED_EXPORT_ID = "12345678-1234-4123-8123-123456789abc"
FIXED_EXPORTED_AT = "2026-11-27T12:00:00Z"


def _make_alert(
    index: int = 1,
    *,
    rule_id: str = "AUTH-001",
    severity: str = "medium",
    risk_level: str = "medium",
    canary: str = "CANARY_SAFE",
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
        "evidence": {"user": canary, "ip": "192.0.2.10"},
    }


def _make_report(
    alerts: list[dict[str, object]],
    *,
    schema_version: int | None = 1,
    report_id: str = "report-canary-001",
) -> bytes:
    payload: dict[str, object] = {
        "report_id": report_id,
        "report_type": "sentinellite_alert_report",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "alert_count": len(alerts),
        "alerts": alerts,
    }
    if schema_version is not None:
        payload["schema_version"] = schema_version
    return json.dumps(payload).encode("utf-8")


def _make_telemetry_payload(
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
    rules = [
        "AUTH-001", "AUTH-002", "AUTH-003",
        "PROC-001", "PROC-002", "PROC-003",
        "NET-001", "NET-002", "NET-003",
        "FIM-001", "FIM-002", "FIM-003", "FIM-004",
        "FIM-005", "FIM-006", "FIM-007", "FIM-008",
    ]
    sevs = ["info", "low", "medium", "high", "critical"]
    alerts: list[dict[str, object]] = []
    idx = 0
    for rule_id in rules:
        for sev in sevs:
            for rl in sevs:
                if idx < MAX_GROUPS:
                    alerts.append(
                        _make_alert(idx, rule_id=rule_id, severity=sev, risk_level=rl)
                    )
                    idx += 1
    return alerts


def test_1_valid_schema_v1_fixture() -> None:
    raw = (FIXTURES_DIR / "schema_v1_alert.json").read_bytes()
    out = json.loads(
        export_telemetry_bytes(
            raw, export_id=FIXED_EXPORT_ID, exported_at=FIXED_EXPORTED_AT
        ).decode("utf-8")
    )
    assert set(out) == TELEMETRY_TOP_LEVEL_KEYS
    assert out["schema_version"] == TELEMETRY_SCHEMA_VERSION
    assert out["output_type"] == TELEMETRY_OUTPUT_TYPE
    assert out["alert_count"] >= 1


def test_2_valid_legacy_unversioned_fixture_and_16_source_preservation() -> None:
    legacy_path = FIXTURES_DIR / "legacy_unversioned_alert.json"
    before = legacy_path.read_bytes()
    out = json.loads(
        export_telemetry_bytes(
            before, export_id=FIXED_EXPORT_ID, exported_at=FIXED_EXPORTED_AT
        ).decode("utf-8")
    )
    assert out["schema_version"] == 1
    assert out["alert_count"] >= 1
    assert legacy_path.read_bytes() == before


def test_3_empty_alert_report() -> None:
    out = json.loads(
        export_telemetry_bytes(
            _make_report([]), export_id=FIXED_EXPORT_ID, exported_at=FIXED_EXPORTED_AT
        ).decode("utf-8")
    )
    assert out["alert_count"] == 0
    assert out["groups"] == []


def test_4_and_5_repeated_groups_and_multiple_severity_risk_combinations() -> None:
    alerts = [
        _make_alert(1, rule_id="AUTH-001", severity="medium", risk_level="medium"),
        _make_alert(2, rule_id="AUTH-001", severity="medium", risk_level="medium"),
        _make_alert(3, rule_id="AUTH-001", severity="high", risk_level="high"),
        _make_alert(4, rule_id="FIM-004", severity="high", risk_level="critical"),
    ]
    out = json.loads(
        export_telemetry_bytes(
            _make_report(alerts),
            export_id=FIXED_EXPORT_ID,
            exported_at=FIXED_EXPORTED_AT,
        ).decode("utf-8")
    )
    assert out["alert_count"] == 4
    assert out["groups"] == [
        {"rule_id": "AUTH-001", "severity": "high", "risk_level": "high", "count": 1},
        {"rule_id": "AUTH-001", "severity": "medium", "risk_level": "medium", "count": 2},
        {"rule_id": "FIM-004", "severity": "high", "risk_level": "critical", "count": 1},
    ]


def test_6_exact_field_allowlists_and_8_sensitive_canary_exclusion() -> None:
    canary = "SECRET_CANARY_USER_10_0_0_99"
    alert = _make_alert(1, canary=canary)
    alert["explanation"] = {
        "rule_id": "AUTH-001",
        "title": f"Title {canary}",
        "summary": f"Summary {canary}",
        "why_it_matched": f"Why {canary}",
        "possible_causes": [canary],
        "recommended_actions": [canary],
        "evidence_summary": {"rule_id": "AUTH-001", "message": canary},
        "confidence": "medium",
    }
    raw = _make_report([alert], report_id=f"rep-{canary}")
    encoded = export_telemetry_bytes(
        raw, export_id=FIXED_EXPORT_ID, exported_at=FIXED_EXPORTED_AT
    ).decode("utf-8")
    assert canary not in encoded
    parsed = json.loads(encoded)
    assert set(parsed) == TELEMETRY_TOP_LEVEL_KEYS
    for group in parsed["groups"]:
        assert set(group) == TELEMETRY_GROUP_KEYS


def test_c2_f01_exception_confidentiality_excludes_nested_evidence_canaries() -> None:
    canary = "NESTED_EVIDENCE_CANARY_KEY_SECRET"
    bad_report = {
        "schema_version": 1,
        "report_id": f"rep-{canary}",
        "report_type": "sentinellite_alert_report",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "alert_count": 1,
        "alerts": [
            {
                **_make_alert(1, canary=canary),
                "evidence": {canary: float("inf") if False else {"nested": [1, 2]}},
                "unexpected_extra": canary,
            }
        ],
    }
    # Force canonical incompatibility with nested canary key name inside alert/evidence
    bad_report["alerts"][0]["evidence"] = {canary: "not-valid-with-extra"}
    raw = json.dumps(bad_report).encode("utf-8")

    try:
        export_telemetry_bytes(raw)
    except TelemetryError as exc:
        formatted_tb = traceback.format_exc()
        assert exc.outcome is TelemetryOutcome.INCOMPATIBLE
        assert canary not in str(exc)
        assert canary not in formatted_tb
        assert exc.__cause__ is None
    else:
        raise AssertionError("Expected TelemetryError for incompatible report.")


@pytest.mark.parametrize(
    "bad_rule",
    ["CUSTOM-001", "AUTH-999", "AUTH-001; DROP TABLE", "user:alice"],
)
def test_7_unknown_and_malicious_rule_id_rejection(bad_rule: str) -> None:
    raw = _make_report([_make_alert(1, rule_id=bad_rule)])
    with pytest.raises(TelemetryError) as exc:
        export_telemetry_bytes(raw)
    assert exc.value.outcome is TelemetryOutcome.UNSUPPORTED_RULE
    assert bad_rule not in str(exc.value)


def test_9_unknown_telemetry_fields_and_nested_group_injection() -> None:
    top_extra = _make_telemetry_payload()
    top_extra["extra"] = {"nested": "secret"}
    with pytest.raises(TelemetryError) as exc1:
        validate_telemetry_data(top_extra)
    assert exc1.value.outcome is TelemetryOutcome.INCOMPATIBLE

    group_extra = _make_telemetry_payload(
        alert_count=1,
        groups=[
            {
                "rule_id": "AUTH-001",
                "severity": "medium",
                "risk_level": "medium",
                "count": 1,
                "extra": {"nested": "secret"},
            }
        ],
    )
    with pytest.raises(TelemetryError) as exc2:
        validate_telemetry_data(group_extra)
    assert exc2.value.outcome is TelemetryOutcome.INCOMPATIBLE


@pytest.mark.parametrize(
    "field,value,expected_outcome",
    [
        ("schema_version", True, TelemetryOutcome.INCOMPATIBLE),
        ("schema_version", 0, TelemetryOutcome.INCOMPATIBLE),
        ("schema_version", -1, TelemetryOutcome.INCOMPATIBLE),
        ("schema_version", 2, TelemetryOutcome.UNSUPPORTED_SCHEMA),
        ("output_type", "wrong_type", TelemetryOutcome.INCOMPATIBLE),
        ("alert_count", False, TelemetryOutcome.INCOMPATIBLE),
        ("alert_count", -1, TelemetryOutcome.INCOMPATIBLE),
        ("alert_count", 1.5, TelemetryOutcome.INCOMPATIBLE),
        ("export_id", "not-a-uuid", TelemetryOutcome.INCOMPATIBLE),
        ("export_id", FIXED_EXPORT_ID.upper(), TelemetryOutcome.INCOMPATIBLE),
        ("exported_at", "2026-11-27T12:00:00+00:00", TelemetryOutcome.INCOMPATIBLE),
        ("exported_at", "2026-11-27T12:00:00-05:00", TelemetryOutcome.INCOMPATIBLE),
        ("exported_at", "2026-02-29T12:00:00Z", TelemetryOutcome.INCOMPATIBLE),
        ("exported_at", "2026-04-31T00:00:00Z", TelemetryOutcome.INCOMPATIBLE),
        ("exported_at", "2026-13-01T00:00:00Z", TelemetryOutcome.INCOMPATIBLE),
        ("exported_at", "2026-11-27T24:00:00Z", TelemetryOutcome.INCOMPATIBLE),
        ("exported_at", "2026-11-27T12:00:00.123Z", TelemetryOutcome.INCOMPATIBLE),
        ("exported_at", "2026-11-27T12:00:00.1234567Z", TelemetryOutcome.INCOMPATIBLE),
    ],
)
def test_10_invalid_scalar_types_dates_and_versions(
    field: str, value: object, expected_outcome: TelemetryOutcome
) -> None:
    payload = _make_telemetry_payload()
    payload[field] = value
    with pytest.raises(TelemetryError) as exc:
        validate_telemetry_data(payload)
    assert exc.value.outcome is expected_outcome


def test_c2_f03_leap_year_valid_utc_timestamp() -> None:
    payload = _make_telemetry_payload(exported_at="2024-02-29T23:59:59.123456Z")
    validated = validate_telemetry_data(payload)
    assert validated["exported_at"] == "2024-02-29T23:59:59.123456Z"


@pytest.mark.parametrize(
    "bad_group",
    [
        {"rule_id": "AUTH-001", "severity": "bogus", "risk_level": "medium", "count": 1},
        {"rule_id": "AUTH-001", "severity": "medium", "risk_level": "bogus", "count": 1},
        {"rule_id": "AUTH-001", "severity": "medium", "risk_level": "medium", "count": True},
        {"rule_id": "AUTH-001", "severity": "medium", "risk_level": "medium", "count": 1.0},
        {"rule_id": "AUTH-001", "severity": "medium", "risk_level": "medium", "count": 0},
        {"rule_id": "AUTH-001", "severity": "medium", "risk_level": "medium", "count": -1},
    ],
)
def test_c2_f04_invalid_group_enums_and_counts(bad_group: dict[str, object]) -> None:
    payload = _make_telemetry_payload(alert_count=1, groups=[bad_group])
    with pytest.raises(TelemetryError) as exc:
        validate_telemetry_data(payload)
    assert exc.value.outcome is TelemetryOutcome.INCOMPATIBLE


def test_11_malformed_utf8_surrogates_nonfinite_duplicate_keys_and_deep_nesting() -> None:
    # Duplicate keys
    with pytest.raises(TelemetryError) as exc1:
        export_telemetry_bytes(b'{"a": 1, "a": 2}')
    assert exc1.value.outcome is TelemetryOutcome.MALFORMED

    # Malformed JSON
    with pytest.raises(TelemetryError) as exc2:
        export_telemetry_bytes(b"{invalid")
    assert exc2.value.outcome is TelemetryOutcome.MALFORMED

    # Invalid UTF-8
    with pytest.raises(TelemetryError) as exc3:
        export_telemetry_bytes(b"\xff\xfe")
    assert exc3.value.outcome is TelemetryOutcome.MALFORMED

    # Lone surrogate in JSON string
    with pytest.raises(TelemetryError) as exc4:
        export_telemetry_bytes(b'{"a": "\\ud800"}')
    assert exc4.value.outcome is TelemetryOutcome.INCOMPATIBLE

    # Nonfinite number
    with pytest.raises(TelemetryError) as exc5:
        export_telemetry_bytes(b'{"a": NaN}')
    assert exc5.value.outcome is TelemetryOutcome.MALFORMED

    # Deep nesting (> Python recursion limit)
    deep = b"[" * 1500 + b"1" + b"]" * 1500
    with pytest.raises(TelemetryError) as exc6:
        export_telemetry_bytes(deep)
    assert exc6.value.outcome in {TelemetryOutcome.MALFORMED, TelemetryOutcome.INCOMPATIBLE}


def test_12_unsupported_versions() -> None:
    raw = (FIXTURES_DIR / "unsupported_schema_version.json").read_bytes()
    with pytest.raises(TelemetryError) as exc1:
        export_telemetry_bytes(raw)
    assert exc1.value.outcome is TelemetryOutcome.UNSUPPORTED_SCHEMA


def test_13_invalid_counts_duplicate_groups_and_unsorted_groups() -> None:
    dup_payload = _make_telemetry_payload(
        alert_count=2,
        groups=[
            {"rule_id": "AUTH-001", "severity": "medium", "risk_level": "medium", "count": 1},
            {"rule_id": "AUTH-001", "severity": "medium", "risk_level": "medium", "count": 1},
        ],
    )
    with pytest.raises(TelemetryError) as exc1:
        validate_telemetry_data(dup_payload)
    assert exc1.value.outcome is TelemetryOutcome.INCOMPATIBLE

    mismatch_payload = _make_telemetry_payload(
        alert_count=5,
        groups=[
            {"rule_id": "AUTH-001", "severity": "medium", "risk_level": "medium", "count": 1},
        ],
    )
    with pytest.raises(TelemetryError) as exc2:
        validate_telemetry_data(mismatch_payload)
    assert exc2.value.outcome is TelemetryOutcome.INCOMPATIBLE

    unsorted_payload = _make_telemetry_payload(
        alert_count=2,
        groups=[
            {"rule_id": "FIM-004", "severity": "high", "risk_level": "high", "count": 1},
            {"rule_id": "AUTH-001", "severity": "medium", "risk_level": "medium", "count": 1},
        ],
    )
    with pytest.raises(TelemetryError) as exc3:
        validate_telemetry_data(unsorted_payload)
    assert exc3.value.outcome is TelemetryOutcome.INCOMPATIBLE


def test_14_resource_limit_exact_boundaries() -> None:
    # Input size boundary: exact 2 MiB accepted, 2 MiB + 1 rejected
    base_raw = _make_report([_make_alert(1)])
    padded_exact = base_raw + b" " * (MAX_INPUT_BYTES - len(base_raw))
    assert len(padded_exact) == MAX_INPUT_BYTES
    assert export_telemetry_bytes(
        padded_exact, export_id=FIXED_EXPORT_ID, exported_at=FIXED_EXPORTED_AT
    )
    with pytest.raises(TelemetryError) as exc_size:
        export_telemetry_bytes(padded_exact + b" ")
    assert exc_size.value.outcome is TelemetryOutcome.LIMIT_EXCEEDED

    # Alert count boundary: exact 1,000 accepted, 1,001 rejected
    ok_alerts = [_make_alert(i) for i in range(MAX_INPUT_ALERTS)]
    out_ok = json.loads(
        export_telemetry_bytes(
            _make_report(ok_alerts),
            export_id=FIXED_EXPORT_ID,
            exported_at=FIXED_EXPORTED_AT,
        ).decode("utf-8")
    )
    assert out_ok["alert_count"] == MAX_INPUT_ALERTS

    too_many_alerts = [_make_alert(i) for i in range(MAX_INPUT_ALERTS + 1)]
    with pytest.raises(TelemetryError) as exc_alerts:
        export_telemetry_bytes(_make_report(too_many_alerts))
    assert exc_alerts.value.outcome is TelemetryOutcome.LIMIT_EXCEEDED

    # Group cardinality boundary: exact 128 accepted, 129 rejected
    alerts_128 = _make_128_group_alerts()
    largest_bytes = export_telemetry_bytes(
        _make_report(alerts_128),
        export_id=FIXED_EXPORT_ID,
        exported_at=FIXED_EXPORTED_AT,
    )
    largest_data = json.loads(largest_bytes.decode("utf-8"))
    assert len(largest_data["groups"]) == MAX_GROUPS
    # Largest feasible valid payload under 128-group cap is well below 64 KiB
    assert len(largest_bytes) < MAX_OUTPUT_BYTES

    alerts_129 = [*alerts_128, _make_alert(999, rule_id="FIM-008", severity="critical", risk_level="critical")]
    with pytest.raises(TelemetryError) as exc_groups:
        export_telemetry_bytes(_make_report(alerts_129))
    assert exc_groups.value.outcome is TelemetryOutcome.LIMIT_EXCEEDED

    # Serialization guard exercised at and above exact reduced boundary
    assert serialize_telemetry_json(largest_data, max_output_bytes=len(largest_bytes)) == largest_bytes
    with pytest.raises(TelemetryError) as exc_out:
        serialize_telemetry_json(largest_data, max_output_bytes=len(largest_bytes) - 1)
    assert exc_out.value.outcome is TelemetryOutcome.LIMIT_EXCEEDED


def test_15_deterministic_serialization_with_fixed_id_and_time() -> None:
    raw = _make_report([_make_alert(1), _make_alert(2, rule_id="FIM-004")])
    first = export_telemetry_bytes(
        raw, export_id=FIXED_EXPORT_ID, exported_at=FIXED_EXPORTED_AT
    )
    second = export_telemetry_bytes(
        raw, export_id=FIXED_EXPORT_ID, exported_at=FIXED_EXPORTED_AT
    )
    assert first == second


def test_17_no_network_calls_or_credential_acquisition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _forbid(*args: object, **kwargs: object) -> None:
        raise AssertionError("Network access is forbidden during offline telemetry export.")

    monkeypatch.setattr(socket, "socket", _forbid)
    monkeypatch.setattr(socket, "create_connection", _forbid)
    monkeypatch.setattr(urllib.request, "urlopen", _forbid)
    raw = _make_report([_make_alert(1)])
    out = export_telemetry_bytes(
        raw, export_id=FIXED_EXPORT_ID, exported_at=FIXED_EXPORTED_AT
    )
    assert parse_telemetry_json(out)["export_id"] == FIXED_EXPORT_ID


def test_c2_f05_saved_telemetry_parser_strict_validation() -> None:
    raw_report = _make_report([_make_alert(1)])
    saved_bytes = export_telemetry_bytes(
        raw_report, export_id=FIXED_EXPORT_ID, exported_at=FIXED_EXPORTED_AT
    )
    parsed = parse_telemetry_json(saved_bytes)
    assert parsed["export_id"] == FIXED_EXPORT_ID
    assert parsed["alert_count"] == 1

    # Reject duplicate keys, nonfinite numbers, invalid UTF-8, lone surrogates, oversized
    for bad_input, expected_outcome in (
        (b'{"schema_version": 1, "schema_version": 1}', TelemetryOutcome.MALFORMED),
        (b'{"schema_version": NaN}', TelemetryOutcome.MALFORMED),
        (b"{broken", TelemetryOutcome.MALFORMED),
        (b"\xff\xfe", TelemetryOutcome.MALFORMED),
        (b'{"export_id": "\\ud800"}', TelemetryOutcome.INCOMPATIBLE),
        (b" " * (MAX_OUTPUT_BYTES + 1), TelemetryOutcome.LIMIT_EXCEEDED),
    ):
        with pytest.raises(TelemetryError) as exc:
            parse_telemetry_json(bad_input)
        assert exc.value.outcome is expected_outcome
