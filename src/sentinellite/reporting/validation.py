"""Canonical, side-effect-free alert-report parsing and validation.

``parse_report_json`` accepts UTF-8 bytes or JSON text and returns a
``ValidatedReport``. ``validate_report_data`` accepts already decoded data;
only the parser can establish that the source had no duplicate JSON keys.
``detect_report_contract`` identifies a candidate contract, not its validity.

Failures expose a ``ReportValidationOutcome`` through typed exceptions. JSON
decoding failures are malformed; decoded contract violations (including invalid
Unicode scalars, cycles, and validation recursion failures) are incompatible.
A positive future version on a SentinelLite alert-report object is unsupported
before inspecting its body.
No filesystem operations, scoring, or explanation generation occur here.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sentinellite.reporting.schema import (
    ALERT_ALLOWED_KEYS,
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

# Accept ISO date/time forms understood by the historical fromisoformat parser,
# including minute precision. Guard genuine ISO separators and component ranges
# because fromisoformat also tolerates arbitrary separators/normalizes offsets.
_TIMESTAMP_PATTERN = re.compile(
    r"(?:[0-9]{4}-?[0-9]{2}-?[0-9]{2}|[0-9]{4}-?W[0-9]{2}(?:-?[1-7])?)"
    r"[Tt ](?P<hour>[0-9]{2})(?::?(?P<minute>[0-9]{2}))?"
    r"(?::?(?P<second>[0-9]{2}))?(?:[.,][0-9]+)?"
    r"(?:[Zz]|[+-](?P<offset_hour>[0-9]{2})(?::?(?P<offset_minute>[0-9]{2}))?"
    r"(?::?(?P<offset_second>[0-9]{2}))?(?:[.,][0-9]+)?)"
)


class ReportSchemaError(ValueError):
    """Base class for failures on the canonical validation path."""

    outcome: ReportValidationOutcome


class MalformedReportError(ReportSchemaError):
    """The input cannot be safely decoded as JSON."""

    outcome = ReportValidationOutcome.MALFORMED


class IncompatibleReportError(ReportSchemaError):
    """Decoded data does not satisfy a supported report contract."""

    outcome = ReportValidationOutcome.INCOMPATIBLE


class UnsupportedSchemaError(ReportSchemaError):
    """An alert report declares a positive future schema version."""

    outcome = ReportValidationOutcome.UNSUPPORTED_SCHEMA

    def __init__(self, schema_version: int) -> None:
        self.schema_version = schema_version
        # Keep the version as metadata; rendering arbitrarily large decoded
        # integers can itself exceed the interpreter's conversion limit.
        super().__init__("Unsupported alert-report schema version.")


@dataclass(frozen=True, slots=True)
class ValidatedReport:
    """Validated snapshot with explicit contract provenance.

    Accessors return defensive copies, so neither subsequent input mutations nor
    consumer edits invalidate the snapshot. Legacy data never acquires a version
    field. Construct results through the canonical parser or validator.
    """

    contract: ReportContract
    _data: dict[str, Any] = field(repr=False)

    @property
    def outcome(self) -> ReportValidationOutcome:
        if self.contract is ReportContract.SCHEMA_V1:
            return ReportValidationOutcome.VALID_SCHEMA_V1
        return ReportValidationOutcome.VALID_LEGACY_UNVERSIONED

    @property
    def schema_version(self) -> int | None:
        if self.contract is ReportContract.SCHEMA_V1:
            return ALERT_REPORT_SCHEMA_VERSION
        return None

    @property
    def data(self) -> dict[str, Any]:
        return self.to_dict()

    def to_dict(self) -> dict[str, Any]:
        return _copy_json_value(self._data, "$", set())


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key.")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError("Non-finite JSON number.")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Non-finite JSON number (numeric overflow).")
    return number


def parse_report_json(source: str | bytes | bytearray) -> ValidatedReport:
    """Decode strict JSON and validate it, returning data and contract provenance.

    Byte inputs must be UTF-8; the decoder's automatic UTF-16/32 detection is
    intentionally bypassed. Duplicate keys at every depth, non-finite constants,
    float overflow, and decoder recursion failures are malformed. Wrong API input
    types raise TypeError. No size or fixed nesting limit is introduced here.
    """
    if not isinstance(source, (str, bytes, bytearray)):
        raise TypeError("Report JSON must be text or UTF-8 bytes.")
    try:
        if isinstance(source, (bytes, bytearray)):
            source = source.decode("utf-8", errors="strict")
        else:
            source.encode("utf-8", errors="strict")
        data = json.loads(
            source,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except UnicodeError as error:
        raise MalformedReportError("Report JSON is not valid UTF-8.") from error
    except json.JSONDecodeError as error:
        raise MalformedReportError(
            f"Malformed JSON at line {error.lineno}, column {error.colno}."
        ) from error
    except RecursionError as error:
        raise MalformedReportError("Report JSON exceeds the parser recursion capacity.") from error
    except ValueError as error:
        # Includes strict hooks and the interpreter's integer conversion limit.
        raise MalformedReportError(f"Malformed JSON: {error}") from error
    return validate_report_data(data)


def detect_report_contract(data: object) -> ReportContract:
    """Identify a candidate contract without validating its envelope or alerts.

    Check report identity first, so unrelated versioned artifacts are incompatible.
    An absent version selects legacy; a present version must be an exact positive
    integer (never a boolean). Future versions are not interpreted as schema v1.
    """
    if type(data) is not dict:
        raise IncompatibleReportError("Report top level must be a JSON object.")
    if type(data.get("report_type")) is not str or data["report_type"] != ALERT_REPORT_TYPE:
        raise IncompatibleReportError(f"$.report_type must equal {ALERT_REPORT_TYPE!r}.")
    if "schema_version" not in data:
        return ReportContract.LEGACY_UNVERSIONED
    version = data["schema_version"]
    if type(version) is not int or version < 1:
        raise IncompatibleReportError("$.schema_version must be a positive integer.")
    if version != ALERT_REPORT_SCHEMA_VERSION:
        raise UnsupportedSchemaError(version)
    return ReportContract.SCHEMA_V1


def _copy_json_value(value: Any, path: str, active: set[int]) -> Any:
    """Check JSON-native values and snapshot them; detect cycles, allow aliases."""
    if type(value) is str:
        _unicode_string(value, path)
        return value
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise IncompatibleReportError(f"{path} must contain only finite JSON numbers.")
        return value
    if type(value) not in (dict, list):
        raise IncompatibleReportError(f"{path} must contain only JSON-native values.")
    identity = id(value)
    if identity in active:
        raise IncompatibleReportError(f"{path} contains a cyclic JSON value.")
    active.add(identity)
    try:
        if type(value) is list:
            return [
                _copy_json_value(item, f"{path}[{index}]", active)
                for index, item in enumerate(value)
            ]
        result = {}
        for key, item in value.items():
            if type(key) is not str:
                raise IncompatibleReportError(f"{path} JSON object keys must be strings.")
            _unicode_string(key, path)
            result[key] = _copy_json_value(item, f"{path}[{key!r}]", active)
        return result
    finally:
        active.remove(identity)


def _object_fields(
    value: object, required: frozenset[str], allowed: frozenset[str], path: str
) -> dict[str, Any]:
    if type(value) is not dict:
        raise IncompatibleReportError(f"{path} must be a JSON object.")
    missing = required - value.keys()
    if missing:
        raise IncompatibleReportError(
            f"{path} missing required fields: {', '.join(sorted(missing))}."
        )
    if value.keys() - allowed:
        raise IncompatibleReportError(f"{path} contains unexpected fields.")
    return value


def _unicode_string(value: str, path: str) -> None:
    """Reject surrogate code points, without filtering valid Unicode/control text."""
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise IncompatibleReportError(f"{path} contains an invalid Unicode scalar.") from error


def _string(value: object, path: str) -> str:
    if type(value) is not str:
        raise IncompatibleReportError(f"{path} must be a string.")
    return value


def _identifier(value: object, path: str) -> str:
    value = _string(value, path)
    if not value.strip():
        raise IncompatibleReportError(f"{path} must be a non-empty identifier.")
    return value


def _enum(value: object, allowed: frozenset[str], path: str) -> None:
    if type(value) is not str or value not in allowed:
        raise IncompatibleReportError(f"{path} must be one of: {', '.join(sorted(allowed))}.")


def _timestamp(value: object) -> None:
    path = "$.generated_at"
    value = _string(value, path)
    match = _TIMESTAMP_PATTERN.fullmatch(value)
    if match is None:
        raise IncompatibleReportError(f"{path} must be a timezone-aware ISO datetime.")
    for component, maximum in (
        ("hour", 23),
        ("minute", 59),
        ("second", 59),
        ("offset_hour", 23),
        ("offset_minute", 59),
        ("offset_second", 59),
    ):
        number = match[component]
        if number is not None and int(number) > maximum:
            raise IncompatibleReportError(f"{path} contains an invalid {component}.")
    try:
        timestamp = datetime.fromisoformat(value.replace("z", "Z"))
    except ValueError as error:
        raise IncompatibleReportError(f"{path} contains an invalid datetime.") from error
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise IncompatibleReportError(f"{path} must include a timezone.")


def _explanation(value: object, parent_rule_id: str, path: str) -> None:
    value = _object_fields(value, EXPLANATION_REQUIRED_KEYS, EXPLANATION_REQUIRED_KEYS, path)
    for key in ("rule_id", "title", "summary", "why_it_matched"):
        _string(value[key], f"{path}.{key}")
    _identifier(value["rule_id"], f"{path}.rule_id")
    _enum(value["confidence"], EXPLANATION_CONFIDENCE_VALUES, f"{path}.confidence")
    if value["rule_id"] != parent_rule_id:
        raise IncompatibleReportError(f"{path}.rule_id must equal the parent alert rule_id.")
    for key in ("possible_causes", "recommended_actions"):
        items = value[key]
        if type(items) is not list:
            raise IncompatibleReportError(f"{path}.{key} must be a list of strings.")
        for index, item in enumerate(items):
            _string(item, f"{path}.{key}[{index}]")
    if type(value["evidence_summary"]) is not dict:
        raise IncompatibleReportError(f"{path}.evidence_summary must be a JSON object.")


def _validate_contract(data: dict[str, Any], contract: ReportContract) -> None:
    versioned = contract is ReportContract.SCHEMA_V1
    report_keys = SCHEMA_V1_REPORT_TOP_LEVEL_KEYS if versioned else LEGACY_REPORT_TOP_LEVEL_KEYS
    _object_fields(data, report_keys, report_keys, "$")
    _identifier(data["report_id"], "$.report_id")
    _timestamp(data["generated_at"])
    count = data["alert_count"]
    if type(count) is not int or count < 0:
        raise IncompatibleReportError("$.alert_count must be a non-negative integer.")
    alerts = data["alerts"]
    if type(alerts) is not list:
        raise IncompatibleReportError("$.alerts must be a JSON array.")
    if count != len(alerts):
        raise IncompatibleReportError("$.alert_count does not match the length of $.alerts.")
    required = ALERT_REQUIRED_KEYS if versioned else LEGACY_ALERT_REQUIRED_KEYS
    allowed = ALERT_ALLOWED_KEYS if versioned else LEGACY_ALERT_ALLOWED_KEYS
    for index, alert in enumerate(alerts):
        path = f"$.alerts[{index}]"
        _object_fields(alert, required, allowed, path)
        for key in sorted(required - {"base_score", "risk_score", "evidence"}):
            _string(alert[key], f"{path}.{key}")
        for key in ("alert_id", "rule_id", "event_id"):
            _identifier(alert[key], f"{path}.{key}")
        _enum(alert["severity"], SEVERITY_VALUES, f"{path}.severity")
        _enum(alert["risk_level"], RISK_LEVEL_VALUES, f"{path}.risk_level")
        for key in ("base_score", "risk_score"):
            score = alert[key]
            if type(score) is not int or not ALERT_SCORE_MIN <= score <= ALERT_SCORE_MAX:
                raise IncompatibleReportError(
                    f"{path}.{key} must be an integer from {ALERT_SCORE_MIN} to {ALERT_SCORE_MAX}."
                )
        if type(alert["evidence"]) is not dict:
            raise IncompatibleReportError(f"{path}.evidence must be a JSON object.")
        if "explanation" in alert:
            _explanation(alert["explanation"], alert["rule_id"], f"{path}.explanation")


def validate_report_data(data: object) -> ValidatedReport:
    """Validate decoded data and snapshot it under its original contract.

    Enforce exact envelopes, complete alerts/explanations, JSON-native evidence,
    Unicode scalar strings (including object keys), non-empty identifiers,
    finite numbers, and stored score/level validity independently. This API cannot
    recover duplicate keys already discarded by a different JSON decoder; use
    ``parse_report_json`` at untrusted JSON boundaries.
    """
    try:
        contract = detect_report_contract(data)
        snapshot = _copy_json_value(data, "$", set())
        _validate_contract(snapshot, contract)
    except RecursionError as error:
        raise IncompatibleReportError(
            "Report exceeds the validation recursion capacity."
        ) from error
    return ValidatedReport(contract=contract, _data=snapshot)
