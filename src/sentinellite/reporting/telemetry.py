"""Canonical offline telemetry schema-v1 projection, validation, and serialization.

This module provides a privacy-minimized, allowlist-only telemetry export
contract derived from one validated SentinelLite alert report. It reuses
``parse_report_json`` without altering alert-report or notification-summary
contracts, and performs no filesystem or network operations.

Security boundary notes:
- Public ``TelemetryError`` diagnostics are fixed, sanitized strings with
  suppressed parser exception chains (``from None``). They do not protect against
  privileged debugging or process-memory inspection.
- Byte and container-depth caps reduce resource exhaustion risks, but do not
  guarantee a precise peak-memory bound during Python JSON decoding.
"""

from __future__ import annotations

import json
import math
import re
import uuid
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sentinellite.reporting.schema import RISK_LEVEL_VALUES, SEVERITY_VALUES
from sentinellite.reporting.validation import (
    IncompatibleReportError,
    MalformedReportError,
    UnsupportedSchemaError,
    parse_report_json,
)

TELEMETRY_SCHEMA_VERSION = 1
TELEMETRY_OUTPUT_TYPE = "sentinellite_telemetry"

MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_INPUT_ALERTS = 1000
MAX_GROUPS = 128
MAX_OUTPUT_BYTES = 64 * 1024
MAX_SAVED_TELEMETRY_BYTES = 64 * 1024
MAX_JSON_NESTING_DEPTH = 64

TELEMETRY_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "output_type",
        "export_id",
        "exported_at",
        "alert_count",
        "groups",
    }
)
TELEMETRY_GROUP_KEYS = frozenset({"rule_id", "severity", "risk_level", "count"})

# Frozen v1 rule-ID allowlist; do not auto-expand when future detection rules are added.
TELEMETRY_ALLOWED_RULE_IDS = frozenset(
    {
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
    }
)

_UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_UTC_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{6})?Z$"
)


class TelemetryOutcome(StrEnum):
    """Declared outcomes for offline telemetry projection, parsing, and I/O."""

    MALFORMED = "malformed"
    INCOMPATIBLE = "incompatible"
    UNSUPPORTED_SCHEMA = "unsupported-schema"
    UNSUPPORTED_RULE = "unsupported-rule"
    LIMIT_EXCEEDED = "limit-exceeded"
    OUTPUT_ERROR = "output-error"


class TelemetryError(ValueError):
    """Base error for sanitized telemetry failures."""

    outcome: TelemetryOutcome

    def __init__(self, message: str, *, outcome: TelemetryOutcome | None = None) -> None:
        if outcome is not None:
            self.outcome = outcome
        super().__init__(message)


class TelemetryMalformedError(TelemetryError):
    outcome = TelemetryOutcome.MALFORMED


class TelemetryIncompatibleError(TelemetryError):
    outcome = TelemetryOutcome.INCOMPATIBLE


class TelemetryUnsupportedSchemaError(TelemetryError):
    outcome = TelemetryOutcome.UNSUPPORTED_SCHEMA


class TelemetryUnsupportedRuleError(TelemetryError):
    outcome = TelemetryOutcome.UNSUPPORTED_RULE


class TelemetryLimitExceededError(TelemetryError):
    outcome = TelemetryOutcome.LIMIT_EXCEEDED


class TelemetryOutputError(TelemetryError):
    outcome = TelemetryOutcome.OUTPUT_ERROR

    def __init__(self, message: str, *, published: bool = False) -> None:
        self.published = published
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class TelemetryGroup:
    """Aggregated alert count for one allowlisted (rule_id, severity, risk_level) key."""

    rule_id: str
    severity: str
    risk_level: str
    count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "risk_level": self.risk_level,
            "count": self.count,
        }


@dataclass(frozen=True, slots=True)
class TelemetryExport:
    """Immutable, validated telemetry schema-v1 snapshot."""

    schema_version: int
    output_type: str
    export_id: str
    exported_at: str
    alert_count: int
    groups: tuple[TelemetryGroup, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "output_type": self.output_type,
            "export_id": self.export_id,
            "exported_at": self.exported_at,
            "alert_count": self.alert_count,
            "groups": [group.to_dict() for group in self.groups],
        }


def check_json_nesting_depth(
    text: str,
    *,
    max_depth: int = MAX_JSON_NESTING_DEPTH,
) -> None:
    """Enforce maximum JSON container nesting depth before calling json.loads().

    Root object/array counts as depth 1; brackets and braces inside quoted JSON
    strings (respecting escaped quotes and backslashes) do not affect depth.
    """
    depth = 0
    in_string = False
    escaped = False

    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char in ("{", "["):
            depth += 1
            if depth > max_depth:
                raise TelemetryLimitExceededError(
                    f"JSON container nesting depth exceeds maximum of {max_depth}."
                )
        elif char in ("}", "]"):
            depth -= 1
            if depth < 0:
                # Defer syntax rejection to strict JSON parsing so malformed
                # inputs retain MALFORMED outcome rather than miscounting depth.
                return


def _is_exact_int(value: object) -> bool:
    return type(value) is int


def _validate_uuid4(value: object) -> str:
    if type(value) is not str or not _UUID4_RE.fullmatch(value):
        raise TelemetryIncompatibleError(
            "Telemetry export_id must be a canonical lowercase UUIDv4 string."
        )
    return value


def _validate_utc_timestamp(value: object) -> str:
    if type(value) is not str or not _UTC_TIMESTAMP_RE.fullmatch(value):
        raise TelemetryIncompatibleError(
            "Telemetry exported_at must be a canonical UTC ISO-8601 Z timestamp."
        )
    try:
        datetime.fromisoformat(value)
    except ValueError:
        raise TelemetryIncompatibleError(
            "Telemetry exported_at must be a valid calendar date and UTC time."
        ) from None
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key.")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise ValueError("Non-finite JSON number.")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Non-finite JSON number.")
    return number


def validate_telemetry_data(data: object) -> TelemetryExport:
    """Validate decoded data strictly against telemetry schema-v1 and return snapshot."""
    if type(data) is not dict:
        raise TelemetryIncompatibleError("Telemetry payload must be a JSON object.")
    if set(data) != TELEMETRY_TOP_LEVEL_KEYS:
        raise TelemetryIncompatibleError(
            "Telemetry payload does not match exact top-level field allowlist."
        )

    schema_version = data["schema_version"]
    if not _is_exact_int(schema_version) or schema_version <= 0:
        raise TelemetryIncompatibleError("Telemetry schema_version must be a positive integer.")
    if schema_version != TELEMETRY_SCHEMA_VERSION:
        raise TelemetryUnsupportedSchemaError("Unsupported telemetry schema version.")

    output_type = data["output_type"]
    if type(output_type) is not str or output_type != TELEMETRY_OUTPUT_TYPE:
        raise TelemetryIncompatibleError("Invalid telemetry output_type.")

    export_id = _validate_uuid4(data["export_id"])
    exported_at = _validate_utc_timestamp(data["exported_at"])

    alert_count = data["alert_count"]
    if not _is_exact_int(alert_count) or alert_count < 0:
        raise TelemetryIncompatibleError("Telemetry alert_count must be a nonnegative integer.")
    if alert_count > MAX_INPUT_ALERTS:
        raise TelemetryLimitExceededError(
            f"Telemetry alert_count exceeds maximum of {MAX_INPUT_ALERTS}."
        )

    groups = data["groups"]
    if type(groups) is not list:
        raise TelemetryIncompatibleError("Telemetry groups must be a JSON array.")
    if len(groups) > MAX_GROUPS:
        raise TelemetryLimitExceededError(f"Telemetry groups exceed maximum of {MAX_GROUPS}.")

    seen_keys: set[tuple[str, str, str]] = set()
    validated_groups: list[TelemetryGroup] = []
    total_count = 0

    for group in groups:
        if type(group) is not dict or set(group) != TELEMETRY_GROUP_KEYS:
            raise TelemetryIncompatibleError(
                "Telemetry group does not match exact field allowlist."
            )
        rule_id = group["rule_id"]
        severity = group["severity"]
        risk_level = group["risk_level"]
        count = group["count"]

        if type(rule_id) is not str or rule_id not in TELEMETRY_ALLOWED_RULE_IDS:
            raise TelemetryUnsupportedRuleError(
                "Telemetry group contains an unsupported rule identifier."
            )
        if type(severity) is not str or severity not in SEVERITY_VALUES:
            raise TelemetryIncompatibleError("Telemetry group has invalid severity.")
        if type(risk_level) is not str or risk_level not in RISK_LEVEL_VALUES:
            raise TelemetryIncompatibleError("Telemetry group has invalid risk_level.")
        if not _is_exact_int(count) or count < 1:
            raise TelemetryIncompatibleError("Telemetry group count must be a positive integer.")

        key = (rule_id, severity, risk_level)
        if key in seen_keys:
            raise TelemetryIncompatibleError("Duplicate telemetry aggregation group key.")
        seen_keys.add(key)
        total_count += count
        validated_groups.append(
            TelemetryGroup(
                rule_id=rule_id,
                severity=severity,
                risk_level=risk_level,
                count=count,
            )
        )

    if total_count != alert_count:
        raise TelemetryIncompatibleError(
            "Sum of telemetry group counts does not equal alert_count."
        )

    sorted_groups = sorted(
        validated_groups,
        key=lambda g: (g.rule_id, g.severity, g.risk_level),
    )
    if validated_groups != sorted_groups:
        raise TelemetryIncompatibleError("Telemetry groups must be deterministically sorted.")

    return TelemetryExport(
        schema_version=TELEMETRY_SCHEMA_VERSION,
        output_type=TELEMETRY_OUTPUT_TYPE,
        export_id=export_id,
        exported_at=exported_at,
        alert_count=alert_count,
        groups=tuple(validated_groups),
    )


def parse_telemetry_json(source: str | bytes | bytearray) -> TelemetryExport:
    """Strictly parse and validate bounded UTF-8 saved telemetry JSON."""
    if not isinstance(source, (str, bytes, bytearray)):
        raise TypeError("Saved telemetry JSON must be text or UTF-8 bytes.")

    try:
        raw_bytes = (
            source.encode("utf-8", errors="strict") if isinstance(source, str) else bytes(source)
        )
    except UnicodeError:
        raise TelemetryMalformedError("Saved telemetry JSON is not valid UTF-8.") from None

    if len(raw_bytes) > MAX_SAVED_TELEMETRY_BYTES:
        raise TelemetryLimitExceededError(
            f"Saved telemetry input exceeds {MAX_SAVED_TELEMETRY_BYTES}-byte limit."
        )

    try:
        text = raw_bytes.decode("utf-8", errors="strict")
    except UnicodeError:
        raise TelemetryMalformedError("Saved telemetry JSON is not valid UTF-8.") from None

    check_json_nesting_depth(text, max_depth=MAX_JSON_NESTING_DEPTH)

    try:
        data = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except (json.JSONDecodeError, ValueError):
        raise TelemetryMalformedError("Malformed saved telemetry JSON.") from None
    except RecursionError:
        raise TelemetryIncompatibleError(
            "Saved telemetry JSON exceeds validation capacity."
        ) from None

    return validate_telemetry_data(data)


def serialize_telemetry_json(
    telemetry: TelemetryExport | Mapping[str, Any],
    *,
    _max_output_bytes: int = MAX_OUTPUT_BYTES,
) -> bytes:
    """Validate and serialize a telemetry snapshot to deterministic UTF-8 JSON bytes."""
    raw_payload = telemetry.to_dict() if isinstance(telemetry, TelemetryExport) else dict(telemetry)
    validated = validate_telemetry_data(raw_payload)
    text = (
        json.dumps(
            validated.to_dict(),
            indent=2,
            sort_keys=True,
            allow_nan=False,
            ensure_ascii=False,
        )
        + "\n"
    )
    encoded = text.encode("utf-8")
    if len(encoded) > _max_output_bytes:
        raise TelemetryLimitExceededError(
            "Serialized telemetry payload exceeds maximum allowed size."
        )
    return encoded


def project_telemetry_from_bytes(
    source_bytes: bytes | bytearray,
    *,
    _export_id: str | None = None,
    _exported_at: str | None = None,
) -> TelemetryExport:
    """Validate bounded alert-report bytes and project allowlisted telemetry.

    ``_export_id`` and ``_exported_at`` are internal hooks for deterministic tests only.
    """
    if not isinstance(source_bytes, (bytes, bytearray)):
        raise TypeError("source_bytes must be bytes or bytearray.")
    raw = bytes(source_bytes)
    if len(raw) > MAX_INPUT_BYTES:
        raise TelemetryLimitExceededError(f"Input report exceeds {MAX_INPUT_BYTES}-byte limit.")

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        raise TelemetryMalformedError("Input report JSON is not valid UTF-8.") from None

    check_json_nesting_depth(text, max_depth=MAX_JSON_NESTING_DEPTH)

    try:
        validated_report = parse_report_json(text)
    except MalformedReportError:
        raise TelemetryMalformedError("Malformed alert-report JSON.") from None
    except UnsupportedSchemaError:
        raise TelemetryUnsupportedSchemaError("Unsupported alert-report schema version.") from None
    except IncompatibleReportError:
        raise TelemetryIncompatibleError("Incompatible alert-report contract.") from None
    except RecursionError:
        raise TelemetryIncompatibleError("Alert report exceeds validation capacity.") from None

    report_data = validated_report.to_dict()
    alerts = report_data["alerts"]
    if len(alerts) > MAX_INPUT_ALERTS:
        raise TelemetryLimitExceededError(f"Input report exceeds {MAX_INPUT_ALERTS}-alert limit.")

    counts: Counter[tuple[str, str, str]] = Counter()
    for alert in alerts:
        rule_id = alert["rule_id"]
        if rule_id not in TELEMETRY_ALLOWED_RULE_IDS:
            raise TelemetryUnsupportedRuleError(
                "Alert report contains an unsupported rule identifier."
            )
        counts[(rule_id, alert["severity"], alert["risk_level"])] += 1

    if len(counts) > MAX_GROUPS:
        raise TelemetryLimitExceededError(f"Aggregated telemetry exceeds {MAX_GROUPS}-group limit.")

    effective_export_id = _export_id if _export_id is not None else str(uuid.uuid4())
    effective_exported_at = (
        _exported_at
        if _exported_at is not None
        else datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    payload = {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "output_type": TELEMETRY_OUTPUT_TYPE,
        "export_id": effective_export_id,
        "exported_at": effective_exported_at,
        "alert_count": len(alerts),
        "groups": [
            {
                "rule_id": rule_id,
                "severity": severity,
                "risk_level": risk_level,
                "count": count,
            }
            for (rule_id, severity, risk_level), count in sorted(counts.items())
        ],
    }
    return validate_telemetry_data(payload)
