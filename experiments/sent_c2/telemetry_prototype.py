"""Isolated SENT-C2 offline telemetry projection, validation, and serialization prototype.

This module is a design prototype outside ``src/sentinellite/`` and is not part of
any installed CLI or package entry point. It demonstrates in-memory projection,
aggregation, contract validation, saved-telemetry parsing, and resource-limit
enforcement while reusing ``parse_report_json`` from
``sentinellite.reporting.validation``.

Notes:
- Production ``O_NOFOLLOW``/``O_NONBLOCK``/``fstat`` file I/O and CLI commands are
  intentionally out of scope.
- Sanitized public diagnostics suppress untrusted parser details from normal
  tracebacks, but do not protect against privileged debugging or process-memory
  inspection.
- Caller-supplied ``export_id`` and ``exported_at`` overrides on
  ``export_telemetry_bytes`` are reserved for deterministic prototype testing only.
"""

from __future__ import annotations

import json
import math
import re
import uuid
from collections import Counter
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

_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_UTC_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{6})?Z$"
)


class TelemetryOutcome(StrEnum):
    MALFORMED = "malformed"
    INCOMPATIBLE = "incompatible"
    UNSUPPORTED_SCHEMA = "unsupported-schema"
    UNSUPPORTED_RULE = "unsupported-rule"
    LIMIT_EXCEEDED = "limit-exceeded"


class TelemetryError(ValueError):
    """Base error for telemetry projection and validation failures."""

    def __init__(self, outcome: TelemetryOutcome, message: str) -> None:
        self.outcome = outcome
        super().__init__(message)


def _is_exact_int(value: object) -> bool:
    return type(value) is int


def _validate_uuid4(value: object) -> str:
    if type(value) is not str or not _UUID4_RE.fullmatch(value):
        raise TelemetryError(
            TelemetryOutcome.INCOMPATIBLE,
            "export_id must be a canonical lowercase UUIDv4 string.",
        )
    return value


def _validate_utc_timestamp(value: object) -> str:
    if type(value) is not str or not _UTC_TIMESTAMP_RE.fullmatch(value):
        raise TelemetryError(
            TelemetryOutcome.INCOMPATIBLE,
            "exported_at must be a canonical UTC ISO-8601 Z timestamp.",
        )
    try:
        datetime.fromisoformat(value)
    except ValueError:
        raise TelemetryError(
            TelemetryOutcome.INCOMPATIBLE,
            "exported_at must be a valid calendar date and UTC time.",
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
        raise ValueError("Non-finite JSON number (numeric overflow).")
    return number


def validate_telemetry_data(data: object) -> dict[str, Any]:
    """Strictly validate a telemetry payload dict against contract v1."""
    if type(data) is not dict:
        raise TelemetryError(
            TelemetryOutcome.INCOMPATIBLE, "Telemetry payload must be a JSON object."
        )
    if set(data) != TELEMETRY_TOP_LEVEL_KEYS:
        raise TelemetryError(
            TelemetryOutcome.INCOMPATIBLE,
            "Telemetry payload does not match exact top-level allowlist.",
        )

    schema_version = data["schema_version"]
    if not _is_exact_int(schema_version) or schema_version <= 0:
        raise TelemetryError(
            TelemetryOutcome.INCOMPATIBLE,
            "schema_version must be a positive integer.",
        )
    if schema_version != TELEMETRY_SCHEMA_VERSION:
        raise TelemetryError(
            TelemetryOutcome.UNSUPPORTED_SCHEMA,
            "Unsupported telemetry schema version.",
        )

    output_type = data["output_type"]
    if type(output_type) is not str or output_type != TELEMETRY_OUTPUT_TYPE:
        raise TelemetryError(
            TelemetryOutcome.INCOMPATIBLE, "Invalid telemetry output_type."
        )

    export_id = _validate_uuid4(data["export_id"])
    exported_at = _validate_utc_timestamp(data["exported_at"])

    alert_count = data["alert_count"]
    if not _is_exact_int(alert_count) or alert_count < 0:
        raise TelemetryError(
            TelemetryOutcome.INCOMPATIBLE,
            "alert_count must be a nonnegative integer.",
        )
    if alert_count > MAX_INPUT_ALERTS:
        raise TelemetryError(
            TelemetryOutcome.LIMIT_EXCEEDED,
            "alert_count exceeds maximum allowed alerts.",
        )

    groups = data["groups"]
    if type(groups) is not list:
        raise TelemetryError(TelemetryOutcome.INCOMPATIBLE, "groups must be a list.")
    if len(groups) > MAX_GROUPS:
        raise TelemetryError(
            TelemetryOutcome.LIMIT_EXCEEDED,
            "groups exceeds maximum allowed aggregation cardinality.",
        )

    seen_keys: set[tuple[str, str, str]] = set()
    validated_groups: list[dict[str, Any]] = []
    total_count = 0

    for group in groups:
        if type(group) is not dict or set(group) != TELEMETRY_GROUP_KEYS:
            raise TelemetryError(
                TelemetryOutcome.INCOMPATIBLE,
                "Telemetry group does not match exact field allowlist.",
            )
        rule_id = group["rule_id"]
        severity = group["severity"]
        risk_level = group["risk_level"]
        count = group["count"]

        if type(rule_id) is not str or rule_id not in TELEMETRY_ALLOWED_RULE_IDS:
            raise TelemetryError(
                TelemetryOutcome.UNSUPPORTED_RULE,
                "Unsupported or unallowlisted rule_id in telemetry group.",
            )
        if type(severity) is not str or severity not in SEVERITY_VALUES:
            raise TelemetryError(
                TelemetryOutcome.INCOMPATIBLE, "Invalid severity enum value."
            )
        if type(risk_level) is not str or risk_level not in RISK_LEVEL_VALUES:
            raise TelemetryError(
                TelemetryOutcome.INCOMPATIBLE, "Invalid risk_level enum value."
            )
        if not _is_exact_int(count) or count < 1:
            raise TelemetryError(
                TelemetryOutcome.INCOMPATIBLE,
                "Group count must be a positive integer.",
            )

        key = (rule_id, severity, risk_level)
        if key in seen_keys:
            raise TelemetryError(
                TelemetryOutcome.INCOMPATIBLE,
                "Duplicate aggregation group key.",
            )
        seen_keys.add(key)
        total_count += count
        validated_groups.append(
            {
                "rule_id": rule_id,
                "severity": severity,
                "risk_level": risk_level,
                "count": count,
            }
        )

    if total_count != alert_count:
        raise TelemetryError(
            TelemetryOutcome.INCOMPATIBLE,
            "Sum of group counts does not match alert_count.",
        )

    expected_order = sorted(
        validated_groups,
        key=lambda g: (g["rule_id"], g["severity"], g["risk_level"]),
    )
    if validated_groups != expected_order:
        raise TelemetryError(
            TelemetryOutcome.INCOMPATIBLE,
            "Telemetry groups must be deterministically sorted.",
        )

    return {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "output_type": TELEMETRY_OUTPUT_TYPE,
        "export_id": export_id,
        "exported_at": exported_at,
        "alert_count": alert_count,
        "groups": validated_groups,
    }


def parse_telemetry_json(
    source: str | bytes | bytearray,
    *,
    max_input_bytes: int = MAX_OUTPUT_BYTES,
) -> dict[str, Any]:
    """Decode bounded UTF-8 saved telemetry JSON and validate it strictly."""
    if not isinstance(source, (str, bytes, bytearray)):
        raise TypeError("Telemetry JSON must be text or UTF-8 bytes.")
    try:
        raw_bytes = (
            source.encode("utf-8", errors="strict")
            if isinstance(source, str)
            else bytes(source)
        )
        if len(raw_bytes) > max_input_bytes:
            raise TelemetryError(
                TelemetryOutcome.LIMIT_EXCEEDED,
                "Saved telemetry input exceeds maximum allowed size.",
            )
        text = raw_bytes.decode("utf-8", errors="strict")
        data = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except TelemetryError:
        raise
    except UnicodeError:
        raise TelemetryError(
            TelemetryOutcome.MALFORMED, "Telemetry JSON is not valid UTF-8."
        ) from None
    except (json.JSONDecodeError, ValueError):
        raise TelemetryError(
            TelemetryOutcome.MALFORMED, "Malformed telemetry JSON."
        ) from None
    except RecursionError:
        raise TelemetryError(
            TelemetryOutcome.INCOMPATIBLE,
            "Telemetry JSON exceeds nesting capacity.",
        ) from None

    return validate_telemetry_data(data)


def serialize_telemetry_json(
    payload: dict[str, Any],
    *,
    max_output_bytes: int = MAX_OUTPUT_BYTES,
) -> bytes:
    """Validate, serialize to canonical UTF-8 JSON, and enforce output size cap."""
    validated = validate_telemetry_data(payload)
    text = json.dumps(validated, indent=2, sort_keys=True, allow_nan=False) + "\n"
    encoded = text.encode("utf-8")
    if len(encoded) > max_output_bytes:
        raise TelemetryError(
            TelemetryOutcome.LIMIT_EXCEEDED,
            "Serialized telemetry exceeds output size limit.",
        )
    return encoded


def export_telemetry_bytes(
    source_bytes: bytes,
    *,
    export_id: str | None = None,
    exported_at: str | None = None,
) -> bytes:
    """Project one bounded, validated alert report into canonical telemetry JSON bytes.

    ``export_id`` and ``exported_at`` overrides are reserved for deterministic
    prototype testing only.
    """
    if not isinstance(source_bytes, (bytes, bytearray)):
        raise TypeError("source_bytes must be bytes or bytearray.")
    if len(source_bytes) > MAX_INPUT_BYTES:
        raise TelemetryError(
            TelemetryOutcome.LIMIT_EXCEEDED,
            "Input report exceeds 2 MiB limit.",
        )

    try:
        validated_report = parse_report_json(source_bytes)
    except MalformedReportError:
        raise TelemetryError(
            TelemetryOutcome.MALFORMED, "Malformed report JSON."
        ) from None
    except UnsupportedSchemaError:
        raise TelemetryError(
            TelemetryOutcome.UNSUPPORTED_SCHEMA,
            "Unsupported alert-report schema version.",
        ) from None
    except IncompatibleReportError:
        raise TelemetryError(
            TelemetryOutcome.INCOMPATIBLE,
            "Incompatible alert-report contract.",
        ) from None
    except RecursionError:
        raise TelemetryError(
            TelemetryOutcome.INCOMPATIBLE,
            "Alert report exceeds nesting capacity.",
        ) from None

    report_data = validated_report.to_dict()
    alerts = report_data["alerts"]
    if len(alerts) > MAX_INPUT_ALERTS:
        raise TelemetryError(
            TelemetryOutcome.LIMIT_EXCEEDED,
            "Alert count exceeds 1,000-alert limit.",
        )

    counts: Counter[tuple[str, str, str]] = Counter()
    for alert in alerts:
        rule_id = alert["rule_id"]
        if rule_id not in TELEMETRY_ALLOWED_RULE_IDS:
            raise TelemetryError(
                TelemetryOutcome.UNSUPPORTED_RULE,
                "Unsupported or unallowlisted rule_id.",
            )
        counts[(rule_id, alert["severity"], alert["risk_level"])] += 1

    if len(counts) > MAX_GROUPS:
        raise TelemetryError(
            TelemetryOutcome.LIMIT_EXCEEDED,
            "Unique aggregation groups exceed 128-group limit.",
        )

    groups = [
        {
            "rule_id": rule_id,
            "severity": severity,
            "risk_level": risk_level,
            "count": count,
        }
        for (rule_id, severity, risk_level), count in sorted(counts.items())
    ]

    effective_export_id = export_id if export_id is not None else str(uuid.uuid4())
    effective_exported_at = (
        exported_at
        if exported_at is not None
        else datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    payload = {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "output_type": TELEMETRY_OUTPUT_TYPE,
        "export_id": effective_export_id,
        "exported_at": effective_exported_at,
        "alert_count": len(alerts),
        "groups": groups,
    }
    return serialize_telemetry_json(payload)
