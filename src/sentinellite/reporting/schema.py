"""Canonical alert-report contract declarations.

This module defines the stable schema-v1 and verified legacy-unversioned
report contracts. It only declares the contracts; it does not parse or validate
reports.
"""

from enum import StrEnum

ALERT_REPORT_SCHEMA_VERSION = 1
ALERT_REPORT_TYPE = "sentinellite_alert_report"

ALERT_SCORE_MIN = 0
ALERT_SCORE_MAX = 100

LEGACY_REPORT_TOP_LEVEL_KEYS = frozenset(
    {
        "report_id",
        "report_type",
        "generated_at",
        "alert_count",
        "alerts",
    }
)

SCHEMA_V1_REPORT_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        *LEGACY_REPORT_TOP_LEVEL_KEYS,
    }
)

ALERT_REQUIRED_KEYS = frozenset(
    {
        "alert_id",
        "rule_id",
        "rule_name",
        "category",
        "severity",
        "base_score",
        "risk_score",
        "risk_level",
        "event_id",
        "event_type",
        "source",
        "message",
        "description",
        "recommendation",
        "evidence",
    }
)

ALERT_OPTIONAL_KEYS = frozenset({"explanation"})
ALERT_ALLOWED_KEYS = ALERT_REQUIRED_KEYS | ALERT_OPTIONAL_KEYS

# Historical v1.0.0-beta through v1.2.0-beta generated alerts use the same
# core ScoredAlert field set. Explanation was an optional generated addition.
# Freeze this field set independently so future schema changes cannot alter it.
LEGACY_ALERT_REQUIRED_KEYS = frozenset(
    {
        "alert_id",
        "rule_id",
        "rule_name",
        "category",
        "severity",
        "base_score",
        "risk_score",
        "risk_level",
        "event_id",
        "event_type",
        "source",
        "message",
        "description",
        "recommendation",
        "evidence",
    }
)
LEGACY_ALERT_ALLOWED_KEYS = LEGACY_ALERT_REQUIRED_KEYS | frozenset({"explanation"})

EXPLANATION_REQUIRED_KEYS = frozenset(
    {
        "rule_id",
        "title",
        "summary",
        "why_it_matched",
        "possible_causes",
        "recommended_actions",
        "evidence_summary",
        "confidence",
    }
)

SEVERITY_VALUES = frozenset(
    {
        "info",
        "low",
        "medium",
        "high",
        "critical",
    }
)

RISK_LEVEL_VALUES = SEVERITY_VALUES

EXPLANATION_CONFIDENCE_VALUES = frozenset(
    {
        "low",
        "medium",
        "high",
    }
)


class ReportContract(StrEnum):
    """Recognized SentinelLite alert-report contracts."""

    SCHEMA_V1 = "schema-v1"
    LEGACY_UNVERSIONED = "legacy-unversioned"


class ReportValidationOutcome(StrEnum):
    """Declared high-level outcomes for canonical report validation."""

    VALID_SCHEMA_V1 = "valid-schema-v1"
    VALID_LEGACY_UNVERSIONED = "valid-legacy-unversioned"
    MALFORMED = "malformed"
    INCOMPATIBLE = "incompatible"
    UNSUPPORTED_SCHEMA = "unsupported-schema"
