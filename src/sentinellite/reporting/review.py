import stat
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sentinellite.reporting.schema import (
    ALERT_REPORT_SCHEMA_VERSION,
    ReportContract,
    ReportValidationOutcome,
)
from sentinellite.reporting.schema import ALERT_REPORT_TYPE as SUPPORTED_REPORT_TYPE
from sentinellite.reporting.validation import (
    MalformedReportError as CanonicalMalformedReportError,
)
from sentinellite.reporting.validation import (
    ReportSchemaError,
    ValidatedReport,
    parse_report_json,
)
from sentinellite.reporting.validation import (
    UnsupportedSchemaError as CanonicalUnsupportedSchemaError,
)
from sentinellite.reporting.validation import (
    validate_report_data as validate_canonical_report_data,
)

MAX_REPORT_SIZE_BYTES = 2 * 1024 * 1024


class ReportReviewError(Exception):
    """Base error for expected report discovery, loading, and validation failures."""

    outcome: ReportValidationOutcome | None = None


class MalformedReportError(ReportReviewError):
    """Raised when a report cannot be decoded or parsed as JSON."""

    outcome = ReportValidationOutcome.MALFORMED


class IncompatibleReportError(ReportReviewError):
    """Raised when parsed JSON does not match a supported alert-report contract."""

    outcome = ReportValidationOutcome.INCOMPATIBLE


class UnsupportedSchemaError(ReportReviewError):
    """Raised when an alert report declares a future schema version."""

    outcome = ReportValidationOutcome.UNSUPPORTED_SCHEMA

    def __init__(self, schema_version: int, path: Path) -> None:
        self.schema_version = schema_version
        # Keep arbitrary-size versions as metadata rather than rendering them.
        super().__init__(
            f"Unsupported alert-report schema version in report '{path}'. "
            f"Supported schema version is {ALERT_REPORT_SCHEMA_VERSION}."
        )


@dataclass(frozen=True, slots=True)
class ReviewedAlert:
    rule_id: str
    severity: str
    risk_level: str
    risk_score: int
    category: str
    message: str
    has_explanation: bool


@dataclass(frozen=True, slots=True)
class ReviewedReport:
    path: Path
    report_id: str
    report_type: str
    generated_at: datetime
    alert_count: int
    alerts: tuple[ReviewedAlert, ...]
    contract: ReportContract | None = None

    @property
    def schema_version(self) -> int | None:
        return ALERT_REPORT_SCHEMA_VERSION if self.contract is ReportContract.SCHEMA_V1 else None

    @property
    def outcome(self) -> ReportValidationOutcome | None:
        if self.contract is ReportContract.SCHEMA_V1:
            return ReportValidationOutcome.VALID_SCHEMA_V1
        if self.contract is ReportContract.LEGACY_UNVERSIONED:
            return ReportValidationOutcome.VALID_LEGACY_UNVERSIONED
        return None


@dataclass(frozen=True, slots=True)
class ReportListEntry:
    path: Path
    generated_at: datetime | None
    alert_count: int | None
    report_type: str | None
    status: str
    error: str | None
    contract: ReportContract | None = None
    outcome: ReportValidationOutcome | None = None


def discover_report_paths(report_dir: Path) -> list[Path]:
    """Return regular lowercase JSON files directly inside a report directory."""
    try:
        directory_stat = report_dir.stat()
    except FileNotFoundError as error:
        raise ReportReviewError(f"Report directory not found: {report_dir}") from error
    except OSError as error:
        raise ReportReviewError(
            f"Unable to inspect report directory '{report_dir}': {error}"
        ) from error

    if not stat.S_ISDIR(directory_stat.st_mode):
        raise ReportReviewError(f"Report path is not a directory: {report_dir}")

    report_paths: list[Path] = []
    try:
        for candidate in report_dir.iterdir():
            if candidate.suffix != ".json" or candidate.is_symlink():
                continue
            if candidate.is_file():
                report_paths.append(candidate)
    except OSError as error:
        raise ReportReviewError(
            f"Unable to read report directory '{report_dir}': {error}"
        ) from error

    return sorted(report_paths, key=lambda path: (path.name, str(path)))


def load_review_report(path: Path) -> ReviewedReport:
    """Load one local JSON report and validate its supported review shape."""
    try:
        file_stat = path.stat()
    except FileNotFoundError as error:
        raise ReportReviewError(f"Report file not found: {path}") from error
    except OSError as error:
        raise ReportReviewError(f"Unable to inspect report file '{path}': {error}") from error

    if not stat.S_ISREG(file_stat.st_mode):
        raise ReportReviewError(f"Report path is not a regular file: {path}")
    if file_stat.st_size > MAX_REPORT_SIZE_BYTES:
        raise ReportReviewError(
            f"Report file exceeds the {MAX_REPORT_SIZE_BYTES}-byte size limit: {path}"
        )

    try:
        with path.open("rb") as report_file:
            encoded_data = report_file.read(MAX_REPORT_SIZE_BYTES + 1)
    except OSError as error:
        raise ReportReviewError(f"Unable to read report file '{path}': {error}") from error

    if len(encoded_data) > MAX_REPORT_SIZE_BYTES:
        raise ReportReviewError(
            f"Report file exceeds the {MAX_REPORT_SIZE_BYTES}-byte size limit: {path}"
        )

    try:
        return _project_report(parse_report_json(encoded_data), path)
    except ReportSchemaError as error:
        raise _review_error(error, path) from error
    except RecursionError as error:
        raise IncompatibleReportError("Report exceeds the review recursion capacity.") from error


def validate_report_data(data: object, path: Path) -> ReviewedReport:
    """Adapt canonical decoded-data validation to the public review model.

    Stored JSON must enter through load_review_report so duplicate keys are
    checked by the canonical parser before any information can be discarded.
    """
    try:
        return _project_report(validate_canonical_report_data(data), path)
    except ReportSchemaError as error:
        raise _review_error(error, path) from error
    except RecursionError as error:
        raise IncompatibleReportError("Report exceeds the review recursion capacity.") from error


def _review_error(error: ReportSchemaError, path: Path) -> ReportReviewError:
    if isinstance(error, CanonicalMalformedReportError):
        diagnostic = str(error)
        if not diagnostic.startswith("Malformed JSON"):
            diagnostic = f"Malformed JSON: {diagnostic}"
        # Put the safe parser detail before paths so bounded CLI rendering keeps
        # syntax locations visible even for long report paths.
        return MalformedReportError(f"{diagnostic} Report: '{path}'.")
    if isinstance(error, CanonicalUnsupportedSchemaError):
        return UnsupportedSchemaError(error.schema_version, path)
    # Canonical incompatibility diagnostics can contain user-supplied evidence
    # keys. Retain the cause for callers but do not expose it in CLI diagnostics.
    return IncompatibleReportError(
        f"Incompatible report '{path}': expected supported report_type "
        f"'{SUPPORTED_REPORT_TYPE}' and a complete schema-v1 or legacy-unversioned contract."
    )


def _project_report(validated: ValidatedReport, path: Path) -> ReviewedReport:
    data = validated.to_dict()
    return ReviewedReport(
        path=path,
        report_id=data["report_id"],
        report_type=data["report_type"],
        generated_at=datetime.fromisoformat(data["generated_at"].replace("z", "Z")),
        alert_count=data["alert_count"],
        alerts=tuple(
            ReviewedAlert(
                rule_id=alert["rule_id"],
                severity=alert["severity"],
                risk_level=alert["risk_level"],
                risk_score=alert["risk_score"],
                category=alert["category"],
                message=alert["message"],
                has_explanation="explanation" in alert,
            )
            for alert in data["alerts"]
        ),
        contract=validated.contract,
    )


def list_report_entries(report_dir: Path) -> list[ReportListEntry]:
    """Return valid and invalid report entries without hiding other candidates."""
    valid_entries: list[ReportListEntry] = []
    invalid_entries: list[ReportListEntry] = []

    for path in discover_report_paths(report_dir):
        try:
            report = load_review_report(path)
        except ReportReviewError as error:
            invalid_entries.append(
                ReportListEntry(
                    path=path,
                    generated_at=None,
                    alert_count=None,
                    report_type=None,
                    status="invalid",
                    error=str(error),
                    outcome=error.outcome,
                )
            )
            continue

        valid_entries.append(
            ReportListEntry(
                path=report.path,
                generated_at=report.generated_at,
                alert_count=report.alert_count,
                report_type=report.report_type,
                status="valid",
                error=None,
                contract=report.contract,
                outcome=report.outcome,
            )
        )

    valid_entries.sort(key=lambda entry: (entry.path.name, str(entry.path)))
    valid_entries.sort(key=lambda entry: entry.generated_at, reverse=True)
    invalid_entries.sort(key=lambda entry: (entry.path.name, str(entry.path)))
    return [*valid_entries, *invalid_entries]


def build_report_summary(report: ReviewedReport) -> dict[str, object]:
    """Build a deterministic summary without evidence or regenerated explanations."""
    severity_counts = Counter(alert.severity for alert in report.alerts)
    risk_level_counts = Counter(alert.risk_level for alert in report.alerts)

    return {
        "path": str(report.path),
        "report_id": report.report_id,
        "report_type": report.report_type,
        "contract": report.contract.value if report.contract is not None else None,
        "schema_version": report.schema_version,
        "generated_at": report.generated_at.isoformat(),
        "alert_count": report.alert_count,
        "explanation_count": sum(alert.has_explanation for alert in report.alerts),
        "rule_ids": sorted({alert.rule_id for alert in report.alerts}),
        "severity_counts": dict(sorted(severity_counts.items())),
        "risk_level_counts": dict(sorted(risk_level_counts.items())),
    }
